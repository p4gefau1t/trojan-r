use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use serde::Deserialize;
use std::{io, net::SocketAddr, sync::Arc};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{
        broadcast::{channel, Receiver, Sender},
        RwLock,
    },
};

use super::{
    new_error, Command, HandshakeRequest, HandshakeResponse, TcpRequestHeader, TcpResponseHeader,
    UdpAssociateHeader, AUTH_METHOD_NONE,
};
use crate::protocol::{
    AcceptResult, Address, ProxyAcceptor, ProxyTcpStream, ProxyUdpStream, UdpRead, UdpWrite,
};

#[derive(Deserialize)]
pub struct Socks5AcceptorConfig {
    addr: String,
}

pub struct Socks5UdpStream {
    src_addr: Arc<RwLock<Option<SocketAddr>>>,
    inner: Arc<UdpSocket>,
    shutdown_tx: Sender<()>,
    shutdown_rx: Receiver<()>,
}

const UDP_BUFFER_SIZE: usize = 0x2000;

#[async_trait]
impl UdpRead for Socks5UdpStream {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let mut recv_buf = [0u8; UDP_BUFFER_SIZE];
        let (recv_len, addr) = tokio::select! {
            result = self.inner.recv_from(&mut recv_buf) => {
                result?
            }
            _ = self.shutdown_rx.recv() => {
                return Err(io::ErrorKind::ConnectionReset.into());
            }
        };

        let src_address = self.src_addr.read().await.clone();
        if src_address.is_none() {
            // first packet
            self.src_addr.write().await.replace(addr);
        } else if src_address.unwrap() != addr {
            return Err(new_error("udp packet from unknown source"));
        }
        log::debug!("recv_len={}", recv_len);
        let header = UdpAssociateHeader::read_from_buf(&recv_buf[..recv_len])?;
        let header_len = header.serialized_len();
        let payload_len = recv_len - header_len;
        buf[..payload_len].copy_from_slice(&recv_buf[header_len..recv_len]);
        log::debug!("payload={}, addr={}", payload_len, header.address);
        Ok((payload_len, header.address))
    }
}

#[async_trait]
impl UdpWrite for Socks5UdpStream {
    async fn write_to(&mut self, buf: &[u8], addr: &Address) -> io::Result<()> {
        let header = UdpAssociateHeader::new(0, addr.clone());
        let mut send_buf = BytesMut::with_capacity(header.serialized_len() + buf.len());
        header.write_to_buf(&mut send_buf);
        send_buf.put_slice(buf);
        let address = self.src_addr.read().await;
        if address.is_none() {
            return Err(new_error("uninitialized udp socket"));
        }
        let address = address.unwrap();
        self.inner.send_to(&send_buf, address).await?;
        Ok(())
    }
}

#[async_trait]
impl ProxyUdpStream for Socks5UdpStream {
    type R = Self;
    type W = Self;

    fn split(self) -> (Self::R, Self::W) {
        let a = self;
        let b = Self {
            src_addr: a.src_addr.clone(),
            inner: a.inner.clone(),
            shutdown_rx: a.shutdown_tx.subscribe(),
            shutdown_tx: a.shutdown_tx.clone(),
        };
        (a, b)
    }

    fn reunite(r: Self::R, _: Self::W) -> Self {
        r
    }

    async fn close(self) -> io::Result<()> {
        Ok(())
    }
}

pub struct Socks5Acceptor {
    tcp_listener: TcpListener,
}

impl Socks5Acceptor {
    pub async fn new(config: &Socks5AcceptorConfig) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(config.addr.to_owned()).await?;
        Ok(Self { tcp_listener })
    }
}

impl ProxyTcpStream for TcpStream {}

#[async_trait]
impl ProxyAcceptor for Socks5Acceptor {
    type TS = TcpStream;
    type US = Socks5UdpStream;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        let (mut stream, addr) = self.tcp_listener.accept().await?;
        log::info!("socks5 stream from address {}", addr);

        // 1. handshake
        let req = HandshakeRequest::read_from(&mut stream).await?;
        if !req.methods.contains(&AUTH_METHOD_NONE) {
            return Err(new_error("invalid handshake method"));
        }
        let resp = HandshakeResponse::new(AUTH_METHOD_NONE);
        resp.write_to(&mut stream).await?;

        // 2. parse
        let req = TcpRequestHeader::read_from(&mut stream).await?;

        // 3. respond
        return match req.command {
            Command::TcpConnect => {
                let resp =
                    TcpResponseHeader::new(Address::SocketAddress(self.tcp_listener.local_addr()?));
                resp.write_to(&mut stream).await?;
                Ok(AcceptResult::Tcp((stream, req.address)))
            }
            Command::UdpAssociate => {
                log::debug!("udp associate");
                let ip = self.tcp_listener.local_addr().unwrap().ip();
                let socket_addr = SocketAddr::new(ip, 0);
                let udp_socket = Arc::new(UdpSocket::bind(socket_addr).await?);
                let resp = TcpResponseHeader::new(Address::SocketAddress(udp_socket.local_addr()?));
                log::debug!(
                    "udp socket listening on {}",
                    udp_socket.local_addr().unwrap()
                );
                let (shutdown_tx, shutdown_rx) = channel(16);
                resp.write_to(&mut stream).await?;
                {
                    let shutdown_tx = shutdown_tx.clone();
                    // keep tcp connection alive
                    tokio::spawn(async move {
                        let mut buf = [0u8; 0x10];
                        let _ = stream.read(&mut buf).await;
                        log::debug!("shutting down udp session..");
                        let _ = shutdown_tx.send(());
                    });
                }
                Ok(AcceptResult::Udp(Socks5UdpStream {
                    inner: udp_socket,
                    src_addr: Arc::new(RwLock::new(None)),
                    shutdown_rx,
                    shutdown_tx,
                }))
            }
        };
    }
}
