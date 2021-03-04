use crate::protocol::{AcceptResult, Address, ProxyAcceptor, ProxyUdpStream, UdpRead, UdpWrite};
use async_trait::async_trait;
use serde::Deserialize;
use std::{
    io::Result,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[derive(Deserialize)]
pub struct DokodemoAcceptorConfig {
    listen_addr: String,
    target_addr: String,
}

#[derive(Clone)]
pub struct DokodemoUdpStream {
    inner: Arc<UdpSocket>,
    addr: Address,
}

#[async_trait]
impl UdpRead for DokodemoUdpStream {
    async fn read_from(&mut self, buf: &mut [u8]) -> Result<(usize, Address)> {
        let (len, _) = self.inner.recv_from(buf).await?;
        Ok((len, self.addr.clone()))
    }
}

#[async_trait]
impl UdpWrite for DokodemoUdpStream {
    async fn write_to(&mut self, buf: &[u8], _: &Address) -> Result<()> {
        self.inner.send_to(buf, self.addr.to_string()).await?;
        Ok(())
    }
}

#[async_trait]
impl ProxyUdpStream for DokodemoUdpStream {
    type R = Self;
    type W = Self;

    fn split(self) -> (Self::R, Self::W) {
        (self.clone(), self)
    }

    fn reunite(r: Self::R, _: Self::W) -> Self {
        r
    }

    async fn close(self) -> Result<()> {
        Ok(())
    }
}

pub struct DokodemoAcceptor {
    target_addr: Address,
    udp_spawned: AtomicBool,
    tcp_listener: TcpListener,
}

#[async_trait]
impl ProxyAcceptor for DokodemoAcceptor {
    type TS = TcpStream;
    type US = DokodemoUdpStream;

    async fn accept(&self) -> Result<AcceptResult<Self::TS, Self::US>> {
        if !self.udp_spawned.load(Ordering::Relaxed) {
            self.udp_spawned.store(true, Ordering::Relaxed);
            let socket = Arc::new(UdpSocket::bind(self.tcp_listener.local_addr().unwrap()).await?);
            let udp_stream = DokodemoUdpStream {
                inner: socket,
                addr: self.target_addr.clone(),
            };
            log::info!(
                "udp socket listening on {}",
                self.tcp_listener.local_addr().unwrap()
            );
            return Ok(AcceptResult::Udp(udp_stream));
        }
        let (stream, addr) = self.tcp_listener.accept().await?;
        log::info!("tcp connection from {}", addr.to_string());
        Ok(AcceptResult::Tcp((stream, self.target_addr.clone())))
    }
}

impl DokodemoAcceptor {
    pub async fn new(config: &DokodemoAcceptorConfig) -> Result<Self> {
        let tcp_listener = TcpListener::bind(config.listen_addr.clone()).await?;
        Ok(DokodemoAcceptor {
            target_addr: Address::from_str(&config.target_addr)?,
            udp_spawned: AtomicBool::new(false),
            tcp_listener,
        })
    }
}
