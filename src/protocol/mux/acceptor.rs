use std::{io, sync::Arc};

use async_trait::async_trait;
use io::ErrorKind;
use serde::Deserialize;
use tokio::{
    sync::{
        mpsc::{channel, Receiver},
        Mutex,
    },
    task::JoinHandle,
};

use super::{MuxHandle, MuxStream, MuxUdpStream, RequestHeader, STREAM_CHANNEL_LEN};
use crate::protocol::{AcceptResult, Address, ProxyAcceptor};

#[derive(Deserialize)]
pub struct MuxAcceptorConfig {}

pub struct MuxAcceptor {
    accept_stream_rx: Arc<Mutex<Receiver<AcceptResult<MuxStream, MuxUdpStream>>>>,
    handle: JoinHandle<io::Result<()>>,
}

impl Drop for MuxAcceptor {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[async_trait]
impl ProxyAcceptor for MuxAcceptor {
    type TS = MuxStream;
    type US = MuxUdpStream;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        if let Some(result) = self.accept_stream_rx.lock().await.recv().await {
            Ok(result)
        } else {
            Err(io::ErrorKind::ConnectionReset.into())
        }
    }
}

impl MuxAcceptor {
    pub fn new<T: ProxyAcceptor + 'static>(
        inner: T,
        _config: &MuxAcceptorConfig,
    ) -> io::Result<Self> {
        let (accept_stream_tx, accept_stream_rx) = channel(STREAM_CHANNEL_LEN);
        let handle: JoinHandle<io::Result<()>> = tokio::spawn(async move {
            loop {
                let result = match inner.accept().await {
                    Ok(r) => r,
                    Err(e) => {
                        log::error!("mux accept err: {}", e);
                        continue;
                    }
                };
                match result {
                    AcceptResult::Tcp((stream, addr)) => {
                        let accept_stream_tx = accept_stream_tx.clone();
                        let _: JoinHandle<io::Result<()>> = tokio::spawn(async move {
                            let valid_magic_addr = {
                                match &addr {
                                    Address::DomainNameAddress(domain, port) => {
                                        domain == "MUX_CONN" && *port == 0
                                    }
                                    _ => false,
                                }
                            };
                            if !valid_magic_addr {
                                log::error!("invalid mux magic address {}", addr.to_string());
                                return Err(ErrorKind::InvalidData.into());
                            }
                            log::debug!("new inbound stream for mux");
                            let mux_handle = MuxHandle::new(stream);
                            loop {
                                let mut stream = mux_handle.accept().await?;
                                log::debug!("new mux stream {:x} accepted", stream.stream_id);
                                let header = RequestHeader::read_from(&mut stream).await?;
                                let result = match header {
                                    RequestHeader::TcpConnect(addr) => {
                                        AcceptResult::Tcp((stream, addr))
                                    }
                                    RequestHeader::UdpAssociate => {
                                        AcceptResult::Udp(MuxUdpStream { inner: stream })
                                    }
                                };
                                accept_stream_tx
                                    .send(result)
                                    .await
                                    .map_err(|_| io::ErrorKind::ConnectionAborted)?;
                            }
                        });
                    }
                    AcceptResult::Udp(_) => {
                        log::error!("mux: invalid udp stream");
                    }
                }
            }
        });
        Ok(Self {
            accept_stream_rx: Arc::new(Mutex::new(accept_stream_rx)),
            handle,
        })
    }
}
