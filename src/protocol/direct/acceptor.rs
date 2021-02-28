use std::io;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::net::TcpListener;

use super::DirectTcpStream;
use crate::protocol::{AcceptResult, Address, DummyUdpStream, ProxyAcceptor};

#[derive(Deserialize)]
pub struct DirectAcceptorConfig {
    pub addr: String,
}

pub struct DirectAcceptor {
    inner: TcpListener,
}

#[async_trait]
impl ProxyAcceptor for DirectAcceptor {
    type TS = DirectTcpStream;
    type US = DummyUdpStream;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        let (stream, addr) = self.inner.accept().await?;
        let addr = Address::from(addr);
        Ok(AcceptResult::Tcp((DirectTcpStream { inner: stream }, addr)))
    }
}

impl DirectAcceptor {
    pub async fn new(config: &DirectAcceptorConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(&config.addr).await?;
        Ok(Self { inner: listener })
    }
}
