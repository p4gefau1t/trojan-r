use std::io;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::net::TcpListener;

use crate::protocol::{
    direct::DirectTcpStream, AcceptResult, Address, DummyUdpStream, ProxyAcceptor,
};

#[derive(Deserialize)]
pub struct PlaintextAcceptorConfig {
    addr: String,
}

pub struct PlaintextAcceptor {
    inner: TcpListener,
}

#[async_trait]
impl ProxyAcceptor for PlaintextAcceptor {
    type TS = DirectTcpStream;
    type US = DummyUdpStream;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        let (stream, addr) = self.inner.accept().await?;
        let addr = Address::from(addr);
        Ok(AcceptResult::Tcp((DirectTcpStream::new(stream), addr)))
    }
}

impl PlaintextAcceptor {
    pub async fn new(config: &PlaintextAcceptorConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(&config.addr).await?;
        Ok(Self { inner: listener })
    }
}
