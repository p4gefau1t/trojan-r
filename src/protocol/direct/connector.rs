use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};

use crate::protocol::{Address, ProxyConnector};

use super::{DirectTcpStream, DirectUdpStream};

pub struct DirectConnector {}

#[async_trait]
impl ProxyConnector for DirectConnector {
    type TS = DirectTcpStream;
    type US = DirectUdpStream;

    async fn connect_tcp(&self, addr: &Address) -> std::io::Result<Self::TS> {
        log::debug!("direct: connecting to {}", addr);
        let stream = TcpStream::connect(addr.to_string()).await?;
        Ok(DirectTcpStream { inner: stream })
    }

    async fn connect_udp(&self) -> std::io::Result<Self::US> {
        let socket = Arc::new(UdpSocket::bind(":::0").await?);
        Ok(DirectUdpStream { inner: socket })
    }
}
