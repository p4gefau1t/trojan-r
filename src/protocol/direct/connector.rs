use crate::protocol::direct::DirectTcpStream;
use crate::protocol::{Address, ProxyConnector};
use async_trait::async_trait;
use smol::net::{TcpStream, UdpSocket};

use super::DirectUdpStream;

pub struct DirectConnector {}

#[async_trait]
impl ProxyConnector for DirectConnector {
    type TS = DirectTcpStream;
    type US = DirectUdpStream;

    async fn connect_tcp(&self, addr: &Address) -> std::io::Result<Self::TS> {
        // TODO to_string
        log::debug!("direct: connecting to {}", addr);
        let stream = TcpStream::connect(addr.to_string()).await?;
        Ok(DirectTcpStream { inner: stream })
    }

    async fn connect_udp(&self) -> std::io::Result<Self::US> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(DirectUdpStream { inner: socket })
    }
}
