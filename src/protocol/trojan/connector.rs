use crate::protocol::trojan::header::{Command, TrojanRequestHeader};
use crate::protocol::trojan::{new_error, password_to_hash, TrojanUdpStream};
use crate::protocol::{Address, ProxyConnector};
use async_trait::async_trait;
use serde::Deserialize;
use std::io;

#[derive(Deserialize)]
pub struct TrojanConnectorConfig {
    password: String,
}

pub struct TrojanConnector<T: ProxyConnector> {
    inner: T,
    hash: String,
}

impl<T: ProxyConnector> TrojanConnector<T> {
    pub fn new(config: &TrojanConnectorConfig, inner: T) -> io::Result<Self> {
        if config.password.len() < 1 {
            return Err(new_error("no valid password found"));
        }
        let hash = password_to_hash(&config.password);
        Ok(Self { inner, hash })
    }
}

#[async_trait]
impl<T: ProxyConnector> ProxyConnector for TrojanConnector<T> {
    type TS = T::TS;
    type US = TrojanUdpStream<T::TS>;

    async fn connect_tcp(&self, addr: &Address) -> io::Result<Self::TS> {
        let mut stream = self.inner.connect_tcp(addr).await?;
        let header = TrojanRequestHeader::new(&self.hash, Command::TcpConnect, addr);
        header.write_to(&mut stream).await?;
        Ok(stream)
    }

    async fn connect_udp(&self) -> io::Result<Self::US> {
        let dummy_addr = Address::DomainNameAddress(String::from("UDP_CONN"), 0);
        let mut stream = self.inner.connect_tcp(&dummy_addr).await?;
        let header = TrojanRequestHeader::new(&self.hash, Command::UdpAssociate, &dummy_addr);
        header.write_to(&mut stream).await?;
        Ok(TrojanUdpStream::new(stream))
    }
}
