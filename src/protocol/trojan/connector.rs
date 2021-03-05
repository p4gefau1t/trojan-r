use async_trait::async_trait;
use bytes::Buf;
use serde::Deserialize;
use std::io;

use crate::protocol::{Address, ProxyConnector};

use super::{new_error, password_to_hash, RequestHeader, TrojanUdpStream, HASH_STR_LEN};

#[derive(Deserialize)]
pub struct TrojanConnectorConfig {
    password: String,
}

pub struct TrojanConnector<T: ProxyConnector> {
    inner: T,
    hash: [u8; HASH_STR_LEN],
}

impl<T: ProxyConnector> TrojanConnector<T> {
    pub fn new(config: &TrojanConnectorConfig, inner: T) -> io::Result<Self> {
        if config.password.len() < 1 {
            return Err(new_error("no valid password found"));
        }
        let mut hash = [0u8; HASH_STR_LEN];
        password_to_hash(&config.password)
            .as_bytes()
            .copy_to_slice(&mut hash);
        Ok(Self { inner, hash })
    }
}

#[async_trait]
impl<T: ProxyConnector> ProxyConnector for TrojanConnector<T> {
    type TS = T::TS;
    type US = TrojanUdpStream<T::TS>;

    async fn connect_tcp(&self, addr: &Address) -> io::Result<Self::TS> {
        let mut stream = self.inner.connect_tcp(addr).await?;
        let header = RequestHeader::TcpConnect(self.hash.clone(), addr.clone());
        header.write_to(&mut stream).await?;
        Ok(stream)
    }

    async fn connect_udp(&self) -> io::Result<Self::US> {
        let udp_dummy_addr = Address::new_dummy_address();
        let mut stream = self.inner.connect_tcp(&udp_dummy_addr).await?;
        let header = RequestHeader::UdpAssociate(self.hash.clone());
        header.write_to(&mut stream).await?;
        Ok(TrojanUdpStream::new(stream))
    }
}
