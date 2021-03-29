use async_trait::async_trait;
use serde::Deserialize;
use std::{io, collections::HashSet};

use crate::protocol::{Address, ProxyConnector};

use super::{Password, RequestHeader, TrojanUdpStream};

#[derive(Deserialize)]
pub struct TrojanConnectorConfig {
    passwords: HashSet<Password>,
}

pub struct TrojanConnector<T: ProxyConnector> {
    inner: T,
    password: Password,
}

impl<T: ProxyConnector> TrojanConnector<T> {
    pub fn new(config: &TrojanConnectorConfig, inner: T) -> io::Result<Self> {
        Ok(Self {
            inner,
            password: config.passwords.iter().next().unwrap().clone(),
        })
    }
}

#[async_trait]
impl<T: ProxyConnector> ProxyConnector for TrojanConnector<T> {
    type TS = T::TS;
    type US = TrojanUdpStream<T::TS>;

    async fn connect_tcp(&self, addr: &Address) -> io::Result<Self::TS> {
        let mut stream = self.inner.connect_tcp(addr).await?;
        let header = RequestHeader::TcpConnect(self.password.clone(), addr.clone());
        header.write_to(&mut stream).await?;
        Ok(stream)
    }

    async fn connect_udp(&self) -> io::Result<Self::US> {
        let udp_dummy_addr = Address::new_dummy_address();
        let mut stream = self.inner.connect_tcp(&udp_dummy_addr).await?;
        let header = RequestHeader::UdpAssociate(self.password.clone());
        header.write_to(&mut stream).await?;
        Ok(TrojanUdpStream::new(stream))
    }
}
