use async_trait::async_trait;
use serde::Deserialize;
use std::{io, str::FromStr};
use tokio::{io::AsyncWriteExt, net::TcpStream};

use crate::protocol::{trojan::RequestHeader, AcceptResult, Address, ProxyAcceptor};
use crate::proxy::relay_tcp;

use super::{new_error, Password, TrojanUdpStream};

#[derive(Deserialize)]
pub struct TrojanAcceptorConfig {
    password: Password,
    fallback_addr: String,
}

pub struct TrojanAcceptor<T: ProxyAcceptor> {
    password: Password,
    fallback_addr: Address,
    inner: T,
}

#[async_trait]
impl<T: ProxyAcceptor> ProxyAcceptor for TrojanAcceptor<T> {
    type TS = T::TS;
    type US = TrojanUdpStream<T::TS>;
    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        let (mut stream, addr) = self.inner.accept().await?.unwrap_tcp_with_addr();
        let mut first_packet = Vec::new();
        match RequestHeader::read_from(&mut stream, &self.password, &mut first_packet).await {
            Ok(header) => match header {
                RequestHeader::TcpConnect(_, addr) => {
                    log::info!("trojan tcp stream {}", addr);
                    Ok(AcceptResult::Tcp((stream, addr)))
                }
                RequestHeader::UdpAssociate(_) => {
                    log::info!("trojan udp stream {}", addr);
                    Ok(AcceptResult::Udp(TrojanUdpStream::new(stream)))
                }
            },
            Err(e) => {
                log::debug!("first packet {:x?}", first_packet);
                let fallback_addr = self.fallback_addr.clone();
                log::warn!("invalid trojan request, falling back to {}", fallback_addr);
                tokio::spawn(async move {
                    let inbound = stream;
                    let mut outbound = TcpStream::connect(fallback_addr.to_string()).await.unwrap();
                    let _ = outbound.write(&first_packet).await;
                    relay_tcp(inbound, outbound).await;
                });
                Err(new_error(format!("invalid packet: {}", e.to_string())))
            }
        }
    }
}

impl<T: ProxyAcceptor> TrojanAcceptor<T> {
    pub fn new(config: &TrojanAcceptorConfig, inner: T) -> io::Result<Self> {
        let fallback_addr = Address::from_str(&config.fallback_addr)?;
        let password = config.password.clone();
        Ok(Self {
            fallback_addr,
            password,
            inner,
        })
    }
}
