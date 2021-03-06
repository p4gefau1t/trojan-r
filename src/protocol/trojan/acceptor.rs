use async_trait::async_trait;
use bytes::Buf;
use serde::Deserialize;
use std::{io, str::FromStr};
use tokio::{io::AsyncWriteExt, net::TcpStream};

use crate::protocol::{trojan::RequestHeader, AcceptResult, Address, ProxyAcceptor};
use crate::proxy::relay_tcp;

use super::{new_error, password_to_hash, TrojanUdpStream, HASH_STR_LEN};

#[derive(Deserialize)]
pub struct TrojanAcceptorConfig {
    password: String,
    fallback_addr: String,
}

pub struct TrojanAcceptor<T: ProxyAcceptor> {
    valid_hash: [u8; HASH_STR_LEN],
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
        match RequestHeader::read_from(&mut stream, &self.valid_hash, &mut first_packet).await {
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
        let mut valid_hash = [0u8; HASH_STR_LEN];
        password_to_hash(&config.password)
            .as_bytes()
            .copy_to_slice(&mut valid_hash);
        Ok(Self {
            fallback_addr,
            valid_hash,
            inner,
        })
    }
}
