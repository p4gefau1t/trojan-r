use crate::error::Error;
use crate::protocol::{AcceptResult, Address, DummyUdpStream, ProxyAcceptor};
use async_trait::async_trait;
use log;
use serde::Deserialize;
use smol::net::{TcpListener, TcpStream};
use std::io;
use std::io::Result;
use std::str::{from_utf8, FromStr};
use tls_parser::{
    parse_tls_extension_sni, parse_tls_plaintext, TlsExtension, TlsMessage::Handshake,
    TlsMessageHandshake::ClientHello,
};

#[derive(Deserialize)]
pub struct DokodemoAcceptorConfig {
    listen_addr: String,
}

pub struct DokodemoAcceptor {
    tcp_listener: TcpListener,
}

#[inline]
fn new_error<T: ToString>(message: T) -> io::Error {
    return Error::new(format!("socks: {}", message.to_string())).into();
}

#[inline]
fn parse_tls_connection(buf: &[u8]) -> io::Result<String> {
    let (_, res) = parse_tls_plaintext(&buf).map_err(|_| new_error("unexpected protocol"))?;
    match &res.msg[0] {
        Handshake(ClientHello(contents)) => {
            log::debug!("{:?}",contents);
            let ext = contents
                .ext
                .ok_or(())
                .map_err(|_| new_error("unable to find tls extensions"))?;
            match parse_tls_extension_sni(ext)
                .map_err(|_| new_error("parse tls extensions error"))?
            {
                (_, TlsExtension::SNI(v)) => {
                    let name = from_utf8(v[0].1).unwrap().to_string() + ":443";
                    Ok(name)
                }
                _ => Err(new_error("can't find domain name")),
            }
        }
        _ => Err(new_error("unexpected handshake type")),
    }
}

#[async_trait]
impl ProxyAcceptor for DokodemoAcceptor {
    type TS = TcpStream;
    type US = DummyUdpStream;

    async fn accept(&self) -> Result<AcceptResult<Self::TS, Self::US>> {
        let (stream, addr) = self.tcp_listener.accept().await?;
        log::debug!("tcp connection from {}", addr.to_string());

        let mut buf: [u8; 1024] = [0; 1024];
        stream.peek(&mut buf).await?;
        let name = parse_tls_connection(&buf)?;
        log::debug!("connected to {}", name);
        let addr = Address::from_str(&name).map_err(|err| new_error(err.message))?;
        Ok(AcceptResult::Tcp((stream, addr)))
    }
}

impl DokodemoAcceptor {
    pub async fn new(config: &DokodemoAcceptorConfig) -> Result<Self> {
        let tcp_listener = TcpListener::bind(config.listen_addr.clone()).await?;
        Ok(DokodemoAcceptor { tcp_listener })
    }
}
