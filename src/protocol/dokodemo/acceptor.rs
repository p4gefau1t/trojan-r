use crate::error::Error;
use crate::protocol::{AcceptResult, Address, DummyUdpStream, ProxyAcceptor};
use async_trait::async_trait;
use serde::Deserialize;
use smol::net::{TcpListener, TcpStream};
use std::io;
use std::io::Result;
use std::str::{from_utf8, FromStr};
use tls_parser::{
    parse_tls_extensions,
    parse_tls_plaintext, TlsExtension, TlsMessage::Handshake, TlsMessageHandshake::ClientHello,
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
    Error::new(format!("socks: {}", message.to_string())).into()
}

#[inline]
fn parse_tls_connection(buf: &[u8]) -> io::Result<String> {
    let (_, res) = parse_tls_plaintext(&buf).map_err(|_| new_error("unexpected protocol"))?;
    match &res.msg[0] {
        Handshake(ClientHello(contents)) => {
            let ext = contents
                .ext
                .ok_or(())
                .map_err(|_| new_error("unable to find tls extensions"))?;

            let (_, exts) = parse_tls_extensions(ext)
                .map_err(|_| new_error("unable to parse tls extensions"))?;

            let v = exts
                .iter()
                .find_map(|i| match i {
                    TlsExtension::SNI(v) => Some(v),
                    _ => None,
                })
                .ok_or(())
                .map_err(|_| new_error("unable to find tls extension SNI"))?;

            let name = from_utf8(v[0].1).unwrap().to_string() + ":443";
            Ok(name)
        }
        _ => Err(new_error("unexpected handshake type")),
    }
}

#[async_trait]
impl ProxyAcceptor for DokodemoAcceptor {
    type TS = TcpStream;
    type US = DummyUdpStream;

    async fn accept(&self) -> Result<AcceptResult<Self::TS, Self::US>> {
        let (stream, _) = self.tcp_listener.accept().await?;

        let mut buf: [u8; 2048] = [0; 2048];
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
