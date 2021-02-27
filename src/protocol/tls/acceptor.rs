use crate::protocol::{
    tls::{get_cipher_suite, load_cert, load_key, new_error},
    AcceptResult, Address, DummyUdpStream, ProxyAcceptor, ProxyTcpStream,
};
use async_trait::async_trait;
use serde::Deserialize;
use std::{io, path::Path, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    rustls::{NoClientAuth, ServerConfig},
    server::TlsStream,
    TlsAcceptor,
};

#[derive(Deserialize)]
pub struct TrojanTlsAcceptorConfig {
    addr: String,
    cert: String,
    key: String,
    cipher: Option<Vec<String>>,
}

pub struct TrojanTlsAcceptor {
    tls_acceptor: TlsAcceptor,
    tcp_listener: TcpListener,
}

impl ProxyTcpStream for TlsStream<TcpStream> {}

#[async_trait]
impl ProxyAcceptor for TrojanTlsAcceptor {
    type TS = TlsStream<TcpStream>;
    type US = DummyUdpStream;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        let (stream, addr) = self.tcp_listener.accept().await?;
        log::info!("tcp connection from {}", addr);
        let stream = self.tls_acceptor.accept(stream).await?;
        Ok(AcceptResult::Tcp((stream, Address::SocketAddress(addr))))
    }
}

impl TrojanTlsAcceptor {
    pub async fn new(config: &TrojanTlsAcceptorConfig) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(config.addr.to_owned()).await?;
        log::debug!("tls listen addr = {}", config.addr);

        let cert_path = Path::new(&config.cert);
        let key_path = Path::new(&config.key);
        let certs = load_cert(&cert_path)?;
        let mut keys = load_key(&key_path)?;

        let mut tls_config = ServerConfig::new(NoClientAuth::new());
        tls_config
            .set_single_cert(certs, keys.remove(0))
            .map_err(|e| new_error(format!("invalid cert {}", e.to_string())))?;

        tls_config.ciphersuites = get_cipher_suite(config.cipher.clone())?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        Ok(Self {
            tcp_listener,
            tls_acceptor,
        })
    }
}
