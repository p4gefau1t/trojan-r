use crate::protocol::{Address, DummyUdpStream, ProxyConnector, ProxyTcpStream};
use async_trait::async_trait;
use serde::Deserialize;
use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
    sync::Arc,
};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, rustls::ClientConfig, TlsConnector};
use webpki::DNSNameRef;

use super::get_cipher_suite;

#[derive(Deserialize)]
pub struct TrojanTlsConnectorConfig {
    addr: String,
    sni: String,
    cipher: Option<Vec<String>>,
    cert: Option<String>,
}

pub struct TrojanTlsConnector {
    sni: String,
    server_addr: String,
    tls_config: Arc<ClientConfig>,
}

impl ProxyTcpStream for TlsStream<TcpStream> {}

impl TrojanTlsConnector {
    pub fn new(config: &TrojanTlsConnectorConfig) -> io::Result<Self> {
        let mut tls_config = ClientConfig::new();

        tls_config.ciphersuites = get_cipher_suite(config.cipher.clone())?;

        if let Some(ref cert_path) = config.cert {
            let cert_path = Path::new(cert_path);
            tls_config
                .root_store
                .add_pem_file(&mut BufReader::new(File::open(cert_path)?))
                .unwrap();
        } else {
            tls_config
                .root_store
                .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        }

        Ok(Self {
            sni: config.sni.clone(),
            server_addr: config.addr.clone(),
            tls_config: Arc::new(tls_config),
        })
    }
}

#[async_trait]
impl ProxyConnector for TrojanTlsConnector {
    type TS = TlsStream<TcpStream>;
    type US = DummyUdpStream;

    async fn connect_tcp(&self, _: &Address) -> io::Result<Self::TS> {
        let stream = TcpStream::connect(&self.server_addr).await?;
        stream.set_nodelay(true)?;

        let dns_name = DNSNameRef::try_from_ascii_str(&self.sni)
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?;
        let stream = TlsConnector::from(self.tls_config.clone())
            .connect(dns_name, stream)
            .await?;

        log::info!("connected to {}", self.server_addr);
        Ok(stream)
    }

    async fn connect_udp(&self) -> io::Result<Self::US> {
        unimplemented!()
    }
}
