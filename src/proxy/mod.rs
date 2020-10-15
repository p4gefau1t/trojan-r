use crate::{
    error::Error,
    protocol::{
        direct::connector::DirectConnector, dokodemo::acceptor::DokodemoAcceptor,
        dokodemo::acceptor::DokodemoAcceptorConfig, socks5::acceptor::Socks5Acceptor,
        socks5::acceptor::Socks5AcceptorConfig, tls::acceptor::TrojanTlsAcceptor,
        tls::acceptor::TrojanTlsAcceptorConfig, tls::connector::TrojanTlsConnector,
        tls::connector::TrojanTlsConnectorConfig, trojan::acceptor::TrojanAcceptor,
        trojan::acceptor::TrojanAcceptorConfig, trojan::connector::TrojanConnector,
        trojan::connector::TrojanConnectorConfig, AcceptResult, ProxyAcceptor, ProxyConnector,
        ProxyTcpStream, ProxyUdpStream, UdpRead, UdpWrite,
    },
};
use futures::AsyncReadExt;
use log::LevelFilter;
use serde::Deserialize;
use smol::future::FutureExt;
use smol::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use std::fs::File;
use std::io;
use std::io::Read;
use std::sync::Arc;

async fn copy_udp<R: UdpRead, W: UdpWrite>(mut r: R, mut w: W) -> io::Result<()> {
    let mut buf = [0u8; 1024 * 8];
    loop {
        let (size, addr) = r.read_from(&mut buf).await?;
        if size == 0 {
            break;
        }
        w.write_to(&buf[..size], &addr).await?;
    }
    Ok(())
}

async fn copy_tcp<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
) -> io::Result<()> {
    let mut buf = [0u8; 1024 * 32];
    loop {
        let size = r.read(&mut buf).await?;
        if size == 0 {
            break;
        }
        w.write_all(&buf[..size]).await?;
    }
    Ok(())
}

pub async fn relay_udp<T: ProxyUdpStream, U: ProxyUdpStream>(a: T, b: U) {
    let (a_rx, a_tx) = a.split();
    let (b_rx, b_tx) = b.split();
    let t1 = copy_udp(a_rx, b_tx);
    let t2 = copy_udp(b_rx, a_tx);
    if let Err(e) = t1.race(t2).await {
        log::debug!("udp session ends: {}", e)
    }
}

pub async fn relay_tcp<T: ProxyTcpStream, U: ProxyTcpStream>(a: T, b: U) {
    let (a_rx, a_tx) = a.split();
    let (b_rx, b_tx) = b.split();
    let t1 = copy_tcp(a_rx, b_tx);
    let t2 = copy_tcp(b_rx, a_tx);
    if let Err(e) = t1.race(t2).await {
        log::debug!("tcp session ends: {}", e)
    }
}

#[derive(Deserialize)]
struct GlobalConfig {
    mode: String,
    log_level: Option<String>,
}

#[derive(Deserialize)]
struct ClientConfig {
    socks5: Socks5AcceptorConfig,
    trojan: TrojanConnectorConfig,
    tls: TrojanTlsConnectorConfig,
}

#[derive(Deserialize)]
struct ServerConfig {
    trojan: TrojanAcceptorConfig,
    tls: TrojanTlsAcceptorConfig,
}

#[derive(Deserialize)]
struct ForwardConfig {
    dokodemo: DokodemoAcceptorConfig,
    trojan: TrojanConnectorConfig,
    tls: TrojanTlsConnectorConfig,
}

async fn run_proxy<I: ProxyAcceptor, O: ProxyConnector + 'static>(
    acceptor: I,
    connector: O,
) -> io::Result<()> {
    let connector = Arc::new(connector);
    loop {
        match acceptor.accept().await {
            Ok(AcceptResult::Tcp((inbound, addr))) => {
                let connector = connector.clone();
                smol::spawn(async move {
                    match connector.connect_tcp(&addr).await {
                        Ok(outbound) => {
                            relay_tcp(inbound, outbound).await;
                        }
                        Err(e) => {
                            log::error!(
                                "failed to relay tcp connection to {}: {}",
                                addr.to_string(),
                                e.to_string()
                            );
                        }
                    }
                })
                .detach();
            }
            Ok(AcceptResult::Udp(inbound)) => {
                let connector = connector.clone();
                smol::spawn(async move {
                    match connector.connect_udp().await {
                        Ok(outbound) => {
                            relay_udp(inbound, outbound).await;
                        }
                        Err(e) => {
                            log::error!("failed to relay tcp connection: {}", e.to_string());
                        }
                    }
                })
                .detach();
            }
            Err(e) => {
                log::error!("accept failed: {}", e);
            }
        }
    }
}

pub async fn launch_from_config(filename: String) -> io::Result<()> {
    let mut file = File::open(filename)?;
    let mut config_string = String::new();
    file.read_to_string(&mut config_string)?;
    let config: GlobalConfig = toml::from_str(&config_string)?;
    if let Some(log_level) = config.log_level {
        let level = match log_level.as_str() {
            "trace" => LevelFilter::Trace,
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            _ => {
                return Err(Error::new("invalid log_level").into());
            }
        };
        let _ = env_logger::builder().filter_level(level).try_init();
    } else {
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .try_init();
    }
    match config.mode.as_str() {
        "server" => {
            log::debug!("server mode");
            let config: ServerConfig = toml::from_str(&config_string)?;
            let tls_acceptor = TrojanTlsAcceptor::new(&config.tls).await?;
            let trojan_acceptor = TrojanAcceptor::new(&config.trojan, tls_acceptor)?;
            let direct_connector = DirectConnector {};
            run_proxy(trojan_acceptor, direct_connector).await?;
        }
        "client" => {
            log::debug!("client mode");
            let config: ClientConfig = toml::from_str(&config_string)?;
            let socks5_acceptor = Socks5Acceptor::new(&config.socks5).await?;
            let tls_connector = TrojanTlsConnector::new(&config.tls)?;
            let trojan_connector = TrojanConnector::new(&config.trojan, tls_connector)?;
            run_proxy(socks5_acceptor, trojan_connector).await?;
        }
        "forward" => {
            log::debug!("forward mode");
            let config: ForwardConfig = toml::from_str(&config_string)?;
            let dokodemo_acceptor = DokodemoAcceptor::new(&config.dokodemo).await?;
            let tls_connector = TrojanTlsConnector::new(&config.tls)?;
            let trojan_connector = TrojanConnector::new(&config.trojan, tls_connector)?;
            run_proxy(dokodemo_acceptor, trojan_connector).await?;
        }
        _ => {
            log::error!("invalid mode: {}", config.mode.as_str());
        }
    }
    Ok(())
}
