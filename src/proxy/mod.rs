use crate::protocol::websocket::acceptor::{WebSocketAcceptor, WebSocketAcceptorConfig};
use crate::protocol::websocket::connector::{WebSocketConnector, WebSocketConnectorConfig};
use crate::protocol::Address;
use crate::protocol::Address::{DomainNameAddress, SocketAddress};
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
use bit_vec::BitVec;
use futures::AsyncReadExt;
use fxhash::hash32;
use log::LevelFilter;
use serde::Deserialize;
use smol::future::FutureExt;
use smol::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::hash::Hash;

async fn copy_udp<R: UdpRead, W: UdpWrite>(r: &mut R, w: &mut W) -> io::Result<()> {
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
    r: &mut R,
    w: &mut W,
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
    let (mut a_rx, mut a_tx) = a.split();
    let (mut b_rx, mut b_tx) = b.split();
    let t1 = copy_udp(&mut a_rx, &mut b_tx);
    let t2 = copy_udp(&mut b_rx, &mut a_tx);
    if let Err(e) = t1.race(t2).await {
        log::debug!("udp session ends: {}", e)
    }
    let _ = T::reunite(a_rx, a_tx).close();
    let _ = U::reunite(b_rx, b_tx).close();
}

pub async fn relay_tcp<T: ProxyTcpStream, U: ProxyTcpStream>(a: T, b: U) {
    let (mut a_rx, mut a_tx) = a.split();
    let (mut b_rx, mut b_tx) = b.split();
    let t1 = copy_tcp(&mut a_rx, &mut b_tx);
    let t2 = copy_tcp(&mut b_rx, &mut a_tx);
    if let Err(e) = t1.race(t2).await {
        log::debug!("tcp session ends: {}", e)
    }
    let mut a = a_rx.reunite(a_tx).unwrap();
    let mut b = b_rx.reunite(b_tx).unwrap();
    let _ = a.close().await;
    let _ = b.close().await;
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
    websocket: Option<WebSocketConnectorConfig>,
}

#[derive(Deserialize)]
struct ServerConfig {
    trojan: TrojanAcceptorConfig,
    tls: TrojanTlsAcceptorConfig,
    websocket: Option<WebSocketAcceptorConfig>,
}

#[derive(Deserialize)]
struct ForwardConfig {
    dokodemo: DokodemoAcceptorConfig,
    trojan: TrojanConnectorConfig,
    tls: TrojanTlsConnectorConfig,
    websocket: Option<WebSocketConnectorConfig>,
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub struct Route {
    bv: BitVec,
}

#[inline]
pub fn hash24<T: Hash + ?Sized>(v: &T) -> usize {
    (hash32(&v) >> (32 - 24)) as usize
}

impl Route {
    pub fn new() -> Self {
        
        let size_24bit:usize = 16777216 - 1;
        let mut bv = BitVec::from_elem(size_24bit, false);

        if let Ok(lines) = read_lines("rule.txt") {
            for line in lines {
                if let Ok(domain) = line {
                    let i = hash24(&domain);
                    bv.set(i, true);
                }
            }
        }
        Self { bv }
    }

    #[inline]
    pub fn is_match(&self, domain: &str) -> bool {
        let hash = hash24(domain);
        if let Some(true) = self.bv.get(hash) {
            return true;
        }

        let len = domain.len();
        for (i, &item) in domain.as_bytes().iter().enumerate() {
            if item == b'.' {
                let str = &domain[i + 1..len];
                let hash = hash24(str);
                if let Some(true) = self.bv.get(hash) {
                    return true;
                }
            }
        }
        false
    }
}

#[inline]
async fn udp_proxy<I: ProxyUdpStream, O: ProxyConnector + 'static>(inbound: I, connector: Arc<O>) {
    match connector.connect_udp().await {
        Ok(outbound) => {
            relay_udp(inbound, outbound).await;
        }
        Err(e) => {
            log::error!("failed to relay udp connection: {}", e.to_string());
        }
    }
}

#[inline]
async fn tcp_proxy<I: ProxyTcpStream, O: ProxyConnector + 'static>(
    inbound: I,
    connector: Arc<O>,
    addr: &Address,
) {
    match connector.connect_tcp(addr).await {
        Ok(outbound) => {
            relay_tcp(inbound, outbound).await;
        }
        Err(e) => {
            log::error!("failed to relay tcp connection: {}", e.to_string());
        }
    }
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
                    log::info!("accepted {}", &addr);
                    tcp_proxy(inbound, connector, &addr).await;
                })
                .detach();
            }
            Ok(AcceptResult::Udp(inbound)) => {
                let connector = connector.clone();
                smol::spawn(async move {
                    udp_proxy(inbound, connector).await;
                })
                .detach();
            }
            Err(e) => {
                log::error!("accept failed: {}", e);
            }
        }
    }
}

async fn run_rule_proxy<I: ProxyAcceptor, O: ProxyConnector + 'static>(
    acceptor: I,
    connector: O,
) -> io::Result<()> {
    let connector = Arc::new(connector);
    let direct_connector = Arc::new(DirectConnector {});
    let route = Route::new();
    loop {
        match acceptor.accept().await {
            Ok(AcceptResult::Tcp((inbound, addr))) => {
                //match domain
                let result: bool;
                match &addr {
                    SocketAddress(_sockaddr) => result = false,
                    DomainNameAddress(domain, _) => result = route.is_match(domain),
                }

                //do proxy
                let connector = connector.clone();
                let direct_connector = direct_connector.clone();

                smol::spawn(async move {
                    if !result {
                        log::info!("accepted {}", &addr);
                        tcp_proxy(inbound, connector, &addr).await;
                    } else {
                        log::info!("directed {}", &addr);
                        tcp_proxy(inbound, direct_connector, &addr).await;
                    }
                })
                .detach();
            }
            Ok(AcceptResult::Udp(inbound)) => {
                let connector = connector.clone();
                smol::spawn(async move {
                    udp_proxy(inbound, connector).await;
                })
                .detach();
            }
            Err(e) => {
                log::error!("accept failed: {}", e);
            }
        }
    }
}

pub async fn launch_from_config_filename(filename: String) -> io::Result<()> {
    let mut file = File::open(filename)?;
    let mut config_string = String::new();
    file.read_to_string(&mut config_string)?;
    launch_from_config_string(config_string).await
}

pub async fn launch_from_config_string(config_string: String) -> io::Result<()> {
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
            let direct_connector = DirectConnector {};
            let tls_acceptor = TrojanTlsAcceptor::new(&config.tls).await?;
            if config.websocket.is_none() {
                let trojan_acceptor = TrojanAcceptor::new(&config.trojan, tls_acceptor)?;
                run_proxy(trojan_acceptor, direct_connector).await?;
            } else {
                let ws_acceptor = WebSocketAcceptor::new(&config.websocket.unwrap(), tls_acceptor)?;
                let trojan_acceptor = TrojanAcceptor::new(&config.trojan, ws_acceptor)?;
                run_proxy(trojan_acceptor, direct_connector).await?;
            }
        }
        "client" => {
            log::debug!("client mode");
            let config: ClientConfig = toml::from_str(&config_string)?;
            let socks5_acceptor = Socks5Acceptor::new(&config.socks5).await?;
            let tls_connector = TrojanTlsConnector::new(&config.tls)?;
            if config.websocket.is_none() {
                let trojan_connector = TrojanConnector::new(&config.trojan, tls_connector)?;
                run_rule_proxy(socks5_acceptor, trojan_connector).await?;
            } else {
                let ws_connector =
                    WebSocketConnector::new(&config.websocket.unwrap(), tls_connector)?;
                let trojan_connector = TrojanConnector::new(&config.trojan, ws_connector)?;
                run_rule_proxy(socks5_acceptor, trojan_connector).await?;
            }
        }
        "forward" => {
            log::debug!("forward mode");
            let config: ForwardConfig = toml::from_str(&config_string)?;
            let dokodemo_acceptor = DokodemoAcceptor::new(&config.dokodemo).await?;
            let tls_connector = TrojanTlsConnector::new(&config.tls)?;
            if config.websocket.is_none() {
                let trojan_connector = TrojanConnector::new(&config.trojan, tls_connector)?;
                run_rule_proxy(dokodemo_acceptor, trojan_connector).await?;
            } else {
                let ws_connector =
                    WebSocketConnector::new(&config.websocket.unwrap(), tls_connector)?;
                let trojan_connector = TrojanConnector::new(&config.trojan, ws_connector)?;
                run_rule_proxy(dokodemo_acceptor, trojan_connector).await?;
            }
        }
        _ => {
            log::error!("invalid mode: {}", config.mode.as_str());
        }
    }
    Ok(())
}
