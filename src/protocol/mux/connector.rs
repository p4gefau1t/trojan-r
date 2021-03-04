use std::{
    collections::HashMap,
    io,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use serde::Deserialize;
use tokio::{sync::Mutex, task::JoinHandle, time::sleep};

use super::{new_key, Command, MuxHandle, MuxStream, MuxUdpStream, RequestHeader};
use crate::protocol::{Address, ProxyConnector};

#[derive(Deserialize)]
pub struct MuxConnectorConfig {
    concurrent: usize,
    timeout: u32,
}

pub struct MuxConnector<T: ProxyConnector> {
    handlers: Arc<Mutex<HashMap<u32, MuxHandle>>>,
    concurrent: usize,
    inner: T,
    cleaner: JoinHandle<()>,
    handle_id_hint: Arc<AtomicU32>,
}

impl<T: ProxyConnector> Drop for MuxConnector<T> {
    fn drop(&mut self) {
        self.cleaner.abort();
    }
}

impl<T: ProxyConnector> MuxConnector<T> {
    pub fn new(config: &MuxConnectorConfig, inner: T) -> io::Result<Self> {
        let handlers: Arc<Mutex<HashMap<u32, MuxHandle>>> = Arc::new(Mutex::new(HashMap::new()));
        let cleaner = {
            let timeout = Duration::from_secs(config.timeout as u64);
            let handlers = handlers.clone();
            tokio::spawn(async move {
                loop {
                    sleep(timeout).await;
                    log::debug!("cleaning inactive mux stream..");
                    let mut handlers = handlers.lock().await;
                    let mut inactive_handle_id = Vec::new();
                    for (handle_id, handle) in handlers.iter() {
                        let num_streams = handle.established_streams().await;
                        let closed = handle.closed.load(Ordering::Relaxed);
                        if num_streams == 0 || closed {
                            inactive_handle_id.push(*handle_id);
                        }
                        log::debug!("handle {:x}: {:x}", *handle_id, num_streams);
                    }
                    for handle_id in inactive_handle_id.iter() {
                        handlers.remove(handle_id);
                    }
                }
            })
        };
        Ok(Self {
            concurrent: config.concurrent,
            handlers,
            cleaner,
            inner,
            handle_id_hint: Arc::new(AtomicU32::new(0)),
        })
    }
}

impl<T: ProxyConnector> MuxConnector<T> {
    async fn spawn_mux_stream(&self) -> io::Result<MuxStream> {
        let mut handlers = self.handlers.lock().await;
        loop {
            for (handle_id, handle) in handlers.iter() {
                if handle.established_streams().await < self.concurrent {
                    let stream = handle.connect().await?;
                    log::debug!(
                        "mux stream {:x} spawned from handle {:x}",
                        stream.stream_id(),
                        handle_id
                    );
                    return Ok(stream);
                }
            }
            let stream = self
                .inner
                .connect_tcp(&Address::DomainNameAddress("MUX_CONN".to_string(), 0))
                .await?;
            let handle = MuxHandle::new(stream);
            let handle_id = new_key(&handlers, &self.handle_id_hint);
            handlers.insert(handle_id, handle);
            log::debug!("new stream spawned for mux");
        }
    }
}

#[async_trait]
impl<T: ProxyConnector> ProxyConnector for MuxConnector<T> {
    type TS = MuxStream;
    type US = MuxUdpStream;

    async fn connect_tcp(&self, addr: &Address) -> io::Result<Self::TS> {
        let mut stream = self.spawn_mux_stream().await?;
        RequestHeader::new(Command::TcpConnect, addr)
            .write_to(&mut stream)
            .await?;
        return Ok(stream);
    }

    async fn connect_udp(&self) -> io::Result<Self::US> {
        let mut stream = self.spawn_mux_stream().await?;
        RequestHeader::new(
            Command::TcpConnect,
            &Address::DomainNameAddress("UDP_CONN".to_string(), 0),
        )
        .write_to(&mut stream)
        .await?;
        Ok(MuxUdpStream { inner: stream })
    }
}
