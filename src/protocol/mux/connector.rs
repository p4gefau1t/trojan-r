use std::{
    collections::HashMap,
    io,
    sync::{atomic::AtomicU32, Arc},
};

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::Mutex;

use super::{new_key, MuxHandle, MuxStream, MuxUdpStream, RequestHeader};
use crate::protocol::{Address, ProxyConnector};

#[derive(Deserialize)]
pub struct MuxConnectorConfig {
    concurrent: usize,
}

pub struct MuxConnector<T: ProxyConnector> {
    handlers: Mutex<HashMap<u32, MuxHandle>>,
    concurrent: usize,
    inner: T,
    handle_id_hint: Arc<AtomicU32>,
}

impl<T: ProxyConnector> MuxConnector<T> {
    pub fn new(config: &MuxConnectorConfig, inner: T) -> io::Result<Self> {
        let handlers = Mutex::new(HashMap::new());
        if config.concurrent < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid parameters for mux",
            ));
        }
        Ok(Self {
            concurrent: config.concurrent,
            handlers,
            inner,
            handle_id_hint: Arc::new(AtomicU32::new(0)),
        })
    }
}

impl<T: ProxyConnector> MuxConnector<T> {
    async fn clean_mux_streams(&self) {
        let mut inactive_handle_id = Vec::new();
        let mut handlers = self.handlers.lock().await;
        for (handle_id, handle) in handlers.iter() {
            let num_streams = handle.established_streams().await;
            if num_streams == 0 || handle.is_closed() {
                inactive_handle_id.push(*handle_id);
            }
            log::debug!(
                "mux handle {:x}: {}/{}",
                *handle_id,
                num_streams,
                self.concurrent
            );
        }
        for handle_id in inactive_handle_id.iter() {
            let handle = handlers.remove(handle_id).unwrap();
            handle.close().await; // TODO dead lock?
        }
    }

    async fn spawn_mux_stream(&self) -> io::Result<MuxStream> {
        let mut handlers = self.handlers.lock().await;
        loop {
            for (handle_id, handle) in handlers.iter() {
                if handle.established_streams().await < self.concurrent {
                    let stream = match handle.connect().await {
                        Ok(stream) => stream,
                        Err(e) => {
                            log::error!(
                                "fail to spawn new mux stream from handle {:x}: {}",
                                *handle_id,
                                e
                            );
                            handle.close().await; // TODO dead lock?
                            continue;
                        }
                    };
                    log::debug!(
                        "mux stream {:x} spawned from handle {:x}",
                        stream.stream_id,
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
        self.clean_mux_streams().await;
        let header = RequestHeader::TcpConnect(addr.clone());
        header.write_to(&mut stream).await?;
        return Ok(stream);
    }

    async fn connect_udp(&self) -> io::Result<Self::US> {
        let mut stream = self.spawn_mux_stream().await?;
        self.clean_mux_streams().await;
        let header = RequestHeader::UdpAssociate;
        header.write_to(&mut stream).await?;
        Ok(MuxUdpStream { inner: stream })
    }
}
