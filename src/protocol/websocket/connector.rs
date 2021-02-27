use super::{new_error, BinaryWsStream};
use crate::protocol::{DummyUdpStream, ProxyConnector};
use async_trait::async_trait;
use serde::Deserialize;
use std::io;
use tokio_tungstenite::{
    client_async,
    tungstenite::http::{StatusCode, Uri},
};

#[derive(Deserialize)]
pub struct WebSocketConnectorConfig {
    uri: String,
}

pub struct WebSocketConnector<T: ProxyConnector> {
    uri: Uri,
    inner: T,
}

#[async_trait]
impl<T: ProxyConnector> ProxyConnector for WebSocketConnector<T> {
    type TS = BinaryWsStream<T::TS>;
    type US = DummyUdpStream;

    async fn connect_tcp(&self, addr: &crate::protocol::Address) -> io::Result<Self::TS> {
        let stream = self.inner.connect_tcp(addr).await?;
        let (stream, resp) = client_async(&self.uri, stream)
            .await
            .map_err(|e| new_error(e))?;
        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(new_error(format!("bad status: {}", resp.status())));
        }
        let stream = BinaryWsStream::new(stream);
        Ok(stream)
    }

    async fn connect_udp(&self) -> io::Result<Self::US> {
        unimplemented!()
    }
}

impl<T: ProxyConnector> WebSocketConnector<T> {
    pub fn new(config: &WebSocketConnectorConfig, inner: T) -> io::Result<Self> {
        let uri = config.uri.parse().map_err(|e| new_error(e))?;
        Ok(Self { inner, uri })
    }
}
