use super::{new_error, BinaryWsStream};
use crate::protocol::{AcceptResult, DummyUdpStream, ProxyAcceptor};
use async_trait::async_trait;
use log::error;
use serde::Deserialize;
use std::io;
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{
        handshake::server::{Callback, ErrorResponse, Request, Response},
        http::StatusCode,
    },
};

#[derive(Deserialize)]
pub struct WebSocketAcceptorConfig {
    path: String,
}

struct WebSocketCallback {
    path: String,
}

impl Callback for WebSocketCallback {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        if request.uri().to_string() != self.path {
            let mut resp = ErrorResponse::new(None);
            *resp.status_mut() = StatusCode::NOT_FOUND;
            error!(
                "invalid websocket path: {}, expected: {}",
                request.uri(),
                self.path
            );
            Err(resp)
        } else {
            Ok(response)
        }
    }
}

pub struct WebSocketAcceptor<T: ProxyAcceptor> {
    path: String,
    inner: T,
}

#[async_trait]
impl<T: ProxyAcceptor> ProxyAcceptor for WebSocketAcceptor<T> {
    type TS = BinaryWsStream<T::TS>;
    type US = DummyUdpStream;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        let (stream, addr) = self.inner.accept().await?.unwrap_tcp_with_addr();
        let stream = accept_hdr_async_with_config(
            stream,
            WebSocketCallback {
                path: self.path.clone(),
            },
            None,
        )
        .await
        .map_err(|e| new_error(e))?;
        let stream = BinaryWsStream::new(stream);
        Ok(AcceptResult::Tcp((stream, addr)))
    }
}

impl<T: ProxyAcceptor> WebSocketAcceptor<T> {
    pub fn new(config: &WebSocketAcceptorConfig, inner: T) -> io::Result<Self> {
        Ok(Self {
            inner,
            path: config.path.clone(),
        })
    }
}
