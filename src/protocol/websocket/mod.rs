pub mod acceptor;
pub mod connector;

use async_io_stream::IoStream;
use futures::{ready, AsyncRead, AsyncWrite, Sink, Stream};

use crate::error::Error;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use super::ProxyTcpStream;
use async_tungstenite::{tungstenite::Message, WebSocketStream};

struct AWsWrapper<T: AsyncRead + AsyncWrite + Unpin> {
    inner: WebSocketStream<T>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Stream for AWsWrapper<T> {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let message = ready!(Pin::new(&mut self.inner).poll_next(cx));
        if message.is_none() {
            return Poll::Ready(None);
        }
        let message = message.unwrap().map_err(|e| new_error(e))?;
        // binary only
        match message {
            Message::Binary(binary) => return Poll::Ready(Some(Ok(binary))),
            Message::Close(_) => {
                return Poll::Ready(None);
            }
            _ => return Poll::Ready(Some(Err(new_error("invalid message type")))),
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Sink<Vec<u8>> for AWsWrapper<T> {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_ready(cx)
            .map_err(|e| new_error(e))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let message = Message::Binary(item);
        Pin::new(&mut self.inner)
            .start_send(message)
            .map_err(|e| new_error(e))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|e| new_error(e))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let message = Message::Close(None);
        let inner = Pin::new(&mut self.inner);
        ready!(inner.poll_ready(cx)).map_err(|e| new_error(e))?;
        let inner = Pin::new(&mut self.inner);
        inner.start_send(message).map_err(|e| new_error(e))?;
        let inner = Pin::new(&mut self.inner);
        inner.poll_close(cx).map_err(|e| new_error(e))
    }
}

pub struct WebSocketRWStream<T: AsyncRead + AsyncWrite + Unpin> {
    inner: IoStream<AWsWrapper<T>, Vec<u8>>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocketRWStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WebSocketRWStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyTcpStream for WebSocketRWStream<T> {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> WebSocketRWStream<T> {
    pub fn new(inner: WebSocketStream<T>) -> Self {
        let wrapper = AWsWrapper { inner };
        Self {
            inner: IoStream::new(wrapper),
        }
    }
}

fn new_error<T: ToString>(message: T) -> io::Error {
    return Error::new(format!("websocket: {}", message.to_string())).into();
}
