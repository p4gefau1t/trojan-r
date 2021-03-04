use std::{io, pin::Pin, sync::Arc, task::Context, task::Poll};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, UdpSocket},
};

use super::ProxyTcpStream;
use crate::protocol::{Address, ProxyUdpStream, UdpRead, UdpWrite};

pub mod connector;

pub struct DirectTcpStream {
    inner: TcpStream,
}

impl DirectTcpStream {
    pub fn new(inner: TcpStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for DirectTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DirectTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl ProxyTcpStream for DirectTcpStream {}

#[derive(Clone)]
pub struct DirectUdpStream {
    inner: Arc<UdpSocket>,
}

#[async_trait]
impl UdpRead for DirectUdpStream {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let (len, addr) = self.inner.recv_from(buf).await?;
        Ok((len, Address::SocketAddress(addr)))
    }
}

#[async_trait]
impl UdpWrite for DirectUdpStream {
    async fn write_to(&mut self, buf: &[u8], addr: &Address) -> io::Result<()> {
        let _ = self.inner.send_to(buf, addr.to_string()).await?;
        Ok(())
    }
}

#[async_trait]
impl ProxyUdpStream for DirectUdpStream {
    type R = Self;
    type W = Self;

    fn split(self) -> (Self::R, Self::W) {
        (self.clone(), self)
    }

    fn reunite(r: Self::R, _: Self::W) -> Self {
        r
    }

    async fn close(self) -> io::Result<()> {
        Ok(())
    }
}
