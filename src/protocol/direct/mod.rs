use std::{io, pin::Pin, task::Context, task::Poll};

use async_trait::async_trait;
use pin_project::pin_project;
use smol::net::{TcpStream, UdpSocket};
use smol::prelude::*;

use super::ProxyTcpStream;
use crate::protocol::{Address, ProxyUdpStream, UdpRead, UdpWrite};

pub mod connector;

#[pin_project]
pub struct DirectTcpStream {
    #[pin]
    inner: TcpStream,
}

impl AsyncRead for DirectTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for DirectTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<io::Result<()>> {
        self.project().inner.poll_close(cx)
    }
}

impl ProxyTcpStream for DirectTcpStream {}

#[pin_project]
#[derive(Clone)]
pub struct DirectUdpStream {
    #[pin]
    inner: UdpSocket,
}

#[async_trait]
impl UdpRead for DirectUdpStream {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let (size, addr) = self.inner.recv_from(buf).await?;
        Ok((size, Address::SocketAddress(addr)))
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
