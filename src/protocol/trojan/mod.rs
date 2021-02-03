use crate::error::Error;
use crate::protocol::trojan::header::TrojanUdpHeader;
use crate::protocol::{Address, ProxyTcpStream, ProxyUdpStream, UdpRead, UdpWrite};
use async_trait::async_trait;
use futures::{
    io::{ReadHalf, WriteHalf},
    AsyncReadExt,
};
use sha2::{Digest, Sha224};
use smol::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use std::fmt::Write;
use std::io;

pub mod acceptor;
pub mod connector;
mod header;

fn new_error<T: ToString>(message: T) -> io::Error {
     Error::new(format!("trojan: {}", message.to_string())).into()
}

fn password_to_hash<T: ToString>(s: T) -> String {
    let mut hasher = Sha224::new();
    hasher.update(&s.to_string().into_bytes());
    let h = hasher.finalize();
    let mut s = String::with_capacity(56);
    for i in h {
        write!(s, "{:02x}", i).unwrap();
    }
    s
}

pub struct TrojanUdpReader<T> {
    inner: T,
}

#[async_trait]
impl<T: AsyncRead + Unpin + Send + Sync> UdpRead for TrojanUdpReader<T> {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let header = TrojanUdpHeader::read_from(&mut self.inner).await?;
        self.inner
            .read_exact(&mut buf[..header.payload_len as usize])
            .await?;
        Ok((header.payload_len as usize, header.address))
    }
}

pub struct TrojanUdpWriter<T> {
    inner: T,
}

#[async_trait]
impl<T: AsyncWrite + Unpin + Send + Sync> UdpWrite for TrojanUdpWriter<T> {
    async fn write_to(&mut self, buf: &[u8], addr: &Address) -> io::Result<()> {
        let header = TrojanUdpHeader::new(addr, buf.len());
        header.write_to(&mut self.inner).await?;
        self.inner.write(buf).await?;
        Ok(())
    }
}

pub struct TrojanUdpStream<T: ProxyTcpStream> {
    reader: TrojanUdpReader<ReadHalf<T>>,
    writer: TrojanUdpWriter<WriteHalf<T>>,
}

impl<T: ProxyTcpStream> TrojanUdpStream<T> {
    pub fn new(inner: T) -> Self {
        let (reader, writer) = inner.split();
        let reader = TrojanUdpReader { inner: reader };
        let writer = TrojanUdpWriter { inner: writer };
        Self { reader, writer }
    }
}

#[async_trait]
impl<T: ProxyTcpStream> UdpRead for TrojanUdpStream<T> {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        self.reader.read_from(buf).await
    }
}

#[async_trait]
impl<T: ProxyTcpStream> UdpWrite for TrojanUdpStream<T> {
    async fn write_to(&mut self, buf: &[u8], addr: &Address) -> io::Result<()> {
        self.writer.write_to(buf, addr).await
    }
}

#[async_trait]
impl<T: ProxyTcpStream> ProxyUdpStream for TrojanUdpStream<T> {
    type R = TrojanUdpReader<ReadHalf<T>>;
    type W = TrojanUdpWriter<WriteHalf<T>>;

    fn split(self) -> (Self::R, Self::W) {
        (self.reader, self.writer)
    }

    fn reunite(r: Self::R, w: Self::W) -> Self {
        Self {
            reader: r,
            writer: w,
        }
    }

    async fn close(self) -> io::Result<()> {
        let mut inner = self.reader.inner.reunite(self.writer.inner).unwrap();
        inner.close().await?;
        Ok(())
    }
}
