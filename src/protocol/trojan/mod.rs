use crate::error::Error;
use async_trait::async_trait;
use bytes::BufMut;
use sha2::{Digest, Sha224};
use std::{fmt::Write, io};
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use super::{Address, ProxyTcpStream, ProxyUdpStream, UdpRead, UdpWrite};

pub mod acceptor;
pub mod connector;

fn new_error<T: ToString>(message: T) -> io::Error {
    return Error::new(format!("trojan: {}", message.to_string())).into();
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

const CMD_TCP_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub enum Command {
    /// CONNECT command (TCP tunnel)
    TcpConnect,
    /// UDP ASSOCIATE command
    UdpAssociate,
}

impl Command {
    #[inline]
    fn as_u8(self) -> u8 {
        match self {
            Command::TcpConnect => CMD_TCP_CONNECT,
            Command::UdpAssociate => CMD_UDP_ASSOCIATE,
        }
    }

    #[inline]
    fn from_u8(code: u8) -> io::Result<Command> {
        match code {
            CMD_TCP_CONNECT => Ok(Command::TcpConnect),
            CMD_UDP_ASSOCIATE => Ok(Command::UdpAssociate),
            _ => Err(new_error(format!("invalid request command: {}", code))),
        }
    }
}

/// ```plain
/// +-----------------------+---------+----------------+---------+----------+
/// | hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
/// +-----------------------+---------+----------------+---------+----------+
/// |          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
/// +-----------------------+---------+----------------+---------+----------+
///
/// where Trojan Request is a SOCKS5-like request:
///
/// +-----+------+----------+----------+
/// | CMD | ATYP | DST.ADDR | DST.PORT |
/// +-----+------+----------+----------+
/// |  1  |  1   | Variable |    2     |
/// +-----+------+----------+----------+
///
/// where:
///
/// o  CMD
/// o  CONNECT X'01'
/// o  UDP ASSOCIATE X'03'
/// o  ATYP address type of following address
/// o  IP V4 address: X'01'
/// o  DOMAINNAME: X'03'
/// o  IP V6 address: X'04'
/// o  DST.ADDR desired destination address
/// o  DST.PORT desired destination port in network octet order
/// ```
struct RequestHeader {
    hash: String,
    command: Command,
    address: Address,
}

impl RequestHeader {
    pub fn new(hash: &String, command: Command, address: &Address) -> Self {
        Self {
            hash: hash.clone(),
            command,
            address: address.clone(),
        }
    }

    pub async fn read_from<R>(
        stream: &mut R,
        valid_hash: &String,
        first_packet: &mut Vec<u8>,
    ) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut hash_buf = [0u8; 56];
        let size = stream.read(&mut hash_buf).await?;
        if size != 56 {
            first_packet.extend_from_slice(&hash_buf[..size]);
            return Err(new_error("first packet too short"));
        }

        let hash = String::from_utf8(hash_buf[..].to_vec()).map_err(|e| {
            first_packet.extend_from_slice(&hash_buf[..]);
            new_error(format!("failed to convert hash to utf8 {}", e.to_string()))
        })?;

        if !(valid_hash == &hash) {
            first_packet.extend_from_slice(&hash_buf[..]);
            return Err(new_error(format!("invalid password hash: {}", hash)));
        }

        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;

        let mut cmd = [0u8; 1];
        stream.read_exact(&mut cmd).await?;
        let command = Command::from_u8(cmd[0])?;
        let address = Address::read_from_stream(stream).await?;

        stream.read_exact(&mut crlf).await?;
        Ok(Self {
            hash,
            command,
            address,
        })
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let header_len = 56 + 2 + 1 + self.address.serialized_len() + 2;
        let mut buf = Vec::with_capacity(header_len);

        let cursor = &mut buf;
        let crlf = b"\r\n";
        cursor.put_slice(self.hash.as_bytes());
        cursor.put_slice(crlf);
        cursor.put_u8(self.command.as_u8());
        self.address.write_to_buf(cursor);
        cursor.put_slice(crlf);

        w.write(&buf).await?;
        Ok(())
    }
}

/// ```plain
/// +------+----------+----------+--------+---------+----------+
/// | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
/// +------+----------+----------+--------+---------+----------+
/// |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
/// +------+----------+----------+--------+---------+----------+
/// ```
pub struct TrojanUdpHeader {
    pub address: Address,
    pub payload_len: u16,
}

impl TrojanUdpHeader {
    pub fn new(address: &Address, payload_len: usize) -> Self {
        Self {
            address: address.clone(),
            payload_len: payload_len as u16,
        }
    }

    pub async fn read_from<R>(stream: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let address = Address::read_from_stream(stream).await?;
        log::debug!("udp addr read: {}", address);
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let len = ((len[0] as u16) << 8) | (len[1] as u16);
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
        Ok(Self {
            address,
            payload_len: len,
        })
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        self.address.write_to_stream(w).await?;
        self.payload_len.to_be_bytes();
        w.write(&self.payload_len.to_be_bytes()).await?;
        let crlf = b"\r\n";
        w.write(crlf).await?;
        Ok(())
    }
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
        let (reader, writer) = split(inner);
        let reader = TrojanUdpReader { inner: reader };
        let writer = TrojanUdpWriter { inner: writer };
        Self { reader, writer }
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
        let mut inner = self.reader.inner.unsplit(self.writer.inner);
        inner.shutdown().await?;
        Ok(())
    }
}
