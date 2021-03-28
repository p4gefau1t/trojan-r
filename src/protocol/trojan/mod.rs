use crate::error::Error;
use async_trait::async_trait;
use bytes::BufMut;
use sha2::{Digest, Sha224};
use std::{fmt::Formatter, io, str};
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use super::{Address, ProxyTcpStream, ProxyUdpStream, UdpRead, UdpWrite};

use serde::{de, Deserialize, Deserializer};

pub mod acceptor;
pub mod connector;

const HASH_STR_LEN: usize = 56;

fn new_error<T: ToString>(message: T) -> io::Error {
    Error::new(format!("trojan: {}", message.to_string())).into()
}

/// trojan header password field
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Password(String);

impl Password {
    /// Creates a trojan request password field from serde deserialize.
    pub fn new(pwd: &str) -> Password {
        // create a Sha224 object
        let mut hasher = Sha224::new();

        // write input password.
        hasher.update(pwd);

        // read hash digest and consume hasher, then construct a valid
        //utf-8 string which every character is hex.
        let password = hasher
            .finalize()
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect();
        Password(password)
    }

    /// create password from a bytes slice
    pub fn read_from(passwd_buf: &[u8]) -> io::Result<Password> {
        match str::from_utf8(passwd_buf) {
            Ok(s) => Ok(Password(String::from(s))),
            Err(_) => Err(new_error(format!(
                "invalid password hash: {}",
                String::from_utf8_lossy(passwd_buf)
            ))),
        }
    }
}

impl<'d> Deserialize<'d> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'d>>::Error>
    where
        D: Deserializer<'d>,
    {
        struct PasswordVisitor;

        impl<'d> de::Visitor<'d> for PasswordVisitor {
            type Value = Password;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("expect 'valid password'")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Password::new(v))
            }
        }

        deserializer.deserialize_str(PasswordVisitor)
    }
}

const CMD_TCP_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

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
enum RequestHeader {
    TcpConnect(Password, Address),
    UdpAssociate(Password),
}

impl RequestHeader {
    async fn read_from<R>(
        stream: &mut R,
        password: &Password,
        first_packet: &mut Vec<u8>,
    ) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut hash_buf = [0u8; HASH_STR_LEN];
        let len = stream.read(&mut hash_buf).await?;
        if len != HASH_STR_LEN {
            first_packet.extend_from_slice(&hash_buf[..len]);
            return Err(new_error("first packet too short"));
        }

        let client_password = Password::read_from(&hash_buf[..])?;

        if &client_password != password {
            first_packet.extend_from_slice(&hash_buf);
            return Err(new_error(format!(
                "invalid password hash: {}",
                client_password.0
            )));
        }

        let mut crlf_buf = [0u8; 2];
        let mut cmd_buf = [0u8; 1];

        stream.read_exact(&mut crlf_buf).await?;
        stream.read_exact(&mut cmd_buf).await?;
        let addr = Address::read_from_stream(stream).await?;
        stream.read_exact(&mut crlf_buf).await?;

        match cmd_buf[0] {
            CMD_TCP_CONNECT => Ok(Self::TcpConnect(client_password, addr)),
            CMD_UDP_ASSOCIATE => Ok(Self::UdpAssociate(client_password)),
            _ => Err(new_error("invalid command")),
        }
    }

    async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let udp_dummy_addr = Address::new_dummy_address();
        let (password, addr, cmd) = match self {
            RequestHeader::TcpConnect(password, addr) => (password, addr, CMD_TCP_CONNECT),
            RequestHeader::UdpAssociate(password) => (password, &udp_dummy_addr, CMD_UDP_ASSOCIATE),
        };

        let header_len = HASH_STR_LEN + 2 + 1 + addr.serialized_len() + 2;
        let mut buf = Vec::with_capacity(header_len);

        let cursor = &mut buf;
        let crlf = b"\r\n";
        cursor.put_slice(password.0.as_bytes());
        cursor.put_slice(crlf);
        cursor.put_u8(cmd);
        addr.write_to_buf(cursor);
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
pub struct UdpHeader {
    pub address: Address,
    pub payload_len: u16,
}

impl UdpHeader {
    #[inline]
    pub fn new(addr: &Address, payload_len: usize) -> Self {
        Self {
            address: addr.clone(),
            payload_len: payload_len as u16,
        }
    }

    pub async fn read_from<R>(stream: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let addr = Address::read_from_stream(stream).await?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        let len = ((buf[0] as u16) << 8) | (buf[1] as u16);
        stream.read_exact(&mut buf).await?;
        log::debug!("udp addr={} len={}", addr, len);
        Ok(Self {
            address: addr,
            payload_len: len,
        })
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = Vec::with_capacity(self.address.serialized_len() + 2 + 1);
        let cursor = &mut buf;
        self.address.write_to_buf(cursor);
        cursor.put_u16(self.payload_len);
        cursor.put_slice(b"\r\n");
        w.write(&buf).await?;
        Ok(())
    }
}

pub struct TrojanUdpReader<T> {
    inner: T,
}

#[async_trait]
impl<T: AsyncRead + Unpin + Send + Sync> UdpRead for TrojanUdpReader<T> {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let header = UdpHeader::read_from(&mut self.inner).await?;
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
        let header = UdpHeader::new(addr, buf.len());
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
