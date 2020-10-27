use std::{
    fmt::Debug,
    io::{self},
    u8, vec,
};

use super::super::Address;
use bytes::{BufMut, BytesMut};
use smol::prelude::*;

use crate::protocol::socks5::new_error;

pub mod consts {
    pub const SOCKS5_VERSION: u8 = 0x05;

    pub const SOCKS5_AUTH_METHOD_NONE: u8 = 0x00;

    pub const SOCKS5_CMD_TCP_CONNECT: u8 = 0x01;
    pub const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

    pub const SOCKS5_REPLY_SUCCEEDED: u8 = 0x00;
}

#[derive(Clone, Debug, Copy)]
pub enum Command {
    /// CONNECT command (TCP tunnel)
    TcpConnect,
    /// UDP ASSOCIATE command
    UdpAssociate,
}

impl Command {
    #[inline]
    fn from_u8(code: u8) -> Option<Command> {
        match code {
            consts::SOCKS5_CMD_TCP_CONNECT => Some(Command::TcpConnect),
            consts::SOCKS5_CMD_UDP_ASSOCIATE => Some(Command::UdpAssociate),
            _ => None,
        }
    }
}

/// TCP request header after handshake
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct TcpRequestHeader {
    /// SOCKS5 command
    pub command: Command,
    /// Remote address
    pub address: Address,
}

impl TcpRequestHeader {
    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> io::Result<TcpRequestHeader>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 3];
        let _ = r.read_exact(&mut buf).await?;

        let ver = buf[0];
        if ver != consts::SOCKS5_VERSION {
            return Err(new_error(format!("unsupported socks version {:#x}", ver)));
        }

        let cmd = buf[1];
        let command = match Command::from_u8(cmd) {
            Some(c) => c,
            None => {
                return Err(new_error(format!("unsupported command {:#x}", cmd)));
            }
        };

        let address = Address::read_from_stream(r).await?;
        Ok(TcpRequestHeader { command, address })
    }
}

/// TCP response header
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct TcpResponseHeader {
    /// Reply address
    pub address: Address,
}

impl TcpResponseHeader {
    /// Creates a response header
    pub fn new(address: Address) -> TcpResponseHeader {
        TcpResponseHeader { address }
    }

    /// Write to a writer
    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Writes to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let TcpResponseHeader { ref address } = *self;
        buf.put_slice(&[consts::SOCKS5_VERSION, consts::SOCKS5_REPLY_SUCCEEDED, 0x00]);
        address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    pub fn serialized_len(&self) -> usize {
        self.address.serialized_len() + 3
    }
}

/// SOCKS5 handshake request packet
///
/// ```plain
/// +----+----------+----------+
/// |VER | NMETHODS | METHODS  |
/// +----+----------+----------+
/// | 5  |    1     | 1 to 255 |
/// +----+----------+----------|
/// ```
#[derive(Clone, Debug)]
pub struct HandshakeRequest {
    pub methods: Vec<u8>,
}

impl HandshakeRequest {
    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> io::Result<HandshakeRequest>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 2];
        let _ = r.read_exact(&mut buf).await?;

        let ver = buf[0];
        let nmet = buf[1];

        if ver != consts::SOCKS5_VERSION {
            use std::io::{Error, ErrorKind};
            let err = Error::new(
                ErrorKind::InvalidData,
                format!("unsupported socks version {:#x}", ver),
            );
            return Err(err);
        }

        let mut methods = vec![0u8; nmet as usize];
        let _ = r.read_exact(&mut methods).await?;

        Ok(HandshakeRequest { methods })
    }
}

/// SOCKS5 handshake response packet
///
/// ```plain
/// +----+--------+
/// |VER | METHOD |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
/// ```
#[derive(Clone, Debug, Copy)]
pub struct HandshakeResponse {
    pub chosen_method: u8,
}

impl HandshakeResponse {
    /// Creates a handshake response
    pub fn new(cm: u8) -> HandshakeResponse {
        HandshakeResponse { chosen_method: cm }
    }

    /// Write to a writer
    pub async fn write_to<W>(self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(self, buf: &mut B) {
        buf.put_slice(&[consts::SOCKS5_VERSION, self.chosen_method]);
    }

    /// Length in bytes
    pub fn serialized_len(self) -> usize {
        2
    }
}

/// UDP ASSOCIATE request header
///
/// ```plain
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct UdpAssociateHeader {
    /// Fragment
    pub frag: u8,
    /// Remote address
    pub address: Address,
}

impl UdpAssociateHeader {
    /// Creates a header
    pub fn new(frag: u8, address: Address) -> UdpAssociateHeader {
        UdpAssociateHeader { frag, address }
    }

    pub fn read_from_buf(buf: &[u8]) -> io::Result<UdpAssociateHeader> {
        if buf.len() <= 3 {
            return Err(new_error("packet too short"));
        }
        let addr = Address::read_from_buf(&buf[3..])?;
        Ok(UdpAssociateHeader::new(0, addr))
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&[0x00, 0x00, 0x00]);
        self.address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    pub fn serialized_len(&self) -> usize {
        3 + self.address.serialized_len()
    }
}
