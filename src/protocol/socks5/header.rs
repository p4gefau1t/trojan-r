use std::{
    fmt::{self, Debug},
    io::{self},
    u8, vec,
};

use super::super::Address;
use bytes::{BufMut, BytesMut};
use smol::prelude::*;

pub use self::consts::{
    SOCKS5_AUTH_METHOD_GSSAPI, SOCKS5_AUTH_METHOD_NONE, SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE,
    SOCKS5_AUTH_METHOD_PASSWORD,
};
use crate::protocol::socks5::new_error;

mod consts {
    pub const SOCKS5_VERSION: u8 = 0x05;

    pub const SOCKS5_AUTH_METHOD_NONE: u8 = 0x00;
    pub const SOCKS5_AUTH_METHOD_GSSAPI: u8 = 0x01;
    pub const SOCKS5_AUTH_METHOD_PASSWORD: u8 = 0x02;
    pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE: u8 = 0xff;

    pub const SOCKS5_CMD_TCP_CONNECT: u8 = 0x01;
    pub const SOCKS5_CMD_TCP_BIND: u8 = 0x02;
    pub const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

    pub const SOCKS5_ADDR_TYPE_IPV4: u8 = 0x01;
    pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
    pub const SOCKS5_ADDR_TYPE_IPV6: u8 = 0x04;

    pub const SOCKS5_REPLY_SUCCEEDED: u8 = 0x00;
    pub const SOCKS5_REPLY_GENERAL_FAILURE: u8 = 0x01;
    pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
    pub const SOCKS5_REPLY_HOST_UNREACHABLE: u8 = 0x04;
    pub const SOCKS5_REPLY_CONNECTION_REFUSED: u8 = 0x05;
    pub const SOCKS5_REPLY_TTL_EXPIRED: u8 = 0x06;
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

#[derive(Clone, Debug, Copy)]
pub enum Command {
    /// CONNECT command (TCP tunnel)
    TcpConnect,
    /// BIND command (Not supported in ShadowSocks)
    TcpBind,
    /// UDP ASSOCIATE command
    UdpAssociate,
}

impl Command {
    #[inline]
    fn as_u8(self) -> u8 {
        match self {
            Command::TcpConnect => consts::SOCKS5_CMD_TCP_CONNECT,
            Command::TcpBind => consts::SOCKS5_CMD_TCP_BIND,
            Command::UdpAssociate => consts::SOCKS5_CMD_UDP_ASSOCIATE,
        }
    }

    #[inline]
    fn from_u8(code: u8) -> Option<Command> {
        match code {
            consts::SOCKS5_CMD_TCP_CONNECT => Some(Command::TcpConnect),
            consts::SOCKS5_CMD_TCP_BIND => Some(Command::TcpBind),
            consts::SOCKS5_CMD_UDP_ASSOCIATE => Some(Command::UdpAssociate),
            _ => None,
        }
    }
}

/// SOCKS5 reply code
#[derive(Clone, Debug, Copy)]
pub enum Reply {
    Succeeded,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,

    OtherReply(u8),
}

impl Reply {
    #[inline]
    fn as_u8(self) -> u8 {
        match self {
            Reply::Succeeded => consts::SOCKS5_REPLY_SUCCEEDED,
            Reply::GeneralFailure => consts::SOCKS5_REPLY_GENERAL_FAILURE,
            Reply::ConnectionNotAllowed => consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            Reply::NetworkUnreachable => consts::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            Reply::HostUnreachable => consts::SOCKS5_REPLY_HOST_UNREACHABLE,
            Reply::ConnectionRefused => consts::SOCKS5_REPLY_CONNECTION_REFUSED,
            Reply::TtlExpired => consts::SOCKS5_REPLY_TTL_EXPIRED,
            Reply::CommandNotSupported => consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            Reply::AddressTypeNotSupported => consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
            Reply::OtherReply(c) => c,
        }
    }

    #[inline]
    fn from_u8(code: u8) -> Reply {
        match code {
            consts::SOCKS5_REPLY_SUCCEEDED => Reply::Succeeded,
            consts::SOCKS5_REPLY_GENERAL_FAILURE => Reply::GeneralFailure,
            consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED => Reply::ConnectionNotAllowed,
            consts::SOCKS5_REPLY_NETWORK_UNREACHABLE => Reply::NetworkUnreachable,
            consts::SOCKS5_REPLY_HOST_UNREACHABLE => Reply::HostUnreachable,
            consts::SOCKS5_REPLY_CONNECTION_REFUSED => Reply::ConnectionRefused,
            consts::SOCKS5_REPLY_TTL_EXPIRED => Reply::TtlExpired,
            consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED => Reply::CommandNotSupported,
            consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => Reply::AddressTypeNotSupported,
            _ => Reply::OtherReply(code),
        }
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Reply::Succeeded => write!(f, "Succeeded"),
            Reply::AddressTypeNotSupported => write!(f, "Address type not supported"),
            Reply::CommandNotSupported => write!(f, "Command not supported"),
            Reply::ConnectionNotAllowed => write!(f, "Connection not allowed"),
            Reply::ConnectionRefused => write!(f, "Connection refused"),
            Reply::GeneralFailure => write!(f, "General failure"),
            Reply::HostUnreachable => write!(f, "Host unreachable"),
            Reply::NetworkUnreachable => write!(f, "Network unreachable"),
            Reply::OtherReply(u) => write!(f, "Other reply ({})", u),
            Reply::TtlExpired => write!(f, "TTL expired"),
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
    /// Creates a request header
    pub fn new(cmd: Command, addr: Address) -> TcpRequestHeader {
        TcpRequestHeader {
            command: cmd,
            address: addr,
        }
    }

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

    /// Write data into a writer
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
        let TcpRequestHeader {
            ref address,
            ref command,
        } = *self;

        buf.put_slice(&[consts::SOCKS5_VERSION, command.as_u8(), 0x00]);
        address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    pub fn serialized_len(&self) -> usize {
        self.address.serialized_len() + 3
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
    /// SOCKS5 reply
    pub reply: Reply,
    /// Reply address
    pub address: Address,
}

impl TcpResponseHeader {
    /// Creates a response header
    pub fn new(reply: Reply, address: Address) -> TcpResponseHeader {
        TcpResponseHeader { reply, address }
    }

    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> io::Result<TcpResponseHeader>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 3];
        let _ = r.read_exact(&mut buf).await?;

        let ver = buf[0];
        let reply_code = buf[1];

        if ver != consts::SOCKS5_VERSION {
            return Err(new_error(format!("unsupported socks version {:#x}", ver)));
        }

        let address = Address::read_from_stream(r).await?;

        Ok(TcpResponseHeader {
            reply: Reply::from_u8(reply_code),
            address,
        })
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
        let TcpResponseHeader {
            ref reply,
            ref address,
        } = *self;
        buf.put_slice(&[consts::SOCKS5_VERSION, reply.as_u8(), 0x00]);
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
    /// Creates a handshake request
    pub fn new(methods: Vec<u8>) -> HandshakeRequest {
        HandshakeRequest { methods }
    }

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

    /// Write to a writer
    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let HandshakeRequest { ref methods } = *self;
        buf.put_slice(&[consts::SOCKS5_VERSION, methods.len() as u8]);
        buf.put_slice(&methods);
    }

    /// Get length of bytes
    pub fn serialized_len(&self) -> usize {
        2 + self.methods.len()
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

    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> io::Result<HandshakeResponse>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 2];
        let _ = r.read_exact(&mut buf).await?;

        let ver = buf[0];
        let met = buf[1];

        if ver != consts::SOCKS5_VERSION {
            use std::io::{Error, ErrorKind};
            let err = Error::new(
                ErrorKind::InvalidData,
                format!("unsupported socks version {:#x}", ver),
            );
            Err(err)
        } else {
            Ok(HandshakeResponse { chosen_method: met })
        }
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
