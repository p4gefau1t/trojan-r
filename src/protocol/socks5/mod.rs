use crate::error::Error;
use std::io;

pub mod acceptor;

use std::{fmt::Debug, u8, vec};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::Address;

const VERSION: u8 = 0x05;

const AUTH_METHOD_NONE: u8 = 0x00;

const CMD_TCP_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const REPLY_SUCCEEDED: u8 = 0x00;

fn new_error<T: ToString>(message: T) -> io::Error {
    return Error::new(format!("socks: {}", message.to_string())).into();
}

#[derive(Clone, Debug, Copy)]
enum Command {
    /// CONNECT command (TCP tunnel)
    TcpConnect,
    /// UDP ASSOCIATE command
    UdpAssociate,
}

impl Command {
    #[inline]
    fn from_u8(code: u8) -> Option<Command> {
        match code {
            CMD_TCP_CONNECT => Some(Command::TcpConnect),
            CMD_UDP_ASSOCIATE => Some(Command::UdpAssociate),
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
struct TcpRequestHeader {
    /// SOCKS5 command
    command: Command,
    /// Remote address
    address: Address,
}

impl TcpRequestHeader {
    /// Read from a reader
    async fn read_from<R>(r: &mut R) -> io::Result<TcpRequestHeader>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 3];
        let _ = r.read_exact(&mut buf).await?;

        let ver = buf[0];
        if ver != VERSION {
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
struct TcpResponseHeader {
    /// Reply address
    address: Address,
}

impl TcpResponseHeader {
    /// Creates a response header
    fn new(address: Address) -> TcpResponseHeader {
        TcpResponseHeader { address }
    }

    /// Write to a writer
    async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write(&buf).await?;
        Ok(())
    }

    /// Writes to buffer
    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let TcpResponseHeader { ref address } = *self;
        buf.put_slice(&[VERSION, REPLY_SUCCEEDED, 0x00]);
        address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    fn serialized_len(&self) -> usize {
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
struct HandshakeRequest {
    methods: Vec<u8>,
}

impl HandshakeRequest {
    /// Read from a reader
    async fn read_from<R>(r: &mut R) -> io::Result<HandshakeRequest>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 2];
        let _ = r.read_exact(&mut buf).await?;

        let ver = buf[0];
        let nmet = buf[1];

        if ver != VERSION {
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
struct HandshakeResponse {
    chosen_method: u8,
}

impl HandshakeResponse {
    /// Creates a handshake response
    fn new(cm: u8) -> HandshakeResponse {
        HandshakeResponse { chosen_method: cm }
    }

    /// Write to a writer
    async fn write_to<W>(self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write to buffer
    fn write_to_buf<B: BufMut>(self, buf: &mut B) {
        buf.put_slice(&[VERSION, self.chosen_method]);
    }

    /// Length in bytes
    fn serialized_len(self) -> usize {
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
struct UdpAssociateHeader {
    /// Fragment
    frag: u8,
    /// Remote address
    address: Address,
}

impl UdpAssociateHeader {
    /// Creates a header
    fn new(frag: u8, address: Address) -> UdpAssociateHeader {
        UdpAssociateHeader { frag, address }
    }

    fn read_from_buf(buf: &[u8]) -> io::Result<UdpAssociateHeader> {
        if buf.len() <= 3 {
            return Err(new_error("packet too short"));
        }
        let addr = Address::read_from_buf(&buf[3..])?;
        Ok(UdpAssociateHeader::new(0, addr))
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&[0x00, 0x00, 0x00]);
        self.address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    fn serialized_len(&self) -> usize {
        3 + self.address.serialized_len()
    }
}
