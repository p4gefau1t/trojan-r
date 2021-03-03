use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::new_error;
use crate::protocol::Address;
use std::io;

pub mod consts {
    pub const CMD_TCP_CONNECT: u8 = 0x01;
    pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
}

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
            Command::TcpConnect => consts::CMD_TCP_CONNECT,
            Command::UdpAssociate => consts::CMD_UDP_ASSOCIATE,
        }
    }

    #[inline]
    fn from_u8(code: u8) -> io::Result<Command> {
        match code {
            consts::CMD_TCP_CONNECT => Ok(Command::TcpConnect),
            consts::CMD_UDP_ASSOCIATE => Ok(Command::UdpAssociate),
            _ => Err(new_error(format!("invalid request command: {}", code))),
        }
    }
}

pub struct SimpleSocksRequestHeader {
    pub command: Command,
    pub address: Address,
}

impl SimpleSocksRequestHeader {
    pub fn new(command: Command, address: &Address) -> Self {
        Self {
            command,
            address: address.clone(),
        }
    }

    pub async fn read_from<R>(stream: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut cmd = [0u8; 1];
        stream.read_exact(&mut cmd).await?;
        let command = Command::from_u8(cmd[0])?;
        let address = Address::read_from_stream(stream).await?;
        Ok(Self { command, address })
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let cmd = [self.command.as_u8()];
        w.write(&cmd).await?;
        self.address.write_to_stream(w).await?;
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
pub struct SimpleSocksUdpHeader {
    pub address: Address,
    pub payload_len: u16,
}

impl SimpleSocksUdpHeader {
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
        Ok(())
    }
}
