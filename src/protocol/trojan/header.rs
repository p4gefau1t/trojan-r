use super::new_error;
use crate::protocol::Address;
use smol::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::io;

mod consts {
    pub const TROJAN_CMD_TCP_CONNECT: u8 = 0x01;
    pub const TROJAN_CMD_UDP_ASSOCIATE: u8 = 0x03;
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
            Command::TcpConnect => consts::TROJAN_CMD_TCP_CONNECT,
            Command::UdpAssociate => consts::TROJAN_CMD_UDP_ASSOCIATE,
        }
    }

    #[inline]
    fn from_u8(code: u8) -> io::Result<Command> {
        match code {
            consts::TROJAN_CMD_TCP_CONNECT => Ok(Command::TcpConnect),
            consts::TROJAN_CMD_UDP_ASSOCIATE => Ok(Command::UdpAssociate),
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
pub struct TrojanRequestHeader {
    pub hash: String,
    pub command: Command,
    pub address: Address,
}

impl TrojanRequestHeader {
    pub fn new(hash: &String, command: Command, address: &Address) -> Self {
        // TODO use reference
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
        // TODO dirty code

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
        w.write_all(self.hash.as_bytes()).await?;
        let crlf = [0x0du8, 0x0a];
        w.write_all(&crlf).await?;
        let cmd = [self.command.as_u8()];
        w.write_all(&cmd).await?;
        self.address.write_to_stream(w).await?;
        w.write_all(&crlf).await?;
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
        let len = [
            ((self.payload_len & 0xff00) >> 8) as u8,
            (self.payload_len & 0xff) as u8,
        ];
        w.write_all(&len).await?;
        let crlf = [0x0du8, 0x0a];
        w.write_all(&crlf).await?;
        Ok(())
    }
}
