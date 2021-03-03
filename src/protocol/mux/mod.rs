use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes};
use futures_core::{ready, Future};
use futures_util::FutureExt;
use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{
        mpsc::{
            channel,
            error::{SendError, TrySendError},
            Receiver, Sender,
        },
        Mutex,
    },
    task::JoinHandle,
};

use std::{
    cmp::min,
    collections::HashMap,
    io::{self, Cursor},
    num::Wrapping,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use super::{Address, ProxyTcpStream, ProxyUdpStream, UdpRead, UdpWrite};
use crate::error::Error;

pub mod acceptor;
pub mod connector;

fn new_error<T: ToString>(message: T) -> io::Error {
    return Error::new(format!("mux: {}", message.to_string())).into();
}

const SMUX_VERSION: u8 = 1;
const HEADER_LEN: usize = 8;
const MAX_DATA_LEN: usize = 0xffff;

const CMD_SYNC: u8 = 0;
const CMD_FINISH: u8 = 1;
const CMD_PUSH: u8 = 2;
const CMD_NOP: u8 = 3;

const SHARED_CHANNEL_LEN: usize = 0x200;
const PRIVATE_CHANNEL_LEN: usize = 0x50;
const STREAM_CHANNEL_LEN: usize = 0x20;

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

struct RequestHeader {
    command: Command,
    address: Address,
}

impl RequestHeader {
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
struct UdpHeader {
    pub address: Address,
    pub payload_len: u16,
}

impl UdpHeader {
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

struct SyncFrame {
    stream_id: u32,
}

struct PushFrame {
    stream_id: u32,
    data: Bytes,
}

struct FinishFrame {
    stream_id: u32,
}

struct NopFrame {
    stream_id: u32,
}
enum MuxFrame {
    Sync(SyncFrame),
    Push(PushFrame),
    Finish(FinishFrame),
    Nop(NopFrame),
}

impl MuxFrame {
    async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        let (stream_id, command) = match self {
            MuxFrame::Sync(f) => (f.stream_id, CMD_SYNC),
            MuxFrame::Finish(f) => (f.stream_id, CMD_FINISH),
            MuxFrame::Nop(f) => (f.stream_id, CMD_NOP),
            MuxFrame::Push(f) => (f.stream_id, CMD_PUSH),
        };
        let mut buf = [0u8; HEADER_LEN];
        let mut cursor = &mut buf[..];
        let data_length = if let MuxFrame::Push(f) = self {
            f.data.len()
        } else {
            0
        };
        assert!(data_length <= MAX_DATA_LEN);
        cursor.put_u8(SMUX_VERSION);
        cursor.put_u8(command);
        cursor.put_u16(data_length as u16);
        cursor.put_u32(stream_id);
        writer.write(&buf).await?;
        if let MuxFrame::Push(f) = self {
            writer.write(&f.data).await?;
        }
        Ok(())
    }

    async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; HEADER_LEN];
        reader.read_exact(&mut buf).await?;

        let mut cursor = Cursor::new(buf);
        let version = cursor.get_u8();
        if version != SMUX_VERSION {
            return Err(new_error("invalid mux version"));
        }
        let command = cursor.get_u8();
        let length = cursor.get_u16();
        let stream_id = cursor.get_u32();

        let frame = match command {
            CMD_FINISH => MuxFrame::Finish(FinishFrame { stream_id }),
            CMD_NOP => MuxFrame::Nop(NopFrame { stream_id }),
            CMD_SYNC => MuxFrame::Sync(SyncFrame { stream_id }),
            CMD_PUSH => {
                let mut buf = Vec::with_capacity(length as usize);
                buf.resize(length as usize, 0);
                reader.read_exact(&mut buf).await?;
                MuxFrame::Push(PushFrame {
                    stream_id,
                    data: Bytes::from(buf),
                })
            }
            _ => return Err(new_error("invalid mux command")),
        };

        Ok(frame)
    }
}

fn new_key<T>(map: &HashMap<u32, T>, hint: &AtomicU32) -> u32 {
    let init_hint = hint.load(Ordering::Relaxed);
    let mut key = Wrapping(init_hint + 1);
    loop {
        if !map.contains_key(&key.0) {
            hint.store(key.0, Ordering::Relaxed);
            return key.0;
        }
        key.0 += 1;
        if key.0 == init_hint {
            panic!();
        }
    }
}

pub struct MuxStreamReadHalf {
    rx: Receiver<PushFrame>,
    read_buffer: Option<Bytes>,
}

impl AsyncRead for MuxStreamReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(read_buffer) = &mut self.read_buffer {
                if read_buffer.len() <= buf.remaining() {
                    buf.put_slice(read_buffer);
                    self.read_buffer = None;
                } else {
                    let len = buf.remaining();
                    buf.put_slice(&read_buffer[..len]);
                    read_buffer.advance(len);
                }
                return Poll::Ready(Ok(()));
            }
            if let Some(f) = ready!(self.rx.poll_recv(cx)) {
                self.read_buffer = Some(f.data);
            } else {
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
        }
    }
}

pub struct MuxStreamWriteHalf {
    tx: Sender<MuxFrame>,
    write_future:
        Option<Pin<Box<dyn Future<Output = Result<(), SendError<MuxFrame>>> + Send + Sync>>>,
    stream_id: u32,
    closed: bool,
}

impl AsyncWrite for MuxStreamWriteHalf {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        loop {
            if let Some(fut) = &mut self.write_future {
                if ready!(fut.poll_unpin(cx)).is_err() {
                    return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
                }
                self.write_future = None;
                return Poll::Ready(Ok(buf.len()));
            }

            let stream_id = self.stream_id;
            let frame = MuxFrame::Push(PushFrame {
                stream_id,
                data: Bytes::copy_from_slice(buf),
            });

            // FIXME horrible workaround
            if let Err(e) = self.tx.try_send(frame) {
                match e {
                    TrySendError::Full(f) => {
                        let tx = self.tx.clone();
                        let fut = Box::pin(async move {
                            tx.send(f).await?;
                            Ok(())
                        });
                        self.write_future = Some(fut);
                    }
                    TrySendError::Closed(_) => {
                        return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
                    }
                }
            } else {
                return Poll::Ready(Ok(buf.len()));
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        return Poll::Ready(Ok(()));
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.closed = true;
        let frame = MuxFrame::Finish(FinishFrame {
            stream_id: self.stream_id,
        });
        // FIXME horrible workaround
        if let Err(e) = self.tx.try_send(frame) {
            let tx = self.tx.clone();
            match e {
                TrySendError::Full(frame) => {
                    tokio::spawn(async move {
                        let _ = tx.send(frame).await;
                    });
                }
                TrySendError::Closed(_) => {}
            }
        }
        return Poll::Ready(Ok(()));
    }
}

pub struct MuxStream {
    read_half: MuxStreamReadHalf,
    write_half: MuxStreamWriteHalf,
}

impl MuxStream {
    fn stream_id(&self) -> u32 {
        self.write_half.stream_id
    }

    fn new(stream_id: u32, tx: Sender<MuxFrame>, rx: Receiver<PushFrame>) -> Self {
        MuxStream {
            read_half: MuxStreamReadHalf {
                rx,
                read_buffer: None,
            },
            write_half: MuxStreamWriteHalf {
                tx,
                stream_id,
                write_future: None,
                closed: false,
            },
        }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read_half).poll_read(cx, buf)
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.write_half).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.write_half).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.write_half).poll_shutdown(cx)
    }
}

impl ProxyTcpStream for MuxStream {}

#[async_trait]
impl UdpRead for MuxStreamReadHalf {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let udp_header = UdpHeader::read_from(self).await?;
        let len = min(udp_header.payload_len as usize, buf.len());
        self.read_exact(&mut buf[..len]).await?;
        Ok((len, udp_header.address))
    }
}

#[async_trait]
impl UdpWrite for MuxStreamWriteHalf {
    async fn write_to(&mut self, buf: &[u8], addr: &Address) -> io::Result<()> {
        let len = min(buf.len(), MAX_DATA_LEN);
        let udp_header = UdpHeader::new(addr, len);
        udp_header.write_to(self).await?;
        Ok(())
    }
}

pub struct MuxUdpStream {
    inner: MuxStream,
}

#[async_trait]
impl ProxyUdpStream for MuxUdpStream {
    type R = MuxStreamReadHalf;
    type W = MuxStreamWriteHalf;

    fn split(self) -> (Self::R, Self::W) {
        (self.inner.read_half, self.inner.write_half)
    }

    fn reunite(r: Self::R, w: Self::W) -> Self {
        MuxUdpStream {
            inner: MuxStream {
                read_half: r,
                write_half: w,
            },
        }
    }

    async fn close(mut self) -> io::Result<()> {
        self.inner.write_half.shutdown().await
    }
}

struct MuxHandle {
    read_handle: JoinHandle<io::Result<()>>,
    write_handle: JoinHandle<io::Result<()>>,
    write_tx: Sender<MuxFrame>,
    accept_stream_rx: Arc<Mutex<Receiver<MuxStream>>>,
    mux_map: Arc<Mutex<HashMap<u32, Sender<PushFrame>>>>,
    closed: Arc<AtomicBool>,
    stream_id_hint: Arc<AtomicU32>,
}

impl Drop for MuxHandle {
    fn drop(&mut self) {
        self.read_handle.abort();
        self.write_handle.abort();
    }
}

impl MuxHandle {
    fn new<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static>(inner: T) -> Self {
        let (mut r, mut w) = split(inner);
        let mux_map = Arc::new(Mutex::new(HashMap::new()));
        let (write_tx, mut write_rx) = channel(SHARED_CHANNEL_LEN);
        let (accept_stream_tx, accept_stream_rx) = channel(STREAM_CHANNEL_LEN);
        let closed = Arc::new(AtomicBool::new(false));
        let read_handle: JoinHandle<io::Result<()>> = {
            let write_tx = write_tx.clone();
            let mux_map = mux_map.clone();
            let closed = closed.clone();
            tokio::spawn(async move {
                loop {
                    let frame = MuxFrame::read_from(&mut r).await.map_err(|e| {
                        closed.store(true, Ordering::Relaxed);
                        log::error!("mux read error: {}", e);
                        e
                    })?;
                    match frame {
                        MuxFrame::Sync(f) => {
                            let stream_id = f.stream_id;
                            let (tx, rx) = channel(PRIVATE_CHANNEL_LEN);
                            let stream = MuxStream::new(stream_id, write_tx.clone(), rx);
                            mux_map.lock().await.insert(f.stream_id, tx);
                            accept_stream_tx
                                .send(stream)
                                .await
                                .map_err(|_| io::ErrorKind::ConnectionReset)?;
                        }
                        MuxFrame::Push(f) => {
                            let stream_id = f.stream_id;
                            let tx = {
                                let mut m = mux_map.lock().await;
                                if let Some(tx) = m.get_mut(&stream_id) {
                                    tx.clone()
                                } else {
                                    log::warn!("invalid frame recvd, stream_id={:x}", stream_id);
                                    continue;
                                }
                            };
                            if let Err(_) = tx.send(f).await {
                                log::warn!("frame recvd but the stream %{:x} is closed", stream_id);
                                mux_map.lock().await.remove(&stream_id);
                            }
                        }
                        MuxFrame::Finish(f) => {
                            let stream_id = f.stream_id;
                            mux_map.lock().await.remove(&stream_id);
                            log::debug!("remote shutdown stream {:x}", f.stream_id);
                        }
                        MuxFrame::Nop(_) => {}
                    }
                }
            })
        };
        let write_handle: JoinHandle<io::Result<()>> = {
            let mux_map = mux_map.clone();
            let closed = closed.clone();
            tokio::spawn(async move {
                loop {
                    if let Some(mut frame) = write_rx.recv().await {
                        match &mut frame {
                            MuxFrame::Push(p) => {
                                // oversized data
                                if p.data.len() > MAX_DATA_LEN {
                                    while p.data.len() > MAX_DATA_LEN {
                                        let new_data = p.data.split_off(MAX_DATA_LEN);
                                        let new_frame = MuxFrame::Push(PushFrame {
                                            stream_id: p.stream_id,
                                            data: new_data,
                                        });
                                        new_frame.write_to(&mut w).await.map_err(|e| {
                                            closed.store(true, Ordering::Relaxed);
                                            log::error!("mux write error: {}", e);
                                            e
                                        })?;
                                    }
                                }
                            }

                            MuxFrame::Finish(f) => {
                                log::debug!("local shutdown stream {:x}", f.stream_id);
                                mux_map.lock().await.remove(&f.stream_id);
                            }
                            _ => {}
                        }
                        frame.write_to(&mut w).await.map_err(|e| {
                            closed.store(true, Ordering::Relaxed);
                            log::error!("mux write error: {}", e);
                            e
                        })?;
                    } else {
                        log::debug!("all write_tx are closed",);
                        return Ok(());
                    }
                }
            })
        };
        Self {
            read_handle,
            write_handle,
            write_tx,
            accept_stream_rx: Arc::new(Mutex::new(accept_stream_rx)),
            mux_map,
            closed,
            stream_id_hint: Arc::new(AtomicU32::new(0)),
        }
    }

    async fn generate_stream_id(&self) -> u32 {
        let mux_map = self.mux_map.lock().await;
        let stream_id = new_key(&mux_map, &self.stream_id_hint);
        stream_id
    }

    async fn connect(&self) -> io::Result<MuxStream> {
        let stream_id = self.generate_stream_id().await;
        let (tx, rx) = channel(PRIVATE_CHANNEL_LEN);
        let frame = MuxFrame::Sync(SyncFrame { stream_id });
        self.write_tx
            .send(frame)
            .await
            .map_err(|_| io::ErrorKind::ConnectionReset)?;
        let stream = MuxStream::new(stream_id, self.write_tx.clone(), rx);
        self.mux_map.lock().await.insert(stream_id, tx);
        Ok(stream)
    }

    async fn accept(&self) -> io::Result<MuxStream> {
        if let Some(stream) = self.accept_stream_rx.lock().await.recv().await {
            Ok(stream)
        } else {
            Err(io::ErrorKind::ConnectionReset.into())
        }
    }

    async fn established_streams(&self) -> usize {
        self.mux_map.lock().await.len()
    }
}

#[tokio::test]
async fn test_read_half() {
    let (tx, rx) = channel(0x10);
    let mut r = MuxStreamReadHalf {
        rx,
        read_buffer: None,
    };
    let payload = b"1234123123213123abcd";
    let handle = tokio::spawn(async move {
        let mut buf = Vec::new();
        buf.resize(payload.len() * 2, 0);
        for _ in 0..500 {
            r.read_exact(&mut buf).await.unwrap();
            assert!(&buf[..payload.len()] == payload);
            assert!(&buf[payload.len()..] == payload);
        }
    });
    for _ in 0..1000 {
        let _ = tx
            .send(PushFrame {
                stream_id: 0,
                data: Bytes::copy_from_slice(payload),
            })
            .await;
    }
    handle.await.unwrap();
}
