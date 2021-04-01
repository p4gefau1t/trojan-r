use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes};
use futures_core::{ready, Future};
use futures_util::FutureExt;
use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
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

use super::{trojan::UdpHeader, Address, ProxyTcpStream, ProxyUdpStream, UdpRead, UdpWrite};
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

enum RequestHeader {
    TcpConnect(Address),
    UdpAssociate,
}

impl RequestHeader {
    async fn read_from<R>(stream: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut cmd = [0u8; 1];
        stream.read_exact(&mut cmd).await?;
        let addr = Address::read_from_stream(stream).await?;
        match cmd[0] {
            CMD_TCP_CONNECT => Ok(Self::TcpConnect(addr)),
            CMD_UDP_ASSOCIATE => Ok(Self::UdpAssociate),
            _ => Err(new_error("invalid cmd")),
        }
    }

    async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let dummy_addr = Address::new_dummy_address();
        let (cmd, addr) = match self {
            RequestHeader::TcpConnect(addr) => (CMD_TCP_CONNECT, addr),
            RequestHeader::UdpAssociate => (CMD_UDP_ASSOCIATE, &dummy_addr),
        };
        let mut buf = Vec::with_capacity(1 + addr.serialized_len());
        let cursor = &mut buf;

        cursor.put_u8(cmd);
        addr.write_to_buf(cursor);

        w.write(&buf).await?;
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
        cursor.put_u16_le(data_length as u16);
        cursor.put_u32_le(stream_id);
        writer.write(&buf).await?;
        if let MuxFrame::Push(f) = self {
            writer.write(&f.data).await?;
        }
        writer.flush().await?;
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
        let length = cursor.get_u16_le();
        let stream_id = cursor.get_u32_le();

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

pub struct MuxStream {
    tx: Sender<MuxFrame>,
    stream_id: u32,
    rx: Receiver<PushFrame>,
    read_buffer: Option<Bytes>,
    write_buffer: Option<Bytes>,
    write_future:
        Option<Pin<Box<dyn Future<Output = Result<(), SendError<MuxFrame>>> + Send + Sync>>>,
    closed: Arc<AtomicBool>,
}

impl MuxStream {
    #[inline]
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

impl AsyncRead for MuxStream {
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

impl MuxStream {
    fn try_send_frame(&mut self, frame: MuxFrame) -> io::Result<bool> {
        if self.is_closed() {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
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
                    Ok(false)
                }
                TrySendError::Closed(_) => Err(io::ErrorKind::ConnectionReset.into()),
            }
        } else {
            Ok(true)
        }
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.is_closed() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        loop {
            if let Some(fut) = &mut self.write_future {
                if ready!(fut.poll_unpin(cx)).is_err() {
                    return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
                }
                self.write_future = None;
                if self.write_buffer.is_none() {
                    return Poll::Ready(Ok(buf.len()));
                }
            }

            let stream_id = self.stream_id;
            if let Some(mut data) = self.write_buffer.take() {
                let mut all_sent = true;
                while data.len() > MAX_DATA_LEN {
                    let fragment = data.split_off(MAX_DATA_LEN);
                    let frame = MuxFrame::Push(PushFrame {
                        stream_id,
                        data: fragment,
                    });
                    if !self.try_send_frame(frame)? {
                        // pending
                        all_sent = false;
                        break;
                    }
                }
                if !all_sent {
                    self.write_buffer = Some(data);
                    // poll write_future
                    continue;
                }
                // the last frame
                let frame = MuxFrame::Push(PushFrame { stream_id, data });
                if !self.try_send_frame(frame)? {
                    // poll write_future, return Ready once the future is done
                    self.write_buffer = None;
                    continue;
                } else {
                    return Poll::Ready(Ok(buf.len()));
                }
            }

            // self.write_buffer == None, first polling
            let data = Bytes::copy_from_slice(buf);
            self.write_buffer = Some(data);
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        return Poll::Ready(Ok(()));
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        loop {
            if let Some(fut) = &mut self.write_future {
                if ready!(fut.poll_unpin(cx)).is_err() {
                    return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
                }
                self.write_future = None;
                if self.write_buffer.is_none() {
                    break;
                }
            }
            let stream_id = self.stream_id;
            if let Some(mut data) = self.write_buffer.take() {
                let mut all_sent = true;
                while data.len() > MAX_DATA_LEN {
                    let fragment = data.split_off(MAX_DATA_LEN);
                    let frame = MuxFrame::Push(PushFrame {
                        stream_id,
                        data: fragment,
                    });
                    if !self.try_send_frame(frame)? {
                        all_sent = false;
                        break;
                    }
                }
                if !all_sent {
                    self.write_buffer = Some(data);
                    // poll write_future
                    continue;
                }
                // the last frame
                let frame = MuxFrame::Push(PushFrame { stream_id, data });
                if !self.try_send_frame(frame)? {
                    self.write_buffer = None;
                    continue;
                } else {
                    break;
                }
            }
            break;
        }

        self.closed.store(true, Ordering::Relaxed);
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

impl Drop for MuxStream {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Relaxed) {
            log::debug!("MuxStream was dropped without calling shutdown");
            self.closed.store(true, Ordering::Relaxed);
            let frame = MuxFrame::Finish(FinishFrame {
                stream_id: self.stream_id,
            });
            if let Err(e) = self.tx.try_send(frame) {
                match e {
                    TrySendError::Full(f) => {
                        let tx = self.tx.clone();
                        tokio::spawn(async move {
                            let _ = tx.send(f).await;
                        });
                    }
                    TrySendError::Closed(_) => {}
                }
            }
        }
    }
}

impl MuxStream {
    fn new(
        stream_id: u32,
        tx: Sender<MuxFrame>,
        rx: Receiver<PushFrame>,
    ) -> (Self, Arc<AtomicBool>) {
        let closed = Arc::new(AtomicBool::new(false));
        (
            MuxStream {
                rx,
                read_buffer: None,
                write_buffer: None,
                closed: closed.clone(),
                tx,
                stream_id,
                write_future: None,
            },
            closed,
        )
    }
}

impl ProxyTcpStream for MuxStream {}

#[async_trait]
impl UdpRead for ReadHalf<MuxStream> {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let udp_header = UdpHeader::read_from(self).await?;
        let len = min(udp_header.payload_len as usize, buf.len());
        self.read_exact(&mut buf[..len]).await?;
        Ok((len, udp_header.address))
    }
}

#[async_trait]
impl UdpWrite for WriteHalf<MuxStream> {
    async fn write_to(&mut self, buf: &[u8], addr: &Address) -> io::Result<()> {
        let len = min(buf.len(), MAX_DATA_LEN);
        let udp_header = UdpHeader::new(addr, len);
        udp_header.write_to(self).await?;
        self.write(buf).await?;
        Ok(())
    }
}

pub struct MuxUdpStream {
    inner: MuxStream,
}

#[async_trait]
impl ProxyUdpStream for MuxUdpStream {
    type R = ReadHalf<MuxStream>;
    type W = WriteHalf<MuxStream>;

    fn split(self) -> (Self::R, Self::W) {
        split(self.inner)
    }

    fn reunite(r: Self::R, w: Self::W) -> Self {
        MuxUdpStream {
            inner: r.unsplit(w),
        }
    }

    async fn close(mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }
}

struct MuxStreamHandle {
    closed: Arc<AtomicBool>,
    tx: Sender<PushFrame>,
}

impl MuxStreamHandle {
    #[inline]
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

struct MuxHandle {
    read_handle: JoinHandle<io::Result<()>>,
    write_handle: JoinHandle<io::Result<()>>,
    write_tx: Sender<MuxFrame>,
    accept_stream_rx: Arc<Mutex<Receiver<MuxStream>>>,
    mux_map: Arc<Mutex<HashMap<u32, MuxStreamHandle>>>,
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
                async fn echo_finish_frame(
                    stream_id: u32,
                    write_tx: &Sender<MuxFrame>,
                ) -> io::Result<()> {
                    let new_frame = MuxFrame::Finish(FinishFrame { stream_id });
                    write_tx
                        .send(new_frame)
                        .await
                        .map_err(|_| io::ErrorKind::ConnectionReset)?;
                    log::debug!("echo finish frame {:x}", stream_id);
                    Ok(())
                }
                let fut = {
                    let mux_map = mux_map.clone();
                    // stupid workaround
                    async move {
                        if false {
                            return Err(io::Error::new(io::ErrorKind::ConnectionReset, ""));
                        }
                        if false {
                            return Ok(());
                        }
                        loop {
                            let frame = MuxFrame::read_from(&mut r).await?;
                            match frame {
                                MuxFrame::Sync(f) => {
                                    let stream_id = f.stream_id;
                                    let (tx, rx) = channel(PRIVATE_CHANNEL_LEN);
                                    let (stream, closed) =
                                        MuxStream::new(stream_id, write_tx.clone(), rx);
                                    mux_map
                                        .lock()
                                        .await
                                        .insert(f.stream_id, MuxStreamHandle { tx, closed });
                                    accept_stream_tx
                                        .send(stream)
                                        .await
                                        .map_err(|_| io::ErrorKind::ConnectionReset)?;
                                }
                                MuxFrame::Push(f) => {
                                    let stream_id = f.stream_id;
                                    let tx = {
                                        let m = mux_map.lock().await;
                                        if let Some(handle) = m.get(&stream_id) {
                                            handle.tx.clone()
                                        } else {
                                            log::debug!(
                                                "invalid frame recvd, stream_id = {:x}",
                                                stream_id
                                            );
                                            continue;
                                        }
                                    };
                                    if let Err(_) = tx.send(f).await {
                                        log::debug!(
                                            "frame recvd but the stream {:x} is closed",
                                            stream_id
                                        );
                                        if let Some(_) = mux_map.lock().await.remove(&stream_id) {
                                            echo_finish_frame(stream_id, &write_tx).await?;
                                        }
                                    }
                                }
                                MuxFrame::Finish(f) => {
                                    let stream_id = f.stream_id;
                                    if let Some(stream_handle) =
                                        mux_map.lock().await.remove(&stream_id)
                                    {
                                        stream_handle.close();
                                        echo_finish_frame(stream_id, &write_tx).await?;
                                    }

                                    log::debug!("remote shutdown stream {:x}", stream_id);
                                }
                                MuxFrame::Nop(_) => {}
                            }
                        }
                    }
                };
                let _ = fut.await;
                closed.store(true, Ordering::Relaxed);
                mux_map.lock().await.clear();
                log::debug!("mux read err");
                Ok(())
            })
        };
        let write_handle: JoinHandle<io::Result<()>> = {
            let mux_map = mux_map.clone();
            let closed = closed.clone();
            tokio::spawn(async move {
                let fut = {
                    let mux_map = mux_map.clone();
                    async move {
                        // Stupid workaround
                        if false {
                            return Err(io::Error::new(io::ErrorKind::ConnectionReset, ""));
                        }
                        loop {
                            if let Some(mut frame) = write_rx.recv().await {
                                match &mut frame {
                                    MuxFrame::Push(p) => {
                                        assert!(p.data.len() < MAX_DATA_LEN);
                                    }
                                    MuxFrame::Finish(f) => {
                                        log::debug!("local shutdown stream {:x}", f.stream_id);
                                        if let None = mux_map.lock().await.remove(&f.stream_id) {
                                            continue;
                                        }
                                    }
                                    _ => {}
                                }
                                frame.write_to(&mut w).await?;
                            } else {
                                log::debug!("all write_tx are closed",);
                                return Ok(());
                            }
                        }
                    }
                };
                if let Err(e) = fut.await {
                    log::error!("mux write err {}", e);
                    closed.store(true, Ordering::Relaxed);
                }
                mux_map.lock().await.clear();
                Ok(())
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
        let (stream, closed) = MuxStream::new(stream_id, self.write_tx.clone(), rx);
        self.mux_map
            .lock()
            .await
            .insert(stream_id, MuxStreamHandle { closed, tx });
        Ok(stream)
    }

    async fn accept(&self) -> io::Result<MuxStream> {
        if let Some(stream) = self.accept_stream_rx.lock().await.recv().await {
            Ok(stream)
        } else {
            Err(io::ErrorKind::ConnectionReset.into())
        }
    }

    #[inline]
    async fn established_streams(&self) -> usize {
        self.mux_map.lock().await.len()
    }

    #[inline]
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    #[inline]
    async fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);

        // drop inner
        self.read_handle.abort();
        self.write_handle.abort();

        let mut mux_map = self.mux_map.lock().await;
        for (_, stream_handle) in mux_map.iter() {
            stream_handle.close();
        }
        mux_map.clear();
    }
}
