//! CF media transport, ported from Flowseal 1.12.0 (3fc8b9e).
//! Each origin shares an H2 client. Native channels own and cancel their requests.
use crate::cfproxy::{cf_prefers_tls, cf_timeout_active};
use crate::config::*;
use crate::crypto::TrackedStream;
use crate::{ldebug, lwarn};
use bytes::Bytes;
use parking_lot::Mutex;
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::{AbortHandle, JoinSet};
use tokio_util::sync::CancellationToken;

const MAX_PACKET: usize = 4 * 1024 * 1024;
const CHANNEL_REQUESTS: usize = 8;
const CHANNEL_BYTES: usize = 8 * 1024 * 1024;
const LANE_REQUESTS: usize = 64;
const LANE_BYTES: usize = 32 * 1024 * 1024;
const HISTORY_BYTES: usize = 64 * 1024;
const HISTORY_PACKETS: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(65);
const SETUP_TIMEOUT: Duration = Duration::from_secs(8);
const COOLDOWN: f64 = 30.0;

pub fn enabled() -> bool {
    CF_H2_MEDIA.load(Ordering::Relaxed)
        && CFPROXY_ENABLED.load(Ordering::Relaxed)
        && !DISABLE_SECURE.load(Ordering::Relaxed)
        && !FORCE_TEST_DC.load(Ordering::Relaxed)
}

#[derive(Debug)]
enum Error {
    Io(io::Error),
    Http(reqwest::Error),
    Invalid(&'static str),
    Capacity(&'static str),
    Transport(i32),
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Self::Http(error)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(fmt, "{}", error),
            Self::Http(error) => write!(fmt, "{}", error),
            Self::Invalid(message) | Self::Capacity(message) => write!(fmt, "{}", message),
            Self::Transport(code) => write!(fmt, "MTProto transport {}", code),
        }
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn plaintext<R: AsyncRead + Unpin>(
    reader: &mut R,
    cipher: &mut TrackedStream,
    count: usize,
) -> io::Result<Vec<u8>> {
    let mut data = vec![0; count];
    reader.read_exact(&mut data).await?;
    cipher.xor(&mut data);
    Ok(data)
}

async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    cipher: &mut TrackedStream,
    tag: u32,
) -> io::Result<Bytes> {
    let length = if tag == PROTO_TAG_ABRIDGED {
        let first = plaintext(reader, cipher, 1).await?[0] & 0x7f;
        let words = if first == 0x7f {
            let bytes = plaintext(reader, cipher, 3).await?;
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]) as usize
        } else {
            first as usize
        };
        words * 4
    } else {
        let bytes = plaintext(reader, cipher, 4).await?;
        (u32::from_le_bytes(bytes.try_into().unwrap()) & 0x7fff_ffff) as usize
    };
    let limit = MAX_PACKET + if tag == PROTO_TAG_SECURE { 256 } else { 0 };
    if !(24..=limit).contains(&length) {
        return Err(invalid("native packet size outside bounds"));
    }
    let mut body = plaintext(reader, cipher, length).await?;
    if tag == PROTO_TAG_SECURE {
        let (packet_length, padding_limit) = if body[..8] == [0; 8] {
            let content_length = u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize;
            (20 + content_length, 256)
        } else {
            (24 + (length - 24) / 16 * 16, 15)
        };
        if packet_length < 24 || packet_length > length || length - packet_length > padding_limit {
            return Err(invalid("invalid padded MTProto packet"));
        }
        body.truncate(packet_length);
    }
    if body.len() % 4 != 0 || body.len() > MAX_PACKET {
        return Err(invalid("unaligned MTProto packet"));
    }
    Ok(Bytes::from(body))
}

fn encode_reply(body: &[u8], tag: u32) -> io::Result<Vec<u8>> {
    if body.is_empty() || body.len() % 4 != 0 || body.len() > MAX_PACKET {
        return Err(invalid("invalid MTProto reply length"));
    }
    let mut frame = Vec::with_capacity(body.len() + 7);
    if tag == PROTO_TAG_ABRIDGED {
        let words = (body.len() / 4) as u32;
        if words < 0x7f {
            frame.push(words as u8);
        } else {
            frame.push(0x7f);
            frame.extend_from_slice(&words.to_le_bytes()[..3]);
        }
        frame.extend_from_slice(body);
    } else {
        let mut padding = [0; 3];
        rand::thread_rng().fill_bytes(&mut padding);
        let count = if tag == PROTO_TAG_SECURE {
            (padding[0] % 4) as usize
        } else {
            0
        };
        frame.extend_from_slice(&((body.len() + count) as u32).to_le_bytes());
        frame.extend_from_slice(body);
        frame.extend_from_slice(&padding[..count]);
    }
    Ok(frame)
}

struct Reservation {
    _requests: Option<OwnedSemaphorePermit>,
    _bytes: Option<OwnedSemaphorePermit>,
    lane: Arc<Lane>,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        drop(self._requests.take());
        drop(self._bytes.take());
        self.lane.changed.notify_waiters();
        self.lane.changed.notify_one();
    }
}
struct Reply {
    body: Bytes,
    // These permits stay with the queued response until native delivery finishes.
    _memory: Vec<OwnedSemaphorePermit>,
}

struct Pending {
    started: f64,
    receiving: AtomicBool,
    replayable: bool,
    retired: Weak<AtomicBool>,
    abort: AbortHandle,
}

struct Lane {
    client: reqwest::Client,
    url: String,
    requests: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
    reply_bytes: Arc<Semaphore>,
    pending: Mutex<HashMap<usize, Arc<Pending>>>,
    changed: Notify,
    failed_until: Mutex<f64>,
    next_request: AtomicUsize,
}
impl Lane {
    fn new(host: &str) -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .http2_prior_knowledge()
            .http2_initial_stream_window_size(256 * 1024)
            .http2_initial_connection_window_size(4 * 1024 * 1024)
            .pool_max_idle_per_host(1)
            .pool_idle_timeout(Duration::from_secs(60))
            .connect_timeout(SETUP_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()?;
        Ok(Self::with_client(client, format!("https://{}/api", host)))
    }
    fn with_client(client: reqwest::Client, url: String) -> Self {
        Self {
            client,
            url,
            requests: Arc::new(Semaphore::new(LANE_REQUESTS)),
            bytes: Arc::new(Semaphore::new(LANE_BYTES)),
            reply_bytes: Arc::new(Semaphore::new(LANE_BYTES)),
            pending: Default::default(),
            changed: Notify::new(),
            failed_until: Mutex::new(0.0),
            next_request: AtomicUsize::new(0),
        }
    }
    async fn preflight(&self) -> Result<(), Error> {
        let response = self.client.head(&self.url).send().await?;
        if response.version() != reqwest::Version::HTTP_2 {
            return Err(Error::Invalid("preflight requires HTTP/2"));
        }
        if response.status().is_success() || matches!(response.status().as_u16(), 405 | 501) {
            Ok(())
        } else {
            Err(Error::Invalid("CF /api preflight failed"))
        }
    }
    fn reserve(self: &Arc<Self>, size: usize) -> Option<Reservation> {
        let requests = self.requests.clone().try_acquire_owned().ok()?;
        let bytes = self
            .bytes
            .clone()
            .try_acquire_many_owned(size as u32)
            .ok()?;
        Some(Reservation {
            _requests: Some(requests),
            _bytes: Some(bytes),
            lane: self.clone(),
        })
    }
    fn rotate_capacity(&self) {
        let now = now_monotonic();
        let candidate = self
            .pending
            .lock()
            .values()
            .filter(|request| {
                request.replayable
                    && !request.receiving.load(Ordering::Acquire)
                    && request.retired.strong_count() > 0
                    && now - request.started >= 3.0
                    && now - request.started <= 30.0
                    && !request.abort.is_finished()
            })
            .min_by(|left, right| left.started.total_cmp(&right.started))
            .cloned();
        if let Some(request) = candidate {
            if let Some(retired) = request.retired.upgrade() {
                retired.store(true, Ordering::Release);
                request.abort.abort();
            }
        }
    }
    async fn post(
        &self,
        body: Bytes,
        state: Arc<Pending>,
        channel_memory: Arc<Semaphore>,
    ) -> Result<Reply, Error> {
        STATS.h2_requests.fetch_add(1, Ordering::Relaxed);
        let mut response = self
            .client
            .post(&self.url)
            .header("content-type", "application/octet-stream")
            .header("accept-encoding", "identity")
            .body(body)
            .send()
            .await?;
        if response.version() != reqwest::Version::HTTP_2 {
            return Err(Error::Invalid("CF /api downgraded HTTP version"));
        }
        let status = response.status().as_u16();
        if matches!(status, 403 | 404 | 429 | 444) {
            return Err(Error::Transport(-(status as i32)));
        }
        if status != 200 {
            return Err(Error::Invalid("CF /api status"));
        }
        if response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("text/html"))
        {
            return Err(Error::Invalid("CF /api returned HTML"));
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_PACKET as u64)
        {
            return Err(Error::Invalid("CF /api Content-Length exceeds bound"));
        }
        state.receiving.store(true, Ordering::Release);
        let mut data = Vec::new();
        let mut memory = vec![
            self.reply_bytes
                .clone()
                .try_acquire_many_owned(0)
                .map_err(|_| Error::Invalid("H2 lane closed"))?,
            channel_memory
                .clone()
                .try_acquire_many_owned(0)
                .map_err(|_| Error::Invalid("H2 channel closed"))?,
        ];
        while let Some(chunk) = response.chunk().await? {
            if data.len() + chunk.len() > MAX_PACKET {
                return Err(Error::Invalid("CF /api response exceeds bound"));
            }
            memory[0].merge(
                self.reply_bytes
                    .clone()
                    .try_acquire_many_owned(chunk.len() as u32)
                    .map_err(|_| Error::Capacity("H2 lane reply memory exhausted"))?,
            );
            memory[1].merge(
                channel_memory
                    .clone()
                    .try_acquire_many_owned(chunk.len() as u32)
                    .map_err(|_| Error::Capacity("H2 channel reply memory exhausted"))?,
            );
            data.extend_from_slice(&chunk);
        }
        if data.len() % 4 != 0 {
            return Err(Error::Invalid("unaligned CF /api reply"));
        }
        if data.len() == 4 {
            let code = i32::from_le_bytes(data[..].try_into().unwrap());
            if code < 0 {
                return Err(Error::Transport(code));
            }
        }
        Ok(Reply {
            body: data.into(),
            _memory: memory,
        })
    }
}

struct PoolEntry {
    lane: Option<Arc<Lane>>,
    failed_until: f64,
}
pub struct CfH2Pool {
    origins: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<PoolEntry>>>>,
    retry_after: Mutex<HashMap<i32, f64>>,
    cancel: CancellationToken,
}
impl CfH2Pool {
    pub fn new(cancel: CancellationToken) -> Self {
        Self {
            origins: Default::default(),
            retry_after: Default::default(),
            cancel,
        }
    }
    pub async fn open(&self, dc: i32) -> Option<Channel> {
        if !enabled()
            || !cf_prefers_tls()
            || !DC_DEFAULT_IPS.contains_key(&dc)
            || self.cancel.is_cancelled()
        {
            return None;
        }
        if self
            .retry_after
            .lock()
            .get(&dc)
            .is_some_and(|until| *until > now_monotonic())
        {
            return None;
        }
        tokio::select! {
            _ = self.cancel.cancelled() => None,
            result = tokio::time::timeout(SETUP_TIMEOUT, self.open_inner(dc)) => match result {
                Ok(channel) => channel,
                Err(_) => {
                    self.retry_after.lock().insert(dc, now_monotonic() + COOLDOWN);
                    STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                    None
                }
            }
        }
    }
    async fn open_inner(&self, dc: i32) -> Option<Channel> {
        let domains = crate::balancer::BALANCER.read().get_domains_for_dc(dc);
        {
            let mut origins = self.origins.lock().await;
            origins.retain(|host, entry| {
                let current = domains
                    .iter()
                    .any(|domain| host.ends_with(&format!(".{}", domain)));
                current
                    || entry.try_lock().map_or(true, |entry| {
                        entry
                            .lane
                            .as_ref()
                            .is_some_and(|lane| Arc::strong_count(lane) > 1)
                    })
            });
        }
        for base in domains {
            if cf_timeout_active(&base, true) {
                continue;
            }
            let host = format!("kws{}.{}", dc, base);
            let entry = self
                .origins
                .lock()
                .await
                .entry(host.clone())
                .or_insert_with(|| {
                    Arc::new(tokio::sync::Mutex::new(PoolEntry {
                        lane: None,
                        failed_until: 0.0,
                    }))
                })
                .clone();
            let mut entry = entry.lock().await;
            if entry.failed_until > now_monotonic() {
                continue;
            }
            if let Some(lane) = &entry.lane {
                if *lane.failed_until.lock() > now_monotonic() {
                    continue;
                }
            } else {
                let lane = Arc::new(Lane::new(&host).ok()?);
                // A cancelled preflight owns no retained client or driver.
                if let Err(error) = lane.preflight().await {
                    ldebug!("H2 preflight {} failed: {}", host, error);
                    STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                    entry.failed_until = now_monotonic() + COOLDOWN;
                    continue;
                }
                entry.lane = Some(lane);
            }
            crate::balancer::BALANCER
                .write()
                .update_domain_for_dc(dc, &base);
            return Some(Channel {
                lane: entry.lane.as_ref()?.clone(),
            });
        }
        None
    }
    pub async fn close(&self) {
        self.cancel.cancel();
        self.origins.lock().await.clear();
    }
}

struct Packet {
    body: Bytes,
    sent: f64,
    attempts: u8,
    last_attempt: f64,
    retired: Arc<AtomicBool>,
    reply_id: Option<Bytes>,
}
impl Packet {
    fn observe_reply(&mut self, reply: &[u8]) {
        let identifier = &reply[..reply.len().min(24)];
        if self.reply_id.as_deref() != Some(identifier) {
            // A Bytes slice would retain the full media response allocation.
            self.reply_id = Some(Bytes::copy_from_slice(identifier));
            self.attempts = 0;
        }
    }
}
struct Request {
    lane: Weak<Lane>,
    size: usize,
    lane_id: usize,
    packet: Option<usize>,
    replay: bool,
    state: Arc<Pending>,
}
impl Drop for Request {
    fn drop(&mut self) {
        self.state.abort.abort();
        if let Some(lane) = self.lane.upgrade() {
            lane.pending.lock().remove(&self.lane_id);
        }
    }
}
pub struct Channel {
    lane: Arc<Lane>,
}

impl Channel {
    pub async fn bridge<R, W>(
        self,
        mut reader: R,
        mut writer: W,
        tag: u32,
        mut decrypt: TrackedStream,
        mut encrypt: TrackedStream,
        cancel: CancellationToken,
    ) where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (uploads, mut upload_rx) = mpsc::channel(1);
        let (replies, mut reply_rx) = mpsc::channel::<Reply>(16);
        let queued = Arc::new(AtomicUsize::new(0));
        let queued_writer = queued.clone();
        let mut forwarding = JoinSet::new();
        let upload_task = forwarding.spawn(async move {
            loop {
                let packet = read_packet(&mut reader, &mut decrypt, tag).await?;
                if uploads.send(packet).await.is_err() {
                    return Ok::<(), io::Error>(());
                }
            }
        });
        forwarding.spawn(async move {
            while let Some(reply) = reply_rx.recv().await {
                let mut frame = encode_reply(&reply.body, tag)?;
                encrypt.xor(&mut frame);
                writer.write_all(&frame).await?;
                queued_writer.fetch_sub(1, Ordering::Release);
            }
            Ok::<(), io::Error>(())
        });
        let result = self
            .run(&mut upload_rx, &replies, &queued, &mut forwarding, &cancel)
            .await;
        if let Err(Error::Transport(code)) = result {
            upload_task.abort();
            let reply = Reply {
                body: Bytes::copy_from_slice(&code.to_le_bytes()),
                _memory: Vec::new(),
            };
            queued.fetch_add(1, Ordering::Release);
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                let _ = replies.send(reply).await;
                drop(replies);
                while forwarding.join_next().await.is_some() {}
            })
            .await;
        }
        forwarding.abort_all();
        while forwarding.join_next().await.is_some() {}
    }

    async fn run(
        &self,
        uploads: &mut mpsc::Receiver<Bytes>,
        replies: &mpsc::Sender<Reply>,
        queued: &AtomicUsize,
        forwarding: &mut JoinSet<io::Result<()>>,
        cancel: &CancellationToken,
    ) -> Result<(), Error> {
        let channel_memory = Arc::new(Semaphore::new(CHANNEL_BYTES));
        let mut requests = JoinSet::new();
        let mut active: HashMap<tokio::task::Id, Request> = HashMap::new();
        let mut history: HashMap<usize, Packet> = HashMap::new();
        let mut order = VecDeque::new();
        let mut next_packet = 0usize;
        let mut auth_key = [0; 8];
        let mut waiting: Option<Bytes> = None;
        let mut waiting_since = now_monotonic();
        let mut last_progress = now_monotonic();
        let mut next_recovery = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut request_bytes = 0usize;
        let result = loop {
            let now = now_monotonic();
            // Retain bounded exact ciphertext. Plaintext handshakes never enter history.
            while order
                .front()
                .is_some_and(|id| history.get(id).is_none_or(|p| now - p.sent > 30.0))
            {
                if let Some(id) = order.pop_front() {
                    history.remove(&id);
                }
            }
            if waiting.is_some()
                && active.len() < CHANNEL_REQUESTS
                && request_bytes + waiting.as_ref().unwrap().len() <= CHANNEL_BYTES
            {
                if let Some(reservation) = self.lane.reserve(waiting.as_ref().unwrap().len()) {
                    let body = waiting.take().unwrap();
                    let mut packet_id = None;
                    if body[..8] != [0; 8] && auth_key != body[..8] {
                        history.clear();
                        order.clear();
                        auth_key.copy_from_slice(&body[..8]);
                    }
                    if body[..8] != [0; 8] && body.len() <= HISTORY_BYTES {
                        packet_id = order
                            .iter()
                            .find(|id| history.get(id).is_some_and(|packet| packet.body == body))
                            .copied();
                        if packet_id.is_none() {
                            next_packet += 1;
                            packet_id = Some(next_packet);
                            history.insert(
                                next_packet,
                                Packet {
                                    body: body.clone(),
                                    sent: now,
                                    attempts: 0,
                                    last_attempt: 0.0,
                                    retired: Arc::new(AtomicBool::new(false)),
                                    reply_id: None,
                                },
                            );
                            order.push_back(next_packet);
                        }
                        while order.len() > HISTORY_PACKETS
                            || history.values().map(|p| p.body.len()).sum::<usize>() > HISTORY_BYTES
                        {
                            if let Some(id) = order.pop_front() {
                                history.remove(&id);
                            }
                        }
                    }
                    request_bytes += body.len();
                    self.spawn_request(
                        body,
                        packet_id,
                        false,
                        &history,
                        reservation,
                        channel_memory.clone(),
                        &mut requests,
                        &mut active,
                    );
                }
            }
            let can_upload = waiting.is_none();
            let recovery_active = !history.is_empty() || waiting.is_some();
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break Ok(()),
                _ = forwarding.join_next() => break Ok(()),
                completed = requests.join_next_with_id(), if !requests.is_empty() => {
                    let Some(completed) = completed else { continue; };
                    let id = match &completed { Ok((id, _)) => *id, Err(error) => error.id() };
                    let Some(request) = active.remove(&id) else { continue; };
                    self.lane.pending.lock().remove(&request.lane_id);
                    request_bytes -= request.size;
                    let response = match completed {
                        Ok((_, (_, result))) => result,
                        Err(error) if error.is_cancelled() => continue,
                        Err(_) => break Err(Error::Invalid("H2 request task failed")),
                    };
                    match response {
                        Ok(reply) => {
                            last_progress = now_monotonic();
                            if !reply.body.is_empty() {
                                if let Some(packet) = request.packet.and_then(|id| history.get_mut(&id)) {
                                    packet.observe_reply(&reply.body);
                                }
                                queued.fetch_add(1, Ordering::Release);
                                STATS.bytes_down.fetch_add(reply.body.len() as i64, Ordering::Relaxed);
                                if replies.try_send(reply).is_err() { break Err(Error::Invalid("native reply queue exhausted")); }
                            }
                        }
                        Err(error) => {
                            STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                            if !matches!(error, Error::Transport(_) | Error::Capacity(_)) { *self.lane.failed_until.lock() = now_monotonic() + COOLDOWN; }
                            lwarn!("H2 channel request failed: {}", error);
                            break Err(error);
                        }
                    }
                }
                packet = uploads.recv(), if can_upload => {
                    let Some(packet) = packet else { break Ok(()); };
                    waiting = Some(packet); waiting_since = now_monotonic();
                }
                _ = self.lane.changed.notified(), if waiting.is_some() => {},
                _ = tokio::time::sleep_until(next_recovery), if recovery_active => {
                    next_recovery = tokio::time::Instant::now() + Duration::from_secs(1);
                    if waiting.is_some() {
                        if now_monotonic() - waiting_since >= REQUEST_TIMEOUT.as_secs_f64() { break Err(Error::Invalid("H2 upload capacity timeout")); }
                        self.lane.rotate_capacity();
                    }
                    if queued.load(Ordering::Acquire) > 0 { continue; }
                    let now = now_monotonic();
                    let replays = active.values().filter(|request| request.replay).count();
                    for &id in &order {
                        let Some(packet) = history.get_mut(&id) else { continue; };
                        let originals: Vec<_> = active.values().filter(|request| request.packet == Some(id) && !request.replay).collect();
                        let overdue = packet.retired.load(Ordering::Acquire) || originals.iter().any(|request|
                            now - request.state.started >= 3.0 && !request.state.receiving.load(Ordering::Acquire));
                        let last = order.back() == Some(&id);
                        if packet.attempts >= 3 || now - packet.sent > 30.0 || now - packet.last_attempt < 2.0
                            || originals.iter().any(|request| request.state.receiving.load(Ordering::Acquire))
                            || active.values().any(|request| request.packet == Some(id) && request.replay)
                            || (!overdue && (!last || !active.is_empty() || now - last_progress < 1.0)) {
                            continue;
                        }
                        if replays >= 2 || active.len() >= CHANNEL_REQUESTS || request_bytes + packet.body.len() > CHANNEL_BYTES { break; }
                        let Some(reservation) = self.lane.reserve(packet.body.len()) else { break; };
                        let body = packet.body.clone();
                        packet.attempts += 1; packet.last_attempt = now;
                        STATS.h2_replays.fetch_add(1, Ordering::Relaxed);
                        request_bytes += body.len();
                        self.spawn_request(body, Some(id), true, &history, reservation, channel_memory.clone(), &mut requests, &mut active);
                        break;
                    }
                }
            }
        };
        requests.abort_all();
        while requests.join_next().await.is_some() {}
        for request in active.values() {
            self.lane.pending.lock().remove(&request.lane_id);
        }
        result
    }

    fn spawn_request(
        &self,
        body: Bytes,
        packet: Option<usize>,
        replay: bool,
        history: &HashMap<usize, Packet>,
        reservation: Reservation,
        memory: Arc<Semaphore>,
        requests: &mut JoinSet<(usize, Result<Reply, Error>)>,
        active: &mut HashMap<tokio::task::Id, Request>,
    ) {
        let lane = self.lane.clone();
        let lane_id = lane.next_request.fetch_add(1, Ordering::Relaxed);
        let retired = packet
            .and_then(|id| history.get(&id))
            .map(|p| Arc::downgrade(&p.retired))
            .unwrap_or_default();
        // Start behind a oneshot so metadata is installed before the request runs.
        let (ready, started) = tokio::sync::oneshot::channel();
        let size = body.len();
        let task = requests.spawn(async move {
            let state = started.await.expect("request metadata installed");
            let result = lane.post(body, state, memory).await;
            drop(reservation);
            (size, result)
        });
        let state = Arc::new(Pending {
            started: now_monotonic(),
            receiving: AtomicBool::new(false),
            replayable: packet.is_some(),
            retired,
            abort: task.clone(),
        });
        self.lane.pending.lock().insert(lane_id, state.clone());
        active.insert(
            task.id(),
            Request {
                lane: Arc::downgrade(&self.lane),
                size,
                lane_id,
                packet,
                replay,
                state: state.clone(),
            },
        );
        STATS.bytes_up.fetch_add(size as i64, Ordering::Relaxed);
        let _ = ready.send(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::new_aes_ctr;
    use tokio::net::TcpListener;

    fn cipher() -> TrackedStream {
        new_aes_ctr(&[7; 32], &[3; 16])
    }

    async fn decode_frame(frame: Vec<u8>, tag: u32) -> io::Result<Bytes> {
        let mut encrypted = frame;
        cipher().xor(&mut encrypted);
        read_packet(&mut encrypted.as_slice(), &mut cipher(), tag).await
    }

    #[tokio::test]
    async fn native_packet_framing_quick_ack_and_padding() {
        let body = vec![1; 24];
        let mut abridged = vec![0x80 | 6];
        abridged.extend_from_slice(&body);
        assert_eq!(
            decode_frame(abridged, PROTO_TAG_ABRIDGED).await.unwrap(),
            body
        );
        let mut extended = vec![0xff, 6, 0, 0];
        extended.extend_from_slice(&body);
        assert_eq!(
            decode_frame(extended, PROTO_TAG_ABRIDGED).await.unwrap(),
            body
        );
        for padding in 0..=256 {
            let mut plain = vec![0; 24];
            plain[16..20].copy_from_slice(&4u32.to_le_bytes());
            let mut frame = ((24 + padding) as u32 | 0x8000_0000).to_le_bytes().to_vec();
            frame.extend_from_slice(&plain);
            frame.resize(frame.len() + padding, 0xff);
            assert_eq!(decode_frame(frame, PROTO_TAG_SECURE).await.unwrap(), plain);
        }
        let mut oversized = ((MAX_PACKET + 1) as u32).to_le_bytes().to_vec();
        cipher().xor(&mut oversized);
        assert!(read_packet(
            &mut oversized.as_slice(),
            &mut cipher(),
            PROTO_TAG_INTERMEDIATE
        )
        .await
        .is_err());
        let error = encode_reply(&(-429i32).to_le_bytes(), PROTO_TAG_ABRIDGED).unwrap();
        assert_eq!(error, [vec![1], (-429i32).to_le_bytes().to_vec()].concat());
    }

    #[test]
    fn replay_history_releases_large_response_storage() {
        struct ResponseStorage {
            bytes: Vec<u8>,
            dropped: Arc<AtomicBool>,
        }
        impl AsRef<[u8]> for ResponseStorage {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        impl Drop for ResponseStorage {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let response = Bytes::from_owner(ResponseStorage {
            bytes: vec![1; MAX_PACKET],
            dropped: dropped.clone(),
        });
        let mut packet = Packet {
            body: Bytes::from_static(&[1; 24]),
            sent: 0.0,
            attempts: 2,
            last_attempt: 0.0,
            retired: Default::default(),
            reply_id: None,
        };
        packet.observe_reply(&response);
        drop(response);
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(packet.reply_id.as_ref().unwrap().len(), 24);
        assert_eq!(packet.attempts, 0);
    }

    struct Endpoint {
        lane: Arc<Lane>,
        cancel: CancellationToken,
        task: tokio::task::JoinHandle<()>,
        sockets: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
    }
    impl Endpoint {
        async fn start(status: u16, delay: Duration) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let sockets = Arc::new(AtomicUsize::new(0));
            let calls = Arc::new(AtomicUsize::new(0));
            let cancel = CancellationToken::new();
            let server_cancel = cancel.clone();
            let server_sockets = sockets.clone();
            let server_calls = calls.clone();
            let task = tokio::spawn(async move {
                let mut sessions = JoinSet::new();
                loop {
                    tokio::select! {
                        _ = server_cancel.cancelled() => break,
                        _ = sessions.join_next(), if !sessions.is_empty() => {},
                        accepted = listener.accept() => {
                            let (stream, _) = accepted.unwrap();
                            server_sockets.fetch_add(1, Ordering::Relaxed);
                            let calls = server_calls.clone();
                            sessions.spawn(async move {
                                let mut connection = h2::server::handshake(stream).await.unwrap();
                                let mut replies = JoinSet::new();
                                loop {
                                    tokio::select! {
                                        _ = replies.join_next(), if !replies.is_empty() => {},
                                        request = connection.accept() => {
                                            let Some(Ok((request, mut respond))) = request else { break; };
                                            let calls = calls.clone();
                                            replies.spawn(async move {
                                                if request.method() == http::Method::HEAD {
                                                    let _ = respond.send_response(http::Response::builder().status(501).body(()).unwrap(), true);
                                                    return;
                                                }
                                                calls.fetch_add(1, Ordering::Relaxed);
                                                let mut input = request.into_body();
                                                let mut body = Vec::new();
                                                while let Some(Ok(chunk)) = input.data().await {
                                                    input.flow_control().release_capacity(chunk.len()).unwrap();
                                                    body.extend_from_slice(&chunk);
                                                }
                                                tokio::time::sleep(delay).await;
                                                let response = http::Response::builder().status(status)
                                                    .header("content-type", "application/octet-stream").body(()).unwrap();
                                                if let Ok(mut sender) = respond.send_response(response, status != 200) {
                                                    if status == 200 { let _ = sender.send_data(body.into(), true); }
                                                }
                                            });
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
                sessions.abort_all();
                while sessions.join_next().await.is_some() {}
            });
            let client = reqwest::Client::builder()
                .no_proxy()
                .http2_prior_knowledge()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .unwrap();
            let lane = Arc::new(Lane::with_client(client, format!("http://{}/api", address)));
            Self {
                lane,
                task,
                cancel,
                sockets,
                calls,
            }
        }
        async fn close(self) {
            self.cancel.cancel();
            self.task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn multiplexed_channels_share_connection_and_release_all_reservations() {
        let endpoint = Endpoint::start(200, Duration::ZERO).await;
        endpoint.lane.preflight().await.unwrap();
        let cancel = CancellationToken::new();
        let mut bridges = JoinSet::new();
        let mut clients = Vec::new();
        for value in [1, 2] {
            let (mut client, server) = tokio::io::duplex(4096);
            let (read, write) = tokio::io::split(server);
            let channel = Channel {
                lane: endpoint.lane.clone(),
            };
            bridges.spawn(channel.bridge(
                read,
                write,
                PROTO_TAG_INTERMEDIATE,
                cipher(),
                cipher(),
                cancel.clone(),
            ));
            let body = vec![value; 24];
            let mut frame = encode_reply(&body, PROTO_TAG_INTERMEDIATE).unwrap();
            cipher().xor(&mut frame);
            client.write_all(&frame).await.unwrap();
            clients.push((client, body));
        }
        for (client, expected) in &mut clients {
            let body = tokio::time::timeout(
                Duration::from_secs(3),
                read_packet(client, &mut cipher(), PROTO_TAG_INTERMEDIATE),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(body.as_ref(), expected);
        }
        assert_eq!(endpoint.sockets.load(Ordering::Relaxed), 1);
        cancel.cancel();
        while bridges.join_next().await.is_some() {}
        assert_eq!(endpoint.lane.requests.available_permits(), LANE_REQUESTS);
        assert_eq!(endpoint.lane.bytes.available_permits(), LANE_BYTES);
        assert_eq!(endpoint.lane.reply_bytes.available_permits(), LANE_BYTES);
        assert!(endpoint.lane.pending.lock().is_empty());
        endpoint.close().await;
    }

    #[tokio::test]
    async fn http_transport_error_reaches_native_client_before_eof() {
        let endpoint = Endpoint::start(429, Duration::ZERO).await;
        let (mut client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(server);
        let task = tokio::spawn(
            Channel {
                lane: endpoint.lane.clone(),
            }
            .bridge(
                read,
                write,
                PROTO_TAG_INTERMEDIATE,
                cipher(),
                cipher(),
                CancellationToken::new(),
            ),
        );
        let mut frame = encode_reply(&[1; 24], PROTO_TAG_INTERMEDIATE).unwrap();
        cipher().xor(&mut frame);
        client.write_all(&frame).await.unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        cipher().xor(&mut reply);
        assert_eq!(
            reply,
            [4u32.to_le_bytes(), (-429i32).to_le_bytes()].concat()
        );
        task.await.unwrap();
        assert_eq!(*endpoint.lane.failed_until.lock(), 0.0);
        endpoint.close().await;
    }

    #[tokio::test]
    async fn local_memory_pressure_does_not_cool_down_the_origin() {
        let endpoint = Endpoint::start(200, Duration::ZERO).await;
        let reserved = endpoint
            .lane
            .reply_bytes
            .clone()
            .acquire_many_owned(LANE_BYTES as u32)
            .await
            .unwrap();
        let (mut client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(server);
        let task = tokio::spawn(
            Channel {
                lane: endpoint.lane.clone(),
            }
            .bridge(
                read,
                write,
                PROTO_TAG_INTERMEDIATE,
                cipher(),
                cipher(),
                CancellationToken::new(),
            ),
        );
        let mut frame = encode_reply(&[1; 24], PROTO_TAG_INTERMEDIATE).unwrap();
        cipher().xor(&mut frame);
        client.write_all(&frame).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*endpoint.lane.failed_until.lock(), 0.0);
        assert!(endpoint.lane.pending.lock().is_empty());
        drop(reserved);
        assert_eq!(endpoint.lane.reply_bytes.available_permits(), LANE_BYTES);
        endpoint.close().await;
    }

    #[tokio::test]
    async fn replay_is_bounded_and_plaintext_handshakes_are_never_replayed() {
        for encrypted in [false, true] {
            let endpoint = Endpoint::start(200, Duration::from_secs(60)).await;
            let (mut client, server) = tokio::io::duplex(4096);
            let (read, write) = tokio::io::split(server);
            let cancel = CancellationToken::new();
            let task = tokio::spawn(
                Channel {
                    lane: endpoint.lane.clone(),
                }
                .bridge(
                    read,
                    write,
                    PROTO_TAG_INTERMEDIATE,
                    cipher(),
                    cipher(),
                    cancel.clone(),
                ),
            );
            let body = vec![u8::from(encrypted); 24];
            let mut frame = encode_reply(&body, PROTO_TAG_INTERMEDIATE).unwrap();
            cipher().xor(&mut frame);
            client.write_all(&frame).await.unwrap();
            tokio::time::sleep(Duration::from_millis(4500)).await;
            let calls = endpoint.calls.load(Ordering::Relaxed);
            assert_eq!(calls, if encrypted { 2 } else { 1 });
            assert!(endpoint.lane.pending.lock().len() <= CHANNEL_REQUESTS);
            cancel.cancel();
            task.await.unwrap();
            assert_eq!(endpoint.lane.bytes.available_permits(), LANE_BYTES);
            endpoint.close().await;
        }
    }

    #[tokio::test]
    async fn aborting_bridge_releases_lane_metadata_and_budgets() {
        let endpoint = Endpoint::start(200, Duration::from_secs(60)).await;
        let (mut client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(server);
        let task = tokio::spawn(
            Channel {
                lane: endpoint.lane.clone(),
            }
            .bridge(
                read,
                write,
                PROTO_TAG_INTERMEDIATE,
                cipher(),
                cipher(),
                CancellationToken::new(),
            ),
        );
        let mut frame = encode_reply(&[1; 24], PROTO_TAG_INTERMEDIATE).unwrap();
        cipher().xor(&mut frame);
        client.write_all(&frame).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while endpoint.calls.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        let _ = task.await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while endpoint.lane.bytes.available_permits() != LANE_BYTES {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(endpoint.lane.pending.lock().is_empty());
        endpoint.close().await;
    }

    #[tokio::test]
    async fn disconnect_cancels_hanging_http_without_cooling_healthy_origin() {
        let endpoint = Endpoint::start(200, Duration::from_secs(30)).await;
        let (mut client, server) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(server);
        let task = tokio::spawn(
            Channel {
                lane: endpoint.lane.clone(),
            }
            .bridge(
                read,
                write,
                PROTO_TAG_INTERMEDIATE,
                cipher(),
                cipher(),
                CancellationToken::new(),
            ),
        );
        let mut frame = encode_reply(&[1; 24], PROTO_TAG_INTERMEDIATE).unwrap();
        cipher().xor(&mut frame);
        client.write_all(&frame).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while endpoint.calls.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(client);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(endpoint.lane.pending.lock().is_empty());
        assert_eq!(endpoint.lane.requests.available_permits(), LANE_REQUESTS);
        assert_eq!(*endpoint.lane.failed_until.lock(), 0.0);
        endpoint.close().await;
    }
}
