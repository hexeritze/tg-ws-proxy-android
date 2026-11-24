//! H2 media transport — Rust port of upstream `cf_h2.py`.
//!
//! Architecture (mirrors Python):
//! - `H2Pool` — per-host lanes, per-DC setup retry gate, 8s open timeout.
//! - `H2Lane` — one HTTP/2 connection per `kws{dc}.{domain}` host. Preflight HEAD,
//!   capacity accounting (64 concurrent / 32 MiB), 30s cooldown on non-transport errors.
//! - `H2Channel` — one MTProto client session over a lane. Bounded reply queue (16),
//!   replay history (16 packets / 64 KiB), 250ms recovery task with replay rotation,
//!   send-lock (native awaits, replay try_lock only).
//!
//! Wire framing (`read_packet` / `encode_reply`) is byte-compatible with the
//! WebSocket bridge framing: header AND body are XOR-decrypted in place with the
//! same client decryptor stream.

use crate::balancer;
use crate::config::*;
use crate::crypto::TrackedStream;
use crate::ws;
use bytes::Bytes;
use once_cell::sync::Lazy;
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch, Notify};
use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Constants (cf_h2.py L24-45)
// ---------------------------------------------------------------------------

const MAX_PACKET: u64 = 4 * 1024 * 1024;
const MAX_PLAIN_PADDING: u64 = 256;
const MAX_CHANNEL_REQUESTS: u64 = 8;
const MAX_CHANNEL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LANE_REQUESTS: u64 = 64;
const MAX_LANE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_LANE_REPLY_BYTES: u64 = 32 * 1024 * 1024;
const DOMAIN_COOLDOWN: f64 = 30.0;
const REQUEST_TIMEOUT: f64 = 65.0;
const SETUP_TIMEOUT: f64 = 8.0;
const REPLAY_IDLE_SECONDS: f64 = 1.0;
const REPLAY_REQUEST_SECONDS: f64 = 3.0;
const REPLAY_CHECK_SECONDS: f64 = 0.25;
const REPLAY_MAX_AGE: f64 = 30.0;
const REPLAY_HISTORY_BYTES: u64 = 64 * 1024;
const REPLAY_HISTORY_PACKETS: usize = 16;
const MAX_CHANNEL_REPLAYS: usize = 2;
const REPLAY_SLOT_SECONDS: f64 = 30.0;
const REPLAY_RETRY_SECONDS: f64 = 2.0;
const REPLAY_MAX_ATTEMPTS: u64 = 3;
const SLOW_RESPONSE_SECONDS: f64 = 3.0;
const DIAGNOSTIC_INTERVAL: f64 = 5.0;

// ---------------------------------------------------------------------------
// Failure taxonomy
// ---------------------------------------------------------------------------

/// Channel failure reason. `Transport` carries the MTProto negative error code and
/// the bridge writes it back to the client as an int32le reply.
#[derive(Debug, Clone, Copy)]
pub enum H2Fail {
    Transport(i32),
    /// Lane reply buffer saturated (Python `BufferError`): no lane counters,
    /// no cooldown — the channel simply fails and a fresh one is opened next time.
    ReplyBufferFull,
    Closed,
}

// ---------------------------------------------------------------------------
// Wire framing (cf_h2.py `_read_packet` / `_encode_reply`)
// ---------------------------------------------------------------------------

async fn decrypt_read<R: AsyncRead + Unpin>(
    reader: &mut R,
    dec: &mut TrackedStream,
    count: usize,
) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; count];
    reader.read_exact(&mut buf).await.map_err(|e| format!("read: {e}"))?;
    dec.xor(&mut buf);
    Ok(buf)
}

/// Read one MTProto packet from the client side. Returns `(body, quick)`.
/// Port of `cf_h2.py:_read_packet` — header bytes are XOR-decrypted with the same
/// stream as the body.
pub async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    clt_dec: &mut TrackedStream,
    tag: u32,
) -> Result<(Bytes, bool), String> {
    let first = decrypt_read(reader, clt_dec, 1).await?;
    let (quick, length): (bool, u64) = if tag == PROTO_TAG_ABRIDGED {
        let w = first[0] & 0x7f;
        let mut words: u32 = w as u32;
        if w == 0x7f {
            let extra = decrypt_read(reader, clt_dec, 3).await?;
            words = (extra[0] as u32) | ((extra[1] as u32) << 8) | ((extra[2] as u32) << 16);
        }
        (first[0] & 0x80 != 0, words as u64 * 4)
    } else {
        let buf = decrypt_read(reader, clt_dec, 4).await?;
        let value = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        (value & 0x80000000 != 0, (value & 0x7fffffff) as u64)
    };

    let max_len = MAX_PACKET + if tag == PROTO_TAG_SECURE { MAX_PLAIN_PADDING } else { 0 };
    if length < 24 || length > max_len {
        return Err(format!("frame length {length} out of range"));
    }
    let mut body = decrypt_read(reader, clt_dec, length as usize).await?;

    if tag == PROTO_TAG_SECURE {
        let all_zero = body.iter().take(8).all(|&b| b == 0);
        let (packet_length, max_padding) = if all_zero {
            (
                20u64 + u32::from_le_bytes([body[16], body[17], body[18], body[19]]) as u64,
                MAX_PLAIN_PADDING,
            )
        } else {
            (24 + ((length - 24) / 16) * 16, 15)
        };
        let padding = length - packet_length;
        if packet_length < 24 || packet_length > length || padding > max_padding {
            return Err(format!(
                "secure frame invalid: frame={length} packet={packet_length} padding={padding} limit={max_padding}"
            ));
        }
        body.truncate(packet_length as usize);
    }

    if body.len() % 4 != 0 || (body.len() as u64) > MAX_PACKET {
        return Err(format!("body length {} invalid", body.len()));
    }
    Ok((Bytes::from(body), quick))
}

/// Encode a reply body for the client. Port of `cf_h2.py:_encode_reply`.
/// Secure tag appends 0-3 random padding bytes; abridged uses 1/4-byte prefix.
pub fn encode_reply(body: &[u8], tag: u32) -> Option<Bytes> {
    if body.is_empty() || body.len() % 4 != 0 || (body.len() as u64) > MAX_PACKET {
        return None;
    }
    if tag == PROTO_TAG_ABRIDGED {
        let words = (body.len() / 4) as u32;
        let mut out = Vec::with_capacity(body.len() + 4);
        if words < 0x7f {
            out.push(words as u8);
        } else {
            out.push(0x7f);
            out.push(words as u8);
            out.push((words >> 8) as u8);
            out.push((words >> 16) as u8);
        }
        out.extend_from_slice(body);
        Some(Bytes::from(out))
    } else {
        let mut padding = Vec::new();
        if tag == PROTO_TAG_SECURE {
            let mut one = [0u8; 1];
            rand::thread_rng().fill_bytes(&mut one);
            padding.resize((one[0] % 4) as usize, 0);
            rand::thread_rng().fill_bytes(&mut padding);
        }
        let total = (body.len() + padding.len()) as u32;
        let mut out = Vec::with_capacity(4 + body.len() + padding.len());
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(&padding);
        Some(Bytes::from(out))
    }
}

// ---------------------------------------------------------------------------
// Capacity accounting (lane)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum ReserveResult {
    Ok,
    Closed,
    NoCap { ch_ok: bool },
}

/// Lane capacity state — check AND increment happen under one lock so the
/// (channel, lane) reservation is atomic (Python relies on asyncio never
/// preempting the synchronous `_reserve` body).
#[derive(Default)]
struct CapState {
    closed: bool,
    per_channel: HashMap<u64, (u64, u64)>, // channel_id -> (requests, bytes)
    lane_inflight: u64,
    lane_bytes: u64,
}

// ---------------------------------------------------------------------------
// Replay state (channel)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ReplayEntry {
    key: [u8; 8],
    body: Bytes,
    seq: u64,
    sent_at: f64,
    attempts: u64,
    last_attempt: Option<f64>,
    pending: Option<u64>,
    originals: HashSet<u64>,
    retired: bool,
    reply_id: Option<[u8; 24]>,
}

impl ReplayEntry {
    fn replayed(&self) -> bool {
        self.last_attempt.is_some() || self.attempts > 0
    }
}

/// `_replay_limit` (cf_h2.py): 3 if entry has originals, is retired, or is the
/// newest; 0 otherwise.
fn replay_limit(e: &ReplayEntry, history: &[ReplayEntry]) -> u64 {
    let newest = history.last().map(|last| last.key == e.key).unwrap_or(false);
    if !e.originals.is_empty() || e.retired || newest {
        REPLAY_MAX_ATTEMPTS
    } else {
        0
    }
}

struct InflightReq {
    len: u64,
    /// Паритет с RequestTrace.replay (cf_h2.py L52): метка, что запрос — replay.
    #[allow(dead_code)]
    replay: bool,
    join: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct ChState {
    closed: bool,
    pending: HashMap<u64, InflightReq>,
    pending_since: HashMap<u64, f64>,
    sent_since: HashMap<u64, f64>,
    receiving: HashSet<u64>,
    replay_pending: HashSet<u64>,
    replay_history: Vec<ReplayEntry>,
    replay_key: Option<[u8; 8]>,
    delivering_since: Option<f64>,
    reply_bytes: u64,
    pending_bytes: u64,
    last_progress: f64,
    last_native_send: f64,
    http_bytes: u64,
    small_responses: u64,
    large_responses: u64,
    requests: u64,
    up: u64,
    down: u64,
    quick_requests: u64,
    replay_requests: u64,
    poll_requests: u64,
    replay_rotations: u64,
    capacity_rotations: u64,
    first_poll_gap: f64,
    upload_wait_since: Option<f64>,
    upload_wait_phase: u8, // 1=channel-capacity 2=lane-capacity 3=send-lock
    upload_wait_bytes: u64,
}

fn phase_str(p: u8) -> &'static str {
    match p {
        1 => "channel-capacity",
        2 => "lane-capacity",
        3 => "send-lock",
        _ => "none",
    }
}

// ---------------------------------------------------------------------------
// H2Lane
// ---------------------------------------------------------------------------

pub struct H2Lane {
    pool: Arc<H2Pool>,
    pub host: String,
    pub lane_id: u64,
    created_at: f64,
    idle_since: Mutex<Option<std::time::Instant>>,
    dead: AtomicBool,
    failed_until: AtomicU64, // f64 bits, monotonic
    channels: Mutex<HashSet<u64>>,
    channel_refs: Mutex<Vec<Weak<H2Channel>>>,
    send_req: Mutex<Option<h2::client::SendRequest<Bytes>>>,
    shutdown_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    cap: Mutex<CapState>,
    pub cap_notify: Notify,
    next_wait_log: AtomicU64, // f64 bits

    requests: AtomicU64,
    responses: AtomicU64,
    errors: AtomicU64,
    slow_headers: AtomicU64,
    slow_bodies: AtomicU64,
    max_headers_ms: AtomicU64,
    max_body_ms: AtomicU64,
    replays: AtomicU64,
    max_inflight: AtomicU64,
    queued_bytes: AtomicU64,
    reply_buffer_bytes: AtomicU64,
    next_large_slow_log: AtomicU64, // f64 bits
    capacity_rotations: AtomicU64,
}

impl H2Lane {
    fn new(pool: Arc<H2Pool>, host: String, id: u64) -> Arc<Self> {
        let now = now_monotonic();
        Arc::new(Self {
            pool,
            host,
            lane_id: id,
            created_at: now,
            idle_since: Mutex::new(None),
            dead: AtomicBool::new(false),
            failed_until: AtomicU64::new(0.0f64.to_bits()),
            channels: Mutex::new(HashSet::new()),
            channel_refs: Mutex::new(Vec::new()),
            send_req: Mutex::new(None),
            shutdown_tx: Mutex::new(None),
            cap: Mutex::new(CapState::default()),
            cap_notify: Notify::new(),
            next_wait_log: AtomicU64::new(0.0f64.to_bits()),
            requests: AtomicU64::new(0),
            responses: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            slow_headers: AtomicU64::new(0),
            slow_bodies: AtomicU64::new(0),
            max_headers_ms: AtomicU64::new(0),
            max_body_ms: AtomicU64::new(0),
            replays: AtomicU64::new(0),
            max_inflight: AtomicU64::new(0),
            queued_bytes: AtomicU64::new(0),
            reply_buffer_bytes: AtomicU64::new(0),
            next_large_slow_log: AtomicU64::new(0.0f64.to_bits()),
            capacity_rotations: AtomicU64::new(0),
        })
    }

    pub fn is_failed(&self, now: f64) -> bool {
        f64::from_bits(self.failed_until.load(Ordering::Relaxed)) > now
    }

    fn set_failed_until(&self, until: f64) {
        let bits = until.to_bits();
        let prev = self.failed_until.load(Ordering::Relaxed);
        if bits >= prev {
            self.failed_until.store(bits, Ordering::Relaxed);
        }
    }

    fn channels_count(&self) -> usize {
        self.channels.lock().unwrap().len()
    }

    fn channel_list(&self) -> Vec<Arc<H2Channel>> {
        self.channel_refs
            .lock()
            .unwrap()
            .iter()
            .filter_map(|w| w.upgrade())
            .collect()
    }

    pub fn add_channel_ref(&self, ch: Arc<H2Channel>) {
        self.channels.lock().unwrap().insert(ch.channel_id);
        self.channel_refs.lock().unwrap().push(Arc::downgrade(&ch));
        *self.idle_since.lock().unwrap() = None;
    }

    pub fn remove_channel_ref(&self, id: u64) {
        self.channels.lock().unwrap().remove(&id);
        let mut refs = self.channel_refs.lock().unwrap();
        if let Some(pos) = refs.iter().position(|w| w.upgrade().map(|c| c.channel_id == id).unwrap_or(false)) {
            refs.remove(pos);
        }
        drop(refs);
        if self.channels.lock().unwrap().is_empty() {
            *self.idle_since.lock().unwrap() = Some(std::time::Instant::now());
        }
    }

    pub fn idle_for_close(&self) -> bool {
        self.channels_count() == 0
            && self.idle_since
                .lock()
                .unwrap()
                .map(|t| t.elapsed() >= Duration::from_secs_f64(H2_LANE_IDLE_CLOSE_SECS))
                .unwrap_or(false)
    }

    /// Atomic channel+lane capacity reservation (check AND increment under one lock).
    fn try_reserve(&self, ch: u64, len: u64) -> ReserveResult {
        let mut cap = self.cap.lock().unwrap();
        if cap.closed {
            return ReserveResult::Closed;
        }
        let ch_ok = cap
            .per_channel
            .get(&ch)
            .map(|(r, b)| *r < MAX_CHANNEL_REQUESTS && *b + len <= MAX_CHANNEL_BYTES)
            .unwrap_or(true);
        let lane_ok = cap.lane_inflight < MAX_LANE_REQUESTS && cap.lane_bytes + len <= MAX_LANE_BYTES;
        if ch_ok && lane_ok {
            let (ch_req, ch_bytes) = cap.per_channel.entry(ch).or_insert((0, 0));
            *ch_req += 1;
            *ch_bytes += len;
            cap.lane_inflight += 1;
            cap.lane_bytes += len;
            let inflight = cap.lane_inflight;
            drop(cap);
            self.queued_bytes.fetch_add(len, Ordering::Relaxed);
            if inflight > self.max_inflight.load(Ordering::Relaxed) {
                self.max_inflight.store(inflight, Ordering::Relaxed);
            }
            ReserveResult::Ok
        } else {
            ReserveResult::NoCap { ch_ok }
        }
    }

    fn release(&self, ch: u64, len: u64) {
        let mut cap = self.cap.lock().unwrap();
        if let Some((cr, cb)) = cap.per_channel.get_mut(&ch) {
            *cr = cr.saturating_sub(1);
            *cb = cb.saturating_sub(len);
        }
        cap.lane_inflight = cap.lane_inflight.saturating_sub(1);
        cap.lane_bytes = cap.lane_bytes.saturating_sub(len);
        drop(cap);
        self.queued_bytes.fetch_sub(len, Ordering::Relaxed);
        self.cap_notify.notify_waiters();
    }

    fn max_ms(&self, slot: &AtomicU64, ms: u64) {
        loop {
            let cur = slot.load(Ordering::Relaxed);
            if ms <= cur {
                break;
            }
            if slot
                .compare_exchange_weak(cur, ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    // -- error taxonomy (lane._post finally / except chain) -----------------

    /// MTProto transport error: errors++, NO cooldown (peer protocol error).
    fn err_transport(&self, code: i32) -> H2Fail {
        self.errors.fetch_add(1, Ordering::Relaxed);
        H2Fail::Transport(code)
    }

    /// Non-transport (HTTP/IO/parse) error: errors++ + 30s lane cooldown.
    fn err_nontransport(&self) -> H2Fail {
        self.errors.fetch_add(1, Ordering::Relaxed);
        self.set_failed_until(now_monotonic() + DOMAIN_COOLDOWN);
        H2Fail::Closed
    }

    fn h2_err(&self, e: &h2::Error) -> H2Fail {
        let _ = e; // keep for logs
        self.errors.fetch_add(1, Ordering::Relaxed);
        self.set_failed_until(now_monotonic() + DOMAIN_COOLDOWN);
        if e.is_go_away() || e.is_io() {
            self.mark_dead();
        }
        H2Fail::Closed
    }

    /// Connection is gone: fail capacity, fail all channels, drop from pool map.
    pub fn mark_dead(&self) {
        if !self.dead.swap(true, Ordering::SeqCst) {
            let mut cap = self.cap.lock().unwrap();
            cap.closed = true;
            drop(cap);
            self.cap_notify.notify_waiters();
            for ch in self.channel_list() {
                ch.fail(H2Fail::Closed);
            }
            self.pool.remove_lane_if_dead(&self.host);
        }
    }

    // -- preflight + connection --------------------------------------------

    /// TCP+TLS(h2)+HTTP/2 handshake, spawn connection task, HEAD `https://host/api`.
    pub async fn preflight(self: &Arc<Self>) -> Result<(), String> {
        let tls = ws::tls_h2_connect(&self.host, &self.host, Duration::from_secs_f64(SETUP_TIMEOUT))
            .await
            .map_err(|e| e.compact())?;

        let (send_req, mut connection) = h2::client::Builder::new()
            .initial_window_size(256 * 1024)
            .max_concurrent_streams(MAX_LANE_REQUESTS as u32)
            .handshake(tls)
            .await
            .map_err(|e| format!("h2 handshake: {e}"))?;
        connection.set_target_window_size(4 * 1024 * 1024);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        *self.shutdown_tx.lock().unwrap() = Some(shutdown_tx);

        let lane = Arc::clone(self);
        tokio::spawn(async move {
            tokio::select! {
                r = connection => {
                    if let Err(e) = r {
                        log_debug(&format!("H2 lane={} host={} connection ended: {e}", lane.lane_id, lane.host));
                    }
                    lane.mark_dead();
                }
                _ = shutdown_rx => {
                    // lane.close() requested: drop connection without mark_dead
                }
            }
        });

        *self.send_req.lock().unwrap() = Some(send_req);

        // Preflight: HEAD https://host/api
        let req = http::Request::builder()
            .method("HEAD")
            .uri(&format!("https://{}/api", self.host))
            .body(())
            .map_err(|e| format!("build preflight: {e}"))?;
        let (resp_fut, _send_stream) = {
            let mut g = self.send_req.lock().unwrap();
            let sr = g.as_mut().ok_or_else(|| "lane has no send_req".to_string())?;
            sr.send_request(req, true).map_err(|e| format!("preflight send: {e}"))?
        };
        let resp = resp_fut
            .await
            .map_err(|e| format!("preflight response: {e}"))?;
        let status = resp.status().as_u16();
        if !((200..300).contains(&status) || status == 405 || status == 501) {
            return Err(format!("preflight status {status}"));
        }
        log_debug(&format!(
            "H2 lane={} host={} preflight ok",
            self.lane_id, self.host
        ));
        Ok(())
    }

    /// Lane shutdown: close capacity, stop connection, close all channels.
    pub async fn close(self: &Arc<Self>) {
        {
            let mut cap = self.cap.lock().unwrap();
            cap.closed = true;
        }
        self.cap_notify.notify_waiters();
        if let Some(tx) = self.shutdown_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
        *self.send_req.lock().unwrap() = None;
        let channels = self.channel_list();
        for ch in channels {
            ch.close().await;
        }
        self.dead.store(true, Ordering::SeqCst);
        log_debug(&format!("H2 CLOSED {}", self.summary()));
    }

    // -- diagnostics (log_wait / log_flow / summary) ------------------------

    /// Port of `lane.log_wait` (cf_h2.py L808-831). H2 DETAIL section skipped
    /// (no request_traces in the Rust port).
    pub fn log_wait(&self, now: f64) {
        if now < f64::from_bits(self.next_wait_log.load(Ordering::Relaxed)) {
            return;
        }
        self.next_wait_log.store((now + 1.0).to_bits(), Ordering::Relaxed);
        let channels = self.channel_list();
        let waiting: Vec<u64> = channels
            .iter()
            .filter(|c| c.waiting(now))
            .map(|c| c.channel_id)
            .collect();
        if waiting.is_empty() {
            return;
        }
        self.next_wait_log.store((now + DIAGNOSTIC_INTERVAL).to_bits(), Ordering::Relaxed);
        let mut ids = waiting.clone();
        ids.sort_unstable();
        let parts: Vec<String> = channels
            .iter()
            .filter(|c| ids.contains(&c.channel_id))
            .map(|c| c.wait_state_str(now))
            .collect();
        log_debug(&format!(
            "H2 WAIT lane={} affected={} inflight={} body_buffer={} [{}]",
            self.lane_id,
            ids.len(),
            self.cap.lock().unwrap().lane_inflight,
            self.reply_buffer_bytes.load(Ordering::Relaxed),
            parts.join("; ")
        ));
    }

    pub fn log_flow(&self, now: f64) {
        let mut channels = self.channel_list();
        if channels.is_empty() {
            return;
        }
        channels.sort_by_key(|c| c.channel_id);
        for chunk in channels.chunks(8) {
            let parts: Vec<String> = chunk.iter().map(|c| c.flow_state_str(now)).collect();
            log_debug(&format!("H2 FLOW lane={} [{}]", self.lane_id, parts.join("; ")));
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "lane={} host={} age_s={:.0} channels={} tcp_connections=1 requests={} replies={} errors={} inflight={} max_inflight={} queued_bytes={} reply_buffer_bytes={} replays={} capacity_rotations={} slow_headers={} slow_bodies={} max_headers_ms={} max_body_ms={}",
            self.lane_id,
            self.host,
            (now_monotonic() - self.created_at).max(0.0),
            self.channels_count(),
            self.requests.load(Ordering::Relaxed),
            self.responses.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
            self.cap.lock().unwrap().lane_inflight,
            self.max_inflight.load(Ordering::Relaxed),
            self.queued_bytes.load(Ordering::Relaxed),
            self.reply_buffer_bytes.load(Ordering::Relaxed),
            self.replays.load(Ordering::Relaxed),
            self.capacity_rotations.load(Ordering::Relaxed),
            self.slow_headers.load(Ordering::Relaxed),
            self.slow_bodies.load(Ordering::Relaxed),
            self.max_headers_ms.load(Ordering::Relaxed),
            self.max_body_ms.load(Ordering::Relaxed),
        )
    }
}

// ---------------------------------------------------------------------------
// H2Channel
// ---------------------------------------------------------------------------

pub struct H2Channel {
    lane: Arc<H2Lane>,
    pub channel_id: u64,
    pub label: String,
    state: Mutex<ChState>,
    next_task: AtomicU64,
    send_lock: TokioMutex<()>,
    send_held: AtomicBool,
    tx: mpsc::Sender<Bytes>,
    rx: Mutex<Option<mpsc::Receiver<Bytes>>>,
    fail_tx: watch::Sender<bool>,
    recovery_notify: Notify,
    closed: AtomicBool,
    transport_error: AtomicI32, // 0 = none
}

impl H2Channel {
    fn new(lane: Arc<H2Lane>, channel_id: u64, label: String) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(16);
        let (fail_tx, _) = watch::channel(false);
        let now = now_monotonic();
        let ch = Arc::new(Self {
            lane,
            channel_id,
            label,
            state: Mutex::new(ChState {
                last_progress: now,
                last_native_send: now,
                ..Default::default()
            }),
            next_task: AtomicU64::new(1),
            send_lock: TokioMutex::new(()),
            send_held: AtomicBool::new(false),
            tx,
            rx: Mutex::new(Some(rx)),
            fail_tx,
            recovery_notify: Notify::new(),
            closed: AtomicBool::new(false),
            transport_error: AtomicI32::new(0),
        });
        ch.lane.add_channel_ref(ch.clone());
        ch
    }

    /// One-time handover of the reply receiver + failure watch to the bridge.
    pub fn take_receiver(&self) -> (mpsc::Receiver<Bytes>, watch::Receiver<bool>) {
        (
            self.rx.lock().unwrap().take().expect("receiver taken once"),
            self.fail_tx.subscribe(),
        )
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub fn transport_error(&self) -> Option<i32> {
        let v = self.transport_error.load(Ordering::SeqCst);
        if v == 0 {
            None
        } else {
            Some(v)
        }
    }

    fn native_backpressure(&self) -> bool {
        let s = self.state.lock().unwrap();
        s.reply_bytes > 0 || s.delivering_since.is_some()
    }

    pub fn last_native_send(&self) -> f64 {
        self.state.lock().unwrap().last_native_send
    }

    /// `_fail` (cf_h2.py L352-362): close channel, record transport error, push a
    /// single Err sentinel via the watch flag. Does NOT clear `pending` — the
    /// per-request finish guards own the capacity release.
    pub fn fail(&self, err: H2Fail) {
        if !self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        if let H2Fail::Transport(code) = err {
            self.transport_error.store(code, Ordering::SeqCst);
        }
        let mut s = self.state.lock().unwrap();
        s.closed = true;
        s.reply_bytes = 0;
        drop(s);
        self.recovery_notify.notify_waiters();
        let _ = self.fail_tx.send_replace(true);
    }

    /// `send` wrapper (cf_h2.py L364-376): native path sets upload_wait
    /// phase=send-lock and AWaits the send lock.
    pub async fn send(self: &Arc<Self>, body: Bytes, quick: bool) -> bool {
        if self.is_closed() {
            return false;
        }
        let now = now_monotonic();
        {
            let mut s = self.state.lock().unwrap();
            s.upload_wait_since = Some(now);
            s.upload_wait_phase = 3;
            s.upload_wait_bytes = body.len() as u64;
        }
        self.send_held.store(true, Ordering::SeqCst);
        let _g = self.send_lock.lock().await;
        self.send_held.store(false, Ordering::Relaxed);
        let ok = self.send_inner(body, quick, false).await;
        let mut s = self.state.lock().unwrap();
        s.upload_wait_since = None;
        s.upload_wait_phase = 0;
        s.upload_wait_bytes = 0;
        ok
    }

    /// Replay path: if the send lock is held, bail out (recovery will retry);
    /// otherwise try_lock (no waiting).
    pub(crate) async fn send_replay(self: &Arc<Self>, body: Bytes) -> bool {
        if self.is_closed() || self.send_held.load(Ordering::SeqCst) {
            return false;
        }
        let g = match self.send_lock.try_lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let ok = self.send_inner(body, false, true).await;
        drop(g);
        ok
    }

    /// Port of `_send` (cf_h2.py L380-434). Returns false when the packet was
    /// not queued (capacity timeout / replay guard / closed).
    async fn send_inner(self: &Arc<Self>, body: Bytes, quick: bool, replay: bool) -> bool {
        let len = body.len() as u64;
        let now = now_monotonic();
        let lane = &self.lane;

        // 1. capacity (replay: no wait; native: wait up to REQUEST_TIMEOUT)
        if replay {
            if !matches!(lane.try_reserve(self.channel_id, len), ReserveResult::Ok) {
                return false;
            }
        } else {
            let deadline = now + REQUEST_TIMEOUT;
            loop {
                match lane.try_reserve(self.channel_id, len) {
                    ReserveResult::Ok => break,
                    ReserveResult::Closed => return false,
                    ReserveResult::NoCap { ch_ok } => {
                        let t = now_monotonic();
                        if t >= deadline {
                            log_warn(&format!(
                                "[{}] H2 channel={} capacity timeout after {REQUEST_TIMEOUT}s",
                                self.label, self.channel_id
                            ));
                            return false;
                        }
                        let phase: u8 = if ch_ok { 2 } else { 1 };
                        {
                            let mut s = self.state.lock().unwrap();
                            s.upload_wait_since = Some(t);
                            s.upload_wait_phase = phase;
                            s.upload_wait_bytes = len;
                        }
                        // Register the waiter *before* the re-check so a release that
                        // lands in between cannot be lost (tokio Notify docs pattern).
                        let n = lane.cap_notify.notified();
                        tokio::pin!(n);
                        n.as_mut().enable();
                        match lane.try_reserve(self.channel_id, len) {
                            ReserveResult::Ok => break,
                            ReserveResult::Closed => return false,
                            ReserveResult::NoCap { ch_ok } => {
                                {
                                    let mut s = self.state.lock().unwrap();
                                    s.upload_wait_phase = if ch_ok { 2 } else { 1 };
                                }
                                let rem = (deadline - now_monotonic()).max(0.0);
                                let _ = tokio::time::timeout(Duration::from_secs_f64(rem), n.as_mut()).await;
                            }
                        }
                    }
                }
            }
        }

        // 2. replay guards / remember packet
        let mut s = self.state.lock().unwrap();
        if s.closed {
            drop(s);
            lane.release(self.channel_id, len);
            return false;
        }
        let task_id = self.next_task.fetch_add(1, Ordering::Relaxed);

        let packet_idx: Option<usize> = if replay {
            let mut key = [0u8; 8];
            key.copy_from_slice(&body[..8]);
            let idx = s.replay_history.iter().position(|e| e.key == key);
            let due = match idx {
                Some(i) => {
                    let e = &s.replay_history[i];
                    e.pending.is_none() && self.replay_due(e, now, &s).is_none()
                }
                None => false,
            };
            if !due {
                drop(s);
                lane.release(self.channel_id, len);
                return false;
            }
            idx
        } else {
            self.remember_packet(&mut s, &body, now)
        };

        // 3. stats (exact order from _send)
        s.pending_bytes += len;
        s.requests += 1;
        s.replay_requests += replay as u64;
        s.up += len;
        STATS.bytes_up.fetch_add(len as i64, Ordering::Relaxed);
        if !replay {
            s.last_native_send = now;
        }
        if quick {
            s.quick_requests += 1;
        }

        // 4. replay bookkeeping
        if replay {
            if let Some(i) = packet_idx {
                if !self.overdue_original(&s.replay_history[i], now, &s) {
                    s.poll_requests += 1;
                }
                let rep = s.replay_history[i].replayed();
                if !rep {
                    s.first_poll_gap = s.first_poll_gap.max(now - s.last_progress);
                }
                s.replay_pending.insert(task_id);
                s.replay_history[i].attempts += 1;
                s.replay_history[i].last_attempt = Some(now);
                s.replay_history[i].pending = Some(task_id);
            }
        }

        // 5. register pending
        s.pending.insert(task_id, InflightReq { len, replay, join: None });
        s.pending_since.insert(task_id, now);

        // 6. native originals + history trim
        if !replay {
            if let Some(i) = packet_idx {
                s.replay_history[i].originals.insert(task_id);
            }
            self.trim_history(&mut s, now);
        }

        // 7. snapshot for the spawned request task
        let packet = packet_idx.and_then(|i| s.replay_history.get(i).cloned());
        let body_c = body.clone();
        let ch = Arc::clone(self);
        let lane_c = Arc::clone(lane);
        drop(s);

        // 8. spawn request task (guard inside owns the finish/release path)
        let handle = tokio::spawn(async move {
            let _guard = ReqFinishGuard::new(Arc::clone(&ch), Arc::clone(&lane_c), task_id, len);
            match post_request(&lane_c, &ch, task_id, body_c).await {
                Ok(reply) => deliver_reply(&ch, packet, reply),
                Err(e) => {
                    STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                    ch.fail(e);
                }
            }
        });
        let mut s = self.state.lock().unwrap();
        if let Some(p) = s.pending.get_mut(&task_id) {
            p.join = Some(handle);
        }
        true
    }

    // -- replay helpers ------------------------------------------------------

    fn remember_packet(&self, s: &mut ChState, body: &Bytes, now: f64) -> Option<usize> {
        if body.len() < 8 || (body.len() as u64) > REPLAY_HISTORY_BYTES {
            return None;
        }
        let mut key = [0u8; 8];
        key.copy_from_slice(&body[..8]);
        if key.iter().all(|&b| b == 0) {
            return None;
        }
        match s.replay_key {
            None => {
                s.replay_key = Some(key);
                s.replay_history.clear();
            }
            Some(k) if k != key => {
                s.replay_key = Some(key);
                s.replay_history.clear();
            }
            _ => {}
        }
        if let Some(i) = s.replay_history.iter().position(|e| e.body == *body) {
            return Some(i);
        }
        s.replay_history.push(ReplayEntry {
            key,
            body: body.clone(),
            seq: s.requests,
            sent_at: now,
            attempts: 0,
            last_attempt: None,
            pending: None,
            originals: HashSet::new(),
            retired: false,
            reply_id: None,
        });
        Some(s.replay_history.len() - 1)
    }

    fn trim_history(&self, s: &mut ChState, now: f64) {
        let total = |h: &Vec<ReplayEntry>| h.iter().map(|e| e.body.len() as u64).sum::<u64>();
        while s.replay_history.len() > REPLAY_HISTORY_PACKETS || total(&s.replay_history) > REPLAY_HISTORY_BYTES {
            let idx = s
                .replay_history
                .iter()
                .position(|e| {
                    e.originals.is_empty()
                        && !(e.retired && e.attempts < REPLAY_MAX_ATTEMPTS && now - e.sent_at <= REPLAY_MAX_AGE)
                });
            match idx {
                Some(i) => {
                    let e = &mut s.replay_history[i];
                    if let Some(p) = e.pending {
                        s.replay_pending.remove(&p);
                    }
                    s.replay_history.remove(i);
                }
                None => break,
            }
        }
    }

    /// `_replay_due` (cf_h2.py `_replay_blocker`): None => due, Some(reason) => blocked.
    fn replay_due(&self, e: &ReplayEntry, now: f64, s: &ChState) -> Option<&'static str> {
        if !(0.0..=REPLAY_MAX_AGE).contains(&(now - e.sent_at)) {
            return Some("expired");
        }
        if e.attempts >= replay_limit(e, &s.replay_history) {
            return Some("budget-used");
        }
        if s.reply_bytes > 0 || s.delivering_since.is_some() {
            return Some("native-backpressure");
        }
        if e.originals.iter().any(|t| s.receiving.contains(t)) {
            return Some("original-body");
        }
        if let Some(p) = e.pending {
            if s.receiving.contains(&p) {
                return Some("replay-body");
            }
        }
        if e.replayed() {
            if let Some(la) = e.last_attempt {
                if now - la < REPLAY_RETRY_SECONDS {
                    return Some("backoff-or-progress");
                }
            }
        }
        if self.overdue_original(e, now, s) {
            return None;
        }
        // `entry is not self.replay_history[-1]` — compare by msg_id key.
        if s.replay_history.last().map(|last| last.key != e.key).unwrap_or(true) {
            return Some("receiver-active");
        }
        // receiver-active part 2: any pending task that is not this entry's pending
        for (id, _) in s.pending.iter() {
            if e.pending != Some(*id) {
                return Some("receiver-active");
            }
        }
        if e.replayed() && now - s.last_progress < REPLAY_IDLE_SECONDS {
            return Some("backoff");
        }
        None
    }

    fn overdue_original(&self, e: &ReplayEntry, now: f64, s: &ChState) -> bool {
        if e.retired {
            return true;
        }
        e.originals.iter().any(|t| {
            s.sent_since
                .get(t)
                .map(|sent| !s.receiving.contains(t) && now - sent >= REPLAY_REQUEST_SECONDS)
                .unwrap_or(false)
        })
    }

    /// `_capacity_candidate` (cf_h2.py L215-226): oldest eligible sent task,
    /// replay-pending first. Returns (task, entry-to-retire).
    fn capacity_candidate(&self, s: &ChState, now: f64) -> Option<(u64, Option<ReplayEntry>)> {
        // Python: sort by (task not in replay_pending, sent) — replay-pending first,
        // then oldest sent first.
        let mut items: Vec<(bool, f64, u64)> = s
            .sent_since
            .iter()
            .filter(|(id, _)| s.pending.contains_key(id) && !s.receiving.contains(id))
            .map(|(id, sent)| (s.replay_pending.contains(id), *sent, *id))
            .collect();
        items.sort_by(|a, b| {
            b.0
                .cmp(&a.0)
                .then(a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        });
        for (is_replay, sent, id) in items {
            if now - sent < REPLAY_REQUEST_SECONDS {
                continue;
            }
            if is_replay {
                return Some((id, None));
            }
            for e in s.replay_history.iter() {
                if e.originals.contains(&id) && now - e.sent_at <= REPLAY_MAX_AGE {
                    return Some((id, Some(e.clone())));
                }
            }
        }
        None
    }

    /// `_make_upload_room` (cf_h2.py L228-263). Snapshot lane capacity first,
    /// then iterate channel locks one at a time (never two at once).
    fn make_upload_room(self: &Arc<Self>, now: f64) {
        let (phase, wait_bytes) = {
            let s = self.state.lock().unwrap();
            match s.upload_wait_since {
                None => return,
                Some(_) => (s.upload_wait_phase, s.upload_wait_bytes),
            }
        };
        // lane capacity snapshot (lock-read-drop)
        let lane_has_cap = {
            let cap = self.lane.cap.lock().unwrap();
            let lane_ok = cap.lane_inflight < MAX_LANE_REQUESTS && cap.lane_bytes + wait_bytes <= MAX_LANE_BYTES;
            let ch_ok = cap
                .per_channel
                .get(&self.channel_id)
                .map(|(r, b)| *r < MAX_CHANNEL_REQUESTS && *b + wait_bytes <= MAX_CHANNEL_BYTES)
                .unwrap_or(false);
            (ch_ok, lane_ok)
        };
        let (channels, is_lane_phase) = if phase == 1 {
            // channel-capacity: only self, and only if we still have no room
            if lane_has_cap.0 {
                return;
            }
            (vec![Arc::clone(self)], false)
        } else if phase == 2 {
            // lane-capacity: all lane channels sorted by oldest sent_since
            if lane_has_cap.1 {
                return;
            }
            let mut cs = self.lane.channel_list();
            cs.sort_by(|a, b| {
                let ma = a.state.lock().unwrap().sent_since.values().copied().fold(f64::MAX, f64::min);
                let mb = b.state.lock().unwrap().sent_since.values().copied().fold(f64::MAX, f64::min);
                ma.partial_cmp(&mb).unwrap_or(std::cmp::Ordering::Equal)
            });
            (cs, true)
        } else {
            return; // phase 3 (send-lock) — nothing to rotate
        };
        let _ = is_lane_phase;
        for ch in &channels {
            let cand = {
                let s = ch.state.lock().unwrap();
                ch.capacity_candidate(&s, now)
            };
            let (task, entry) = match cand {
                Some(c) => c,
                None => continue,
            };
            let mut s = ch.state.lock().unwrap();
            s.sent_since.remove(&task);
            if let Some(e) = &entry {
                let key = e.key;
                if let Some(pos) = s.replay_history.iter().position(|x| x.key == key) {
                    s.replay_history[pos].retired = true;
                }
            }
            if let Some(p) = s.pending.get_mut(&task) {
                if let Some(j) = p.join.take() {
                    j.abort();
                }
            }
            s.capacity_rotations += 1;
            drop(s);
            self.lane.capacity_rotations.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }

    /// `_recover` loop (cf_h2.py L536-575): 250ms tick + wakeup, log_wait,
    /// upload-room rotation, then at most one replay per tick.
    pub(crate) async fn recover(self: &Arc<Self>) {
        loop {
            // Register before the tick so a wakeup racing with the sleep is not lost
            // (tokio Notify docs pattern: pin once, then as_mut() per use).
            let n = self.recovery_notify.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs_f64(REPLAY_CHECK_SECONDS)) => {}
                _ = n.as_mut() => {}
            }
            if self.is_closed() {
                return;
            }
            let now = now_monotonic();
            self.lane.log_wait(now);
            self.make_upload_room(now);
            if self.native_backpressure() {
                continue;
            }
            // priority: overdue first (seq asc), then non-overdue (seq desc)
            let mut list: Vec<(u8, u64, ReplayEntry)> = {
                let s = self.state.lock().unwrap();
                let mut v: Vec<(u8, u64, ReplayEntry)> = Vec::new();
                for e in s.replay_history.iter() {
                    if self.overdue_original(e, now, &s) {
                        v.push((0, e.seq, e.clone()));
                    } else {
                        v.push((1, u64::MAX - e.seq, e.clone()));
                    }
                }
                v
            };
            list.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            for (_p, _s, entry) in list {
                let due = {
                    let s = self.state.lock().unwrap();
                    self.replay_due(&entry, now, &s).is_none()
                };
                if !due {
                    continue;
                }
                let (replace, body) = {
                    let mut s = self.state.lock().unwrap();
                    let mut replace = entry.pending;
                    if replace.is_none() && s.replay_pending.len() >= MAX_CHANNEL_REPLAYS {
                        replace = s
                            .pending
                            .iter()
                            .find(|(id, _)| s.replay_pending.contains(id) && !s.receiving.contains(id))
                            .map(|(id, _)| *id);
                    }
                    let replace = match replace {
                        Some(r) => r,
                        None => continue,
                    };
                    if s.receiving.contains(&replace) {
                        continue;
                    }
                    match s.sent_since.get(&replace) {
                        None => continue,
                        Some(sent) if now - sent < REPLAY_SLOT_SECONDS => continue,
                        _ => {}
                    }
                    if let Some(p) = s.pending.get_mut(&replace) {
                        if let Some(j) = p.join.take() {
                            j.abort();
                        }
                    }
                    s.replay_rotations += 1;
                    (replace, entry.body.clone())
                };
                let _ = replace;
                let _ok = self.send_replay(body).await;
                // Python: `break` after the first replay attempt — back to the 250ms tick.
                break;
            }
        }
    }

    /// `receive` (cf_h2.py L577-583): next reply body, or None when the channel
    /// failed / the bridge is done. Buffered replies are dropped on failure to
    /// match Python's queue-drain-on-fail semantics.
    pub async fn receive(
        &self,
        rx: &mut mpsc::Receiver<Bytes>,
        fail_rx: &mut watch::Receiver<bool>,
    ) -> Option<Bytes> {
        if *fail_rx.borrow_and_update() {
            return None;
        }
        loop {
            tokio::select! {
                r = rx.recv() => return r,
                _ = fail_rx.changed() => return None,
            }
        }
    }

    /// `_wake_receiver`: poke recovery when the channel goes fully idle.
    pub fn wake_receiver(&self) {
        if self.is_closed() {
            return;
        }
        let s = self.state.lock().unwrap();
        let active = !s.pending.is_empty() || s.reply_bytes > 0 || s.delivering_since.is_some();
        drop(s);
        if !active {
            self.recovery_notify.notify_waiters();
        }
    }

    /// `close` (cf_h2.py L585-614): fail, abort pending joins, double-release
    /// guard over all pending, clear replay state, detach from lane.
    pub async fn close(self: &Arc<Self>) {
        if !self.closed.compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed).is_ok()
            && self.state.lock().unwrap().closed
        {
            return;
        }
        self.fail(H2Fail::Closed);
        // abort all pending request tasks
        let mut joins: Vec<JoinHandle<()>> = Vec::new();
        {
            let mut s = self.state.lock().unwrap();
            s.closed = true;
            for p in s.pending.values_mut() {
                if let Some(j) = p.join.take() {
                    joins.push(j);
                }
            }
        }
        for j in joins {
            let _ = j.await;
        }
        // double-release guard: release every remaining pending entry exactly once
        {
            let mut s = self.state.lock().unwrap();
            let ids: Vec<(u64, u64)> = s.pending.iter().map(|(id, p)| (*id, p.len)).collect();
            for (id, len) in ids {
                s.pending.remove(&id);
                s.pending_since.remove(&id);
                s.sent_since.remove(&id);
                s.replay_pending.remove(&id);
                for e in s.replay_history.iter_mut() {
                    e.originals.remove(&id);
                    if e.pending == Some(id) {
                        e.pending = None;
                    }
                }
                self.lane.release(self.channel_id, len);
            }
            s.replay_history.clear();
            s.replay_key = None;
            s.replay_pending.clear();
            s.reply_bytes = 0;
        }
        self.lane.remove_channel_ref(self.channel_id);
        self.recovery_notify.notify_waiters();
        let _ = self.tx.try_send(Bytes::new()); // no-op: receiver may be gone; real close is via watch
        log_debug(&format!(
            "H2 channel={} closed lane={} {}",
            self.channel_id,
            self.lane.lane_id,
            self.lane.summary()
        ));
    }

    // -- diagnostics ---------------------------------------------------------

    fn waiting(&self, now: f64) -> bool {
        let s = self.state.lock().unwrap();
        let has_stale = s
            .pending
            .keys()
            .any(|id| {
                let stale = s
                    .pending_since
                    .get(id)
                    .map(|ps| now - *ps >= 3.0)
                    .unwrap_or(false);
                (!s.replay_pending.contains(id) && !s.receiving.contains(id) && stale)
                    || s
                        .delivering_since
                        .map(|ds| now - ds >= 3.0)
                        .unwrap_or(false)
            });
        has_stale && now - s.last_native_send <= REPLAY_MAX_AGE
    }

    /// `_wait_state` (cf_h2.py L293-310).
    pub fn wait_state_str(&self, now: f64) -> String {
        let s = self.state.lock().unwrap();
        let oldest = s.pending_since.values().copied().fold(now, f64::min);
        let recovery_left: u64 = s
            .replay_history
            .iter()
            .filter(|e| now - e.sent_at <= REPLAY_MAX_AGE)
            .map(|e| replay_limit(e, &s.replay_history).saturating_sub(e.attempts))
            .sum();
        let waiting_headers = s
            .sent_since
            .iter()
            .filter(|(id, sent)| {
                !s.replay_pending.contains(id)
                    && !s.receiving.contains(id)
                    && now - *sent >= REPLAY_REQUEST_SECONDS
            })
            .count();
        format!(
            "channel={} pending={} replays={} receiving={} ready_bytes={} native_write={} idle_ms={} oldest_ms={} native_age_ms={} recovery_left={} waiting_headers={}",
            self.channel_id,
            s.pending.len(),
            s.replay_pending.len(),
            s.receiving.len(),
            s.reply_bytes,
            u8::from(s.delivering_since.is_some()),
            ((now - s.last_progress) * 1000.0) as u64,
            ((now - oldest) * 1000.0) as u64,
            ((now - s.last_native_send) * 1000.0) as u64,
            recovery_left,
            waiting_headers,
        )
    }

    /// `_flow_state` (cf_h2.py).
    pub fn flow_state_str(&self, now: f64) -> String {
        let s = self.state.lock().unwrap();
        format!(
            "channel={} req={} up={} down={} pending={} reply_bytes={} up_wait={}/{}ms last_progress={:.0}ms http_bytes={} small={} large={}",
            self.channel_id,
            s.requests,
            s.up,
            s.down,
            s.pending.len(),
            s.reply_bytes,
            phase_str(s.upload_wait_phase),
            s.upload_wait_since
                .map(|t| ((now - t) * 1000.0) as u64)
                .unwrap_or(0),
            ((now - s.last_progress) * 1000.0) as u64,
            s.http_bytes,
            s.small_responses,
            s.large_responses,
        )
    }
}

// ---------------------------------------------------------------------------
// Request lifecycle
// ---------------------------------------------------------------------------

/// Abort-safe finish guard: created INSIDE the spawned request future so its
/// drop glue runs on both normal completion and `abort()`. Releases lane
/// capacity exactly once per task (double-release guard: removal from `pending`
/// must succeed).
struct ReqFinishGuard {
    ch: Arc<H2Channel>,
    lane: Arc<H2Lane>,
    task_id: u64,
    len: u64,
    done: bool,
}

impl ReqFinishGuard {
    fn new(ch: Arc<H2Channel>, lane: Arc<H2Lane>, task_id: u64, len: u64) -> Self {
        Self { ch, lane, task_id, len, done: false }
    }

    fn finish(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        {
            let mut s = self.ch.state.lock().unwrap();
            if s.pending.remove(&self.task_id).is_none() {
                // already released by channel.close() — double-release guard
                return;
            }
            s.pending_bytes = s.pending_bytes.saturating_sub(self.len);
            s.pending_since.remove(&self.task_id);
            s.sent_since.remove(&self.task_id);
            s.replay_pending.remove(&self.task_id);
            for e in s.replay_history.iter_mut() {
                e.originals.remove(&self.task_id);
                if e.pending == Some(self.task_id) {
                    e.pending = None;
                }
            }
        }
        self.lane.release(self.ch.channel_id, self.len);
        self.ch.wake_receiver();
    }
}

impl Drop for ReqFinishGuard {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Port of `lane._post` (cf_h2.py L681-806): send request body over HTTP/2,
/// enforce header/body checks in the exact upstream order, stream the reply.
async fn post_request(
    lane: &Arc<H2Lane>,
    ch: &Arc<H2Channel>,
    task_id: u64,
    body: Bytes,
) -> Result<Bytes, H2Fail> {
    lane.requests.fetch_add(1, Ordering::Relaxed);
    STATS.h2_requests.fetch_add(1, Ordering::Relaxed);
    let started = now_monotonic();

    let req = http::Request::builder()
        .method("POST")
        .uri(&format!("https://{}/api", lane.host))
        .header("content-type", "application/octet-stream")
        .header("accept-encoding", "identity")
        .body(())
        .map_err(|_| H2Fail::Closed)?;

    let (resp_fut, mut send_stream) = {
        let mut g = lane.send_req.lock().unwrap();
        let sr = g.as_mut().ok_or(H2Fail::Closed)?;
        sr.send_request(req, false).map_err(|_| H2Fail::Closed)?
    };
    if let Err(e) = send_stream.send_data(body, true) {
        return Err(lane.h2_err(&e));
    }

    // sent_since stamped AFTER the body is fully sent, BEFORE awaiting headers
    {
        let mut s = ch.state.lock().unwrap();
        s.sent_since.insert(task_id, now_monotonic());
        s.last_progress = now_monotonic();
    }

    let resp = resp_fut.await.map_err(|e| lane.h2_err(&e))?;
    let headers_at = now_monotonic();

    // (1) slow headers accounting
    let headers_elapsed = headers_at - started;
    if headers_elapsed >= SLOW_RESPONSE_SECONDS {
        lane.slow_headers.fetch_add(1, Ordering::Relaxed);
        lane.max_ms(&lane.max_headers_ms, (headers_elapsed * 1000.0) as u64);
    }

    let status = resp.status().as_u16();
    let cf_ray: String = resp
        .headers()
        .get("cf-ray")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(64)
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let declared: Option<u64> = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());

    // (3) MTProto transport error statuses — errors++, NO cooldown
    if status == 403 || status == 404 || status == 429 || status == 444 {
        log_warn(&format!(
            "H2 lane={} host={} transport status {} cf_ray={cf_ray}",
            lane.lane_id, lane.host, status
        ));
        return Err(lane.err_transport(-(status as i32)));
    }
    // (4) any other non-200 — non-transport, cooldown
    if status != 200 {
        return Err(lane.err_nontransport());
    }
    // (5) HTML error page
    if content_type.contains("text/html") {
        return Err(lane.err_nontransport());
    }
    // (6) response_started: receiving + last_progress BEFORE any body byte
    {
        let mut s = ch.state.lock().unwrap();
        s.receiving.insert(task_id);
        s.last_progress = now_monotonic();
    }
    let receiving = true;

    // (7) declared length sanity
    if let Some(decl) = declared {
        if decl > MAX_PACKET {
            cleanup_post(lane, ch, task_id, 0, receiving);
            return Err(lane.err_nontransport());
        }
    }

    // body loop
    let mut recv = resp.into_body();
    let mut out: Vec<u8> = Vec::new();
    let mut buffered: u64 = 0;
    let body_res = loop {
        let chunk = match recv.data().await {
            None => break Ok::<(), H2Fail>(()),
            Some(Ok(c)) => c,
            Some(Err(e)) => break Err(lane.h2_err(&e)),
        };
        let clen = chunk.len() as u64;
        if (out.len() as u64) + clen > MAX_PACKET {
            break Err(lane.err_nontransport());
        }
        if lane.reply_buffer_bytes.load(Ordering::Relaxed) + clen > MAX_LANE_REPLY_BYTES {
            // Python `BufferError` — bare re-raise: no lane counters, no cooldown.
            break Err(H2Fail::ReplyBufferFull);
        }
        lane.reply_buffer_bytes.fetch_add(clen, Ordering::Relaxed);
        buffered += clen;
        {
            let mut s = ch.state.lock().unwrap();
            s.last_progress = now_monotonic();
        }
        out.extend_from_slice(&chunk);
    };
    // drain trailers (Python awaits them after the body)
    let _ = recv.trailers().await;

    if let Err(e) = body_res {
        cleanup_post(lane, ch, task_id, buffered, receiving);
        return Err(e);
    }

    let received = out.len() as u64;
    if received > 0 && received % 4 != 0 {
        cleanup_post(lane, ch, task_id, buffered, receiving);
        return Err(lane.err_nontransport());
    }
    if let Some(decl) = declared {
        if content_type.contains("identity") && received != decl {
            cleanup_post(lane, ch, task_id, buffered, receiving);
            return Err(lane.err_nontransport());
        }
    }
    if received == 4 {
        let code = i32::from_le_bytes([out[0], out[1], out[2], out[3]]);
        if code < 0 {
            cleanup_post(lane, ch, task_id, buffered, receiving);
            return Err(lane.err_transport(code));
        }
    }

    // success accounting
    lane.responses.fetch_add(1, Ordering::Relaxed);
    {
        let mut s = ch.state.lock().unwrap();
        s.http_bytes += received;
        if received <= 4096 {
            s.small_responses += 1;
        } else {
            s.large_responses += 1;
        }
        let body_elapsed = now_monotonic() - headers_at;
        if body_elapsed >= SLOW_RESPONSE_SECONDS {
            lane.slow_bodies.fetch_add(1, Ordering::Relaxed);
            lane.max_ms(&lane.max_body_ms, (body_elapsed * 1000.0) as u64);
        }
        if body_elapsed >= SLOW_RESPONSE_SECONDS.max(2.0) && received > 4096 {
            let nl = f64::from_bits(lane.next_large_slow_log.load(Ordering::Relaxed)).max(
                now_monotonic() + 20.0,
            );
            lane.next_large_slow_log.store(nl.to_bits(), Ordering::Relaxed);
        }
    }
    cleanup_post(lane, ch, task_id, buffered, receiving);
    Ok(Bytes::from(out))
}

/// finally-block of `_post`: release reply buffer, clear receiving.
fn cleanup_post(lane: &Arc<H2Lane>, ch: &Arc<H2Channel>, task_id: u64, buffered: u64, receiving: bool) {
    let mut rb = lane.reply_buffer_bytes.load(Ordering::Relaxed);
    let mut target = rb.saturating_sub(buffered);
    // CAS loop to avoid clobbering concurrent increments
    loop {
        match lane
            .reply_buffer_bytes
            .compare_exchange_weak(rb, target, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(c) => {
                rb = c;
                target = rb.saturating_sub(buffered);
            }
        }
    }
    if receiving {
        ch.state.lock().unwrap().receiving.remove(&task_id);
    }
}

/// Port of `_run_request` reply delivery: update replay entry reply_id, check
/// channel byte cap, push into the bounded reply queue.
fn deliver_reply(ch: &Arc<H2Channel>, packet: Option<ReplayEntry>, reply: Bytes) {
    if ch.is_closed() || reply.is_empty() {
        return;
    }
    if let Some(mut p) = packet {
        if reply.len() >= 24 {
            let mut rid = [0u8; 24];
            rid.copy_from_slice(&reply[..24]);
            if p.reply_id != Some(rid) {
                p.reply_id = Some(rid);
                p.attempts = 0;
                let mut s = ch.state.lock().unwrap();
                if let Some(e) = s.replay_history.iter_mut().find(|e| e.key == p.key) {
                    e.reply_id = p.reply_id;
                    e.attempts = p.attempts;
                }
            }
        }
    }
    let fits = {
        let mut s = ch.state.lock().unwrap();
        if s.closed {
            return;
        }
        if s.reply_bytes + (reply.len() as u64) > MAX_CHANNEL_BYTES {
            false
        } else {
            s.reply_bytes += reply.len() as u64;
            true
        }
    };
    if !fits {
        ch.fail(H2Fail::Closed);
        return;
    }
    match ch.tx.try_send(reply) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            ch.fail(H2Fail::Closed);
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // bridge already gone — drop the reply
        }
    }
}

// ---------------------------------------------------------------------------
// H2Pool
// ---------------------------------------------------------------------------

pub struct H2Pool {
    self_ref: Mutex<Option<Weak<H2Pool>>>,
    closed: AtomicBool,
    lanes: Mutex<HashMap<String, Arc<H2Lane>>>,
    host_locks: Mutex<HashMap<String, Arc<TokioMutex<()>>>>,
    failed_until: Mutex<HashMap<String, AtomicU64>>, // f64 bits per host
    setup_retry_after: Mutex<HashMap<i32, AtomicU64>>, // f64 bits per dc
    next_lane: AtomicU64,
    next_channel: AtomicU64,
}

impl H2Pool {
    pub fn new() -> Arc<Self> {
        let p = Arc::new(H2Pool {
            self_ref: Mutex::new(None),
            closed: AtomicBool::new(false),
            lanes: Mutex::new(HashMap::new()),
            host_locks: Mutex::new(HashMap::new()),
            failed_until: Mutex::new(HashMap::new()),
            setup_retry_after: Mutex::new(HashMap::new()),
            next_lane: AtomicU64::new(1),
            next_channel: AtomicU64::new(1),
        });
        *p.self_ref.lock().unwrap() = Some(Arc::downgrade(&p));
        p
    }

    fn self_arc(&self) -> Option<Arc<H2Pool>> {
        self.self_ref.lock().unwrap().as_ref().and_then(|w| w.upgrade())
    }

    /// `CfH2Pool.open` (cf_h2.py L870-943): setup-retry gate + 8s timeout.
    pub async fn open(&self, dc: i32, label: String) -> Option<Arc<H2Channel>> {
        if self.closed.load(Ordering::Relaxed) {
            return None;
        }
        let now = now_monotonic();
        {
            let gate = self.setup_retry_after.lock().unwrap();
            if let Some(slot) = gate.get(&dc) {
                if f64::from_bits(slot.load(Ordering::Relaxed)) > now {
                    return None;
                }
            }
        }
        let label_t = label.clone();
        match tokio::time::timeout(Duration::from_secs_f64(SETUP_TIMEOUT), self._open(dc, label_t)).await {
            Ok(ch) => ch,
            Err(_) => {
                let until = (now + DOMAIN_COOLDOWN).to_bits();
                let mut gate = self.setup_retry_after.lock().unwrap();
                let slot = gate.entry(dc).or_insert(AtomicU64::new(0));
                let prev = slot.load(Ordering::Relaxed);
                if until >= prev {
                    slot.store(until, Ordering::Relaxed);
                }
                STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                log_warn(&format!("[{label}] H2 open dc={dc} setup timeout"));
                None
            }
        }
    }

    async fn _open(&self, dc: i32, label: String) -> Option<Arc<H2Channel>> {
        if !DC_DEFAULT_IPS.contains_key(&dc) {
            return None;
        }
        let domains = balancer::BALANCER.read().get_domains_for_dc(dc);
        for base_domain in domains {
            if cf_timeout_in_cooldown(&base_domain, true) {
                continue;
            }
            let host = format!("kws{dc}.{base_domain}");
            let hlock = {
                let mut locks = self.host_locks.lock().unwrap();
                locks
                    .entry(host.clone())
                    .or_insert_with(|| Arc::new(TokioMutex::new(())))
                    .clone()
            };
            let _g = hlock.lock().await;

            let now = now_monotonic();
            {
                let f = self.failed_until.lock().unwrap();
                if let Some(slot) = f.get(&host) {
                    if f64::from_bits(slot.load(Ordering::Relaxed)) > now {
                        continue;
                    }
                }
            }

            let existing = self.lanes.lock().unwrap().get(&host).cloned().filter(|l| !l.dead.load(Ordering::Relaxed));
            let lane = match existing {
                Some(l) if !l.is_failed(now) => l,
                Some(_) => continue,
                None => {
                    // drop any lingering dead lane from the map
                    {
                        let mut lanes = self.lanes.lock().unwrap();
                        if let Some(l) = lanes.get(&host) {
                            if l.dead.load(Ordering::Relaxed) {
                                lanes.remove(&host);
                            }
                        }
                    }
                    let pool = match self.self_arc() {
                        Some(p) => p,
                        None => return None,
                    };
                    let id = self.next_lane.fetch_add(1, Ordering::Relaxed);
                    let l = H2Lane::new(pool, host.clone(), id);
                    match l.preflight().await {
                        Ok(()) => {
                            self.lanes.lock().unwrap().insert(host.clone(), l.clone());
                            l
                        }
                        Err(e) => {
                            log_warn(&format!("[{label}] H2 preflight {host} failed: {e}"));
                            {
                                let until = (now + DOMAIN_COOLDOWN).to_bits();
                                let mut f = self.failed_until.lock().unwrap();
                                let slot = f.entry(host.clone()).or_insert(AtomicU64::new(0));
                                let prev = slot.load(Ordering::Relaxed);
                                if until >= prev {
                                    slot.store(until, Ordering::Relaxed);
                                }
                            }
                            let _ = l.close().await;
                            continue;
                        }
                    }
                }
            };

            let ch_id = self.next_channel.fetch_add(1, Ordering::Relaxed);
            let ch = H2Channel::new(lane, ch_id, label.clone());
            balancer::BALANCER.write().update_domain_for_dc(dc, &base_domain);
            log_info(&format!("[{label}] H2 ROUTE dc={dc} host={host}"));
            return Some(ch);
        }
        None
    }

    /// Remove a dead lane from the map (only if it is still the mapped one).
    pub fn remove_lane_if_dead(&self, host: &str) {
        let mut lanes = self.lanes.lock().unwrap();
        if let Some(l) = lanes.get(host) {
            if l.dead.load(Ordering::Relaxed) {
                lanes.remove(host);
            }
        }
    }

    /// Close all lanes (shutdown / reset).
    pub async fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let lanes: Vec<(String, Arc<H2Lane>)> = {
            let mut m = self.lanes.lock().unwrap();
            m.drain().collect()
        };
        for (_, l) in lanes {
            l.close().await;
        }
    }

    pub fn log_stats(&self) {
        let lanes: Vec<Arc<H2Lane>> = self.lanes.lock().unwrap().values().cloned().collect();
        for l in lanes {
            if l.channels_count() > 0 {
                log_debug(&format!("H2 STATS {}", l.summary()));
            }
        }
    }

    pub fn log_flow(&self) {
        let now = now_monotonic();
        let lanes: Vec<Arc<H2Lane>> = self.lanes.lock().unwrap().values().cloned().collect();
        for l in lanes {
            l.log_flow(now);
        }
    }

    /// Battery pass: close lanes that have no channels and have been idle for
    /// `H2_LANE_IDLE_CLOSE_SECS`.
    pub fn close_idle_lanes(&self) {
        let mut to_close = Vec::new();
        {
            let lanes = self.lanes.lock().unwrap();
            for (host, l) in lanes.iter() {
                if l.idle_for_close() {
                    to_close.push((host.clone(), l.clone()));
                }
            }
        }
        for (host, l) in to_close {
            let same = {
                let lanes = self.lanes.lock().unwrap();
                lanes.get(&host).map(|cur| Arc::ptr_eq(cur, &l)).unwrap_or(false)
            };
            if !same {
                continue;
            }
            self.lanes.lock().unwrap().remove(&host);
            log_debug(&format!("H2 idle lane closed host={host}"));
            tokio::spawn(async move {
                l.close().await;
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Bridge (cf_h2.py `bridge_h2` L945-1001)
// ---------------------------------------------------------------------------

/// Run the H2 bridge for one client session. `clt_dec` decrypts client→proxy
/// upload framing; `clt_enc` encrypts proxy→client download framing.
/// Terminates when either direction fails; on a transport error writes the
/// int32le code back to the client.
pub async fn bridge_h2<R, W>(
    reader: &mut R,
    writer: &mut W,
    channel: Arc<H2Channel>,
    tag: u32,
    label: String,
    mut clt_dec: TrackedStream,
    mut clt_enc: TrackedStream,
    cancel_token: CancellationToken,
) where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let (rx, fail_rx) = channel.take_receiver();
    let mut rx = rx;
    let mut fail_rx = fail_rx;
    if *fail_rx.borrow_and_update() {
        channel.close().await;
        return;
    }

    // Three concurrent "tasks" as plain futures: `select!` polls them in place
    // and dropping the losers cancels them (Python `asyncio.wait` + `cancel()`).
    enum Dir {
        Upload,
        Download,
        Recovery,
    }
    let up_ch = Arc::clone(&channel);
    let up_label = label.clone();
    let mut upload = Box::pin(async {
        loop {
            let (body, quick) = match read_packet(reader, &mut clt_dec, tag).await {
                Ok(v) => v,
                Err(e) => {
                    log_debug(&format!("[{up_label}] H2 upload end: {e}"));
                    return;
                }
            };
            if !up_ch.send(body, quick).await {
                log_debug(&format!("[{up_label}] H2 upload rejected"));
                return;
            }
        }
    });

    let down_ch = Arc::clone(&channel);
    let down_label = label.clone();
    let mut download = Box::pin(async {
        loop {
            let body = match down_ch.receive(&mut rx, &mut fail_rx).await {
                Some(b) => b,
                None => return,
            };
            let frame = match encode_reply(&body, tag) {
                Some(f) => f,
                None => {
                    log_warn(&format!("[{down_label}] H2 bad reply body len={}", body.len()));
                    return;
                }
            };
            let mut out = frame.to_vec();
            clt_enc.xor(&mut out);
            if writer.write_all(&out).await.is_err() {
                return;
            }
            if writer.flush().await.is_err() {
                return;
            }
            {
                let mut s = down_ch.state.lock().unwrap();
                s.down += frame.len() as u64;
                s.last_progress = now_monotonic();
            }
            STATS.bytes_down.fetch_add(frame.len() as i64, Ordering::Relaxed);
        }
    });

    let mut recovery = Box::pin(channel.recover());

    let finished = tokio::select! {
        _ = &mut upload => Dir::Upload,
        _ = &mut download => Dir::Download,
        _ = &mut recovery => Dir::Recovery,
        _ = cancel_token.cancelled() => Dir::Recovery,
    };
    let _ = finished;
    drop(upload);
    drop(download);
    drop(recovery);

    if let Some(code) = channel.transport_error() {
        let err_body = code.to_le_bytes();
        if let Some(frame) = encode_reply(&err_body, tag) {
            let mut buf = frame.to_vec();
            clt_enc.xor(&mut buf);
            let _ = writer.write_all(&buf).await;
            let _ = writer.flush().await;
        }
    }
    channel.close().await;
    let _ = cancel_token;
}

// ---------------------------------------------------------------------------
// Global pool
// ---------------------------------------------------------------------------

static H2_POOL: Lazy<Arc<H2Pool>> = Lazy::new(H2Pool::new);

pub fn h2_pool() -> &'static Arc<H2Pool> {
    &H2_POOL
}

/// Shutdown hook (called from StopProxy inside the runtime).
pub async fn close_h2_pool() {
    H2_POOL.close().await;
}
