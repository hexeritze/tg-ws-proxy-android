//! Fake TLS fronting for the masking site.
//!
//! Accepts the proxy's 5-byte handshake prefix, verifies the HMAC-authenticated
//! ClientHello (the first 28 bytes of client_random carry the HMAC prefix, the
//! next 4 carry an XOR-masked little-endian timestamp) and answers with a
//! synthetic ServerHello + CCS + one ApplicationData record whose HMAC covers
//! the whole flight. Replayed ClientHellos are routed to the masking domain so
//! an active prober cannot distinguish this proxy from the real site.

use crate::config::{log_debug, log_warn, STATS};
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use rand::RngCore;
use sha2::Sha256;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_CCS: u8 = 0x14;
pub const TLS_RECORD_APPDATA: u8 = 0x17;

const CLIENT_RANDOM_OFFSET: usize = 11;
const CLIENT_RANDOM_LEN: usize = 32;
const SESSION_ID_OFFSET: usize = 44;
const SESSION_ID_LEN: usize = 32;

const TIMESTAMP_TOLERANCE: i64 = 120;
const TLS_APPDATA_MAX: usize = 16384;
const APPDATA_MIN: u32 = 64;
const APPDATA_FALLBACK_RANGE: (u32, u32) = (64, 160);
const SERVER_HELLO_DELAY_MS: (u64, u64) = (8, 24);
const PROFILE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_MAX_FLIGHT: usize = 128 * 1024;

const READ_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_RECORD_TIMEOUT: Duration = Duration::from_secs(10);
const MASKING_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

// Offsets inside the ServerHello record:
// 5 (record hdr) + 4 (handshake type+len) + 2 (version) = 11.
const SH_RANDOM_OFF: usize = 11;

// TLS extension / key-share constants (mirror of fake_tls.py).
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519MLKEM768: u16 = 0x11ec;
const X25519_KEY_LEN: usize = 32;
const X25519MLKEM768_CLIENT_SHARE_LEN: usize = 1216;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

// Pick the first offered suite in this order, default TLS_AES_128_GCM_SHA256.
const CIPHER_PREFERENCE: [u16; 3] = [0x1301, 0x1303, 0x1302];

// ClientHello replay window: 2 * 120s (timestamp validity) + 1s slack.
const REPLAY_WINDOW: Duration = Duration::from_secs(241);
const REPLAY_CACHE_SIZE: usize = 65536;

type HmacSha256 = Hmac<Sha256>;

pub struct FakeTlsStream {
    pub read: Box<dyn AsyncRead + Send + Unpin>,
    pub write: Box<dyn AsyncWrite + Send + Unpin>,
}

/// Offered cipher suites and key_share groups from a ClientHello.
#[derive(Default)]
struct ClientHelloInfo {
    cipher_suites: HashSet<u16>,
    key_shares: HashMap<u16, usize>, // named group -> key_exchange length
}

fn parse_client_hello(data: &[u8]) -> ClientHelloInfo {
    // Extract offered cipher suites and key_share groups. Malformed input
    // yields empty info so the caller answers plain X25519 / 0x1301.
    let mut info = ClientHelloInfo::default();
    let mut pos = 5 + 4 + 2 + CLIENT_RANDOM_LEN; // 43
    if pos >= data.len() {
        return info;
    }
    pos += 1 + data[pos] as usize;
    if pos + 2 > data.len() {
        return info;
    }
    let suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let suites_end = pos + suites_len;
    if suites_end > data.len() {
        return info;
    }
    let mut off = pos;
    while off + 2 <= suites_end {
        info
            .cipher_suites
            .insert(u16::from_be_bytes([data[off], data[off + 1]]));
        off += 2;
    }
    pos = suites_end;
    if pos >= data.len() {
        return info;
    }
    pos += 1 + data[pos] as usize;
    if pos + 2 > data.len() {
        return info;
    }
    let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(data.len());
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if ext_type == EXT_KEY_SHARE && pos + 2 <= ext_end {
            let list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            let shares_end = (pos + 2 + list_len).min(ext_end);
            let mut soff = pos + 2;
            while soff + 4 <= shares_end {
                let group = u16::from_be_bytes([data[soff], data[soff + 1]]);
                let key_len = u16::from_be_bytes([data[soff + 2], data[soff + 3]]) as usize;
                soff += 4 + key_len;
                if soff <= shares_end {
                    // First occurrence wins (setdefault).
                    info.key_shares.entry(group).or_insert(key_len);
                }
            }
        }
        pos += ext_len;
    }
    info
}

fn verify_client_hello(data: &[u8], secret: &[u8]) -> Option<([u8; 32], [u8; 32], i64)> {
    if data.len() < 43 {
        return None;
    }
    if data[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }
    if data[5] != 0x01 {
        return None;
    }

    let mut client_random = [0u8; 32];
    client_random
        .copy_from_slice(&data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN]);

    let mut zeroed = data.to_vec();
    for b in &mut zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN] {
        *b = 0;
    }

    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(&zeroed);
    let expected = mac.finalize().into_bytes();

    if expected[..28] != client_random[..28] {
        return None;
    }

    let mut ts_bytes = [0u8; 4];
    for i in 0..4 {
        ts_bytes[i] = client_random[28 + i] ^ expected[28 + i];
    }
    let timestamp = u32::from_le_bytes(ts_bytes) as i64;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (now - timestamp).abs() > TIMESTAMP_TOLERANCE {
        return None;
    }

    let mut session_id = [0u8; 32];
    if data.len() >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43] == 0x20 {
        session_id
            .copy_from_slice(&data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]);
    }

    Some((client_random, session_id, timestamp))
}

fn select_cipher(info: &ClientHelloInfo) -> u16 {
    for &suite in CIPHER_PREFERENCE.iter() {
        if info.cipher_suites.contains(&suite) {
            return suite;
        }
    }
    CIPHER_PREFERENCE[0]
}

fn x25519_public_key() -> [u8; 32] {
    // A fresh ephemeral X25519 public key; fall back to a field element
    // (top bit clear) if ring cannot generate one.
    let rng = ring::rand::SystemRandom::new();
    match ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng) {
        Ok(kp) => match kp.compute_public_key() {
            Ok(pk) => {
                let mut out = [0u8; 32];
                out.copy_from_slice(pk.as_ref());
                out
            }
            Err(_) => {
                let mut out = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut out);
                out[X25519_KEY_LEN - 1] &= 0x7f;
                out
            }
        },
        Err(_) => {
            let mut out = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut out);
            out[X25519_KEY_LEN - 1] &= 0x7f;
            out
        }
    }
}

/// Mirror the hybrid post-quantum group when the client offers it, as current
/// browsers and servers do; the client never derives keys from it.
fn server_key_share(info: &ClientHelloInfo) -> (u16, Vec<u8>) {
    if info
        .key_shares
        .get(&GROUP_X25519MLKEM768)
        == Some(&X25519MLKEM768_CLIENT_SHARE_LEN)
    {
        let mut ke = vec![0u8; MLKEM768_CIPHERTEXT_LEN + X25519_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut ke[..MLKEM768_CIPHERTEXT_LEN]);
        ke[MLKEM768_CIPHERTEXT_LEN..].copy_from_slice(&x25519_public_key());
        (GROUP_X25519MLKEM768, ke)
    } else {
        (GROUP_X25519, x25519_public_key().to_vec())
    }
}

fn appdata_len() -> usize {
    let profiled = PROFILED_APPDATA_LEN.load(Ordering::Relaxed);
    if profiled != 0 {
        return profiled as usize;
    }
    let (lo, hi) = APPDATA_FALLBACK_RANGE;
    lo as usize + (rand::thread_rng().next_u32() % (hi - lo + 1)) as usize
}

/// Length of the first ApplicationData record in a server's first flight.
/// Returns None while more data is needed, 0 if the flight cannot contain
/// one (alert, TLS 1.2 handshake, garbage).
fn first_appdata_record_len(data: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    while pos + 5 <= data.len() {
        let rtype = data[pos];
        let rec_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
        if rtype == TLS_RECORD_APPDATA {
            return Some(rec_len);
        }
        if rtype != TLS_RECORD_HANDSHAKE && rtype != TLS_RECORD_CCS {
            return Some(0);
        }
        pos += 5 + rec_len;
    }
    None
}

/// ServerHello + CCS + one ApplicationData record.
///
/// Telegram clients parse exactly these three records and check the HMAC over
/// all of them, so the shape stays fixed while sizes may vary.
fn build_server_hello(
    secret: &[u8],
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    info: &ClientHelloInfo,
) -> Vec<u8> {
    let (group, key_exchange) = server_key_share(info);

    let mut exts = Vec::with_capacity(7 + 8 + key_exchange.len());
    exts.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&0x0304u16.to_be_bytes());
    exts.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
    exts.extend_from_slice(&(4u16 + key_exchange.len() as u16).to_be_bytes());
    exts.extend_from_slice(&group.to_be_bytes());
    exts.extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
    exts.extend_from_slice(&key_exchange);

    let mut body =
        Vec::with_capacity(2 + 32 + 1 + session_id.len() + 2 + 1 + 2 + exts.len());
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&select_cipher(info).to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut message = Vec::with_capacity(4 + body.len());
    message.push(0x02);
    let mlen = body.len() as u32;
    message.extend_from_slice(&[(mlen >> 16) as u8, (mlen >> 8) as u8, mlen as u8]);
    message.extend_from_slice(&body);

    let mut server_hello = Vec::with_capacity(5 + message.len());
    server_hello.push(TLS_RECORD_HANDSHAKE);
    server_hello.extend_from_slice(&[0x03, 0x03]);
    server_hello
        .extend_from_slice(&(message.len() as u16).to_be_bytes());
    server_hello.extend_from_slice(&message);

    let alen = appdata_len();
    let mut response = Vec::with_capacity(server_hello.len() + CCS_FRAME.len() + 5 + alen);
    response.extend_from_slice(&server_hello);
    response.extend_from_slice(&CCS_FRAME);
    response.push(TLS_RECORD_APPDATA);
    response.extend_from_slice(&[0x03, 0x03]);
    response.extend_from_slice(&(alen as u16).to_be_bytes());
    let mut encrypted = vec![0u8; alen];
    rand::thread_rng().fill_bytes(&mut encrypted);
    response.extend_from_slice(&encrypted);

    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(client_random);
    mac.update(&response);
    let server_random = mac.finalize().into_bytes();

    let mut final_bytes = response;
    final_bytes[SH_RANDOM_OFF..SH_RANDOM_OFF + 32].copy_from_slice(&server_random);
    final_bytes
}

// ---------------------------------------------------------------------------
// Profiled appdata length
// ---------------------------------------------------------------------------

static PROFILED_APPDATA_LEN: AtomicU32 = AtomicU32::new(0);

pub fn set_profiled_appdata_len(length: Option<u32>) {
    match length {
        None => PROFILED_APPDATA_LEN.store(0, Ordering::Relaxed),
        Some(l) => {
            let clamped = l.clamp(APPDATA_MIN, TLS_APPDATA_MAX as u32);
            PROFILED_APPDATA_LEN.store(clamped, Ordering::Relaxed);
        }
    }
}

fn probe_client_config() -> Option<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // `builder()` already selects the safe defaults (TLS 1.3 with the ring
    // provider); only the trust store and client-auth choice remain.
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Some(Arc::new(config))
}

/// Measure the first encrypted record the masking site sends after ServerHello.
/// The ClientHello is sent raw and the flight is read before the handshake
/// completes, so the local TLS state never needs the server's certificate.
pub async fn probe_appdata_len(domain: &str) -> Option<usize> {
    let config = probe_client_config()?;
    let server_name = rustls::pki_types::ServerName::try_from(domain.to_string()).ok()?;
    let mut conn = rustls::ClientConnection::new(config, server_name).ok()?;
    // rustls 0.23 buffers the ClientHello in the connection; drain it with
    // `write_tls` (there is no `send()` in this API).
    let mut first_flight = Vec::new();
    if conn.write_tls(&mut first_flight).is_err() || first_flight.is_empty() {
        return None;
    }

    let stream = match tokio::time::timeout(
        PROFILE_PROBE_TIMEOUT,
        TcpStream::connect((domain, 443u16)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            log_debug(&format!("faketls probe: cannot connect to {}:443", domain));
            return None;
        }
    };
    let mut stream = stream;
    let _ = stream.set_nodelay(true);

    let deadline = tokio::time::Instant::now() + PROFILE_PROBE_TIMEOUT;
    if tokio::time::timeout_at(deadline, stream.write_all(&first_flight)).await.is_err() {
        return None;
    }
    let _ = stream.flush().await;

    let mut flight = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let n = match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => return None,
        };
        if n == 0 {
            return None;
        }
        flight.extend_from_slice(&buf[..n]);
        match first_appdata_record_len(&flight) {
            Some(0) => return None,
            Some(len) => {
                log_debug(&format!(
                    "faketls probe: {} first appdata record = {} bytes",
                    domain, len
                ));
                return Some(len);
            }
            None => {}
        }
        if flight.len() > PROBE_MAX_FLIGHT {
            return None;
        }
    }
}

// ---------------------------------------------------------------------------
// ClientHello replay cache
// ---------------------------------------------------------------------------

struct ReplayCache {
    order: VecDeque<[u8; 32]>,
    expiry: HashMap<[u8; 32], Instant>,
}

impl ReplayCache {
    fn new() -> Self {
        ReplayCache {
            order: VecDeque::with_capacity(REPLAY_CACHE_SIZE),
            expiry: HashMap::with_capacity(REPLAY_CACHE_SIZE),
        }
    }

    /// Returns true if this client_random was not seen within the window.
    /// Insertion order is expiry order, so stale entries are at the front.
    fn first_seen(&mut self, client_random: &[u8; 32]) -> bool {
        let now = Instant::now();
        while let Some(front) = self.order.front().copied() {
            let expired = self
                .expiry
                .get(&front)
                .map(|e| *e <= now)
                .unwrap_or(true);
            if !expired {
                break;
            }
            self.order.pop_front();
            self.expiry.remove(&front);
        }
        if self.expiry.contains_key(client_random) {
            return false;
        }
        if self.order.len() >= REPLAY_CACHE_SIZE {
            if let Some(oldest) = self.order.pop_front() {
                self.expiry.remove(&oldest);
            }
        }
        self.expiry.insert(*client_random, now + REPLAY_WINDOW);
        self.order.push_back(*client_random);
        true
    }
}

static REPLAY_CACHE: Lazy<Mutex<ReplayCache>> = Lazy::new(|| Mutex::new(ReplayCache::new()));

pub fn replay_first_seen(client_random: &[u8; 32]) -> bool {
    let mut g = REPLAY_CACHE.lock().unwrap_or_else(|p| p.into_inner());
    g.first_seen(client_random)
}

// ---------------------------------------------------------------------------
// Record framing
// ---------------------------------------------------------------------------

fn wrap_tls_record(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / TLS_APPDATA_MAX + 1));
    let mut offset = 0;
    while offset < data.len() {
        let end = std::cmp::min(offset + TLS_APPDATA_MAX, data.len());
        let chunk = &data[offset..end];
        out.push(TLS_RECORD_APPDATA);
        out.push(0x03);
        out.push(0x03);
        out.push((chunk.len() >> 8) as u8);
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
        offset = end;
    }
    out
}

struct TlsRecordReader {
    inner: ReadHalf<TcpStream>,
    buf: Vec<u8>,
    pos: usize,
    read_left: usize,
}

impl TlsRecordReader {
    fn new(inner: ReadHalf<TcpStream>) -> Self {
        TlsRecordReader {
            inner,
            buf: Vec::new(),
            pos: 0,
            read_left: 0,
        }
    }

    fn compact(&mut self) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn next_payload(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            loop {
                if self.read_left > 0 {
                    let want = std::cmp::min(self.read_left, 16384);
                    let mut chunk = vec![0u8; want];
                    let n = self.inner.read(&mut chunk).await?;
                    if n == 0 {
                        return Ok(Vec::new());
                    }
                    chunk.truncate(n);
                    self.read_left -= n;
                    return Ok(chunk);
                }

                let mut hdr = [0u8; 5];
                self.inner.read_exact(&mut hdr).await?;
                let rtype = hdr[0];
                let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;

                if rtype == TLS_RECORD_CCS {
                    if rec_len > 0 {
                        let mut junk = vec![0u8; rec_len];
                        self.inner.read_exact(&mut junk).await?;
                    }
                    continue;
                }

                if rtype != TLS_RECORD_APPDATA {
                    return Ok(Vec::new());
                }

                let want = std::cmp::min(rec_len, 65536);
                let mut chunk = vec![0u8; want];
                let n = self.inner.read(&mut chunk).await?;
                if n == 0 {
                    return Ok(Vec::new());
                }
                chunk.truncate(n);
                if rec_len > n {
                    self.read_left = rec_len - n;
                }
                return Ok(chunk);
            }
        })
    }
}

impl AsyncRead for TlsRecordReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            let avail = this.buf.len() - this.pos;
            if avail > 0 {
                let n = std::cmp::min(avail, buf.remaining());
                let src = &this.buf[this.pos..this.pos + n];
                buf.put_slice(src);
                this.pos += n;
                if this.pos == this.buf.len() {
                    this.buf.clear();
                    this.pos = 0;
                }
                return std::task::Poll::Ready(Ok(()));
            }

            this.compact();
            let polled = {
                let mut fut = this.next_payload();
                Pin::new(&mut fut).poll(cx)
            };
            match polled {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => {
                    return std::task::Poll::Ready(Err(
                        if e.kind() == std::io::ErrorKind::UnexpectedEof {
                            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "faketls eof")
                        } else {
                            e
                        },
                    ))
                }
                std::task::Poll::Ready(Ok(payload)) => {
                    if payload.is_empty() {
                        return std::task::Poll::Ready(Ok(()));
                    }
                    this.buf = payload;
                    this.pos = 0;
                }
            }
        }
    }
}

struct TlsRecordWriter {
    inner: WriteHalf<TcpStream>,
}

impl TlsRecordWriter {
    fn new(inner: WriteHalf<TcpStream>) -> Self {
        TlsRecordWriter { inner }
    }
}

impl AsyncWrite for TlsRecordWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let wrapped = wrap_tls_record(buf);
        match Pin::new(&mut this.inner).poll_write(cx, &wrapped) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Ok(n)) => {
                std::task::Poll::Ready(Ok(if n >= buf.len() { buf.len() } else { n }))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Handshake entry point
// ---------------------------------------------------------------------------

pub async fn server_handshake(
    mut conn: TcpStream,
    first: u8,
    secret: &[u8],
    masking: &str,
    label: &str,
) -> Option<FakeTlsStream> {
    let mut hdr_rest = [0u8; 4];
    match tokio::time::timeout(READ_HANDSHAKE_TIMEOUT, conn.read_exact(&mut hdr_rest)).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record header", label));
            return None;
        }
    }

    let mut tls_header = [0u8; 5];
    tls_header[0] = first;
    tls_header[1..5].copy_from_slice(&hdr_rest);
    let record_len = u16::from_be_bytes([tls_header[3], tls_header[4]]) as usize;

    let mut body = vec![0u8; record_len];
    match tokio::time::timeout(READ_RECORD_TIMEOUT, conn.read_exact(&mut body)).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record body", label));
            return None;
        }
    }

    let mut client_hello = Vec::with_capacity(5 + record_len);
    client_hello.extend_from_slice(&tls_header);
    client_hello.extend_from_slice(&body);

    let tls_result = verify_client_hello(&client_hello, secret);
    // A recorded hello stays valid for minutes; answering it again would tell
    // an active prober that this is a proxy, not the masking site.
    let replayed = matches!(tls_result, Some((ref cr, _, _)) if !replay_first_seen(cr));

    match (tls_result, replayed) {
        (Some((client_random, session_id, ts)), false) => {
            log_debug(&format!("[{}] Fake TLS handshake ok (ts={})", label, ts));
            let info = parse_client_hello(&client_hello);
            let server_hello = build_server_hello(secret, &client_random, &session_id, &info);
            let (lo, hi) = SERVER_HELLO_DELAY_MS;
            let delay = lo + rand::thread_rng().next_u64() % (hi - lo + 1);
            tokio::time::sleep(Duration::from_millis(delay)).await;
            if conn.write_all(&server_hello).await.is_err() {
                return None;
            }
            let _ = conn.flush().await;

            let (r, w) = tokio::io::split(conn);
            Some(FakeTlsStream {
                read: Box::new(TlsRecordReader::new(r)),
                write: Box::new(TlsRecordWriter::new(w)),
            })
        }
        _ => {
            log_debug(&format!(
                "[{}] Fake TLS {} (size={} rec={}) -> masking",
                label,
                if replayed { "hello replayed" } else { "verify failed" },
                client_hello.len(),
                record_len
            ));
            proxy_to_masking_domain(conn, client_hello, masking, label).await;
            None
        }
    }
}

async fn proxy_to_masking_domain(conn: TcpStream, initial: Vec<u8>, domain: &str, label: &str) {
    let upstream = match tokio::time::timeout(
        MASKING_CONNECT_TIMEOUT,
        TcpStream::connect((domain, 443u16)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            log_warn(&format!(
                "[{}] masking: cannot connect to {}:443",
                label, domain
            ));
            return;
        }
    };

    log_debug(&format!("[{}] masking -> {}:443", label, domain));
    STATS
        .connections_masked
        .fetch_add(1, Ordering::Relaxed);

    let mut upstream = upstream;
    if upstream.write_all(&initial).await.is_err() {
        return;
    }

    let (mut c_read, mut c_write) = tokio::io::split(conn);
    let (mut u_read, mut u_write) = tokio::io::split(upstream);

    let up = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut c_read, &mut u_write).await;
        let _ = u_write.shutdown().await;
    });
    let down = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut u_read, &mut c_write).await;
        let _ = c_write.shutdown().await;
    });

    let _ = tokio::join!(up, down);
}
