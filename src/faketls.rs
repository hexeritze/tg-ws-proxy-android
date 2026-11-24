use crate::config::{log_debug, log_warn, STATS};
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
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

const READ_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_RECORD_TIMEOUT: Duration = Duration::from_secs(10);
const MASKING_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

const SH_RANDOM_OFF: usize = 11;
type HmacSha256 = Hmac<Sha256>;

pub struct FakeTlsStream {
    pub read: Box<dyn AsyncRead + Send + Unpin>,
    pub write: Box<dyn AsyncWrite + Send + Unpin>,
}

#[derive(Default)]
struct ReplayCache {
    expiry: HashMap<[u8; 32], f64>,
    order: VecDeque<([u8; 32], f64)>,
}
impl ReplayCache {
    fn first_seen(&mut self, random: [u8; 32], now: f64) -> bool {
        while self.order.front().is_some_and(|(_, expiry)| *expiry <= now) {
            if let Some((random, _)) = self.order.pop_front() {
                self.expiry.remove(&random);
            }
        }
        if self.expiry.contains_key(&random) {
            return false;
        }
        if self.order.len() >= 65536 {
            if let Some((old, _)) = self.order.pop_front() {
                self.expiry.remove(&old);
            }
        }
        let expiry = now + 241.0;
        self.expiry.insert(random, expiry);
        self.order.push_back((random, expiry));
        true
    }
}
// Process lifetime matches upstream, including stop/start cycles.
static REPLAY_CACHE: Lazy<Mutex<ReplayCache>> = Lazy::new(Default::default);
static PROFILE: Lazy<Mutex<(String, Option<usize>, f64)>> = Lazy::new(Default::default);

#[derive(Default)]
struct ClientHelloInfo {
    suites: Vec<u16>,
    key_shares: HashMap<u16, usize>,
}
fn read_u16(data: &[u8], position: &mut usize) -> Option<usize> {
    let bytes = data.get(*position..*position + 2)?;
    *position += 2;
    Some(u16::from_be_bytes(bytes.try_into().ok()?) as usize)
}
fn parse_client_hello(data: &[u8]) -> Option<ClientHelloInfo> {
    let mut position = 43;
    position += 1 + *data.get(position)? as usize;
    let suites_length = read_u16(data, &mut position)?;
    let suites = data
        .get(position..position + suites_length)?
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    position += suites_length;
    position += 1 + *data.get(position)? as usize;
    let extensions_length = read_u16(data, &mut position)?;
    let end = (position + extensions_length).min(data.len());
    let mut key_shares = HashMap::new();
    while position + 4 <= end {
        let kind = read_u16(data, &mut position)?;
        let length = read_u16(data, &mut position)?;
        let next = position + length;
        if next > end {
            return None;
        }
        if kind == 0x33 {
            let size = read_u16(data, &mut position)?;
            let shares_end = (position + size).min(next);
            while position + 4 <= shares_end {
                let group = read_u16(data, &mut position)? as u16;
                let size = read_u16(data, &mut position)?;
                position += size;
                if position <= shares_end {
                    key_shares.entry(group).or_insert(size);
                }
            }
        }
        position = next;
    }
    Some(ClientHelloInfo { suites, key_shares })
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

    if !bool::from(expected[..28].ct_eq(&client_random[..28])) {
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
        session_id.copy_from_slice(&data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]);
    }

    Some((client_random, session_id, timestamp))
}

fn build_server_hello(
    secret: &[u8],
    random: &[u8; 32],
    session: &[u8; 32],
    info: &ClientHelloInfo,
) -> Vec<u8> {
    let hybrid = info.key_shares.get(&0x11ec) == Some(&1216);
    let group: u16 = if hybrid { 0x11ec } else { 0x1d };
    let key = ring::agreement::EphemeralPrivateKey::generate(
        &ring::agreement::X25519,
        &ring::rand::SystemRandom::new(),
    )
    .expect("system entropy")
    .compute_public_key()
    .expect("X25519 key");
    let mut exchange = vec![0; if hybrid { 1088 } else { 0 }];
    rand::thread_rng().fill_bytes(&mut exchange);
    exchange.extend_from_slice(key.as_ref());
    let suite = [0x1301u16, 0x1303, 0x1302]
        .into_iter()
        .find(|suite| info.suites.contains(suite))
        .unwrap_or(0x1301);
    let mut extensions = vec![0, 0x2b, 0, 2, 3, 4, 0, 0x33];
    extensions.extend_from_slice(&((exchange.len() + 4) as u16).to_be_bytes());
    extensions.extend_from_slice(&group.to_be_bytes());
    extensions.extend_from_slice(&(exchange.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&exchange);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.push(32);
    body.extend_from_slice(session);
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut response = vec![0x16, 3, 3];
    response.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    response.push(2);
    response.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    response.extend_from_slice(&body);
    response.extend_from_slice(&CCS_FRAME);
    let appdata_size = PROFILE
        .lock()
        .1
        .unwrap_or_else(|| rand::thread_rng().gen_range(64..=160));
    response.extend_from_slice(&[0x17, 3, 3]);
    response.extend_from_slice(&(appdata_size as u16).to_be_bytes());
    let start = response.len();
    response.resize(start + appdata_size, 0);
    rand::thread_rng().fill_bytes(&mut response[start..]);
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(random);
    mac.update(&response);
    response[SH_RANDOM_OFF..SH_RANDOM_OFF + 32].copy_from_slice(&mac.finalize().into_bytes());
    response
}

fn first_appdata_record_len(data: &[u8]) -> Option<usize> {
    let mut position = 0;
    while position + 5 <= data.len() {
        let kind = data[position];
        let length = u16::from_be_bytes([data[position + 3], data[position + 4]]) as usize;
        if kind == TLS_RECORD_APPDATA {
            return Some(length);
        }
        if !matches!(kind, TLS_RECORD_HANDSHAKE | TLS_RECORD_CCS) {
            return Some(0);
        }
        position += 5 + length;
    }
    None
}

pub async fn profile_masking_domain(domain: &str) {
    {
        let mut profile = PROFILE.lock();
        if profile.0 == domain && profile.2 > crate::config::now_monotonic() {
            return;
        }
        *profile = (
            domain.to_string(),
            None,
            crate::config::now_monotonic() + 3600.0,
        );
    }
    let probe = async {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let name = rustls_pki_types::ServerName::try_from(domain.to_string()).ok()?;
        let mut client = rustls::ClientConnection::new(std::sync::Arc::new(config), name).ok()?;
        let mut hello = Vec::new();
        client.write_tls(&mut hello).ok()?;
        let mut stream = TcpStream::connect((domain, 443)).await.ok()?;
        stream.write_all(&hello).await.ok()?;
        let mut flight = Vec::new();
        let mut chunk = [0; 16384];
        while flight.len() <= 65536 {
            let size = stream.read(&mut chunk).await.ok()?;
            if size == 0 {
                return None;
            }
            flight.extend_from_slice(&chunk[..size]);
            if let Some(length) = first_appdata_record_len(&flight) {
                return (length > 0).then_some(length.clamp(64, TLS_APPDATA_MAX));
            }
        }
        None
    };
    if let Ok(Some(length)) = tokio::time::timeout(Duration::from_secs(5), probe).await {
        PROFILE.lock().1 = Some(length);
    }
}

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

struct TlsRecordReader<R> {
    inner: R,
    header: [u8; 5],
    header_read: usize,
    remaining: usize,
    discard: bool,
}
impl<R> TlsRecordReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            header: [0; 5],
            header_read: 0,
            remaining: 0,
            discard: false,
        }
    }
}
impl<R: AsyncRead + Unpin> AsyncRead for TlsRecordReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::{ready, Poll};
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.remaining > 0 {
                let mut scratch = [0; TLS_APPDATA_MAX];
                let limit = this.remaining.min(scratch.len()).min(output.remaining());
                let mut buffer = ReadBuf::new(&mut scratch[..limit]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buffer))?;
                let size = buffer.filled().len();
                if size == 0 {
                    return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
                }
                this.remaining -= size;
                if !this.discard {
                    output.put_slice(buffer.filled());
                    return Poll::Ready(Ok(()));
                }
                continue;
            }
            while this.header_read < 5 {
                let mut buffer = ReadBuf::new(&mut this.header[this.header_read..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buffer))?;
                let size = buffer.filled().len();
                if size == 0 {
                    return if this.header_read == 0 {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()))
                    };
                }
                this.header_read += size;
            }
            if !matches!(this.header[0], TLS_RECORD_APPDATA | TLS_RECORD_CCS)
                || this.header[1..3] != [3, 3]
            {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid FakeTLS record",
                )));
            }
            this.remaining = u16::from_be_bytes([this.header[3], this.header[4]]) as usize;
            this.discard = this.header[0] == TLS_RECORD_CCS;
            this.header_read = 0;
        }
    }
}

struct TlsRecordWriter<W> {
    inner: W,
    pending: Vec<u8>,
    offset: usize,
    plaintext_len: usize,
}
impl<W> TlsRecordWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            offset: 0,
            plaintext_len: 0,
        }
    }
}
impl<W: AsyncWrite + Unpin> TlsRecordWriter<W> {
    fn drain(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        use std::task::{ready, Poll};
        while self.offset < self.pending.len() {
            let size =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.offset..]))?;
            if size == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            self.offset += size;
        }
        self.pending.clear();
        self.offset = 0;
        Poll::Ready(Ok(()))
    }
}
impl<W: AsyncWrite + Unpin> AsyncWrite for TlsRecordWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.pending.is_empty() {
            this.plaintext_len = data.len().min(TLS_APPDATA_MAX);
            this.pending = wrap_tls_record(&data[..this.plaintext_len]);
        }
        std::task::ready!(this.drain(cx))?;
        std::task::Poll::Ready(Ok(this.plaintext_len))
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

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

    match verify_client_hello(&client_hello, secret) {
        Some((client_random, session_id, ts)) => {
            log_debug(&format!("[{}] Fake TLS handshake ok (ts={})", label, ts));
            if !REPLAY_CACHE
                .lock()
                .first_seen(client_random, crate::config::now_monotonic())
            {
                proxy_to_masking_domain(conn, client_hello, masking, label).await;
                return None;
            }
            let info = parse_client_hello(&client_hello).unwrap_or_default();
            let server_hello = build_server_hello(secret, &client_random, &session_id, &info);
            let delay = rand::thread_rng().gen_range(8..=24);
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
        None => {
            log_debug(&format!(
                "[{}] Fake TLS verify failed (size={} rec={}) -> masking",
                label,
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
    STATS.connections_masked.fetch_add(1, Ordering::Relaxed);

    let mut upstream = upstream;
    if upstream.write_all(&initial).await.is_err() {
        return;
    }

    let (mut c_read, mut c_write) = tokio::io::split(conn);
    let (mut u_read, mut u_write) = tokio::io::split(upstream);

    tokio::select! {
        _ = tokio::io::copy(&mut c_read, &mut u_write) => {},
        _ = tokio::io::copy(&mut u_read, &mut c_write) => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fragmented_tls_records_survive_pending_reads_and_partial_writes() {
        let (sender, receiver) = tokio::io::duplex(1);
        let expected: Vec<u8> = (0..40_000).map(|index| index as u8).collect();
        let data = expected.clone();
        let task = tokio::spawn(async move {
            let mut writer = TlsRecordWriter::new(sender);
            writer.write_all(&data).await.unwrap();
            writer.shutdown().await.unwrap();
        });
        let mut reader = TlsRecordReader::new(receiver);
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, expected);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn partial_header_is_preserved_between_polls_and_ccs_is_discarded() {
        let (mut sender, receiver) = tokio::io::duplex(1);
        let task = tokio::spawn(async move {
            sender.write_all(&CCS_FRAME).await.unwrap();
            for byte in wrap_tls_record(b"test") {
                sender.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut reader = TlsRecordReader::new(receiver);
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"test");
        task.await.unwrap();
    }
}

#[cfg(test)]
mod hello_tests {
    use super::*;

    #[test]
    fn server_flight_mirrors_cipher_and_hybrid_group_with_whole_flight_hmac() {
        let info = ClientHelloInfo {
            suites: vec![0x1303],
            key_shares: HashMap::from([(0x11ec, 1216)]),
        };
        let secret = [9; 16];
        let random = [7; 32];
        let session = [3; 32];
        let response = build_server_hello(&secret, &random, &session, &info);
        assert_eq!(&response[76..78], &0x1303u16.to_be_bytes());
        assert_eq!(&response[91..93], &0x11ecu16.to_be_bytes());
        assert_eq!(&response[93..95], &1120u16.to_be_bytes());
        assert_eq!(&response[44..76], &session);
        let mut zeroed = response.clone();
        zeroed[11..43].fill(0);
        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(&random);
        mac.update(&zeroed);
        assert_eq!(&response[11..43], mac.finalize().into_bytes().as_slice());
        assert!(first_appdata_record_len(&response)
            .is_some_and(|length| (64..=16384).contains(&length)));
    }

    #[test]
    fn replay_cache_covers_timestamp_window_and_expires_entries() {
        let mut cache = ReplayCache::default();
        assert!(cache.first_seen([1; 32], 0.0));
        assert!(!cache.first_seen([1; 32], 240.9));
        assert!(cache.first_seen([1; 32], 241.0));
        assert_eq!(cache.order.len(), 1);
        for number in 0..70_000u32 {
            let mut random = [0; 32];
            random[..4].copy_from_slice(&number.to_le_bytes());
            cache.first_seen(random, 242.0);
        }
        assert_eq!(cache.expiry.len(), 65536);
        assert_eq!(cache.order.len(), 65536);
    }
}
