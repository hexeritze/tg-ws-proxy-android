use crate::cfproxy::*;
use crate::config::*;
use crate::crypto::*;
use crate::faketls;
use crate::ws::*;
use crate::{ldebug, linfo, lwarn};
use byteorder::{ByteOrder, LittleEndian};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Fronting flag — proxy/pool.py::_WsPool.try_fronting_first (начинается true)
// ---------------------------------------------------------------------------

static TRY_FRONTING_FIRST: AtomicBool = AtomicBool::new(false);

pub fn ws_pool_fronting_first() -> bool {
    TRY_FRONTING_FIRST.load(Ordering::Relaxed)
}

pub fn set_ws_pool_fronting_first(v: bool) {
    TRY_FRONTING_FIRST.store(v, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

fn configured_target(map: &HashMap<i32, String>, dc: i32, media: bool) -> Option<String> {
    let target = if media {
        map.get(&-dc).or_else(|| map.get(&dc))
    } else {
        map.get(&dc)
    };
    target.filter(|target| !target.is_empty()).cloned()
}

pub fn resolve_configured_target(dc: i32, is_media: bool) -> Option<String> {
    configured_target(&DC_OPT.read(), dc, is_media)
}

pub fn resolve_fallback_target(dc: i32, _is_media: bool, is_test: bool) -> String {
    if is_test {
        DC_TEST_IPS
            .get(&dc)
            .map(|s| s.to_string())
            .unwrap_or_default()
    } else {
        DC_DEFAULT_IPS
            .get(&dc)
            .map(|s| s.to_string())
            .unwrap_or_default()
    }
}

pub fn ws_domains(dc: i32, is_media: bool) -> Vec<String> {
    let mut effective_dc = dc;
    if let Some(o) = DC_OVERRIDES.get(&dc) {
        effective_dc = *o;
    }
    if is_media {
        vec![
            format!("kws{}-1.web.telegram.org", effective_dc),
            format!("kws{}.web.telegram.org", effective_dc),
        ]
    } else {
        vec![
            format!("kws{}.web.telegram.org", effective_dc),
            format!("kws{}-1.web.telegram.org", effective_dc),
        ]
    }
}

pub fn ws_path_for(is_test: bool) -> &'static str {
    if is_test {
        WS_PATH_TEST
    } else {
        WS_PATH
    }
}

pub fn media_tag(is_media: bool) -> &'static str {
    if is_media {
        " media"
    } else {
        ""
    }
}

pub fn is_media_int(b: bool) -> i32 {
    if b {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// WsPool — порт proxy/pool.py::_WsPool
// refilling-backoff (1s..3600s), rotation протухших, fronting-first.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DcSlot {
    pub dc: i32,
    pub is_media: i32,
    pub is_test: bool,
}

pub struct PoolEntry {
    pub ws: RawWebSocket,
    pub created: f64,
}

struct SlotState {
    queue: parking_lot::Mutex<VecDeque<PoolEntry>>,
    running: AtomicBool,
    changed: tokio::sync::Notify,
    last_used: parking_lot::Mutex<f64>,
}

impl SlotState {
    fn new() -> Self {
        Self {
            queue: parking_lot::Mutex::new(VecDeque::new()),
            running: AtomicBool::new(false),
            changed: tokio::sync::Notify::new(),
            last_used: parking_lot::Mutex::new(now_monotonic()),
        }
    }
}

pub struct WsPool {
    slots: parking_lot::Mutex<HashMap<DcSlot, Arc<SlotState>>>,
    cancel: CancellationToken,
    tasks: tokio_util::task::TaskTracker,
}

impl WsPool {
    pub fn new(cancel: CancellationToken) -> Self {
        Self {
            slots: Default::default(),
            cancel,
            tasks: Default::default(),
        }
    }

    pub async fn get(
        self: &Arc<Self>,
        dc: i32,
        is_media: bool,
        is_test: bool,
        target_ip: String,
        domains: Vec<String>,
    ) -> Option<RawWebSocket> {
        if POOL_SIZE.load(Ordering::Relaxed) <= 0 || self.cancel.is_cancelled() {
            return None;
        }
        let slot = DcSlot {
            dc,
            is_media: is_media_int(is_media),
            is_test,
        };
        let state = self.schedule(slot, target_ip, domains);
        let mut queue = state.queue.lock();
        while let Some(entry) = queue.pop_front() {
            if now_monotonic() - entry.created < WS_POOL_REUSE_MAX_AGE && !entry.ws.is_closed() {
                STATS.pool_hits.fetch_add(1, Ordering::Relaxed);
                state.changed.notify_one();
                return Some(entry.ws);
            }
        }
        STATS.pool_misses.fetch_add(1, Ordering::Relaxed);
        state.changed.notify_one();
        None
    }

    fn schedule(
        self: &Arc<Self>,
        slot: DcSlot,
        ip: String,
        domains: Vec<String>,
    ) -> Arc<SlotState> {
        let state = self
            .slots
            .lock()
            .entry(slot)
            .or_insert_with(|| Arc::new(SlotState::new()))
            .clone();
        *state.last_used.lock() = now_monotonic();
        if !self.cancel.is_cancelled() && !state.running.swap(true, Ordering::AcqRel) {
            let pool = self.clone();
            let state_task = state.clone();
            self.tasks.spawn(async move {
                tokio::select! {
                    biased;
                    _ = pool.cancel.cancelled() => {},
                    _ = pool.maintain(slot, &state_task, ip, domains) => {},
                }
                state_task.queue.lock().clear();
                state_task.running.store(false, Ordering::Release);
            });
        }
        state
    }

    async fn maintain(&self, slot: DcSlot, state: &SlotState, ip: String, domains: Vec<String>) {
        let mut failures = 0u32;
        let mut retry_at = 0.0;
        loop {
            let now = now_monotonic();
            let wanted = POOL_SIZE.load(Ordering::Relaxed).max(0) as usize;
            // Stop speculative connections after two minutes without demand.
            // New client demand starts this manager again.
            if wanted == 0 || now - *state.last_used.lock() >= WS_POOL_REUSE_MAX_AGE {
                return;
            }
            let needed = {
                let mut queue = state.queue.lock();
                queue.retain(|entry| {
                    now - entry.created < WS_POOL_REUSE_MAX_AGE && !entry.ws.is_closed()
                });
                wanted.saturating_sub(queue.len())
            };
            if needed > 0 && now >= retry_at {
                let mut attempts = tokio::task::JoinSet::new();
                for _ in 0..needed {
                    let ip = ip.clone();
                    let domains = domains.clone();
                    attempts.spawn(async move {
                        connect_one_ws_full(
                            &ip,
                            &domains,
                            ws_path_for(slot.is_test),
                            WS_POOL_CONNECT_TIMEOUT,
                        )
                        .await
                    });
                }
                let mut connected = 0;
                while let Some(result) = attempts.join_next().await {
                    if let Ok(Some(ws)) = result {
                        state.queue.lock().push_back(PoolEntry {
                            ws,
                            created: now_monotonic(),
                        });
                        connected += 1;
                    }
                }
                if connected > 0 {
                    failures = 0;
                    retry_at = 0.0;
                } else {
                    failures = failures.saturating_add(1);
                    retry_at =
                        now_monotonic() + (2f64.powi(failures.min(13) as i32 - 1)).min(3600.0);
                }
            }
            let now = now_monotonic();
            let expires = state
                .queue
                .lock()
                .front()
                .map(|e| e.created + WS_POOL_REUSE_MAX_AGE)
                .unwrap_or(now + WS_POOL_REUSE_MAX_AGE);
            let idle_until = *state.last_used.lock() + WS_POOL_REUSE_MAX_AGE;
            let next = if retry_at > now {
                retry_at.min(expires)
            } else {
                expires
            };
            tokio::select! {
                _ = state.changed.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs_f64((next.min(idle_until) - now).max(0.01))) => {},
            }
        }
    }

    pub async fn warmup(self: &Arc<Self>, map: &HashMap<i32, String>) {
        if POOL_SIZE.load(Ordering::Relaxed) <= 0 {
            return;
        }
        let dcs: HashSet<i32> = map.keys().map(|dc| dc.abs()).collect();
        for dc in dcs {
            for media in [false, true] {
                let Some(target) = configured_target(map, dc, media) else {
                    continue;
                };
                let slot = DcSlot {
                    dc,
                    is_media: is_media_int(media),
                    is_test: FORCE_TEST_DC.load(Ordering::Relaxed),
                };
                self.schedule(slot, target.clone(), ws_domains(dc, media));
            }
        }
    }

    pub async fn close_all(&self) {
        self.cancel.cancel();
        self.tasks.close();
        self.tasks.wait().await;
        self.slots.lock().clear();
    }
}

pub struct CfWorkerPool {
    idle: parking_lot::Mutex<HashMap<i32, (RawWebSocket, f64, String)>>,
    refilling: parking_lot::Mutex<HashSet<i32>>,
    retry_after: parking_lot::Mutex<HashMap<i32, (u32, f64)>>,
    exhausted_until: parking_lot::Mutex<HashMap<String, f64>>,
    secure_first: AtomicBool,
    cancel: CancellationToken,
    tasks: tokio_util::task::TaskTracker,
}

impl CfWorkerPool {
    pub fn new(cancel: CancellationToken) -> Self {
        Self {
            idle: Default::default(),
            refilling: Default::default(),
            retry_after: Default::default(),
            exhausted_until: Default::default(),
            secure_first: AtomicBool::new(true),
            cancel,
            tasks: Default::default(),
        }
    }

    pub async fn get(
        self: &Arc<Self>,
        dc: i32,
        dst: String,
        domains: Vec<String>,
    ) -> Option<(RawWebSocket, String)> {
        if POOL_SIZE.load(Ordering::Relaxed) <= 0 {
            return None;
        }
        let entry = self.idle.lock().remove(&dc).filter(|(ws, created, _)| {
            !ws.is_closed() && now_monotonic() - created < CF_WORKER_POOL_MAX_AGE
        });
        self.refill_now(dc, dst, domains).await;
        if let Some((ws, _, domain)) = entry {
            STATS.cf_pool_hits.fetch_add(1, Ordering::Relaxed);
            Some((ws, domain))
        } else {
            STATS.cf_pool_misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    pub async fn refill_now(self: &Arc<Self>, dc: i32, dst: String, domains: Vec<String>) {
        if POOL_SIZE.load(Ordering::Relaxed) <= 0
            || self.cancel.is_cancelled()
            || domains.is_empty()
        {
            return;
        }
        if self
            .retry_after
            .lock()
            .get(&dc)
            .is_some_and(|(_, after)| *after > now_monotonic())
        {
            return;
        }
        if !self.refilling.lock().insert(dc) {
            return;
        }
        let pool = self.clone();
        self.tasks.spawn(async move {
            let result = tokio::select! {
                _ = pool.cancel.cancelled() => None,
                result = pool.connect_one(domains, dst, dc) => result,
            };
            if let Some((ws, domain)) = result {
                pool.retry_after.lock().remove(&dc);
                let created = now_monotonic();
                pool.idle.lock().insert(dc, (ws, created, domain));
                pool.refilling.lock().remove(&dc);
                // A single deadline frees idle worker sockets without polling.
                tokio::select! {
                    _ = pool.cancel.cancelled() => {},
                    _ = tokio::time::sleep(Duration::from_secs_f64(CF_WORKER_POOL_MAX_AGE)) => {},
                }
                let mut idle = pool.idle.lock();
                if idle
                    .get(&dc)
                    .is_some_and(|(_, timestamp, _)| *timestamp == created)
                {
                    idle.remove(&dc);
                }
                return;
            } else if !pool.cancel.is_cancelled() {
                let mut retries = pool.retry_after.lock();
                let failures = retries.get(&dc).map_or(1, |(n, _)| n.saturating_add(1));
                retries.insert(
                    dc,
                    (
                        failures,
                        now_monotonic() + 2f64.powi(failures.min(13) as i32 - 1).min(3600.0),
                    ),
                );
            }
            pool.refilling.lock().remove(&dc);
        });
    }

    pub async fn connect_one(
        &self,
        domains: Vec<String>,
        dst: String,
        dc: i32,
    ) -> Option<(RawWebSocket, String)> {
        let path = format!("/apiws?dst={}&dc={}", dst, dc);
        let first = self.secure_first.load(Ordering::Relaxed);
        let modes = if DISABLE_SECURE.load(Ordering::Relaxed) {
            vec![false]
        } else {
            vec![first, !first]
        };
        for domain in self.available_domains(domains).await {
            for (attempt, secure) in modes.iter().copied().enumerate() {
                match ws_connect_full_opts(&domain, &domain, &path, 8.0, None, Some(secure)).await {
                    Ok(ws) => {
                        self.secure_first.store(secure, Ordering::Relaxed);
                        return Some((ws, domain));
                    }
                    Err(WsError::Timeout) if attempt + 1 < modes.len() => continue,
                    Err(error) => {
                        self.report_failure(&domain, &error).await;
                        break;
                    }
                }
            }
        }
        None
    }

    pub async fn available_domains(&self, domains: Vec<String>) -> Vec<String> {
        let now = now_monotonic();
        let mut exhausted = self.exhausted_until.lock();
        exhausted.retain(|_, until| *until > now);
        let mut available: Vec<_> = domains
            .into_iter()
            .filter(|d| !exhausted.contains_key(d))
            .collect();
        use rand::seq::SliceRandom;
        available.shuffle(&mut rand::thread_rng());
        available
    }

    pub async fn report_failure(&self, domain: &str, error: &WsError) {
        let delay = match error {
            WsError::Handshake(h) if h.status_code == 429 => 86400.0 - now_unix_f64() % 86400.0,
            WsError::Handshake(h) if h.status_code >= 500 => 60.0,
            WsError::Io(_) | WsError::Timeout => 60.0,
            _ => return,
        };
        self.exhausted_until
            .lock()
            .insert(domain.to_string(), now_monotonic() + delay);
    }

    pub async fn warmup(self: &Arc<Self>, map: &HashMap<i32, String>) {
        if FORCE_TEST_DC.load(Ordering::Relaxed) {
            return;
        }
        let domains = CF_WORKER_DOMAINS.read().clone();
        for (&dc, &ip) in DC_DEFAULT_IPS
            .iter()
            .filter(|(dc, _)| !map.contains_key(dc))
        {
            self.refill_now(dc, ip.to_string(), domains.clone()).await;
        }
    }

    pub async fn close_all(&self) {
        self.cancel.cancel();
        self.tasks.close();
        self.tasks.wait().await;
        self.idle.lock().clear();
    }
}

pub struct ProxyPools {
    pub ws: Arc<WsPool>,
    pub cf_worker: Arc<CfWorkerPool>,
    pub h2: crate::cf_h2::CfH2Pool,
    tcp_backoff: parking_lot::Mutex<HashMap<(String, u16), TcpRetry>>,
}

impl ProxyPools {
    pub fn new(cancel: CancellationToken) -> Self {
        Self {
            ws: Arc::new(WsPool::new(cancel.clone())),
            cf_worker: Arc::new(CfWorkerPool::new(cancel.clone())),
            h2: crate::cf_h2::CfH2Pool::new(cancel),
            tcp_backoff: Default::default(),
        }
    }
    pub async fn warmup(&self, map: &HashMap<i32, String>) {
        self.ws.warmup(map).await;
        self.cf_worker.warmup(map).await;
    }
    pub async fn close_all(&self) {
        self.ws.close_all().await;
        self.cf_worker.close_all().await;
        self.h2.close().await;
    }
}

#[derive(Default)]
struct TcpRetry {
    failures: u32,
    after: f64,
    connecting: bool,
}

// ---------------------------------------------------------------------------
// HTTP transport detection
// ---------------------------------------------------------------------------

pub fn is_http_transport(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    &data[..4] == b"POST"
        || &data[..3] == b"GET"
        || &data[..4] == b"HEAD"
        || (data.len() >= 7 && &data[..7] == b"OPTIONS")
}

// ---------------------------------------------------------------------------
// Bridge WS — generic core + TcpStream wrapper.
// Сессионная статистика как в bridge_ws_reencrypt оригинала.
// ---------------------------------------------------------------------------

pub async fn bridge_ws<R, W>(
    conn_read: R,
    conn_write: W,
    ws: RawWebSocket,
    label: String,
    dc: i32,
    is_media: bool,
    mut splitter: Option<MsgSplitter>,
    mut clt_dec: TrackedStream,
    mut clt_enc: TrackedStream,
    mut tg_enc: TrackedStream,
    mut tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let start = now_monotonic();
    let mut conn_read = conn_read;
    let mut conn_write = conn_write;
    let upload = async {
        let mut buf = vec![0u8; WS_BRIDGE_CHUNK_SIZE];
        loop {
            let n = conn_read.read(&mut buf).await?;
            if n == 0 {
                if let Some(splitter) = splitter.as_mut() {
                    ws.send_batch(&splitter.flush()).await?;
                }
                return Ok::<(), WsError>(());
            }
            STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
            let chunk = &mut buf[..n];
            clt_dec.xor(chunk);
            if let Some(splitter) = splitter.as_mut() {
                let plain = chunk.to_vec();
                tg_enc.xor(chunk);
                ws.send_batch(&splitter.split(chunk, &plain)).await?;
            } else {
                tg_enc.xor(chunk);
                ws.send(chunk).await?;
            }
        }
    };
    let download = async {
        loop {
            let mut chunk = ws.recv().await?;
            STATS
                .bytes_down
                .fetch_add(chunk.len() as i64, Ordering::Relaxed);
            tg_dec.xor(&mut chunk);
            clt_enc.xor(&mut chunk);
            conn_write.write_all(&chunk).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), WsError>(())
    };
    // Dropping either future also drops an in-progress write. No detached
    // forwarding tasks or periodic keepalive timer survive a client session.
    tokio::select! {
        _ = cancel_token.cancelled() => {},
        _ = upload => {},
        _ = download => {},
    }
    ws.close().await;
    ldebug!(
        "[{}] DC{}{} WS closed after {:.1}s",
        label,
        dc,
        media_tag(is_media),
        now_monotonic() - start
    );
}

/// Совместимость: bridge по TcpStream (разрезаем внутри).
pub async fn bridge_ws_stream(
    conn: TcpStream,
    ws: RawWebSocket,
    label: String,
    dc: i32,
    is_media: bool,
    splitter: Option<MsgSplitter>,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) {
    let (conn_read, conn_write) = tokio::io::split(conn);
    bridge_ws(
        conn_read,
        conn_write,
        ws,
        label,
        dc,
        is_media,
        splitter,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Bridge TCP — generic core + wrapper.
// ---------------------------------------------------------------------------

pub async fn bridge_tcp<CR, CW>(
    mut c_read: CR,
    mut c_write: CW,
    mut remote: TcpStream,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) where
    CR: AsyncReadExt + Unpin + Send + 'static,
    CW: AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut r_read, mut r_write) = remote.split();
    let mut clt_dec = clt_dec;
    let mut clt_enc = clt_enc;
    let mut tg_enc = tg_enc;
    let mut tg_dec = tg_dec;
    let upload = async {
        let mut buffer = vec![0; WS_BRIDGE_CHUNK_SIZE];
        loop {
            let n = c_read.read(&mut buffer).await?;
            if n == 0 {
                return Ok::<(), std::io::Error>(());
            }
            STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
            clt_dec.xor(&mut buffer[..n]);
            tg_enc.xor(&mut buffer[..n]);
            r_write.write_all(&buffer[..n]).await?;
        }
    };
    let download = async {
        let mut buffer = vec![0; WS_BRIDGE_CHUNK_SIZE];
        loop {
            let n = r_read.read(&mut buffer).await?;
            if n == 0 {
                return Ok::<(), std::io::Error>(());
            }
            STATS.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
            tg_dec.xor(&mut buffer[..n]);
            clt_enc.xor(&mut buffer[..n]);
            c_write.write_all(&buffer[..n]).await?;
        }
    };
    tokio::select! {
        _ = cancel_token.cancelled() => {},
        _ = upload => {},
        _ = download => {},
    }
}

pub async fn bridge_tcp_stream(
    client: TcpStream,
    remote: TcpStream,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) {
    let (c_read, c_write) = tokio::io::split(client);
    bridge_tcp(
        c_read,
        c_write,
        remote,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
    )
    .await;
}

// ---------------------------------------------------------------------------
// TCP fallback — порт bridge._tcp_fallback
// ---------------------------------------------------------------------------

pub async fn tcp_fallback<R, W>(
    pools: &ProxyPools,
    conn_read: R,
    conn_write: W,
    dst: &str,
    port: u16,
    init: &[u8],
    label: String,
    ctx_streams: (TrackedStream, TrackedStream, TrackedStream, TrackedStream),
    cancel_token: CancellationToken,
) -> bool
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let key = (dst.to_string(), port);
    {
        let mut attempts = pools.tcp_backoff.lock();
        let retry = attempts.entry(key.clone()).or_default();
        if retry.connecting || retry.after > now_monotonic() {
            return false;
        }
        retry.connecting = true;
    }
    struct Attempt<'a> {
        pools: &'a ProxyPools,
        key: (String, u16),
    }
    impl Drop for Attempt<'_> {
        fn drop(&mut self) {
            if let Some(retry) = self.pools.tcp_backoff.lock().get_mut(&self.key) {
                retry.connecting = false;
            }
        }
    }
    let attempt = Attempt {
        pools,
        key: key.clone(),
    };
    let connected = tokio::select! {
        _ = cancel_token.cancelled() => return false,
        result = tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = TcpStream::connect((dst, port)).await?;
            stream.set_nodelay(true)?;
            stream.write_all(init).await?;
            Ok::<_, std::io::Error>(stream)
        }) => result,
    };
    let remote = match connected {
        Ok(Ok(stream)) => stream,
        _ => {
            let mut attempts = pools.tcp_backoff.lock();
            let retry = attempts.entry(key.clone()).or_default();
            retry.failures = retry.failures.saturating_add(1);
            let delay = (30.0 * 2f64.powi(retry.failures.min(8) as i32 - 1)).min(3600.0);
            retry.after = now_monotonic() + delay;
            lwarn!(
                "[{}] TCP fallback {}:{} failed, retry in {:.0}s",
                label,
                dst,
                port,
                delay
            );
            return false;
        }
    };
    drop(attempt);
    pools.tcp_backoff.lock().remove(&key);
    STATS
        .connections_tcp_fallback
        .fetch_add(1, Ordering::Relaxed);
    let (clt_dec, clt_enc, tg_enc, tg_dec) = ctx_streams;
    bridge_tcp(
        conn_read,
        conn_write,
        remote,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
    )
    .await;
    true
}

// ---------------------------------------------------------------------------
// Cfproxy fallback — мобильная версия (параллель + 429 cooldown + DoH),
// путь и secure как в оригинале.
// ---------------------------------------------------------------------------

async fn cfproxy_acquire_ws(
    dc: i32,
    _is_media: bool,
    path: &str,
    cancel: &CancellationToken,
) -> Option<(RawWebSocket, String)> {
    let mut domains = crate::balancer::BALANCER.read().get_domains_for_dc(dc);
    let secure = !DISABLE_SECURE.load(Ordering::Relaxed);
    let retry_single = domains.len() == 1 && secure;
    if retry_single {
        domains.push(domains[0].clone());
    }
    let tls_first = cf_prefers_tls();
    let mut timeouts = 0usize;
    for (index, base) in domains.into_iter().enumerate() {
        if cfproxy_429_cooldown_remaining(&base) > Duration::ZERO {
            continue;
        }
        let mut tls = secure && (tls_first != (timeouts % 2 == 1));
        if retry_single && index == 1 && timeouts == 0 {
            tls = !tls_first;
        }
        if cf_timeout_active(&base, tls) {
            continue;
        }
        let host = format!("kws{}.{}", dc, base);
        let timeout = [3.0, 3.0, 5.0, 5.0, 10.0][timeouts];
        let result = tokio::select! {
            _ = cancel.cancelled() => return None,
            result = tokio::time::timeout(Duration::from_secs_f64(timeout),
                ws_connect_full_opts(&host, &host, path, timeout, None, Some(tls))) => result,
        };
        match result {
            Ok(Ok(ws)) => {
                record_cf_success(tls);
                crate::balancer::BALANCER
                    .write()
                    .update_domain_for_dc(dc, &base);
                return Some((ws, base));
            }
            Err(_) | Ok(Err(WsError::Timeout)) => {
                record_cf_timeout(&base, tls);
                timeouts += 1;
                if timeouts == 5 {
                    break;
                }
            }
            Ok(Err(error)) => {
                if is_http_status_error(&error, 429) {
                    mark_cfproxy_429_cooldown(&base, &error);
                }
                if retry_single {
                    break;
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// doFallback — порт bridge.do_fallback: cf_worker -> cf -> tcp.
// CF не "съедает" conn при провале: тот же conn уходит в TCP fallback.
// halves передаются дальше только в успешную ветвь: worker-ws и cf-ws
// добываются БЕЗ halves, затем halves уходят в bridge/tcp.
// ---------------------------------------------------------------------------

pub async fn do_fallback<R, W>(
    pools: &ProxyPools,
    conn_read: R,
    conn_write: W,
    relay_init: &[u8],
    label: String,
    dc: i32,
    is_test: bool,
    is_media: bool,
    proto: u32,
    splitter: Option<MsgSplitter>,
    clt_dec: &TrackedStream,
    clt_enc: &TrackedStream,
    tg_enc: &TrackedStream,
    tg_dec: &TrackedStream,
    cancel_token: CancellationToken,
) -> bool
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let m_tag = if is_media { " media" } else { "" };
    let fallback_dst = resolve_fallback_target(dc, is_media, is_test);
    let use_cf = CFPROXY_ENABLED.load(Ordering::Relaxed) && !is_test;
    let worker_domains = CF_WORKER_DOMAINS.read().clone();
    let ws_path = ws_path_for(is_test);
    let secure_port = 443;
    let use_worker = !worker_domains.is_empty() && !fallback_dst.is_empty();

    // Шаг 1: worker-ws (без halves) — порт _cfproxy_worker_fallback.
    if use_worker {
        let pooled = if is_test {
            None
        } else {
            pools
                .cf_worker
                .get(dc, fallback_dst.clone(), worker_domains.clone())
                .await
        };
        let worker_ws = if let Some((ws, worker_domain)) = pooled {
            linfo!(
                "[{}] DC{}{} -> CF worker pool hit via {} for {}",
                label,
                dc,
                m_tag,
                worker_domain,
                fallback_dst
            );
            Some(ws)
        } else {
            pools
                .cf_worker
                .connect_one(worker_domains, fallback_dst.clone(), dc)
                .await
                .map(|(ws, _)| ws)
        };
        if let Some(ws) = worker_ws {
            STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
            if ws.send(relay_init).await.is_ok() {
                bridge_ws(
                    conn_read,
                    conn_write,
                    ws,
                    label,
                    dc,
                    is_media,
                    None, // оригинал: splitter=None для worker
                    clt_dec.clone_state(),
                    clt_enc.clone_state(),
                    tg_enc.clone_state(),
                    tg_dec.clone_state(),
                    cancel_token,
                )
                .await;
                return true;
            }
            ws.close().await;
            // send failed — падаем сквозь к CF/TCP на тех же halves.
        }
    }

    // Шаг 2: cf-ws (без halves).
    if use_cf {
        if is_media && crate::cf_h2::enabled() && cf_prefers_tls() {
            if let Some(channel) = pools.h2.open(dc).await {
                STATS.connections_h2.fetch_add(1, Ordering::Relaxed);
                STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
                channel
                    .bridge(
                        conn_read,
                        conn_write,
                        proto,
                        clt_dec.clone_state(),
                        clt_enc.clone_state(),
                        cancel_token,
                    )
                    .await;
                return true;
            }
        }
        if let Some((ws, _chosen_domain)) =
            cfproxy_acquire_ws(dc, is_media, ws_path, &cancel_token).await
        {
            STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
            linfo!(" DC{}{} подключен через CF", dc, m_tag);

            if ws.send(relay_init).await.is_ok() {
                bridge_ws(
                    conn_read,
                    conn_write,
                    ws,
                    label,
                    dc,
                    is_media,
                    splitter,
                    clt_dec.clone_state(),
                    clt_enc.clone_state(),
                    tg_enc.clone_state(),
                    tg_dec.clone_state(),
                    cancel_token,
                )
                .await;
                return true;
            }
            ws.close().await;
            // CF умер сразу после хендшейка — пробуем TCP на том же conn.
        }
        // CF не дал ws — halves НЕ тронуты, идём в TCP fallback ниже.
    }

    // Шаг 3: tcp.
    if !fallback_dst.is_empty() {
        linfo!(
            "[{}] DC{}{} -> TCP fallback to {}:{}",
            label,
            dc,
            m_tag,
            fallback_dst,
            secure_port
        );
        return tcp_fallback(
            pools,
            conn_read,
            conn_write,
            &fallback_dst,
            secure_port,
            relay_init,
            label,
            (
                clt_dec.clone_state(),
                clt_enc.clone_state(),
                tg_enc.clone_state(),
                tg_dec.clone_state(),
            ),
            cancel_token,
        )
        .await;
    }

    false
}

// ---------------------------------------------------------------------------
// Client serving — порт tg_ws_proxy._handle_client (dd + ee/FakeTLS).
// ---------------------------------------------------------------------------

async fn read_proxy_protocol_line(conn: &mut TcpStream) -> Option<String> {
    let mut line = Vec::with_capacity(108);
    let mut byte = [0u8; 1];
    let res = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = conn.read(&mut byte).await.map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
            if line.len() > 108 {
                break;
            }
        }
        Ok::<(), ()>(())
    })
    .await;
    match res {
        Ok(Ok(())) => Some(String::from_utf8_lossy(&line).to_string()),
        _ => None,
    }
}

pub async fn handle_client(
    pools: Arc<ProxyPools>,
    mut conn: TcpStream,
    cancel_token: CancellationToken,
) {
    STATS.connections_total.fetch_add(1, Ordering::Relaxed);
    STATS.connections_active.fetch_add(1, Ordering::Relaxed);
    struct ActiveGuard;
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            if STATS.connections_active.load(Ordering::Relaxed) > 0 {
                STATS.connections_active.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
    let _guard = ActiveGuard;

    let peer = conn
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let mut label = peer;

    let _ = conn.set_nodelay(true);

    let current_secret = PROXY_SECRET.read().clone();
    let secret_bytes = hex::decode(&current_secret).unwrap_or_default();

    // PROXY protocol (proxy_config.proxy_protocol в оригинале).
    if PROXY_PROTOCOL.load(Ordering::Relaxed) {
        match read_proxy_protocol_line(&mut conn).await {
            Some(line) => {
                let text = line.trim().to_string();
                if text.starts_with("PROXY ") {
                    let parts: Vec<&str> = text.split_whitespace().collect();
                    if parts.len() >= 6 {
                        label = format!("{}:{}", parts[2], parts[4]);
                    }
                    ldebug!("[{}] PROXY protocol: {}", label, text);
                } else {
                    ldebug!(
                        "[{}] expected PROXY header, got: {:?}",
                        label,
                        text.chars().take(60).collect::<String>()
                    );
                }
            }
            None => {
                ldebug!("[{}] disconnected during PROXY header", label);
                return;
            }
        }
    }

    // FakeTLS (ee-secret): первый байт решает всё — как _read_client_init.
    let masking = FAKE_TLS_DOMAIN.read().clone();
    if !masking.is_empty() {
        let mut first = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut first)).await {
            Ok(Ok(_)) => {}
            _ => {
                ldebug!("[{}] client disconnected before handshake", label);
                return;
            }
        }
        if first[0] == faketls::TLS_RECORD_HANDSHAKE {
            match faketls::server_handshake(conn, first[0], &secret_bytes, &masking, &label).await {
                Some(plain) => {
                    serve_core(
                        &pools,
                        plain.read,
                        plain.write,
                        label,
                        secret_bytes,
                        cancel_token,
                    )
                    .await;
                }
                None => {}
            }
            return;
        } else {
            ldebug!(
                "[{}] non-TLS byte 0x{:02X} -> HTTP redirect",
                label,
                first[0]
            );
            let redirect = format!(
                "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                masking
            );
            let _ = conn.write_all(redirect.as_bytes()).await;
            return;
        }
    }

    let (conn_read, conn_write) = tokio::io::split(conn);
    serve_core(
        &pools,
        conn_read,
        conn_write,
        label,
        secret_bytes,
        cancel_token,
    )
    .await;
}

/// Ядро обслуживания соединения: 64-байтный handshake → маршрут → bridge.
/// Generic над транспортом (TcpStream-halves или FakeTLS-duplex-halves).
async fn serve_core<R, W>(
    pools: &ProxyPools,
    mut conn_read: R,
    mut conn_write: W,
    label: String,
    secret_bytes: Vec<u8>,
    cancel_token: CancellationToken,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    // 64-байтный handshake
    let mut handshake = [0u8; 64];
    match tokio::time::timeout(
        Duration::from_secs(10),
        conn_read.read_exact(&mut handshake),
    )
    .await
    {
        Ok(Ok(_)) => {}
        _ => {
            ldebug!("[{}] client disconnected before handshake", label);
            return;
        }
    }

    if is_http_transport(&handshake) {
        STATS
            .connections_http_reject
            .fetch_add(1, Ordering::Relaxed);
        let _ = conn_write
            .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
            .await;
        let _ = conn_write.shutdown().await;
        return;
    }

    // _try_handshake: key = SHA256(prekey + secret).
    let clt_dec_prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let clt_dec_iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let mut hash_dec = Sha256::new();
    hash_dec.update(clt_dec_prekey);
    hash_dec.update(&secret_bytes);
    let mut clt_decryptor = new_aes_ctr(&hash_dec.finalize(), clt_dec_iv);

    let mut decrypted = handshake;
    clt_decryptor.xor(&mut decrypted);

    let proto_tag = &decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4];
    let proto = LittleEndian::read_u32(proto_tag);
    if !valid_proto(proto) {
        STATS.connections_bad.fetch_add(1, Ordering::Relaxed);
        lwarn!("[{}] bad handshake (wrong secret or proto)", label);
        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::io::copy(&mut conn_read.take(64 * 1024), &mut tokio::io::sink()),
        )
        .await;
        return;
    }

    let dc_raw = LittleEndian::read_u16(&decrypted[DC_IDX_POS..DC_IDX_POS + 2]) as i16;
    let mut dc = dc_raw as i32;
    if dc < 0 {
        dc = -dc;
    }
    let is_media = dc_raw < 0;

    // Test DC: proxy_config.force_test_dc или dc >= 10000.
    let mut is_test_dc = FORCE_TEST_DC.load(Ordering::Relaxed) || dc >= 10000;
    if dc >= 10000 {
        linfo!("[{}] test DC{} -> DC{}", label, dc, dc - 10000);
        dc -= 10000;
    }
    // force_test_dc тянет весь трафик на тестовые IP/путь.
    if FORCE_TEST_DC.load(Ordering::Relaxed) {
        is_test_dc = true;
    }
    let m_tag = if is_media { " media" } else { "" };

    let proto_int = proto; // u32 tag; MsgSplitter маппит через proto_tag_to_type
    let dc_idx = if is_media { -dc } else { dc };

    ldebug!(
        "[{}] handshake ok: DC{}{} proto=0x{:08X}{}",
        label,
        dc,
        m_tag,
        proto_int,
        if is_test_dc { " test" } else { "" }
    );

    // relayInit генерация (1-в-1 c Go + RESERVED из utils.py).
    let mut relay_init = [0u8; 64];
    loop {
        rand::thread_rng().fill_bytes(&mut relay_init);
        if relay_init[0] == RESERVED_FIRST_BYTE {
            continue;
        }
        if is_reserved_start(&relay_init[..4]) {
            continue;
        }
        if relay_init[4] == 0 && relay_init[5] == 0 && relay_init[6] == 0 && relay_init[7] == 0 {
            continue;
        }
        break;
    }

    let mut tg_dec_prekey_and_iv = [0u8; 48];
    for i in 0..48 {
        tg_dec_prekey_and_iv[i] = relay_init[8 + 47 - i];
    }

    let mut tg_encryptor = new_aes_ctr(&relay_init[8..40], &relay_init[40..56]);
    let tg_decryptor = new_aes_ctr(&tg_dec_prekey_and_iv[..32], &tg_dec_prekey_and_iv[32..]);

    let mut dc_bytes = [0u8; 2];
    LittleEndian::write_u16(&mut dc_bytes, dc_idx as u16);

    let mut tail_plain = [0u8; 8];
    tail_plain[0..4].copy_from_slice(proto_tag);
    tail_plain[4..6].copy_from_slice(&dc_bytes);
    rand::thread_rng().fill_bytes(&mut tail_plain[6..8]);

    let mut encrypted_full = relay_init;
    tg_encryptor.xor(&mut encrypted_full);

    let mut keystream_tail = [0u8; 8];
    for i in 0..8 {
        keystream_tail[i] = encrypted_full[56 + i] ^ relay_init[56 + i];
        relay_init[56 + i] = tail_plain[i] ^ keystream_tail[i];
    }

    // clt_encryptor: prekey/iv = reverse(client_dec_prekey_iv), key=SHA256+secret.
    let mut clt_enc_prekey_and_iv = [0u8; 48];
    for i in 0..48 {
        clt_enc_prekey_and_iv[i] = handshake[8 + 47 - i];
    }
    let mut hash_enc = Sha256::new();
    hash_enc.update(&clt_enc_prekey_and_iv[..32]);
    hash_enc.update(&secret_bytes);
    let clt_encryptor = new_aes_ctr(&hash_enc.finalize(), &clt_enc_prekey_and_iv[32..]);

    let target = resolve_configured_target(dc, is_media);
    let ws = if let Some(target) = target {
        pools
            .ws
            .get(dc, is_media, is_test_dc, target, ws_domains(dc, is_media))
            .await
    } else {
        None
    };
    let splitter = Some(MsgSplitter::new(proto_int));
    if let Some(ws) = ws {
        if ws.send(&relay_init).await.is_ok() {
            STATS.connections_ws.fetch_add(1, Ordering::Relaxed);
            bridge_ws(
                conn_read,
                conn_write,
                ws,
                label,
                dc,
                is_media,
                splitter,
                clt_decryptor,
                clt_encryptor,
                tg_encryptor,
                tg_decryptor,
                cancel_token,
            )
            .await;
            return;
        }
        ws.close().await;
    }
    do_fallback(
        pools,
        conn_read,
        conn_write,
        &relay_init,
        label,
        dc,
        is_test_dc,
        is_media,
        proto_int,
        splitter,
        &clt_decryptor,
        &clt_encryptor,
        &tg_encryptor,
        &tg_decryptor,
        cancel_token,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub async fn run_proxy(
    pools: Arc<ProxyPools>,
    host: String,
    port: u16,
    dc_opt_map: HashMap<i32, String>,
    cancel_root: CancellationToken,
    listener: TcpListener,
) -> std::io::Result<()> {
    {
        let mut m = DC_OPT.write();
        *m = dc_opt_map.clone();
    }

    let mut tasks = tokio::task::JoinSet::new();
    let refresh_cancel = cancel_root.clone();
    tasks.spawn(async move {
        start_cfproxy_refresh(refresh_cancel).await;
    });

    {
        let p = pools.clone();
        let map = dc_opt_map.clone();
        tasks.spawn(async move {
            p.warmup(&map).await;
        });
    }

    let masking = FAKE_TLS_DOMAIN.read().clone();
    if !masking.is_empty() {
        tasks.spawn(async move {
            faketls::profile_masking_domain(&masking).await;
        });
    }

    linfo!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    linfo!("  TG WS Proxy запущен");
    linfo!("  Адрес: {}:{}", host, port);
    linfo!("  Target DC IPs:");
    let mut dcs: Vec<i32> = dc_opt_map.keys().copied().collect();
    dcs.sort();
    for dc in dcs {
        if let Some(ip) = dc_opt_map.get(&dc) {
            linfo!("    DC{}: {}", dc, ip);
        }
    }
    if CFPROXY_ENABLED.load(Ordering::Relaxed) {
        linfo!("  CF proxy:      enabled");
    }
    if !CF_WORKER_DOMAINS.read().is_empty() {
        linfo!(
            "  CF worker:     enabled ({})",
            CF_WORKER_DOMAINS.read().join(", ")
        );
    }
    if DISABLE_SECURE.load(Ordering::Relaxed) {
        linfo!("  No secure:     enabled (port 80 for CF proxy/worker)");
    }
    if !FAKE_TLS_DOMAIN.read().is_empty() {
        linfo!("  Fake TLS:      {}", FAKE_TLS_DOMAIN.read().clone());
    }

    if LOG_VERBOSE.load(Ordering::Relaxed) {
        let cancel_stats = cancel_root.clone();
        tasks.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = cancel_stats.cancelled() => return,
                    _ = interval.tick() => {
                        linfo!(" {}", STATS.summary_ru());
                    }
                }
            }
        });
    }

    let connections = Arc::new(tokio::sync::Semaphore::new(64));
    loop {
        tokio::select! {
            _ = cancel_root.cancelled() => {
                break;
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            accept = listener.accept() => {
                match accept {
                    Ok((conn, _)) => {
                        let Ok(permit) = connections.clone().try_acquire_owned() else { continue; };
                        let p = pools.clone();
                        let cancel = cancel_root.child_token();
                        tasks.spawn(async move {
                            let _permit = permit;
                            tokio::select! {
                                _ = cancel.cancelled() => {},
                                _ = handle_client(p, conn, cancel.clone()) => {},
                            }
                        });
                    }
                    Err(error) => {
                        lwarn!("accept failed: {}", error);
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }
            }
        }
    }

    drop(listener);
    cancel_root.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    pools.close_all().await;
    Ok(())
}

pub fn parse_cidr_pool(cidrs_str: &str) -> HashMap<i32, String> {
    let mut result = HashMap::new();
    if cidrs_str.trim().is_empty() {
        return result;
    }
    for pair in cidrs_str.split(',') {
        let parts: Vec<&str> = pair.split(':').collect();
        if parts.len() == 2 {
            let dc_raw = parts[0].trim();
            let ip_raw = parts[1].trim();
            if let Ok(dc) = dc_raw.parse::<i32>() {
                if !ip_raw.is_empty() {
                    if let Ok(ip) = ip_raw.parse::<std::net::IpAddr>() {
                        result.insert(dc, ip.to_string());
                    }
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_media_overrides_are_shared_by_warmup_and_client_routing() {
        let map = HashMap::from([
            (2, "192.0.2.1".to_string()),
            (-2, "192.0.2.2".to_string()),
            (-3, "192.0.2.3".to_string()),
        ]);
        assert_eq!(
            configured_target(&map, 2, false).as_deref(),
            Some("192.0.2.1")
        );
        assert_eq!(
            configured_target(&map, 2, true).as_deref(),
            Some("192.0.2.2")
        );
        assert_eq!(
            configured_target(&map, 3, true).as_deref(),
            Some("192.0.2.3")
        );
        assert!(configured_target(&map, 3, false).is_none());
    }

    #[tokio::test]
    async fn tcp_failure_backs_off_and_does_not_redial_during_cooldown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let cancel = CancellationToken::new();
        let pools = ProxyPools::new(cancel.clone());
        for _ in 0..2 {
            let stream = || new_aes_ctr(&[0; 32], &[0; 16]);
            assert!(
                !tcp_fallback(
                    &pools,
                    tokio::io::empty(),
                    tokio::io::sink(),
                    "127.0.0.1",
                    port,
                    &[0; 64],
                    "test".into(),
                    (stream(), stream(), stream(), stream()),
                    cancel.clone()
                )
                .await
            );
        }
        let attempts = pools.tcp_backoff.lock();
        let attempt = &attempts[&("127.0.0.1".to_string(), port)];
        assert_eq!(attempt.failures, 1);
        assert!(!attempt.connecting);
        assert!((29.0..=30.0).contains(&(attempt.after - now_monotonic())));
    }

    #[tokio::test]
    async fn worker_limits_preserve_domains_for_other_status_codes() {
        let pool = CfWorkerPool::new(CancellationToken::new());
        for code in [403, 404, 429, 500] {
            let domain = format!("worker{}.example", code);
            let error = WsError::Handshake(WsHandshakeError {
                status_code: code,
                status_line: String::new(),
                headers: Default::default(),
                location: String::new(),
            });
            pool.report_failure(&domain, &error).await;
            assert_eq!(
                pool.available_domains(vec![domain]).await.is_empty(),
                code == 429 || code == 500
            );
        }
    }
}
