use crate::config::*;
use crate::ws::{is_http_status_error, ws_connect_once, RawWebSocket, WsError};
use crate::{ldebug, lerror, linfo, lwarn};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

use once_cell::sync::Lazy;
static CFPROXY_SEM: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(CFPROXY_GLOBAL_PARALLEL));

// ---------------------------------------------------------------------------
// Domain decoding
// ---------------------------------------------------------------------------

pub fn decode_cf_domain(s: &str) -> String {
    if !s.ends_with(".com") {
        return s.to_string();
    }
    let suffix = ".co.uk";
    let p = &s[..s.len() - 4];
    let mut n = 0i32;
    for c in p.chars() {
        if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
            n += 1;
        }
    }
    let mut result: Vec<u8> = Vec::new();
    for &c in p.as_bytes() {
        if c >= b'a' && c <= b'z' {
            let v = (((c - b'a') as i32 - n % 26 + 26) % 26) as u8 + b'a';
            result.push(v);
        } else if c >= b'A' && c <= b'Z' {
            let v = (((c - b'A') as i32 - n % 26 + 26) % 26) as u8 + b'A';
            result.push(v);
        } else {
            result.push(c);
        }
    }
    let mut out = String::from_utf8_lossy(&result).to_string();
    out.push_str(suffix);
    out
}

pub fn normalize_cf_domain(s: &str) -> String {
    let mut decoded = decode_cf_domain(s.trim()).trim().to_lowercase();
    while decoded.ends_with('.') {
        decoded.pop();
    }
    if !is_valid_domain(&decoded) {
        return String::new();
    }
    decoded
}

pub fn default_cfproxy_domains() -> Vec<String> {
    let mut domains = Vec::with_capacity(CFPROXY_ENC.len());
    for enc in CFPROXY_ENC {
        let d = normalize_cf_domain(enc);
        if !d.is_empty() {
            domains.push(d);
        }
    }
    domains
}

pub fn merge_cfproxy_domains(lists: &[Vec<String>]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut merged = Vec::new();
    for list in lists {
        for raw in list {
            let d = normalize_cf_domain(raw);
            if d.is_empty() || seen.contains(&d) {
                continue;
            }
            // Дополнительно валидируем как в _normalize_domain_pool оригинала.
            if !crate::config::is_valid_domain(&d) {
                continue;
            }
            seen.insert(d.clone());
            merged.push(d);
        }
    }
    merged
}

// ---------------------------------------------------------------------------
// 429 cooldown logic
// ---------------------------------------------------------------------------

pub fn clear_cfproxy_429_cooldowns() {
    CFPROXY_429.write().clear();
}

pub fn clear_cfproxy_429_cooldown(domain: &str) {
    let d = normalize_cf_domain(domain);
    if d.is_empty() {
        return;
    }
    CFPROXY_429.write().remove(&d);
}

pub fn retry_after_delay(err: &WsError) -> Duration {
    let h = match err.handshake() {
        Some(h) => h,
        None => return Duration::ZERO,
    };
    let retry_after = h.headers.get("retry-after").map(|s| s.trim()).unwrap_or("");
    if retry_after.is_empty() {
        return Duration::ZERO;
    }
    if let Ok(seconds) = retry_after.parse::<i64>() {
        if seconds > 0 {
            return Duration::from_secs(seconds as u64);
        }
    }
    // http date parse (best-effort): пропускаем, как маловероятный кейс
    Duration::ZERO
}

pub fn next_cfproxy_429_cooldown_delay(prev: &Cfproxy429State, retry_after: Duration) -> Duration {
    if retry_after > Duration::ZERO {
        if retry_after > CFPROXY_429_MAX_COOLDOWN {
            return CFPROXY_429_MAX_COOLDOWN;
        }
        return retry_after;
    }
    let mut strikes = prev.strikes;
    let expired = match prev.until {
        None => true,
        Some(u) => u.elapsed() > CFPROXY_429_MAX_COOLDOWN,
    };
    if expired {
        strikes = 0;
    }
    let mut delay = CFPROXY_429_COOLDOWN;
    for _ in 0..strikes {
        delay *= 2;
        if delay >= CFPROXY_429_MAX_COOLDOWN {
            return CFPROXY_429_MAX_COOLDOWN;
        }
    }
    if delay > CFPROXY_429_MAX_COOLDOWN {
        return CFPROXY_429_MAX_COOLDOWN;
    }
    delay
}

pub fn mark_cfproxy_429_cooldown(domain: &str, err: &WsError) {
    let d = normalize_cf_domain(domain);
    if d.is_empty() {
        return;
    }
    let retry_after = retry_after_delay(err);
    let mut map = CFPROXY_429.write();
    let prev = map.get(&d).cloned().unwrap_or_default();
    let delay = next_cfproxy_429_cooldown_delay(&prev, retry_after);
    let mut strikes = prev.strikes + 1;
    let expired = match prev.until {
        None => true,
        Some(u) => u.elapsed() > CFPROXY_429_MAX_COOLDOWN,
    };
    if expired {
        strikes = 1;
    }
    map.insert(
        d.clone(),
        Cfproxy429State {
            until: Some(Instant::now() + delay),
            strikes,
        },
    );
    drop(map);
    ldebug!(
        " CF cooldown {}: {:.0}s after 429",
        d,
        delay.as_secs_f64().ceil()
    );
}

pub fn cfproxy_429_cooldown_remaining(domain: &str) -> Duration {
    let d = normalize_cf_domain(domain);
    if d.is_empty() {
        return Duration::ZERO;
    }
    let map = CFPROXY_429.read();
    let state = match map.get(&d) {
        Some(s) => s.clone(),
        None => return Duration::ZERO,
    };
    drop(map);
    let until = match state.until {
        Some(u) => u,
        None => return Duration::ZERO,
    };
    let now = Instant::now();
    if until <= now {
        CFPROXY_429.write().remove(&d);
        return Duration::ZERO;
    }
    until - now
}

pub async fn acquire_cfproxy_attempt_slot() -> Option<tokio::sync::SemaphorePermit<'static>> {
    CFPROXY_SEM.acquire().await.ok()
}

// ---------------------------------------------------------------------------
// Cache files
// ---------------------------------------------------------------------------

fn cfproxy_cache_path() -> Option<PathBuf> {
    let dir = CFPROXY.read().cache_dir.trim().to_string();
    if dir.is_empty() {
        return None;
    }
    Some(PathBuf::from(dir).join(CFPROXY_CACHE_FILE_NAME))
}

// Активный домен больше не сохраняется в отдельный файл. Балансер работает в памяти.

fn load_cfproxy_domains_from_cache() -> Vec<String> {
    let path = match cfproxy_cache_path() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let list: Vec<String> = data.split('\n').map(|s| s.to_string()).collect();
    merge_cfproxy_domains(&[list])
}

fn save_cfproxy_domains_to_cache(domains: &[String]) {
    let path = match cfproxy_cache_path() {
        Some(p) => p,
        None => return,
    };
    if domains.is_empty() {
        return;
    }
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            ldebug!(" CF: кеш создать не удалось: {}", e);
            return;
        }
    }
    let data = domains.join("\n");
    if let Err(e) = std::fs::write(&path, data) {
        ldebug!(" CF: кеш сохранить не удалось: {}", e);
    }
}

fn should_refresh_cfproxy_domains() -> bool {
    let path = match cfproxy_cache_path() {
        Some(p) => p,
        None => return true,
    };
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(_) => return true,
    };
    let modified = match meta.modified() {
        Ok(t) => t,
        Err(_) => return true,
    };
    match modified.elapsed() {
        Ok(elapsed) => elapsed >= CFPROXY_REFRESH_INTERVAL,
        Err(_) => true,
    }
}

pub fn init_cfproxy_domains() {
    let defaults = default_cfproxy_domains();
    let cached = load_cfproxy_domains_from_cache();

    let mut cfg = CFPROXY.write();
    if !cfg.user_domain.is_empty() {
        let ud = cfg.user_domain.clone();
        cfg.domains = vec![ud.clone()];
        crate::balancer::BALANCER
            .write()
            .update_domains_list(&cfg.domains);
        return;
    }

    if !cached.is_empty() {
        let n = cached.len();
        cfg.domains = merge_cfproxy_domains(&[cached, defaults]);
        crate::balancer::BALANCER
            .write()
            .update_domains_list(&cfg.domains);
        drop(cfg);
        linfo!(" CF: кеш доменов загружен ({} шт.)", n);
    } else {
        cfg.domains = defaults;
        crate::balancer::BALANCER
            .write()
            .update_domains_list(&cfg.domains);
    }
}

pub async fn start_cfproxy_refresh(cancel: tokio_util::sync::CancellationToken) {
    if !CFPROXY_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
        || !CFPROXY.read().user_domain.is_empty()
    {
        return;
    }
    let refresh = async {
        if should_refresh_cfproxy_domains() {
            try_refresh_cfproxy_domains().await;
        }
        loop {
            tokio::time::sleep(CFPROXY_REFRESH_INTERVAL).await;
            try_refresh_cfproxy_domains().await;
        }
    };
    tokio::select! { _ = cancel.cancelled() => {}, _ = refresh => {} }
}

static CF_TIMEOUTS: once_cell::sync::Lazy<
    parking_lot::Mutex<std::collections::HashMap<(String, bool), f64>>,
> = once_cell::sync::Lazy::new(Default::default);
static CF_SUCCESSES: parking_lot::Mutex<[u64; 2]> = parking_lot::Mutex::new([0, 0]);

pub fn cf_prefers_tls() -> bool {
    let counts = CF_SUCCESSES.lock();
    counts[1] >= counts[0]
}
pub fn cf_timeout_active(domain: &str, tls: bool) -> bool {
    CF_TIMEOUTS
        .lock()
        .get(&(domain.to_string(), tls))
        .is_some_and(|until| *until > now_monotonic())
}
pub fn record_cf_timeout(domain: &str, tls: bool) {
    let now = now_monotonic();
    let mut timeouts = CF_TIMEOUTS.lock();
    timeouts.retain(|_, until| *until > now);
    timeouts.insert((domain.to_string(), tls), now + 30.0);
}
pub fn record_cf_success(tls: bool) {
    CF_SUCCESSES.lock()[usize::from(tls)] += 1;
}
pub fn reset_cf_timeouts() {
    CF_TIMEOUTS.lock().clear();
    *CF_SUCCESSES.lock() = [0, 0];
}

pub async fn try_refresh_cfproxy_domains() -> bool {
    let has_user = !CFPROXY.read().user_domain.is_empty();
    if has_user {
        return true;
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Cache-buster как в оригинале ("?" + 7 случайных букв), UA tg-ws-proxy.
    let nonce: String = {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..7).map(|_| rng.gen_range(b'a'..=b'z') as char).collect()
    };
    let url = format!("{}?{}", CFPROXY_DOMAINS_URL, nonce);
    let mut resp = match client
        .get(&url)
        .header("User-Agent", "tg-ws-proxy")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            ldebug!(" CF: GitHub недоступен: {}", e);
            return false;
        }
    };
    if resp.status().as_u16() != 200 {
        ldebug!(" CF: GitHub вернул {}", resp.status().as_u16());
        return false;
    }
    let mut payload = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) if payload.len() + chunk.len() <= 64 * 1024 => payload.extend_from_slice(&chunk),
            Ok(None) => break,
            _ => return false,
        }
    }
    let body = String::from_utf8_lossy(&payload);

    let mut fetched_raw = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        fetched_raw.push(line.to_string());
    }

    // Валидация пула как в оригинале: минимум CFPROXY_MIN_VALID_DOMAINS
    // валидных доменов, иначе игнорируем payload и остаёмся на текущем пуле.
    let decoded: Vec<String> = fetched_raw.iter().map(|d| normalize_cf_domain(d)).collect();
    let pool = normalize_domain_pool(&decoded);
    if pool.len() >= CFPROXY_MIN_VALID_DOMAINS {
        let merged = pool.clone();
        {
            let mut cfg = CFPROXY.write();
            if !cfg.user_domain.is_empty() {
                return true;
            }
            cfg.domains = merged.clone();
        }
        crate::balancer::BALANCER
            .write()
            .update_domains_list(&merged);
        save_cfproxy_domains_to_cache(&merged);
        linfo!(" CF: список доменов обновлен ({} шт.)", pool.len());
        return true;
    }

    if !fetched_raw.is_empty() {
        lwarn!(
            " CF: игнорирую список доменов (total={}, valid={}, need>={}); остаюсь на текущем пуле",
            fetched_raw.len(),
            pool.len(),
            CFPROXY_MIN_VALID_DOMAINS
        );
    } else {
        ldebug!(" CF: обновить список доменов не удалось (пустой ответ), остаюсь на кеше/встроенном списке");
    }
    false
}

// ---------------------------------------------------------------------------
// DNS over HTTPS (DoH) resolve
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "data")]
    data: String,
    #[serde(rename = "type")]
    type_: i32,
}
#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

static DOH_CACHE: Lazy<parking_lot::RwLock<std::collections::HashMap<String, (String, Instant)>>> =
    Lazy::new(|| parking_lot::RwLock::new(std::collections::HashMap::new()));

fn pick_preferred_ip(candidates: &[String]) -> String {
    let mut fallback_v6 = String::new();
    for c in candidates {
        let c = c.trim();
        if let Ok(ip) = c.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => return v4.to_string(),
                std::net::IpAddr::V6(v6) => {
                    if fallback_v6.is_empty() {
                        fallback_v6 = v6.to_string();
                    }
                }
            }
        }
    }
    fallback_v6
}

pub async fn resolve_doh(domain: &str) -> Option<String> {
    if let Some((ip, exp)) = DOH_CACHE.read().get(domain).cloned() {
        if Instant::now() < exp {
            return Some(ip);
        }
    }

    let endpoints = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query",
        "https://dns.quad9.net/dns-query",
        "https://dns.adguard-dns.com/dns-query",
    ];

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(1500))
        .build()
        .ok()?;

    let (tx, mut rx) = tokio::sync::mpsc::channel(endpoints.len() + 1);
    let mut tasks = tokio::task::JoinSet::new();

    for u in endpoints {
        let client = client.clone();
        let domain = domain.to_string();
        let tx = tx.clone();
        tasks.spawn(async move {
            let full = format!("{}?name={}&type=A", u, domain);
            if let Ok(resp) = client
                .get(&full)
                .header("Accept", "application/dns-json")
                .send()
                .await
            {
                if resp.status().as_u16() == 200 {
                    if let Ok(r) = resp.json::<DohResponse>().await {
                        for ans in r.answer {
                            if ans.type_ == 1 {
                                let _ = tx.send(Some(ans.data)).await;
                                return;
                            }
                        }
                    }
                }
            }
            let _ = tx.send(None).await;
        });
    }

    // UDP-резолв через системный resolver как дополнительный кандидат
    {
        let domain2 = domain.to_string();
        let tx = tx.clone();
        tasks.spawn(async move {
            let host = format!("{}:443", domain2);
            if let Ok(Ok(addrs)) =
                tokio::time::timeout(Duration::from_millis(1500), tokio::net::lookup_host(host))
                    .await
            {
                let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                let p = pick_preferred_ip(&ips);
                if !p.is_empty() {
                    let _ = tx.send(Some(p)).await;
                    return;
                }
            }
            let _ = tx.send(None).await;
        });
    }

    drop(tx); // Чтобы rx.recv() завершился, когда все таски завершатся

    let deadline = tokio::time::sleep(Duration::from_millis(1500));
    tokio::pin!(deadline);

    let mut final_ip = None;
    loop {
        tokio::select! {
            _ = &mut deadline => {
                break;
            }
            msg = rx.recv() => {
                match msg {
                    Some(Some(ip)) => {
                        final_ip = Some(ip);
                        break;
                    }
                    Some(None) => {} // Таска ничего не нашла
                    None => break,   // Все таски завершились
                }
            }
        }
    }

    // Отменяем все незавершенные фоновые таски (исправление утечки)
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}

    if let Some(ip) = &final_ip {
        let mut cache = DOH_CACHE.write();
        cache.retain(|_, (_, expires)| *expires > Instant::now());
        if cache.len() >= 256 {
            cache.clear();
        }
        cache.insert(
            domain.to_string(),
            (ip.clone(), Instant::now() + Duration::from_secs(300)),
        );
    }

    final_ip
}

// ---------------------------------------------------------------------------
// cfConnectDomain
// ---------------------------------------------------------------------------

fn new_timed_attempt_timeout(base: Duration, phase: Duration) -> Duration {
    let mut eff = base;
    if eff <= Duration::ZERO {
        eff = Duration::from_secs(5);
    }
    if eff > phase {
        eff = phase;
    }
    eff
}

pub async fn cf_connect_domain(
    domain: &str,
    path: &str,
    timeout: f64,
) -> (Option<RawWebSocket>, String, Option<WsError>) {
    let path = if path.is_empty() { "/apiws" } else { path };

    let attempt_timeout = crate::ws::ws_connect_timeout(timeout);
    let mut phase_timeout = attempt_timeout;
    if phase_timeout > CFPROXY_DIAL_PHASE_TIMEOUT {
        phase_timeout = CFPROXY_DIAL_PHASE_TIMEOUT;
    }

    let host_timeout = new_timed_attempt_timeout(phase_timeout, phase_timeout);
    match ws_connect_once(domain, domain, path, host_timeout).await {
        Ok(ws) => return (Some(ws), String::new(), None),
        Err(host_err) => {
            if is_http_status_error(&host_err, 429) {
                return (None, String::new(), Some(host_err));
            }
            let resolved_ip = resolve_doh(domain).await.unwrap_or_default();
            if resolved_ip.is_empty() {
                ldebug!(" CF DNS {} -> no result", domain);
                return (None, String::new(), Some(host_err));
            }
            ldebug!(" CF DNS {} -> {}", domain, resolved_ip);
            let ip_timeout = new_timed_attempt_timeout(phase_timeout, phase_timeout);
            match ws_connect_once(&resolved_ip, domain, path, ip_timeout).await {
                Ok(ws) => (Some(ws), resolved_ip, None),
                Err(e) => (None, resolved_ip, Some(e)),
            }
        }
    }
}

pub fn log_cf_conn_error(msg: &str, err: &WsError) {
    if let WsError::Io(e) = err {
        if e.kind() == std::io::ErrorKind::ConnectionReset {
            return;
        }
    }
    if is_http_status_error(err, 429) {
        lwarn!("{}", msg);
    } else {
        lerror!("{}", msg);
    }
}

// активный домен set/save
pub fn set_active_domain_and_save(_chosen: &str) {
    // Больше не используется для файлов. Балансер обновляется внутри proxy.rs
}
