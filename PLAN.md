# Цель

Полностью доработать Rust-ядро локального форка для Android (`tg-ws-proxy-android`) так, чтобы в нём были
**все функции из upstream-репозитория** `Flowseal/tg-ws-proxy` (Python, github.com), при этом:

- без утечек памяти (ограниченные пулы, очереди, истории; корректные release-пути capacity при abort/close);
- с экономным расходом батареи (без busy-loops: recovery-цикл 250 мс с `Notify`/sleep, 60-секундный периодический
  sweep, агрессивные idle-таймауты — H2-лейны без каналов закрываются через 600 с, 4 tokio-воркера).

Ключевые функции upstream, которые должны появиться в ядре:

1. **H2 media-транспорт** (`cf_h2.py`, 1001 строка): H2Pool → H2Lane (per-host, preflight HEAD) → H2Channel;
   HTTP/2 POST `https://kws{dc}.{domain}/api`; replay-история (16 пакетов / 64 KiB, ключ body[:8]),
   recovery-таск 250 мс, MAX_CHANNEL_REPLAYS=2, REPLAY_SLOT=30 c; 9 правил `_replay_blocker`;
   send-lock (replay — try_lock, не ждёт); классификация ошибок (Transport → без cooldown;
   прочие → `failed_until += 30 c`); slow-аккаунтинг; фрейминг (abridged 1/4-байт, secure padding-strip,
   XOR через тот же TrackedStream, заголовки тоже расшифровываются).
2. **CF TLS/non-TLS чередование** (`cf_websocket.py`): `cf_prefers_tls()`, таймаут-кулдауны 30 с по
   `(domain, use_tls)`, `CF_CONNECT_TIMEOUTS = [3,3,5,5,10]`, retry_single_domain.
3. **TCP-fallback с экспоненциальным backoff** (`bridge.py`): ключ (dst,port), connecting-set,
   `delay = min(30·2^min(failures-1,7), 3600)`.
4. **Порядок fallback в `do_fallback`**: worker-ws → **H2 (только media DC, `cf_prefers_tls()`)** →
   cf-WS → tcp. H2 включён при `CFPROXY_H2_MEDIA && CFPROXY_ENABLED && !DISABLE_SECURE && !FORCE_TEST_DC`.
5. **FakeTLS** (полный порт `fake_tls.py`) — уже готов в `src/faketls.rs`.

Условие по умолчанию: `DISABLE_SECURE = true` → H2 **выключен** по умолчанию (не менять).

# План (статус)

| # | Шаг | Файл | Статус |
|---|-----|------|--------|
| 1 | Зависимости: `h2 = "0.4"`, `http = "0.2"`, `http-body = "0.4"`, `http-body-util = "0.1"`, `bytes`, `ring`, `rand = "0.8"` + `cargo fetch` | `Cargo.toml` | ✅ готово |
| 2 | H2-флаги (`CFPROXY_H2_MEDIA`), статистика (`connections_h2`, `h2_requests`, `h2_errors`, `h2_tcp_connections`), CF-счётчики TLS/no-TLS, таймаут-кулдауны `CF_TIMEOUT_UNTIL`, `cf_prefers_tls()`, `DC_DEFAULT_IPS` | `src/config.rs` | ✅ готово |
| 3 | Полный FakeTLS: HMAC server_random, replay-кэш (241 s/65536), x25519 hybrid share 1120 B, profiled appdata | `src/faketls.rs` | ✅ готово |
| 4 | `TLS_CONFIG_H2` (webpki-roots + ALPN `h2` + resumption), `tls_h2_connect(dial_addr, domain, timeout)` | `src/ws.rs` | ✅ готово |
| 5 | **Новый модуль H2-транспорт**: `read_packet`/`encode_reply` (фрейминг), `H2Pool`/`H2Lane`/`H2Channel`, `ReqFinishGuard` (abort-safe release), replay-история + recovery, `bridge_h2` (upload/download/recovery + transport-error reply) | `src/h2media.rs` | ⏳ выполняется |
| 6 | TCP-fallback с backoff; H2-ветка в `do_fallback` (media-only, до cf-WS); проброс `proto_tag: Option<&[u8]>` в 4 call-site; `connections_h2`+`connections_cfproxy`; H2 log_flow/log_stats + idle-sweep 600 c в 60-сек периодическом таске | `src/proxy.rs` | ⬜ |
| 7 | `cf_connect_domain` с флагом `secure` (через `ws_connect_once_full`) для TLS/non-TLS чередования в `cfproxy_acquire_ws` | `src/cfproxy.rs`, `src/proxy.rs` | ⬜ |
| 8 | `pub mod h2media;`, глобальный `H2_POOL` (Lazy), закрытие пула в StopProxy (`rt.block_on`), `reset_cf_timeouts()`, probe-таск `probe_appdata_len` | `src/lib.rs` | ⬜ |
| 9 | `cargo build` → фикс ошибок → pass по памяти/батареи → commit → итоговый отчёт на русском | весь проект | ⬜ |

# Критические инварианты (соблюдать при реализации)

- **h2 0.4 API**: `SendRequest` под `std::sync::Mutex<Option<SendRequest<Bytes>>>`; `send_request(req, false)`
  под замком, затем `send_stream.send_data(body, true)` **вне** замка; **без** `send_trailers` (END_STREAM
  уже выставлен). `http`-типы — 0.2 (не смешивать с http 1.0 из reqwest).
- **Жизненный цикл lane**: завершение Connection-таска → `lane.dead = true` → пул удаляет lane
  (`Arc::ptr_eq`) → все каналы фейлятся `H2Fail::Closed`; следующий `open()` создаёт свежий lane c preflight.
- **Атомарность capacity**: `try_reserve(ch, len)` — check+increment в одной блокировке
  `CapState` (channel: 8 req/8 MiB; lane: 64 req/32 MiB; reply_buffer 32 MiB); waiter — fresh
  `Notify::notified()`, `enable()` ДО повторной проверки, `timeout(remaining)` до REQUEST_TIMEOUT=65 s.
- **Abort-safe**: release capacity/очистка pending живут в `ReqFinishGuard` (drop glue), создаваемом внутри
  spawned future; double-release guard — удаление task_id из `pending` атомарно с release.
- **Порядок проверок в `_post`** (verbatim из Python): slow_headers → статус 403/404/429/444 →
  `Transport(-status)` (errors++, без cooldown) → !=200 → non-transport (errors++ + failed_until+30) →
  text/html → non-transport → `response_started()` (receiving + last_progress) → declared-length →
  body-цикл (4 MiB cap, lane reply_buffer 32 MiB) → `%4` → content-encoding identity mismatch →
  negative int32 → `Transport(code)` → success-статистика.
- **Framing**: заголовки расшифровываются XOR через тот же `TrackedStream` (`xor` in-place);
  abridged: 1 байт, `words==0x7f` → ещё 3 байта (ASSIGN, не OR); secure: padding-strip
  (`body[:8]==0` → `20+u32le(body[16..20])`, max 256; иначе `24+((len-24)//16)*16`, max 15).
- **Отправка H2-каналу не шлёт relay_init** (только WS). Направление: client→proxy XOR `clt_dec`,
  proxy→client XOR `clt_enc`.
- **Порядок lock'ов**: channel std-Mutex — внешний, lane CapState — внутренний; два channel-lock'а
  одновременно не держать; `_make_upload_room` — снапшот lane capacity (lock-read-drop) до channel-lock'ов.
- **WsError** не имеет Display — использовать `WsError::compact()`.
- Лог-функции принимают `&str`; `now_monotonic() -> f64`.

# Ссылки

- Upstream raw: `https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/<path>` (README: `docs/README.md`).
- Python-референсы (локально): `/tmp/tgwsp-ref/` — `cf_h2.py` (1001L, прочитана целиком), `bridge.py`,
  `cf_websocket.py`, `fake_tls.py`, `h2_transport.py`, `balancer.py` и др.
- h2-исходники: `~/.cargo/registry/src/.../h2-0.4.20/` (проверено: client.rs, share.rs, error.rs).
- Рабочая директория: `/home/mseverin/data/android-fork/tg-ws-proxy-android`; Rust 1.100.0;
  `~/.cargo` может требовать `danger-full-access` при записи в registry.
