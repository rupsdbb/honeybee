//! HTTP API and embedded web UI.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use miniscript::bitcoin::Txid;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::{Auth, COOKIE_NAME, SESSION_TTL};
use crate::config::Config;
use crate::store::{Store, WalletRecord};
use crate::sync::{Event, Manager, Tip, WalletRt};
use crate::wallet::{Chain, ScriptType, address_of, parse_input, script_at};

#[derive(Clone)]
pub struct AppState {
    pub mgr: Arc<Manager>,
    pub store: Arc<Store>,
    pub auth: Arc<Auth>,
    pub cfg: Arc<Config>,
}

pub struct ApiError(StatusCode, String);

impl ApiError {
    fn bad_request(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::BAD_REQUEST, msg.into())
    }
    fn not_found() -> Self {
        ApiError(StatusCode::NOT_FOUND, "not found".into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("{e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/api/status", get(status))
        .route("/api/wallets", get(list_wallets).post(create_wallet))
        .route("/api/wallets/preview", post(preview_wallet))
        .route("/api/wallets/{id}", get(wallet_detail).patch(update_wallet).delete(delete_wallet))
        .route("/api/wallets/{id}/rescan", post(rescan_wallet))
        .route("/api/wallets/{id}/tx/{txid}", get(tx_detail))
        .route("/api/wallets/{id}/labels/{txid}", put(set_label))
        .route("/api/wallets/{id}/export.csv", get(export_csv))
        .route("/api/qr", get(qr))
        .route("/api/events", get(events))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .route("/", get(|h| asset(h, "text/html; charset=utf-8", include_str!("../static/index.html"))))
        .route("/app.js", get(|h| asset(h, "text/javascript; charset=utf-8", include_str!("../static/app.js"))))
        .route("/style.css", get(|h| asset(h, "text/css; charset=utf-8", include_str!("../static/style.css"))))
        .route("/favicon.svg", get(|h| asset(h, "image/svg+xml", include_str!("../static/favicon.svg"))))
        .route("/api/session", get(session))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .merge(api)
        .layer(middleware::from_fn(csrf_guard))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Embedded static file, revalidated by content hash so upgrades are picked up.
async fn asset(headers: HeaderMap, content_type: &'static str, body: &'static str) -> Response {
    use miniscript::bitcoin::hashes::{Hash, sha256};
    let etag = format!("\"{}\"", &sha256::Hash::hash(body.as_bytes()).to_string()[..16]);
    if headers.get(header::IF_NONE_MATCH).is_some_and(|v| v.as_bytes() == etag.as_bytes()) {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }
    (
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (header::CACHE_CONTROL, "no-cache".to_string()),
            (header::ETAG, etag),
        ],
        body,
    )
        .into_response()
}

async fn security_headers(req: Request, next: Next) -> Response {
    let is_api = req.uri().path().starts_with("/api/");
    let is_favicon = req.uri().path() == "/favicon.svg";
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    let csp = if is_favicon {
        // The logo's inline <style> switches its colors for dark mode; no scripts.
        "default-src 'none'; style-src 'unsafe-inline'"
    } else {
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; \
         connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    };
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(csp));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    // Keep wallet URLs out of explorer logs when following links.
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    if is_api && !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

/// State-changing requests must carry a custom header, which a cross-site
/// form or image can't add (on top of the SameSite=Strict cookie).
async fn csrf_guard(req: Request, next: Next) -> Response {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe && req.headers().get("x-honeybee").is_none_or(|v| v != "1") {
        return ApiError(StatusCode::FORBIDDEN, "missing X-Honeybee header".into()).into_response();
    }
    next.run(req).await
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE_NAME)
        .map(|(_, v)| v.to_string())
}

fn authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    !state.auth.required() || session_token(headers).is_some_and(|t| state.auth.check_token(&t))
}

async fn require_auth(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if authenticated(&state, req.headers()) {
        next.run(req).await
    } else {
        ApiError(StatusCode::UNAUTHORIZED, "login required".into()).into_response()
    }
}

async fn session(State(state): State<AppState>, headers: HeaderMap) -> Json<Value> {
    Json(json!({
        "auth_required": state.auth.required(),
        "authenticated": authenticated(&state, &headers),
    }))
}

#[derive(Deserialize)]
struct LoginBody {
    password: String,
}

fn cookie(state: &AppState, value: &str, max_age: u64) -> HeaderValue {
    let secure = if state.cfg.secure_cookie { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"
    ))
    .expect("valid cookie")
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginBody>,
) -> ApiResult<Response> {
    if !state.auth.required() {
        return Ok(Json(json!({ "ok": true })).into_response());
    }
    let ip = peer.ip();
    let attempt = state.auth.begin_attempt(ip).map_err(|m| ApiError(StatusCode::TOO_MANY_REQUESTS, m))?;
    let slot = state.auth.verify_slot().await;
    let auth = state.auth.clone();
    let ok = tokio::task::spawn_blocking(move || auth.verify(&body.password)).await.unwrap_or(false);
    drop(slot);
    if ok {
        attempt.succeeded();
    } else {
        drop(attempt);
        tracing::warn!("failed login from {ip}");
        tokio::time::sleep(Duration::from_millis(500)).await;
        return Err(ApiError(StatusCode::UNAUTHORIZED, "Wrong password.".into()));
    }
    let token = state.auth.issue_token();
    let mut res = Json(json!({ "ok": true })).into_response();
    res.headers_mut().insert(header::SET_COOKIE, cookie(&state, &token, SESSION_TTL.as_secs()));
    Ok(res)
}

async fn logout(State(state): State<AppState>) -> Response {
    let mut res = Json(json!({ "ok": true })).into_response();
    res.headers_mut().insert(header::SET_COOKIE, cookie(&state, "", 0));
    res
}

#[derive(Serialize)]
struct StatusView {
    version: &'static str,
    connected: bool,
    endpoint: String,
    server_version: Option<String>,
    network: String,
    tip: Option<Tip>,
    error: Option<String>,
    explorer_url: Option<String>,
    auth_required: bool,
}

async fn status(State(state): State<AppState>) -> Json<StatusView> {
    let conn = state.mgr.client().status().borrow().clone();
    Json(StatusView {
        version: env!("CARGO_PKG_VERSION"),
        connected: conn.connected,
        endpoint: state.mgr.client().endpoint(),
        server_version: conn.server_version,
        network: state.mgr.network.to_string(),
        tip: state.mgr.tip(),
        error: state.mgr.chain_error().or(if conn.connected { None } else { conn.last_error }),
        explorer_url: state.cfg.explorer_url.as_ref().map(|u| u.trim_end_matches('/').to_string()),
        auth_required: state.auth.required(),
    })
}

async fn list_wallets(State(state): State<AppState>) -> Json<Value> {
    let list: Vec<_> = state.mgr.wallets().iter().map(|w| state.mgr.summary(w)).collect();
    Json(json!(list))
}

fn find_wallet(state: &AppState, id: &str) -> ApiResult<Arc<WalletRt>> {
    state.mgr.wallet(id).ok_or_else(ApiError::not_found)
}

#[derive(Deserialize)]
struct WalletInput {
    input: String,
    #[serde(default)]
    script_type: Option<String>,
}

fn parse_script_type(s: Option<&str>) -> ApiResult<Option<ScriptType>> {
    match s.unwrap_or("auto") {
        "" | "auto" => Ok(None),
        other => serde_json::from_value(json!(other))
            .map(Some)
            .map_err(|_| ApiError::bad_request(format!("unknown script type '{other}'"))),
    }
}

async fn preview_wallet(State(state): State<AppState>, Json(body): Json<WalletInput>) -> ApiResult<Json<Value>> {
    let network = state.mgr.network;
    let spec = parse_input(&body.input, parse_script_type(body.script_type.as_deref())?, network)
        .map_err(ApiError::bad_request)?;
    let chains = spec.chains(network).map_err(ApiError::bad_request)?;
    let mut preview = serde_json::Map::new();
    for chain in &chains {
        let addrs: Vec<String> = match chain {
            Chain::Ranged { descriptor, .. } => {
                (0..5).filter_map(|i| script_at(descriptor, i).ok()).filter_map(|s| address_of(&s, network)).collect()
            }
            Chain::Fixed { scripts, .. } => scripts.iter().take(5).filter_map(|s| address_of(s, network)).collect(),
        };
        preview.insert(serde_json::to_value(chain.kind()).unwrap().as_str().unwrap().to_string(), json!(addrs));
    }
    Ok(Json(json!({ "spec": spec, "addresses": preview })))
}

#[derive(Deserialize)]
struct CreateWallet {
    name: String,
    input: String,
    #[serde(default)]
    script_type: Option<String>,
    #[serde(default)]
    gap_limit: Option<u32>,
}

fn validate_name(name: &str) -> ApiResult<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 60 {
        return Err(ApiError::bad_request("Name must be 1 to 60 characters."));
    }
    Ok(name.to_string())
}

fn validate_gap(gap: u32) -> ApiResult<u32> {
    if !(1..=1000).contains(&gap) {
        return Err(ApiError::bad_request("Gap limit must be between 1 and 1000."));
    }
    Ok(gap)
}

async fn create_wallet(State(state): State<AppState>, Json(body): Json<CreateWallet>) -> ApiResult<Json<Value>> {
    let name = validate_name(&body.name)?;
    let gap_limit = validate_gap(body.gap_limit.unwrap_or(state.cfg.gap_limit))?;
    let spec = parse_input(&body.input, parse_script_type(body.script_type.as_deref())?, state.mgr.network)
        .map_err(ApiError::bad_request)?;
    if let Some(existing) = state.mgr.wallets().iter().find(|w| w.record().spec == spec) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!("This wallet is already being watched as \"{}\".", existing.record().name),
        ));
    }
    let record = WalletRecord {
        id: hex::encode(rand::random::<[u8; 6]>()),
        name,
        spec,
        gap_limit,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    };
    let w = state.mgr.add_wallet(record).map_err(ApiError::bad_request)?;
    Ok(Json(json!(state.mgr.summary(&w))))
}

async fn wallet_detail(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let w = find_wallet(&state, &id)?;
    let labels = state.store.labels(&id)?;
    Ok(Json(json!({
        "wallet": state.mgr.summary(&w),
        "snapshot": w.snapshot().as_deref(),
        "labels": labels,
    })))
}

#[derive(Deserialize)]
struct UpdateWallet {
    name: Option<String>,
    gap_limit: Option<u32>,
}

async fn update_wallet(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateWallet>,
) -> ApiResult<Json<Value>> {
    let w = find_wallet(&state, &id)?;
    let record = w.record();
    let name = match body.name {
        Some(n) => validate_name(&n)?,
        None => record.name,
    };
    let gap = validate_gap(body.gap_limit.unwrap_or(record.gap_limit))?;
    state.mgr.update_wallet(&w, name, gap)?;
    Ok(Json(json!(state.mgr.summary(&w))))
}

async fn delete_wallet(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    find_wallet(&state, &id)?;
    state.mgr.remove_wallet(&id)?;
    Ok(Json(json!({ "ok": true })))
}

async fn rescan_wallet(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let w = find_wallet(&state, &id)?;
    state.mgr.rescan(&w).await;
    Ok(Json(json!({ "ok": true })))
}

async fn tx_detail(State(state): State<AppState>, Path((id, txid)): Path<(String, String)>) -> ApiResult<Json<Value>> {
    let w = find_wallet(&state, &id)?;
    let txid: Txid = txid.parse().map_err(|_| ApiError::bad_request("invalid txid"))?;
    let detail = state.mgr.tx_detail(&w, &txid).await.ok_or_else(ApiError::not_found)?;
    let label = state.store.labels(&id)?.remove(&detail.txid);
    Ok(Json(json!({ "tx": detail, "label": label })))
}

#[derive(Deserialize)]
struct LabelBody {
    label: String,
}

async fn set_label(
    State(state): State<AppState>,
    Path((id, txid)): Path<(String, String)>,
    Json(body): Json<LabelBody>,
) -> ApiResult<Json<Value>> {
    find_wallet(&state, &id)?;
    let txid: Txid = txid.parse().map_err(|_| ApiError::bad_request("invalid txid"))?;
    let label = body.label.trim();
    if label.chars().count() > 200 {
        return Err(ApiError::bad_request("Labels are limited to 200 characters."));
    }
    state.store.set_label(&id, &txid.to_string(), label)?;
    // Let other open tabs refresh their labels.
    state.mgr.notify(Event::Wallet { id });
    Ok(Json(json!({ "ok": true })))
}

async fn export_csv(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    let w = find_wallet(&state, &id)?;
    let snapshot = w.snapshot().ok_or_else(|| ApiError(StatusCode::CONFLICT, "Wallet not synced yet.".into()))?;
    let labels = state.store.labels(&id)?;
    let mut out = String::from("date_utc,txid,height,amount_btc,fee_btc,balance_btc,label\n");
    for row in snapshot.txs.iter().rev() {
        let date = row.time.map(format_utc).unwrap_or_default();
        let fee = if row.net < 0 { row.fee.map(|f| btc(f as i64)).unwrap_or_default() } else { String::new() };
        let label = labels.get(&row.txid).map(|l| csv_field(l)).unwrap_or_default();
        out.push_str(&format!(
            "{date},{},{},{},{fee},{},{label}\n",
            row.txid,
            row.height.max(0),
            btc(row.net),
            btc(row.balance_after)
        ));
    }
    let filename: String = w
        .record()
        .name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}-transactions.csv\"")),
        ],
        out,
    )
        .into_response())
}

fn btc(sats: i64) -> String {
    let sign = if sats < 0 { "-" } else { "" };
    let abs = sats.unsigned_abs();
    format!("{sign}{}.{:08}", abs / 100_000_000, abs % 100_000_000)
}

fn csv_field(s: &str) -> String {
    // Quote, and defuse spreadsheet formula injection.
    let s = if s.starts_with(['=', '+', '-', '@']) { format!("'{s}") } else { s.to_string() };
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// Seconds since the epoch -> "YYYY-MM-DD HH:MM:SS" (UTC).
fn format_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[derive(Deserialize)]
struct QrQuery {
    data: String,
}

async fn qr(Query(q): Query<QrQuery>) -> ApiResult<Response> {
    if q.data.is_empty() || q.data.len() > 300 {
        return Err(ApiError::bad_request("QR data must be 1 to 300 bytes."));
    }
    let code = qrcode::QrCode::with_error_correction_level(q.data.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(220, 220)
        .quiet_zone(true)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Ok(([(header::CONTENT_TYPE, "image/svg+xml"), (header::CACHE_CONTROL, "private, max-age=3600")], svg)
        .into_response())
}

async fn events(State(state): State<AppState>) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let stream = BroadcastStream::new(state.mgr.events()).map(|item| {
        let data = match item {
            Ok(event) => serde_json::to_string(&event).unwrap_or_default(),
            // Missed some events: tell the page to reload everything.
            Err(_) => r#"{"type":"resync"}"#.to_string(),
        };
        Ok(SseEvent::default().data(data))
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(20)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_dates() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00");
        assert_eq!(format_utc(1231006505), "2009-01-03 18:15:05");
        assert_eq!(format_utc(1709251199), "2024-02-29 23:59:59");
    }

    #[test]
    fn btc_formatting() {
        assert_eq!(btc(0), "0.00000000");
        assert_eq!(btc(-123_456_789), "-1.23456789");
        assert_eq!(btc(2_100_000_000_000_000), "21000000.00000000");
    }

    #[test]
    fn csv_escaping() {
        assert_eq!(csv_field("a \"b\""), "\"a \"\"b\"\"\"");
        assert_eq!(csv_field("=cmd()"), "\"'=cmd()\"");
    }
}
