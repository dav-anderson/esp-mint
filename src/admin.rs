//! The operator's HTTP routes: the payout report and the settle call.
//!
//! These run on their own listener (`ESP_ADMIN_BIND`, default
//! `127.0.0.1:3101`), never on the public API's port, and the bind address must
//! be a loopback address or the process will not start. If `ESP_ADMIN_TOKEN` is
//! set, every request must carry `Authorization: Bearer <token>`.
//!
//! - `GET /payouts`: the open entries summed per service. JSON by default,
//!   plain text with `?format=text`.
//! - `POST /payouts/pay`: body
//!   `{"service": "<x-only hex>", "payment_ref": "...", "entry_ids": ["..."],
//!   "mixed_memos": false}`. Marks exactly those entries completed. `200` with
//!   what was paid, `400` if the request is refused (nothing changed), `500` if
//!   the queue file could not be written (the entries stay open). Also takes
//!   `?format=text`.
//!
//! Each request opens the queue file afresh and one request runs at a time, so a
//! change made by `esp-mint pay` on the command line is seen at once. Two
//! processes writing at the same moment is still a race: do not run both at the
//! same time.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use secp256k1::XOnlyPublicKey;
use serde::Deserialize;
use serde_json::json;

use crate::payouts;
use crate::queue::{Payment, Queue};
use crate::server::now_secs;

pub struct AdminState {
    pub queue_path: PathBuf,
    /// Held for the whole request.
    pub lock: Mutex<()>,
    /// The bearer token, if one is required.
    pub token: Option<String>,
}

/// Refuse a bind address that is not loopback.
pub fn check_loopback(bind: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|_| format!("ESP_ADMIN_BIND `{bind}` is not an address like 127.0.0.1:3101"))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "ESP_ADMIN_BIND `{bind}` is not a loopback address. The admin routes are for the operator on this machine only"
        ));
    }
    Ok(addr)
}

#[derive(Deserialize)]
struct FormatQuery {
    format: Option<String>,
}

impl FormatQuery {
    fn text(&self) -> Result<bool, Response> {
        match self.format.as_deref() {
            None | Some("json") => Ok(false),
            Some("text") => Ok(true),
            Some(other) => Err(error(
                StatusCode::BAD_REQUEST,
                &format!("format must be json or text, not `{other}`"),
                false,
            )),
        }
    }
}

#[derive(Deserialize)]
struct PayBody {
    service: XOnlyPublicKey,
    payment_ref: String,
    entry_ids: Vec<String>,
    #[serde(default)]
    mixed_memos: bool,
}

fn text_response(code: StatusCode, body: String) -> Response {
    (
        code,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

fn error(code: StatusCode, why: &str, text: bool) -> Response {
    if text {
        text_response(code, format!("error: {why}\n"))
    } else {
        (code, Json(json!({"error": why}))).into_response()
    }
}

fn authorized(state: &AdminState, headers: &HeaderMap) -> bool {
    match &state.token {
        None => true,
        Some(token) => headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|given| given == token),
    }
}

async fn payouts_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(query): Query<FormatQuery>,
) -> Response {
    let text = match query.text() {
        Ok(text) => text,
        Err(response) => return response,
    };
    if !authorized(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or wrong admin token", text);
    }
    let Ok(_guard) = state.lock.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "the admin lock is poisoned", text);
    };
    let groups = match Queue::open(&state.queue_path).and_then(|q| payouts::report(&q)) {
        Ok(groups) => groups,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string(), text),
    };
    if text {
        text_response(StatusCode::OK, payouts::render_report(&groups))
    } else {
        (StatusCode::OK, Json(groups)).into_response()
    }
}

async fn pay_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(query): Query<FormatQuery>,
    Json(body): Json<PayBody>,
) -> Response {
    let text = match query.text() {
        Ok(text) => text,
        Err(response) => return response,
    };
    if !authorized(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or wrong admin token", text);
    }
    let Ok(_guard) = state.lock.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "the admin lock is poisoned", text);
    };
    let result = Queue::open(&state.queue_path).and_then(|mut queue| {
        queue.complete(&Payment {
            service: body.service,
            payment_ref: &body.payment_ref,
            entry_ids: &body.entry_ids,
            allow_mixed_memos: body.mixed_memos,
            now_unix: now_secs(),
        })
    });
    match result {
        Ok(paid) if text => text_response(StatusCode::OK, payouts::render_paid(&paid)),
        Ok(paid) => (StatusCode::OK, Json(paid)).into_response(),
        Err(e) => {
            let code = if e.is_refusal() {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            error(code, &e.to_string(), text)
        }
    }
}

pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/payouts", get(payouts_handler))
        .route("/payouts/pay", post(pay_handler))
        .with_state(state)
}

