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
//! - `POST /payouts/decline`: body `{"entry_id": "...", "reason": "..."}`.
//!   Declines the payout of an open entry: signs the entry's stored decline
//!   outputs (the accepted notes minus the fee, each under its own service and
//!   day), marks the entry declined with the reason and the signatures, and
//!   answers with how many outputs and how much ESP were reissued. The service
//!   learns of it by sending its redemption request again. This is a stand-in
//!   for development: it is to be replaced by delivery over AIR. Do not pay and
//!   decline the same entry. If a decline stops half way, run it again before
//!   paying. Also takes `?format=text`.
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
use crate::redeem::{self, DeclineError};
use crate::server::{EspState, now_secs};

pub struct AdminState {
    pub queue_path: PathBuf,
    /// Held for the whole request.
    pub lock: Mutex<()>,
    /// The bearer token, if one is required.
    pub token: Option<String>,
    /// The mint, which the decline call needs to sign. Without it the decline
    /// route answers `501`. When it is there, the queue is also changed under the
    /// mint's own queue lock, so a redemption never writes it at the same moment.
    pub esp: Option<Arc<EspState>>,
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
#[serde(deny_unknown_fields)]
struct DeclineBody {
    entry_id: String,
    reason: String,
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
        return error(
            StatusCode::UNAUTHORIZED,
            "missing or wrong admin token",
            text,
        );
    }
    let Ok(_guard) = state.lock.lock() else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the admin lock is poisoned",
            text,
        );
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
        return error(
            StatusCode::UNAUTHORIZED,
            "missing or wrong admin token",
            text,
        );
    }
    let Ok(_guard) = state.lock.lock() else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the admin lock is poisoned",
            text,
        );
    };
    let _queue_guard = match state.esp.as_ref().map(|esp| esp.queue_lock.lock()) {
        None => None,
        Some(Ok(guard)) => Some(guard),
        Some(Err(_)) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the queue lock is poisoned",
                text,
            );
        }
    };
    let max_ref_bytes = state
        .esp
        .as_ref()
        .map(|esp| esp.config.current().queue_max_payment_ref_bytes)
        .unwrap_or(crate::queue::MAX_REF_LEN);
    let result = Queue::open(&state.queue_path).and_then(|queue| {
        let mut queue = queue.with_max_ref_bytes(max_ref_bytes);
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

async fn decline_handler(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(query): Query<FormatQuery>,
    Json(body): Json<DeclineBody>,
) -> Response {
    let text = match query.text() {
        Ok(text) => text,
        Err(response) => return response,
    };
    if !authorized(&state, &headers) {
        return error(
            StatusCode::UNAUTHORIZED,
            "missing or wrong admin token",
            text,
        );
    }
    if state.esp.is_none() {
        return error(
            StatusCode::NOT_IMPLEMENTED,
            "this admin listener has no mint to sign with",
            text,
        );
    }
    // Signing reads and writes the mint's files, so it runs on a blocking thread.
    let joined = tokio::task::spawn_blocking(move || {
        let Ok(_guard) = state.lock.lock() else {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "the admin lock is poisoned".to_string(),
            ));
        };
        let Some(esp) = state.esp.as_ref() else {
            return Err((StatusCode::NOT_IMPLEMENTED, "no mint".to_string()));
        };
        let (Ok(mut logic), Ok(responses), Ok(_queue)) = (
            esp.logic.lock(),
            esp.responses.lock(),
            esp.queue_lock.lock(),
        ) else {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "the mint lock is poisoned".to_string(),
            ));
        };
        // Decline outputs are signed with the current keyset, whichever one the
        // redemption asked for; the signatures name it (see decline_gens).
        let rot = crate::server::rotor_of(esp, &mut logic)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let gens = match &rot {
            Some(r) => r.gens(&logic),
            None => crate::rotation::Gens::only(&logic, &esp.master),
        };
        redeem::decline_gens(
            &gens,
            &responses,
            &state.queue_path,
            &body.entry_id,
            &body.reason,
            esp.config.current().redeem_max_reason_bytes,
            now_secs(),
        )
        .map_err(|e| match e {
            DeclineError::Refused(why) => (StatusCode::BAD_REQUEST, why),
            DeclineError::Internal(why) => (StatusCode::INTERNAL_SERVER_ERROR, why),
        })
    })
    .await;
    match joined {
        Ok(Ok(declined)) if text => text_response(
            StatusCode::OK,
            format!(
                "declined entry {}: {} output(s) reissued, {} ESP units\n",
                declined.entry_id, declined.outputs, declined.reissued_esp
            ),
        ),
        Ok(Ok(declined)) => (StatusCode::OK, Json(declined)).into_response(),
        Ok(Err((code, why))) => error(code, &why, text),
        Err(e) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("decline task failed: {e}"),
            text,
        ),
    }
}

/// The body ceiling, before any handler parses the body. Over it the answer is
/// the same `413` as on the public routes (`error`, `code`, `size_bytes`,
/// `limit_bytes`), always JSON.
async fn limit_body(
    State(limit): State<usize>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let (parts, body) = request.into_parts();
    match crate::server::read_limited(
        &parts.headers,
        body,
        limit,
        "Operator requests are small JSON.",
    )
    .await
    {
        Ok(bytes) => {
            next.run(axum::extract::Request::from_parts(
                parts,
                axum::body::Body::from(bytes),
            ))
            .await
        }
        Err(refusal) => refusal.into_response(),
    }
}

pub fn router(state: Arc<AdminState>) -> Router {
    // The ceiling on a request body here is `admin.max_request_bytes`. It is read
    // once, when the router is built, so changing it needs a restart.
    let limit = state
        .esp
        .as_ref()
        .map(|esp| esp.config.current().admin_max_request_bytes)
        .unwrap_or(1024 * 1024);
    Router::new()
        .route("/payouts", get(payouts_handler))
        .route("/payouts/pay", post(pay_handler))
        .route("/payouts/decline", post(decline_handler))
        .layer(axum::extract::DefaultBodyLimit::max(limit))
        .layer(axum::middleware::from_fn_with_state(limit, limit_body))
        .with_state(state)
}
