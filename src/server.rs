//! The ESP mint's HTTP API.
//!
//! Routes:
//!
//! - `POST /exchange`: PSP notes and blinded outputs in, blind signatures out.
//!   `200` with the response, `400` if the request is refused, `502` if the PSP
//!   could not be reached or refused the burn (a retry is safe), `500` for a
//!   fault in the mint (a retry is safe).
//! - `GET /audit`: issued, redeemed and outstanding ESP units.
//! - `GET /health`: `200` while the mint locks are sound, `503` otherwise.
//!
//! There is no authentication and no TLS. A note authorizes its own spend, so a
//! caller can only burn notes they hold. Bind to localhost.
//!
//! The mint and the stored responses are behind two mutexes, taken in that
//! order and held for the whole request, including the call to the PSP. One
//! request runs at a time. That is fine for development and is not a design for
//! load.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use mint_core::MintLogic;
use serde_json::{Value, json};

use crate::exchange::{self, ExchangeError, ExchangeRequest, Psp};
use crate::keys::MasterSecret;
use crate::responses::Responses;

pub struct EspState {
    pub logic: Mutex<MintLogic>,
    pub master: MasterSecret,
    pub psp: Box<dyn Psp + Send + Sync>,
    pub responses: Mutex<Responses>,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Why the process should exit, if it should: a poisoned lock means a thread
/// panicked holding the mint or the stored responses, and every later request
/// would fail.
pub fn fatal(state: &EspState) -> Option<&'static str> {
    if state.logic.is_poisoned() {
        Some("the mint lock is poisoned")
    } else if state.responses.is_poisoned() {
        Some("the responses lock is poisoned")
    } else {
        None
    }
}

/// Run one exchange and map the outcome to a status and a body.
pub fn run_exchange(state: &EspState, request: &ExchangeRequest, now_unix: u64) -> (StatusCode, Value) {
    let (Ok(logic), Ok(mut responses)) = (state.logic.lock(), state.responses.lock()) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "the mint lock is poisoned"}),
        );
    };
    match exchange::exchange(
        &logic,
        &state.master,
        state.psp.as_ref(),
        &mut responses,
        now_unix,
        request,
    ) {
        Ok(response) => match serde_json::to_value(&response) {
            Ok(body) => (StatusCode::OK, body),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": e.to_string()}),
            ),
        },
        Err(ExchangeError::Rejected(r)) => (StatusCode::BAD_REQUEST, json!({"error": r.to_string()})),
        Err(ExchangeError::Psp(e)) => (StatusCode::BAD_GATEWAY, json!({"error": e})),
        Err(ExchangeError::Internal(e)) => {
            (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e}))
        }
    }
}

async fn exchange_handler(
    State(state): State<Arc<EspState>>,
    Json(request): Json<ExchangeRequest>,
) -> (StatusCode, Json<Value>) {
    // The PSP client is blocking, so the work runs on a blocking thread.
    let joined =
        tokio::task::spawn_blocking(move || run_exchange(&state, &request, now_secs())).await;
    match joined {
        Ok((code, body)) => (code, Json(body)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("exchange task failed: {e}")})),
        ),
    }
}

async fn audit_handler(State(state): State<Arc<EspState>>) -> (StatusCode, Json<Value>) {
    let Ok(logic) = state.logic.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "the mint lock is poisoned"})),
        );
    };
    match logic.audit_totals() {
        Ok((issued, redeemed)) => (
            StatusCode::OK,
            Json(json!({
                "issued": issued.units,
                "redeemed": redeemed.units,
                "outstanding": issued.units.saturating_sub(redeemed.units),
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

async fn health_handler(State(state): State<Arc<EspState>>) -> (StatusCode, Json<Value>) {
    match fatal(&state) {
        None => (StatusCode::OK, Json(json!({"status": "ok"}))),
        Some(why) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "broken", "reason": why})),
        ),
    }
}

pub fn router(state: Arc<EspState>) -> Router {
    Router::new()
        .route("/exchange", post(exchange_handler))
        .route("/audit", get(audit_handler))
        .route("/health", get(health_handler))
        .with_state(state)
}
