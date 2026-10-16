//! The ESP mint's HTTP API.
//!
//! Routes:
//!
//! - `POST /exchange`: PSP notes and blinded outputs in, blind signatures out.
//!   `200` with the response, `400` if the request is refused, `413` if the body
//!   is over `exchange.max_request_bytes`, `502` if the PSP could not be reached
//!   or refused the burn (a retry is safe), `500` for a fault in the mint (a retry
//!   is safe).
//! - `POST /transfer`: ESP notes the service holds in, fresh notes only the
//!   service controls out, with the same service and the same redeemable-after
//!   day. `200` with the response, `400` if the request is refused (nothing was
//!   burned), `413` if the body is over `transfer.max_request_bytes`, `500` for a
//!   fault in the mint (a retry is safe).
//! - `POST /redeem`: a service's redemption. The body is the request in its
//!   canonical binary encoding (`redeem::encode`), not JSON, so that its length
//!   is the size the fee is charged on. `200` with the answer (which notes were
//!   accepted and why not, the fee, what is owed, the refunds, and the queue
//!   entry's status), `400` if the request is refused (nothing was burned; the
//!   body has a `code`, and for output limits the totals to rebuild from), `413`
//!   if the body is over `redeem.max_request_bytes`, `500` for a fault in the
//!   mint (a retry is safe).
//! - `GET /fees`: the fee rates, size formulas and ceilings now in force, for a
//!   wallet that builds a request.
//! - `GET /audit`: issued, redeemed and outstanding ESP units.
//! - `GET /health`: `200` while the mint locks are sound, `503` otherwise.
//!
//! Every route that takes a body checks its size first. A body whose
//! `Content-Length` is over the route's ceiling is refused with `413` without
//! reading any of it, and one that does not say is read only as far as the
//! ceiling. Nothing is parsed, checked, burned or charged for a request that is
//! too large. After that the order is the same on every route, cheapest first:
//! the shape and field limits, the amounts, the signatures, the mint's database,
//! the reservations of other unfinished requests, and only then anything that is
//! written or burned.
//!
//! Each request takes the settings once, at its start (`state.config.current()`),
//! and uses them throughout, so a reload (`SIGHUP`) changes the rates and limits
//! for requests accepted after it and never for one already running.
//!
//! There is no authentication and no TLS. A note authorizes its own spend, so a
//! caller can only burn notes they hold. Bind to localhost.
//!
//! The mint and the stored responses are behind two mutexes, taken in that
//! order and held for the whole request, including the call to the PSP. One
//! request runs at a time. That is fine for development and is not a design for
//! load.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use mint_core::MintLogic;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::config;
use crate::exchange::{self, ExchangeError, ExchangeRequest, Psp, Rejection};
use crate::fee;
use crate::keys::MasterSecret;
use crate::redeem::{self, RedeemError, RedeemRejection};
use crate::responses::Responses;
use crate::transfer::{self, TransferError, TransferRejection, TransferRequest};

pub struct EspState {
    pub logic: Mutex<MintLogic>,
    pub master: MasterSecret,
    pub psp: Box<dyn Psp + Send + Sync>,
    pub responses: Mutex<Responses>,
    /// The redemption queue file (`queue.json`).
    pub queue_path: PathBuf,
    /// Held while the queue file is changed, so that a redemption and the
    /// operator's settle or decline calls never rewrite it at the same time.
    /// Taken after the mint and the stored responses.
    pub queue_lock: Mutex<()>,
    /// The mint's settings: fee rates, ceilings and limits. A request takes
    /// them once at its start; a reload swaps them for the next request.
    pub config: config::Handle,
    /// Key rotation: the previous key set and the rollover answers. `None`
    /// for a mint without rotation (the unit tests). Always locked after the
    /// mint (and after the responses and the queue, when those are taken).
    pub rotor: Option<Mutex<crate::rotation::Rotor>>,
    pub rollovers: Option<Mutex<crate::rotation::Rollovers>>,
}

/// Lock the rotor and rotate as far as the clock says. The caller holds the
/// mint lock.
pub fn rotor_of<'a>(
    state: &'a EspState,
    logic: &mut MintLogic,
) -> Result<Option<std::sync::MutexGuard<'a, crate::rotation::Rotor>>, String> {
    let Some(r) = &state.rotor else {
        return Ok(None);
    };
    let mut g = r
        .lock()
        .map_err(|_| "the rotor lock is poisoned".to_string())?;
    g.refresh(logic)
        .map_err(|e| format!("key rotation failed: {e}"))?;
    Ok(Some(g))
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
    } else if state.queue_lock.is_poisoned() {
        Some("the queue lock is poisoned")
    } else {
        None
    }
}

/// A rejection's extra fields for the wallet: what the fee was worked out from.
fn fee_details(
    body: &mut Value,
    fee: u128,
    size_bytes: u64,
    fee_per_byte: u128,
    paid: u128,
    outputs: u128,
) {
    body["code"] = json!("not_exact");
    body["fee_esp"] = json!(fee.to_string());
    body["size_bytes"] = json!(size_bytes);
    body["fee_per_byte"] = json!(fee_per_byte.to_string());
    body["paid_esp"] = json!(paid.to_string());
    body["outputs_esp"] = json!(outputs.to_string());
    body["required_esp"] = json!(outputs.saturating_add(fee).to_string());
}

/// Run one exchange and map the outcome to a status and a body.
pub fn run_exchange(
    state: &EspState,
    request: &ExchangeRequest,
    now_unix: u64,
) -> (StatusCode, Value) {
    let settings = state.config.current().exchange_settings();
    let (Ok(mut logic), Ok(mut responses)) = (state.logic.lock(), state.responses.lock()) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "the mint lock is poisoned"}),
        );
    };
    let rot = match rotor_of(state, &mut logic) {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    };
    let gens = match &rot {
        Some(r) => r.gens(&logic),
        None => crate::rotation::Gens::only(&logic, &state.master),
    };
    match exchange::exchange_gens(
        &gens,
        state.psp.as_ref(),
        &mut responses,
        now_unix,
        request,
        &settings,
    ) {
        Ok(response) => match serde_json::to_value(&response) {
            Ok(body) => (StatusCode::OK, body),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": e.to_string()}),
            ),
        },
        Err(ExchangeError::Rejected(r)) => {
            let mut body = json!({"error": r.to_string()});
            match &r {
                // The wallet reads these two to mark exactly those notes as spent.
                Rejection::Keyset { code, .. } => body["code"] = json!(code),
                Rejection::MissingKeyset => body["code"] = json!("missing_keyset"),
                Rejection::NoteSpentElsewhere { spent } => {
                    body["code"] = json!("note_spent_elsewhere");
                    body["spent"] = json!(spent);
                }
                // The wallet reads these to rebuild the outputs.
                Rejection::NotExactWithFee {
                    paid,
                    requested,
                    fee,
                    size_bytes,
                    fee_per_byte,
                } => fee_details(
                    &mut body,
                    *fee,
                    *size_bytes,
                    *fee_per_byte,
                    *paid,
                    *requested,
                ),
                _ => {}
            }
            (StatusCode::BAD_REQUEST, body)
        }
        Err(ExchangeError::Psp(e)) => (StatusCode::BAD_GATEWAY, json!({"error": e})),
        Err(ExchangeError::Internal(e)) => (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    }
}

/// Run one transfer and map the outcome to a status and a body.
pub fn run_transfer(state: &EspState, request: &TransferRequest) -> (StatusCode, Value) {
    let settings = state.config.current().transfer_settings();
    let (Ok(mut logic), Ok(mut responses)) = (state.logic.lock(), state.responses.lock()) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "the mint lock is poisoned"}),
        );
    };
    let rot = match rotor_of(state, &mut logic) {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    };
    let gens = match &rot {
        Some(r) => r.gens(&logic),
        None => crate::rotation::Gens::only(&logic, &state.master),
    };
    // Notes pending rollovers hold (locked after the rotor, as everywhere).
    if let Some(r) = &state.rollovers {
        match r.lock() {
            Ok(store) => responses.set_external_holds(store.held_nonces("")),
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": "the rollovers lock is poisoned"}),
                );
            }
        }
    }
    match transfer::transfer_gens(&gens, &mut responses, request, &settings) {
        Ok(response) => match serde_json::to_value(&response) {
            Ok(body) => (StatusCode::OK, body),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": e.to_string()}),
            ),
        },
        Err(TransferError::Rejected(r)) => {
            let mut body = json!({"error": r.to_string()});
            if let Some(code) = r.code() {
                body["code"] = json!(code);
            }
            // The wallet reads these two to stop offering that note.
            if let TransferRejection::AlreadySpent { index } = &r {
                body["code"] = json!("note_spent_elsewhere");
                body["spent"] = json!([index]);
            }
            if let TransferRejection::NotExactWithFee {
                inputs,
                outputs,
                fee,
                size_bytes,
                fee_per_byte,
            } = &r
            {
                fee_details(
                    &mut body,
                    *fee,
                    *size_bytes,
                    *fee_per_byte,
                    *inputs,
                    *outputs,
                );
            }
            (StatusCode::BAD_REQUEST, body)
        }
        Err(TransferError::Internal(e)) => (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    }
}

/// Run one redemption from its encoded body and map the outcome to a status and
/// a body. The size limit is the caller's: this is only reached with a body that
/// is within it.
pub fn run_redeem(state: &EspState, body: &[u8], now_unix: u64) -> (StatusCode, Value) {
    let config = state.config.current();
    let settings = config.redeem_settings();
    let request = match redeem::decode_with(body, settings.max_memo_bytes) {
        Ok(request) => request,
        Err(why) => {
            let r = RedeemRejection::Malformed(why);
            return (
                StatusCode::BAD_REQUEST,
                json!({"error": r.to_string(), "code": r.code()}),
            );
        }
    };
    let (Ok(mut logic), Ok(mut responses), Ok(_queue)) = (
        state.logic.lock(),
        state.responses.lock(),
        state.queue_lock.lock(),
    ) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "the mint lock is poisoned"}),
        );
    };
    let rot = match rotor_of(state, &mut logic) {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    };
    let gens = match &rot {
        Some(r) => r.gens(&logic),
        None => crate::rotation::Gens::only(&logic, &state.master),
    };
    // Notes pending rollovers hold (locked after the rotor, as everywhere).
    if let Some(r) = &state.rollovers {
        match r.lock() {
            Ok(store) => responses.set_external_holds(store.held_nonces("")),
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": "the rollovers lock is poisoned"}),
                );
            }
        }
    }
    match redeem::redeem_gens(
        &gens,
        &mut responses,
        &state.queue_path,
        &request,
        &settings,
        now_unix,
    ) {
        Ok(response) => match serde_json::to_value(&response) {
            Ok(body) => (StatusCode::OK, body),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": e.to_string()}),
            ),
        },
        Err(RedeemError::Rejected(r)) => {
            let mut body = r.details();
            body["error"] = json!(r.to_string());
            body["code"] = json!(r.code());
            (StatusCode::BAD_REQUEST, body)
        }
        Err(RedeemError::Internal(e)) => (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    }
}

type Refusal = (StatusCode, Json<Value>);

/// The body of a `413`.
fn too_large(size: Option<u64>, limit: usize, hint: &str) -> Refusal {
    let said = match size {
        Some(size) => format!("the request is {size} bytes"),
        None => "the request is larger than the ceiling".to_string(),
    };
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({
            "error": format!(
                "{said}, and this route accepts at most {limit} bytes. {hint} Nothing was parsed, burned or charged"
            ),
            "code": "request_too_large",
            "size_bytes": size,
            "limit_bytes": limit as u64,
        })),
    )
}

/// The body of a `400` for a body that is not a request.
fn malformed(why: impl std::fmt::Display) -> Refusal {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": format!("not a valid request: {why}"),
            "code": "malformed_request",
        })),
    )
}

/// Read a request body, but only up to `limit` bytes. This is the first thing
/// every route does, before anything is parsed: a body that says it is too large
/// is refused without reading any of it, and one that does not say is read only
/// as far as the limit.
pub(crate) async fn read_limited(
    headers: &HeaderMap,
    body: Body,
    limit: usize,
    hint: &str,
) -> Result<Bytes, Refusal> {
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > limit as u64) {
        return Err(too_large(declared, limit, hint));
    }
    match axum::body::to_bytes(body, limit).await {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.to_string().contains("length limit") => Err(too_large(None, limit, hint)),
        Err(e) => Err(malformed(format!("the body could not be read: {e}"))),
    }
}

/// Read the body of a JSON route under its ceiling and parse it. Unknown fields
/// are not a problem here: the request types decide that.
async fn read_json<T: DeserializeOwned>(
    headers: &HeaderMap,
    body: Body,
    limit: usize,
    hint: &str,
) -> Result<T, Refusal> {
    let bytes = read_limited(headers, body, limit, hint).await?;
    serde_json::from_slice(&bytes).map_err(malformed)
}

async fn redeem_handler(
    State(state): State<Arc<EspState>>,
    headers: HeaderMap,
    body: Body,
) -> (StatusCode, Json<Value>) {
    // The ceiling comes first. Nothing is parsed, checked or charged for a body
    // over it.
    let limit = state.config.current().redeem_max_request_bytes;
    let bytes = match read_limited(
        &headers,
        body,
        limit,
        "Split the redemption into several requests.",
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(refusal) => return refusal,
    };
    // Decoding and checking read files and can take a while for a big request.
    let joined = tokio::task::spawn_blocking(move || run_redeem(&state, &bytes, now_secs())).await;
    match joined {
        Ok((code, body)) => (code, Json(body)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("redeem task failed: {e}")})),
        ),
    }
}

async fn transfer_handler(
    State(state): State<Arc<EspState>>,
    headers: HeaderMap,
    body: Body,
) -> (StatusCode, Json<Value>) {
    let limit = state.config.current().transfer_max_request_bytes;
    let request: TransferRequest = match read_json(
        &headers,
        body,
        limit,
        "Split the transfer into several requests.",
    )
    .await
    {
        Ok(request) => request,
        Err(refusal) => return refusal,
    };
    // The work reads and writes files, so it runs on a blocking thread.
    let joined = tokio::task::spawn_blocking(move || run_transfer(&state, &request)).await;
    match joined {
        Ok((code, body)) => (code, Json(body)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("transfer task failed: {e}")})),
        ),
    }
}

async fn exchange_handler(
    State(state): State<Arc<EspState>>,
    headers: HeaderMap,
    body: Body,
) -> (StatusCode, Json<Value>) {
    let limit = state.config.current().exchange_max_request_bytes;
    let request: ExchangeRequest = match read_json(
        &headers,
        body,
        limit,
        "Split the exchange into several requests.",
    )
    .await
    {
        Ok(request) => request,
        Err(refusal) => return refusal,
    };
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

/// The fees, size formulas and ceilings in force now, as a wallet needs them to
/// build a request. Rates are decimal strings, like every `u128` on the wire.
pub fn fees_body(config: &config::Config) -> Value {
    json!({
        "exchange": {
            "fee_per_byte": config.exchange_fee_per_byte.to_string(),
            "max_request_bytes": config.exchange_max_request_bytes,
            "max_items": config.exchange_max_items,
            "min_psp": config.exchange_min_psp,
            "maturity_days": config.maturity_days,
            "size": {
                "fixed": fee::EXCHANGE_FIXED_BYTES,
                "per_input": fee::INPUT_BYTES,
                "per_output": fee::OUTPUT_BYTES,
            },
        },
        "transfer": {
            "fee_per_byte": config.transfer_fee_per_byte.to_string(),
            "max_request_bytes": config.transfer_max_request_bytes,
            "max_items": config.transfer_max_items,
            "size": {
                "fixed": fee::TRANSFER_FIXED_BYTES,
                "per_input": fee::INPUT_BYTES,
                "per_output": fee::OUTPUT_BYTES,
            },
        },
        "redeem": {
            "fee_per_byte": config.redeem_fee_per_byte.to_string(),
            "max_request_bytes": config.redeem_max_request_bytes,
            "max_memo_bytes": config.redeem_max_memo_bytes,
            "size": {
                "fixed": redeem::FIXED_BYTES,
                "per_input": redeem::INPUT_BYTES,
                "per_output": redeem::OUTPUT_BYTES,
                "plus": "the memo's length in bytes",
            },
        },
    })
}

async fn fees_handler(State(state): State<Arc<EspState>>) -> Json<Value> {
    Json(fees_body(&state.config.current()))
}

async fn audit_handler(State(state): State<Arc<EspState>>) -> (StatusCode, Json<Value>) {
    let Ok(mut logic) = state.logic.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "the mint lock is poisoned"})),
        );
    };
    let rot = match rotor_of(&state, &mut logic) {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))),
    };
    // Every generation: the current, the previous and the deleted ones.
    let totals = logic.audit_totals().and_then(|(mut i, mut d)| {
        if let Some(r) = &rot {
            if let Some((_, p)) = &r.previous {
                let (pi, pd) = p.audit_totals()?;
                i += pi;
                d += pd;
            }
            let (ri, rd) = r.retired_totals();
            i += mint_types::Amount::from_units(ri);
            d += mint_types::Amount::from_units(rd);
        }
        Ok((i, d))
    });
    match totals {
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
        None => (
            StatusCode::OK,
            Json(json!({"status": "ok", "network": state.config.current().network})),
        ),
        Some(why) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"status": "broken", "reason": why, "network": state.config.current().network}),
            ),
        ),
    }
}

/// `GET /keysets`: the live keyset IDs, `{current, previous}`, on every mint
/// (rotating or not). ESP keys are derived per amount and terms, so they are
/// not listed; a reply's `keys` carry them. A wallet reads `current` to name
/// the keyset its new outputs should be signed by.
async fn keysets_handler(State(state): State<Arc<EspState>>) -> (StatusCode, Json<Value>) {
    let Ok(mut logic) = state.logic.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "the mint lock is poisoned"})),
        );
    };
    match rotor_of(&state, &mut logic) {
        Ok(Some(r)) => {
            let g = r.gens(&logic);
            (
                StatusCode::OK,
                Json(json!({"current": g.current_id, "previous": g.previous_id})),
            )
        }
        Ok(None) => (
            StatusCode::OK,
            Json(json!({
                "current": crate::rotation::keyset_id(&state.master),
                "previous": Value::Null,
            })),
        ),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))),
    }
}

/// `GET /rotation`: public and read-only, the same shape as fsp-mint's.
async fn rotation_handler(State(state): State<Arc<EspState>>) -> (StatusCode, Json<Value>) {
    let Ok(mut logic) = state.logic.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "the mint lock is poisoned"})),
        );
    };
    match rotor_of(&state, &mut logic) {
        Ok(Some(r)) => (
            StatusCode::OK,
            Json(serde_json::to_value(r.window()).unwrap_or_default()),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "this mint does not rotate its keys"})),
        ),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))),
    }
}

/// `POST /rollover`: move ESP of the previous (or current) key set to the
/// current one, same amounts and terms. Stored by request hash.
async fn rollover_handler(
    State(state): State<Arc<EspState>>,
    Json(req): Json<crate::rotation::RolloverRequest>,
) -> (StatusCode, Json<Value>) {
    let (Ok(mut logic), Ok(responses)) = (state.logic.lock(), state.responses.lock()) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "the mint lock is poisoned"})),
        );
    };
    let rot = match rotor_of(&state, &mut logic) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "this mint does not rotate its keys"})),
            );
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))),
    };
    let Some(Ok(mut store)) = state.rollovers.as_ref().map(|r| r.lock()) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "the rollovers lock is poisoned"})),
        );
    };
    // Notes an unfinished transfer or redemption will burn.
    let (mut held, _) = responses.redeem_holds("");
    for (_, p) in responses.pending_transfers() {
        held.extend(p.inputs.iter().cloned());
    }
    let held: std::collections::HashSet<String> = held.into_iter().collect();
    match crate::rotation::rollover(&rot.gens(&logic), &rot, &mut store, &held, &req) {
        Ok(a) => (
            StatusCode::OK,
            Json(serde_json::to_value(a).unwrap_or_default()),
        ),
        Err(crate::rotation::RolloverError::Refused(e)) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": e})))
        }
        Err(crate::rotation::RolloverError::Keyset(code, e)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e, "code": code})),
        ),
        Err(crate::rotation::RolloverError::Spent(i)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("input {i}: the note is already spent"),
                "code": "note_spent_elsewhere",
                "spent": [i],
            })),
        ),
        Err(crate::rotation::RolloverError::Internal(e)) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e})))
        }
    }
}

pub fn router(state: Arc<EspState>) -> Router {
    Router::new()
        .route("/rotation", get(rotation_handler))
        .route("/keysets", get(keysets_handler))
        .route("/rollover", post(rollover_handler))
        .route("/exchange", post(exchange_handler))
        .route("/transfer", post(transfer_handler))
        .route("/redeem", post(redeem_handler))
        .route("/fees", get(fees_handler))
        .route("/audit", get(audit_handler))
        .route("/health", get(health_handler))
        .with_state(state)
}
