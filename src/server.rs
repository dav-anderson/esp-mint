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
//! - `POST /rollover`: ESP notes of the previous key set moved to the current
//!   one. `200` with the response, `400` if the request is refused (nothing was
//!   burned), `413` if the body is over `rollover.max_request_bytes`, `404` if
//!   the mint does not rotate.
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
//! - `GET /audit`: issued, redeemed and outstanding ESP units, and the
//!   outstanding split into `outstanding_matured` (days that have come),
//!   `outstanding_unmatured` (days ahead) and `outstanding_unsplit` (issued
//!   before 0.5.0, day unknown), from the per-day ledger (see `ledger`).
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

use std::collections::HashSet;
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
    /// The exchanges this process is in the middle of (see [`InFlight`]).
    pub in_flight: InFlight,
}

/// The code of the `409` an exchange gets while the same request is already
/// being processed.
pub const IN_PROGRESS: &str = "in_progress";

/// The exchanges being processed right now, by request hash.
///
/// An exchange does not hold the mint's lock while it waits on the PSP (see the
/// phases in `exchange`), so a second copy of the same request can arrive in
/// that wait. The `pending` entry cannot tell it from a retry after a crash, and
/// a retry would carry on from the entry, so two copies would both call the PSP.
/// This set is what tells them apart: it lives in memory, so a restart empties
/// it, which is right, since after a restart nothing is running and the entry
/// on file is a crashed request to be carried on. It is not storage and nothing
/// of it needs to survive.
#[derive(Default)]
pub struct InFlight {
    hashes: Mutex<HashSet<String>>,
}

/// A request's place in [`InFlight`]. Dropping it gives the place up, however
/// the request ended.
pub struct Claim<'a> {
    set: &'a InFlight,
    hash: String,
}

impl InFlight {
    /// Take the place of `hash`, or `None` if something else already has it.
    pub fn claim(&self, hash: &str) -> Option<Claim<'_>> {
        // A set cannot be left half-changed by a panic, so a poisoned lock is
        // still good to use.
        let mut set = self.hashes.lock().unwrap_or_else(|e| e.into_inner());
        if !set.insert(hash.to_string()) {
            return None;
        }
        Some(Claim {
            set: self,
            hash: hash.to_string(),
        })
    }

    /// How many requests are in the middle of being processed.
    pub fn len(&self) -> usize {
        self.hashes.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        let mut set = self.set.hashes.lock().unwrap_or_else(|e| e.into_inner());
        set.remove(&self.hash);
    }
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
    body["code"] = json!(sp_wire::codes::NOT_EXACT);
    body["fee_esp"] = json!(fee.to_string());
    body["size_bytes"] = json!(size_bytes);
    body["fee_per_byte"] = json!(fee_per_byte.to_string());
    body["paid_esp"] = json!(paid.to_string());
    body["outputs_esp"] = json!(outputs.to_string());
    body["required_esp"] = json!(outputs.saturating_add(fee).to_string());
}

/// Run one exchange and map the outcome to a status and a body.
///
/// The mint's lock is held for the steps that touch the mint and let go while
/// the PSP is called (see the phases in `exchange`), so a slow PSP holds up only
/// the request that is waiting on it. The same request arriving again while it
/// is being processed is answered `409` `in_progress` and is not processed a
/// second time; the wallet keeps its request and sends it again.
pub fn run_exchange(
    state: &EspState,
    request: &ExchangeRequest,
    now_unix: u64,
) -> (StatusCode, Value) {
    let settings = state.config.current().exchange_settings();
    let hash = match exchange::request_hash(request) {
        Ok(hash) => hash,
        Err(e) => return exchange_outcome(Err(e)),
    };
    let Some(_claim) = state.in_flight.claim(&hash) else {
        return (
            StatusCode::CONFLICT,
            json!({
                "error": "this exchange is already being processed. Nothing is lost: send the same request again in a moment",
                "code": IN_PROGRESS,
            }),
        );
    };
    exchange_outcome(run_exchange_phases(state, request, now_unix, &settings))
}

/// Take the locks, build the key sets and run `f` on them.
fn with_mint<T>(
    state: &EspState,
    f: impl FnOnce(&crate::rotation::Gens, &mut Responses) -> Result<T, ExchangeError>,
) -> Result<T, ExchangeError> {
    let (Ok(mut logic), Ok(mut responses)) = (state.logic.lock(), state.responses.lock()) else {
        return Err(ExchangeError::Internal(
            "the mint lock is poisoned".to_string(),
        ));
    };
    let rot = rotor_of(state, &mut logic).map_err(ExchangeError::Internal)?;
    let gens = match &rot {
        Some(r) => r.gens(&logic),
        None => crate::rotation::Gens::only(&logic, &state.master),
    };
    f(&gens, &mut responses)
}

fn run_exchange_phases(
    state: &EspState,
    request: &ExchangeRequest,
    now_unix: u64,
    settings: &exchange::ExchangeSettings,
) -> Result<exchange::ExchangeResponse, ExchangeError> {
    // 1. Every check, under the lock. Nothing is written.
    let plan = match with_mint(state, |gens, responses| {
        exchange::prepare_gens(gens, responses, now_unix, request, settings)
    })? {
        exchange::Prepared::Done(response) => return Ok(response),
        exchange::Prepared::Go(plan) => plan,
    };
    // 2. The PSP's look at the notes, with no lock held.
    exchange::precheck(state.psp.as_ref(), &plan)?;
    // 3. Check again, now that the lock was let go, and reserve.
    with_mint(state, |gens, responses| {
        exchange::reserve_gens(gens, responses, request, &plan)
    })?;
    // 4. The burn, with no lock held. The reservation is on file.
    exchange::burn_phase(state.psp.as_ref(), request, &plan)?;
    // 5. Sign and finish, under the lock.
    with_mint(state, |gens, responses| {
        exchange::finish_gens(gens, responses, request, &plan)
    })
}

/// The status and body an exchange's outcome is answered with.
fn exchange_outcome(
    result: Result<exchange::ExchangeResponse, ExchangeError>,
) -> (StatusCode, Value) {
    match result {
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
                Rejection::MissingKeyset => body["code"] = json!(sp_wire::codes::MISSING_KEYSET),
                Rejection::BadDenomination { .. } => {
                    body["code"] = json!(crate::units::BAD_DENOMINATION)
                }
                Rejection::NoteSpentElsewhere { spent } => {
                    body["code"] = json!(sp_wire::codes::NOTE_SPENT_ELSEWHERE);
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
                body["code"] = json!(sp_wire::codes::NOTE_SPENT_ELSEWHERE);
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

/// What a `413` says to do, per route (the same text over HTTP and AIR).
const EXCHANGE_HINT: &str = "Split the exchange into several requests.";
const TRANSFER_HINT: &str = "Split the transfer into several requests.";
const ROLLOVER_HINT: &str = "Split the rollover into several requests.";
const REDEEM_HINT: &str = "Split the redemption into several requests.";

/// The JSON body of a `413` (shared with the AIR listener).
fn too_large_body(size: Option<u64>, limit: usize, hint: &str) -> Value {
    let said = match size {
        Some(size) => format!("the request is {size} bytes"),
        None => "the request is larger than the ceiling".to_string(),
    };
    json!({
        "error": format!(
            "{said}, and this route accepts at most {limit} bytes. {hint} Nothing was parsed, burned or charged"
        ),
        "code": sp_wire::codes::REQUEST_TOO_LARGE,
        "size_bytes": size,
        "limit_bytes": limit as u64,
    })
}

/// The body of a `413`.
fn too_large(size: Option<u64>, limit: usize, hint: &str) -> Refusal {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(too_large_body(size, limit, hint)),
    )
}

/// The JSON body of a `400` for a body that is not a request (shared with the
/// AIR listener).
fn malformed_body(why: impl std::fmt::Display) -> Value {
    json!({
        "error": format!("not a valid request: {why}"),
        "code": sp_wire::codes::MALFORMED_REQUEST,
    })
}

/// The body of a `400` for a body that is not a request.
fn malformed(why: impl std::fmt::Display) -> Refusal {
    (StatusCode::BAD_REQUEST, Json(malformed_body(why)))
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
    let bytes = match read_limited(&headers, body, limit, REDEEM_HINT).await {
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
    let request: TransferRequest = match read_json(&headers, body, limit, TRANSFER_HINT).await {
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
    let request: ExchangeRequest = match read_json(&headers, body, limit, EXCHANGE_HINT).await {
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
        "rollover": {
            "max_request_bytes": config.rollover_max_request_bytes,
            "max_items": config.rollover_max_items,
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
    let (Ok(mut logic), Ok(responses)) = (state.logic.lock(), state.responses.lock()) else {
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
            Json(audit_body(
                issued.units,
                redeemed.units,
                &responses,
                now_secs(),
            )),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

/// The body of `GET /audit`: mint-core's counters, and the split of what is
/// outstanding by whether its day has come at `now_unix`, from the per-day
/// ledger (see `ledger`).
///
/// - `outstanding_matured` / `outstanding_unmatured`: what the ledger knows is
///   outstanding under days that have come / days still ahead.
/// - `outstanding_unsplit`: the rest of `outstanding`, which the ledger can not
///   place: ESP issued before 0.5.0, whose day was not kept. Zero on a mint that
///   has run 0.5.0 from its first note. It also moves by what an unfinished
///   request has burned or signed and the ledger does not count yet (see
///   `requests_unfinished`), and is never below zero.
/// - `requests_unfinished`: exchanges, transfers and redemptions not finished.
/// - `as_of_day`: the day (since the Unix epoch) that "has come" is measured at.
pub fn audit_body(issued: u64, redeemed: u64, responses: &Responses, now_unix: u64) -> Value {
    let outstanding = issued.saturating_sub(redeemed);
    let split = responses.ledger().split(now_unix);
    let known = split.matured.saturating_add(split.unmatured);
    let as_units = |v: u128| u64::try_from(v).unwrap_or(u64::MAX);
    json!({
        "issued": issued,
        "redeemed": redeemed,
        "outstanding": outstanding,
        "outstanding_matured": as_units(split.matured),
        "outstanding_unmatured": as_units(split.unmatured),
        "outstanding_unsplit": as_units(u128::from(outstanding).saturating_sub(known)),
        "requests_unfinished": responses.unfinished(),
        "as_of_day": now_unix / crate::terms::SECONDS_PER_DAY,
    })
}

async fn health_handler(State(state): State<Arc<EspState>>) -> (StatusCode, Json<Value>) {
    match fatal(&state) {
        None => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "network": state.config.current().network,
                "wire_version": sp_wire::WIRE_VERSION,
            })),
        ),
        Some(why) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "broken",
                "reason": why,
                "network": state.config.current().network,
                "wire_version": sp_wire::WIRE_VERSION,
            })),
        ),
    }
}

/// `GET /keysets`: the live keyset IDs, `{current, previous}`, on every mint
/// (rotating or not). ESP keys are derived per amount and terms, so they are
/// not listed; a reply's `keys` carry them. A wallet reads `current` to name
/// the keyset its new outputs should be signed by. As a status and a body, so
/// that the AIR listener answers with the same.
fn keysets_outcome(state: &EspState) -> (StatusCode, Value) {
    let Ok(mut logic) = state.logic.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "the mint lock is poisoned"}),
        );
    };
    match rotor_of(state, &mut logic) {
        Ok(Some(r)) => {
            let g = r.gens(&logic);
            (
                StatusCode::OK,
                json!({"current": g.current_id, "previous": g.previous_id}),
            )
        }
        Ok(None) => (
            StatusCode::OK,
            json!({
                "current": crate::rotation::keyset_id(&state.master),
                "previous": Value::Null,
            }),
        ),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    }
}

async fn keysets_handler(State(state): State<Arc<EspState>>) -> (StatusCode, Json<Value>) {
    let (code, body) = keysets_outcome(&state);
    (code, Json(body))
}

/// `GET /rotation`: public and read-only, the same shape as fsp-mint's. As a
/// status and a body, so that the AIR listener answers with the same.
fn rotation_outcome(state: &EspState) -> (StatusCode, Value) {
    let Ok(mut logic) = state.logic.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "the mint lock is poisoned"}),
        );
    };
    match rotor_of(state, &mut logic) {
        Ok(Some(r)) => (
            StatusCode::OK,
            serde_json::to_value(r.window()).unwrap_or_default(),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            json!({"error": "this mint does not rotate its keys"}),
        ),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    }
}

async fn rotation_handler(State(state): State<Arc<EspState>>) -> (StatusCode, Json<Value>) {
    let (code, body) = rotation_outcome(&state);
    (code, Json(body))
}

/// `POST /rollover`: move ESP of the previous (or current) key set to the
/// current one, same amounts and terms. Stored by request hash: the answer is
/// kept before any note is marked spent, so a resend (over HTTP or AIR) gets the
/// stored answer and a crash in the middle is finished by the next resend. As a
/// status and a body, so that the AIR listener answers with the same.
pub fn rollover_outcome(
    state: &EspState,
    req: &crate::rotation::RolloverRequest,
    max_items: usize,
) -> (StatusCode, Value) {
    let (Ok(mut logic), Ok(responses)) = (state.logic.lock(), state.responses.lock()) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "the mint lock is poisoned"}),
        );
    };
    let rot = match rotor_of(state, &mut logic) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                json!({"error": "this mint does not rotate its keys"}),
            );
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    };
    let Some(Ok(mut store)) = state.rollovers.as_ref().map(|r| r.lock()) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "the rollovers lock is poisoned"}),
        );
    };
    // Notes an unfinished transfer or redemption will burn.
    let (mut held, _) = responses.redeem_holds("");
    for (_, p) in responses.pending_transfers() {
        held.extend(p.inputs.iter().cloned());
    }
    let held: std::collections::HashSet<String> = held.into_iter().collect();
    match crate::rotation::rollover(&rot.gens(&logic), &rot, &mut store, &held, req, max_items) {
        Ok(a) => (StatusCode::OK, serde_json::to_value(a).unwrap_or_default()),
        Err(crate::rotation::RolloverError::Refused(e)) => {
            (StatusCode::BAD_REQUEST, json!({"error": e}))
        }
        Err(crate::rotation::RolloverError::Keyset(code, e)) => {
            (StatusCode::BAD_REQUEST, json!({"error": e, "code": code}))
        }
        Err(crate::rotation::RolloverError::Spent(i)) => (
            StatusCode::BAD_REQUEST,
            json!({
                "error": format!("input {i}: the note is already spent"),
                "code": sp_wire::codes::NOTE_SPENT_ELSEWHERE,
                "spent": [i],
            }),
        ),
        Err(crate::rotation::RolloverError::Internal(e)) => {
            (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e}))
        }
    }
}

async fn rollover_handler(
    State(state): State<Arc<EspState>>,
    headers: HeaderMap,
    body: Body,
) -> (StatusCode, Json<Value>) {
    let config = state.config.current();
    let req: crate::rotation::RolloverRequest = match read_json(
        &headers,
        body,
        config.rollover_max_request_bytes,
        ROLLOVER_HINT,
    )
    .await
    {
        Ok(request) => request,
        Err(refusal) => return refusal,
    };
    let (code, body) = rollover_outcome(&state, &req, config.rollover_max_items);
    (code, Json(body))
}

// ---- over AIR ---------------------------------------------------------------

/// The signed refusal of a 4xx. A `400` is the route's body as it is. Any other
/// 4xx (the `404` of a mint that does not rotate, the `409` `in_progress` of an
/// exchange already being processed, the `413` of a body over its ceiling) has
/// `http_status` added to the body, so that the wallet can treat it as it treats
/// that status over HTTP: only a `400` means "refused, nothing was burned", and
/// the others are an error where the outcome may be unknown and the same request
/// is sent again.
fn refused(status: StatusCode, mut body: Value) -> sp_wire::air_request::Served {
    if status != StatusCode::BAD_REQUEST {
        if let Some(object) = body.as_object_mut() {
            object.insert("http_status".into(), json!(status.as_u16()));
        }
    }
    sp_wire::air_request::Served::Refused(serde_json::to_vec(&body).expect("a JSON value encodes"))
}

/// What a route's outcome is over AIR: a success is the body, byte for byte
/// (`serde_json`, the same as axum's `Json`); a 4xx is a signed refusal
/// ([`refused`]); a 5xx, or a body that cannot be encoded, is "cannot answer
/// now": nothing of the mint's state is told to the wallet, and a retry is safe,
/// because what changes state is idempotent by request hash.
fn served_of(what: &str, (status, body): (StatusCode, Value)) -> sp_wire::air_request::Served {
    use sp_wire::air_request::Served;
    if status.is_success() {
        return match serde_json::to_vec(&body) {
            Ok(bytes) => Served::Body(bytes),
            Err(e) => {
                eprintln!("AIR: {what} could not be encoded: {e}");
                Served::Unavailable
            }
        };
    }
    if status.is_client_error() {
        return refused(status, body);
    }
    eprintln!("AIR: {what} cannot be answered now ({status}): {body}");
    Served::Unavailable
}

/// A call with a JSON body, over AIR: the same ceiling, the same parse and the
/// same refusals as the HTTP route of the same name, and the same answer. A body
/// over `limit` bytes is refused (the `413` JSON, before it is parsed), and one
/// that does not parse as `Q` is `malformed_request`.
fn post_served<Q: DeserializeOwned>(
    what: &str,
    limit: usize,
    hint: &str,
    body: &[u8],
    call: impl FnOnce(Q) -> (StatusCode, Value),
) -> sp_wire::air_request::Served {
    if body.len() > limit {
        return refused(
            StatusCode::PAYLOAD_TOO_LARGE,
            too_large_body(Some(body.len() as u64), limit, hint),
        );
    }
    match serde_json::from_slice::<Q>(body) {
        Ok(request) => served_of(what, call(request)),
        Err(e) => refused(StatusCode::BAD_REQUEST, malformed_body(e)),
    }
}

/// What `GET /health` reports, as the body of a mint-info reply over AIR:
/// `ok` while the mint locks are sound and `broken` otherwise (`/health` is
/// `503` then, with the reason), and the wire version and network.
pub fn mint_info(state: &EspState) -> sp_wire::air_request::MintInfo {
    sp_wire::air_request::MintInfo {
        status: if fatal(state).is_none() {
            "ok"
        } else {
            "broken"
        }
        .to_string(),
        wire_version: sp_wire::WIRE_VERSION,
        network: state.config.current().network.clone(),
    }
}

/// What the AIR listener says to one kind of request: the JSON body the HTTP
/// route of the same name returns, built by the same code, or a signed "cannot
/// answer now" where the route would answer 5xx, or a signed refusal where it
/// would answer 4xx. `None` for a kind this mint does not serve (keys: the ESP
/// has no `GET /keys`; and anything unknown), which the listener skips.
///
/// `body` is the request body (empty for the reads). The ceilings are the same
/// ones the HTTP routes have, read once at the start of the request, so the same
/// request is refused in both. Exchange, transfer, redeem and rollover are
/// idempotent by request hash in the mint, so a resend gets the stored answer.
pub fn air_served(state: &EspState, kind: u8, body: &[u8]) -> Option<sp_wire::air_request::Served> {
    use sp_wire::air_request::{
        KIND_EXCHANGE, KIND_FEES, KIND_KEYSETS, KIND_MINT_INFO, KIND_REDEEM, KIND_ROLLOVER,
        KIND_ROTATION, KIND_TRANSFER, Served,
    };
    let config = state.config.current();
    Some(match kind {
        KIND_MINT_INFO => match serde_json::to_vec(&mint_info(state)) {
            Ok(bytes) => Served::Body(bytes),
            Err(_) => Served::Unavailable,
        },
        KIND_KEYSETS => served_of("keysets", keysets_outcome(state)),
        KIND_ROTATION => served_of("rotation", rotation_outcome(state)),
        KIND_FEES => served_of("fees", (StatusCode::OK, fees_body(&config))),
        KIND_ROLLOVER => post_served(
            "rollover",
            config.rollover_max_request_bytes,
            ROLLOVER_HINT,
            body,
            |req: crate::rotation::RolloverRequest| {
                rollover_outcome(state, &req, config.rollover_max_items)
            },
        ),
        KIND_EXCHANGE => post_served(
            "exchange",
            config.exchange_max_request_bytes,
            EXCHANGE_HINT,
            body,
            |req: ExchangeRequest| run_exchange(state, &req, now_secs()),
        ),
        KIND_TRANSFER => post_served(
            "transfer",
            config.transfer_max_request_bytes,
            TRANSFER_HINT,
            body,
            |req: TransferRequest| run_transfer(state, &req),
        ),
        KIND_REDEEM => {
            // The body is the canonical binary encoding, not JSON.
            let limit = config.redeem_max_request_bytes;
            if body.len() > limit {
                refused(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    too_large_body(Some(body.len() as u64), limit, REDEEM_HINT),
                )
            } else {
                served_of("redeem", run_redeem(state, body, now_secs()))
            }
        }
        _ => return None,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Movements;
    use crate::responses::Entry;
    use crate::terms::SECONDS_PER_DAY as DAY;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("esp-mint-audit-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pending(day: u64) -> Entry {
        Entry::Pending {
            redeemable_after_day: day,
            inputs: vec![],
            outputs: vec![],
        }
    }

    /// A store whose ledger has issued 100 under day 10 and 40 under day 11 and
    /// redeemed 25 under day 10, as exchanges and a redemption would have left it.
    fn known(dir: &std::path::Path) -> Responses {
        let mut r = Responses::open(&dir.join("responses.json")).unwrap();
        let mut m = Movements::new();
        m.issue(10, 100).issue(11, 40).redeem(10, 25);
        // `finish` needs an entry to finish; any unfinished one will do
        r.put("h", pending(10)).unwrap();
        r.finish("h", done(10), &m).unwrap();
        r
    }

    fn done(day: u64) -> Entry {
        let service = sp_wire::ServiceDid::parse(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        Entry::Done(sp_wire::esp::exchange::ExchangeResponse {
            keyset: String::new(),
            service,
            redeemable_after_day: day,
            signatures: vec![],
            keys: vec![],
            fee_per_byte: 0,
            fee_esp: 0,
            size_bytes: 0,
        })
    }

    #[test]
    fn an_empty_mint_audits_to_zeros() {
        let dir = scratch("empty");
        let r = Responses::open(&dir.join("responses.json")).unwrap();
        let body = audit_body(0, 0, &r, 10 * DAY);
        assert_eq!(body["outstanding"], 0);
        assert_eq!(body["outstanding_matured"], 0);
        assert_eq!(body["outstanding_unmatured"], 0);
        assert_eq!(body["outstanding_unsplit"], 0);
        assert_eq!(body["requests_unfinished"], 0);
        assert_eq!(body["as_of_day"], 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_split_moves_from_unmatured_to_matured_across_a_day_boundary() {
        let dir = scratch("boundary");
        let r = known(&dir);
        // The counters agree with the ledger: 140 issued, 25 redeemed.
        let at = |now| audit_body(140, 25, &r, now);

        let before = at(10 * DAY - 1);
        assert_eq!(before["as_of_day"], 9);
        assert_eq!(before["outstanding"], 115);
        assert_eq!(before["outstanding_matured"], 0);
        assert_eq!(before["outstanding_unmatured"], 115);
        assert_eq!(before["outstanding_unsplit"], 0);

        // the first second of day 10: what was issued for day 10 has matured
        let day10 = at(10 * DAY);
        assert_eq!(day10["as_of_day"], 10);
        assert_eq!(day10["outstanding_matured"], 75);
        assert_eq!(day10["outstanding_unmatured"], 40);
        assert_eq!(day10["outstanding_unsplit"], 0);

        // and the next day, the rest
        let day11 = at(11 * DAY);
        assert_eq!(day11["outstanding_matured"], 115);
        assert_eq!(day11["outstanding_unmatured"], 0);

        // the parts always add up to the outstanding total
        for now in [9 * DAY, 10 * DAY, 10 * DAY + 5, 11 * DAY, 400 * DAY] {
            let b = at(now);
            let sum = b["outstanding_matured"].as_u64().unwrap()
                + b["outstanding_unmatured"].as_u64().unwrap()
                + b["outstanding_unsplit"].as_u64().unwrap();
            assert_eq!(sum, b["outstanding"].as_u64().unwrap());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn esp_issued_before_the_ledger_is_reported_as_unsplit() {
        let dir = scratch("legacy");
        // an existing mint upgraded: 500 outstanding, the ledger knows nothing
        let r = Responses::open(&dir.join("responses.json")).unwrap();
        let body = audit_body(500, 0, &r, 10 * DAY);
        assert_eq!(body["outstanding"], 500);
        assert_eq!(body["outstanding_matured"], 0);
        assert_eq!(body["outstanding_unmatured"], 0);
        assert_eq!(body["outstanding_unsplit"], 500);

        // then 115 more is issued under the ledger: only the old part is unsplit
        let known = known(&scratch("legacy-known"));
        let body = audit_body(500 + 140, 25, &known, 10 * DAY);
        assert_eq!(body["outstanding"], 615);
        assert_eq!(body["outstanding_matured"], 75);
        assert_eq!(body["outstanding_unmatured"], 40);
        assert_eq!(body["outstanding_unsplit"], 500);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_request_part_way_through_never_makes_the_unsplit_amount_negative() {
        let dir = scratch("inflight");
        let mut r = known(&dir);
        r.put("e", pending(12)).unwrap();
        // A transfer burned its inputs (the counters say 20 redeemed more) and
        // has not been counted yet, so the counters are below the ledger.
        let body = audit_body(140, 45, &r, 11 * DAY);
        assert_eq!(body["outstanding"], 95);
        assert_eq!(body["outstanding_unsplit"], 0);
        assert_eq!(body["requests_unfinished"], 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
