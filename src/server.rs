//! The ESP mint's requests, and the HTTP API that is left.
//!
//! **Wallets reach this mint over AIR only.** The calls (mint info, keysets,
//! rotation, fees, rollover, exchange, transfer and redeem) are answered by the
//! AIR listener (`air_listener`) with `air_served`, which builds each reply from
//! one outcome function per call (`run_exchange`, `run_transfer`, `run_redeem`,
//! `rollover_outcome`, `keysets_outcome`, `rotation_outcome`, `fees_body`,
//! `mint_info`). There are no HTTP routes for them.
//!
//! What is left on HTTP, on `server.bind` (loopback only):
//!
//! - `GET /audit`: issued, redeemed and outstanding ESP units, and the
//!   outstanding split into `outstanding_matured` (days that have come) and
//!   `outstanding_unmatured` (days ahead), from the per-day ledger (see
//!   `ledger`), with the number of requests still unfinished. For the operator.
//! - `GET /health`: `200` while the mint locks are sound, `503` otherwise. Read
//!   by `spi` and the health monitor on this machine; wallets get the same
//!   status in the mint info over AIR.
//!
//! The operator's routes (payouts, settle, decline) are on the admin router
//! (`admin`), on `server.admin_bind`, also loopback only.
//!
//! Every call that takes a body checks its size first: a body over the call's
//! ceiling is refused with the `413` JSON before anything is parsed, checked,
//! burned or charged for. After that the order is the same on every call,
//! cheapest first: the shape and field limits, the amounts, the signatures, the
//! mint's database, the reservations of other unfinished requests, and only then
//! anything that is written or burned.
//!
//! Each request takes the settings once, at its start (`state.config.current()`),
//! and uses them throughout, so a reload (`SIGHUP`) changes the rates and limits
//! for requests accepted after it and never for one already running.
//!
//! There is no authentication and no TLS on HTTP: it is loopback only. A note
//! authorizes its own spend, so a caller of the AIR listener can only burn notes
//! they hold.
//!
//! The mint and the stored responses are behind two mutexes, taken in that
//! order and held for the whole request, including the call to the PSP. One
//! request runs at a time. That is fine for development and is not a design for
//! load.

use std::collections::HashSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::get;
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
    /// Key rotation: the previous key set and the rollover answers. Every
    /// mint rotates. Always locked after the mint (and after the responses and
    /// the queue, when those are taken).
    pub rotor: Mutex<crate::rotation::Rotor>,
    pub rollovers: Mutex<crate::rotation::Rollovers>,
    /// The exchanges this process is in the middle of (see [`InFlight`]).
    pub in_flight: InFlight,
}

/// The queue file in a network's data folder.
pub fn queue_path(data_dir: &Path) -> PathBuf {
    data_dir.join("queue.json")
}

impl EspState {
    /// The state `esp-mint serve` runs on, opened from the network's data
    /// folder `data_dir`: the rotor and the mint it opens (generation 0 and any
    /// later one, from `config`'s `rotation.activation_hours` and
    /// `rotation.period_hours`), the rollover answers, the stored responses,
    /// the queue file, and `psp` for the burns of an exchange.
    ///
    /// `clock` is the mint's clock in unix seconds, for a rotation that is
    /// tested without waiting; `0` is the system clock, which is what `serve`
    /// passes. Every mint rotates, so there is no other way to open one.
    pub fn open(
        data_dir: &Path,
        psp: Box<dyn Psp + Send + Sync>,
        config: config::Config,
        clock: u64,
    ) -> Result<EspState, Box<dyn Error>> {
        let (rotor, logic) = crate::rotation::Rotor::open_at(
            data_dir,
            config.rotation_activation_hours,
            config.rotation_period_hours,
            clock,
        )?;
        let master = rotor.current.master.clone();
        let rollovers = crate::rotation::Rollovers::open(data_dir)?;
        let responses = Responses::open(&data_dir.join(crate::rotation::RESPONSES_FILE))?;
        Ok(EspState {
            logic: Mutex::new(logic),
            master,
            psp,
            responses: Mutex::new(responses),
            queue_path: queue_path(data_dir),
            queue_lock: Mutex::new(()),
            config: config::Handle::new(config),
            rotor: Mutex::new(rotor),
            rollovers: Mutex::new(rollovers),
            in_flight: Default::default(),
        })
    }
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
) -> Result<std::sync::MutexGuard<'a, crate::rotation::Rotor>, String> {
    let mut g = state
        .rotor
        .lock()
        .map_err(|_| "the rotor lock is poisoned".to_string())?;
    g.refresh(logic)
        .map_err(|e| format!("key rotation failed: {e}"))?;
    Ok(g)
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
    hold_for_rollovers(state, &mut responses).map_err(ExchangeError::Internal)?;
    let gens = rot.gens(&logic);
    f(&gens, &mut responses)
}

/// Tell `responses` which notes and output blind nonces pending rollovers hold,
/// so that no request stored there takes them. Locks the rollovers after the
/// rotor, as everywhere (logic, responses, rotor, rollovers); the caller holds
/// the first three.
fn hold_for_rollovers(state: &EspState, responses: &mut Responses) -> Result<(), String> {
    let store = state
        .rollovers
        .lock()
        .map_err(|_| "the rollovers lock is poisoned".to_string())?;
    responses.set_external_holds(store.held_nonces(""), store.held_outputs(""));
    Ok(())
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
    // 4. The burn, with no lock held. The reservation is on file. If the PSP
    // refuses the burn, nothing was burned: the entry is taken out again, under
    // the lock, and the request is answered 400. A fault or a timeout keeps it.
    if let Err(e) = exchange::burn_phase(state.psp.as_ref(), request, &plan) {
        if e.is_burn_refusal() {
            with_mint(state, |_, responses| exchange::withdraw(responses, &plan))?;
        }
        return Err(e);
    }
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
    let mut rot = match rotor_of(state, &mut logic) {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    };
    // Notes and outputs pending rollovers hold (locked after the rotor).
    if let Err(e) = hold_for_rollovers(state, &mut responses) {
        return (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e}));
    }
    let gens = rot.gens(&logic);
    match transfer::transfer_gens(&gens, &mut responses, request, &settings) {
        Ok(response) => match serde_json::to_value(&response) {
            Ok(body) => {
                // Finished: the burn proofs of this transfer (see
                // `Retired::burn_proofs`) are of no use any more.
                let id = transfer::request_hash(request);
                if let Err(e) = rot.forget_proofs(crate::rotation::Source::Responses, &id) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({"error": e.to_string()}),
                    );
                }
                (StatusCode::OK, body)
            }
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
            if let TransferRejection::AlreadySpent { indexes } = &r {
                body["code"] = json!(sp_wire::codes::NOTE_SPENT_ELSEWHERE);
                body["spent"] = json!(indexes);
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
    let mut rot = match rotor_of(state, &mut logic) {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    };
    // Notes and outputs pending rollovers hold (locked after the rotor).
    if let Err(e) = hold_for_rollovers(state, &mut responses) {
        return (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e}));
    }
    let gens = rot.gens(&logic);
    match redeem::redeem_gens(
        &gens,
        &mut responses,
        &state.queue_path,
        &request,
        &settings,
        now_unix,
    ) {
        Ok(response) => match serde_json::to_value(&response) {
            Ok(body) => {
                // Finished: the burn proofs of this redemption are of no use
                // any more (see `Retired::burn_proofs`).
                let id = redeem::request_hash(&request);
                if let Err(e) = rot.forget_proofs(crate::rotation::Source::Responses, &id) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({"error": e.to_string()}),
                    );
                }
                (StatusCode::OK, body)
            }
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

/// What a `413` says to do, per call.
const EXCHANGE_HINT: &str = "Split the exchange into several requests.";
const TRANSFER_HINT: &str = "Split the transfer into several requests.";
const ROLLOVER_HINT: &str = "Split the rollover into several requests.";
const REDEEM_HINT: &str = "Split the redemption into several requests.";

/// The JSON body of a `413`.
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

/// The JSON body of a `400` for a body that is not a request.
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
/// the operator's routes do (`admin`), before anything is parsed: a body that
/// says it is too large is refused without reading any of it, and one that does
/// not say is read only as far as the limit. (The AIR calls check the length of
/// the body they were handed, in `post_served`.)
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
    let totals = (|| -> Result<(u128, u128), String> {
        let current = logic.audit_totals().map_err(|e| e.to_string())?;
        let previous = match &rot.previous {
            Some((_, p)) => p.audit_totals().map_err(|e| e.to_string())?,
            None => (0, 0),
        };
        sum_generations([current, previous, rot.retired_totals()])
    })();
    match totals {
        Ok((issued, redeemed)) => (
            StatusCode::OK,
            Json(audit_body(issued, redeemed, &responses, now_secs())),
        ),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))),
    }
}

/// The (issued, redeemed) totals of all the generations added up, each add
/// checked. An overflow is an error, never a wrapped or a clamped figure.
fn sum_generations(parts: [(u128, u128); 3]) -> Result<(u128, u128), String> {
    let mut sums = (0u128, 0u128);
    for (issued, redeemed) in parts {
        sums.0 = sums
            .0
            .checked_add(issued)
            .ok_or("the issued totals of the generations add up to more than a u128")?;
        sums.1 = sums
            .1
            .checked_add(redeemed)
            .ok_or("the redeemed totals of the generations add up to more than a u128")?;
    }
    Ok(sums)
}

/// The body of `GET /audit`: mint-core's counters, and the split of what is
/// outstanding by whether its day has come at `now_unix`, from the per-day
/// ledger (see `ledger`).
///
/// - `outstanding_matured` / `outstanding_unmatured`: what the ledger knows is
///   outstanding under days that have come / days still ahead.
/// - `requests_unfinished`: exchanges, transfers and redemptions not finished.
///   What one has burned or signed is counted by mint-core at once and by the
///   ledger when the request finishes, so `outstanding` can be ahead of
///   matured + unmatured by that much while any are unfinished, and by nothing
///   when none are.
/// - `as_of_day`: the day (since the Unix epoch) that "has come" is measured at.
///
/// `issued`, `redeemed`, `outstanding`, `outstanding_matured` and
/// `outstanding_unmatured` are decimal strings: they are `u128` and a JSON
/// number cannot hold one. The other fields are numbers.
pub fn audit_body(issued: u128, redeemed: u128, responses: &Responses, now_unix: u64) -> Value {
    let outstanding = issued.saturating_sub(redeemed);
    let split = responses.ledger().split(now_unix);
    json!({
        "issued": issued.to_string(),
        "redeemed": redeemed.to_string(),
        "outstanding": outstanding.to_string(),
        "outstanding_matured": split.matured.to_string(),
        "outstanding_unmatured": split.unmatured.to_string(),
        "requests_unfinished": responses.unfinished(),
        "as_of_day": now_unix / crate::terms::SECONDS_PER_DAY,
    })
}

/// `GET /health`: `status`, `network` and `wire_version`, and `version` (this
/// binary's). `spi upgrade` reads `version` after a restart to know that the new
/// binary is the one serving.
async fn health_handler(State(state): State<Arc<EspState>>) -> (StatusCode, Json<Value>) {
    match fatal(&state) {
        None => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "network": state.config.current().network,
                "wire_version": sp_wire::WIRE_VERSION,
                "version": env!("CARGO_PKG_VERSION"),
            })),
        ),
        Some(why) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "broken",
                "reason": why,
                "network": state.config.current().network,
                "wire_version": sp_wire::WIRE_VERSION,
                "version": env!("CARGO_PKG_VERSION"),
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
        Ok(r) => {
            let g = r.gens(&logic);
            (
                StatusCode::OK,
                json!({"current": g.current_id, "previous": g.previous_id}),
            )
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    }
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
        Ok(r) => (
            StatusCode::OK,
            serde_json::to_value(r.window()).unwrap_or_default(),
        ),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    }
}

/// Rollover: move ESP of the previous (or current) key set to the
/// current one, same amounts and terms. Stored by request hash: the answer is
/// kept before any note is marked spent, so a resend gets the
/// stored answer and a crash in the middle is finished by the next resend. As a
/// status and a body, which the AIR listener turns into the reply.
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
    let mut rot = match rotor_of(state, &mut logic) {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    };
    let Ok(mut store) = state.rollovers.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "the rollovers lock is poisoned"}),
        );
    };
    // What unfinished exchanges, transfers and redemptions hold.
    let (notes, outputs) = responses.held_by_all();
    let held = crate::rotation::Held { notes, outputs };
    let result =
        crate::rotation::rollover(&rot.gens(&logic), &rot, &mut store, &held, req, max_items);
    match result {
        Ok(a) => {
            // Finished: its burn proofs (see `Retired::burn_proofs`) are of no
            // use any more. A resend of the answer comes back here to try again.
            if let Err(e) = rot.forget_proofs(crate::rotation::Source::Rollovers, &req.hash()) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": e.to_string()}),
                );
            }
            (StatusCode::OK, serde_json::to_value(a).unwrap_or_default())
        }
        Err(crate::rotation::RolloverError::Coded(code, e)) => {
            (StatusCode::BAD_REQUEST, json!({"error": e, "code": code}))
        }
        Err(crate::rotation::RolloverError::Refused(e)) => {
            (StatusCode::BAD_REQUEST, json!({"error": e}))
        }
        Err(crate::rotation::RolloverError::Keyset(code, e)) => {
            (StatusCode::BAD_REQUEST, json!({"error": e, "code": code}))
        }
        Err(crate::rotation::RolloverError::Spent(spent)) => (
            StatusCode::BAD_REQUEST,
            json!({
                "error": spent_inputs_text(&spent),
                "code": sp_wire::codes::NOTE_SPENT_ELSEWHERE,
                "spent": spent,
            }),
        ),
        Err(crate::rotation::RolloverError::Internal(e)) => {
            (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e}))
        }
    }
}

/// The text of a rollover refusal for spent notes, naming every one:
/// `input 1: the note is already spent`, or `inputs 1, 3: the notes are already
/// spent`.
fn spent_inputs_text(spent: &[usize]) -> String {
    let list = spent
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if spent.len() == 1 {
        format!("input {list}: the note is already spent")
    } else {
        format!("inputs {list}: the notes are already spent")
    }
}

// ---- over AIR ---------------------------------------------------------------

/// The signed refusal of a 4xx. A `400` is the route's body as it is. Any other
/// 4xx (the `409` `in_progress` of an exchange already being processed, the
/// `413` of a body over its ceiling) has
/// `http_status` added to the body, so that the wallet can treat it as it treats
/// that status as an HTTP status: only a `400` means "refused, nothing was burned", and
/// the others are an error where the outcome may be unknown and the same request
/// is sent again.
fn refused(status: StatusCode, mut body: Value) -> sp_wire::air_request::Served {
    if status != StatusCode::BAD_REQUEST
        && let Some(object) = body.as_object_mut()
    {
        object.insert("http_status".into(), json!(status.as_u16()));
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

/// A call with a JSON body: the ceiling first, then the parse, then the call. A
/// body over `limit` bytes is refused (the `413` JSON, before it is parsed), and
/// one that does not parse as `Q` is `malformed_request`.
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

/// What the AIR listener says to one kind of request: the JSON body of the
/// call, or a signed "cannot answer now" for a 5xx outcome, or a signed refusal
/// for a 4xx one. `None` for a kind this mint does not serve (keys: the ESP has
/// no keys call; and anything unknown), which the listener skips.
///
/// `body` is the request body (empty for the reads). The ceilings are read once
/// at the start of the request. Exchange, transfer, redeem and rollover are
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

/// The HTTP API that is left: `/audit` and `/health`, on `server.bind`
/// (loopback only). Wallets do not use it; they use the AIR listener.
pub fn router(state: Arc<EspState>) -> Router {
    Router::new()
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
        for field in ["issued", "redeemed", "outstanding"] {
            assert_eq!(body[field], "0", "{field}");
        }
        assert_eq!(body["outstanding_matured"], "0");
        assert_eq!(body["outstanding_unmatured"], "0");
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
        assert_eq!(before["issued"], "140");
        assert_eq!(before["redeemed"], "25");
        assert_eq!(before["outstanding"], "115");
        assert_eq!(before["outstanding_matured"], "0");
        assert_eq!(before["outstanding_unmatured"], "115");

        // the first second of day 10: what was issued for day 10 has matured
        let day10 = at(10 * DAY);
        assert_eq!(day10["as_of_day"], 10);
        assert_eq!(day10["outstanding_matured"], "75");
        assert_eq!(day10["outstanding_unmatured"], "40");

        // and the next day, the rest
        let day11 = at(11 * DAY);
        assert_eq!(day11["outstanding_matured"], "115");
        assert_eq!(day11["outstanding_unmatured"], "0");

        // the parts always add up to the outstanding total
        for now in [9 * DAY, 10 * DAY, 10 * DAY + 5, 11 * DAY, 400 * DAY] {
            let b = at(now);
            let part = |f: &str| b[f].as_str().unwrap().parse::<u64>().unwrap();
            assert_eq!(
                part("outstanding_matured") + part("outstanding_unmatured"),
                part("outstanding")
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_request_part_way_through_is_counted_as_unfinished() {
        let dir = scratch("inflight");
        let mut r = known(&dir);
        r.put("e", pending(12)).unwrap();
        // A transfer burned its inputs (the counters say 20 redeemed more) and
        // has not been counted yet, so the counters are below the ledger.
        let body = audit_body(140, 45, &r, 11 * DAY);
        assert_eq!(body["outstanding"], "95");
        // The ledger has not seen the transfer yet, so its split is still the
        // 115 it knew; the unfinished request is what tells the two apart.
        assert_eq!(body["outstanding_matured"], "115");
        assert_eq!(body["outstanding_unmatured"], "0");
        assert_eq!(body["requests_unfinished"], 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_totals_are_decimal_strings_and_the_sum_across_generations_is_checked() {
        // Fails if the totals go back to u64 or to JSON numbers: 2^64 + 5 issued
        // is clamped or wrapped, and a JSON number loses it.
        let dir = scratch("wide");
        let r = Responses::open(&dir.join("responses.json")).unwrap();
        let body = audit_body(18_446_744_073_709_551_621, 6, &r, 10 * DAY);
        assert_eq!(body["issued"], "18446744073709551621");
        assert_eq!(body["redeemed"], "6");
        assert_eq!(body["outstanding"], "18446744073709551615");
        assert_eq!(body["requests_unfinished"], 0);
        let sum = sum_generations([(1 << 63, 1), (1 << 63, 2), (5, 3)]);
        assert_eq!(sum, Ok((18_446_744_073_709_551_621, 6)));
        // an overflow is an error, not a wrapped figure
        assert!(sum_generations([(u128::MAX, 0), (1, 0), (0, 0)]).is_err());
        assert!(sum_generations([(0, 1), (0, u128::MAX), (0, 0)]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
