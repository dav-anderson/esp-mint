//! The AIR plumbing the integration tests share: a real `air_server` in this
//! process (`sp_wire::air_request::local_server`), esp-mint's own listener on it,
//! and a wallet-side `call` that sends one request the way the wallet does
//! (`sp_wire::air_request::ask`) and hands back the status and JSON the mint's
//! outcome has.
//!
//! Wallets reach the ESP mint over AIR only, so these tests, which used to call
//! the HTTP routes, call the AIR listener instead. A reply is read as the HTTP
//! route's answer used to be: an answered request is `200` and its JSON; a signed
//! refusal is its `http_status` (`400` when it has none) and its JSON, without the
//! `http_status` field; a signed "cannot answer now" is `503` and no JSON.
//!
//! The AIR client always dials port 5702 (upstream item 12), so these tests need
//! that port free; `local_server::start` says so when it is not. One server
//! serves every test of a binary, and the tests take turns on it (it has a single
//! storage worker, so tests running in parallel starve each other past their
//! timeouts). Each test has its own mint key, so no two tests touch the same cell.

#![allow(dead_code)]

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use esp_mint::air_listener::{self, Serve, Settings};
use esp_mint::exchange::ExchangeResponse;
use esp_mint::ledger::Movements;
use esp_mint::responses::Entry;
use esp_mint::server::{self, EspState};
use serde_json::Value;
use sp_wire::ServiceDid;
use sp_wire::WIRE_VERSION;
use sp_wire::air_request::addr;
use sp_wire::air_request::ask::{AskConfig, AskError, InFlight, Verified, ask};
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::{
    KIND_EXCHANGE, KIND_FEES, KIND_KEYSETS, KIND_MINT_INFO, KIND_REDEEM, KIND_ROLLOVER,
    KIND_ROTATION, KIND_TRANSFER, STATUS_UNAVAILABLE, Served, VerifyError, local_server,
};
use sp_wire::seal::SecretKey as DidKey;

/// One test at a time on the shared AIR server.
static AIR_TURN: Mutex<()> = Mutex::new(());

/// The shared server plus this test's turn on it; the turn ends when this drops,
/// whether the test passed, failed or panicked.
pub struct Server {
    server: ServerRef,
    _turn: std::sync::MutexGuard<'static, ()>,
}

impl std::ops::Deref for Server {
    type Target = ServerRef;

    fn deref(&self) -> &ServerRef {
        &self.server
    }
}

pub fn server() -> Server {
    let turn = AIR_TURN.lock().unwrap_or_else(|e| e.into_inner());
    let server = local_server::start().expect("a local AIR server (is port 5702 free?)");
    Server {
        server,
        _turn: turn,
    }
}

/// The listener on a thread of its own, as `esp-mint serve` runs it. Dropping it
/// stops it.
pub struct Listener {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<(), String>>>,
}

pub fn start_serving(server: &ServerRef, key: &DidKey, dir: &Path, serve: Arc<Serve>) -> Listener {
    let settings = Settings {
        server: server.clone(),
        held_reads: 16,
        timeout_secs: 10,
        state_dir: dir.to_path_buf(),
    };
    let key = key.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let thread = thread::Builder::new()
        .name("test-air-listener".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(air_listener::run(&settings, &key, &serve, async move {
                let _ = stopped.await;
            }))
        })
        .unwrap();
    Listener {
        stop: Some(stop),
        thread: Some(thread),
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// One ESP mint on the AIR: its DID, its listener and the wallet side to call it.
pub struct Air {
    pub did: ServiceDid,
    cfg: AskConfig,
    /// Dropped before `server`, so the listener has stopped when the turn ends.
    _listener: Listener,
    pub server: Server,
}

/// Record in the ledger ESP that a test signed straight from the mint
/// (`issue_with_key`), the way an exchange records the outputs it signs: an entry
/// is put and finished with the movements in one write. Without it the counters
/// say the ESP is outstanding and the ledger does not, and the parts of the
/// audit do not add up to the total. Only a test that reads those parts needs
/// it.
pub fn record_issued(state: &EspState, day: u64, units: u64) {
    static N: AtomicU64 = AtomicU64::new(0);
    let hash = format!("fixture-issue-{}", N.fetch_add(1, Ordering::Relaxed));
    let mut movements = Movements::new();
    movements.issue(day, u128::from(units));
    let mut responses = state.responses.lock().unwrap();
    responses
        .put(
            &hash,
            Entry::Pending {
                redeemable_after_day: day,
                inputs: vec![],
                outputs: vec![],
            },
        )
        .unwrap();
    responses
        .finish(
            &hash,
            Entry::Done(ExchangeResponse {
                keyset: String::new(),
                service: ServiceDid::parse(
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                )
                .unwrap(),
                redeemable_after_day: day,
                signatures: vec![],
                keys: vec![],
                fee_per_byte: 0,
                fee_esp: 0,
                size_bytes: 0,
            }),
            &movements,
        )
        .unwrap();
}

/// The kind of request a route of the old HTTP API stands for.
fn kind_of(route: &str) -> u8 {
    match route {
        "/exchange" => KIND_EXCHANGE,
        "/transfer" => KIND_TRANSFER,
        "/redeem" => KIND_REDEEM,
        "/rollover" => KIND_ROLLOVER,
        "/rotation" => KIND_ROTATION,
        "/keysets" => KIND_KEYSETS,
        "/fees" => KIND_FEES,
        "/health" => KIND_MINT_INFO,
        other => panic!("{other} is not a call the ESP mint answers over AIR"),
    }
}

/// A refusal's status and JSON: its `http_status` (`400` when it has none), and
/// the body without that field.
fn refusal(body: &[u8]) -> (u16, Value) {
    let mut value = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
    let status = value
        .get("http_status")
        .and_then(Value::as_u64)
        .unwrap_or(400) as u16;
    if let Some(object) = value.as_object_mut() {
        object.remove("http_status");
    }
    (status, value)
}

/// What the mint answers to a route's call when it is called in this process,
/// as the listener calls it (not over AIR: for tests of how the mint handles
/// calls that overlap, which the listener, which answers one at a time, does
/// not make), read like [`Air::call`].
pub fn served_call(state: &EspState, route: &str, body: &[u8]) -> (u16, Value) {
    match server::air_served(state, kind_of(route), body) {
        Some(Served::Body(bytes)) => (200, serde_json::from_slice(&bytes).unwrap_or(Value::Null)),
        Some(Served::Refused(bytes)) => refusal(&bytes),
        Some(Served::Unavailable) => (503, Value::Null),
        Some(Served::Ignored(why)) => panic!("{route}: expected an answer, got no reply: {why}"),
        None => panic!("{route} is not served"),
    }
}

impl Air {
    /// Take the turn on the shared server and start the listener for `state`,
    /// under a new mint key. The listener keeps its slot counter in a new folder
    /// under `dir`, so that a mint started again on the same data is a mint
    /// that has not answered anything yet. The turn is held until this drops,
    /// so a test that starts the mint again drops the first one first.
    pub fn start(state: &Arc<EspState>, dir: &Path) -> Air {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = dir.join(format!("air-{}", N.fetch_add(1, Ordering::Relaxed)));
        let server = server();
        let key = DidKey::new();
        let did = addr::key_to_did(&key.public_key());
        let state = Arc::clone(state);
        let serve: Arc<Serve> =
            Arc::new(move |kind: u8, body: &[u8]| server::air_served(&state, kind, body));
        std::fs::create_dir_all(&dir).unwrap();
        let listener = start_serving(&server, &key, &dir, serve);
        let cfg = AskConfig {
            server: server.server.clone(),
            mint: did,
            wire_version: WIRE_VERSION,
            network: "main".to_string(),
            reply_wait_secs: 30,
            attempts: 3,
            max_skew_secs: 300,
            timeout_secs: 10,
        };
        Air {
            did,
            cfg,
            _listener: listener,
            server,
        }
    }

    /// Send one request of `kind` with `body` and return the verified reply.
    pub fn ask(&self, kind: u8, body: &[u8]) -> Result<Verified, AskError> {
        async fn go(cfg: &AskConfig, flight: &mut InFlight) -> Result<Verified, AskError> {
            let client = client::connect(&cfg.server).await?;
            ask(&client, cfg, flight, &mut |_| Ok(())).await
        }
        let cfg = &self.cfg;
        let body = body.to_vec();
        block_on_new_runtime(move || async move {
            let mut flight = InFlight::with_body(kind, body);
            go(cfg, &mut flight).await
        })
        .map_err(AskError::from)
        .and_then(|r| r)
    }

    /// The route's call over AIR: the status and JSON of the outcome (see the
    /// module docs). A reply that fails a check, or no reply, fails the test.
    pub fn call(&self, route: &str, body: &[u8]) -> (u16, Value) {
        match self.ask(kind_of(route), body) {
            Ok(v) => {
                if v.refused() {
                    refusal(v.body())
                } else {
                    (200, serde_json::from_slice(v.body()).unwrap_or(Value::Null))
                }
            }
            // The mint said it cannot answer now: what a 5xx is over AIR.
            Err(AskError::Verify(VerifyError::Refused(STATUS_UNAVAILABLE))) => (503, Value::Null),
            Err(e) => panic!("{route} over AIR: {e}"),
        }
    }

    pub fn get_json(&self, route: &str) -> (u16, Value) {
        self.call(route, &[])
    }

    pub fn post_json(&self, route: &str, body: &impl serde::Serialize) -> (u16, Value) {
        self.call(route, &serde_json::to_vec(body).unwrap())
    }

    pub fn post_bytes(&self, route: &str, bytes: &[u8]) -> (u16, Value) {
        self.call(route, bytes)
    }
}
