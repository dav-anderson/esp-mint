//! The exchange does not hold the mint's lock while it waits on the PSP.
//!
//! A PSP built from mint-server's own handlers, with a `/melt` that can be
//! made to wait (until the test lets it go) or to answer late, and the ESP
//! mint calling it through `HttpPsp`. These tests check that one exchange
//! stuck at the PSP does not stop another, that the same request sent again
//! while it is stuck is answered "in progress" and processed once, and that a
//! PSP timeout leaves nothing stuck.
//!
//! The AIR listener answers one request at a time, so overlapping calls cannot
//! be made through it. The first two tests therefore hand the calls to the mint
//! in this process on threads of their own (`common::served_call`: what the
//! listener calls, with the same answers), and read `/health` and `/audit` over
//! HTTP; the PSP timeout, which is one call after another, goes over AIR (see
//! `common`: a refusal is read as its HTTP status and body, a signed "cannot
//! answer now" as `503`).
//!
//! These are plain tests with their own runtime, because the PSP client is
//! blocking and must not be created or used on an async thread.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use esp_mint::exchange::{self, ExchangeRequest, ExchangeResponse};
use esp_mint::psp_client::HttpPsp;
use esp_mint::responses::{Entry, Responses};
use esp_mint::server::{self, EspState};
use mint_core::MintLogic;
use mint_core::keygen;
use mint_core::store::Store;
use mint_server::api::{MeltRequest, MeltResponse};
use mint_server::state::AppState;
use mint_types::{
    Amount, BlindNonce, MintInput, MintOutput, Nonce, Note, gen_denominations, melt_sighash,
};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1};
use sp_wire::ServiceDid;
use tokio::runtime::Runtime;

const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ONE_PSP: u64 = 100_000_000_000;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("esp-mint-hold-{}-{name}", {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn service() -> ServiceDid {
    ServiceDid::parse(&format!("02{G_X}")).unwrap()
}

fn serve(rt: &Runtime, app: Router) -> String {
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    rt.spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

type Memos = Arc<Mutex<BTreeMap<String, String>>>;

fn nonce_key(nonce: &Nonce) -> String {
    hex::encode(nonce.0.serialize())
}

/// What the PSP's first `/melt` does before it burns.
#[derive(Clone, Copy)]
enum Hold {
    /// Wait until the test calls [`Gate::release`].
    UntilReleased,
    /// Wait this long, then burn, as a PSP that answers late would.
    Sleep(Duration),
}

/// Controls the PSP's first `/melt`. Later melts are never held.
struct Gate {
    hold: Hold,
    /// How many `/melt` calls have reached the PSP.
    arrived: AtomicUsize,
    released: AtomicBool,
}

impl Gate {
    fn new(hold: Hold) -> Arc<Self> {
        Arc::new(Gate {
            hold,
            arrived: AtomicUsize::new(0),
            released: AtomicBool::new(false),
        })
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
    }

    /// Wait until `n` melts have reached the PSP.
    fn wait_for_arrivals(&self, n: usize) {
        let start = Instant::now();
        while self.arrived.load(Ordering::SeqCst) < n {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the melt never reached the PSP"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

type PspState = (Arc<AppState>, Memos, Arc<Gate>);

/// `/melt`, which keeps the memo of the burn before it burns, as the real PSP's
/// does, and holds the first call as the gate says.
async fn melt_gated(
    State((state, memos, gate)): State<PspState>,
    Json(req): Json<MeltRequest>,
) -> Result<Json<MeltResponse>, (StatusCode, Json<serde_json::Value>)> {
    let first = gate.arrived.fetch_add(1, Ordering::SeqCst) == 0;
    if first {
        let gate = Arc::clone(&gate);
        // Waiting blocks, so it is done off the async threads.
        tokio::task::spawn_blocking(move || match gate.hold {
            Hold::UntilReleased => {
                let start = Instant::now();
                while !gate.released.load(Ordering::SeqCst)
                    && start.elapsed() < Duration::from_secs(60)
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            Hold::Sleep(d) => std::thread::sleep(d),
        })
        .await
        .unwrap();
    }
    let logic = state.logic.lock().unwrap();
    for input in &req.inputs {
        if !logic.is_spent(input.note.nonce).unwrap() {
            memos
                .lock()
                .unwrap()
                .insert(nonce_key(&input.note.nonce), req.memo.clone());
        }
    }
    logic
        .melt(&req.inputs, req.memo.as_bytes())
        .map(|burned| Json(MeltResponse { burned }))
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })
}

/// `/burns`: whether each note is spent, and the memo it was burned under.
async fn burns(
    State((state, memos, _)): State<PspState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let nonces: Vec<Nonce> = serde_json::from_value(req["nonces"].clone()).unwrap();
    let logic = state.logic.lock().unwrap();
    let burns: Vec<serde_json::Value> = nonces
        .iter()
        .map(|n| {
            let spent = logic.is_spent(*n).unwrap();
            let memo = if spent {
                memos.lock().unwrap().get(&nonce_key(n)).cloned()
            } else {
                None
            };
            serde_json::json!({"spent": spent, "memo": memo})
        })
        .collect();
    Json(serde_json::json!({ "burns": burns }))
}

fn start_psp(rt: &Runtime, dir: &Path, gate: &Arc<Gate>) -> (String, Arc<AppState>) {
    let cfg = keygen::generate(&gen_denominations(2, Amount::from_units(1024)));
    let logic = MintLogic::new(cfg, Store::open(&dir.join("psp-db")).unwrap());
    let state = Arc::new(AppState {
        logic: Mutex::new(logic),
        admin_token: String::new(),
    });
    let memos: Memos = Arc::new(Mutex::new(BTreeMap::new()));
    let app = Router::new()
        .route("/melt", post(melt_gated))
        .route("/burns", post(burns))
        .with_state((Arc::clone(&state), memos, Arc::clone(gate)));
    (serve(rt, app), state)
}

thread_local! {
    /// The ESP mint's keyset, which exchanges name (set by `start_esp`).
    static KS: std::cell::RefCell<String> = Default::default();
}

fn ks() -> String {
    KS.with(|k| k.borrow().clone())
}

/// The ESP mint, with its PSP client giving up after `psp_timeout_secs`.
fn start_esp(
    rt: &Runtime,
    dir: &Path,
    psp_url: &str,
    psp_timeout_secs: u64,
) -> (String, Arc<EspState>) {
    let (logic, master) = esp_mint::mint::open(&dir.join("esp")).unwrap();
    KS.with(|k| *k.borrow_mut() = esp_mint::rotation::keyset_id(&master));
    let responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
    let state = Arc::new(EspState {
        logic: Mutex::new(logic),
        master,
        psp: Box::new(HttpPsp::with_timeout(psp_url, psp_timeout_secs).unwrap()),
        responses: Mutex::new(responses),
        queue_path: dir.join("esp").join("queue.json"),
        queue_lock: Mutex::new(()),
        config: esp_mint::config::Handle::default(),
        rotor: None,
        rollovers: None,
        in_flight: Default::default(),
    });
    (serve(rt, server::router(Arc::clone(&state))), state)
}

fn psp_note(psp: &AppState, units: u64) -> (Note, Keypair) {
    let keypair = Keypair::new(SECP256K1, &mut OsRng);
    let nonce = Nonce(keypair.public_key());
    let (blind_point, blinding_key) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
    let amount = Amount::from_units(units);
    let logic = psp.logic.lock().unwrap();
    let outcome = logic
        .issue(&MintOutput {
            amount,
            blind_nonce: BlindNonce(blind_point),
        })
        .unwrap();
    let signature =
        bdhke::unblind_message(&outcome.0, &blinding_key, &logic.public_keys()[&amount]);
    (Note { nonce, signature }, keypair)
}

/// Split a total into powers of two, the way the wallet does.
fn split(total: u64) -> Vec<u64> {
    (0..64)
        .rev()
        .map(|bit| 1u64 << bit)
        .filter(|p| total & p != 0)
        .collect()
}

/// An exchange of one PSP note for `esp_total` ESP units, split into powers of
/// two.
fn request(note: Note, keypair: &Keypair, units: u64, esp_total: u64) -> ExchangeRequest {
    let outputs: Vec<MintOutput> = split(esp_total)
        .into_iter()
        .map(|amount| {
            let key = Keypair::new(SECP256K1, &mut OsRng);
            let nonce = Nonce(key.public_key());
            let (blind_point, _) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
            MintOutput {
                amount: Amount::from_units(amount),
                blind_nonce: BlindNonce(blind_point),
            }
        })
        .collect();
    let mut input = MintInput {
        amount: Amount::from_units(units),
        note,
        spend_signature: secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap(),
    };
    let sighash = melt_sighash(
        std::slice::from_ref(&input),
        exchange::memo(&service(), &outputs).as_bytes(),
    );
    input.spend_signature = SECP256K1.sign_schnorr(&sighash, keypair);
    ExchangeRequest {
        service: service(),
        psp_inputs: vec![input],
        psp_input_keysets: vec!["00".repeat(8)],
        keyset: ks(),
        outputs,
    }
}

/// `/audit` and `/health`, read over HTTP.
fn get_json(base: &str, path: &str) -> (u16, serde_json::Value) {
    assert!(matches!(path, "/audit" | "/health"), "{path}");
    let response = reqwest::blocking::get(format!("{base}{path}")).unwrap();
    let code = response.status().as_u16();
    (code, response.json().unwrap())
}

/// The exchange handed to the mint in this process (see the module docs).
fn exchange_now(state: &EspState, req: &ExchangeRequest) -> (u16, serde_json::Value) {
    common::served_call(state, "/exchange", &serde_json::to_vec(req).unwrap())
}

/// Send an exchange on another thread, so the test can go on while it waits.
fn post_in_background(
    state: &Arc<EspState>,
    req: &ExchangeRequest,
) -> std::thread::JoinHandle<(u16, serde_json::Value)> {
    let (state, req) = (Arc::clone(state), req.clone());
    std::thread::spawn(move || exchange_now(&state, &req))
}

fn is_pending(state: &EspState, req: &ExchangeRequest) -> bool {
    let hash = exchange::request_hash(req).unwrap();
    matches!(
        state.responses.lock().unwrap().get(&hash),
        Some(Entry::Pending { .. })
    )
}

#[test]
fn an_exchange_stuck_at_the_psp_does_not_block_an_unrelated_request() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("unrelated");
    let gate = Gate::new(Hold::UntilReleased);
    let (psp_url, psp) = start_psp(&rt, &dir, &gate);
    let (esp, state) = start_esp(&rt, &dir, &psp_url, 30);

    let (a, ka) = psp_note(&psp, 1);
    let (b, kb) = psp_note(&psp, 2);
    let first = request(a, &ka, 1, ONE_PSP);
    let other = request(b, &kb, 2, 2 * ONE_PSP);

    // The first reaches the PSP and waits there.
    let waiting = post_in_background(&state, &first);
    gate.wait_for_arrivals(1);
    assert!(is_pending(&state, &first));
    assert_eq!(state.in_flight.len(), 1);

    // While it waits, the mint answers other requests, including a whole
    // exchange of other notes.
    let started = Instant::now();
    assert_eq!(get_json(&esp, "/health").0, 200);
    assert_eq!(get_json(&esp, "/audit").1["issued"], 0);
    assert_eq!(common::served_call(&state, "/keysets", b"").0, 200);
    let (code, body) = exchange_now(&state, &other);
    assert_eq!(code, 200, "{body}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "an unrelated request waited on the stuck one"
    );
    assert!(psp.logic.lock().unwrap().is_spent(b.nonce).unwrap());
    assert!(!psp.logic.lock().unwrap().is_spent(a.nonce).unwrap());
    assert_eq!(get_json(&esp, "/audit").1["issued"], 2 * ONE_PSP);

    // The stuck one finishes when the PSP answers.
    gate.release();
    let (code, body) = waiting.join().unwrap();
    assert_eq!(code, 200, "{body}");
    let response: ExchangeResponse = serde_json::from_value(body).unwrap();
    assert_eq!(response.signatures.len(), first.outputs.len());
    assert_eq!(get_json(&esp, "/audit").1["issued"], 3 * ONE_PSP);
    assert!(state.in_flight.is_empty());
    assert!(!is_pending(&state, &first));
    rt.shutdown_background();
}

#[test]
fn the_same_request_sent_again_while_it_is_in_progress_is_not_processed_twice() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("duplicate");
    let gate = Gate::new(Hold::UntilReleased);
    let (psp_url, psp) = start_psp(&rt, &dir, &gate);
    let (esp, state) = start_esp(&rt, &dir, &psp_url, 30);

    let (a, ka) = psp_note(&psp, 1);
    let first = request(a, &ka, 1, ONE_PSP);
    let waiting = post_in_background(&state, &first);
    gate.wait_for_arrivals(1);

    // Two more copies while the first waits: each is told it is in progress,
    // and neither reaches the PSP.
    for _ in 0..2 {
        let (code, body) = exchange_now(&state, &first);
        assert_eq!(code, 409, "{body}");
        assert_eq!(body["code"], "in_progress");
    }
    assert_eq!(gate.arrived.load(Ordering::SeqCst), 1);

    // A different request for the same note is held back by the reservation,
    // as before, and does not reach the PSP either.
    let rival = request(a, &ka, 1, ONE_PSP);
    let (code, body) = exchange_now(&state, &rival);
    assert_eq!(code, 400, "{body}");
    assert!(body["error"].as_str().unwrap().contains("held by another"));
    assert_eq!(gate.arrived.load(Ordering::SeqCst), 1);

    gate.release();
    let (code, done) = waiting.join().unwrap();
    assert_eq!(code, 200, "{done}");
    // One burn, one issue, and a later copy gets the stored answer.
    let (code, again) = exchange_now(&state, &first);
    assert_eq!(code, 200);
    assert_eq!(again, done);
    assert_eq!(gate.arrived.load(Ordering::SeqCst), 1);
    assert_eq!(get_json(&esp, "/audit").1["issued"], ONE_PSP);
    assert!(state.in_flight.is_empty());
    rt.shutdown_background();
}

#[test]
fn a_psp_timeout_leaves_nothing_stuck_and_the_retry_finishes() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("timeout");
    // The PSP's first melt takes 3 seconds, and the mint gives up after 1.
    let gate = Gate::new(Hold::Sleep(Duration::from_secs(3)));
    let (psp_url, psp) = start_psp(&rt, &dir, &gate);
    let (esp, state) = start_esp(&rt, &dir, &psp_url, 1);
    let air = common::Air::start(&state, &dir.join("air"));

    let (a, ka) = psp_note(&psp, 1);
    let (b, kb) = psp_note(&psp, 1);
    let first = request(a, &ka, 1, ONE_PSP);
    let other = request(b, &kb, 1, ONE_PSP);

    // over AIR a signed "cannot answer now", which the HTTP route called a 502
    let (code, body) = air.post_json("/exchange", &first);
    assert_eq!(code, 503, "{body}");
    // Nothing is running, no lock is held, and the request is on file as
    // pending: the burn may have happened, so it is not rolled back, and the
    // retry will find out.
    assert!(state.in_flight.is_empty());
    assert!(is_pending(&state, &first));
    assert_eq!(get_json(&esp, "/health").0, 200);

    // An unrelated exchange goes through now.
    let (code, body) = air.post_json("/exchange", &other);
    assert_eq!(code, 200, "{body}");

    // The retry, once the PSP has answered or given up, finishes the request
    // whether or not the late burn happened, and burns the note once.
    std::thread::sleep(Duration::from_millis(3500));
    let (code, body) = air.post_json("/exchange", &first);
    assert_eq!(code, 200, "{body}");
    assert!(psp.logic.lock().unwrap().is_spent(a.nonce).unwrap());
    assert_eq!(get_json(&esp, "/audit").1["issued"], 2 * ONE_PSP);
    // Nothing is left reserved or running.
    assert!(state.in_flight.is_empty());
    assert_eq!(
        state.responses.lock().unwrap().pending_exchanges().count(),
        0
    );
    rt.shutdown_background();
}
