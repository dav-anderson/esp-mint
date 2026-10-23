//! The ESP mint's AIR listener against a real `air_server` started in this
//! process: a wallet's mint-info, keysets, rotation, fees, rollover, exchange,
//! transfer and redeem requests are answered, signed by the mint's own DID key,
//! and checked by the same code the wallet runs (`sp_wire::air_request::ask`).
//! Every call runs against a real ESP mint (with a stand-in PSP for the
//! exchange). The four that change state are also resent (the same body, a new
//! request, and the same body handed straight to the mint: the answer is the
//! stored one and nothing is applied twice), refused and made to fail, and the
//! rollover is run at its full size (1000 notes). One test builds the state the
//! way `serve` does and checks the answer, the ledger and the audit together.
//!
//! The AIR client always dials port 5702 (upstream item 12), so these tests need
//! that port free; `local_server::start` says so when it is not. One server
//! serves every test of this binary, and each test has its own mint key, so no
//! two tests ever touch the same cell.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use esp_mint::air_listener::{self, Serve, Settings};
use esp_mint::config::Config;
use esp_mint::exchange::{self, ExchangeRequest, ExchangeResponse};
use esp_mint::psp_client::HttpPsp;
use esp_mint::redeem::{self, RedeemInput, RedeemOutput, RedeemRequest};
use esp_mint::rotation::{RolloverRequest, RolloverResponse};
use esp_mint::server::{self, EspState};
use esp_mint::terms::Terms;
use esp_mint::transfer::{self, TransferRequest, TransferResponse};
use mint_core::MintLogic;
use mint_core::keygen;
use mint_core::store::Store;
use mint_server::api::{MeltRequest, MeltResponse};
use mint_server::state::AppState;
use mint_types::{
    Amount, BlindNonce, MintInput, MintOutput, Nonce, Note, gen_denominations, melt_sighash,
};
use rand::rngs::OsRng;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, SECP256K1, SecretKey};
use sp_wire::air_request::addr::{self, mailbox_secret, reply_secret, shared_wallet};
use sp_wire::air_request::ask::{AskConfig, AskError, InFlight, Verified};
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::{
    KIND_EXCHANGE, KIND_FEES, KIND_KEYSETS, KIND_MINT_INFO, KIND_REDEEM, KIND_ROLLOVER,
    KIND_ROTATION, KIND_TRANSFER, MintInfo, STATUS_UNAVAILABLE, Served, VerifyError, local_server,
    verify_receipt,
};
use sp_wire::seal::SecretKey as DidKey;
use sp_wire::{ServiceDid, WIRE_VERSION};

const NETWORK: &str = "main";
const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// A test amount of PSP, as in the exchange tests.
const ONE_PSP: u64 = 100_000_000_000;
/// A test ESP note size, a power of two.
const ONE: u64 = 1 << 36;
/// A redeemable-after day long past, so every note below is mature.
const PAST: u64 = 100;
/// The rotating mint's clock at the start, and one rotation period.
const T0: u64 = 1_800_000_000;
const H: u64 = 3600;

/// One test at a time on the shared AIR server. It has a single storage worker,
/// so tests running in parallel starve each other past their timeouts.
static AIR_TURN: Mutex<()> = Mutex::new(());

/// The shared server plus this test's turn on it; the turn ends when this drops,
/// whether the test passed, failed or panicked.
struct Server {
    server: ServerRef,
    _turn: std::sync::MutexGuard<'static, ()>,
}

impl std::ops::Deref for Server {
    type Target = ServerRef;

    fn deref(&self) -> &ServerRef {
        &self.server
    }
}

fn server() -> Server {
    let turn = AIR_TURN.lock().unwrap_or_else(|e| e.into_inner());
    let server = local_server::start().expect("a local AIR server (is port 5702 free?)");
    Server {
        server,
        _turn: turn,
    }
}

fn scratch(name: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "esp-mint-air-info-{}-{name}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A mint's DID key and the DID it stands for.
fn mint_key() -> (DidKey, ServiceDid) {
    let key = DidKey::new();
    let did = addr::key_to_did(&key.public_key());
    (key, did)
}

fn service() -> ServiceDid {
    ServiceDid::parse(&format!("02{G_X}")).unwrap()
}

/// The key behind `G_X`: secret key 1.
fn service_keypair() -> Keypair {
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&bytes).unwrap())
}

fn zero_sig() -> Signature {
    Signature::from_slice(&[0u8; 64]).unwrap()
}

// ---------------------------------------------------------------- the listener

/// The listener on a thread of its own, as `serve` runs it. Dropping it stops it.
struct Listener {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<(), String>>>,
}

fn start_serving(server: &ServerRef, key: &DidKey, dir: &Path, serve: Arc<Serve>) -> Listener {
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

impl Listener {
    /// Stop it and say how it ended: `Ok` for a stop, `Err` for a failure or a panic.
    fn stop(mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.thread.take().unwrap().join() {
            Ok(result) => result,
            Err(_) => Err("the listener thread panicked".into()),
        }
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

fn config(server: &ServerRef, did: &ServiceDid, wait: u64, attempts: u32) -> AskConfig {
    AskConfig {
        server: server.clone(),
        mint: did.clone(),
        wire_version: WIRE_VERSION,
        network: NETWORK.to_string(),
        reply_wait_secs: wait,
        attempts,
        max_skew_secs: 300,
        timeout_secs: 10,
    }
}

/// The wallet's flow for any kind, blocking.
fn ask_any(cfg: &AskConfig, flight: &mut InFlight) -> Result<Verified, AskError> {
    async fn go(cfg: &AskConfig, flight: &mut InFlight) -> Result<Verified, AskError> {
        let client = client::connect(&cfg.server).await?;
        sp_wire::air_request::ask::ask(&client, cfg, flight, &mut |_| Ok(())).await
    }
    block_on_new_runtime(move || go(cfg, flight))
        .map_err(AskError::from)
        .and_then(|r| r)
}

/// Ask with a body (or none), blocking, with the wallet's own flow.
fn ask_body(cfg: &AskConfig, kind: u8, body: &[u8]) -> Result<Verified, AskError> {
    ask_any(cfg, &mut InFlight::with_body(kind, body.to_vec()))
}

fn json_bytes(value: &impl serde::Serialize) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn reply_cell(did: &ServiceDid, flight: &InFlight) -> DidKey {
    let shared = shared_wallet(&flight.r, &addr::did_to_key(did).unwrap());
    reply_secret(&shared, &flight.request_id, 0)
}

fn wait_for_next(dir: &Path, want: u32) {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let now = air_listener::read_next(dir).unwrap();
        if now == want {
            return;
        }
        assert!(
            Instant::now() < until,
            "the counter is {now}, expected {want}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------- the mint

/// The PSP stand-in's memos: of each burn, by nonce (hex), as the real PSP keeps it.
type Memos = Arc<Mutex<BTreeMap<String, String>>>;

fn nonce_key(nonce: &Nonce) -> String {
    hex::encode(nonce.0.serialize())
}

/// `/melt`, which keeps the memo of the burn before it burns, as the real PSP's does.
async fn melt_recording(
    State((state, memos)): State<(Arc<AppState>, Memos)>,
    Json(req): Json<MeltRequest>,
) -> Result<Json<MeltResponse>, (StatusCode, Json<serde_json::Value>)> {
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
    State((state, memos)): State<(Arc<AppState>, Memos)>,
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

fn serve_http(rt: &tokio::runtime::Runtime, app: Router) -> String {
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    rt.spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// A real ESP mint with its HTTP routes served in this process, a stand-in PSP
/// beside it (for the exchange), and the listener's `serve` for it.
struct Esp {
    rt: tokio::runtime::Runtime,
    /// The ESP's HTTP base URL.
    base: String,
    state: Arc<EspState>,
    psp: Arc<AppState>,
    /// The keyset requests name: the current one when the mint started.
    ks: String,
}

/// A mint that rotates every hour on a manual clock at [`T0`] (`set_clock`
/// moves it), as every mint does.
fn start_esp(dir: &Path, config: Config) -> Esp {
    start_esp_at(dir, config, None)
}

/// [`start_esp`], with the PSP the ESP calls at `psp_url` instead of the
/// stand-in (a dead one, for the tests of a mint that cannot answer).
fn start_esp_at(dir: &Path, config: Config, psp_url: Option<&str>) -> Esp {
    let config = Config {
        rotation_activation_hours: 1,
        rotation_period_hours: 1,
        ..config
    };
    start_esp_on(dir, config, T0, psp_url)
}

/// The mint `esp-mint serve` builds (`EspState::open`) on `dir`, with this config
/// and clock (`0` is the system clock), and a stand-in PSP beside it.
fn start_esp_on(dir: &Path, config: Config, clock: u64, psp_url: Option<&str>) -> Esp {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    // The PSP stand-in, in the form of the real PSP's.
    let cfg = keygen::generate(&gen_denominations(2, Amount::from_units(1024)));
    let psp_logic = MintLogic::new(cfg, Store::open(&dir.join("psp-db")).unwrap());
    let psp = Arc::new(AppState {
        logic: Mutex::new(psp_logic),
        admin_token: String::new(),
    });
    let memos: Memos = Arc::new(Mutex::new(BTreeMap::new()));
    let psp_app = Router::new()
        .route("/melt", post(melt_recording))
        .route("/burns", post(burns))
        .with_state((Arc::clone(&psp), Arc::clone(&memos)));
    let psp_base = serve_http(&rt, psp_app);

    let state = Arc::new(
        EspState::open(
            &dir.join("esp"),
            Box::new(HttpPsp::new(psp_url.unwrap_or(&psp_base)).unwrap()),
            config,
            clock,
        )
        .unwrap(),
    );
    let ks = state.rotor.lock().unwrap().current.id.clone();
    let base = serve_http(&rt, server::router(Arc::clone(&state)));
    Esp {
        rt,
        base,
        state,
        psp,
        ks,
    }
}

impl Esp {
    /// The listener's `serve` for this mint: what `esp-mint serve` runs.
    fn serve(&self) -> Arc<Serve> {
        let state = Arc::clone(&self.state);
        Arc::new(move |kind: u8, body: &[u8]| server::air_served(&state, kind, body))
    }

    /// GET an HTTP route (`/audit` and `/health` are all there is): the status
    /// and the bytes of the answer.
    fn http_get(&self, path: &str) -> (u16, Vec<u8>) {
        self.rt.block_on(async {
            let r = reqwest::get(format!("{}{path}", self.base)).await.unwrap();
            let status = r.status().as_u16();
            (status, r.bytes().await.unwrap().to_vec())
        })
    }

    fn http_json(&self, path: &str) -> serde_json::Value {
        serde_json::from_slice(&self.http_get(path).1).unwrap()
    }

    /// What the mint answers to `kind` with `body` when it is called in this
    /// process, as the listener calls it.
    fn served(&self, kind: u8, body: &[u8]) -> Option<Served> {
        server::air_served(&self.state, kind, body)
    }

    /// The body of an answered call made in this process.
    fn served_body(&self, kind: u8, body: &[u8]) -> Vec<u8> {
        match self.served(kind, body) {
            Some(Served::Body(bytes)) => bytes,
            Some(Served::Refused(body)) => {
                panic!(
                    "expected an answer, got a refusal: {}",
                    String::from_utf8_lossy(&body)
                )
            }
            Some(Served::Unavailable) => panic!("expected an answer, got 'unavailable'"),
            Some(Served::Ignored(why)) => panic!("expected an answer, got no reply: {why}"),
            None => panic!("expected an answer, the kind is not served"),
        }
    }

    /// The same request handed straight to the mint is answered with `want`.
    fn assert_served(&self, kind: u8, body: &[u8], want: &[u8]) {
        assert_eq!(self.served_body(kind, body).as_slice(), want);
    }

    fn set_clock(&self, t: u64) {
        self.state
            .rotor
            .lock()
            .unwrap()
            .clock
            .store(t, Ordering::SeqCst);
    }

    /// A PSP note of `units`, issued by the stand-in PSP, and the key that spends it.
    fn psp_note(&self, units: u64) -> (Note, Keypair) {
        let keypair = Keypair::new(SECP256K1, &mut OsRng);
        let nonce = Nonce(keypair.public_key());
        let (blind_point, blinding_key) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        let amount = Amount::from_units(units);
        let logic = self.psp.logic.lock().unwrap();
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

    /// An ESP note this mint has issued under these terms, and the key that spends it.
    fn esp_note(&self, units: u64, service: ServiceDid, day: u64) -> (Note, Keypair) {
        let terms = Terms {
            service,
            redeemable_after_day: day,
        };
        let keypair = Keypair::new(SECP256K1, &mut OsRng);
        let nonce = Nonce(keypair.public_key());
        let (blind_point, blinding_key) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        let amount = Amount::from_units(units);
        let sk = self.state.master.key_for(amount, &terms);
        let logic = self.state.logic.lock().unwrap();
        let outcome = logic
            .issue_with_key(
                &sk,
                &MintOutput {
                    amount,
                    blind_nonce: BlindNonce(blind_point),
                },
            )
            .unwrap();
        let signature =
            bdhke::unblind_message(&outcome.0, &blinding_key, &sk.public_key(SECP256K1));
        (Note { nonce, signature }, keypair)
    }

    fn is_spent(&self, note: &Note) -> bool {
        self.state
            .logic
            .lock()
            .unwrap()
            .is_spent(note.nonce)
            .unwrap()
    }

    fn audit(&self) -> serde_json::Value {
        self.http_json("/audit")
    }

    /// An exchange of one PSP note of `units` for the ESP amounts, as a wallet builds it.
    fn exchange_of(&self, note: Note, keypair: &Keypair, units: u64) -> ExchangeRequest {
        let outputs: Vec<MintOutput> = split(3 * ONE_PSP)
            .into_iter()
            .chain(split(ONE_PSP))
            .map(|amount| blinded(amount).0)
            .collect();
        let mut input = MintInput {
            amount: Amount::from_units(units),
            note,
            spend_signature: zero_sig(),
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
            keyset: self.ks.clone(),
            outputs,
        }
    }

    /// A transfer of the notes (note, key, units) to fresh ones of `out_units`,
    /// for the service `G_X`, redeemable after `day`.
    fn transfer_of(
        &self,
        notes: &[(Note, &Keypair, u64)],
        out_units: &[u64],
        day: u64,
    ) -> TransferRequest {
        let outputs: Vec<MintOutput> = out_units.iter().map(|&u| blinded(u).0).collect();
        let mut inputs: Vec<MintInput> = notes
            .iter()
            .map(|(note, _, units)| MintInput {
                amount: Amount::from_units(*units),
                note: *note,
                spend_signature: zero_sig(),
            })
            .collect();
        let sighash = transfer::digest(&service(), day, &inputs, &outputs);
        for (input, (_, keypair, _)) in inputs.iter_mut().zip(notes) {
            input.spend_signature = SECP256K1.sign_schnorr(&sighash, keypair);
        }
        TransferRequest {
            service: service(),
            redeemable_after_day: day,
            input_keysets: vec![self.ks.clone(); inputs.len()],
            inputs,
            keyset: self.ks.clone(),
            outputs,
            service_signature: SECP256K1.sign_schnorr(&sighash, &service_keypair()),
        }
    }

    /// A redemption of the notes (note, key, units, day) for the service `G_X`.
    fn redemption_of(&self, notes: &[(Note, &Keypair, u64, u64)]) -> RedeemRequest {
        let memo = "btc:bc1qpayhere";
        let decline_outputs: Vec<RedeemOutput> = Vec::new();
        let mut inputs: Vec<RedeemInput> = notes
            .iter()
            .map(|(note, _, units, day)| RedeemInput {
                service: service(),
                redeemable_after_day: *day,
                keyset: self.ks.clone(),
                input: MintInput {
                    amount: Amount::from_units(*units),
                    note: *note,
                    spend_signature: zero_sig(),
                },
            })
            .collect();
        let sighash = redeem::digest(&service(), &self.ks, &inputs, memo, &decline_outputs, &[]);
        for (input, (_, keypair, _, _)) in inputs.iter_mut().zip(notes) {
            input.input.spend_signature = SECP256K1.sign_schnorr(&sighash, keypair);
        }
        RedeemRequest {
            service: service(),
            output_keyset: self.ks.clone(),
            inputs,
            memo: memo.to_string(),
            decline_outputs,
            refund_outputs: vec![],
            service_signature: SECP256K1.sign_schnorr(&sighash, &service_keypair()),
        }
    }

    /// `n` notes of one unit under `PAST`, then one rotation later: the notes are
    /// of the previous keyset. Returns the notes, the previous and the current keyset.
    fn rotated(&self, n: usize) -> (Vec<(Note, Keypair)>, String, String) {
        let notes: Vec<_> = (0..n).map(|_| self.esp_note(1, service(), PAST)).collect();
        self.served_body(KIND_ROTATION, b"");
        self.set_clock(T0 + H);
        let w: serde_json::Value =
            serde_json::from_slice(&self.served_body(KIND_ROTATION, b"")).unwrap();
        (
            notes,
            w["previous"]["id"].as_str().unwrap().to_string(),
            w["current"]["id"].as_str().unwrap().to_string(),
        )
    }
}

/// Split a total into powers of two, the way the wallet does: one note for each
/// bit set, largest first.
fn split(total: u64) -> Vec<u64> {
    (0..64)
        .rev()
        .map(|bit| 1u64 << bit)
        .filter(|p| total & p != 0)
        .collect()
}

fn blinded(units: u64) -> (MintOutput, Keypair, SecretKey) {
    let kp = Keypair::new(SECP256K1, &mut OsRng);
    let (b, r) = bdhke::blind_message(&Nonce(kp.public_key()).as_hash_preimage(), None);
    (
        MintOutput {
            amount: Amount::from_units(units),
            blind_nonce: BlindNonce(b),
        },
        kp,
        r,
    )
}

/// A rollover of all of `notes` (one unit each, under `PAST`) into as many fresh
/// outputs of `out_units` each (1 keeps the amounts, anything else changes them).
fn rollover_of(
    notes: &[(Note, Keypair)],
    input_keyset: &str,
    keyset: &str,
    out_units: u64,
) -> RolloverRequest {
    let mut request = RolloverRequest {
        service: service(),
        redeemable_after_day: PAST,
        input_keysets: vec![input_keyset.to_string(); notes.len()],
        keyset: keyset.to_string(),
        inputs: notes
            .iter()
            .map(|(note, _)| MintInput {
                amount: Amount::from_units(1),
                note: *note,
                spend_signature: zero_sig(),
            })
            .collect(),
        outputs: notes.iter().map(|_| blinded(out_units).0).collect(),
    };
    let digest = request.digest();
    for (input, (_, keypair)) in request.inputs.iter_mut().zip(notes) {
        input.spend_signature = SECP256K1.sign_schnorr(&digest, keypair);
    }
    request
}

// ---------------------------------------------------------------- the reads

#[test]
fn mint_info_keysets_rotation_and_fees_are_answered_with_what_the_mint_serves() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("reads");
    let esp = start_esp(&dir, Config::default());
    let listener = start_serving(&server, &key, &dir, esp.serve());
    let cfg = config(&server, &did, 10, 3);

    // Mint info says what /health says, and passes the check the wallet makes.
    let v = ask_body(&cfg, KIND_MINT_INFO, b"").unwrap();
    assert!(!v.refused());
    let info: MintInfo = v.json().unwrap();
    let health = esp.http_json("/health");
    assert_eq!(info.status, health["status"].as_str().unwrap());
    assert_eq!(info.network, health["network"].as_str().unwrap());
    assert_eq!(
        u64::from(info.wire_version),
        health["wire_version"].as_u64().unwrap()
    );
    assert_eq!(info.wire_version, WIRE_VERSION);
    sp_wire::air_request::check_mint_info(v.body(), WIRE_VERSION, NETWORK).unwrap();
    // and the receipt verifies from the DID alone
    verify_receipt(&did, &v.receipt).unwrap();

    // The others are the exact bytes the mint serves, and JSON.
    for (kind, name) in [
        (KIND_KEYSETS, "keysets"),
        (KIND_ROTATION, "rotation"),
        (KIND_FEES, "fees"),
    ] {
        let over_air = ask_body(&cfg, kind, b"").unwrap();
        assert!(!over_air.refused(), "{name}");
        esp.assert_served(kind, b"", over_air.body());
        let json: serde_json::Value = over_air.json().unwrap();
        assert!(json.is_object(), "{name}: a JSON object");
    }
    wait_for_next(&dir, 4);
    listener.stop().unwrap();
}

// ---------------------------------------------------------------- exchange, transfer, redeem

const DAY: u64 = 21_000;

#[test]
fn a_resent_request_of_each_kind_is_answered_with_the_stored_answer_and_applied_once() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("resend");
    let esp = start_esp(&dir, Config::default());
    let listener = start_serving(&server, &key, &dir, esp.serve());
    let cfg = config(&server, &did, 10, 3);

    // The exchange.

    let (note, keypair) = esp.psp_note(4);
    let req = esp.exchange_of(note, &keypair, 4);
    let body = json_bytes(&req);

    let first = ask_body(&cfg, KIND_EXCHANGE, &body).unwrap();
    assert!(
        !first.refused(),
        "{}",
        String::from_utf8_lossy(first.body())
    );
    let response: ExchangeResponse = first.json().unwrap();
    assert_eq!(response.service, service());
    assert_eq!(response.signatures.len(), req.outputs.len());
    assert!(esp.psp.logic.lock().unwrap().is_spent(note.nonce).unwrap());
    assert_eq!(esp.audit()["issued"], 4 * ONE_PSP);

    // The same request handed straight to the mint is the stored answer, byte for
    // byte what AIR said.
    esp.assert_served(KIND_EXCHANGE, &body, first.body());

    // The same request over AIR again (a new request id) is answered again, from
    // the stored answer, and nothing is applied twice.
    let again = ask_body(&cfg, KIND_EXCHANGE, &body).unwrap();
    assert_ne!(again.request_id, first.request_id);
    assert_eq!(again.body(), first.body());
    assert_eq!(esp.audit()["issued"], 4 * ONE_PSP);
    assert!(esp.state.in_flight.is_empty());
    wait_for_next(&dir, 2);

    // A crash between answering and writing the counter replays the slots: the
    // counter goes back to 0, a new listener serves both requests again, and the
    // mint, which stored its answer before it burned, applies nothing again.
    listener.stop().unwrap();
    air_listener::write_next(&dir, 0).unwrap();
    let listener = start_serving(&server, &key, &dir, esp.serve());
    wait_for_next(&dir, 2);
    assert_eq!(esp.audit()["issued"], 4 * ONE_PSP);
    assert_eq!(esp.audit()["redeemed"], 0);
    // and the reply cell kept the first answer
    let third = ask_body(&cfg, KIND_EXCHANGE, &body).unwrap();
    assert_eq!(third.body(), first.body());

    // The transfer, on the same mint: the totals are on top of the exchange's.

    let (a, ka) = esp.esp_note(2 * ONE, service(), DAY);
    let (b, kb) = esp.esp_note(ONE, service(), DAY);
    assert_eq!(esp.audit()["issued"], 4 * ONE_PSP + 3 * ONE);
    let req = esp.transfer_of(&[(a, &ka, 2 * ONE), (b, &kb, ONE)], &[ONE, 2 * ONE], DAY);
    let body = json_bytes(&req);

    let first = ask_body(&cfg, KIND_TRANSFER, &body).unwrap();
    assert!(
        !first.refused(),
        "{}",
        String::from_utf8_lossy(first.body())
    );
    let response: TransferResponse = first.json().unwrap();
    assert_eq!(response.service, service());
    assert_eq!(response.redeemable_after_day, DAY);
    assert_eq!(response.signatures.len(), 2);
    assert!(esp.is_spent(&a) && esp.is_spent(&b));
    // the notes are burned (redeemed) and issued again in their place
    assert_eq!(esp.audit()["redeemed"], 3 * ONE);
    assert_eq!(esp.audit()["issued"], 4 * ONE_PSP + 6 * ONE);

    esp.assert_served(KIND_TRANSFER, &body, first.body());
    let again = ask_body(&cfg, KIND_TRANSFER, &body).unwrap();
    assert_ne!(again.request_id, first.request_id);
    assert_eq!(again.body(), first.body());
    // only the first moved the totals
    assert_eq!(esp.audit()["issued"], 4 * ONE_PSP + 6 * ONE);
    assert_eq!(esp.audit()["redeemed"], 3 * ONE);

    // The redemption, in its binary encoding.

    let (a, ka) = esp.esp_note(ONE, service(), PAST);
    let req = esp.redemption_of(&[(a, &ka, ONE, PAST)]);
    // Not JSON: the canonical bytes.
    let bytes = req.encode();
    assert!(serde_json::from_slice::<serde_json::Value>(&bytes).is_err());

    let first = ask_body(&cfg, KIND_REDEEM, &bytes).unwrap();
    assert!(
        !first.refused(),
        "{}",
        String::from_utf8_lossy(first.body())
    );
    let answer: serde_json::Value = first.json().unwrap();
    assert_eq!(answer["notes"][0]["accepted"], true);
    assert!(esp.is_spent(&a));
    assert_eq!(esp.audit()["redeemed"], 4 * ONE);

    esp.assert_served(KIND_REDEEM, &bytes, first.body());
    let again = ask_body(&cfg, KIND_REDEEM, &bytes).unwrap();
    assert_ne!(again.request_id, first.request_id);
    assert_eq!(again.body(), first.body());
    assert_eq!(esp.audit()["redeemed"], 4 * ONE);
    // one queue entry, not two
    assert_eq!(
        esp_mint::queue::Queue::open(&esp.state.queue_path)
            .unwrap()
            .len(),
        1
    );

    // The rollover.

    let (notes, previous, current) = esp.rotated(2);
    let req = rollover_of(&notes, &previous, &current, 1);
    let body = json_bytes(&req);

    let first = ask_body(&cfg, KIND_ROLLOVER, &body).unwrap();
    assert!(
        !first.refused(),
        "{}",
        String::from_utf8_lossy(first.body())
    );
    let response: RolloverResponse = first.json().unwrap();
    assert_eq!(response.epoch, 1);
    assert_eq!(response.keyset, current, "the answer names its signer");
    assert_eq!(response.signatures.len(), 2);

    // The same request handed straight to the mint, and over AIR again: the stored answer.
    esp.assert_served(KIND_ROLLOVER, &body, first.body());
    let again = ask_body(&cfg, KIND_ROLLOVER, &body).unwrap();
    assert_ne!(again.request_id, first.request_id);
    assert_eq!(again.body(), first.body());

    // A rollover that changes the amounts is refused, with no `http_status` (it is
    // a 400), and it burned nothing.
    let extra = vec![esp.esp_note(1, service(), PAST)];
    let bad = json_bytes(&rollover_of(&extra, &previous, &current, 2));
    let refused = ask_body(&cfg, KIND_ROLLOVER, &bad).unwrap();
    assert!(refused.refused());
    let body: serde_json::Value = serde_json::from_slice(refused.body()).unwrap();
    assert!(body.get("http_status").is_none());
    assert!(!esp.is_spent(&extra[0].0));
    listener.stop().unwrap();
}

// ---------------------------------------------------------------- rollover

/// The full size of a rollover: 1000 notes, the most one request may carry. The
/// request is about half a megabyte (the body length is 4 bytes, and the ceiling
/// is the mint's setting), the AIR server takes it as one record, and the answer
/// comes back whole.
#[test]
fn a_full_rollover_of_a_thousand_notes_goes_over_air() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("rollover-full");
    let esp = start_esp(&dir, Config::default());
    let listener = start_serving(&server, &key, &dir, esp.serve());
    let cfg = config(&server, &did, 60, 2);

    let (notes, previous, current) = esp.rotated(1000);
    let req = rollover_of(&notes, &previous, &current, 1);
    let body = json_bytes(&req);
    assert!(
        body.len() > 300_000 && body.len() < 1 << 20,
        "a full rollover is {} bytes: half a megabyte, under the 1 MiB ceiling",
        body.len()
    );

    let first = ask_body(&cfg, KIND_ROLLOVER, &body).unwrap();
    assert!(
        !first.refused(),
        "{}",
        String::from_utf8_lossy(first.body())
    );
    let response: RolloverResponse = first.json().unwrap();
    assert_eq!(response.signatures.len(), 1000);
    assert_eq!(response.keys.len(), 1000);
    // The same bytes handed straight to the mint, from the stored answer.
    esp.assert_served(KIND_ROLLOVER, &body, first.body());
    listener.stop().unwrap();
}

// ---------------------------------------------------------------- serve wiring

/// The unix day, from the system clock.
fn unix_day() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86_400
}

/// The state `esp-mint serve` runs on, built the way `serve` builds it (the
/// library constructor, from a `Config` with its defaults, on the system clock),
/// answers an exchange through `air_served`: the answer, the ledger and the
/// audit agree.
#[test]
fn the_state_serve_builds_answers_an_exchange_and_the_answer_ledger_and_audit_agree() {
    let dir = scratch("serve-wiring");
    let esp = start_esp_on(&dir, Config::default(), 0, None);
    let (note, keypair) = esp.psp_note(4);
    let req = esp.exchange_of(note, &keypair, 4);

    let day_before = unix_day();
    let body = esp.served_body(KIND_EXCHANGE, &json_bytes(&req));
    let day_after = unix_day();

    // The answer.
    let response: ExchangeResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(response.service, service());
    assert_eq!(response.keyset, esp.ks);
    assert_eq!(response.signatures.len(), req.outputs.len());
    assert!(
        (day_before + 365..=day_after + 365).contains(&response.redeemable_after_day),
        "the default maturity is 365 days: {}",
        response.redeemable_after_day
    );
    assert!(esp.psp.logic.lock().unwrap().is_spent(note.nonce).unwrap());

    // The ledger holds the outputs under their day, and nothing redeemed.
    let day = esp
        .state
        .responses
        .lock()
        .unwrap()
        .ledger()
        .day(response.redeemable_after_day);
    assert_eq!((day.issued, day.redeemed), (u128::from(4 * ONE_PSP), 0));

    // The audit (which `serve` serves on `server.bind`) says the same, and the
    // days ahead are unmatured.
    let audit = esp.audit();
    assert_eq!(audit["issued"], 4 * ONE_PSP);
    assert_eq!(audit["redeemed"], 0);
    assert_eq!(audit["outstanding"], 4 * ONE_PSP);
    assert_eq!(audit["outstanding_matured"], 0);
    assert_eq!(audit["outstanding_unmatured"], 4 * ONE_PSP);
    assert_eq!(audit["requests_unfinished"], 0);
}

// ---------------------------------------------------------------- refusals

#[test]
fn a_body_over_its_ceiling_is_refused_before_it_is_parsed_with_a_413() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("ceilings");
    let esp = start_esp(
        &dir,
        Config {
            exchange_max_request_bytes: 4096,
            transfer_max_request_bytes: 4096,
            rollover_max_request_bytes: 4096,
            redeem_max_request_bytes: 1000,
            ..Config::default()
        },
    );
    let listener = start_serving(&server, &key, &dir, esp.serve());
    let cfg = config(&server, &did, 10, 3);

    for (kind, route) in [
        (KIND_EXCHANGE, "/exchange"),
        (KIND_TRANSFER, "/transfer"),
        (KIND_ROLLOVER, "/rollover"),
    ] {
        // One byte over: refused for its size, not for its content.
        let big = vec![b' '; 4097];
        let v = ask_body(&cfg, kind, &big).unwrap();
        assert!(v.refused(), "{route}");
        let body: serde_json::Value = serde_json::from_slice(v.body()).unwrap();
        assert_eq!(body["code"], "request_too_large", "{route}");
        assert_eq!(body["http_status"], 413, "{route}");
        assert_eq!(body["limit_bytes"], 4096, "{route}");
        assert_eq!(body["size_bytes"], 4097, "{route}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("Nothing was parsed, burned or charged"),
            "{route}: {body}"
        );

        // At the limit the body is read, and is not a request: a 400.
        let at = vec![b' '; 4096];
        let v = ask_body(&cfg, kind, &at).unwrap();
        assert!(v.refused(), "{route}");
        let body: serde_json::Value = serde_json::from_slice(v.body()).unwrap();
        assert_eq!(body["code"], "malformed_request", "{route}");
        assert!(body.get("http_status").is_none(), "{route}: a 400");
    }

    // Redemption: the same, on the binary body.
    let big = vec![0xffu8; 1001];
    let v = ask_body(&cfg, KIND_REDEEM, &big).unwrap();
    assert!(v.refused());
    let body: serde_json::Value = serde_json::from_slice(v.body()).unwrap();
    assert_eq!(
        (body["code"].as_str(), body["http_status"].as_u64()),
        (Some("request_too_large"), Some(413))
    );
    assert_eq!(body["limit_bytes"], 1000);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("Nothing was parsed, burned or charged"),
        "{body}"
    );
    let at = vec![0xffu8; 1000];
    let v = ask_body(&cfg, KIND_REDEEM, &at).unwrap();
    assert!(v.refused());
    let body: serde_json::Value = serde_json::from_slice(v.body()).unwrap();
    assert_eq!(body["code"], "malformed_request");
    assert!(body.get("http_status").is_none());

    // A redemption that is perfectly good but too big is refused for its size,
    // without a burn or a fee.
    let held: Vec<(Note, Keypair)> = (0..8)
        .map(|_| esp.esp_note(4 * ONE, service(), PAST))
        .collect();
    let notes: Vec<(Note, &Keypair, u64, u64)> = held
        .iter()
        .map(|(note, key)| (*note, key, 4 * ONE, PAST))
        .collect();
    let bytes = esp.redemption_of(&notes).encode();
    assert!(bytes.len() > 1000);
    let v = ask_body(&cfg, KIND_REDEEM, &bytes).unwrap();
    assert!(v.refused());
    let body: serde_json::Value = serde_json::from_slice(v.body()).unwrap();
    assert_eq!(
        (body["code"].as_str(), body["http_status"].as_u64()),
        (Some("request_too_large"), Some(413))
    );
    assert!(held.iter().all(|(note, _)| !esp.is_spent(note)));

    // Nothing was written by any of the refusals.
    assert!(esp.state.responses.lock().unwrap().is_empty());
    assert!(!esp.state.queue_path.exists());
    listener.stop().unwrap();
}

#[test]
fn refusals_are_signed_replies_with_the_text_and_the_status() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("refusals");
    let esp = start_esp(&dir, Config::default());
    let listener = start_serving(&server, &key, &dir, esp.serve());
    let cfg = config(&server, &did, 10, 3);

    // A note spent by another transfer: a 400 with the notes named, which the
    // wallet turns into `SpentElsewhere`.
    let (a, ka) = esp.esp_note(ONE, service(), DAY);
    let first = esp.transfer_of(&[(a, &ka, ONE)], &[ONE], DAY);
    assert!(
        !ask_body(&cfg, KIND_TRANSFER, &json_bytes(&first))
            .unwrap()
            .refused()
    );
    let second = json_bytes(&esp.transfer_of(&[(a, &ka, ONE)], &[ONE], DAY));
    let v = ask_body(&cfg, KIND_TRANSFER, &second).unwrap();
    assert!(v.refused());
    let body: serde_json::Value = serde_json::from_slice(v.body()).unwrap();
    assert_eq!(body["code"], "note_spent_elsewhere");
    assert_eq!(body["spent"], serde_json::json!([0]));
    assert!(body.get("http_status").is_none());

    // A redemption with a bad service signature: a 400 with its code.
    let (b, kb) = esp.esp_note(ONE, service(), PAST);
    let mut redemption = esp.redemption_of(&[(b, &kb, ONE, PAST)]);
    let other = {
        let mut bytes = [0u8; 32];
        bytes[31] = 2;
        Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&bytes).unwrap())
    };
    redemption.service_signature = SECP256K1.sign_schnorr(&[7u8; 32], &other);
    let bytes = redemption.encode();
    let v = ask_body(&cfg, KIND_REDEEM, &bytes).unwrap();
    assert!(v.refused());
    let body: serde_json::Value = serde_json::from_slice(v.body()).unwrap();
    assert_eq!(body["code"], "bad_service_signature");
    assert!(!esp.is_spent(&b), "nothing was burned");

    // The same exchange arriving while it is being processed is a 409
    // `in_progress`: over AIR a signed refusal that says it was a 409, so the
    // wallet does not take it for a refusal of its notes. Nothing is lost: it
    // sends the same request again.
    let (note, keypair) = esp.psp_note(4);
    let req = esp.exchange_of(note, &keypair, 4);
    let body = json_bytes(&req);
    let hash = exchange::request_hash(&req).unwrap_or_else(|_| panic!("the request has a hash"));
    let claim = esp.state.in_flight.claim(&hash).expect("a free place");
    let v = ask_body(&cfg, KIND_EXCHANGE, &body).unwrap();
    assert!(v.refused());
    let held: serde_json::Value = serde_json::from_slice(v.body()).unwrap();
    assert_eq!(held["code"], "in_progress");
    assert_eq!(held["http_status"], 409);
    assert!(!esp.psp.logic.lock().unwrap().is_spent(note.nonce).unwrap());
    drop(claim);
    // Once the place is free the same request goes through.
    let v = ask_body(&cfg, KIND_EXCHANGE, &body).unwrap();
    assert!(!v.refused(), "{}", String::from_utf8_lossy(v.body()));
    listener.stop().unwrap();
}

// ---------------------------------------------------------------- cannot answer

#[test]
fn a_psp_that_cannot_be_reached_is_a_signed_unavailable_and_a_retry_is_safe() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("dead-psp");
    // Nothing listens on port 9: the mint cannot reach its PSP.
    let esp = start_esp_at(&dir, Config::default(), Some("http://127.0.0.1:9"));
    let listener = start_serving(&server, &key, &dir, esp.serve());
    let cfg = config(&server, &did, 10, 3);

    let (note, keypair) = esp.psp_note(4);
    let req = esp.exchange_of(note, &keypair, 4);
    let body = json_bytes(&req);
    let mut flight = InFlight::with_body(KIND_EXCHANGE, body.clone());
    match ask_any(&cfg, &mut flight) {
        Err(AskError::Verify(VerifyError::Refused(s))) => assert_eq!(s, STATUS_UNAVAILABLE),
        other => panic!("expected a signed 'unavailable', got {other:?}"),
    }
    // It was signed: the reply cell holds a receipt that verifies from the DID.
    let sealed = block_on_new_runtime(|| async {
        let client = client::connect(&server).await.unwrap();
        client::read_once(&client, reply_cell(&did, &flight).public_key(), 10)
            .await
            .unwrap()
    })
    .unwrap()
    .expect("a reply");
    let plain = addr::open(&flight.r, &sealed).unwrap();
    let receipt = verify_receipt(&did, &plain).unwrap();
    assert_eq!(receipt.status, STATUS_UNAVAILABLE);
    assert!(receipt.body.is_empty());
    assert!(matches!(
        esp.served(KIND_EXCHANGE, &body),
        Some(Served::Unavailable)
    ));
    // Nothing was burned or issued, so the wallet may send it again.
    assert!(!esp.psp.logic.lock().unwrap().is_spent(note.nonce).unwrap());
    assert_eq!(esp.audit()["issued"], 0);
    listener.stop().unwrap();
}

#[test]
fn a_mint_that_is_broken_says_so_in_a_signed_reply_for_every_call() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("poisoned");
    let esp = start_esp(&dir, Config::default());
    let listener = start_serving(&server, &key, &dir, esp.serve());
    let cfg = config(&server, &did, 10, 3);

    // Requests that parse and would reach the mint, built before it breaks.
    let (rolled, previous, current) = esp.rotated(1);
    let rollover = json_bytes(&rollover_of(&rolled, &previous, &current, 1));
    let (note, keypair) = esp.psp_note(4);
    let exchange = json_bytes(&esp.exchange_of(note, &keypair, 4));
    let (a, ka) = esp.esp_note(ONE, service(), DAY);
    let transfer = json_bytes(&esp.transfer_of(&[(a, &ka, ONE)], &[ONE], DAY));
    let (b, kb) = esp.esp_note(ONE, service(), PAST);
    let redeem = esp.redemption_of(&[(b, &kb, ONE, PAST)]).encode();

    // A thread panics while it holds the mint: the lock is poisoned, and the
    // HTTP routes would answer 500.
    let state = Arc::clone(&esp.state);
    let panicked = thread::spawn(move || {
        let _held = state.logic.lock().unwrap();
        panic!("poisoning the mint lock on purpose");
    })
    .join();
    assert!(panicked.is_err(), "the thread panicked, as it was meant to");
    assert!(esp.state.logic.is_poisoned());

    for (kind, body) in [
        (KIND_KEYSETS, Vec::new()),
        (KIND_ROTATION, Vec::new()),
        (KIND_ROLLOVER, rollover),
        (KIND_EXCHANGE, exchange),
        (KIND_TRANSFER, transfer),
        (KIND_REDEEM, redeem),
    ] {
        match ask_body(&cfg, kind, &body) {
            Err(AskError::Verify(VerifyError::Refused(s))) => assert_eq!(s, STATUS_UNAVAILABLE),
            other => panic!("kind {kind}: expected a signed 'unavailable', got {other:?}"),
        }
    }
    // Mint info still says what is wrong, and fees (settings only) still answer.
    let info: MintInfo = ask_body(&cfg, KIND_MINT_INFO, b"").unwrap().json().unwrap();
    assert_eq!(info.status, "broken");
    assert!(!ask_body(&cfg, KIND_FEES, b"").unwrap().refused());
    listener.stop().unwrap();
}

#[test]
fn the_esp_and_the_psp_can_share_an_air_server_because_their_mailboxes_are_their_own() {
    // Two mints on one server, each with its own DID: a request to one is never
    // seen by the other, so the PSP's listener never meets the ESP's requests.
    let server = server();
    let (esp_key, esp_did) = mint_key();
    let (psp_key, psp_did) = mint_key();
    assert_ne!(esp_did, psp_did);
    let dir = scratch("shared");
    let esp = start_esp(&dir, Config::default());
    let listener = start_serving(&server, &esp_key, &dir, esp.serve());
    // A stand-in for the PSP: answers only mint info, as its own DID.
    let psp_dir = scratch("shared-psp");
    let psp_serve: Arc<Serve> = Arc::new(|kind: u8, _: &[u8]| {
        (kind == KIND_MINT_INFO).then(|| {
            sp_wire::air_request::Served::Body(
                serde_json::to_vec(&MintInfo {
                    status: "ok".into(),
                    wire_version: WIRE_VERSION,
                    network: NETWORK.into(),
                })
                .unwrap(),
            )
        })
    });
    let psp_listener = start_serving(&server, &psp_key, &psp_dir, psp_serve);

    // Each answers its own mint info; the ESP's mailbox 0 and the PSP's slot 0
    // are different cells.
    for did in [&esp_did, &psp_did] {
        let v = ask_body(&config(&server, did, 10, 3), KIND_MINT_INFO, b"").unwrap();
        assert!(!v.refused());
        verify_receipt(did, &v.receipt).unwrap();
    }
    // And a request to the PSP's DID for a kind only the ESP serves is not
    // answered by the ESP.
    match ask_body(&config(&server, &psp_did, 2, 1), KIND_FEES, b"") {
        Err(AskError::Unreachable { .. }) => {}
        other => panic!("the PSP's mailbox is not the ESP's: {other:?}"),
    }
    assert!(mailbox_secret(&esp_did, 0).public_key() != mailbox_secret(&psp_did, 0).public_key());
    psp_listener.stop().unwrap();
    listener.stop().unwrap();
}
