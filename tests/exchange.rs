//! The exchange over AIR, end to end: a PSP stand-in (mint-core's `AppState`
//! behind `/melt` and `/burns` handlers), the ESP mint calling it through `HttpPsp` (the one HTTP call the ESP
//! mint makes), its AIR listener, and a wallet that blinds, signs and unblinds
//! the way a real one does.
//!
//! The exchange goes over AIR (see `common`: a refusal is read as its HTTP status
//! and body, a signed "cannot answer now" as `503`); `/audit` and `/health`,
//! which are all that is left of the ESP mint's HTTP API, are read over HTTP.
//! These are plain tests with their own runtime, because the PSP client is
//! blocking and must not be created or used on an async thread.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use esp_mint::exchange::{self, ExchangeRequest, ExchangeResponse};
use esp_mint::psp_client::HttpPsp;
use esp_mint::responses::{Entry, Responses};
use esp_mint::rotation::Rollovers;
use esp_mint::server::{self, EspState};
use esp_mint::terms::Terms;
use mint_core::MintLogic;
use mint_core::keygen;
use mint_core::state::AppState;
use mint_core::store::Store;
use mint_types::{
    Amount, BlindNonce, MintInput, MintOutput, Nonce, Note, gen_denominations, melt_sighash,
};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1, SecretKey};
use sp_wire::ServiceDid;
use sp_wire::melt::{MeltRequest, MeltResponse};
use tokio::runtime::Runtime;

const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ONE_PSP: u64 = 100_000_000_000;

/// A total of `/audit`, which is a decimal string.
fn audit_units(total: &serde_json::Value) -> u64 {
    total.as_str().unwrap().parse().unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("esp-mint-http-{}-{name}", {
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

/// The memo of each burn, by nonce (hex), as the real PSP keeps it.
type Memos = Arc<Mutex<BTreeMap<String, String>>>;

fn nonce_key(nonce: &Nonce) -> String {
    hex::encode(nonce.0.serialize())
}

/// `/melt`, as the real PSP's: every check first (a `400` records and burns
/// nothing), then the memo of the burn, then the burn.
async fn melt_recording(
    State((state, memos)): State<(Arc<AppState>, Memos)>,
    Json(req): Json<MeltRequest>,
) -> Result<Json<MeltResponse>, (StatusCode, Json<serde_json::Value>)> {
    let logic = state.logic.lock().unwrap();
    let refused = |why: String| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": why})),
        )
    };
    let sighash = melt_sighash(&req.inputs, req.memo.as_bytes());
    for input in &req.inputs {
        logic
            .verify_note(input)
            .and_then(|()| logic.verify_spend_authorization(input, sighash))
            .map_err(|e| refused(e.to_string()))?;
        if logic.is_spent(input.note.nonce).unwrap() {
            return Err(refused("a note is spent".into()));
        }
    }
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
                StatusCode::INTERNAL_SERVER_ERROR,
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

/// A PSP with `/melt` and `/burns`, in the form of the real PSP's.
fn start_psp(rt: &Runtime, dir: &Path) -> (String, Arc<AppState>, Memos) {
    let cfg = keygen::generate(&gen_denominations(2, Amount::from_units(1024)));
    let logic = MintLogic::new(cfg, Store::open(&dir.join("psp-db")).unwrap());
    let state = Arc::new(AppState {
        logic: Mutex::new(logic),
    });
    let memos: Memos = Arc::new(Mutex::new(BTreeMap::new()));
    let app = Router::new()
        .route("/melt", post(melt_recording))
        .route("/burns", post(burns))
        .with_state((Arc::clone(&state), Arc::clone(&memos)));
    (serve(rt, app), state, memos)
}

thread_local! {
    /// The ESP mint's keyset, which exchanges name (set by `start_esp`).
    static KS: std::cell::RefCell<String> = Default::default();
}

fn ks() -> String {
    KS.with(|k| k.borrow().clone())
}

/// For a request built before the ESP mint starts: its keyset, from the
/// master secret the mint will load.
fn preset_ks(dir: &Path) {
    std::fs::create_dir_all(dir.join("esp")).unwrap();
    let master =
        esp_mint::keys::load_or_generate(&dir.join("esp").join("master_secret.hex")).unwrap();
    KS.with(|k| *k.borrow_mut() = esp_mint::rotation::keyset_id(&master));
}

/// One ESP mint: its HTTP base URL (`/audit`, `/health`) and its AIR listener.
struct Esp {
    base: String,
    air: common::Air,
}

fn start_esp(rt: &Runtime, dir: &Path, psp_url: &str) -> Esp {
    start_esp_with(rt, dir, psp_url, esp_mint::config::Config::default()).0
}

/// An ESP mint with these settings, and its state. Dropping the `Esp`, the state
/// and the runtime stops the mint and lets go of its data folder, so that the
/// same folder can be opened again, as after a restart (and gives up the turn on
/// the AIR server).
fn start_esp_with(
    rt: &Runtime,
    dir: &Path,
    psp_url: &str,
    config: esp_mint::config::Config,
) -> (Esp, Arc<EspState>) {
    start_esp_at(rt, dir, psp_url, config, 0)
}

/// Like `start_esp_with`, on this clock (`0` is the system clock).
fn start_esp_at(
    rt: &Runtime,
    dir: &Path,
    psp_url: &str,
    config: esp_mint::config::Config,
    clock: u64,
) -> (Esp, Arc<EspState>) {
    // The state `serve` builds, on this clock, with this PSP and config.
    let state = Arc::new(
        EspState::open(
            &dir.join("esp"),
            Box::new(HttpPsp::new(psp_url).unwrap()),
            config,
            clock,
        )
        .unwrap(),
    );
    KS.with(|k| *k.borrow_mut() = state.rotor.lock().unwrap().current.id.clone());
    let base = serve(rt, server::router(Arc::clone(&state)));
    let air = common::Air::start(&state, &dir.join("air"));
    (Esp { base, air }, state)
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

struct Wanted {
    nonce: Nonce,
    blinding_key: SecretKey,
    amount: u64,
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

/// An exchange request the way a wallet builds it: each amount in
/// `esp_amounts` is a total, split into powers of two.
fn request(
    note: Note,
    keypair: &Keypair,
    units: u64,
    esp_amounts: &[u64],
) -> (ExchangeRequest, Vec<Wanted>) {
    let amounts: Vec<u64> = esp_amounts.iter().flat_map(|&a| split(a)).collect();
    request_exact(note, keypair, units, &amounts)
}

/// Like `request`, but each amount is an output as it stands, whatever it is.
fn request_exact(
    note: Note,
    keypair: &Keypair,
    units: u64,
    esp_amounts: &[u64],
) -> (ExchangeRequest, Vec<Wanted>) {
    request_for_service(service(), note, keypair, units, esp_amounts)
}

/// Like `request_exact`, for this service.
fn request_for_service(
    service: ServiceDid,
    note: Note,
    keypair: &Keypair,
    units: u64,
    esp_amounts: &[u64],
) -> (ExchangeRequest, Vec<Wanted>) {
    let mut wanted = Vec::new();
    let mut outputs = Vec::new();
    for &amount in esp_amounts {
        let key = Keypair::new(SECP256K1, &mut OsRng);
        let nonce = Nonce(key.public_key());
        let (blind_point, blinding_key) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        outputs.push(MintOutput {
            amount: Amount::from_units(amount),
            blind_nonce: BlindNonce(blind_point),
        });
        wanted.push(Wanted {
            nonce,
            blinding_key,
            amount,
        });
    }
    let mut input = MintInput {
        amount: Amount::from_units(units),
        note,
        spend_signature: secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap(),
    };
    let sighash = melt_sighash(
        std::slice::from_ref(&input),
        exchange::memo(&service, &outputs).as_bytes(),
    );
    input.spend_signature = SECP256K1.sign_schnorr(&sighash, keypair);
    (
        ExchangeRequest {
            service,
            psp_inputs: vec![input],
            psp_input_keysets: vec!["00".repeat(8)],
            keyset: ks(),
            outputs,
        },
        wanted,
    )
}

fn post_json(esp: &Esp, path: &str, body: &impl serde::Serialize) -> (u16, serde_json::Value) {
    esp.air.post_json(path, body)
}

/// `/audit` and `/health` are read over HTTP.
fn get_json(esp: &Esp, path: &str) -> (u16, serde_json::Value) {
    assert!(matches!(path, "/audit" | "/health"), "{path}");
    let response = reqwest::blocking::get(format!("{}{path}", esp.base)).unwrap();
    let code = response.status().as_u16();
    (code, response.json().unwrap())
}

#[test]
fn an_exchange_over_air_burns_the_psp_and_issues_verifiable_esp() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("happy");
    let (psp_url, psp, _memos) = start_psp(&rt, &dir);
    let esp = start_esp(&rt, &dir, &psp_url);

    let (note, keypair) = psp_note(&psp, 4);
    let (req, wanted) = request(note, &keypair, 4, &[3 * ONE_PSP, ONE_PSP]);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200, "{body}");
    let response: ExchangeResponse = serde_json::from_value(body.clone()).unwrap();

    // the signatures verify under the keys derived for these terms
    let master =
        esp_mint::keys::load_or_generate(&dir.join("esp").join("master_secret.hex")).unwrap();
    let terms = Terms {
        service: service(),
        redeemable_after_day: response.redeemable_after_day,
    };
    for (i, w) in wanted.iter().enumerate() {
        let sk = master.key_for(Amount::from_units(w.amount), &terms);
        assert_eq!(response.keys[i], sk.public_key(SECP256K1));
        let unblinded =
            bdhke::unblind_message(&response.signatures[i], &w.blinding_key, &response.keys[i]);
        assert!(bdhke::verify_message(
            &sk,
            unblinded,
            &w.nonce.as_hash_preimage()
        ));
    }

    // the PSP note is burned, and the ESP supply is 4 PSP
    assert!(psp.logic.lock().unwrap().is_spent(note.nonce).unwrap());
    let (code, audit) = get_json(&esp, "/audit");
    assert_eq!(code, 200);
    assert_eq!(audit["issued"], (4 * ONE_PSP).to_string());
    assert_eq!(audit["outstanding"], (4 * ONE_PSP).to_string());

    // the same request again returns the same response and issues nothing more
    let (code, again) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200);
    assert_eq!(again, body);
    assert_eq!(
        get_json(&esp, "/audit").1["issued"],
        (4 * ONE_PSP).to_string()
    );

    assert_eq!(get_json(&esp, "/health").0, 200);
    assert_eq!(get_json(&esp, "/health").1["network"], "main");
    // The wire format this mint speaks; a wallet refuses a mint on another number.
    assert_eq!(
        get_json(&esp, "/health").1["wire_version"],
        sp_wire::WIRE_VERSION
    );
    rt.shutdown_background();
}

/// The nonces and blind nonces a pending exchange of `req` holds, as hex.
fn held(req: &ExchangeRequest) -> (Vec<String>, Vec<String>) {
    (
        req.psp_inputs
            .iter()
            .map(|i| nonce_key(&i.note.nonce))
            .collect(),
        req.outputs
            .iter()
            .map(|o| hex::encode(o.blind_nonce.0.serialize()))
            .collect(),
    )
}

/// An exchange that is validated and pending, as it is after a crash, in the
/// ESP mint's responses file.
fn write_pending(dir: &Path, req: &ExchangeRequest) {
    std::fs::create_dir_all(dir.join("esp")).unwrap();
    let mut responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
    let (inputs, outputs) = held(req);
    responses
        .put(
            &exchange::request_hash(req).unwrap(),
            Entry::Pending {
                redeemable_after_day: 21_000,
                inputs,
                outputs,
            },
        )
        .unwrap();
}

#[test]
fn a_retry_after_this_exchanges_own_burn_is_finished_over_air() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("own-burn");
    let (psp_url, psp, memos) = start_psp(&rt, &dir);
    let (note, keypair) = psp_note(&psp, 1);
    preset_ks(&dir);
    let (req, wanted) = request(note, &keypair, 1, &[ONE_PSP]);
    write_pending(&dir, &req);
    // the burn happened under this exchange's memo and its reply was lost
    let memo = exchange::memo(&req.service, &req.outputs);
    memos
        .lock()
        .unwrap()
        .insert(nonce_key(&note.nonce), memo.clone());
    psp.logic
        .lock()
        .unwrap()
        .melt(&req.psp_inputs, memo.as_bytes())
        .unwrap();

    let esp = start_esp(&rt, &dir, &psp_url);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200, "{body}");
    let response: ExchangeResponse = serde_json::from_value(body).unwrap();
    assert_eq!(response.redeemable_after_day, 21_000);
    assert_eq!(response.signatures.len(), wanted.len());
    assert_eq!(get_json(&esp, "/audit").1["issued"], ONE_PSP.to_string());
    rt.shutdown_background();
}

#[test]
fn a_note_burned_elsewhere_during_a_pending_exchange_is_a_400_and_signs_nothing() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("elsewhere");
    let (psp_url, psp, memos) = start_psp(&rt, &dir);
    let (note, keypair) = psp_note(&psp, 1);
    preset_ks(&dir);
    let (req, _) = request(note, &keypair, 1, &[ONE_PSP]);
    write_pending(&dir, &req);
    // the holder burns the same note at the PSP under another memo
    let mut other = MintInput {
        amount: Amount::from_units(1),
        note,
        spend_signature: secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap(),
    };
    let sighash = melt_sighash(std::slice::from_ref(&other), b"somewhere else");
    other.spend_signature = SECP256K1.sign_schnorr(&sighash, &keypair);
    memos
        .lock()
        .unwrap()
        .insert(nonce_key(&note.nonce), "somewhere else".to_string());
    psp.logic
        .lock()
        .unwrap()
        .melt(&[other], b"somewhere else")
        .unwrap();

    let esp = start_esp(&rt, &dir, &psp_url);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 400, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("different request")
    );
    assert_eq!(body["code"], "note_spent_elsewhere");
    assert_eq!(body["spent"], serde_json::json!([0]));
    assert_eq!(get_json(&esp, "/audit").1["issued"], "0");
    rt.shutdown_background();
}

#[test]
fn an_output_a_pending_rollover_holds_is_refused_to_an_exchange_and_the_psp_note_survives() {
    // Fails if the exchange does not look at the output blind nonces pending
    // rollovers hold.
    let rt = Runtime::new().unwrap();
    let dir = scratch("rollover-holds");
    let (psp_url, psp, _) = start_psp(&rt, &dir);
    let (note, keypair) = psp_note(&psp, 1);
    preset_ks(&dir);
    let (req, _) = request(note, &keypair, 1, &[ONE_PSP]);
    let mut rollovers = Rollovers::open(&dir.join("esp")).unwrap();
    rollovers.begin("pending", 0, vec![], held(&req).1).unwrap();
    let esp = start_esp(&rt, &dir, &psp_url);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 400, "{body}");
    assert!(body["error"].as_str().unwrap().contains("held"), "{body}");
    assert!(!psp.logic.lock().unwrap().is_spent(note.nonce).unwrap());
    rt.shutdown_background();
}

#[test]
fn a_badly_formed_or_underpaid_exchange_is_a_400_and_the_psp_note_survives() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("denomination");
    let (psp_url, psp, _memos) = start_psp(&rt, &dir);
    let esp = start_esp(&rt, &dir, &psp_url);

    let (note, keypair) = psp_note(&psp, 1);
    // the right total, as one output that is not a power of two
    let (req, _) = request_exact(note, &keypair, 1, &[ONE_PSP]);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "bad_denomination");
    assert_eq!(
        body["error"],
        "output 0: ESP amounts are powers of two. Nothing was burned"
    );
    assert!(!psp.logic.lock().unwrap().is_spent(note.nonce).unwrap());
    assert_eq!(get_json(&esp, "/audit").1["issued"], "0");

    // outputs worth more than the PSP note
    let (under, under_key) = psp_note(&psp, 1);
    let (req, _) = request(under, &under_key, 1, &[ONE_PSP + 1]);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 400);
    assert!(body["error"].as_str().unwrap().contains("worth"));
    assert!(!psp.logic.lock().unwrap().is_spent(under.nonce).unwrap());
    assert_eq!(get_json(&esp, "/audit").1["issued"], "0");

    // the same total as the first, split into powers of two, goes through
    let (req, _) = request(note, &keypair, 1, &[ONE_PSP]);
    assert!(req.outputs.len() > 1);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200, "{body}");
    assert_eq!(get_json(&esp, "/audit").1["issued"], ONE_PSP.to_string());
    rt.shutdown_background();
}

#[test]
fn an_unreachable_psp_is_a_503_and_leaves_nothing_behind() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("down");
    let (_psp_url, psp, _memos) = start_psp(&rt, &dir);
    // nothing listens on port 1
    let esp = start_esp(&rt, &dir, "http://127.0.0.1:1");

    let (note, keypair) = psp_note(&psp, 1);
    let (req, _) = request(note, &keypair, 1, &[ONE_PSP]);
    let (code, body) = post_json(&esp, "/exchange", &req);
    // over AIR a signed "cannot answer now", which the HTTP route called a 502
    assert_eq!(code, 503, "{body}");
    assert!(!psp.logic.lock().unwrap().is_spent(note.nonce).unwrap());
    assert_eq!(get_json(&esp, "/audit").1["issued"], "0");
    rt.shutdown_background();
}

/// The entry stored under this exchange, if any.
fn entry_of(state: &EspState, req: &ExchangeRequest) -> Option<Entry> {
    let hash = exchange::request_hash(req).unwrap();
    state.responses.lock().unwrap().get(&hash).cloned()
}

#[test]
fn a_melt_the_psp_refuses_is_a_400_that_drops_the_entry() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("refused");
    let (psp_url, psp, memos) = start_psp(&rt, &dir);
    let (esp, state) = start_esp_with(&rt, &dir, &psp_url, Default::default());

    // A note of 2 claimed as 4: the PSP's `/melt` answers 400.
    let (note, keypair) = psp_note(&psp, 2);
    let (req, _) = request(note, &keypair, 4, &[4 * ONE_PSP]);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 400, "{body}");
    let why = body["error"].as_str().unwrap();
    assert!(
        why.starts_with("the PSP refused to burn the notes: psp /melt returned 400 Bad Request: ")
    );
    assert!(why.ends_with(". Nothing was burned or issued"), "{why}");
    assert_eq!(entry_of(&state, &req), None);
    assert!(memos.lock().unwrap().is_empty());
    assert!(!psp.logic.lock().unwrap().is_spent(note.nonce).unwrap());
    rt.shutdown_background();
}

#[test]
fn nothing_but_audit_and_health_is_served_over_http() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("routes");
    let (psp_url, _psp, _memos) = start_psp(&rt, &dir);
    let esp = start_esp(&rt, &dir, &psp_url);
    let client = reqwest::blocking::Client::new();
    // the calls wallets make go over AIR only, and the PSP's and the operator's
    // routes are not here either
    for path in [
        "/exchange",
        "/transfer",
        "/redeem",
        "/rollover",
        "/keysets",
        "/rotation",
        "/fees",
        "/keys",
        "/check-state",
        "/admin/issue",
        "/swap",
        "/melt",
    ] {
        let url = format!("{}{path}", esp.base);
        let post = client
            .post(&url)
            .json(&serde_json::json!({}))
            .send()
            .unwrap();
        assert_eq!(post.status().as_u16(), 404, "POST {path}");
        let get = client.get(&url).send().unwrap();
        assert_eq!(get.status().as_u16(), 404, "GET {path}");
    }
    for path in ["/audit", "/health"] {
        assert_eq!(get_json(&esp, path).0, 200, "{path}");
    }
    rt.shutdown_background();
}

/// The split on `/audit`, as (matured, unmatured, unfinished).
fn split_of(esp: &Esp) -> (u64, u64, u64) {
    let (code, audit) = get_json(esp, "/audit");
    assert_eq!(code, 200, "{audit}");
    assert_eq!(
        audit_units(&audit["outstanding_matured"]) + audit_units(&audit["outstanding_unmatured"]),
        audit_units(&audit["outstanding"]),
        "the parts add up: {audit}"
    );
    (
        audit_units(&audit["outstanding_matured"]),
        audit_units(&audit["outstanding_unmatured"]),
        audit["requests_unfinished"].as_u64().unwrap(),
    )
}

#[test]
fn the_audit_splits_the_outstanding_esp_by_maturity_and_keeps_the_split_across_a_restart() {
    let rt_psp = Runtime::new().unwrap();
    let dir = scratch("split");
    let (psp_url, psp, _memos) = start_psp(&rt_psp, &dir);

    // A mint whose notes are redeemable the day they are issued (terms.maturity_days = 0).
    let rt1 = Runtime::new().unwrap();
    let config = esp_mint::config::Config {
        maturity_days: 0,
        ..Default::default()
    };
    let (esp, state) = start_esp_with(&rt1, &dir, &psp_url, config);
    assert_eq!(split_of(&esp), (0, 0, 0));
    let (note, keypair) = psp_note(&psp, 2);
    let (first, _) = request(note, &keypair, 2, &[2 * ONE_PSP]);
    let (code, first_body) = post_json(&esp, "/exchange", &first);
    assert_eq!(code, 200, "{first_body}");
    assert_eq!(split_of(&esp), (2 * ONE_PSP, 0, 0));
    drop(esp);
    drop(state);
    drop(rt1);

    // The restart, with the default of 365 days: what was issued before is still
    // matured, and what is issued now is not.
    let rt2 = Runtime::new().unwrap();
    let (esp, state) = start_esp_with(&rt2, &dir, &psp_url, esp_mint::config::Config::default());
    assert_eq!(split_of(&esp), (2 * ONE_PSP, 0, 0));
    let (note, keypair) = psp_note(&psp, 1);
    let (second, _) = request(note, &keypair, 1, &[ONE_PSP]);
    let (code, body) = post_json(&esp, "/exchange", &second);
    assert_eq!(code, 200, "{body}");
    assert_eq!(split_of(&esp), (2 * ONE_PSP, ONE_PSP, 0));
    // asking again counts nothing twice
    assert_eq!(post_json(&esp, "/exchange", &second), (200, body));
    assert_eq!(post_json(&esp, "/exchange", &first), (200, first_body));
    assert_eq!(split_of(&esp), (2 * ONE_PSP, ONE_PSP, 0));

    drop(esp);
    drop(state);
    drop(rt2);
    rt_psp.shutdown_background();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- the key stream ---------------------------------------------------------

/// 1,800,000,000 s is day 20,833 (20,833 x 86,400 = 1,799,971,200). With the
/// default `terms.maturity_days` of 365 a new exchange on this clock is
/// redeemable after day 21,198, and with 30 after day 20,863.
const T0: u64 = 1_800_000_000;

/// A key-set ID as the stream's records carry it.
fn id8(id: &str) -> [u8; 8] {
    hex::decode(id).unwrap().try_into().unwrap()
}

/// A service nobody else uses.
fn other_service() -> ServiceDid {
    let key = Keypair::new(SECP256K1, &mut OsRng);
    ServiceDid::from_slice(&key.public_key().serialize()).unwrap()
}

/// Fails if the control record, the day it publishes or the keys in it are not
/// what a wallet will look for: m and the live key set in control record 0, then,
/// once a service has exchanged, its 64 keys for day (today + m) and the next
/// day, and no other day. The keys must be the very keys the exchange was
/// signed with, so a mint that signed with other keys than it published, or
/// published a day other than the one it gave, fails here.
#[test]
fn a_finished_exchange_is_published_on_the_stream_for_the_days_a_wallet_will_look_at() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("stream-e1");
    let (psp_url, psp, _memos) = start_psp(&rt, &dir);
    let (esp, _state) = start_esp_at(&rt, &dir, &psp_url, esp_mint::config::Config::default(), 0);
    let generation = id8(&ks());
    // The exchange is dated by the system clock, so the days follow it.
    let today = esp_mint::server::now_secs() / 86_400;

    // Before any exchange there is a control record and no day.
    assert_eq!(
        esp.air.publish().as_deref(),
        Some(
            "key stream: wrote 1 control record(s) and 0 day record part(s) (0 bytes); 0 service(s) known"
        )
    );
    let control = esp.air.control(0).expect("control record 0");
    assert_eq!(control.index, 0);
    assert_eq!(control.maturity_days, 365);
    assert_eq!(control.current.epoch, 0);
    assert_eq!(control.current.id, generation);
    assert_eq!(control.previous, None);
    assert!(esp.air.control(1).is_none());
    assert!(esp.air.day(generation, today + 365, 0, 0).is_none());

    let (note, keypair) = psp_note(&psp, 4);
    let (req, wanted) = request(note, &keypair, 4, &[3 * ONE_PSP, ONE_PSP]);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200, "{body}");
    let response: ExchangeResponse = serde_json::from_value(body).unwrap();
    assert_eq!(response.redeemable_after_day, today + 365);

    // Two days (today + 365 and today + 366) of one service: 2 x (34 + 2,145) bytes.
    assert_eq!(
        esp.air.publish().as_deref(),
        Some(
            "key stream: wrote 0 control record(s) and 2 day record part(s) (4358 bytes); 1 service(s) known"
        )
    );
    for day in [today + 365, today + 366] {
        let record = esp.air.day(generation, day, 0, 0).expect("the day");
        assert_eq!((record.day, record.bucket, record.buckets), (day, 0, 1));
        assert_eq!(record.part, 0);
        assert_eq!(record.services.len(), 1);
        assert_eq!(record.services[0].service, service());
    }
    let day = esp.air.day(generation, today + 365, 0, 0).unwrap();
    for (i, w) in wanted.iter().enumerate() {
        assert_eq!(
            day.services[0].key_for(Amount::from_units(w.amount)),
            Some(&response.keys[i]),
            "the published key of {} is the key it was signed with",
            w.amount
        );
    }
    // The next day has other keys than the first.
    let next = esp.air.day(generation, today + 366, 0, 0).unwrap();
    assert_ne!(next.services[0].keys, day.services[0].keys);
    // No other day is published, and no second part of these.
    assert!(esp.air.day(generation, today + 364, 0, 0).is_none());
    assert!(esp.air.day(generation, today + 367, 0, 0).is_none());
    assert!(esp.air.day(generation, today + 365, 0, 1).is_none());
    assert!(esp.air.day([0xAA; 8], today + 365, 0, 0).is_none());

    // The same request again, and a pass with nothing new, write nothing.
    assert_eq!(post_json(&esp, "/exchange", &req).0, 200);
    assert_eq!(esp.air.publish(), None);
    rt.shutdown_background();
}

/// Fails if a change of m is not a new control record, or if the days move
/// without following m, or if a second exchange after the change is signed for a
/// day that was not published.
#[test]
fn a_change_of_the_maturity_rule_is_a_new_control_record_and_moves_the_days() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("stream-e2");
    let (psp_url, psp, _memos) = start_psp(&rt, &dir);
    let (esp, state) = start_esp_at(&rt, &dir, &psp_url, esp_mint::config::Config::default(), 0);
    let generation = id8(&ks());
    // The exchange is dated by the system clock, so the days follow it.
    let today = esp_mint::server::now_secs() / 86_400;

    let (note, keypair) = psp_note(&psp, 1);
    let (req, _) = request(note, &keypair, 1, &[ONE_PSP]);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200, "{body}");
    assert!(esp.air.publish().is_some());
    assert!(esp.air.control(1).is_none());
    assert!(esp.air.day(generation, today + 30, 0, 0).is_none());

    // The operator makes the rule 30 days and the mint reloads.
    let data = dir.join("esp");
    std::fs::write(
        data.join(esp_mint::config::FILE_NAME),
        "[terms]\nmaturity_days = 30\n",
    )
    .unwrap();
    state.config.reload(&data, &|_: &str| None).unwrap();
    assert_eq!(
        esp.air.publish().as_deref(),
        Some(
            "key stream: wrote 1 control record(s) and 2 day record part(s) (4358 bytes); 1 service(s) known"
        )
    );
    let control = esp.air.control(1).expect("control record 1");
    assert_eq!(control.index, 1);
    assert_eq!(control.maturity_days, 30);
    assert_eq!(control.current.id, generation);
    // Record 0 is as it was.
    assert_eq!(esp.air.control(0).unwrap().maturity_days, 365);
    assert!(esp.air.control(2).is_none());
    for day in [today + 30, today + 31] {
        assert!(esp.air.day(generation, day, 0, 0).is_some(), "day {day}");
    }
    // The days the first exchange needs stay.
    assert!(esp.air.day(generation, today + 365, 0, 0).is_some());

    // An exchange now is for day today + 30, and was signed with the keys that are
    // already published for it.
    let (note, keypair) = psp_note(&psp, 1);
    let (req, wanted) = request(note, &keypair, 1, &[ONE_PSP]);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200, "{body}");
    let response: ExchangeResponse = serde_json::from_value(body).unwrap();
    assert_eq!(response.redeemable_after_day, today + 30);
    let record = esp.air.day(generation, today + 30, 0, 0).unwrap();
    for (i, w) in wanted.iter().enumerate() {
        assert_eq!(
            record.services[0].key_for(Amount::from_units(w.amount)),
            Some(&response.keys[i])
        );
    }
    // Nothing is left to write: no new record for the same m.
    assert_eq!(esp.air.publish(), None);
    assert!(esp.air.control(2).is_none());
    rt.shutdown_background();
}

/// Fails if an exchange made after a reload of `terms.maturity_days` but
/// before the writer has published the new m in a control record is dated with
/// the new m: a wallet reads the old m on the stream and would refuse that day
/// as a key mismatch. Until the control record is written the old m (and its
/// published days) is used; after it, the new one.
#[test]
fn a_reloaded_maturity_rule_is_used_only_once_its_control_record_is_published() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("stream-e2b");
    let (psp_url, psp, _memos) = start_psp(&rt, &dir);
    let (esp, state) = start_esp_at(&rt, &dir, &psp_url, esp_mint::config::Config::default(), 0);
    let generation = id8(&ks());
    let today = esp_mint::server::now_secs() / 86_400;
    // Control record 0 (m = 365) is written.
    assert!(esp.air.publish().is_some());
    assert_eq!(esp.air.control(0).unwrap().maturity_days, 365);

    // The operator makes the rule 30 days and the mint reloads; the writer has
    // not run yet.
    let data = dir.join("esp");
    std::fs::write(
        data.join(esp_mint::config::FILE_NAME),
        "[terms]\nmaturity_days = 30\n",
    )
    .unwrap();
    state.config.reload(&data, &|_: &str| None).unwrap();
    assert!(esp.air.control(1).is_none());

    // An exchange in between still gets today + 365, the day the published m gives.
    let (note, keypair) = psp_note(&psp, 1);
    let (req, wanted) = request(note, &keypair, 1, &[ONE_PSP]);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200, "{body}");
    let response: ExchangeResponse = serde_json::from_value(body).unwrap();
    assert_eq!(response.redeemable_after_day, today + 365);

    // The writer's pass publishes m = 30, and the day the exchange was signed for.
    assert!(esp.air.publish().is_some());
    assert_eq!(
        esp.air.control(1).expect("control record 1").maturity_days,
        30
    );
    let record = esp
        .air
        .day(generation, today + 365, 0, 0)
        .expect("day + 365");
    for (i, w) in wanted.iter().enumerate() {
        assert_eq!(
            record.services[0].key_for(Amount::from_units(w.amount)),
            Some(&response.keys[i])
        );
    }

    // From now on a new exchange gets today + 30.
    let (note, keypair) = psp_note(&psp, 1);
    let (req, _) = request(note, &keypair, 1, &[ONE_PSP]);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200, "{body}");
    let response: ExchangeResponse = serde_json::from_value(body).unwrap();
    assert_eq!(response.redeemable_after_day, today + 30);
    rt.shutdown_background();
}

/// Fails if a service over `stream.max_services` is not refused before its PSP
/// note is burned, or if a service the mint knows is refused too.
#[test]
fn a_new_service_over_the_cap_is_refused_before_anything_is_burned() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("stream-e3");
    let (psp_url, psp, _memos) = start_psp(&rt, &dir);
    let config = esp_mint::config::Config {
        stream_max_services: 1,
        ..esp_mint::config::Config::default()
    };
    let (esp, _state) = start_esp_at(&rt, &dir, &psp_url, config, T0);

    let (note, keypair) = psp_note(&psp, 1);
    let (req, _) = request(note, &keypair, 1, &[ONE_PSP]);
    let (code, first) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200, "{first}");

    // A second service is refused, and its note is not burned.
    let (note_b, key_b) = psp_note(&psp, 1);
    let (req_b, _) = request_for_service(other_service(), note_b, &key_b, 1, &[ONE_PSP]);
    let (code, body) = post_json(&esp, "/exchange", &req_b);
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "service_limit");
    assert!(!psp.logic.lock().unwrap().is_spent(note_b.nonce).unwrap());

    // The service it knows goes on, with a new note and with the old request.
    let (note_c, key_c) = psp_note(&psp, 1);
    let (req_c, _) = request(note_c, &key_c, 1, &[ONE_PSP]);
    assert_eq!(post_json(&esp, "/exchange", &req_c).0, 200);
    let (code, again) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200);
    assert_eq!(again, first);
    assert!(esp.air.publish().unwrap().ends_with("; 1 service(s) known"));
    rt.shutdown_background();
}
