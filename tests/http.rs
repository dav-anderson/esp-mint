//! The exchange over HTTP, end to end: a PSP built from mint-server's own
//! handlers, the ESP server calling it through `HttpPsp`, and a wallet that
//! blinds, signs and unblinds the way a real one does.
//!
//! These are plain tests with their own runtime, because the PSP client is
//! blocking and must not be created or used on an async thread.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use esp_mint::exchange::{self, ExchangeRequest, ExchangeResponse};
use esp_mint::psp_client::HttpPsp;
use esp_mint::responses::{Entry, Responses};
use esp_mint::server::{self, EspState};
use esp_mint::terms::Terms;
use mint_core::MintLogic;
use mint_core::keygen;
use mint_core::store::Store;
use mint_server::api::{MeltRequest, MeltResponse};
use mint_server::state::AppState;
use mint_types::{
    Amount, BlindNonce, MintInput, MintOutput, Nonce, Note, gen_denominations, melt_sighash,
};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1, SecretKey, XOnlyPublicKey};
use tokio::runtime::Runtime;

const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ONE_PSP: u64 = 100_000_000_000;

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

fn service() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&hex::decode(G_X).unwrap()).unwrap()
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

/// A PSP with `/melt` and `/burns`, in the form of the real PSP's.
fn start_psp(rt: &Runtime, dir: &PathBuf) -> (String, Arc<AppState>, Memos) {
    let cfg = keygen::generate(&gen_denominations(2, Amount::from_units(1024)));
    let logic = MintLogic::new(cfg, Store::open(&dir.join("psp-db")).unwrap());
    let state = Arc::new(AppState {
        logic: Mutex::new(logic),
        admin_token: String::new(),
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
fn preset_ks(dir: &PathBuf) {
    std::fs::create_dir_all(dir.join("esp")).unwrap();
    let master =
        esp_mint::keys::load_or_generate(&dir.join("esp").join("master_secret.hex")).unwrap();
    KS.with(|k| *k.borrow_mut() = esp_mint::rotation::keyset_id(&master));
}

fn start_esp(rt: &Runtime, dir: &PathBuf, psp_url: &str) -> String {
    let (logic, master) = esp_mint::mint::open(&dir.join("esp")).unwrap();
    KS.with(|k| *k.borrow_mut() = esp_mint::rotation::keyset_id(&master));
    let responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
    let state = Arc::new(EspState {
        logic: Mutex::new(logic),
        master,
        psp: Box::new(HttpPsp::new(psp_url).unwrap()),
        responses: Mutex::new(responses),
        queue_path: dir.join("esp").join("queue.json"),
        queue_lock: Mutex::new(()),
        config: esp_mint::config::Handle::default(),
        rotor: None,
        rollovers: None,
        in_flight: Default::default(),
    });
    serve(rt, server::router(state))
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
        exchange::memo(&service(), &outputs).as_bytes(),
    );
    input.spend_signature = SECP256K1.sign_schnorr(&sighash, keypair);
    (
        ExchangeRequest {
            service: service(),
            psp_inputs: vec![input],
            psp_input_keysets: vec!["00".repeat(8)],
            keyset: ks(),
            outputs,
        },
        wanted,
    )
}

fn post_json(base: &str, path: &str, body: &impl serde::Serialize) -> (u16, serde_json::Value) {
    let response = reqwest::blocking::Client::new()
        .post(format!("{base}{path}"))
        .json(body)
        .send()
        .unwrap();
    let code = response.status().as_u16();
    (code, response.json().unwrap())
}

fn get_json(base: &str, path: &str) -> (u16, serde_json::Value) {
    let response = reqwest::blocking::get(format!("{base}{path}")).unwrap();
    let code = response.status().as_u16();
    (code, response.json().unwrap())
}

#[test]
fn an_exchange_over_http_burns_the_psp_and_issues_verifiable_esp() {
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
    assert_eq!(audit["issued"], 4 * ONE_PSP);
    assert_eq!(audit["outstanding"], 4 * ONE_PSP);

    // the same request again returns the same response and issues nothing more
    let (code, again) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200);
    assert_eq!(again, body);
    assert_eq!(get_json(&esp, "/audit").1["issued"], 4 * ONE_PSP);

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
fn write_pending(dir: &PathBuf, req: &ExchangeRequest) {
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
fn a_retry_after_this_exchanges_own_burn_is_finished_over_http() {
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
    assert_eq!(get_json(&esp, "/audit").1["issued"], ONE_PSP);
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
    assert_eq!(get_json(&esp, "/audit").1["issued"], 0);
    rt.shutdown_background();
}

#[test]
fn an_output_that_is_not_a_power_of_two_is_a_400_and_the_psp_note_survives() {
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
    assert_eq!(get_json(&esp, "/audit").1["issued"], 0);

    // the same total split into powers of two goes through
    let (req, _) = request(note, &keypair, 1, &[ONE_PSP]);
    assert!(req.outputs.len() > 1);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200, "{body}");
    assert_eq!(get_json(&esp, "/audit").1["issued"], ONE_PSP);
    rt.shutdown_background();
}

#[test]
fn an_underpaid_request_is_a_400_and_the_psp_note_survives() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("under");
    let (psp_url, psp, _memos) = start_psp(&rt, &dir);
    let esp = start_esp(&rt, &dir, &psp_url);

    let (note, keypair) = psp_note(&psp, 1);
    let (req, _) = request(note, &keypair, 1, &[ONE_PSP + 1]);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 400);
    assert!(body["error"].as_str().unwrap().contains("worth"));
    assert!(!psp.logic.lock().unwrap().is_spent(note.nonce).unwrap());
    assert_eq!(get_json(&esp, "/audit").1["issued"], 0);
    rt.shutdown_background();
}

#[test]
fn an_unreachable_psp_is_a_502_and_leaves_nothing_behind() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("down");
    let (_psp_url, psp, _memos) = start_psp(&rt, &dir);
    // nothing listens on port 1
    let esp = start_esp(&rt, &dir, "http://127.0.0.1:1");

    let (note, keypair) = psp_note(&psp, 1);
    let (req, _) = request(note, &keypair, 1, &[ONE_PSP]);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 502, "{body}");
    assert!(!psp.logic.lock().unwrap().is_spent(note.nonce).unwrap());
    assert_eq!(get_json(&esp, "/audit").1["issued"], 0);
    rt.shutdown_background();
}

#[test]
fn nothing_but_the_documented_routes_exist() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("routes");
    let (psp_url, _psp, _memos) = start_psp(&rt, &dir);
    let esp = start_esp(&rt, &dir, &psp_url);
    for path in ["/admin/issue", "/swap", "/melt"] {
        let status = reqwest::blocking::Client::new()
            .post(format!("{esp}{path}"))
            .json(&serde_json::json!({}))
            .send()
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 404, "{path}");
    }
    rt.shutdown_background();
}
