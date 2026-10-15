//! The exchange over HTTP, end to end: a PSP built from mint-server's own
//! handlers, the ESP server calling it through `HttpPsp`, and a wallet that
//! blinds, signs and unblinds the way a real one does.
//!
//! These are plain tests with their own runtime, because the PSP client is
//! blocking and must not be created or used on an async thread.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::routing::post;
use esp_mint::exchange::{self, ExchangeRequest, ExchangeResponse};
use esp_mint::psp_client::HttpPsp;
use esp_mint::responses::Responses;
use esp_mint::server::{self, EspState};
use esp_mint::terms::Terms;
use mint_core::MintLogic;
use mint_core::keygen;
use mint_core::store::Store;
use mint_server::api;
use mint_server::state::AppState;
use mint_types::{
    Amount, BlindNonce, MintInput, MintOutput, Nonce, Note, gen_denominations, melt_sighash,
};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1, SecretKey, XOnlyPublicKey};
use tokio::runtime::Runtime;

const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ONE_PSP: u64 = 1_000_000_000_000;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("esp-mint-http-{}-{name}", std::process::id()));
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

/// A PSP with mint-server's `/melt` and `/check-state`.
fn start_psp(rt: &Runtime, dir: &PathBuf) -> (String, Arc<AppState>) {
    let cfg = keygen::generate(&gen_denominations(2, Amount::from_units(1024)));
    let logic = MintLogic::new(cfg, Store::open(&dir.join("psp-db")).unwrap());
    let state = Arc::new(AppState {
        logic: Mutex::new(logic),
        admin_token: String::new(),
    });
    let app = Router::new()
        .route("/melt", post(api::melt))
        .route("/check-state", post(api::check_state))
        .with_state(Arc::clone(&state));
    (serve(rt, app), state)
}

fn start_esp(rt: &Runtime, dir: &PathBuf, psp_url: &str) -> String {
    let (logic, master) = esp_mint::mint::open(&dir.join("esp")).unwrap();
    let responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
    let state = Arc::new(EspState {
        logic: Mutex::new(logic),
        master,
        psp: Box::new(HttpPsp::new(psp_url).unwrap()),
        responses: Mutex::new(responses),
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
    let signature = bdhke::unblind_message(&outcome.0, &blinding_key, &logic.public_keys()[&amount]);
    (Note { nonce, signature }, keypair)
}

struct Wanted {
    nonce: Nonce,
    blinding_key: SecretKey,
    amount: u64,
}

fn request(note: Note, keypair: &Keypair, units: u64, esp_amounts: &[u64]) -> (ExchangeRequest, Vec<Wanted>) {
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
    let (psp_url, psp) = start_psp(&rt, &dir);
    let esp = start_esp(&rt, &dir, &psp_url);

    let (note, keypair) = psp_note(&psp, 4);
    let (req, wanted) = request(note, &keypair, 4, &[3 * ONE_PSP, ONE_PSP]);
    let (code, body) = post_json(&esp, "/exchange", &req);
    assert_eq!(code, 200, "{body}");
    let response: ExchangeResponse = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(response.credit_esp, 0);

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
        assert!(bdhke::verify_message(&sk, unblinded, &w.nonce.as_hash_preimage()));
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
    rt.shutdown_background();
}

#[test]
fn an_underpaid_request_is_a_400_and_the_psp_note_survives() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("under");
    let (psp_url, psp) = start_psp(&rt, &dir);
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
    let (_psp_url, psp) = start_psp(&rt, &dir);
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
    let (psp_url, _psp) = start_psp(&rt, &dir);
    let esp = start_esp(&rt, &dir, &psp_url);
    for path in ["/admin/issue", "/swap", "/redeem"] {
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
