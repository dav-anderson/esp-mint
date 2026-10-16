//! Redemption over HTTP, end to end: an ESP server with its own mint, the
//! operator's admin listener, and a service that signs and sends the canonical
//! binary encoding the way the wallet does.
//!
//! A redemption never calls the PSP, so the PSP stand-in refuses every call.
//! These are plain tests with their own runtime, because they use the blocking
//! HTTP client.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::Router;
use esp_mint::admin::{self, AdminState};
use esp_mint::exchange::{Burn, Psp};
use esp_mint::payouts;
use esp_mint::queue::Queue;
use esp_mint::redeem::{self, RedeemInput, RedeemOutput, RedeemRequest};
use esp_mint::responses::Responses;
use esp_mint::server::{self, EspState};
use esp_mint::terms::Terms;
use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note};
use rand::rngs::OsRng;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, SECP256K1, SecretKey, XOnlyPublicKey};
use serde_json::Value;
use tokio::runtime::Runtime;

const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ONE: u64 = 1_000_000_000_000;
/// A day long past, so that every note below is mature on the mint's clock.
const PAST: u64 = 100;
const PAST2: u64 = 200;
const RATE: u128 = 1_000_000;
const MEMO: &str = "btc:bc1qpayhere";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("esp-mint-rdhttp-{}-{name}", {
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

/// The key behind `G_X`: secret key 1.
fn service_keypair() -> Keypair {
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&bytes).unwrap())
}

fn other_keypair() -> Keypair {
    let mut bytes = [0u8; 32];
    bytes[31] = 2;
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&bytes).unwrap())
}

struct NoPsp;

impl Psp for NoPsp {
    fn melt(&self, _inputs: &[MintInput], _memo: &str) -> Result<Amount, String> {
        Err("a redemption does not use the PSP".into())
    }

    fn burns(&self, _nonces: &[Nonce]) -> Result<Vec<Burn>, String> {
        Err("a redemption does not use the PSP".into())
    }
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

struct Mint {
    esp: String,
    admin: String,
    state: Arc<EspState>,
    queue_path: PathBuf,
}

thread_local! {
    /// The keysets the test's requests name: (inputs, outputs). Set when the
    /// mint starts, and by a test across a rotation.
    static KS: std::cell::RefCell<(String, String)> = Default::default();
}

fn set_keysets(inputs: &str, outputs: &str) {
    KS.with(|k| *k.borrow_mut() = (inputs.to_string(), outputs.to_string()));
}

fn in_ks() -> String {
    KS.with(|k| k.borrow().0.clone())
}

fn out_ks() -> String {
    KS.with(|k| k.borrow().1.clone())
}

fn start(rt: &Runtime, dir: &PathBuf, max_bytes: usize) -> Mint {
    let (logic, master) = esp_mint::mint::open(&dir.join("esp")).unwrap();
    let id = esp_mint::rotation::keyset_id(&master);
    set_keysets(&id, &id);
    let responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
    let queue_path = dir.join("esp").join("queue.json");
    let state = Arc::new(EspState {
        logic: Mutex::new(logic),
        master,
        psp: Box::new(NoPsp),
        responses: Mutex::new(responses),
        queue_path: queue_path.clone(),
        queue_lock: Mutex::new(()),
        config: esp_mint::config::Handle::new({
            let mut config = esp_mint::config::Config::default();
            config.redeem_fee_per_byte = RATE as u64;
            config.redeem_max_request_bytes = max_bytes;
            config
        }),
        rotor: None,
        rollovers: None,
    });
    let esp = serve(rt, server::router(Arc::clone(&state)));
    let admin_state = Arc::new(AdminState {
        queue_path: queue_path.clone(),
        lock: Mutex::new(()),
        token: None,
        esp: Some(Arc::clone(&state)),
    });
    let admin = serve(rt, admin::router(admin_state));
    Mint {
        esp,
        admin,
        state,
        queue_path,
    }
}

/// A note the mint has issued under these terms, and the key that spends it.
fn esp_note(mint: &Mint, units: u64, service: XOnlyPublicKey, day: u64) -> (Note, Keypair) {
    let terms = Terms {
        service,
        redeemable_after_day: day,
    };
    let keypair = Keypair::new(SECP256K1, &mut OsRng);
    let nonce = Nonce(keypair.public_key());
    let (blind_point, blinding_key) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
    let amount = Amount::from_units(units);
    let sk = mint.state.master.key_for(amount, &terms);
    let logic = mint.state.logic.lock().unwrap();
    let outcome = logic
        .issue_with_key(
            &sk,
            &MintOutput {
                amount,
                blind_nonce: BlindNonce(blind_point),
            },
        )
        .unwrap();
    let signature = bdhke::unblind_message(&outcome.0, &blinding_key, &sk.public_key(SECP256K1));
    (Note { nonce, signature }, keypair)
}

fn is_spent(mint: &Mint, note: &Note) -> bool {
    mint.state
        .logic
        .lock()
        .unwrap()
        .is_spent(note.nonce)
        .unwrap()
}

struct Wanted {
    nonce: Nonce,
    blinding_key: SecretKey,
    amount: u64,
    day: u64,
}

/// A redemption for the service `G_X`: (note, key, units, day) in, decline
/// outputs (units, day) out, signed by `service_signer`.
fn request(
    notes: &[(Note, &Keypair, u64, u64)],
    decline: &[(u64, u64)],
    service_signer: &Keypair,
) -> (RedeemRequest, Vec<Wanted>) {
    let mut wanted = Vec::new();
    let mut decline_outputs = Vec::new();
    for &(amount, day) in decline {
        let keypair = Keypair::new(SECP256K1, &mut OsRng);
        let nonce = Nonce(keypair.public_key());
        let (blind_point, blinding_key) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        decline_outputs.push(RedeemOutput {
            service: service(),
            redeemable_after_day: day,
            output: MintOutput {
                amount: Amount::from_units(amount),
                blind_nonce: BlindNonce(blind_point),
            },
        });
        wanted.push(Wanted {
            nonce,
            blinding_key,
            amount,
            day,
        });
    }
    let mut inputs: Vec<RedeemInput> = notes
        .iter()
        .map(|(note, _, units, day)| RedeemInput {
            service: service(),
            redeemable_after_day: *day,
            keyset: in_ks(),
            input: MintInput {
                amount: Amount::from_units(*units),
                note: *note,
                spend_signature: Signature::from_slice(&[0u8; 64]).unwrap(),
            },
        })
        .collect();
    let sighash = redeem::digest(&service(), &out_ks(), &inputs, MEMO, &decline_outputs, &[]);
    for (input, (_, keypair, _, _)) in inputs.iter_mut().zip(notes) {
        input.input.spend_signature = SECP256K1.sign_schnorr(&sighash, keypair);
    }
    let service_signature = SECP256K1.sign_schnorr(&sighash, service_signer);
    (
        RedeemRequest {
            service: service(),
            output_keyset: out_ks(),
            inputs,
            memo: MEMO.to_string(),
            decline_outputs,
            refund_outputs: vec![],
            service_signature,
        },
        wanted,
    )
}

fn post_bytes(base: &str, bytes: Vec<u8>) -> (u16, Value) {
    let response = reqwest::blocking::Client::new()
        .post(format!("{base}/redeem"))
        .header("content-type", "application/octet-stream")
        .body(bytes)
        .send()
        .unwrap();
    let code = response.status().as_u16();
    (code, response.json().unwrap())
}

fn post_json(base: &str, path: &str, body: &Value) -> (u16, Value) {
    let response = reqwest::blocking::Client::new()
        .post(format!("{base}{path}"))
        .json(body)
        .send()
        .unwrap();
    let code = response.status().as_u16();
    (code, response.json().unwrap_or(Value::Null))
}

fn nothing_stored(mint: &Mint) -> bool {
    mint.state.responses.lock().unwrap().is_empty() && !mint.queue_path.exists()
}

#[test]
fn a_request_over_the_ceiling_is_refused_before_it_is_parsed() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("ceiling");
    let mint = start(&rt, &dir, 1000);

    // garbage one byte over the limit: refused for its size, not for its content
    let (code, body) = post_bytes(&mint.esp, vec![0xff; 1001]);
    assert_eq!(code, 413, "{body}");
    assert_eq!(body["code"], "request_too_large");
    assert_eq!(body["limit_bytes"], 1000);

    // garbage at the limit is read, and fails to parse
    let (code, body) = post_bytes(&mint.esp, vec![0xff; 1000]);
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "malformed_request");

    // a request that is perfectly good but too big is refused without a burn or a fee
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(esp_note(&mint, 3 * ONE, service(), PAST));
    }
    let notes: Vec<(Note, &Keypair, u64, u64)> = held
        .iter()
        .map(|(note, key)| (*note, key, 3 * ONE, PAST))
        .collect();
    let (req, _) = request(&notes, &[], &service_keypair());
    let bytes = req.encode();
    assert!(bytes.len() > 1000);
    let (code, body) = post_bytes(&mint.esp, bytes.clone());
    assert_eq!(code, 413, "{body}");
    assert_eq!(body["code"], "request_too_large");
    assert!(held.iter().all(|(note, _)| !is_spent(&mint, note)));
    assert!(nothing_stored(&mint));
    drop(held);
    rt.shutdown_background();
}

#[test]
fn a_request_that_is_not_the_canonical_encoding_is_a_400() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("malformed");
    let mint = start(&rt, &dir, 64 * 1024 * 1024);
    let (note, key) = esp_note(&mint, 3 * ONE, service(), PAST);
    let (req, _) = request(&[(note, &key, 3 * ONE, PAST)], &[], &service_keypair());
    let mut bytes = req.encode();
    bytes.push(0);
    let (code, body) = post_bytes(&mint.esp, bytes);
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "malformed_request");
    // JSON is not the format
    let (code, body) = post_json(&mint.esp, "/redeem", &serde_json::json!({}));
    assert_eq!(code, 400, "{body}");
    assert!(!is_spent(&mint, &note));
    assert!(nothing_stored(&mint));
    rt.shutdown_background();
}

#[test]
fn a_bad_service_signature_is_a_400_with_no_burn_and_no_fee() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("badsig");
    let mint = start(&rt, &dir, 64 * 1024 * 1024);
    let (note, key) = esp_note(&mint, 3 * ONE, service(), PAST);
    let (req, _) = request(&[(note, &key, 3 * ONE, PAST)], &[], &other_keypair());
    let (code, body) = post_bytes(&mint.esp, req.encode());
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "bad_service_signature");
    assert!(!is_spent(&mint, &note));
    assert!(nothing_stored(&mint));
    rt.shutdown_background();
}

#[test]
fn a_redemption_is_queued_then_declined_and_the_service_collects_the_reissued_notes() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("flow");
    let mint = start(&rt, &dir, 64 * 1024 * 1024);
    let (a, ka) = esp_note(&mint, 3 * ONE, service(), PAST);
    let (b, kb) = esp_note(&mint, 2 * ONE, service(), PAST2);
    let (req, wanted) = request(
        &[(a, &ka, 3 * ONE, PAST), (b, &kb, 2 * ONE, PAST2)],
        &[(2 * ONE, PAST), (2 * ONE, PAST2)],
        &service_keypair(),
    );
    let bytes = req.encode();
    let fee = u128::from(bytes.len() as u64) * RATE;
    let id = redeem::request_hash(&req);

    let (code, body) = post_bytes(&mint.esp, bytes.clone());
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["accepted_esp"], (5 * ONE).to_string());
    assert_eq!(body["fee_esp"], fee.to_string());
    assert_eq!(body["size_bytes"], bytes.len());
    assert_eq!(body["owed_esp"], (u128::from(5 * ONE) - fee).to_string());
    assert_eq!(body["message"], "payout queued");
    assert_eq!(body["entry"]["status"], "open");
    assert_eq!(body["notes"][0]["accepted"], true);
    assert!(is_spent(&mint, &a) && is_spent(&mint, &b));
    let queue = Queue::open(&mint.queue_path).unwrap();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.get(&id).unwrap().memo, MEMO);

    // the same request again: the same answer, and nothing more is burned or queued
    let (code, again) = post_bytes(&mint.esp, bytes.clone());
    assert_eq!(code, 200);
    assert_eq!(again, body);
    assert_eq!(Queue::open(&mint.queue_path).unwrap().len(), 1);

    // the operator declines
    let (code, declined) = post_json(
        &mint.admin,
        "/payouts/decline",
        &serde_json::json!({"entry_id": id, "reason": "uptime terms were not met"}),
    );
    assert_eq!(code, 200, "{declined}");
    assert_eq!(declined["outputs"], 2);
    assert_eq!(declined["reissued_esp"], (4 * ONE).to_string());

    // the service asks again with the same bytes and is told
    let (code, after) = post_bytes(&mint.esp, bytes);
    assert_eq!(code, 200, "{after}");
    assert_eq!(after["entry"]["status"], "declined");
    assert_eq!(
        after["entry"]["decline_reason"],
        "uptime terms were not met"
    );
    let sigs = after["entry"]["decline_signatures"].as_array().unwrap();
    assert_eq!(sigs.len(), 2);

    // and the reissued notes verify, each under its own day
    for (w, sig) in wanted.iter().zip(sigs) {
        let terms = Terms {
            service: service(),
            redeemable_after_day: w.day,
        };
        let sk = mint
            .state
            .master
            .key_for(Amount::from_units(w.amount), &terms);
        let signature: secp256k1::PublicKey =
            serde_json::from_value(sig["signature"].clone()).unwrap();
        let key: secp256k1::PublicKey = serde_json::from_value(sig["key"].clone()).unwrap();
        assert_eq!(key, sk.public_key(SECP256K1));
        let unblinded = bdhke::unblind_message(&signature, &w.blinding_key, &key);
        assert!(bdhke::verify_message(
            &sk,
            unblinded,
            &w.nonce.as_hash_preimage()
        ));
    }

    // it cannot be declined twice
    let (code, again) = post_json(
        &mint.admin,
        "/payouts/decline",
        &serde_json::json!({"entry_id": id, "reason": "again"}),
    );
    assert_eq!(code, 400, "{again}");
    // and a decline needs an entry that exists, a reason, and nothing else
    let (code, _) = post_json(
        &mint.admin,
        "/payouts/decline",
        &serde_json::json!({"entry_id": "nope", "reason": "why"}),
    );
    assert_eq!(code, 400);
    let (code, _) = post_json(
        &mint.admin,
        "/payouts/decline",
        &serde_json::json!({"entry_id": id, "reason": "why", "extra": 1}),
    );
    assert_eq!(code, 422);
    rt.shutdown_background();
}

#[test]
fn a_redemption_split_across_two_requests_makes_two_queue_entries() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("split");
    let mint = start(&rt, &dir, 64 * 1024 * 1024);
    let (a, ka) = esp_note(&mint, 3 * ONE, service(), PAST);
    let (b, kb) = esp_note(&mint, 2 * ONE, service(), PAST);
    let (c, kc) = esp_note(&mint, 4 * ONE, service(), PAST2);
    let (first, _) = request(
        &[(a, &ka, 3 * ONE, PAST), (b, &kb, 2 * ONE, PAST)],
        &[],
        &service_keypair(),
    );
    let (second, _) = request(&[(c, &kc, 4 * ONE, PAST2)], &[], &service_keypair());
    let (code, one) = post_bytes(&mint.esp, first.encode());
    assert_eq!(code, 200, "{one}");
    let (code, two) = post_bytes(&mint.esp, second.encode());
    assert_eq!(code, 200, "{two}");

    // each request paid its own fee, by its own size
    assert_eq!(one["size_bytes"], first.encode().len());
    assert_eq!(two["size_bytes"], second.encode().len());
    assert_ne!(one["fee_esp"], two["fee_esp"]);

    let queue = Queue::open(&mint.queue_path).unwrap();
    assert_eq!(queue.len(), 2);
    assert!(queue.get(&redeem::request_hash(&first)).is_some());
    assert!(queue.get(&redeem::request_hash(&second)).is_some());
    // the payout report adds them up for the service
    let groups = payouts::report(&queue).unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].entries, 2);
    let owed = |v: &Value| v["owed_esp"].as_str().unwrap().parse::<u128>().unwrap();
    assert_eq!(groups[0].owed_esp, owed(&one) + owed(&two));
    rt.shutdown_background();
}

#[test]
fn when_the_accepted_notes_only_cover_the_fee_nothing_is_owed_and_a_retry_says_so() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("nothing-owed");
    let mint = start(&rt, &dir, 64 * 1024 * 1024);
    // the fee for one note and no outputs: 320 bytes
    let fee = redeem::fee_for(redeem::encoded_len(1, MEMO.len(), 0, 0), RATE);
    assert_eq!(fee, 320_000_000);
    let (note, key) = esp_note(&mint, fee as u64, service(), PAST);
    let (req, _) = request(&[(note, &key, fee as u64, PAST)], &[], &service_keypair());
    let (code, body) = post_bytes(&mint.esp, req.encode());
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["owed_esp"], "0");
    assert_eq!(body["fee_esp"], fee.to_string());
    assert_eq!(body["message"], "nothing owed, fee taken");
    assert!(body["entry"].is_null());
    assert!(is_spent(&mint, &note));
    // no queue entry
    assert!(Queue::open(&mint.queue_path).unwrap().is_empty());
    // a retry returns the stored answer
    let (code, again) = post_bytes(&mint.esp, req.encode());
    assert_eq!(code, 200);
    assert_eq!(again, body);
    rt.shutdown_background();
}

#[test]
fn a_request_below_the_fee_is_refused_with_the_fee_in_the_body() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("below-fee");
    let mint = start(&rt, &dir, 64 * 1024 * 1024);
    let (note, key) = esp_note(&mint, 1000, service(), PAST);
    let (req, _) = request(&[(note, &key, 1000, PAST)], &[], &service_keypair());
    let (code, body) = post_bytes(&mint.esp, req.encode());
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "below_fee");
    assert_eq!(body["value_esp"], "1000");
    assert_eq!(body["fee_esp"], "320000000");
    // the per-note reasons are in the body, and nothing was burned
    assert_eq!(body["notes"].as_array().unwrap().len(), 1);
    assert_eq!(body["notes"][0]["reason"], serde_json::Value::Null);
    assert_eq!(body["notes"][0]["burned"], false);
    assert!(!is_spent(&mint, &note));
    assert!(nothing_stored(&mint));
    rt.shutdown_background();
}

#[test]
fn decline_outputs_over_the_limit_come_back_with_the_totals_to_rebuild_from() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("over-limit");
    let mint = start(&rt, &dir, 64 * 1024 * 1024);
    let (a, ka) = esp_note(&mint, 3 * ONE, service(), PAST);
    // asks for all of it back, but the fee comes off
    let (req, _) = request(
        &[(a, &ka, 3 * ONE, PAST)],
        &[(3 * ONE, PAST)],
        &service_keypair(),
    );
    let (code, body) = post_bytes(&mint.esp, req.encode());
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "outputs_over_limit");
    assert_eq!(body["list"], "decline_outputs");
    assert_eq!(body["totals"]["accepted_esp"], (3 * ONE).to_string());
    assert_eq!(
        body["totals"]["accepted_by_terms"][0]["redeemable_after_day"],
        PAST
    );
    assert_eq!(
        body["totals"]["accepted_by_terms"][0]["esp"],
        (3 * ONE).to_string()
    );
    assert!(!is_spent(&mint, &a));
    assert!(nothing_stored(&mint));
    rt.shutdown_background();
}

// ---- key rotation -----------------------------------------------------------

const T0: u64 = 1_800_000_000;

fn start_rotating(rt: &Runtime, dir: &PathBuf) -> Mint {
    let data = dir.join("esp");
    let (rotor, logic) = esp_mint::rotation::Rotor::open_at(&data, 1, 1, T0).unwrap();
    let master = rotor.current.master.clone();
    set_keysets(&rotor.current.id, &rotor.current.id);
    let queue_path = data.join("queue.json");
    let state = Arc::new(EspState {
        logic: Mutex::new(logic),
        master,
        psp: Box::new(NoPsp),
        responses: Mutex::new(Responses::open(&data.join("responses.json")).unwrap()),
        queue_path: queue_path.clone(),
        queue_lock: Mutex::new(()),
        config: esp_mint::config::Handle::new({
            let mut c = esp_mint::config::Config::default();
            c.redeem_fee_per_byte = RATE as u64;
            c
        }),
        rollovers: Some(Mutex::new(
            esp_mint::rotation::Rollovers::open(&data).unwrap(),
        )),
        rotor: Some(Mutex::new(rotor)),
    });
    let esp = serve(rt, server::router(Arc::clone(&state)));
    let admin = serve(
        rt,
        admin::router(Arc::new(AdminState {
            queue_path: queue_path.clone(),
            lock: Mutex::new(()),
            token: None,
            esp: Some(Arc::clone(&state)),
        })),
    );
    Mint {
        esp,
        admin,
        state,
        queue_path,
    }
}

fn set_clock(mint: &Mint, t: u64) {
    let r = mint.state.rotor.as_ref().unwrap().lock().unwrap();
    r.clock.store(t, std::sync::atomic::Ordering::SeqCst);
}

fn get_json(base: &str, path: &str) -> Value {
    reqwest::blocking::get(format!("{base}{path}"))
        .unwrap()
        .json()
        .unwrap()
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

fn rollover_req(
    note: &(Note, Keypair),
    units: u64,
    out_units: u64,
) -> esp_mint::rotation::RolloverRequest {
    let (o, _, _) = blinded(out_units);
    let mut r = esp_mint::rotation::RolloverRequest {
        service: service(),
        redeemable_after_day: PAST,
        input_keysets: vec![in_ks()],
        keyset: out_ks(),
        inputs: vec![MintInput {
            amount: Amount::from_units(units),
            note: note.0,
            spend_signature: Signature::from_slice(&[0u8; 64]).unwrap(),
        }],
        outputs: vec![o],
    };
    let d = r.digest();
    r.inputs[0].spend_signature = SECP256K1.sign_schnorr(&d, &note.1);
    r
}

fn current_key(mint: &Mint, units: u64) -> secp256k1::PublicKey {
    let r = mint.state.rotor.as_ref().unwrap().lock().unwrap();
    r.current
        .master
        .key_for(
            Amount::from_units(units),
            &Terms {
                service: service(),
                redeemable_after_day: PAST,
            },
        )
        .public_key(SECP256K1)
}

#[test]
fn rotation_keeps_previous_esp_for_one_period_then_it_is_lost() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("rotation");
    // Generation 0 is the mint as it was.
    let (_, master0) = esp_mint::mint::open(&dir.join("esp")).unwrap();
    let mint = start_rotating(&rt, &dir);
    assert_eq!(
        mint.state.master, master0,
        "generation 0 = the existing master secret"
    );
    let w = get_json(&mint.esp, "/rotation");
    assert_eq!(
        (w["first_issue"].clone(), w["current"]["epoch"].clone()),
        (Value::Null, 0.into())
    );

    let a = esp_note(&mint, 2 * ONE, service(), PAST);
    let b = esp_note(&mint, ONE, service(), PAST);
    let c = esp_note(&mint, ONE, service(), PAST);
    let d = esp_note(&mint, ONE, service(), PAST);
    let w = get_json(&mint.esp, "/rotation");
    assert_eq!(w["first_issue"], T0, "the first issue starts the clock");
    assert_eq!(w["activation"], T0 + 3600);

    set_clock(&mint, T0 + 3600);
    let w = get_json(&mint.esp, "/rotation");
    assert_eq!(
        (
            w["active"].clone(),
            w["current"]["epoch"].clone(),
            w["previous"]["epoch"].clone()
        ),
        (true.into(), 1.into(), 0.into())
    );
    assert_eq!(w["previous"]["retires"], T0 + 2 * 3600);
    let id0 = esp_mint::rotation::keyset_id(&master0);
    let id1 = w["current"]["id"].as_str().unwrap().to_string();
    // Notes of generation 0 (now previous); new outputs on the current set.
    set_keysets(&id0, &id1);

    // Redemption accepts a previous-set note; the decline is signed with the
    // current set.
    let (req, _) = request(
        &[(a.0, &a.1, 2 * ONE, PAST)],
        &[(ONE, PAST)],
        &service_keypair(),
    );
    let (code, body) = post_bytes(&mint.esp, req.encode());
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["notes"][0]["accepted"], true);
    let id = redeem::request_hash(&req);
    let (code, declined) = post_json(
        &mint.admin,
        "/payouts/decline",
        &serde_json::json!({"entry_id": id, "reason": "terms"}),
    );
    assert_eq!(code, 200, "{declined}");

    // Transfer accepts a previous-set note and signs with the current set.
    let (o, _, _) = blinded(ONE);
    let inputs = vec![MintInput {
        amount: Amount::from_units(ONE),
        note: b.0,
        spend_signature: Signature::from_slice(&[0u8; 64]).unwrap(),
    }];
    let outputs = vec![o];
    let dg = esp_mint::transfer::digest(&service(), PAST, &inputs, &outputs);
    let mut inputs = inputs;
    inputs[0].spend_signature = SECP256K1.sign_schnorr(&dg, &b.1);
    let tr = esp_mint::transfer::TransferRequest {
        service: service(),
        redeemable_after_day: PAST,
        input_keysets: vec![in_ks()],
        inputs,
        keyset: out_ks(),
        outputs,
        service_signature: SECP256K1.sign_schnorr(&dg, &service_keypair()),
    };
    let (code, body) = post_json(&mint.esp, "/transfer", &serde_json::to_value(&tr).unwrap());
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["keyset"], id1.as_str());
    let key: secp256k1::PublicKey = serde_json::from_value(body["keys"][0].clone()).unwrap();
    assert_eq!(key, current_key(&mint, ONE));

    // Rollover by the holder: same amount and terms, current set; a retry gets
    // the stored answer; a split is refused.
    let rq = rollover_req(&c, ONE, ONE);
    let (code, body) = post_json(&mint.esp, "/rollover", &serde_json::to_value(&rq).unwrap());
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["epoch"], 1);
    assert_eq!(body["keyset"], id1.as_str(), "the answer names its signer");
    assert_eq!(
        (
            body["service"].clone(),
            body["redeemable_after_day"].clone()
        ),
        (serde_json::to_value(service()).unwrap(), PAST.into())
    );
    let key: secp256k1::PublicKey = serde_json::from_value(body["keys"][0].clone()).unwrap();
    assert_eq!(key, current_key(&mint, ONE));
    assert_eq!(
        post_json(&mint.esp, "/rollover", &serde_json::to_value(&rq).unwrap()),
        (200, body)
    );
    assert_eq!(
        post_json(
            &mint.esp,
            "/rollover",
            &serde_json::to_value(rollover_req(&d, ONE, ONE / 2)).unwrap()
        )
        .0,
        400
    );

    // The next rotation deletes generation 0 with its spent list: `d` is lost.
    set_clock(&mint, T0 + 2 * 3600);
    let w = get_json(&mint.esp, "/rotation");
    assert_eq!(
        (
            w["current"]["epoch"].clone(),
            w["previous"]["epoch"].clone()
        ),
        (2.into(), 1.into())
    );
    assert!(
        !dir.join("esp").join("master_secret.hex").exists() && !dir.join("esp").join("db").exists()
    );
    let (code, body) = post_json(
        &mint.esp,
        "/rollover",
        &serde_json::to_value(rollover_req(&d, ONE, ONE)).unwrap(),
    );
    assert_eq!(
        (code, body["code"].as_str()),
        (400, Some("keyset_retired")),
        "{body}"
    );
    // A transfer and a redemption naming the retired set are refused the
    // same way, and nothing is burned.
    set_keysets(&id0, &w["current"]["id"].as_str().unwrap().to_string());
    let (late, _) = request(&[(d.0, &d.1, ONE, PAST)], &[], &service_keypair());
    let (code, body) = post_bytes(&mint.esp, late.encode());
    assert_eq!(
        code, 400,
        "below the fee once the expired note is out: {body}"
    );
    // An unknown keyset is told apart from a retired one.
    set_keysets(
        &"ab".repeat(8),
        &w["current"]["id"].as_str().unwrap().to_string(),
    );
    let (code, body) = post_json(
        &mint.esp,
        "/rollover",
        &serde_json::to_value(rollover_req(&d, ONE, ONE)).unwrap(),
    );
    assert_eq!(
        (code, body["code"].as_str()),
        (400, Some("unknown_keyset")),
        "{body}"
    );
    // The audit counts the deleted generation too.
    let audit = get_json(&mint.esp, "/audit");
    assert!(audit["issued"].as_u64().unwrap() >= 5 * ONE, "{audit}");
}

#[test]
fn an_esp_rollover_interrupted_after_the_burn_is_finished_by_the_retry() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("rot-crash");
    let mint = start_rotating(&rt, &dir);
    let n = esp_note(&mint, ONE, service(), PAST);
    let _ = get_json(&mint.esp, "/rotation");
    set_clock(&mint, T0 + 3600);
    let w = get_json(&mint.esp, "/rotation");
    set_keysets(
        w["previous"]["id"].as_str().unwrap(),
        w["current"]["id"].as_str().unwrap(),
    );
    let rq = rollover_req(&n, ONE, ONE);
    // The crash: pending written and the note burned, no answer stored.
    {
        let data = dir.join("esp");
        std::fs::write(
            data.join(esp_mint::rotation::ROLLOVERS_FILE),
            serde_json::json!({"answers": {}, "pending": {rq.hash(): 1}}).to_string(),
        )
        .unwrap();
        let rotor = mint.state.rotor.as_ref().unwrap().lock().unwrap();
        let (g, l) = rotor.previous.as_ref().unwrap();
        let sk = g.master.key_for(
            Amount::from_units(ONE),
            &Terms {
                service: service(),
                redeemable_after_day: PAST,
            },
        );
        l.redeem_with_key(&sk, &rq.inputs[0], rq.digest()).unwrap();
        *mint.state.rollovers.as_ref().unwrap().lock().unwrap() =
            esp_mint::rotation::Rollovers::open(&data).unwrap();
    }
    let (code, body) = post_json(&mint.esp, "/rollover", &serde_json::to_value(&rq).unwrap());
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        post_json(&mint.esp, "/rollover", &serde_json::to_value(&rq).unwrap()),
        (200, body)
    );
}

#[test]
fn a_decline_after_the_requested_keyset_retires_is_signed_by_the_current_set_and_says_so() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("queue-rule");
    let mint = start_rotating(&rt, &dir);
    let id0 = get_json(&mint.esp, "/rotation")["current"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let a = esp_note(&mint, 2 * ONE, service(), PAST);
    // Queued with its outputs asking for generation 0.
    let (req, wanted) = request(
        &[(a.0, &a.1, 2 * ONE, PAST)],
        &[(ONE, PAST)],
        &service_keypair(),
    );
    let bytes = req.encode();
    let (code, body) = post_bytes(&mint.esp, bytes.clone());
    assert_eq!(code, 200, "{body}");
    let id = redeem::request_hash(&req);

    // Two rotations: generation 0 is deleted and listed as retired.
    set_clock(&mint, T0 + 3600);
    let _ = get_json(&mint.esp, "/rotation");
    set_clock(&mint, T0 + 2 * 3600);
    let w = get_json(&mint.esp, "/rotation");
    let current = w["current"]["id"].as_str().unwrap().to_string();
    assert_ne!(current, id0);
    let ks = get_json(&mint.esp, "/keysets");
    assert_eq!(ks["current"], current.as_str());
    assert_ne!(ks["previous"], id0.as_str());

    let (code, declined) = post_json(
        &mint.admin,
        "/payouts/decline",
        &serde_json::json!({"entry_id": id, "reason": "terms"}),
    );
    assert_eq!(code, 200, "{declined}");
    let (code, after) = post_bytes(&mint.esp, bytes);
    assert_eq!(code, 200, "{after}");
    let sigs = after["entry"]["decline_signatures"].as_array().unwrap();
    assert_eq!(sigs.len(), wanted.len());
    for sig in sigs {
        assert_eq!(sig["keyset"], current.as_str(), "the set that signed it");
        let key: secp256k1::PublicKey = serde_json::from_value(sig["key"].clone()).unwrap();
        assert_eq!(key, current_key(&mint, ONE));
    }
}

fn transfer_req(note: &(Note, Keypair), units: u64) -> esp_mint::transfer::TransferRequest {
    let (o, _, _) = blinded(units);
    let mut inputs = vec![MintInput {
        amount: Amount::from_units(units),
        note: note.0,
        spend_signature: Signature::from_slice(&[0u8; 64]).unwrap(),
    }];
    let outputs = vec![o];
    let dg = esp_mint::transfer::digest(&service(), PAST, &inputs, &outputs);
    inputs[0].spend_signature = SECP256K1.sign_schnorr(&dg, &note.1);
    esp_mint::transfer::TransferRequest {
        service: service(),
        redeemable_after_day: PAST,
        input_keysets: vec![in_ks()],
        inputs,
        keyset: out_ks(),
        outputs,
        service_signature: SECP256K1.sign_schnorr(&dg, &service_keypair()),
    }
}

/// After one rotation: (generation 0's id, the current id).
fn rotate_once(mint: &Mint) -> (String, String) {
    let _ = get_json(&mint.esp, "/rotation");
    set_clock(mint, T0 + 3600);
    let w = get_json(&mint.esp, "/rotation");
    (
        w["previous"]["id"].as_str().unwrap().to_string(),
        w["current"]["id"].as_str().unwrap().to_string(),
    )
}

#[test]
fn new_outputs_naming_the_previous_set_are_refused_keyset_not_current_and_nothing_is_burned() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("not-current");
    let mint = start_rotating(&rt, &dir);
    let a = esp_note(&mint, ONE, service(), PAST);
    let b = esp_note(&mint, 2 * ONE, service(), PAST);
    let (id0, id1) = rotate_once(&mint);
    // Previous-set notes in, outputs asked of the previous set: refused.
    set_keysets(&id0, &id0);
    for (route, body) in [
        (
            "/transfer",
            serde_json::to_value(transfer_req(&a, ONE)).unwrap(),
        ),
        (
            "/rollover",
            serde_json::to_value(rollover_req(&a, ONE, ONE)).unwrap(),
        ),
    ] {
        let (code, body) = post_json(&mint.esp, route, &body);
        assert_eq!(
            (code, body["code"].as_str()),
            (400, Some("keyset_not_current")),
            "{route}: {body}"
        );
        assert!(
            body["error"].as_str().unwrap().contains(&id1),
            "names the current set: {body}"
        );
    }
    let (req, _) = request(
        &[(b.0, &b.1, 2 * ONE, PAST)],
        &[(ONE, PAST)],
        &service_keypair(),
    );
    let (code, body) = post_bytes(&mint.esp, req.encode());
    assert_eq!(
        (code, body["code"].as_str()),
        (400, Some("keyset_not_current")),
        "{body}"
    );
    {
        let rotor = mint.state.rotor.as_ref().unwrap().lock().unwrap();
        let (_, prev) = rotor.previous.as_ref().unwrap();
        assert!(
            !prev.is_spent(a.0.nonce).unwrap() && !prev.is_spent(b.0.nonce).unwrap(),
            "nothing burned"
        );
    }
    // Re-blinded for the current set, the same notes go through.
    set_keysets(&id0, &id1);
    let (code, body) = post_json(
        &mint.esp,
        "/transfer",
        &serde_json::to_value(transfer_req(&a, ONE)).unwrap(),
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["keyset"], id1.as_str());
}

/// A rollover of a generation-0 note, accepted and burned before the
/// rotations (its answer lost), then retried after generation 0 is deleted.
/// A rollover left pending across a retirement. `burn`: its input was burned
/// before the crash; `flag`: the burn was also recorded under its hash.
fn rollover_after_retirement(name: &str, burn: bool, flag: bool) -> (u16, Value, String) {
    let rt = Runtime::new().unwrap();
    let dir = scratch(name);
    let mint = start_rotating(&rt, &dir);
    let n = esp_note(&mint, ONE, service(), PAST);
    let (id0, id1) = rotate_once(&mint);
    set_keysets(&id0, &id1);
    let rq = rollover_req(&n, ONE, ONE);
    let data = dir.join("esp");
    {
        let burned: Vec<String> = if flag { vec![rq.hash()] } else { vec![] };
        let nonce = hex::encode(n.0.nonce.0.serialize());
        std::fs::write(
            data.join(esp_mint::rotation::ROLLOVERS_FILE),
            serde_json::json!({"answers": {}, "pending": {rq.hash(): 1}, "burned": burned,
                "holds": {rq.hash(): [nonce]}})
            .to_string(),
        )
        .unwrap();
        let rotor = mint.state.rotor.as_ref().unwrap().lock().unwrap();
        let (g, l) = rotor.previous.as_ref().unwrap();
        let sk = g.master.key_for(
            Amount::from_units(ONE),
            &Terms {
                service: service(),
                redeemable_after_day: PAST,
            },
        );
        if burn {
            l.redeem_with_key(&sk, &rq.inputs[0], rq.digest()).unwrap();
        }
        *mint.state.rollovers.as_ref().unwrap().lock().unwrap() =
            esp_mint::rotation::Rollovers::open(&data).unwrap();
    }
    set_clock(&mint, T0 + 2 * 3600);
    let w = get_json(&mint.esp, "/rotation");
    let current = w["current"]["id"].as_str().unwrap().to_string();
    let (code, body) = post_json(&mint.esp, "/rollover", &serde_json::to_value(&rq).unwrap());
    rt.shutdown_background();
    (code, body, current)
}

#[test]
fn a_resumed_rollover_after_retirement_finishes_only_with_stored_proof_of_its_burn() {
    let (code, body, current) = rollover_after_retirement("proof-yes", true, true);
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        body["keyset"],
        current.as_str(),
        "signed by the current set"
    );
    // Crash injected after the burn, before the flag was written: the proof
    // taken from the spent list at the retirement finishes it.
    let (code, body, current) = rollover_after_retirement("proof-crash", true, false);
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["keyset"], current.as_str());
    // Crash before the burn: nothing proves it, refused.
    let (code, body, _) = rollover_after_retirement("proof-no", false, false);
    assert_eq!(
        (code, body["code"].as_str()),
        (400, Some("burn_not_proven")),
        "{body}"
    );
}

#[test]
fn a_resumed_transfer_after_retirement_finishes_only_with_stored_proof_of_its_burn() {
    // (burned before the crash, flag written, finishes)
    for (burn, flag, ok) in [
        (true, true, true),
        (true, false, true),
        (false, false, false),
    ] {
        let rt = Runtime::new().unwrap();
        let dir = scratch(&format!("tproof-{burn}-{flag}"));
        let mint = start_rotating(&rt, &dir);
        let n = esp_note(&mint, ONE, service(), PAST);
        let (id0, id1) = rotate_once(&mint);
        set_keysets(&id0, &id1);
        let tr = transfer_req(&n, ONE);
        let hash = esp_mint::transfer::request_hash(&tr);
        {
            let rotor = mint.state.rotor.as_ref().unwrap().lock().unwrap();
            let (g, l) = rotor.previous.as_ref().unwrap();
            let sk = g.master.key_for(
                Amount::from_units(ONE),
                &Terms {
                    service: service(),
                    redeemable_after_day: PAST,
                },
            );
            if burn {
                l.redeem_with_key(&sk, &tr.inputs[0], tr.digest()).unwrap();
            }
            mint.state
                .responses
                .lock()
                .unwrap()
                .put(
                    &hash,
                    esp_mint::responses::Entry::TransferPending(
                        esp_mint::responses::TransferPending {
                            inputs: vec![hex::encode(n.0.nonce.0.serialize())],
                            outputs: vec![hex::encode(tr.outputs[0].blind_nonce.0.serialize())],
                            burned: flag,
                        },
                    ),
                )
                .unwrap();
        }
        set_clock(&mint, T0 + 2 * 3600);
        let current = get_json(&mint.esp, "/rotation")["current"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let (code, body) = post_json(&mint.esp, "/transfer", &serde_json::to_value(&tr).unwrap());
        if ok {
            assert_eq!(code, 200, "{body}");
            assert_eq!(body["keyset"], current.as_str());
        } else {
            assert_eq!(
                (code, body["code"].as_str()),
                (400, Some("burn_not_proven")),
                "{body}"
            );
        }
        rt.shutdown_background();
    }
}

#[test]
fn every_keyset_field_is_in_the_request_hash() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("hash-keysets");
    let mint = start_rotating(&rt, &dir);
    let n = esp_note(&mint, ONE, service(), PAST);
    // Transfer: input keyset, output keyset.
    let tr = transfer_req(&n, ONE);
    let mut a = tr.clone();
    a.input_keysets = vec!["ab".repeat(8)];
    let mut b = tr.clone();
    b.keyset = "cd".repeat(8);
    let h = esp_mint::transfer::request_hash;
    assert_ne!(h(&tr), h(&a));
    assert_ne!(h(&tr), h(&b));
    assert_ne!(h(&a), h(&b));
    // Lengths are in the hash: moving a character between fields changes it.
    let mut c = tr.clone();
    c.input_keysets = vec!["ab".into()];
    c.keyset = "cdef".into();
    let mut d = tr.clone();
    d.input_keysets = vec!["abc".into()];
    d.keyset = "def".into();
    assert_ne!(h(&c), h(&d));
    // Rollover: both fields.
    let rq = rollover_req(&n, ONE, ONE);
    let mut e = rq.clone();
    e.input_keysets = vec!["ab".repeat(8)];
    let mut f = rq.clone();
    f.keyset = "cd".repeat(8);
    assert!(rq.hash() != e.hash() && rq.hash() != f.hash() && e.hash() != f.hash());
    // Redemption: each input keyset and the output keyset.
    let (req, _) = request(&[(n.0, &n.1, ONE, PAST)], &[], &service_keypair());
    let mut g = req.clone();
    g.inputs[0].keyset = "ab".repeat(8);
    let mut k = req.clone();
    k.output_keyset = "cd".repeat(8);
    let rh = redeem::request_hash;
    assert!(rh(&req) != rh(&g) && rh(&req) != rh(&k) && rh(&g) != rh(&k));
    rt.shutdown_background();
}

#[test]
fn a_decline_whose_requested_set_is_now_previous_is_signed_by_the_current_set() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("queue-previous");
    let mint = start_rotating(&rt, &dir);
    let a = esp_note(&mint, 2 * ONE, service(), PAST);
    let (req, _) = request(
        &[(a.0, &a.1, 2 * ONE, PAST)],
        &[(ONE, PAST)],
        &service_keypair(),
    );
    let bytes = req.encode();
    assert_eq!(post_bytes(&mint.esp, bytes.clone()).0, 200);
    // One rotation: the requested set is previous, still live, but not current.
    let (_, id1) = rotate_once(&mint);
    let (code, declined) = post_json(
        &mint.admin,
        "/payouts/decline",
        &serde_json::json!({"entry_id": redeem::request_hash(&req), "reason": "terms"}),
    );
    assert_eq!(code, 200, "{declined}");
    let (_, after) = post_bytes(&mint.esp, bytes);
    for sig in after["entry"]["decline_signatures"].as_array().unwrap() {
        assert_eq!(sig["keyset"], id1.as_str());
        let key: secp256k1::PublicKey = serde_json::from_value(sig["key"].clone()).unwrap();
        assert_eq!(key, current_key(&mint, ONE));
    }
}

#[test]
fn a_note_held_by_a_pending_rollover_cannot_be_taken_by_a_transfer_or_another_rollover() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("rollover-holds");
    let mint = start_rotating(&rt, &dir);
    let n = esp_note(&mint, ONE, service(), PAST);
    let rq = rollover_req(&n, ONE, ONE);
    let data = dir.join("esp");
    // A rollover recorded (pending, holding the note), then a crash before
    // its burn.
    std::fs::write(
        data.join(esp_mint::rotation::ROLLOVERS_FILE),
        serde_json::json!({"answers": {}, "pending": {rq.hash(): 0},
            "holds": {rq.hash(): [hex::encode(n.0.nonce.0.serialize())]}})
        .to_string(),
    )
    .unwrap();
    *mint.state.rollovers.as_ref().unwrap().lock().unwrap() =
        esp_mint::rotation::Rollovers::open(&data).unwrap();
    let (code, body) = post_json(
        &mint.esp,
        "/transfer",
        &serde_json::to_value(transfer_req(&n, ONE)).unwrap(),
    );
    assert_eq!(code, 400, "{body}");
    assert!(body.to_string().contains("held"), "{body}");
    let other = rollover_req(&n, ONE, ONE);
    assert_ne!(other.hash(), rq.hash());
    let (code, body) = post_json(
        &mint.esp,
        "/rollover",
        &serde_json::to_value(&other).unwrap(),
    );
    assert_eq!(code, 400, "{body}");
    assert!(body.to_string().contains("held"), "{body}");
    assert!(!is_spent(&mint, &n.0), "nothing burned");
    // The holder finishes.
    let (code, body) = post_json(&mint.esp, "/rollover", &serde_json::to_value(&rq).unwrap());
    assert_eq!(code, 200, "{body}");
    assert!(is_spent(&mint, &n.0));
    rt.shutdown_background();
}

#[test]
fn a_rollover_with_one_spent_input_among_several_burns_none() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("rollover-partial");
    let mint = start_rotating(&rt, &dir);
    let a = esp_note(&mint, ONE, service(), PAST);
    let b = esp_note(&mint, ONE, service(), PAST);
    let c = esp_note(&mint, ONE, service(), PAST);
    // `a` is rolled over first, alone.
    let first = rollover_req(&a, ONE, ONE);
    let (code, body) = post_json(
        &mint.esp,
        "/rollover",
        &serde_json::to_value(&first).unwrap(),
    );
    assert_eq!(code, 200, "{body}");
    // Then three notes, `a` among them: refused whole, and `b` and `c` stay.
    let mut r = esp_mint::rotation::RolloverRequest {
        service: service(),
        redeemable_after_day: PAST,
        input_keysets: vec![in_ks(); 3],
        keyset: out_ks(),
        inputs: [&b, &a, &c]
            .iter()
            .map(|n| MintInput {
                amount: Amount::from_units(ONE),
                note: n.0,
                spend_signature: Signature::from_slice(&[0u8; 64]).unwrap(),
            })
            .collect(),
        outputs: (0..3).map(|_| blinded(ONE).0).collect(),
    };
    let d = r.digest();
    for (input, n) in r.inputs.iter_mut().zip([&b, &a, &c]) {
        input.spend_signature = SECP256K1.sign_schnorr(&d, &n.1);
    }
    let (code, body) = post_json(&mint.esp, "/rollover", &serde_json::to_value(&r).unwrap());
    assert_eq!(code, 400, "{body}");
    assert!(body.to_string().contains("already spent"), "{body}");
    // the body names the spent input (the second in the request), for the wallet
    assert_eq!(body["code"], "note_spent_elsewhere", "{body}");
    assert_eq!(body["spent"], serde_json::json!([1]), "{body}");
    assert!(is_spent(&mint, &a.0));
    assert!(!is_spent(&mint, &b.0), "nothing else was burned");
    assert!(!is_spent(&mint, &c.0), "nothing else was burned");
    rt.shutdown_background();
}

/// A redemption of a previous-set note left pending by a crash, then retried
/// after that set retired. `burn`: its note was burned before the crash;
/// `flag`: the burn was also recorded (`burned: true`) under its hash. The
/// stored decision is taken from a real run of a request of the same shape.
fn redeem_after_retirement(name: &str, burn: bool, flag: bool) -> (u16, Value, Mint, Note) {
    let rt = Runtime::new().unwrap();
    let dir = scratch(name);
    let mint = start_rotating(&rt, &dir);
    let a = esp_note(&mint, 2 * ONE, service(), PAST);
    let b = esp_note(&mint, 2 * ONE, service(), PAST);
    let (id0, id1) = rotate_once(&mint);
    set_keysets(&id0, &id1);
    let (req, _) = request(
        &[(a.0, &a.1, 2 * ONE, PAST)],
        &[(ONE, PAST)],
        &service_keypair(),
    );
    let hash = redeem::request_hash(&req);
    // The decision: from running the request itself when its note is to be
    // burned, else from a twin request (note b) of the same shape.
    let plan = if burn {
        let (code, body) = post_bytes(&mint.esp, req.encode());
        assert_eq!(code, 200, "{body}");
        // The crash came before the queue entry was written.
        std::fs::remove_file(&mint.queue_path).unwrap();
        match mint.state.responses.lock().unwrap().get(&hash) {
            Some(esp_mint::responses::Entry::RedeemDone(r)) => r.plan.clone(),
            other => panic!("{other:?}"),
        }
    } else {
        let (twin, _) = request(
            &[(b.0, &b.1, 2 * ONE, PAST)],
            &[(ONE, PAST)],
            &service_keypair(),
        );
        let (code, body) = post_bytes(&mint.esp, twin.encode());
        assert_eq!(code, 200, "{body}");
        match mint
            .state
            .responses
            .lock()
            .unwrap()
            .get(&redeem::request_hash(&twin))
        {
            Some(esp_mint::responses::Entry::RedeemDone(r)) => r.plan.clone(),
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(is_spent_prev(&mint, &a.0), burn);
    mint.state
        .responses
        .lock()
        .unwrap()
        .put(
            &hash,
            esp_mint::responses::Entry::RedeemPending(redeem::RedeemPending {
                inputs: vec![hex::encode(a.0.nonce.0.serialize())],
                outputs: req
                    .decline_outputs
                    .iter()
                    .map(|o| hex::encode(o.output.blind_nonce.0.serialize()))
                    .collect(),
                plan,
                burned: flag,
            }),
        )
        .unwrap();
    // The note's set retires (two rotations after it was current).
    set_clock(&mint, T0 + 2 * 3600);
    let w = get_json(&mint.esp, "/rotation");
    assert_ne!(w["previous"]["id"], id0.as_str(), "generation 0 is deleted");
    let (code, body) = post_bytes(&mint.esp, req.encode());
    rt.shutdown_background();
    (code, body, mint, a.0)
}

/// Spent in generation 0 while it is the previous set.
fn is_spent_prev(mint: &Mint, note: &Note) -> bool {
    let rotor = mint.state.rotor.as_ref().unwrap().lock().unwrap();
    rotor
        .previous
        .as_ref()
        .unwrap()
        .1
        .is_spent(note.nonce)
        .unwrap()
}

fn retired_proofs(mint: &Mint) -> Value {
    let path = mint
        .queue_path
        .parent()
        .unwrap()
        .join(esp_mint::rotation::RETIRED_FILE);
    serde_json::from_slice::<Value>(&std::fs::read(path).unwrap()).unwrap()["burn_proofs"].clone()
}

#[test]
fn a_resumed_redemption_after_retirement_finishes_only_with_stored_proof_of_its_burn() {
    // (a) Burned, and the flag written: finishes.
    let (code, body, _, _) = redeem_after_retirement("rproof-flag", true, true);
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        body["entry"]["status"], "open",
        "queued by the retry: {body}"
    );

    // (b) Burned, the flag lost to the crash: the retirement took the proof
    // from the spent list and saved it in retired.json; the retry finishes.
    let (code, body, mint, note) = redeem_after_retirement("rproof-crash", true, false);
    let nonce = hex::encode(note.nonce.0.serialize());
    assert!(
        retired_proofs(&mint)
            .as_array()
            .is_some_and(|p| p.iter().any(|n| n == nonce.as_str())),
        "proof saved: {}",
        retired_proofs(&mint)
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["entry"]["status"], "open", "{body}");

    // (c) Crashed before the burn: nothing proves it, refused, nothing signed.
    let (code, body, mint, note) = redeem_after_retirement("rproof-none", false, false);
    assert_eq!(
        (code, body["code"].as_str()),
        (400, Some("burn_not_proven")),
        "{body}"
    );
    let nonce = hex::encode(note.nonce.0.serialize());
    assert!(
        !retired_proofs(&mint)
            .as_array()
            .is_some_and(|p| p.iter().any(|n| n == nonce.as_str()))
    );
}
