//! Redemption over AIR, end to end: an ESP mint with its own AIR listener, the
//! operator's admin listener, and a service that signs and sends the canonical
//! binary encoding the way the wallet does.
//!
//! A redemption never calls the PSP, so the PSP stand-in refuses every call.
//! The wallet's calls (redeem, transfer, rollover, keysets, rotation) go over
//! AIR (see `common`: a refusal is read as its HTTP status and body); the
//! operator's routes on the admin listener and `/audit` go over HTTP. These are
//! plain tests with their own runtime, because they use the blocking HTTP client.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Router;
use esp_mint::admin::{self, AdminState};
use esp_mint::exchange::{Burn, Psp};
use esp_mint::payouts;
use esp_mint::queue::Queue;
use esp_mint::redeem::{self, RedeemInput, RedeemOutput, RedeemRequest};
use esp_mint::server::{self, EspState};
use esp_mint::terms::Terms;
use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note};
use rand::rngs::OsRng;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, SECP256K1, SecretKey};
use serde_json::Value;
use sp_wire::ServiceDid;
use tokio::runtime::Runtime;

const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// A test amount, a power of two (about $1.10).
const ONE: u64 = 1 << 40;
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

fn service() -> ServiceDid {
    ServiceDid::parse(&format!("02{G_X}")).unwrap()
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
    /// The HTTP base URL of the ESP mint (`/audit`, `/health`).
    esp: String,
    admin: String,
    state: Arc<EspState>,
    queue_path: PathBuf,
    /// The mint's AIR listener. A test that keeps the mint past its last call
    /// sets this to `None`, which lets the next mint have the AIR server.
    air: Option<common::Air>,
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

fn start(rt: &Runtime, dir: &Path, max_bytes: usize) -> Mint {
    start_at_rate(rt, dir, max_bytes, RATE)
}

/// `start`, with the redemption fee rate (ESP units per byte) chosen. The mint
/// is the one `serve` builds, on the system clock, with the default rotation
/// (a year to activate, so it does not rotate during a test).
fn start_at_rate(rt: &Runtime, dir: &Path, max_bytes: usize, rate: u128) -> Mint {
    start_with(
        rt,
        dir,
        0,
        esp_mint::config::Config {
            redeem_fee_per_byte: rate as u64,
            redeem_max_request_bytes: max_bytes,
            ..esp_mint::config::Config::default()
        },
    )
}

/// The mint `serve` builds (`EspState::open`) on `dir`, on this clock (`0` is
/// the system clock), with this config, its AIR listener and the admin router.
fn start_with(rt: &Runtime, dir: &Path, clock: u64, config: esp_mint::config::Config) -> Mint {
    let data = dir.join("esp");
    let state = Arc::new(EspState::open(&data, Box::new(NoPsp), config, clock).unwrap());
    let id = state.rotor.lock().unwrap().current.id.clone();
    set_keysets(&id, &id);
    let queue_path = server::queue_path(&data);
    let esp = serve(rt, server::router(Arc::clone(&state)));
    let admin_state = Arc::new(AdminState {
        queue_path: queue_path.clone(),
        lock: Mutex::new(()),
        token: None,
        esp: Arc::clone(&state),
    });
    let admin = serve(rt, admin::router(admin_state));
    let air = Some(common::Air::start(&state, &dir.join("air")));
    Mint {
        esp,
        admin,
        state,
        queue_path,
        air,
    }
}

/// A note the mint has issued under these terms, and the key that spends it.
fn esp_note(mint: &Mint, units: u64, service: ServiceDid, day: u64) -> (Note, Keypair) {
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
    request_with_memo(notes, decline, service_signer, MEMO)
}

fn request_with_memo(
    notes: &[(Note, &Keypair, u64, u64)],
    decline: &[(u64, u64)],
    service_signer: &Keypair,
    memo: &str,
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
    let sighash = redeem::digest(&service(), &out_ks(), &inputs, memo, &decline_outputs, &[]);
    for (input, (_, keypair, _, _)) in inputs.iter_mut().zip(notes) {
        input.input.spend_signature = SECP256K1.sign_schnorr(&sighash, keypair);
    }
    let service_signature = SECP256K1.sign_schnorr(&sighash, service_signer);
    (
        RedeemRequest {
            service: service(),
            output_keyset: out_ks(),
            inputs,
            memo: memo.to_string(),
            decline_outputs,
            refund_outputs: vec![],
            service_signature,
        },
        wanted,
    )
}

/// A redemption, over AIR.
fn esp_post_bytes(mint: &Mint, bytes: Vec<u8>) -> (u16, Value) {
    air(mint).post_bytes("/redeem", &bytes)
}

/// A JSON call to `path` of the ESP mint, over AIR.
fn esp_post_json(mint: &Mint, path: &str, body: &Value) -> (u16, Value) {
    air(mint).post_json(path, body)
}

fn air(mint: &Mint) -> &common::Air {
    mint.air
        .as_ref()
        .expect("the mint's AIR listener is stopped")
}

/// A JSON call to an HTTP route (the operator's, on the admin listener).
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
fn a_request_that_is_not_the_canonical_encoding_is_a_400() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("malformed");
    let mint = start(&rt, &dir, 64 * 1024 * 1024);
    let (note, key) = esp_note(&mint, 4 * ONE, service(), PAST);
    let (req, _) = request(&[(note, &key, 4 * ONE, PAST)], &[], &service_keypair());
    let mut bytes = req.encode();
    bytes.push(0);
    let (code, body) = esp_post_bytes(&mint, bytes);
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "malformed_request");
    // JSON is not the format
    let (code, body) = esp_post_json(&mint, "/redeem", &serde_json::json!({}));
    assert_eq!(code, 400, "{body}");
    assert!(!is_spent(&mint, &note));
    assert!(nothing_stored(&mint));
    rt.shutdown_background();
}

#[test]
fn a_bad_amount_or_a_bad_service_signature_is_a_400_with_no_burn_and_no_fee() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("denomination");
    let mint = start(&rt, &dir, 64 * 1024 * 1024);
    let (good, kg) = esp_note(&mint, 4 * ONE, service(), PAST);
    // an incoming note of an odd size, which the mint holds under that amount
    let (odd, ko) = esp_note(&mint, ONE + 5, service(), PAST);

    let (req, _) = request(&[(odd, &ko, ONE + 5, PAST)], &[], &service_keypair());
    let (code, body) = esp_post_bytes(&mint, req.encode());
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "bad_denomination");
    assert_eq!(
        body["error"],
        "note 0: ESP amounts are powers of two. Nothing was burned and no fee was taken"
    );

    // a decline output that is not a power of two
    let (req, _) = request(
        &[(good, &kg, 4 * ONE, PAST)],
        &[(ONE, PAST), (ONE + 1, PAST)],
        &service_keypair(),
    );
    let (code, body) = esp_post_bytes(&mint, req.encode());
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "bad_denomination");
    assert_eq!(
        body["error"],
        "decline output 1: ESP amounts are powers of two. Nothing was burned and no fee was taken"
    );

    assert!(!is_spent(&mint, &good) && !is_spent(&mint, &odd));
    assert!(nothing_stored(&mint));

    // a request the service did not sign
    let (note, key) = esp_note(&mint, 4 * ONE, service(), PAST);
    let (req, _) = request(&[(note, &key, 4 * ONE, PAST)], &[], &other_keypair());
    let (code, body) = esp_post_bytes(&mint, req.encode());
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "bad_service_signature");
    assert!(!is_spent(&mint, &note));
    assert!(nothing_stored(&mint));
    rt.shutdown_background();
}

#[test]
fn by_default_a_redemption_costs_no_fee_and_the_whole_amount_is_owed() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("default-fee");
    // The rate a mint has when nothing sets one.
    let rate = u128::from(esp_mint::config::Config::default().redeem_fee_per_byte);
    assert_eq!(rate, 0);
    let mint = start_at_rate(&rt, &dir, 64 * 1024 * 1024, rate);
    let (note, key) = esp_note(&mint, 4 * ONE, service(), PAST);
    let (req, _) = request(&[(note, &key, 4 * ONE, PAST)], &[], &service_keypair());
    let (code, body) = esp_post_bytes(&mint, req.encode());
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["fee_esp"], "0");
    assert_eq!(body["owed_esp"], (4 * ONE).to_string());
    assert_eq!(body["message"], "payout queued");
    assert!(is_spent(&mint, &note));
    rt.shutdown_background();
}

#[test]
fn a_redemption_is_queued_then_declined_and_the_service_collects_the_reissued_notes() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("flow");
    let mint = start(&rt, &dir, 64 * 1024 * 1024);
    let (a, ka) = esp_note(&mint, 4 * ONE, service(), PAST);
    let (b, kb) = esp_note(&mint, 2 * ONE, service(), PAST2);
    let (req, wanted) = request(
        &[(a, &ka, 4 * ONE, PAST), (b, &kb, 2 * ONE, PAST2)],
        &[(2 * ONE, PAST), (2 * ONE, PAST2)],
        &service_keypair(),
    );
    let bytes = req.encode();
    let fee = u128::from(bytes.len() as u64) * RATE;
    let id = redeem::request_hash(&req);

    let (code, body) = esp_post_bytes(&mint, bytes.clone());
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["accepted_esp"], (6 * ONE).to_string());
    assert_eq!(body["fee_esp"], fee.to_string());
    assert_eq!(body["size_bytes"], bytes.len());
    assert_eq!(body["owed_esp"], (u128::from(6 * ONE) - fee).to_string());
    assert_eq!(body["message"], "payout queued");
    assert_eq!(body["entry"]["status"], "open");
    assert_eq!(body["notes"][0]["accepted"], true);
    assert!(is_spent(&mint, &a) && is_spent(&mint, &b));
    let queue = Queue::open(&mint.queue_path).unwrap();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.get(&id).unwrap().memo, MEMO);

    // the same request again: the same answer, and nothing more is burned or queued
    let (code, again) = esp_post_bytes(&mint, bytes.clone());
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
    let (code, after) = esp_post_bytes(&mint, bytes);
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
    let (a, ka) = esp_note(&mint, 4 * ONE, service(), PAST);
    let (b, kb) = esp_note(&mint, 2 * ONE, service(), PAST);
    let (c, kc) = esp_note(&mint, 4 * ONE, service(), PAST2);
    let (first, _) = request(
        &[(a, &ka, 4 * ONE, PAST), (b, &kb, 2 * ONE, PAST)],
        &[],
        &service_keypair(),
    );
    let (second, _) = request(&[(c, &kc, 4 * ONE, PAST2)], &[], &service_keypair());
    let (code, one) = esp_post_bytes(&mint, first.encode());
    assert_eq!(code, 200, "{one}");
    let (code, two) = esp_post_bytes(&mint, second.encode());
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
    // A fee only a power of two can equal: a rate of 2^20 per byte, and a memo
    // that makes the request exactly 512 bytes (120 + 187 for one note, and 205
    // of memo), so the fee is 2^29 and one note of that size covers it exactly.
    let rate: u128 = 1 << 20;
    let mint = start_at_rate(&rt, &dir, 64 * 1024 * 1024, rate);
    let memo = format!("{:x<205}", "btc:bc1qpayhere-");
    assert_eq!(memo.len(), 205);
    let fee = redeem::fee_for(redeem::encoded_len(1, memo.len(), 0, 0), rate);
    assert_eq!(fee, 1 << 29);
    let (note, key) = esp_note(&mint, fee as u64, service(), PAST);
    let (req, _) = request_with_memo(
        &[(note, &key, fee as u64, PAST)],
        &[],
        &service_keypair(),
        &memo,
    );
    let (code, body) = esp_post_bytes(&mint, req.encode());
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["owed_esp"], "0");
    assert_eq!(body["fee_esp"], fee.to_string());
    assert_eq!(body["message"], "nothing owed, fee taken");
    assert!(body["entry"].is_null());
    assert!(is_spent(&mint, &note));
    // no queue entry
    assert!(Queue::open(&mint.queue_path).unwrap().is_empty());
    // a retry returns the stored answer
    let (code, again) = esp_post_bytes(&mint, req.encode());
    assert_eq!(code, 200);
    assert_eq!(again, body);
    rt.shutdown_background();
}

#[test]
fn a_request_below_the_fee_is_refused_with_the_fee_in_the_body() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("below-fee");
    let mint = start(&rt, &dir, 64 * 1024 * 1024);
    let (note, key) = esp_note(&mint, 512, service(), PAST);
    let (req, _) = request(&[(note, &key, 512, PAST)], &[], &service_keypair());
    let (code, body) = esp_post_bytes(&mint, req.encode());
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "below_fee");
    assert_eq!(body["value_esp"], "512");
    assert_eq!(body["fee_esp"], "322000000");
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
    let (a, ka) = esp_note(&mint, 4 * ONE, service(), PAST);
    // asks for all of it back, but the fee comes off
    let (req, _) = request(
        &[(a, &ka, 4 * ONE, PAST)],
        &[(4 * ONE, PAST)],
        &service_keypair(),
    );
    let (code, body) = esp_post_bytes(&mint, req.encode());
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "outputs_over_limit");
    assert_eq!(body["list"], "decline_outputs");
    assert_eq!(body["totals"]["accepted_esp"], (4 * ONE).to_string());
    assert_eq!(
        body["totals"]["accepted_by_terms"][0]["redeemable_after_day"],
        PAST
    );
    assert_eq!(
        body["totals"]["accepted_by_terms"][0]["esp"],
        (4 * ONE).to_string()
    );
    assert!(!is_spent(&mint, &a));
    assert!(nothing_stored(&mint));
    rt.shutdown_background();
}

// ---- key rotation -----------------------------------------------------------

const T0: u64 = 1_800_000_000;

fn start_rotating(rt: &Runtime, dir: &Path) -> Mint {
    start_rotating_with(rt, dir, |_| {})
}

fn start_rotating_with(
    rt: &Runtime,
    dir: &Path,
    tweak: impl FnOnce(&mut esp_mint::config::Config),
) -> Mint {
    // Rotation after an hour, every hour, on the test's own clock (`T0`), which
    // `set_clock` moves.
    let mut config = esp_mint::config::Config {
        redeem_fee_per_byte: RATE as u64,
        rotation_activation_hours: 1,
        rotation_period_hours: 1,
        ..esp_mint::config::Config::default()
    };
    tweak(&mut config);
    start_with(rt, dir, T0, config)
}

fn set_clock(mint: &Mint, t: u64) {
    let r = mint.state.rotor.lock().unwrap();
    r.clock.store(t, std::sync::atomic::Ordering::SeqCst);
}

/// `/audit`, over HTTP.
fn get_json(base: &str, path: &str) -> Value {
    assert_eq!(path, "/audit");
    reqwest::blocking::get(format!("{base}{path}"))
        .unwrap()
        .json()
        .unwrap()
}

/// A read of the ESP mint (keysets, rotation), over AIR. It must be answered:
/// a read that is refused fails the test here.
fn esp_get_json(mint: &Mint, path: &str) -> Value {
    let (code, body) = air(mint).get_json(path);
    assert_eq!(code, 200, "{path}: {body}");
    body
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

/// The blind nonces (hex) of the outputs of `rq`, as a pending rollover holds them.
fn blind_hex(rq: &esp_mint::rotation::RolloverRequest) -> Vec<String> {
    let blind = |o: &MintOutput| hex::encode(o.blind_nonce.0.serialize());
    rq.outputs.iter().map(blind).collect()
}

fn current_key(mint: &Mint, units: u64) -> secp256k1::PublicKey {
    let r = mint.state.rotor.lock().unwrap();
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

fn previous_key(mint: &Mint, units: u64) -> secp256k1::PublicKey {
    let r = mint.state.rotor.lock().unwrap();
    r.previous
        .as_ref()
        .unwrap()
        .0
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
    let mint = start_rotating(&rt, &dir);
    // Generation 0 is the master secret in the data folder itself.
    let master0 =
        esp_mint::keys::load_or_generate(&dir.join("esp").join("master_secret.hex")).unwrap();
    assert_eq!(
        mint.state.master, master0,
        "generation 0 = the master secret of the data folder"
    );
    let w = esp_get_json(&mint, "/rotation");
    assert_eq!(
        (w["first_issue"].clone(), w["current"]["epoch"].clone()),
        (Value::Null, 0.into())
    );

    let a = esp_note(&mint, 2 * ONE, service(), PAST);
    let b = esp_note(&mint, ONE, service(), PAST);
    let c = esp_note(&mint, ONE, service(), PAST);
    let d = esp_note(&mint, ONE, service(), PAST);
    let w = esp_get_json(&mint, "/rotation");
    assert_eq!(w["first_issue"], T0, "the first issue starts the clock");
    assert_eq!(w["activation"], T0 + 3600);

    set_clock(&mint, T0 + 3600);
    let w = esp_get_json(&mint, "/rotation");
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
    let (code, body) = esp_post_bytes(&mint, req.encode());
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
    let (code, body) = esp_post_json(&mint, "/transfer", &serde_json::to_value(&tr).unwrap());
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["keyset"], id1.as_str());
    let key: secp256k1::PublicKey = serde_json::from_value(body["keys"][0].clone()).unwrap();
    assert_eq!(key, current_key(&mint, ONE));

    // Rollover by the holder: same amount and terms, current set; a retry gets
    // the stored answer; a split is refused.
    let rq = rollover_req(&c, ONE, ONE);
    let (code, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&rq).unwrap());
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
        esp_post_json(&mint, "/rollover", &serde_json::to_value(&rq).unwrap()),
        (200, body)
    );
    assert_eq!(
        esp_post_json(
            &mint,
            "/rollover",
            &serde_json::to_value(rollover_req(&d, ONE, ONE / 2)).unwrap()
        )
        .0,
        400
    );

    // The next rotation deletes generation 0 with its spent list: `d` is lost.
    set_clock(&mint, T0 + 2 * 3600);
    let w = esp_get_json(&mint, "/rotation");
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
    let (code, body) = esp_post_json(
        &mint,
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
    set_keysets(&id0, w["current"]["id"].as_str().unwrap());
    let (late, _) = request(&[(d.0, &d.1, ONE, PAST)], &[], &service_keypair());
    let (code, body) = esp_post_bytes(&mint, late.encode());
    assert_eq!(
        code, 400,
        "below the fee once the expired note is out: {body}"
    );
    // An unknown keyset is told apart from a retired one.
    set_keysets(&"ab".repeat(8), w["current"]["id"].as_str().unwrap());
    let (code, body) = esp_post_json(
        &mint,
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
    esp_get_json(&mint, "/rotation");
    set_clock(&mint, T0 + 3600);
    let w = esp_get_json(&mint, "/rotation");
    set_keysets(
        w["previous"]["id"].as_str().unwrap(),
        w["current"]["id"].as_str().unwrap(),
    );
    let rq = rollover_req(&n, ONE, ONE);
    // The crash: pending written and the note burned, no answer stored.
    {
        let rotor = mint.state.rotor.lock().unwrap();
        mint.state
            .rollovers
            .lock()
            .unwrap()
            .begin(
                &rq.hash(),
                rotor.current.epoch,
                vec![hex::encode(n.0.nonce.0.serialize())],
                blind_hex(&rq),
            )
            .unwrap();
        let (g, l) = rotor.previous.as_ref().unwrap();
        let sk = g.master.key_for(
            Amount::from_units(ONE),
            &Terms {
                service: service(),
                redeemable_after_day: PAST,
            },
        );
        l.redeem_with_key(&sk, &rq.inputs[0], rq.digest()).unwrap();
    }
    let (code, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&rq).unwrap());
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        esp_post_json(&mint, "/rollover", &serde_json::to_value(&rq).unwrap()),
        (200, body)
    );
}

#[test]
fn a_decline_after_the_requested_keyset_retires_is_signed_by_the_current_set_and_says_so() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("queue-rule");
    let mint = start_rotating(&rt, &dir);
    let id0 = esp_get_json(&mint, "/rotation")["current"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let a = esp_note(&mint, 2 * ONE, service(), PAST);
    // The note is signed straight from the mint here; the ledger is told, as an
    // exchange would have told it.
    common::record_issued(&mint.state, PAST, 2 * ONE);
    // Queued with its outputs asking for generation 0.
    let (req, wanted) = request(
        &[(a.0, &a.1, 2 * ONE, PAST)],
        &[(ONE, PAST)],
        &service_keypair(),
    );
    let bytes = req.encode();
    let (code, body) = esp_post_bytes(&mint, bytes.clone());
    assert_eq!(code, 200, "{body}");
    let id = redeem::request_hash(&req);

    // Two rotations: generation 0 is deleted and listed as retired.
    set_clock(&mint, T0 + 3600);
    esp_get_json(&mint, "/rotation");
    set_clock(&mint, T0 + 2 * 3600);
    let w = esp_get_json(&mint, "/rotation");
    let current = w["current"]["id"].as_str().unwrap().to_string();
    assert_ne!(current, id0);
    let ks = esp_get_json(&mint, "/keysets");
    assert_eq!(ks["current"], current.as_str());
    assert_ne!(ks["previous"], id0.as_str());

    let (code, declined) = post_json(
        &mint.admin,
        "/payouts/decline",
        &serde_json::json!({"entry_id": id, "reason": "terms"}),
    );
    assert_eq!(code, 200, "{declined}");
    // The decline is on the ledger once: the note (2 ONE) was recorded as issued,
    // redeemed by the request, and ONE came back with the decline, so ONE is
    // outstanding, under a day that has come.
    let audit = get_json(&mint.esp, "/audit");
    assert_eq!(audit["outstanding"], ONE, "{audit}");
    assert_eq!(audit["outstanding_matured"], ONE, "{audit}");
    assert_eq!(audit["outstanding_unmatured"], 0, "{audit}");
    assert_eq!(audit["requests_unfinished"], 0, "{audit}");
    let (code, after) = esp_post_bytes(&mint, bytes);
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
    esp_get_json(mint, "/rotation");
    set_clock(mint, T0 + 3600);
    let w = esp_get_json(mint, "/rotation");
    (
        w["previous"]["id"].as_str().unwrap().to_string(),
        w["current"]["id"].as_str().unwrap().to_string(),
    )
}

#[test]
fn new_outputs_naming_the_previous_set_are_signed_by_it() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("previous-out");
    let mint = start_rotating(&rt, &dir);
    let a = esp_note(&mint, ONE, service(), PAST);
    let b = esp_note(&mint, 2 * ONE, service(), PAST);
    let c = esp_note(&mint, 2 * ONE, service(), PAST);
    let (id0, id1) = rotate_once(&mint);
    assert_ne!(id0, id1);
    // Previous-set notes in, outputs asked of the previous set: signed by it.
    set_keysets(&id0, &id0);
    let (code, body) = esp_post_json(
        &mint,
        "/transfer",
        &serde_json::to_value(transfer_req(&a, ONE)).unwrap(),
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["keyset"], id0.as_str(), "the set that signed it");
    let (code, body) = esp_post_json(
        &mint,
        "/rollover",
        &serde_json::to_value(rollover_req(&b, 2 * ONE, 2 * ONE)).unwrap(),
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["keyset"], id0.as_str(), "the set that signed it");
    // A redemption naming the previous set for its decline outputs is
    // accepted too; the keyset it names is stored with it.
    let (req, _) = request(
        &[(c.0, &c.1, 2 * ONE, PAST)],
        &[(ONE, PAST)],
        &service_keypair(),
    );
    let (code, body) = esp_post_bytes(&mint, req.encode());
    assert_eq!(code, 200, "{body}");
}

#[test]
fn outputs_naming_a_set_that_is_not_live_are_refused_and_nothing_is_burned() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("unknown-out");
    let mint = start_rotating(&rt, &dir);
    let a = esp_note(&mint, ONE, service(), PAST);
    let b = esp_note(&mint, 2 * ONE, service(), PAST);
    let (id0, _id1) = rotate_once(&mint);
    set_keysets(&id0, &"ab".repeat(8));
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
        let (code, body) = esp_post_json(&mint, route, &body);
        assert_eq!(
            (code, body["code"].as_str()),
            (400, Some("unknown_keyset")),
            "{route}: {body}"
        );
    }
    let (req, _) = request(
        &[(b.0, &b.1, 2 * ONE, PAST)],
        &[(ONE, PAST)],
        &service_keypair(),
    );
    let (code, body) = esp_post_bytes(&mint, req.encode());
    assert_eq!(
        (code, body["code"].as_str()),
        (400, Some("unknown_keyset")),
        "{body}"
    );
    assert!(
        !is_spent_prev(&mint, &a.0) && !is_spent_prev(&mint, &b.0),
        "nothing burned"
    );
}

/// The state a crash leaves in a rollover, before any retirement: the runtime,
/// the mint, the note and the request.
fn stuck_rollover(
    name: &str,
    burn: bool,
    flag: bool,
) -> (
    Runtime,
    Mint,
    (Note, Keypair),
    esp_mint::rotation::RolloverRequest,
) {
    let rt = Runtime::new().unwrap();
    let dir = scratch(name);
    let mint = start_rotating(&rt, &dir);
    let n = esp_note(&mint, ONE, service(), PAST);
    let (id0, id1) = rotate_once(&mint);
    set_keysets(&id0, &id1);
    let rq = rollover_req(&n, ONE, ONE);
    {
        let rotor = mint.state.rotor.lock().unwrap();
        let mut rollovers = mint.state.rollovers.lock().unwrap();
        rollovers
            .begin(
                &rq.hash(),
                rotor.current.epoch,
                vec![hex::encode(n.0.nonce.0.serialize())],
                blind_hex(&rq),
            )
            .unwrap();
        if flag {
            rollovers.mark_burned(&rq.hash()).unwrap();
        }
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
    }
    (rt, mint, n, rq)
}

/// A rollover of a generation-0 note, accepted and burned before the
/// rotations (its answer lost), then retried after generation 0 is deleted.
/// A rollover left pending across a retirement. `burn`: its input was burned
/// before the crash; `flag`: the burn was also recorded under its hash;
/// `later`: the retry comes after the set the outputs name is deleted too.
/// Returns the ID of the set that should sign: the one the request names while
/// it is live, else the current one.
fn rollover_after_retirement(
    name: &str,
    burn: bool,
    flag: bool,
    later: bool,
) -> (u16, Value, String) {
    let (rt, mint, _, rq) = stuck_rollover(name, burn, flag);
    let id1 = rq.keyset.clone();
    set_clock(&mint, T0 + 2 * 3600);
    let w = esp_get_json(&mint, "/rotation");
    assert_eq!(
        w["previous"]["id"].as_str(),
        Some(id1.as_str()),
        "still live"
    );
    let expected = if later {
        set_clock(&mint, T0 + 3 * 3600);
        let w = esp_get_json(&mint, "/rotation");
        assert_ne!(w["previous"]["id"].as_str(), Some(id1.as_str()), "deleted");
        w["current"]["id"].as_str().unwrap().to_string()
    } else {
        id1.clone()
    };
    let (code, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&rq).unwrap());
    rt.shutdown_background();
    (code, body, expected)
}

#[test]
fn a_resumed_rollover_after_retirement_finishes_only_with_stored_proof_of_its_burn() {
    // The input set is deleted; the set the outputs name is still live (the
    // previous set now), so it signs.
    let (code, body, signer) = rollover_after_retirement("proof-yes", true, true, false);
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["keyset"], signer.as_str(), "signed by the named set");
    assert_eq!(
        body["epoch"], 1,
        "the answer carries the signing set's epoch"
    );
    // Crash injected after the burn, before the flag was written: the proof
    // taken from the spent list at the retirement finishes it.
    let (code, body, signer) = rollover_after_retirement("proof-crash", true, false, false);
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["keyset"], signer.as_str());
    // Crash before the burn: nothing proves it, refused.
    let (code, body, _) = rollover_after_retirement("proof-no", false, false, false);
    assert_eq!(
        (code, body["code"].as_str()),
        (400, Some("burn_not_proven")),
        "{body}"
    );
    // The retry comes after the set the outputs name is deleted too: the
    // current set signs.
    let (code, body, signer) = rollover_after_retirement("proof-late", true, true, true);
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["keyset"], signer.as_str(), "signed by the current set");
}

/// A rollover and a transfer of `n` that name a keyset the mint does not know
/// are refused `unknown_keyset`, nothing is issued for them, and the mint
/// still answers.
fn forged_requests_are_refused(mint: &Mint, n: &(Note, Keypair)) {
    let issued = get_json(&mint.esp, "/audit")["issued"].clone();
    let mut forged = rollover_req(n, 1 << 50, 1 << 50);
    forged.input_keysets = vec!["ab".repeat(8)];
    let d = forged.digest();
    forged.inputs[0].spend_signature = SECP256K1.sign_schnorr(&d, &n.1);
    let (code, body) = esp_post_json(mint, "/rollover", &serde_json::to_value(&forged).unwrap());
    assert_eq!((code, body["code"].as_str()), (400, Some("unknown_keyset")));
    assert_eq!(get_json(&mint.esp, "/audit")["issued"], issued);
    let mut tr = transfer_req(n, 1 << 50);
    tr.input_keysets = vec!["ab".repeat(8)];
    let (code, body) = esp_post_json(mint, "/transfer", &serde_json::to_value(&tr).unwrap());
    assert_eq!((code, body["code"].as_str()), (400, Some("unknown_keyset")));
    esp_get_json(mint, "/keysets"); // the mint still answers
}

#[test]
fn a_burn_proof_left_on_file_serves_no_other_request() {
    // Fails if the guard lets a request that is not resuming use a proof
    // (P2-01), whatever the drop does: a crash between a request's finish and
    // the drop of its proof leaves the proof behind.
    let (rt, mint, n, rq) = stuck_rollover("proof-left", true, false);
    set_clock(&mint, T0 + 2 * 3600);
    esp_get_json(&mint, "/rotation");
    // The request is gone from the store; its proof is still on file.
    let store = esp_mint::rotation::Rollovers::open(&scratch("proof-left-store")).unwrap();
    *mint.state.rollovers.lock().unwrap() = store;
    let key = format!("rollovers:{}", rq.hash());
    let nonce = hex::encode(n.0.nonce.0.serialize());
    assert_eq!(retired_proofs(&mint), serde_json::json!({ key: [nonce] }));
    forged_requests_are_refused(&mint, &n);
    rt.shutdown_background();
}

#[test]
fn a_burn_proof_serves_only_its_own_request_and_is_dropped_when_it_finishes() {
    // Fails if retirement saves the proof where any request can use it (P2-01):
    // once the stuck rollover is finished, a new rollover naming its proven note
    // with a keyset the mint does not know is signed at a large amount; a new
    // transfer panics under the mint lock (F4).
    let (rt, mint, n, rq) = stuck_rollover("proof-forged", true, false);
    set_clock(&mint, T0 + 2 * 3600);
    esp_get_json(&mint, "/rotation");
    let nonce = hex::encode(n.0.nonce.0.serialize());
    let key = format!("rollovers:{}", rq.hash());
    assert_eq!(retired_proofs(&mint), serde_json::json!({ key: [nonce] }));
    let (code, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&rq).unwrap());
    assert_eq!(code, 200, "{body}");
    assert_eq!(retired_proofs(&mint), serde_json::json!({}), "finished");
    forged_requests_are_refused(&mint, &n);
    rt.shutdown_background();
}

#[test]
fn a_rollover_with_two_outputs_sharing_a_blind_nonce_is_refused_before_any_burn() {
    // Fails if the outputs are checked after the burn (P1-07): the note is then
    // burned and the rollover stays pending, holding it.
    let rt = Runtime::new().unwrap();
    let mint = start_rotating(&rt, &scratch("rollover-dup"));
    let [a, b] = [(); 2].map(|_| esp_note(&mint, ONE, service(), PAST));
    let (mut rq, second) = (rollover_req(&a, ONE, ONE), rollover_req(&b, ONE, ONE));
    rq.inputs.extend(second.inputs);
    rq.input_keysets.extend(second.input_keysets);
    rq.outputs.push(rq.outputs[0].clone());
    let d = rq.digest();
    for (input, n) in rq.inputs.iter_mut().zip([&a, &b]) {
        input.spend_signature = SECP256K1.sign_schnorr(&d, &n.1);
    }
    let (_, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&rq).unwrap());
    assert_eq!(body["code"], "duplicate_blind_nonce", "{body}");
    assert!(!is_spent(&mint, &a.0), "nothing burned");
    assert!(!is_spent(&mint, &b.0));
    assert_eq!(mint.state.rollovers.lock().unwrap().holds().count(), 0);
    rt.shutdown_background();
}

/// A rollover of `n` recorded as pending, as a crash before its burn leaves it,
/// holding the output blind nonce of `out`.
fn pending_rollover(mint: &Mint, n: &(Note, Keypair), out: &MintOutput) {
    let mut rq = rollover_req(n, ONE, ONE);
    rq.outputs[0].blind_nonce = out.blind_nonce;
    let epoch = mint.state.rotor.lock().unwrap().current.epoch;
    let held = vec![hex::encode(n.0.nonce.0.serialize())];
    let mut store = mint.state.rollovers.lock().unwrap();
    store
        .begin(&rq.hash(), epoch, held, blind_hex(&rq))
        .unwrap();
}

#[test]
fn an_output_held_by_a_pending_request_is_refused_to_a_rollover_and_the_other_way() {
    // Fails if a pending rollover does not hold its output blind nonces, or if a
    // rollover does not look at the ones other requests hold. Covered: a pending
    // rollover against a transfer and a redemption (an exchange is in
    // `exchange.rs`), and a pending transfer against a rollover; the exchange and
    // redemption holds are read the same way (`Responses::held_by_all`).
    let rt = Runtime::new().unwrap();
    let mint = start_rotating(&rt, &scratch("out-holds"));
    let [a, b, c, d, e] = [(); 5].map(|_| esp_note(&mint, ONE, service(), PAST));
    let tr = transfer_req(&a, ONE);
    pending_rollover(&mint, &b, &tr.outputs[0]);
    let (code, body) = esp_post_json(&mint, "/transfer", &serde_json::to_value(&tr).unwrap());
    assert!(code == 400 && body.to_string().contains("held"), "{body}");
    let (req, _) = request(
        &[(c.0, &c.1, ONE, PAST)],
        &[(ONE, PAST)],
        &service_keypair(),
    );
    pending_rollover(&mint, &d, &req.decline_outputs[0].output);
    let (code, body) = esp_post_bytes(&mint, req.encode());
    assert_eq!((code, body["code"].as_str()), (400, Some("note_held")));
    // The other way: a pending transfer, then a rollover with its output.
    let held = transfer_req(&c, ONE);
    let entry = esp_mint::responses::Entry::TransferPending(esp_mint::responses::TransferPending {
        inputs: vec![hex::encode(c.0.nonce.0.serialize())],
        outputs: vec![hex::encode(held.outputs[0].blind_nonce.0.serialize())],
        burned: false,
    });
    let hash = esp_mint::transfer::request_hash(&held);
    let responses = &mint.state.responses;
    responses.lock().unwrap().put(&hash, entry).unwrap();
    let mut rq = rollover_req(&e, ONE, ONE);
    rq.outputs = held.outputs.clone();
    let dg = rq.digest();
    rq.inputs[0].spend_signature = SECP256K1.sign_schnorr(&dg, &e.1);
    let (code, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&rq).unwrap());
    assert_eq!((code, body["code"].as_str()), (400, Some("note_held")));
    assert!(!is_spent(&mint, &a.0) && !is_spent(&mint, &e.0));
    rt.shutdown_background();
}

/// A transfer left pending across a retirement. `burn`: its input was burned
/// before the crash; `flag`: the burn was also recorded under its hash;
/// `later`: the retry comes after the set the outputs name is deleted too.
/// Returns the status, the body and the ID of the set that should sign: the one
/// the request names while it is live, else the current one.
fn transfer_after_retirement(
    name: &str,
    burn: bool,
    flag: bool,
    later: bool,
) -> (u16, Value, String) {
    let rt = Runtime::new().unwrap();
    let dir = scratch(name);
    let mint = start_rotating(&rt, &dir);
    let n = esp_note(&mint, ONE, service(), PAST);
    let (id0, id1) = rotate_once(&mint);
    set_keysets(&id0, &id1);
    let tr = transfer_req(&n, ONE);
    let hash = esp_mint::transfer::request_hash(&tr);
    {
        let rotor = mint.state.rotor.lock().unwrap();
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
                esp_mint::responses::Entry::TransferPending(esp_mint::responses::TransferPending {
                    inputs: vec![hex::encode(n.0.nonce.0.serialize())],
                    outputs: vec![hex::encode(tr.outputs[0].blind_nonce.0.serialize())],
                    burned: flag,
                }),
            )
            .unwrap();
    }
    set_clock(&mint, T0 + 2 * 3600);
    let w = esp_get_json(&mint, "/rotation");
    assert_eq!(
        w["previous"]["id"].as_str(),
        Some(id1.as_str()),
        "still live"
    );
    let expected = if later {
        set_clock(&mint, T0 + 3 * 3600);
        let w = esp_get_json(&mint, "/rotation");
        assert_ne!(w["previous"]["id"].as_str(), Some(id1.as_str()), "deleted");
        w["current"]["id"].as_str().unwrap().to_string()
    } else {
        id1.clone()
    };
    let (code, body) = esp_post_json(&mint, "/transfer", &serde_json::to_value(&tr).unwrap());
    rt.shutdown_background();
    (code, body, expected)
}

#[test]
fn a_resumed_transfer_after_retirement_finishes_only_with_stored_proof_of_its_burn() {
    // (burned before the crash, flag written, finishes): the input set is
    // deleted, the set the outputs name is still live, so it signs.
    for (burn, flag, ok) in [
        (true, true, true),
        (true, false, true),
        (false, false, false),
    ] {
        let (code, body, signer) =
            transfer_after_retirement(&format!("tproof-{burn}-{flag}"), burn, flag, false);
        if ok {
            assert_eq!(code, 200, "{body}");
            assert_eq!(body["keyset"], signer.as_str(), "signed by the named set");
        } else {
            assert_eq!(
                (code, body["code"].as_str()),
                (400, Some("burn_not_proven")),
                "{body}"
            );
        }
    }
    // The retry comes after the set the outputs name is deleted too: the
    // current set signs.
    let (code, body, signer) = transfer_after_retirement("tproof-late", true, true, true);
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["keyset"], signer.as_str(), "signed by the current set");
}

#[test]
fn a_decline_whose_requested_set_is_still_live_is_signed_by_that_set() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("queue-previous");
    let mint = start_rotating(&rt, &dir);
    let id0 = esp_get_json(&mint, "/rotation")["current"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let a = esp_note(&mint, 2 * ONE, service(), PAST);
    let (req, _) = request(
        &[(a.0, &a.1, 2 * ONE, PAST)],
        &[(ONE, PAST)],
        &service_keypair(),
    );
    let bytes = req.encode();
    assert_eq!(esp_post_bytes(&mint, bytes.clone()).0, 200);
    // One rotation: the requested set is previous, still live.
    let (id0b, _id1) = rotate_once(&mint);
    assert_eq!(id0, id0b);
    let (code, declined) = post_json(
        &mint.admin,
        "/payouts/decline",
        &serde_json::json!({"entry_id": redeem::request_hash(&req), "reason": "terms"}),
    );
    assert_eq!(code, 200, "{declined}");
    let (_, after) = esp_post_bytes(&mint, bytes);
    for sig in after["entry"]["decline_signatures"].as_array().unwrap() {
        assert_eq!(sig["keyset"], id0.as_str(), "signed by the set it named");
        let key: secp256k1::PublicKey = serde_json::from_value(sig["key"].clone()).unwrap();
        assert_eq!(key, previous_key(&mint, ONE));
    }
}

#[test]
fn a_note_held_by_a_pending_rollover_cannot_be_taken_by_a_transfer_or_another_rollover() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("rollover-holds");
    let mint = start_rotating(&rt, &dir);
    let n = esp_note(&mint, ONE, service(), PAST);
    let rq = rollover_req(&n, ONE, ONE);
    // A rollover recorded (pending, holding the note), then a crash before
    // its burn.
    mint.state
        .rollovers
        .lock()
        .unwrap()
        .begin(
            &rq.hash(),
            mint.state.rotor.lock().unwrap().current.epoch,
            vec![hex::encode(n.0.nonce.0.serialize())],
            blind_hex(&rq),
        )
        .unwrap();
    let (code, body) = esp_post_json(
        &mint,
        "/transfer",
        &serde_json::to_value(transfer_req(&n, ONE)).unwrap(),
    );
    assert_eq!(code, 400, "{body}");
    assert!(body.to_string().contains("held"), "{body}");
    let other = rollover_req(&n, ONE, ONE);
    assert_ne!(other.hash(), rq.hash());
    let (code, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&other).unwrap());
    assert_eq!(code, 400, "{body}");
    assert!(body.to_string().contains("held"), "{body}");
    assert!(!is_spent(&mint, &n.0), "nothing burned");
    // The holder finishes.
    let (code, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&rq).unwrap());
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
    let (code, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&first).unwrap());
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
    let (code, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&r).unwrap());
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

#[test]
fn a_rollover_with_two_spent_inputs_not_at_the_start_names_both() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("rollover-two-spent");
    let mint = start_rotating(&rt, &dir);
    let a = esp_note(&mint, ONE, service(), PAST);
    let b = esp_note(&mint, ONE, service(), PAST);
    let c = esp_note(&mint, ONE, service(), PAST);
    let d = esp_note(&mint, ONE, service(), PAST);
    // `b` and `d` are rolled over first, each alone.
    for n in [&b, &d] {
        let one = rollover_req(n, ONE, ONE);
        let (code, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&one).unwrap());
        assert_eq!(code, 200, "{body}");
    }
    // Four notes, the second and the fourth already spent: refused whole, and the
    // refusal names both.
    let order = [&a, &b, &c, &d];
    let mut r = esp_mint::rotation::RolloverRequest {
        service: service(),
        redeemable_after_day: PAST,
        input_keysets: vec![in_ks(); 4],
        keyset: out_ks(),
        inputs: order
            .iter()
            .map(|n| MintInput {
                amount: Amount::from_units(ONE),
                note: n.0,
                spend_signature: Signature::from_slice(&[0u8; 64]).unwrap(),
            })
            .collect(),
        outputs: (0..4).map(|_| blinded(ONE).0).collect(),
    };
    let digest = r.digest();
    for (input, n) in r.inputs.iter_mut().zip(order) {
        input.spend_signature = SECP256K1.sign_schnorr(&digest, &n.1);
    }
    let (code, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&r).unwrap());
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "note_spent_elsewhere", "{body}");
    assert_eq!(body["spent"], serde_json::json!([1, 3]), "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("inputs 1, 3: the notes are already spent"),
        "{body}"
    );
    assert!(!is_spent(&mint, &a.0), "nothing else was burned");
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
    let mut mint = start_rotating(&rt, &dir);
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
        let (code, body) = esp_post_bytes(&mint, req.encode());
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
        let (code, body) = esp_post_bytes(&mint, twin.encode());
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
    let w = esp_get_json(&mint, "/rotation");
    assert_ne!(w["previous"]["id"], id0.as_str(), "generation 0 is deleted");
    let (code, body) = esp_post_bytes(&mint, req.encode());
    // the caller reads the mint's files, and starts the next mint
    mint.air = None;
    rt.shutdown_background();
    (code, body, mint, a.0)
}

/// Spent in generation 0 while it is the previous set.
fn is_spent_prev(mint: &Mint, note: &Note) -> bool {
    let rotor = mint.state.rotor.lock().unwrap();
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
    // from the spent list and saved it in retired.json; the retry finishes, and
    // the proof is dropped with it.
    let (code, body, mint, _) = redeem_after_retirement("rproof-crash", true, false);
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["entry"]["status"], "open", "{body}");
    assert_eq!(retired_proofs(&mint), serde_json::json!({}), "{body}");

    // (c) Crashed before the burn: nothing proves it, refused, nothing signed.
    let (code, body, mint, note) = redeem_after_retirement("rproof-none", false, false);
    assert_eq!(
        (code, body["code"].as_str()),
        (400, Some("burn_not_proven")),
        "{body}"
    );
    let nonce = hex::encode(note.nonce.0.serialize());
    assert!(!retired_proofs(&mint).to_string().contains(&nonce));
}

#[test]
fn a_rollover_over_the_configured_note_count_is_refused_and_nothing_is_burned() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("rollover-count");
    let mint = start_rotating_with(&rt, &dir, |c| c.rollover_max_items = 1);
    let a = esp_note(&mint, ONE, service(), PAST);
    let b = esp_note(&mint, ONE, service(), PAST);
    let mut rq = rollover_req(&a, ONE, ONE);
    let (o, _, _) = blinded(ONE);
    rq.outputs.push(o);
    rq.inputs.push(MintInput {
        amount: Amount::from_units(ONE),
        note: b.0,
        spend_signature: Signature::from_slice(&[0u8; 64]).unwrap(),
    });
    rq.input_keysets.push(in_ks());
    let d = rq.digest();
    rq.inputs[0].spend_signature = SECP256K1.sign_schnorr(&d, &a.1);
    rq.inputs[1].spend_signature = SECP256K1.sign_schnorr(&d, &b.1);
    let (code, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&rq).unwrap());
    assert_eq!(code, 400, "{body}");
    assert!(body.to_string().contains("1 to 1 notes"), "{body}");
    // the notes are still good: a rollover of one of them goes through
    let one = rollover_req(&a, ONE, ONE);
    let (code, body) = esp_post_json(&mint, "/rollover", &serde_json::to_value(&one).unwrap());
    assert_eq!(code, 200, "{body}");
    std::fs::remove_dir_all(&dir).unwrap();
}
