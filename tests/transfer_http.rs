//! The transfer over HTTP, end to end: an ESP server with its own mint, and a
//! service that signs, sends and unblinds the way the wallet does.
//!
//! A transfer never calls the PSP, so the PSP stand-in here refuses every call.
//! These are plain tests with their own runtime, because they use the blocking
//! HTTP client.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Router;
use esp_mint::exchange::{Burn, Psp};
use esp_mint::responses::Responses;
use esp_mint::server::{self, EspState};
use esp_mint::terms::Terms;
use esp_mint::transfer::{self, TransferRequest, TransferResponse};
use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note};
use rand::rngs::OsRng;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, SECP256K1, SecretKey, XOnlyPublicKey};
use tokio::runtime::Runtime;

const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// A test note size, a power of two (about 0.7 PSP).
const ONE_PSP: u64 = 1 << 36;
const NOW: u64 = 1_791_571_184;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("esp-mint-trhttp-{}-{name}", {
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

fn day() -> u64 {
    Terms::new_at(service(), NOW).redeemable_after_day
}

struct NoPsp;

impl Psp for NoPsp {
    fn melt(&self, _inputs: &[MintInput], _memo: &str) -> Result<Amount, String> {
        Err("a transfer does not use the PSP".into())
    }

    fn burns(&self, _nonces: &[Nonce]) -> Result<Vec<Burn>, String> {
        Err("a transfer does not use the PSP".into())
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

thread_local! {
    /// The mint's keyset, which the requests name (set by `start_esp`).
    static KS: std::cell::RefCell<String> = Default::default();
}

fn ks() -> String {
    KS.with(|k| k.borrow().clone())
}

fn start_esp(rt: &Runtime, dir: &Path) -> (String, Arc<EspState>) {
    let (logic, master) = esp_mint::mint::open(&dir.join("esp")).unwrap();
    KS.with(|k| *k.borrow_mut() = esp_mint::rotation::keyset_id(&master));
    let responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
    let state = Arc::new(EspState {
        logic: Mutex::new(logic),
        master,
        psp: Box::new(NoPsp),
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

/// An ESP note the mint has issued for `service` and the test day.
fn esp_note(state: &EspState, units: u64, service: XOnlyPublicKey) -> (Note, Keypair) {
    let terms = Terms {
        service,
        redeemable_after_day: day(),
    };
    let keypair = Keypair::new(SECP256K1, &mut OsRng);
    let nonce = Nonce(keypair.public_key());
    let (blind_point, blinding_key) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
    let amount = Amount::from_units(units);
    let sk = state.master.key_for(amount, &terms);
    let logic = state.logic.lock().unwrap();
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

/// A transfer request for the service `G_X`, signed by `service_signer`. Each
/// amount in `out_amounts` is a total, split into powers of two.
fn request(
    notes: &[(Note, &Keypair, u64)],
    out_amounts: &[u64],
    service_signer: &Keypair,
) -> (TransferRequest, Vec<Wanted>) {
    let amounts: Vec<u64> = out_amounts.iter().flat_map(|&a| split(a)).collect();
    request_exact(notes, &amounts, service_signer)
}

/// Like `request`, but each output is as it stands, whatever it is.
fn request_exact(
    notes: &[(Note, &Keypair, u64)],
    out_amounts: &[u64],
    service_signer: &Keypair,
) -> (TransferRequest, Vec<Wanted>) {
    let mut wanted = Vec::new();
    let mut outputs = Vec::new();
    for &amount in out_amounts {
        let keypair = Keypair::new(SECP256K1, &mut OsRng);
        let nonce = Nonce(keypair.public_key());
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
    let dummy = Signature::from_slice(&[0u8; 64]).unwrap();
    let mut inputs: Vec<MintInput> = notes
        .iter()
        .map(|(note, _, units)| MintInput {
            amount: Amount::from_units(*units),
            note: *note,
            spend_signature: dummy,
        })
        .collect();
    let sighash = transfer::digest(&service(), day(), &inputs, &outputs);
    for (input, (_, keypair, _)) in inputs.iter_mut().zip(notes) {
        input.spend_signature = SECP256K1.sign_schnorr(&sighash, keypair);
    }
    let service_signature = SECP256K1.sign_schnorr(&sighash, service_signer);
    (
        TransferRequest {
            service: service(),
            redeemable_after_day: day(),
            input_keysets: vec![ks(); inputs.len()],
            inputs,
            keyset: ks(),
            outputs,
            service_signature,
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

fn is_spent(state: &EspState, note: &Note) -> bool {
    state.logic.lock().unwrap().is_spent(note.nonce).unwrap()
}

#[test]
fn a_transfer_over_http_swaps_the_notes_and_the_supply_does_not_change() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("happy");
    let (esp, state) = start_esp(&rt, &dir);

    let (a, ka) = esp_note(&state, 2 * ONE_PSP, service());
    let (b, kb) = esp_note(&state, ONE_PSP, service());
    let audit = get_json(&esp, "/audit").1;
    assert_eq!(audit["issued"], 3 * ONE_PSP);
    assert_eq!(audit["outstanding"], 3 * ONE_PSP);

    let (req, wanted) = request(
        &[(a, &ka, 2 * ONE_PSP), (b, &kb, ONE_PSP)],
        &[ONE_PSP, 2 * ONE_PSP],
        &service_keypair(),
    );
    let (code, body) = post_json(&esp, "/transfer", &req);
    assert_eq!(code, 200, "{body}");
    let response: TransferResponse = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(response.service, service());
    assert_eq!(response.redeemable_after_day, day());
    assert_eq!(response.keyset, ks(), "the reply names the set that signed");
    let (_, sets) = get_json(&esp, "/keysets");
    assert_eq!(sets["current"], ks().as_str());
    assert!(sets["previous"].is_null());

    // the new notes verify under the keys derived for the same terms
    let terms = Terms {
        service: service(),
        redeemable_after_day: day(),
    };
    for (i, w) in wanted.iter().enumerate() {
        let sk = state.master.key_for(Amount::from_units(w.amount), &terms);
        assert_eq!(response.keys[i], sk.public_key(SECP256K1));
        let unblinded =
            bdhke::unblind_message(&response.signatures[i], &w.blinding_key, &response.keys[i]);
        assert!(bdhke::verify_message(
            &sk,
            unblinded,
            &w.nonce.as_hash_preimage()
        ));
    }

    // the old notes are spent, and nothing was created or destroyed
    assert!(is_spent(&state, &a) && is_spent(&state, &b));
    let audit = get_json(&esp, "/audit").1;
    assert_eq!(audit["issued"], 6 * ONE_PSP);
    assert_eq!(audit["redeemed"], 3 * ONE_PSP);
    assert_eq!(audit["outstanding"], 3 * ONE_PSP);

    // the same request again returns the same response and changes nothing
    let (code, again) = post_json(&esp, "/transfer", &req);
    assert_eq!(code, 200);
    assert_eq!(again, body);
    assert_eq!(get_json(&esp, "/audit").1["issued"], 6 * ONE_PSP);

    assert_eq!(get_json(&esp, "/health").0, 200);
    rt.shutdown_background();
}

#[test]
fn an_inexact_transfer_is_a_400_and_the_notes_survive() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("inexact");
    let (esp, state) = start_esp(&rt, &dir);

    let (a, ka) = esp_note(&state, ONE_PSP, service());
    let (req, _) = request(&[(a, &ka, ONE_PSP)], &[ONE_PSP + 1], &service_keypair());
    let (code, body) = post_json(&esp, "/transfer", &req);
    assert_eq!(code, 400, "{body}");
    assert!(body["error"].as_str().unwrap().contains("must be exact"));
    assert!(!is_spent(&state, &a));
    let audit = get_json(&esp, "/audit").1;
    assert_eq!(audit["issued"], ONE_PSP);
    assert_eq!(audit["redeemed"], 0);
    rt.shutdown_background();
}

#[test]
fn an_amount_that_is_not_a_power_of_two_is_a_400_and_the_notes_survive() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("denomination");
    let (esp, state) = start_esp(&rt, &dir);

    let (a, ka) = esp_note(&state, 2 * ONE_PSP, service());
    // an output that is not a power of two, though the total is exact
    let (req, _) = request_exact(
        &[(a, &ka, 2 * ONE_PSP)],
        &[ONE_PSP + 1, ONE_PSP - 1],
        &service_keypair(),
    );
    let (code, body) = post_json(&esp, "/transfer", &req);
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "bad_denomination");
    assert_eq!(
        body["error"],
        "output 0: ESP amounts are powers of two. Nothing was burned"
    );
    assert!(!is_spent(&state, &a));

    // an incoming note of an odd size is refused the same way
    let odd = ONE_PSP + 5;
    let (b, kb) = esp_note(&state, odd, service());
    let (req, _) = request(&[(b, &kb, odd)], &[odd], &service_keypair());
    let (code, body) = post_json(&esp, "/transfer", &req);
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["code"], "bad_denomination");
    assert_eq!(
        body["error"],
        "note 0: ESP amounts are powers of two. Nothing was burned"
    );
    assert!(!is_spent(&state, &b));
    let audit = get_json(&esp, "/audit").1;
    assert_eq!(audit["redeemed"], 0);

    // the same total split into powers of two goes through
    let (req, _) = request(
        &[(a, &ka, 2 * ONE_PSP)],
        &[ONE_PSP + 1, ONE_PSP - 1],
        &service_keypair(),
    );
    let (code, body) = post_json(&esp, "/transfer", &req);
    assert_eq!(code, 200, "{body}");
    assert!(is_spent(&state, &a));
    rt.shutdown_background();
}

#[test]
fn a_request_the_service_did_not_sign_is_a_400() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("unsigned");
    let (esp, state) = start_esp(&rt, &dir);

    let (a, ka) = esp_note(&state, ONE_PSP, service());
    // the app holds the note's spend key but not the service's key
    let (req, _) = request(&[(a, &ka, ONE_PSP)], &[ONE_PSP], &other_keypair());
    let (code, body) = post_json(&esp, "/transfer", &req);
    assert_eq!(code, 400, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("service's signature")
    );
    assert!(!is_spent(&state, &a));
    rt.shutdown_background();
}

#[test]
fn a_note_cannot_be_transferred_twice() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("twice");
    let (esp, state) = start_esp(&rt, &dir);

    let (a, ka) = esp_note(&state, ONE_PSP, service());
    let (first, _) = request(&[(a, &ka, ONE_PSP)], &[ONE_PSP], &service_keypair());
    assert_eq!(post_json(&esp, "/transfer", &first).0, 200);
    let (second, _) = request(&[(a, &ka, ONE_PSP)], &[ONE_PSP], &service_keypair());
    let (code, body) = post_json(&esp, "/transfer", &second);
    assert_eq!(code, 400, "{body}");
    assert!(body["error"].as_str().unwrap().contains("already spent"));
    // the body names the spent input, for the wallet
    assert_eq!(body["code"], "note_spent_elsewhere");
    assert_eq!(body["spent"], serde_json::json!([0]));
    // only the first transfer changed the totals
    let audit = get_json(&esp, "/audit").1;
    assert_eq!(audit["issued"], 2 * ONE_PSP);
    assert_eq!(audit["redeemed"], ONE_PSP);
    rt.shutdown_background();
}

#[test]
fn one_spent_input_among_several_leaves_the_others_unburned() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("partial");
    let (esp, state) = start_esp(&rt, &dir);

    let (a, ka) = esp_note(&state, ONE_PSP, service());
    let (b, kb) = esp_note(&state, ONE_PSP, service());
    let (c, kc) = esp_note(&state, ONE_PSP, service());
    let (first, _) = request(&[(a, &ka, ONE_PSP)], &[ONE_PSP], &service_keypair());
    assert_eq!(post_json(&esp, "/transfer", &first).0, 200);
    // Three notes, the second already spent: refused whole.
    let (all, _) = request(
        &[(b, &kb, ONE_PSP), (a, &ka, ONE_PSP), (c, &kc, ONE_PSP)],
        &[3 * ONE_PSP],
        &service_keypair(),
    );
    let (code, body) = post_json(&esp, "/transfer", &all);
    assert_eq!(code, 400, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("note 1 is already spent"),
        "{body}"
    );
    assert!(is_spent(&state, &a));
    assert!(!is_spent(&state, &b));
    assert!(!is_spent(&state, &c));
    let audit = get_json(&esp, "/audit").1;
    assert_eq!(audit["issued"], 4 * ONE_PSP);
    assert_eq!(audit["redeemed"], ONE_PSP);
    rt.shutdown_background();
}

#[test]
fn a_transfer_naming_no_keyset_or_an_unknown_one_is_a_400_and_nothing_is_burned() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("keysets");
    let (esp, state) = start_esp(&rt, &dir);
    let (a, ka) = esp_note(&state, ONE_PSP, service());
    let (req, _) = request(&[(a, &ka, ONE_PSP)], &[ONE_PSP], &service_keypair());

    let mut missing = req.clone();
    missing.keyset = String::new();
    let (code, body) = post_json(&esp, "/transfer", &missing);
    assert_eq!(
        (code, body["code"].as_str()),
        (400, Some("missing_keyset")),
        "{body}"
    );

    let mut unknown = req.clone();
    unknown.input_keysets = vec!["ab".repeat(8)];
    let (code, body) = post_json(&esp, "/transfer", &unknown);
    assert_eq!(
        (code, body["code"].as_str()),
        (400, Some("unknown_keyset")),
        "{body}"
    );

    let mut unknown_out = req.clone();
    unknown_out.keyset = "cd".repeat(8);
    let (code, body) = post_json(&esp, "/transfer", &unknown_out);
    assert_eq!(
        (code, body["code"].as_str()),
        (400, Some("unknown_keyset")),
        "{body}"
    );

    assert!(!is_spent(&state, &a), "nothing was burned");
    let (code, _) = post_json(&esp, "/transfer", &req);
    assert_eq!(code, 200);
    rt.shutdown_background();
}

#[test]
fn a_transfer_moves_nothing_between_the_parts_of_the_audit_split() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("split");
    let (esp, state) = start_esp(&rt, &dir);
    // Notes minted straight from the mint are not in the ledger (as the notes of
    // a mint from before 0.5.0 are not), so all of it is outstanding and unsplit.
    let (a, ka) = esp_note(&state, 2 * ONE_PSP, service());
    let split = |audit: &serde_json::Value| {
        (
            audit["outstanding"].as_u64().unwrap(),
            audit["outstanding_matured"].as_u64().unwrap(),
            audit["outstanding_unmatured"].as_u64().unwrap(),
            audit["outstanding_unsplit"].as_u64().unwrap(),
            audit["requests_unfinished"].as_u64().unwrap(),
        )
    };
    let before = get_json(&esp, "/audit").1;
    assert_eq!(split(&before), (2 * ONE_PSP, 0, 0, 2 * ONE_PSP, 0));

    let (req, _) = request(
        &[(a, &ka, 2 * ONE_PSP)],
        &[ONE_PSP, ONE_PSP],
        &service_keypair(),
    );
    let (code, body) = post_json(&esp, "/transfer", &req);
    assert_eq!(code, 200, "{body}");

    // The transfer is net zero for its day, so the split does not move, and the
    // same request again changes nothing.
    assert_eq!(
        split(&get_json(&esp, "/audit").1),
        (2 * ONE_PSP, 0, 0, 2 * ONE_PSP, 0)
    );
    assert_eq!(post_json(&esp, "/transfer", &req), (200, body));
    assert_eq!(
        split(&get_json(&esp, "/audit").1),
        (2 * ONE_PSP, 0, 0, 2 * ONE_PSP, 0)
    );
    rt.shutdown_background();
}
