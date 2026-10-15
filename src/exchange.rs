//! The PSP-to-ESP exchange.
//!
//! A wallet sends PSP notes and blinded ESP outputs. The mint checks the
//! request, burns the PSP notes at the PSP's `/melt`, and signs the outputs
//! under keys derived for the service and the redeemable-after day. There is no
//! mint fee. The date is set by the mint (the day of issue plus 365), never by
//! the requester.
//!
//! Order of events, and why it is safe to retry at any point:
//!
//! 1. Check the request. Nothing is written yet, and the PSP notes and the ESP
//!    blind nonces must be unused.
//! 2. Check the spend signatures, which are public. This is what proves the
//!    holder authorized exactly this request, because they cover the memo.
//! 3. Write a `pending` entry under the request hash.
//! 4. Burn the PSP notes.
//! 5. Sign the outputs and write a `done` entry.
//!
//! A retry of a done request returns the stored response. A retry of a pending
//! request starts again from step 4: if the PSP notes are already spent it
//! skips the burn, and outputs that were already issued are signed again
//! (signing is deterministic) instead of failing.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use mint_core::MintLogic;
use mint_types::{Amount, MintInput, MintOutput, MintOutputError, Nonce, melt_sighash};
use secp256k1::{PublicKey, SECP256K1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keys::MasterSecret;
use crate::responses::{Entry, Responses};
use crate::terms::Terms;
use crate::units::{self, ESP_PER_PSP};

/// The most inputs, and the most outputs, in one request.
pub const MAX_ITEMS: usize = 1000;

const MEMO_TAG: &[u8] = b"esp-mint/exchange/v1";
const REQUEST_TAG: &[u8] = b"esp-mint/exchange-request/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeRequest {
    /// The service that alone may redeem the new notes (its DID key, x-only).
    pub service: XOnlyPublicKey,
    /// PSP notes, each with a spend signature over the memo's melt digest.
    pub psp_inputs: Vec<MintInput>,
    /// The ESP notes wanted, blinded. Any non-zero amount.
    pub outputs: Vec<MintOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangeResponse {
    pub service: XOnlyPublicKey,
    pub redeemable_after_day: u64,
    /// One blind signature per output, in the request's order.
    pub signatures: Vec<PublicKey>,
    /// The public key each output was signed with, for unblinding.
    pub keys: Vec<PublicKey>,
    /// ESP units recorded as credit because the PSP notes were worth 10% or
    /// more over the outputs. Zero otherwise.
    pub credit_esp: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    NoInputs,
    NoOutputs,
    TooManyItems,
    ZeroAmount,
    DuplicateInput,
    DuplicateBlindNonce,
    BlindNonceAlreadyUsed,
    Overflow,
    /// The PSP notes are worth less than the outputs.
    Underpaid { paid: u128, requested: u128 },
    /// A spend signature does not cover this request.
    BadSpendSignature,
    /// A PSP note is already spent.
    PspNoteSpent,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rejection::NoInputs => write!(f, "no PSP notes"),
            Rejection::NoOutputs => write!(f, "no outputs"),
            Rejection::TooManyItems => write!(f, "more than {MAX_ITEMS} notes or outputs"),
            Rejection::ZeroAmount => write!(f, "an output has amount zero"),
            Rejection::DuplicateInput => write!(f, "a PSP note is listed twice"),
            Rejection::DuplicateBlindNonce => write!(f, "an output blind nonce is listed twice"),
            Rejection::BlindNonceAlreadyUsed => write!(f, "an output blind nonce was already used"),
            Rejection::Overflow => write!(f, "amounts are too large"),
            Rejection::Underpaid { paid, requested } => write!(
                f,
                "PSP notes are worth {paid} ESP units but the outputs total {requested}"
            ),
            Rejection::BadSpendSignature => {
                write!(f, "a spend signature does not cover this request")
            }
            Rejection::PspNoteSpent => write!(f, "a PSP note is already spent"),
        }
    }
}

#[derive(Debug)]
pub enum ExchangeError {
    /// The request is refused. Nothing was burned.
    Rejected(Rejection),
    /// The PSP could not be reached or refused the burn. A retry is safe.
    Psp(String),
    /// A fault in the mint. A retry is safe.
    Internal(String),
}

impl fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExchangeError::Rejected(r) => write!(f, "rejected: {r}"),
            ExchangeError::Psp(e) => write!(f, "PSP: {e}"),
            ExchangeError::Internal(e) => write!(f, "internal: {e}"),
        }
    }
}

impl Error for ExchangeError {}

impl From<Rejection> for ExchangeError {
    fn from(r: Rejection) -> Self {
        ExchangeError::Rejected(r)
    }
}

fn internal<E: ToString>(e: E) -> ExchangeError {
    ExchangeError::Internal(e.to_string())
}

/// What the ESP mint needs from the PSP. `HttpPsp` is the real one.
pub trait Psp {
    /// Burn the notes, bound to `memo`. Returns the PSP units burned.
    fn melt(&self, inputs: &[MintInput], memo: &str) -> Result<Amount, String>;
    /// Whether each nonce is spent, in order.
    fn spent(&self, nonces: &[Nonce]) -> Result<Vec<bool>, String>;
}

/// The memo the PSP burn is bound to:
/// `hex(SHA-256("esp-mint/exchange/v1" || service || each output's amount and blind nonce))`.
pub fn memo(service: &XOnlyPublicKey, outputs: &[MintOutput]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MEMO_TAG);
    hasher.update(service.serialize());
    for output in outputs {
        hasher.update(output.amount.units.to_be_bytes());
        hasher.update(output.blind_nonce.0.serialize());
    }
    hex::encode(hasher.finalize())
}

/// The key a request is stored under. It covers the memo and every input,
/// spend signatures included, so a request with different inputs never gets
/// another request's stored response.
pub fn request_hash(request: &ExchangeRequest) -> Result<String, ExchangeError> {
    let inputs = serde_json::to_vec(&request.psp_inputs).map_err(internal)?;
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_TAG);
    hasher.update(memo(&request.service, &request.outputs).as_bytes());
    hasher.update((inputs.len() as u64).to_be_bytes());
    hasher.update(&inputs);
    Ok(hex::encode(hasher.finalize()))
}

/// The credit for a request: the excess of what was paid over what was
/// requested if it is 10% or more of the request, otherwise zero (the mint
/// keeps a smaller excess). Less than requested is an error.
pub fn assess(paid: u128, requested: u128) -> Result<u128, Rejection> {
    if paid < requested {
        return Err(Rejection::Underpaid { paid, requested });
    }
    let excess = paid - requested;
    let ten_times = excess.checked_mul(10).ok_or(Rejection::Overflow)?;
    Ok(if ten_times >= requested { excess } else { 0 })
}

struct Plan {
    credit: u128,
}

fn validate(request: &ExchangeRequest) -> Result<Plan, Rejection> {
    if request.psp_inputs.is_empty() {
        return Err(Rejection::NoInputs);
    }
    if request.outputs.is_empty() {
        return Err(Rejection::NoOutputs);
    }
    if request.psp_inputs.len() > MAX_ITEMS || request.outputs.len() > MAX_ITEMS {
        return Err(Rejection::TooManyItems);
    }
    let mut nonces = HashSet::new();
    for input in &request.psp_inputs {
        if !nonces.insert(input.note.nonce) {
            return Err(Rejection::DuplicateInput);
        }
    }
    let mut blind_nonces = HashSet::new();
    for output in &request.outputs {
        if output.amount.units == 0 {
            return Err(Rejection::ZeroAmount);
        }
        if !blind_nonces.insert(output.blind_nonce) {
            return Err(Rejection::DuplicateBlindNonce);
        }
    }
    let psp_total = units::total(request.psp_inputs.iter().map(|i| i.amount.units));
    let paid = psp_total
        .checked_mul(u128::from(ESP_PER_PSP))
        .ok_or(Rejection::Overflow)?;
    let requested = units::total(request.outputs.iter().map(|o| o.amount.units));
    Ok(Plan {
        credit: assess(paid, requested)?,
    })
}

/// Run an exchange. `now_unix` sets the redeemable-after day for a new request.
pub fn exchange(
    logic: &MintLogic,
    master: &MasterSecret,
    psp: &dyn Psp,
    responses: &mut Responses,
    now_unix: u64,
    request: &ExchangeRequest,
) -> Result<ExchangeResponse, ExchangeError> {
    let plan = validate(request)?;
    let hash = request_hash(request)?;
    let memo = memo(&request.service, &request.outputs);
    let nonces: Vec<Nonce> = request.psp_inputs.iter().map(|i| i.note.nonce).collect();

    let (redeemable_after_day, recovering) = match responses.get(&hash) {
        Some(Entry::Done(done)) => return Ok(done.clone()),
        Some(Entry::Pending {
            redeemable_after_day,
            ..
        }) => (*redeemable_after_day, true),
        None => (
            Terms::new_at(request.service, now_unix).redeemable_after_day,
            false,
        ),
    };
    let terms = Terms {
        service: request.service,
        redeemable_after_day,
    };

    let psp_total = units::total(request.psp_inputs.iter().map(|i| i.amount.units));

    if !recovering {
        for output in &request.outputs {
            if logic
                .is_blind_nonce_used(&output.blind_nonce)
                .map_err(internal)?
            {
                return Err(Rejection::BlindNonceAlreadyUsed.into());
            }
        }
        // The spend signatures are public to check. They cover the memo, so a
        // pending entry only ever exists for a request its holder signed.
        let sighash = melt_sighash(&request.psp_inputs, memo.as_bytes());
        for input in &request.psp_inputs {
            if logic.verify_spend_authorization(input, sighash).is_err() {
                return Err(Rejection::BadSpendSignature.into());
            }
        }
        let spent = psp_spent(psp, &nonces)?;
        if spent.iter().any(|s| *s) {
            return Err(Rejection::PspNoteSpent.into());
        }
        responses
            .put(
                &hash,
                Entry::Pending {
                    redeemable_after_day,
                    credit_esp: plan.credit,
                },
            )
            .map_err(internal)?;
        burn(psp, request, &memo, psp_total)?;
    } else {
        let spent = psp_spent(psp, &nonces)?;
        if spent.iter().all(|s| *s) {
            // already burned by an earlier attempt
        } else if spent.iter().any(|s| *s) {
            return Err(ExchangeError::Internal(
                "some PSP notes are spent and some are not, which needs a person to look".into(),
            ));
        } else {
            burn(psp, request, &memo, psp_total)?;
        }
    }

    let mut signatures = Vec::with_capacity(request.outputs.len());
    let mut keys = Vec::with_capacity(request.outputs.len());
    for output in &request.outputs {
        let sk = master.key_for(output.amount, &terms);
        let signature = match logic.issue_with_key(&sk, output) {
            Ok(outcome) => outcome.0,
            // Issued by an earlier attempt that stopped part way. Signing is
            // deterministic, so the same signature comes back.
            Err(MintOutputError::BlindNonceAlreadyUsed) if recovering => {
                bdhke::sign_message(&sk, &output.blind_nonce.0)
            }
            Err(e) => return Err(internal(e)),
        };
        keys.push(sk.public_key(SECP256K1));
        signatures.push(signature);
    }

    let response = ExchangeResponse {
        service: request.service,
        redeemable_after_day,
        signatures,
        keys,
        credit_esp: plan.credit,
    };
    responses
        .put(&hash, Entry::Done(response.clone()))
        .map_err(internal)?;
    Ok(response)
}

fn psp_spent(psp: &dyn Psp, nonces: &[Nonce]) -> Result<Vec<bool>, ExchangeError> {
    let spent = psp.spent(nonces).map_err(ExchangeError::Psp)?;
    if spent.len() != nonces.len() {
        return Err(ExchangeError::Psp(
            "the PSP answered for a different number of notes".into(),
        ));
    }
    Ok(spent)
}

fn burn(
    psp: &dyn Psp,
    request: &ExchangeRequest,
    memo: &str,
    expected_psp_units: u128,
) -> Result<(), ExchangeError> {
    let burned = psp
        .melt(&request.psp_inputs, memo)
        .map_err(ExchangeError::Psp)?;
    if u128::from(burned.units) != expected_psp_units {
        return Err(ExchangeError::Psp(format!(
            "the PSP burned {burned} units, expected {expected_psp_units}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;
    use std::path::PathBuf;

    use mint_core::keygen;
    use mint_core::store::Store;
    use mint_types::{BlindNonce, Note, gen_denominations};
    use rand::rngs::OsRng;
    use secp256k1::{Keypair, SecretKey};

    const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const NOW: u64 = 1_791_571_184;
    const ONE_PSP: u64 = 1_000_000_000_000;

    fn service() -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(&hex::decode(G_X).unwrap()).unwrap()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("esp-mint-ex-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A PSP mint in process, standing in for the HTTP one.
    struct FakePsp {
        logic: MintLogic,
        melts: Cell<u32>,
        fail_after_burn: Cell<bool>,
    }

    impl FakePsp {
        fn new(dir: &PathBuf) -> Self {
            let cfg = keygen::generate(&gen_denominations(2, Amount::from_units(1024)));
            let store = Store::open(&dir.join("psp-db")).unwrap();
            FakePsp {
                logic: MintLogic::new(cfg, store),
                melts: Cell::new(0),
                fail_after_burn: Cell::new(false),
            }
        }

        /// A PSP note of `units`, and the key that spends it.
        fn note(&self, units: u64) -> (Note, Keypair) {
            let keypair = Keypair::new(SECP256K1, &mut OsRng);
            let nonce = Nonce(keypair.public_key());
            let (blind_point, blinding_key) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
            let amount = Amount::from_units(units);
            let outcome = self
                .logic
                .issue(&MintOutput {
                    amount,
                    blind_nonce: BlindNonce(blind_point),
                })
                .unwrap();
            let signature =
                bdhke::unblind_message(&outcome.0, &blinding_key, &self.logic.public_keys()[&amount]);
            (Note { nonce, signature }, keypair)
        }
    }

    impl Psp for FakePsp {
        fn melt(&self, inputs: &[MintInput], memo: &str) -> Result<Amount, String> {
            self.melts.set(self.melts.get() + 1);
            let burned = self
                .logic
                .melt(inputs, memo.as_bytes())
                .map_err(|e| e.to_string())?;
            if self.fail_after_burn.get() {
                return Err("timed out".into());
            }
            Ok(burned)
        }

        fn spent(&self, nonces: &[Nonce]) -> Result<Vec<bool>, String> {
            nonces
                .iter()
                .map(|n| self.logic.is_spent(*n).map_err(|e| e.to_string()))
                .collect()
        }
    }

    struct Wanted {
        nonce: Nonce,
        blinding_key: SecretKey,
        amount: u64,
    }

    /// Build a request the way a wallet does. `psp_notes` are (note, key,
    /// units). `signer` signs the spend signatures, normally the note's own key.
    fn build(
        psp_notes: &[(Note, &Keypair, u64)],
        esp_amounts: &[u64],
        signer: Option<&Keypair>,
    ) -> (ExchangeRequest, Vec<Wanted>) {
        let mut wanted = Vec::new();
        let mut outputs = Vec::new();
        for &amount in esp_amounts {
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
        let dummy = secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap();
        let mut inputs: Vec<MintInput> = psp_notes
            .iter()
            .map(|(note, _, units)| MintInput {
                amount: Amount::from_units(*units),
                note: *note,
                spend_signature: dummy,
            })
            .collect();
        let sighash = melt_sighash(&inputs, memo(&service(), &outputs).as_bytes());
        for (input, (_, keypair, _)) in inputs.iter_mut().zip(psp_notes) {
            input.spend_signature = SECP256K1.sign_schnorr(&sighash, signer.unwrap_or(*keypair));
        }
        (
            ExchangeRequest {
                service: service(),
                psp_inputs: inputs,
                outputs,
            },
            wanted,
        )
    }

    struct Setup {
        dir: PathBuf,
        psp: FakePsp,
        logic: MintLogic,
        master: MasterSecret,
        responses: Responses,
    }

    fn setup(name: &str) -> Setup {
        let dir = scratch(name);
        let psp = FakePsp::new(&dir);
        let (logic, master) = crate::mint::open(&dir.join("esp")).unwrap();
        let responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
        Setup {
            dir,
            psp,
            logic,
            master,
            responses,
        }
    }

    impl Setup {
        fn run(&mut self, request: &ExchangeRequest) -> Result<ExchangeResponse, ExchangeError> {
            exchange(
                &self.logic,
                &self.master,
                &self.psp,
                &mut self.responses,
                NOW,
                request,
            )
        }

        fn esp_issued(&self) -> u64 {
            self.logic.audit_totals().unwrap().0.units
        }
    }

    fn rejection(result: Result<ExchangeResponse, ExchangeError>) -> Rejection {
        match result {
            Err(ExchangeError::Rejected(r)) => r,
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    #[test]
    fn one_psp_buys_the_esp_and_the_signatures_verify() {
        let mut s = setup("happy");
        let (note, keypair) = s.psp.note(1);
        let (request, wanted) = build(&[(note, &keypair, 1)], &[ONE_PSP / 2, ONE_PSP / 2], None);
        let response = s.run(&request).unwrap();

        assert_eq!(response.service, service());
        assert_eq!(response.redeemable_after_day, NOW / 86_400 + 365);
        assert_eq!(response.credit_esp, 0);
        assert_eq!(s.esp_issued(), ONE_PSP);
        assert!(s.psp.logic.is_spent(note.nonce).unwrap());

        let terms = Terms {
            service: service(),
            redeemable_after_day: response.redeemable_after_day,
        };
        for (i, w) in wanted.iter().enumerate() {
            let sk = s.master.key_for(Amount::from_units(w.amount), &terms);
            assert_eq!(response.keys[i], sk.public_key(SECP256K1));
            let unblinded =
                bdhke::unblind_message(&response.signatures[i], &w.blinding_key, &response.keys[i]);
            assert!(bdhke::verify_message(&sk, unblinded, &w.nonce.as_hash_preimage()));
        }
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_retry_gets_the_same_response_and_burns_nothing_more() {
        let mut s = setup("retry");
        let (note, keypair) = s.psp.note(2);
        let (request, _) = build(&[(note, &keypair, 2)], &[2 * ONE_PSP], None);
        let first = s.run(&request).unwrap();
        let again = s.run(&request).unwrap();
        assert_eq!(first, again);
        assert_eq!(s.psp.melts.get(), 1);
        assert_eq!(s.esp_issued(), 2 * ONE_PSP);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_retry_still_works_after_the_mint_restarts() {
        let mut s = setup("restart");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let first = s.run(&request).unwrap();
        s.responses = Responses::open(&s.dir.join("esp").join("responses.json")).unwrap();
        assert_eq!(s.run(&request).unwrap(), first);
        assert_eq!(s.psp.melts.get(), 1);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_lost_burn_reply_is_recovered_without_burning_twice() {
        let mut s = setup("recover");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);

        // The PSP burns the note but the reply is lost.
        s.psp.fail_after_burn.set(true);
        assert!(matches!(s.run(&request), Err(ExchangeError::Psp(_))));
        assert!(s.psp.logic.is_spent(note.nonce).unwrap());
        assert_eq!(s.esp_issued(), 0);
        let hash = request_hash(&request).unwrap();
        assert!(matches!(
            s.responses.get(&hash),
            Some(Entry::Pending { .. })
        ));

        // The retry sees the note burned, skips the burn and issues.
        s.psp.fail_after_burn.set(false);
        let response = s.run(&request).unwrap();
        assert_eq!(s.psp.melts.get(), 1);
        assert_eq!(s.esp_issued(), ONE_PSP);
        assert_eq!(response.signatures.len(), 1);
        assert!(matches!(s.responses.get(&hash), Some(Entry::Done(_))));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_recovered_exchange_keeps_the_original_day() {
        let mut s = setup("recover-day");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        s.psp.fail_after_burn.set(true);
        let _ = s.run(&request);
        s.psp.fail_after_burn.set(false);
        // a month later
        let later = NOW + 30 * 86_400;
        let response = exchange(
            &s.logic,
            &s.master,
            &s.psp,
            &mut s.responses,
            later,
            &request,
        )
        .unwrap();
        assert_eq!(response.redeemable_after_day, NOW / 86_400 + 365);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn issuing_already_started_is_finished_on_retry() {
        let mut s = setup("partial-issue");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP / 2, ONE_PSP / 2], None);
        s.psp.fail_after_burn.set(true);
        let _ = s.run(&request);
        // the first output was issued before the stop
        let terms = Terms::new_at(service(), NOW);
        let sk = s.master.key_for(request.outputs[0].amount, &terms);
        s.logic.issue_with_key(&sk, &request.outputs[0]).unwrap();
        s.psp.fail_after_burn.set(false);
        let response = s.run(&request).unwrap();
        assert_eq!(response.signatures.len(), 2);
        assert_eq!(s.esp_issued(), ONE_PSP);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn underpaying_is_refused_before_anything_is_burned() {
        let mut s = setup("under");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP + 1], None);
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::Underpaid {
                paid: u128::from(ONE_PSP),
                requested: u128::from(ONE_PSP) + 1
            }
        );
        assert!(!s.psp.logic.is_spent(note.nonce).unwrap());
        assert_eq!(s.psp.melts.get(), 0);
        assert!(s.responses.is_empty());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_small_excess_is_kept_and_a_large_one_is_credit() {
        let mut s = setup("excess");
        // 5% over what was asked for: kept
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP * 100 / 105], None);
        assert_eq!(s.run(&request).unwrap().credit_esp, 0);
        // twice what was asked for: the excess is credit
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP / 2], None);
        assert_eq!(s.run(&request).unwrap().credit_esp, u128::from(ONE_PSP / 2));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn the_ten_percent_boundary_is_credit() {
        assert_eq!(assess(100, 100), Ok(0));
        assert_eq!(assess(109, 100), Ok(0));
        assert_eq!(assess(110, 100), Ok(10));
        assert_eq!(assess(111, 100), Ok(11));
        assert_eq!(assess(99, 100), Err(Rejection::Underpaid { paid: 99, requested: 100 }));
    }

    #[test]
    fn a_spent_psp_note_is_refused() {
        let mut s = setup("spent");
        let (note, keypair) = s.psp.note(1);
        // burn it some other way first
        let stray = melt_input(&note, &keypair, 1, "elsewhere");
        s.psp.logic.melt(&[stray], b"elsewhere").unwrap();
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        assert_eq!(rejection(s.run(&request)), Rejection::PspNoteSpent);
        assert!(s.responses.is_empty());
        assert_eq!(s.esp_issued(), 0);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    fn melt_input(note: &Note, keypair: &Keypair, units: u64, memo: &str) -> MintInput {
        let dummy = secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap();
        let mut input = MintInput {
            amount: Amount::from_units(units),
            note: *note,
            spend_signature: dummy,
        };
        let sighash = melt_sighash(std::slice::from_ref(&input), memo.as_bytes());
        input.spend_signature = SECP256K1.sign_schnorr(&sighash, keypair);
        input
    }

    #[test]
    fn a_spend_signature_by_someone_else_is_refused_and_leaves_nothing_pending() {
        let mut s = setup("thief");
        let (note, keypair) = s.psp.note(1);
        let thief = Keypair::new(SECP256K1, &mut OsRng);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], Some(&thief));
        assert_eq!(rejection(s.run(&request)), Rejection::BadSpendSignature);
        assert!(s.responses.is_empty());
        assert_eq!(s.psp.melts.get(), 0);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_spend_signature_for_other_outputs_is_refused() {
        let mut s = setup("swapped-outputs");
        let (note, keypair) = s.psp.note(1);
        let (mut request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        // the same inputs, signed for other outputs
        let (other, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        request.outputs = other.outputs;
        assert_eq!(rejection(s.run(&request)), Rejection::BadSpendSignature);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_reused_output_blind_nonce_is_refused() {
        let mut s = setup("reuse");
        let (note, keypair) = s.psp.note(1);
        let (first, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        s.run(&first).unwrap();

        let (note2, keypair2) = s.psp.note(1);
        let (mut second, _) = build(&[(note2, &keypair2, 1)], &[ONE_PSP], None);
        second.outputs = first.outputs.clone();
        let sighash = melt_sighash(&second.psp_inputs, memo(&service(), &second.outputs).as_bytes());
        second.psp_inputs[0].spend_signature = SECP256K1.sign_schnorr(&sighash, &keypair2);
        assert_eq!(rejection(s.run(&second)), Rejection::BlindNonceAlreadyUsed);
        assert!(!s.psp.logic.is_spent(note2.nonce).unwrap());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn malformed_requests_are_refused() {
        let mut s = setup("malformed");
        let (note, keypair) = s.psp.note(1);
        let (good, _) = build(&[(note, &keypair, 1)], &[ONE_PSP / 2, ONE_PSP / 2], None);

        let mut no_inputs = good.clone();
        no_inputs.psp_inputs.clear();
        assert_eq!(rejection(s.run(&no_inputs)), Rejection::NoInputs);

        let mut no_outputs = good.clone();
        no_outputs.outputs.clear();
        assert_eq!(rejection(s.run(&no_outputs)), Rejection::NoOutputs);

        let mut zero = good.clone();
        zero.outputs[0].amount = Amount::ZERO;
        assert_eq!(rejection(s.run(&zero)), Rejection::ZeroAmount);

        let mut dup_output = good.clone();
        dup_output.outputs[1] = dup_output.outputs[0].clone();
        assert_eq!(rejection(s.run(&dup_output)), Rejection::DuplicateBlindNonce);

        let mut dup_input = good.clone();
        dup_input.psp_inputs.push(dup_input.psp_inputs[0].clone());
        assert_eq!(rejection(s.run(&dup_input)), Rejection::DuplicateInput);

        let mut many = good.clone();
        many.outputs = (0..=MAX_ITEMS)
            .map(|i| MintOutput {
                amount: Amount::from_units(1),
                blind_nonce: BlindNonce(
                    SecretKey::from_slice(&{
                        let mut b = [0u8; 32];
                        b[24..].copy_from_slice(&(i as u64 + 1).to_be_bytes());
                        b
                    })
                    .unwrap()
                    .public_key(SECP256K1),
                ),
            })
            .collect();
        assert_eq!(rejection(s.run(&many)), Rejection::TooManyItems);

        assert!(s.responses.is_empty());
        assert!(!s.psp.logic.is_spent(note.nonce).unwrap());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn amounts_at_the_u64_limit_do_not_overflow() {
        let mut s = setup("limits");
        let (note, keypair) = s.psp.note(1);
        // two outputs of u64::MAX total more than a u64, and far more than 1 PSP
        let (request, _) = build(&[(note, &keypair, 1)], &[u64::MAX, u64::MAX], None);
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::Underpaid {
                paid: u128::from(ONE_PSP),
                requested: 2 * u128::from(u64::MAX)
            }
        );
        // the largest note and the largest sum of notes still compute
        assert!(assess(units::psp_to_esp(u64::MAX), u128::from(u64::MAX)).is_ok());
        let many = units::total(std::iter::repeat(u64::MAX).take(MAX_ITEMS));
        assert_eq!(many, u128::from(u64::MAX) * MAX_ITEMS as u128);
        assert!(assess(many, many).is_ok());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_large_note_is_exchanged_in_full() {
        let mut s = setup("large");
        let (note, keypair) = s.psp.note(1024);
        let (request, _) = build(&[(note, &keypair, 1024)], &[1024 * ONE_PSP], None);
        let response = s.run(&request).unwrap();
        assert_eq!(response.credit_esp, 0);
        assert_eq!(s.esp_issued(), 1024 * ONE_PSP);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn the_request_hash_depends_on_the_inputs_and_the_memo_on_the_outputs() {
        let s = setup("hashes");
        let (note, keypair) = s.psp.note(1);
        let (a, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let (b, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        // different blinded outputs
        assert_ne!(request_hash(&a).unwrap(), request_hash(&b).unwrap());
        assert_ne!(memo(&a.service, &a.outputs), memo(&b.service, &b.outputs));
        // same outputs, different inputs
        let mut c = a.clone();
        c.psp_inputs[0].amount = Amount::from_units(2);
        assert_ne!(request_hash(&a).unwrap(), request_hash(&c).unwrap());
        assert_eq!(memo(&a.service, &a.outputs), memo(&c.service, &c.outputs));
        // stable
        assert_eq!(request_hash(&a).unwrap(), request_hash(&a.clone()).unwrap());
        assert_eq!(memo(&a.service, &a.outputs).len(), 64);
        fs::remove_dir_all(&s.dir).unwrap();
    }
}
