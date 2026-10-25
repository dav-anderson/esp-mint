//! Transfer of ESP to the service it is named for.
//!
//! An app that pays a service with ESP hands the service the notes, and with
//! them each note's spend secret. Those notes are only as good as their next
//! spend: the same notes could be handed to two services, or twice to one. So the
//! service asks the mint to swap them for fresh notes that only the service
//! holds. A note can be swapped once, which makes a second presentation fail.
//!
//! The rules:
//!
//! - **Only the named service.** The request is signed with the service's key,
//!   the key whose DID is the service ID in every note's terms. The mint checks
//!   each input against the key it derives for that amount and for the terms
//!   (that service, that day). A note named for another service, or for another
//!   day, does not verify. The outputs are signed under the same terms, so the
//!   new notes name the same service and the same redeemable-after day. An app
//!   cannot move ESP to another service or to a peer, because nothing it can sign
//!   changes whose key signs the request.
//! - **Exact.** The inputs must be worth the outputs plus the fee, summed in
//!   `u128`. Nothing is created and nothing is kept. The fee is
//!   `transfer.fee_per_byte` times the request's canonical size
//!   (`fee::transfer_size`) and is 0 by default: there is no mint fee unless the
//!   operator sets one, because the request is an AIR message and the AIR send
//!   fee covers it. If it is set, it is paid in ESP on top of the exact amount,
//!   the request is still checked as exact against that total, and the rate in
//!   force when the request was accepted is stored on the reply.
//! - **Nothing leaves circulation.** The inputs count as redeemed and the
//!   outputs as issued, by the same amount, so the outstanding total does not
//!   change.
//! - **Crash safe.** The response is stored by request hash, as for the exchange.
//!
//! Order of events, and why it is safe to retry at any point:
//!
//! 1. Check the shape of the request and the totals. Nothing is written yet.
//! 2. A stored finished response for this request hash is returned as it is.
//! 3. Check the service's signature over the digest, then each input (genuine
//!    under its derived key, spend signature over the digest), then the mint's
//!    database (an input not spent, an output blind nonce not used), then that
//!    no input or output blind nonce is held by another unfinished request.
//! 4. Write a `pending` entry that names the inputs and the blind nonces.
//! 5. Burn the inputs, then sign the outputs, then write a `done` entry.
//!
//! A retry of a pending request skips the inputs that are already burned and
//! signs again the outputs that were already issued (signing is deterministic).
//! An input can be burned only by the request that holds it, because step 3 keeps
//! every other request away from a note a pending entry names. So a burned input
//! of a pending request was always burned by that request.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use mint_types::MintOutputError;
#[cfg(test)]
use mint_types::{MintInput, MintOutput};
use secp256k1::SECP256K1;
#[cfg(test)]
use secp256k1::schnorr::Signature;
#[cfg(test)]
use sp_wire::ServiceDid;

use crate::exchange::MAX_ITEMS;
use crate::fee;
use crate::ledger::Movements;
use crate::responses::{Entry, Responses, TransferPending};
use crate::rotation::{Gens, Source};
use crate::terms::Terms;
use crate::units;

// The request type, the digest and the request hash live in sp-wire; they are
// re-exported so the paths are unchanged.
pub use sp_wire::esp::transfer::{
    TransferRequest, TransferResponse, digest, hex_signature, request_hash,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferRejection {
    NoInputs,
    NoOutputs,
    TooManyItems,
    ZeroAmount,
    /// A note or an output amount is not a power of two. Nothing was burned.
    BadDenomination {
        output: bool,
        index: usize,
    },
    DuplicateInput,
    DuplicateBlindNonce,
    BlindNonceAlreadyUsed,
    /// The inputs and the outputs do not have the same total.
    NotExact {
        inputs: u128,
        outputs: u128,
    },
    /// The mint charges a fee on this route, and the inputs do not equal the
    /// outputs plus the fee. `size_bytes` and `fee_per_byte` are what the fee was
    /// worked out from, so that the wallet can rebuild the request.
    NotExactWithFee {
        inputs: u128,
        outputs: u128,
        fee: u128,
        size_bytes: u64,
        fee_per_byte: u128,
    },
    /// The service's signature does not cover this request.
    BadServiceSignature,
    /// An input is not a genuine ESP note for this service, this day and this
    /// amount.
    BadNote {
        index: usize,
    },
    /// An input's spend signature does not cover this request.
    BadSpendSignature {
        index: usize,
    },
    /// These inputs are already spent: every one of them, in order.
    AlreadySpent {
        indexes: Vec<usize>,
    },
    /// An input or an output blind nonce is held by another transfer that has
    /// not finished.
    NoteHeld,
    /// A keyset is missing (`missing_keyset`), retired (`keyset_retired`) or
    /// not this mint's (`unknown_keyset`). Nothing was burned.
    Keyset {
        code: &'static str,
        why: String,
    },
}

impl TransferRejection {
    /// The `code` in the reply body, where the wallet acts on it.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            TransferRejection::Keyset { code, .. } => Some(code),
            TransferRejection::BadDenomination { .. } => Some(crate::units::BAD_DENOMINATION),
            _ => None,
        }
    }
}

impl fmt::Display for TransferRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferRejection::NoInputs => write!(f, "no notes to transfer"),
            TransferRejection::NoOutputs => write!(f, "no outputs"),
            TransferRejection::TooManyItems => write!(
                f,
                "more notes or outputs than one transfer may have (transfer.max_items, {MAX_ITEMS} by default)"
            ),
            TransferRejection::ZeroAmount => write!(f, "a note or an output has amount zero"),
            TransferRejection::BadDenomination { output, index } => write!(
                f,
                "{} {index}: ESP amounts are powers of two. Nothing was burned",
                if *output { "output" } else { "note" }
            ),
            TransferRejection::DuplicateInput => write!(f, "a note is listed twice"),
            TransferRejection::DuplicateBlindNonce => {
                write!(f, "an output blind nonce is listed twice")
            }
            TransferRejection::BlindNonceAlreadyUsed => {
                write!(f, "an output blind nonce was already used")
            }
            TransferRejection::NotExact { inputs, outputs } => {
                let (word, gap) = if inputs > outputs {
                    ("over", inputs - outputs)
                } else {
                    ("short", outputs - inputs)
                };
                write!(
                    f,
                    "a transfer must be exact: the notes are worth {inputs} ESP units and the outputs total {outputs}, which is {word} by {gap}. Nothing was burned"
                )
            }
            TransferRejection::NotExactWithFee {
                inputs,
                outputs,
                fee,
                size_bytes,
                fee_per_byte,
            } => {
                let wanted = outputs.saturating_add(*fee);
                let (word, gap) = if inputs > &wanted {
                    ("over", inputs - wanted)
                } else {
                    ("short", wanted - inputs)
                };
                write!(
                    f,
                    "a transfer must be exact: the outputs total {outputs} ESP units and the fee is {fee} ({size_bytes} bytes at {fee_per_byte} ESP units per byte), so the notes must be worth {wanted}. They are worth {inputs}, which is {word} by {gap}. Nothing was burned"
                )
            }
            TransferRejection::BadServiceSignature => {
                write!(f, "the service's signature does not cover this request")
            }
            TransferRejection::BadNote { index } => write!(
                f,
                "note {index} is not a genuine ESP note for this service, day and amount"
            ),
            TransferRejection::BadSpendSignature { index } => write!(
                f,
                "the spend signature of note {index} does not cover this request"
            ),
            TransferRejection::AlreadySpent { indexes } => match indexes.as_slice() {
                [one] => write!(f, "note {one} is already spent"),
                many => {
                    let list: Vec<String> = many.iter().map(|i| i.to_string()).collect();
                    write!(f, "notes {} are already spent", list.join(", "))
                }
            },
            TransferRejection::NoteHeld => write!(
                f,
                "a note or an output in this request is held by another transfer that has not finished"
            ),
            TransferRejection::Keyset { why, .. } => write!(f, "{why}"),
        }
    }
}

#[derive(Debug)]
pub enum TransferError {
    /// The request is refused. Nothing was burned.
    Rejected(TransferRejection),
    /// A fault in the mint. A retry is safe.
    Internal(String),
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferError::Rejected(r) => write!(f, "rejected: {r}"),
            TransferError::Internal(e) => write!(f, "internal: {e}"),
        }
    }
}

impl Error for TransferError {}

impl From<TransferRejection> for TransferError {
    fn from(r: TransferRejection) -> Self {
        TransferError::Rejected(r)
    }
}

fn internal<E: ToString>(e: E) -> TransferError {
    TransferError::Internal(e.to_string())
}

/// The input nonces and output blind nonces a pending transfer holds, as hex.
fn held_by(request: &TransferRequest) -> TransferPending {
    TransferPending {
        burned: false,
        inputs: request
            .inputs
            .iter()
            .map(|i| hex::encode(i.note.nonce.0.serialize()))
            .collect(),
        outputs: request
            .outputs
            .iter()
            .map(|o| hex::encode(o.blind_nonce.0.serialize()))
            .collect(),
    }
}

/// The shape of the request: counts, repeats, zero amounts and sizes (each a
/// power of two). Nothing here touches the mint.
fn validate_shape(request: &TransferRequest, max_items: usize) -> Result<(), TransferRejection> {
    if request.inputs.is_empty() {
        return Err(TransferRejection::NoInputs);
    }
    if request.outputs.is_empty() {
        return Err(TransferRejection::NoOutputs);
    }
    if request.inputs.len() > max_items || request.outputs.len() > max_items {
        return Err(TransferRejection::TooManyItems);
    }
    if request.input_keysets.len() != request.inputs.len() || request.keyset.is_empty() {
        return Err(TransferRejection::Keyset {
            code: sp_wire::codes::MISSING_KEYSET,
            why: "every input needs its keyset (input_keysets, in order) and the outputs need one (keyset). Nothing was burned".into(),
        });
    }
    let mut nonces = HashSet::new();
    for (index, input) in request.inputs.iter().enumerate() {
        if input.amount.units == 0 {
            return Err(TransferRejection::ZeroAmount);
        }
        if !crate::units::is_denomination(input.amount.units) {
            return Err(TransferRejection::BadDenomination {
                output: false,
                index,
            });
        }
        if !nonces.insert(input.note.nonce) {
            return Err(TransferRejection::DuplicateInput);
        }
    }
    let mut blind_nonces = HashSet::new();
    for (index, output) in request.outputs.iter().enumerate() {
        if output.amount.units == 0 {
            return Err(TransferRejection::ZeroAmount);
        }
        if !crate::units::is_denomination(output.amount.units) {
            return Err(TransferRejection::BadDenomination {
                output: true,
                index,
            });
        }
        if !blind_nonces.insert(output.blind_nonce) {
            return Err(TransferRejection::DuplicateBlindNonce);
        }
    }
    Ok(())
}

/// The exact rule: the inputs must be worth the outputs plus the fee, summed in
/// `u128`.
fn check_totals(
    request: &TransferRequest,
    fee: u128,
    size_bytes: u64,
    fee_per_byte: u128,
) -> Result<(), TransferRejection> {
    let inputs = units::total(request.inputs.iter().map(|i| i.amount.units));
    let outputs = units::total(request.outputs.iter().map(|o| o.amount.units));
    if fee == 0 {
        if inputs != outputs {
            return Err(TransferRejection::NotExact { inputs, outputs });
        }
        return Ok(());
    }
    // A total this large cannot be paid in full either, so it is not exact.
    if outputs.checked_add(fee) != Some(inputs) {
        return Err(TransferRejection::NotExactWithFee {
            inputs,
            outputs,
            fee,
            size_bytes,
            fee_per_byte,
        });
    }
    Ok(())
}

/// The shape of the request and the exact rule, with no fee.
#[cfg_attr(not(test), allow(dead_code))]
fn validate(request: &TransferRequest) -> Result<(), TransferRejection> {
    validate_shape(request, MAX_ITEMS)?;
    check_totals(request, 0, 0, 0)
}

/// The settings a transfer uses. They come from the mint's config
/// (`config::Config::transfer_settings`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferSettings {
    /// The most notes, and the most outputs, in one transfer.
    pub max_items: usize,
    /// ESP units charged for each byte of the request's canonical size
    /// (`fee::transfer_size`). 0 by default: the transfer has no mint fee.
    pub fee_per_byte: u128,
}

impl Default for TransferSettings {
    fn default() -> Self {
        TransferSettings {
            max_items: MAX_ITEMS,
            fee_per_byte: 0,
        }
    }
}

/// Run a transfer with the mint's settings, over both live key sets: each
/// input is checked and burned in the set that signed it (current or previous),
/// and the outputs are signed with the current set, under the same terms.
pub fn transfer_gens(
    gens: &Gens,
    responses: &mut Responses,
    request: &TransferRequest,
    settings: &TransferSettings,
) -> Result<TransferResponse, TransferError> {
    validate_shape(request, settings.max_items)?;
    let digest = request.digest();
    let hash = request_hash(request);

    let mut recovering = false;
    let mut proven = false;
    // The notes this request holds itself, when it is picked up again.
    let mut own: Vec<String> = Vec::new();
    match responses.get(&hash) {
        Some(Entry::Done(done)) => return Ok(done.clone()),
        Some(Entry::TransferPending(p)) => {
            recovering = true;
            proven = p.burned;
            own = p.inputs.clone();
        }
        Some(Entry::Pending { .. }) => {
            return Err(internal("an exchange is stored under this request's hash"));
        }
        Some(Entry::RedeemPending(_)) | Some(Entry::RedeemDone(_)) => {
            return Err(internal("a redemption is stored under this request's hash"));
        }
        None => {}
    }

    // The fee is fixed when the request is first accepted, at the rate in force
    // then. A request picked up again after a crash keeps it: what the inputs are
    // worth over the outputs is the fee it was accepted with, whatever the
    // setting says now.
    let size_bytes = fee::transfer_size(request.inputs.len(), request.outputs.len());
    let (fee_per_byte, fee_esp) = if recovering {
        let inputs = units::total(request.inputs.iter().map(|i| i.amount.units));
        let outputs = units::total(request.outputs.iter().map(|o| o.amount.units));
        let fee_esp = inputs.saturating_sub(outputs);
        (fee::rate_of(fee_esp, size_bytes), fee_esp)
    } else {
        let fee_esp = fee::charge(size_bytes, settings.fee_per_byte);
        check_totals(request, fee_esp, size_bytes, settings.fee_per_byte)?;
        (settings.fee_per_byte, fee_esp)
    };

    // Only the service the notes name may ask. This is checked before anything
    // else that touches the mint.
    SECP256K1
        .verify_schnorr(
            &request.service_signature,
            &digest,
            &request.service.x_only(),
        )
        .map_err(|_| TransferRejection::BadServiceSignature)?;

    let terms = Terms {
        service: request.service,
        redeemable_after_day: request.redeemable_after_day,
    };
    let held = held_by(request);

    // The keysets the request names. A request picked up again after a crash
    // finishes even if a keyset retired since: its inputs of that set were
    // burned before (nothing else could take them), and its outputs are then
    // signed with the current set, which the reply names.
    let keyset_refusal = |what: String, e: crate::rotation::KeysetError| -> TransferError {
        TransferRejection::Keyset {
            code: e.code(),
            why: e.why(&what),
        }
        .into()
    };
    let unresolved = |index: usize| -> TransferError {
        TransferRejection::Keyset {
            code: sp_wire::codes::UNKNOWN_KEYSET,
            why: format!(
                "note {index}: its keyset is not live, and this request is not one started before with its burn proven"
            ),
        }
        .into()
    };
    let mut in_keys = Vec::with_capacity(request.inputs.len());
    for (index, input) in request.inputs.iter().enumerate() {
        match gens.input_key(&request.input_keysets[index], input, &terms) {
            Ok(k) => in_keys.push(Some(k)),
            // Its keyset was deleted since the request was accepted: it may
            // finish without burning only if the stored state proves the burn.
            // Only a request picked up again, for a note it holds itself, and
            // with a proof taken for this request, may skip a note.
            Err(_)
                if proven
                    || (recovering
                        && own.contains(&hex::encode(input.note.nonce.0.serialize()))
                        && gens.burn_proven(Source::Responses, &hash, input)) =>
            {
                in_keys.push(None)
            }
            Err(e) if recovering => {
                return Err(TransferRejection::Keyset {
                    code: sp_wire::codes::BURN_NOT_PROVEN,
                    why: format!(
                        "note {index}: {}; this request was started before, but nothing stored proves its notes were burned under this request, so it cannot be finished without them",
                        e.why("its keyset")
                    ),
                }
                .into());
            }
            Err(e) => return Err(keyset_refusal(format!("note {index}"), e)),
        }
    }
    let (out_logic, out_master, out_keyset) = gens
        .signer(&request.keyset, recovering)
        .map_err(|e| keyset_refusal("the outputs".into(), e))?;

    if !recovering {
        // 1. Each input: genuine under the key derived for its amount and the
        //    terms, and a spend signature over the digest. Public keys only.
        for (index, input) in request.inputs.iter().enumerate() {
            let Some((logic, sk)) = in_keys[index] else {
                return Err(unresolved(index));
            };
            logic
                .verify_note_with_key(&sk, input)
                .map_err(|_| TransferRejection::BadNote { index })?;
            logic
                .verify_spend_authorization(input, digest)
                .map_err(|_| TransferRejection::BadSpendSignature { index })?;
        }
        // 2. The mint's own database. The answers are held back until the
        //    reservations below have been looked at, because a note that is
        //    spent may be spent by an unfinished request, and then "held" is the
        //    truer answer.
        let mut spent_indexes = Vec::new();
        for (index, input) in request.inputs.iter().enumerate() {
            let Some((logic, _)) = in_keys[index] else {
                return Err(unresolved(index));
            };
            if logic.is_spent(input.note.nonce).map_err(internal)? {
                spent_indexes.push(index);
            }
        }
        let mut blind_nonce_used = false;
        for output in &request.outputs {
            if out_logic
                .is_blind_nonce_used(&output.blind_nonce)
                .map_err(internal)?
            {
                blind_nonce_used = true;
                break;
            }
        }
        // 3. Reservations. Keep clear of every unfinished transfer, so that a
        //    note one of them will burn cannot be taken by another request first.
        for (other, pending) in responses.pending_transfers() {
            if other == &hash {
                continue;
            }
            let clash = pending.inputs.iter().any(|n| held.inputs.contains(n))
                || pending.outputs.iter().any(|n| held.outputs.contains(n));
            if clash {
                return Err(TransferRejection::NoteHeld.into());
            }
        }
        // An unfinished exchange will sign its output blind nonces. Its inputs
        // are PSP notes, which a transfer never takes.
        for (_, _, outputs) in responses.pending_exchanges() {
            if outputs.iter().any(|n| held.outputs.contains(n)) {
                return Err(TransferRejection::NoteHeld.into());
            }
        }
        // An unfinished redemption will burn ESP notes and sign output blind
        // nonces, and a finished one keeps its decline outputs' blind nonces for
        // a later decline.
        // A pending rollover will burn the notes it holds and sign its outputs.
        if held
            .inputs
            .iter()
            .any(|n| responses.external_holds().contains(n))
            || held
                .outputs
                .iter()
                .any(|n| responses.external_out_holds().contains(n))
        {
            return Err(TransferRejection::NoteHeld.into());
        }
        let (redeem_inputs, redeem_outputs) = responses.redeem_holds(&hash);
        if held.inputs.iter().any(|n| redeem_inputs.contains(n))
            || held.outputs.iter().any(|n| redeem_outputs.contains(n))
        {
            return Err(TransferRejection::NoteHeld.into());
        }
        if !spent_indexes.is_empty() {
            return Err(TransferRejection::AlreadySpent {
                indexes: spent_indexes,
            }
            .into());
        }
        if blind_nonce_used {
            return Err(TransferRejection::BlindNonceAlreadyUsed.into());
        }
        responses
            .put(&hash, Entry::TransferPending(held.clone()))
            .map_err(internal)?;
    }

    // Burn the inputs. On a retry, an input that is already spent was burned by
    // an earlier attempt of this same request, since no other request could take
    // it while the pending entry names it.
    if !proven {
        for (input, key) in request.inputs.iter().zip(&in_keys) {
            // None: proven burned when its keyset was deleted.
            let Some((logic, sk)) = key.as_ref() else {
                continue;
            };
            if recovering && logic.is_spent(input.note.nonce).map_err(internal)? {
                continue;
            }
            logic.redeem_with_key(sk, input, digest).map_err(internal)?;
        }
        // The proof: every input is burned under this hash. Written before
        // anything is signed.
        let mut done = held.clone();
        done.burned = true;
        responses
            .put(&hash, Entry::TransferPending(done))
            .map_err(internal)?;
    }

    // Sign the outputs under the same terms, with the keyset named.
    let (logic, master) = (out_logic, out_master);
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

    let response = TransferResponse {
        keyset: out_keyset,
        service: request.service,
        redeemable_after_day: request.redeemable_after_day,
        signatures,
        keys,
        fee_per_byte,
        fee_esp,
        size_bytes,
    };
    // The ledger counts the burned inputs and the signed outputs under the
    // notes' day, in the same write that finishes the entry (see `ledger`). The
    // difference is the fee.
    let mut movements = Movements::new();
    movements
        .redeem(
            request.redeemable_after_day,
            units::total(request.inputs.iter().map(|i| i.amount.units)),
        )
        .issue(
            request.redeemable_after_day,
            units::total(request.outputs.iter().map(|o| o.amount.units)),
        );
    responses
        .finish(&hash, Entry::Done(response.clone()), &movements)
        .map_err(internal)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    use mint_core::MintLogic;
    use mint_types::{Amount, BlindNonce, Nonce, Note};
    use rand::rngs::OsRng;
    use secp256k1::{Keypair, SecretKey};

    use crate::keys::MasterSecret;
    use crate::ledger::Day;

    const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const NOW: u64 = 1_791_571_184;
    const DAY: u64 = NOW / 86_400 + 365;
    /// A note size to test with: a power of two, about 0.7 PSP.
    const ONE_PSP: u64 = 1 << 36;

    /// The DID of `service_keypair()`: `02` and the x coordinate `G_X`.
    fn service() -> ServiceDid {
        ServiceDid::parse(&format!("02{G_X}")).unwrap()
    }

    /// The key whose public key is the DID `02` + `G_X`: secret key 1.
    fn service_keypair() -> Keypair {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&bytes).unwrap())
    }

    /// Another service's key: secret key 2.
    fn other_keypair() -> Keypair {
        let mut bytes = [0u8; 32];
        bytes[31] = 2;
        Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&bytes).unwrap())
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("esp-mint-tr-{}-{name}", {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct Setup {
        dir: PathBuf,
        rotor: crate::rotation::Rotor,
        logic: MintLogic,
        master: MasterSecret,
        responses: Responses,
    }

    thread_local! {
        /// The keyset of this test's mint (set by `setup`), which requests name.
        static KS: std::cell::RefCell<String> = std::cell::RefCell::new("00".repeat(8));
    }

    fn ks() -> String {
        KS.with(|k| k.borrow().clone())
    }

    fn setup(name: &str) -> Setup {
        let dir = scratch(name);
        let (rotor, logic) = crate::rotation::Rotor::open_at(&dir.join("esp"), 1, 1, NOW).unwrap();
        let master = rotor.current.master.clone();
        KS.with(|k| *k.borrow_mut() = rotor.current.id.clone());
        let responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
        Setup {
            dir,
            rotor,
            logic,
            master,
            responses,
        }
    }

    impl Setup {
        fn terms(&self) -> Terms {
            Terms {
                service: service(),
                redeemable_after_day: DAY,
            }
        }

        /// An ESP note the mint has issued under these terms, and the key that
        /// spends it.
        fn esp_note(&self, units: u64, service: ServiceDid, day: u64) -> (Note, Keypair) {
            let terms = Terms {
                service,
                redeemable_after_day: day,
            };
            let keypair = Keypair::new(SECP256K1, &mut OsRng);
            let nonce = Nonce(keypair.public_key());
            let (blind_point, blinding_key) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
            let amount = Amount::from_units(units);
            let sk = self.master.key_for(amount, &terms);
            let outcome = self
                .logic
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

        fn run(&mut self, request: &TransferRequest) -> Result<TransferResponse, TransferError> {
            self.run_with(request, &TransferSettings::default())
        }

        /// The transfer, as the server runs it, under these settings.
        fn run_with(
            &mut self,
            request: &TransferRequest,
            settings: &TransferSettings,
        ) -> Result<TransferResponse, TransferError> {
            transfer_gens(
                &self.rotor.gens(&self.logic),
                &mut self.responses,
                request,
                settings,
            )
        }

        /// (issued, redeemed) ESP units.
        fn totals(&self) -> (u64, u64) {
            let (issued, redeemed) = self.logic.audit_totals().unwrap();
            (issued.units, redeemed.units)
        }
    }

    /// A new note the service asked for: its keys and blinding factor.
    struct Wanted {
        keypair: Keypair,
        nonce: Nonce,
        blinding_key: SecretKey,
        amount: u64,
    }

    fn dummy_signature() -> Signature {
        Signature::from_slice(&[0u8; 64]).unwrap()
    }

    /// Build a request the way a service does. `notes` are (note, key, units).
    /// `spend_signer` signs every input instead of the note's own key, and
    /// `service_signer` signs for the service.
    fn build_with(
        notes: &[(Note, &Keypair, u64)],
        out_amounts: &[u64],
        request_service: ServiceDid,
        day: u64,
        spend_signer: Option<&Keypair>,
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
                keypair,
                nonce,
                blinding_key,
                amount,
            });
        }
        let mut inputs: Vec<MintInput> = notes
            .iter()
            .map(|(note, _, units)| MintInput {
                amount: Amount::from_units(*units),
                note: *note,
                spend_signature: dummy_signature(),
            })
            .collect();
        let sighash = digest(&request_service, day, &inputs, &outputs);
        for (input, (_, keypair, _)) in inputs.iter_mut().zip(notes) {
            input.spend_signature =
                SECP256K1.sign_schnorr(&sighash, spend_signer.unwrap_or(*keypair));
        }
        let service_signature = SECP256K1.sign_schnorr(&sighash, service_signer);
        (
            TransferRequest {
                service: request_service,
                redeemable_after_day: day,
                input_keysets: vec![ks(); inputs.len()],
                inputs,
                keyset: ks(),
                outputs,
                service_signature,
            },
            wanted,
        )
    }

    /// Split a total into powers of two, the way the wallet does: one note for
    /// each bit set, largest first. Zero stays as one zero.
    fn split(total: u64) -> Vec<u64> {
        if total == 0 {
            return vec![0];
        }
        (0..64)
            .rev()
            .map(|bit| 1u64 << bit)
            .filter(|p| total & p != 0)
            .collect()
    }

    /// Split a total into exactly `n` powers of two, by halving the largest
    /// note that is more than one until there are `n`.
    fn split_into(total: u64, n: usize) -> Vec<u64> {
        let mut notes = split(total);
        while notes.len() < n {
            let i = notes.iter().position(|&a| a > 1).unwrap();
            let half = notes[i] / 2;
            notes[i] = half;
            notes.insert(i + 1, half);
        }
        notes
    }

    /// Build a request the way a service does: each amount in `out_amounts` is
    /// a total, split into powers of two.
    fn build(
        notes: &[(Note, &Keypair, u64)],
        out_amounts: &[u64],
    ) -> (TransferRequest, Vec<Wanted>) {
        let amounts: Vec<u64> = out_amounts.iter().flat_map(|&a| split(a)).collect();
        build_exact(notes, &amounts)
    }

    /// Like `build`, but each output is as it stands, whatever it is.
    fn build_exact(
        notes: &[(Note, &Keypair, u64)],
        out_amounts: &[u64],
    ) -> (TransferRequest, Vec<Wanted>) {
        build_with(notes, out_amounts, service(), DAY, None, &service_keypair())
    }

    fn rejection(result: Result<TransferResponse, TransferError>) -> TransferRejection {
        match result {
            Err(TransferError::Rejected(r)) => r,
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    fn fake_input(units: u64) -> MintInput {
        let keypair = Keypair::new(SECP256K1, &mut OsRng);
        MintInput {
            amount: Amount::from_units(units),
            note: Note {
                nonce: Nonce(keypair.public_key()),
                signature: keypair.public_key(),
            },
            spend_signature: dummy_signature(),
        }
    }

    fn fake_output(units: u64) -> MintOutput {
        let keypair = Keypair::new(SECP256K1, &mut OsRng);
        MintOutput {
            amount: Amount::from_units(units),
            blind_nonce: BlindNonce(keypair.public_key()),
        }
    }

    fn fake_request(inputs: Vec<MintInput>, outputs: Vec<MintOutput>) -> TransferRequest {
        TransferRequest {
            service: service(),
            redeemable_after_day: DAY,
            input_keysets: vec![ks(); inputs.len()],
            inputs,
            keyset: ks(),
            outputs,
            service_signature: dummy_signature(),
        }
    }

    /// Check that every output of `response` is a note the mint accepts under
    /// the terms, by unblinding it and verifying it with the derived key.
    fn assert_outputs_verify(s: &Setup, response: &TransferResponse, wanted: &[Wanted]) {
        let terms = s.terms();
        assert_eq!(response.signatures.len(), wanted.len());
        for (i, w) in wanted.iter().enumerate() {
            let sk = s.master.key_for(Amount::from_units(w.amount), &terms);
            assert_eq!(response.keys[i], sk.public_key(SECP256K1));
            let unblinded =
                bdhke::unblind_message(&response.signatures[i], &w.blinding_key, &response.keys[i]);
            assert!(bdhke::verify_message(
                &sk,
                unblinded,
                &w.nonce.as_hash_preimage()
            ));
        }
    }

    #[test]
    fn a_transfer_swaps_the_notes_for_new_ones_with_the_same_terms() {
        let mut s = setup("happy");
        let (a, ka) = s.esp_note(2 * ONE_PSP, service(), DAY);
        let (b, kb) = s.esp_note(ONE_PSP, service(), DAY);
        let (issued_before, redeemed_before) = s.totals();
        assert_eq!((issued_before, redeemed_before), (3 * ONE_PSP, 0));

        let (request, wanted) = build(
            &[(a, &ka, 2 * ONE_PSP), (b, &kb, ONE_PSP)],
            &[2 * ONE_PSP, ONE_PSP],
        );
        let response = s.run(&request).unwrap();

        assert_eq!(response.service, service());
        assert_eq!(response.redeemable_after_day, DAY);
        assert_outputs_verify(&s, &response, &wanted);
        // the old notes are spent
        assert!(s.logic.is_spent(a.nonce).unwrap());
        assert!(s.logic.is_spent(b.nonce).unwrap());
        // the inputs count as redeemed and the outputs as issued, by the same
        // amount, so the outstanding total is unchanged
        let (issued, redeemed) = s.totals();
        assert_eq!(issued, issued_before + 3 * ONE_PSP);
        assert_eq!(redeemed, redeemed_before + 3 * ONE_PSP);
        assert_eq!(issued - redeemed, issued_before - redeemed_before);
        // the stored response is a finished one
        assert!(matches!(
            s.responses.get(&request_hash(&request)),
            Some(Entry::Done(_))
        ));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn the_new_notes_can_be_transferred_again() {
        let mut s = setup("chain");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (first, wanted) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        let response = s.run(&first).unwrap();

        // the service now holds the new note: the unblinded signature and the
        // secret behind the nonce
        let w = &wanted[0];
        let note = Note {
            nonce: w.nonce,
            signature: bdhke::unblind_message(
                &response.signatures[0],
                &w.blinding_key,
                &response.keys[0],
            ),
        };
        let (second, _) = build(&[(note, &w.keypair, ONE_PSP)], &[ONE_PSP]);
        let again = s.run(&second).unwrap();
        assert_eq!(again.redeemable_after_day, DAY);
        assert!(s.logic.is_spent(note.nonce).unwrap());
        // two swaps, and the outstanding total is still one note
        let (issued, redeemed) = s.totals();
        assert_eq!((issued, redeemed), (3 * ONE_PSP, 2 * ONE_PSP));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_request_that_is_off_by_one_unit_is_refused_before_anything_is_burned() {
        let mut s = setup("exact");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let totals = s.totals();
        for out in [ONE_PSP + 1, ONE_PSP - 1] {
            let (request, _) = build(&[(a, &ka, ONE_PSP)], &[out]);
            assert_eq!(
                rejection(s.run(&request)),
                TransferRejection::NotExact {
                    inputs: u128::from(ONE_PSP),
                    outputs: u128::from(out),
                }
            );
        }
        assert!(!s.logic.is_spent(a.nonce).unwrap());
        assert_eq!(s.totals(), totals);
        assert!(s.responses.is_empty());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn an_amount_that_is_not_a_power_of_two_is_refused_before_anything_is_burned() {
        let mut s = setup("denomination");
        let (a, ka) = s.esp_note(2 * ONE_PSP, service(), DAY);
        let totals = s.totals();
        // an output of the right total that is not a power of two
        let (request, _) = build_exact(&[(a, &ka, 2 * ONE_PSP)], &[ONE_PSP + 1, ONE_PSP - 1]);
        let r = rejection(s.run(&request));
        assert_eq!(
            r,
            TransferRejection::BadDenomination {
                output: true,
                index: 0
            }
        );
        assert_eq!(
            r.to_string(),
            "output 0: ESP amounts are powers of two. Nothing was burned"
        );
        assert_eq!(r.code(), Some("bad_denomination"));
        // one odd output among good ones names its place
        let (request, _) = build_exact(&[(a, &ka, 2 * ONE_PSP)], &[ONE_PSP, ONE_PSP - 1, 1]);
        assert_eq!(
            rejection(s.run(&request)),
            TransferRejection::BadDenomination {
                output: true,
                index: 1
            }
        );
        // an incoming note of an odd size is refused the same way, whatever the
        // mint holds under that amount
        let odd = ONE_PSP + 5;
        let (b, kb) = s.esp_note(odd, service(), DAY);
        let (request, _) = build_exact(&[(b, &kb, odd)], &split(odd));
        let r = rejection(s.run(&request));
        assert_eq!(
            r,
            TransferRejection::BadDenomination {
                output: false,
                index: 0
            }
        );
        assert_eq!(
            r.to_string(),
            "note 0: ESP amounts are powers of two. Nothing was burned"
        );
        assert!(!s.logic.is_spent(a.nonce).unwrap());
        assert!(!s.logic.is_spent(b.nonce).unwrap());
        assert_eq!(s.totals(), (totals.0 + odd, totals.1));
        assert!(s.responses.is_empty());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_total_split_into_powers_of_two_is_transferred() {
        let mut s = setup("split");
        let (a, ka) = s.esp_note(4 * ONE_PSP, service(), DAY);
        // one note of 4 ONE_PSP, paid out as two totals that are not powers of
        // two, each split into powers of two
        let (request, wanted) = build(&[(a, &ka, 4 * ONE_PSP)], &[4 * ONE_PSP - 5, 5]);
        assert!(request.outputs.len() > 2);
        assert!(
            request
                .outputs
                .iter()
                .all(|o| o.amount.units.is_power_of_two())
        );
        let response = s.run(&request).unwrap();
        assert_outputs_verify(&s, &response, &wanted);
        assert!(s.logic.is_spent(a.nonce).unwrap());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_fee_is_paid_in_esp_on_top_of_the_exact_amount_and_the_rate_is_kept() {
        let mut s = setup("fee");
        let rate = 1_000u128;
        let with_fee = TransferSettings {
            fee_per_byte: rate,
            ..TransferSettings::default()
        };
        let size = fee::transfer_size(1, 1);
        let fee_esp = fee::charge(size, rate);
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        // The exact amount with no fee on top is refused under a fee, and says
        // what the fee is. Nothing is burned.
        let (request, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        match rejection(s.run_with(&request, &with_fee)) {
            TransferRejection::NotExactWithFee {
                fee,
                size_bytes,
                fee_per_byte,
                ..
            } => assert_eq!((fee, size_bytes, fee_per_byte), (fee_esp, size, rate)),
            other => panic!("expected NotExactWithFee, got {other:?}"),
        }
        assert!(!s.logic.is_spent(a.nonce).unwrap());
        assert!(s.responses.is_empty());
        // With the fee left off the outputs, it goes through. The fee depends on
        // how many outputs there are, and the rest is split into powers of two,
        // so take the fewest outputs n for which the rest after the fee for n
        // outputs splits into exactly n.
        let (n, rest, fee_esp, size) = (1..=MAX_ITEMS)
            .find_map(|n| {
                let size = fee::transfer_size(1, n);
                let fee_esp = fee::charge(size, rate);
                let rest = ONE_PSP - fee_esp as u64;
                (split(rest).len() <= n && n as u64 <= rest).then_some((n, rest, fee_esp, size))
            })
            .unwrap();
        let (request, _) = build_exact(&[(a, &ka, ONE_PSP)], &split_into(rest, n));
        assert_eq!(request.outputs.len(), n);
        let response = s.run_with(&request, &with_fee).unwrap();
        assert_eq!(
            (response.fee_per_byte, response.fee_esp, response.size_bytes),
            (rate, fee_esp, size)
        );
        // A retry after the rate was changed gets the reply stored at the old rate.
        let later = TransferSettings {
            fee_per_byte: rate * 5,
            ..TransferSettings::default()
        };
        let again = s.run_with(&request, &later).unwrap();
        assert_eq!(again, response);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn with_no_fee_the_reply_says_so() {
        let mut s = setup("nofee");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (request, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        let response = s.run(&request).unwrap();
        assert_eq!((response.fee_per_byte, response.fee_esp), (0, 0));
        assert_eq!(response.size_bytes, fee::transfer_size(1, 1));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn sums_are_exact_in_u128_past_the_size_of_one_note() {
        let top = 1u64 << 63;
        let two = 2 * u128::from(top);
        let ok = fake_request(
            vec![fake_input(top), fake_input(top)],
            vec![fake_output(top), fake_output(top)],
        );
        assert_eq!(validate(&ok), Ok(()));
        let short = fake_request(
            vec![fake_input(top), fake_input(top)],
            vec![fake_output(top), fake_output(1)],
        );
        assert_eq!(
            validate(&short),
            Err(TransferRejection::NotExact {
                inputs: two,
                outputs: u128::from(top) + 1,
            })
        );
        // a split whose pieces add up to more than one note holds
        let split = fake_request(
            vec![fake_input(top), fake_input(top)],
            vec![fake_output(top), fake_output(top / 2), fake_output(top / 2)],
        );
        assert_eq!(validate(&split), Ok(()));
    }

    #[test]
    fn the_shape_of_a_request_is_checked() {
        assert_eq!(
            validate(&fake_request(vec![], vec![fake_output(1)])),
            Err(TransferRejection::NoInputs)
        );
        assert_eq!(
            validate(&fake_request(vec![fake_input(1)], vec![])),
            Err(TransferRejection::NoOutputs)
        );
        assert_eq!(
            validate(&fake_request(vec![fake_input(0)], vec![fake_output(1)])),
            Err(TransferRejection::ZeroAmount)
        );
        assert_eq!(
            validate(&fake_request(
                vec![fake_input(1)],
                vec![fake_output(0), fake_output(1)]
            )),
            Err(TransferRejection::ZeroAmount)
        );
        let one = fake_input(1);
        assert_eq!(
            validate(&fake_request(vec![one.clone(), one], vec![fake_output(2)])),
            Err(TransferRejection::DuplicateInput)
        );
        let out = fake_output(1);
        assert_eq!(
            validate(&fake_request(
                vec![fake_input(1), fake_input(1)],
                vec![out.clone(), out]
            )),
            Err(TransferRejection::DuplicateBlindNonce)
        );
        let many_in: Vec<MintInput> = (0..=MAX_ITEMS).map(|_| fake_input(1)).collect();
        assert_eq!(
            validate(&fake_request(many_in, vec![fake_output(1)])),
            Err(TransferRejection::TooManyItems)
        );
        let many_out: Vec<MintOutput> = (0..=MAX_ITEMS).map(|_| fake_output(1)).collect();
        assert_eq!(
            validate(&fake_request(vec![fake_input(1)], many_out)),
            Err(TransferRejection::TooManyItems)
        );
    }

    #[test]
    fn a_request_not_signed_by_the_service_is_refused_and_nothing_is_burned() {
        let mut s = setup("bad-service-sig");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let totals = s.totals();
        // signed by another key: the app holds the notes' spend secrets but not
        // the service's key
        let (request, _) = build_with(
            &[(a, &ka, ONE_PSP)],
            &[ONE_PSP],
            service(),
            DAY,
            None,
            &other_keypair(),
        );
        assert_eq!(
            rejection(s.run(&request)),
            TransferRejection::BadServiceSignature
        );
        assert!(!s.logic.is_spent(a.nonce).unwrap());
        assert_eq!(s.totals(), totals);
        assert!(s.responses.is_empty());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_note_named_for_another_service_or_day_cannot_be_transferred() {
        let mut s = setup("wrong-terms");
        let other = ServiceDid::from(other_keypair().public_key());
        let (foreign, kf) = s.esp_note(ONE_PSP, other, DAY);
        let (late, kl) = s.esp_note(ONE_PSP, service(), DAY + 1);

        // this service holds the foreign note's secret and signs for itself, but
        // the note is named for the other service
        let (request, _) = build(&[(foreign, &kf, ONE_PSP)], &[ONE_PSP]);
        assert_eq!(
            rejection(s.run(&request)),
            TransferRejection::BadNote { index: 0 }
        );

        // a note for a later day does not pass as the request's day
        let (request, _) = build(&[(late, &kl, ONE_PSP)], &[ONE_PSP]);
        assert_eq!(
            rejection(s.run(&request)),
            TransferRejection::BadNote { index: 0 }
        );

        // the second input is the bad one, and the good one is not burned
        let (good, kg) = s.esp_note(ONE_PSP, service(), DAY);
        let totals = s.totals();
        let (request, _) = build(
            &[(good, &kg, ONE_PSP), (late, &kl, ONE_PSP)],
            &[2 * ONE_PSP],
        );
        assert_eq!(
            rejection(s.run(&request)),
            TransferRejection::BadNote { index: 1 }
        );
        assert!(!s.logic.is_spent(good.nonce).unwrap());
        assert_eq!(s.totals(), totals);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn the_outputs_cannot_be_moved_to_another_service() {
        // A request that names another service is checked against that service's
        // terms, where these notes do not verify. A request that names the right
        // service gets outputs signed under its terms and no others.
        let mut s = setup("no-redirect");
        let other = ServiceDid::from(other_keypair().public_key());
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (request, _) = build_with(
            &[(a, &ka, ONE_PSP)],
            &[ONE_PSP],
            other,
            DAY,
            None,
            &other_keypair(),
        );
        assert_eq!(
            rejection(s.run(&request)),
            TransferRejection::BadNote { index: 0 }
        );
        assert!(!s.logic.is_spent(a.nonce).unwrap());

        let (request, wanted) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        let response = s.run(&request).unwrap();
        assert_eq!(response.service, service());
        let other_terms = Terms {
            service: other,
            redeemable_after_day: DAY,
        };
        let wrong = s
            .master
            .key_for(Amount::from_units(wanted[0].amount), &other_terms);
        assert_ne!(response.keys[0], wrong.public_key(SECP256K1));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_spend_signature_by_the_wrong_key_is_refused() {
        let mut s = setup("bad-spend-sig");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (b, kb) = s.esp_note(ONE_PSP, service(), DAY);
        let stranger = Keypair::new(SECP256K1, &mut OsRng);
        let totals = s.totals();
        let (request, _) = build_with(
            &[(a, &ka, ONE_PSP), (b, &kb, ONE_PSP)],
            &[2 * ONE_PSP],
            service(),
            DAY,
            Some(&stranger),
            &service_keypair(),
        );
        assert_eq!(
            rejection(s.run(&request)),
            TransferRejection::BadSpendSignature { index: 0 }
        );
        assert!(!s.logic.is_spent(a.nonce).unwrap());
        assert!(!s.logic.is_spent(b.nonce).unwrap());
        assert_eq!(s.totals(), totals);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_signature_made_for_other_outputs_is_refused() {
        let mut s = setup("replay");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (mut request, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        // swap in another output after signing: the digest no longer matches
        request.outputs = vec![fake_output(ONE_PSP)];
        assert_eq!(
            rejection(s.run(&request)),
            TransferRejection::BadServiceSignature
        );
        assert!(!s.logic.is_spent(a.nonce).unwrap());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_note_can_be_transferred_once() {
        let mut s = setup("twice");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (first, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        s.run(&first).unwrap();
        let totals = s.totals();
        // the same note presented again, with other outputs
        let (second, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        assert_eq!(
            rejection(s.run(&second)),
            TransferRejection::AlreadySpent { indexes: vec![0] }
        );
        assert_eq!(s.totals(), totals);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn an_output_blind_nonce_cannot_be_used_twice() {
        let mut s = setup("blind-reuse");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (b, kb) = s.esp_note(ONE_PSP, service(), DAY);
        let (first, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        s.run(&first).unwrap();
        // a second request that reuses the first one's output blind nonce
        let (mut second, _) = build(&[(b, &kb, ONE_PSP)], &[ONE_PSP]);
        second.outputs[0].blind_nonce = first.outputs[0].blind_nonce;
        // sign again over the changed outputs
        let sighash = second.digest();
        second.inputs[0].spend_signature = SECP256K1.sign_schnorr(&sighash, &kb);
        second.service_signature = SECP256K1.sign_schnorr(&sighash, &service_keypair());
        assert_eq!(
            rejection(s.run(&second)),
            TransferRejection::BlindNonceAlreadyUsed
        );
        assert!(!s.logic.is_spent(b.nonce).unwrap());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_retry_gets_the_same_response_and_burns_nothing_more() {
        let mut s = setup("retry");
        let (a, ka) = s.esp_note(2 * ONE_PSP, service(), DAY);
        let (request, _) = build(&[(a, &ka, 2 * ONE_PSP)], &[ONE_PSP, ONE_PSP]);
        let first = s.run(&request).unwrap();
        let totals = s.totals();
        let again = s.run(&request).unwrap();
        assert_eq!(first, again);
        assert_eq!(s.totals(), totals);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_retry_still_works_after_the_mint_restarts() {
        let mut s = setup("restart");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (request, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        let first = s.run(&request).unwrap();
        s.responses = Responses::open(&s.dir.join("esp").join("responses.json")).unwrap();
        assert_eq!(s.run(&request).unwrap(), first);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_transfer_that_stopped_part_way_is_finished_by_a_retry() {
        let mut s = setup("recover");
        let (a, ka) = s.esp_note(2 * ONE_PSP, service(), DAY);
        let (b, kb) = s.esp_note(2 * ONE_PSP, service(), DAY);
        let (request, wanted) = build(
            &[(a, &ka, 2 * ONE_PSP), (b, &kb, 2 * ONE_PSP)],
            &[ONE_PSP, 3 * ONE_PSP],
        );
        let hash = request_hash(&request);
        let terms = s.terms();

        // The mint validated the request, wrote the pending entry, burned the
        // first note and signed the first output, then stopped.
        s.responses
            .put(&hash, Entry::TransferPending(held_by(&request)))
            .unwrap();
        let sk_in = s.master.key_for(request.inputs[0].amount, &terms);
        s.logic
            .redeem_with_key(&sk_in, &request.inputs[0], request.digest())
            .unwrap();
        let sk_out = s.master.key_for(request.outputs[0].amount, &terms);
        s.logic
            .issue_with_key(&sk_out, &request.outputs[0])
            .unwrap();
        assert_eq!(s.totals(), (4 * ONE_PSP + ONE_PSP, 2 * ONE_PSP));

        // the retry finishes it, burning and signing only what is left
        let response = s.run(&request).unwrap();
        assert_outputs_verify(&s, &response, &wanted);
        assert!(s.logic.is_spent(a.nonce).unwrap());
        assert!(s.logic.is_spent(b.nonce).unwrap());
        assert_eq!(s.totals(), (4 * ONE_PSP + 4 * ONE_PSP, 4 * ONE_PSP));
        assert!(matches!(s.responses.get(&hash), Some(Entry::Done(_))));
        // and a further retry returns the stored response
        assert_eq!(s.run(&request).unwrap(), response);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_request_that_stopped_before_burning_anything_is_finished_by_a_retry() {
        let mut s = setup("recover-early");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (request, wanted) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        let hash = request_hash(&request);
        s.responses
            .put(&hash, Entry::TransferPending(held_by(&request)))
            .unwrap();
        let response = s.run(&request).unwrap();
        assert_outputs_verify(&s, &response, &wanted);
        assert!(s.logic.is_spent(a.nonce).unwrap());
        assert_eq!(s.totals(), (2 * ONE_PSP, ONE_PSP));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn another_request_cannot_take_a_note_an_unfinished_transfer_holds() {
        let mut s = setup("held");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (first, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        let (second, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        // the first is validated and pending, and has not burned anything yet
        s.responses
            .put(
                &request_hash(&first),
                Entry::TransferPending(held_by(&first)),
            )
            .unwrap();
        assert_eq!(rejection(s.run(&second)), TransferRejection::NoteHeld);
        assert!(!s.logic.is_spent(a.nonce).unwrap());
        // the first one finishes on retry, and then the second is a double spend
        s.run(&first).unwrap();
        assert_eq!(
            rejection(s.run(&second)),
            TransferRejection::AlreadySpent { indexes: vec![0] }
        );
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn another_request_cannot_take_an_output_blind_nonce_an_unfinished_transfer_holds() {
        let mut s = setup("held-output");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (b, kb) = s.esp_note(ONE_PSP, service(), DAY);
        let (first, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        s.responses
            .put(
                &request_hash(&first),
                Entry::TransferPending(held_by(&first)),
            )
            .unwrap();
        let (mut second, _) = build(&[(b, &kb, ONE_PSP)], &[ONE_PSP]);
        second.outputs[0].blind_nonce = first.outputs[0].blind_nonce;
        let sighash = second.digest();
        second.inputs[0].spend_signature = SECP256K1.sign_schnorr(&sighash, &kb);
        second.service_signature = SECP256K1.sign_schnorr(&sighash, &service_keypair());
        assert_eq!(rejection(s.run(&second)), TransferRejection::NoteHeld);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_transfer_cannot_take_an_output_blind_nonce_an_unfinished_exchange_holds() {
        let mut s = setup("held-by-exchange");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (request, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        let blind = hex::encode(request.outputs[0].blind_nonce.0.serialize());
        // an exchange, with other hashes and PSP notes, is pending on that nonce
        s.responses
            .put(
                "an-exchange",
                Entry::Pending {
                    redeemable_after_day: DAY,
                    inputs: vec!["02aa".into()],
                    outputs: vec![blind],
                },
            )
            .unwrap();
        assert_eq!(rejection(s.run(&request)), TransferRejection::NoteHeld);
        assert!(!s.logic.is_spent(a.nonce).unwrap());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn an_exchange_entry_under_a_transfer_hash_is_a_fault_not_a_success() {
        let mut s = setup("kinds");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (request, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        let hash = request_hash(&request);
        assert_eq!(hash.len(), 64);
        s.responses
            .put(
                &hash,
                Entry::Pending {
                    redeemable_after_day: DAY,
                    inputs: vec![],
                    outputs: vec![],
                },
            )
            .unwrap();
        assert!(matches!(s.run(&request), Err(TransferError::Internal(_))));
        assert!(!s.logic.is_spent(a.nonce).unwrap());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_transfer_cannot_take_a_note_or_an_output_an_unfinished_redemption_holds() {
        use crate::redeem::{self, RedeemPending};
        let mut s = setup("held-by-redeem");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (b, kb) = s.esp_note(ONE_PSP, service(), DAY);
        // a redemption is pending on note `a` and on a blind nonce
        let (request, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        let (other, _) = build(&[(b, &kb, ONE_PSP)], &[ONE_PSP]);
        s.responses
            .put(
                "a-redemption",
                Entry::RedeemPending(RedeemPending {
                    burned: false,
                    inputs: vec![hex::encode(a.nonce.0.serialize())],
                    outputs: vec![hex::encode(other.outputs[0].blind_nonce.0.serialize())],
                    plan: redeem::empty_plan(),
                }),
            )
            .unwrap();
        assert_eq!(rejection(s.run(&request)), TransferRejection::NoteHeld);
        assert_eq!(rejection(s.run(&other)), TransferRejection::NoteHeld);
        assert!(!s.logic.is_spent(a.nonce).unwrap());
        assert!(!s.logic.is_spent(b.nonce).unwrap());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_transfer_cannot_take_an_output_a_finished_redemption_may_still_sign() {
        use crate::redeem::{self, RedeemOutput, RedeemRecord};
        let mut s = setup("held-by-done-redeem");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (request, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        s.responses
            .put(
                "a-redemption",
                Entry::RedeemDone(RedeemRecord {
                    output_keyset: String::new(),
                    plan: redeem::empty_plan(),
                    refund: vec![],
                    decline_outputs: vec![RedeemOutput {
                        service: service(),
                        redeemable_after_day: DAY,
                        output: request.outputs[0].clone(),
                    }],
                }),
            )
            .unwrap();
        assert_eq!(rejection(s.run(&request)), TransferRejection::NoteHeld);
        assert!(!s.logic.is_spent(a.nonce).unwrap());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_redemption_entry_under_a_transfer_hash_is_a_fault() {
        use crate::redeem::{self, RedeemPending};
        let mut s = setup("redeem-kind");
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (request, _) = build(&[(a, &ka, ONE_PSP)], &[ONE_PSP]);
        s.responses
            .put(
                &request_hash(&request),
                Entry::RedeemPending(RedeemPending {
                    burned: false,
                    inputs: vec![],
                    outputs: vec![],
                    plan: redeem::empty_plan(),
                }),
            )
            .unwrap();
        assert!(matches!(s.run(&request), Err(TransferError::Internal(_))));
        assert!(!s.logic.is_spent(a.nonce).unwrap());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_finished_transfer_is_counted_once_in_the_ledger_under_the_notes_day() {
        let mut s = setup("ledger");
        let (a, ka) = s.esp_note(2 * ONE_PSP, service(), DAY);
        let (b, kb) = s.esp_note(ONE_PSP, service(), DAY);
        assert_eq!(s.responses.ledger().day(DAY), Day::default());
        let (request, _) = build(
            &[(a, &ka, 2 * ONE_PSP), (b, &kb, ONE_PSP)],
            &[ONE_PSP, 2 * ONE_PSP],
        );
        s.run(&request).unwrap();
        // The notes were minted straight from the mint here, so the ledger has
        // only the transfer: the inputs burned and the outputs signed, equal.
        let counted = Day {
            issued: u128::from(3 * ONE_PSP),
            redeemed: u128::from(3 * ONE_PSP),
        };
        assert_eq!(s.responses.ledger().day(DAY), counted);
        assert_eq!(s.responses.ledger().day(DAY + 1), Day::default());
        // A retry, and a retry after a restart, count nothing more.
        s.run(&request).unwrap();
        assert_eq!(s.responses.ledger().day(DAY), counted);
        s.responses = Responses::open(&s.dir.join("esp").join("responses.json")).unwrap();
        s.run(&request).unwrap();
        assert_eq!(s.responses.ledger().day(DAY), counted);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_transfer_fee_leaves_the_ledger_short_of_the_outputs_by_the_fee() {
        let mut s = setup("ledger-fee");
        let rate = 1_000u128;
        let with_fee = TransferSettings {
            fee_per_byte: rate,
            ..TransferSettings::default()
        };
        let (a, ka) = s.esp_note(ONE_PSP, service(), DAY);
        let (n, rest, fee_esp, _) = (1..=MAX_ITEMS)
            .find_map(|n| {
                let size = fee::transfer_size(1, n);
                let fee_esp = fee::charge(size, rate);
                let rest = ONE_PSP - fee_esp as u64;
                (split(rest).len() <= n && n as u64 <= rest).then_some((n, rest, fee_esp, size))
            })
            .unwrap();
        let (request, _) = build_exact(&[(a, &ka, ONE_PSP)], &split_into(rest, n));
        s.run_with(&request, &with_fee).unwrap();
        let day = s.responses.ledger().day(DAY);
        assert_eq!(day.redeemed, u128::from(ONE_PSP));
        assert_eq!(day.issued, u128::from(rest));
        assert_eq!(day.redeemed - day.issued, fee_esp);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_transfer_that_stopped_part_way_counts_nothing_until_it_is_finished_and_then_once() {
        let mut s = setup("ledger-recover");
        let (a, ka) = s.esp_note(2 * ONE_PSP, service(), DAY);
        let (request, _) = build(&[(a, &ka, 2 * ONE_PSP)], &[ONE_PSP, ONE_PSP]);
        let hash = request_hash(&request);
        let terms = s.terms();
        s.responses
            .put(&hash, Entry::TransferPending(held_by(&request)))
            .unwrap();
        // The input is burned and the first output signed, then it stops.
        let sk_in = s.master.key_for(request.inputs[0].amount, &terms);
        s.logic
            .redeem_with_key(&sk_in, &request.inputs[0], request.digest())
            .unwrap();
        let sk_out = s.master.key_for(request.outputs[0].amount, &terms);
        s.logic
            .issue_with_key(&sk_out, &request.outputs[0])
            .unwrap();
        // The counters moved, the ledger has not, and a restart keeps it so.
        s.responses = Responses::open(&s.dir.join("esp").join("responses.json")).unwrap();
        assert_eq!(s.responses.ledger().day(DAY), Day::default());
        assert_eq!(s.responses.unfinished(), 1);

        s.run(&request).unwrap();
        let counted = Day {
            issued: u128::from(2 * ONE_PSP),
            redeemed: u128::from(2 * ONE_PSP),
        };
        assert_eq!(s.responses.ledger().day(DAY), counted);
        assert_eq!(s.responses.unfinished(), 0);
        s.run(&request).unwrap();
        assert_eq!(s.responses.ledger().day(DAY), counted);
        fs::remove_dir_all(&s.dir).unwrap();
    }
}
