//! Redemption: a service turns ESP notes into a payout.
//!
//! Only the owner of a service's DID key may redeem ESP for that service.
//! Holders cannot cash out at the mint: they spend or transfer their notes to
//! the service (see `transfer`), and the service redeems.
//!
//! The rules:
//!
//! - **Signature first.** The service signs the request digest with its DID
//!   key. That is checked before anything else touches the mint. A bad
//!   signature means no burn and no fee, because nobody authorized the request.
//! - **Each note on its own.** Every input names the service and the
//!   redeemable-after day it claims, and the mint checks the note against the
//!   key it derives for that amount and those terms. A note is accepted if its
//!   claimed service is the signer (`WrongService`), it is genuine with a valid
//!   spend signature (`BadProof`), it is not spent, listed twice or held by an
//!   unfinished request (`AlreadySpent`), and its day has come by the mint's
//!   clock (`Immature`). The first reason that applies is the one reported.
//!   Mixed dates are allowed, and a rejected note does not sink the others.
//! - **Value and fee.** V is the total of the notes that are genuine and not
//!   spent, accepted or not. A is the accepted total and R the rest, so
//!   V = A + R. The fee is a rate per byte times the size of the whole request
//!   in its canonical encoding (see below), whatever happens to its notes. It
//!   is never returned. If V is below the fee, the request is refused, nothing
//!   is burned and no fee is charged.
//! - **One canonical encoding.** The request travels, is measured, is hashed
//!   and is signed in one fixed binary layout (`encode` and `decode`). Every
//!   field has a fixed size except the payout memo (at most
//!   `redeem.max_memo_bytes`) and the two list lengths. A body that does not decode exactly is
//!   refused, so there are no unknown fields. The size is the length of that
//!   encoding, so a service can work out the fee before it sends. There is no
//!   cap on notes, outputs or dates: only the ceiling on the whole encoded
//!   request, which `server::air_served` enforces before it parses any further. A large service splits a redemption across several requests;
//!   each pays its own fee and gets its own queue entry.
//! - **How the fee is taken.** If A covers the fee, it comes off the payout and
//!   the rejected notes are not touched. If it does not, all of A goes to the
//!   fee and the shortfall comes from the genuine rejected notes: they are all
//!   burned and `refund_outputs` reissue what is left of them (at most R minus
//!   the shortfall, and for each service and date at most the rejected notes
//!   with those terms).
//! - **Payout.** One queue entry for A minus the fee, if that is above zero.
//!   The entry is paid by hand, or declined, in which case `decline_outputs`
//!   are signed and the accepted notes come back minus the fee, each with its
//!   original service and day (see `decline`).
//! - **Crash safe.** Stored by request hash with reservations, like the exchange
//!   and the transfer.
//!
//! The outputs are fixed in the request, before the mint decides which notes
//! are accepted. So the limits are checked after the decision and before any
//! burn, and a request that breaks them is refused with the totals it needs to
//! be rebuilt (see `Totals`). Nothing was burned.
//!
//! Order of events, and why it is safe to retry at any point:
//!
//! 1. Check the shape of the request. Nothing is written yet.
//! 2. A stored finished record for this request hash is answered as it is, with
//!    the queue entry's status as it is now.
//! 3. Check the service's signature.
//! 4. Decide each note, check the fee and the output limits, check that no
//!    input or output is held by another unfinished request, and write a
//!    `redeem_pending` entry with the decision and what it holds.
//! 5. Burn the notes the decision names, sign the refund outputs, queue the
//!    entry, and write the `redeem_done` record.
//!
//! A retry of a pending request does not decide again: it uses the stored
//! decision, skips the notes that are already burned, and signs again the
//! refunds that were already issued (signing is deterministic). A note of a
//! pending request can be burned only by that request, because step 4 keeps
//! every other request away from it.

use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt;
use std::path::Path;

use mint_core::MintLogic;
#[cfg(test)]
use mint_types::MintOutput;
use mint_types::{MintInput, MintOutputError};
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sp_wire::ServiceDid;

use crate::keys::MasterSecret;
use crate::ledger::Movements;
use crate::queue::{self, Queue, QueueError, SignedOutput, Status, dec};
use crate::responses::{Entry, Responses};
use crate::rotation::Gens;
use crate::terms::Terms;

// The canonical request, its encoding and the reply types live in sp-wire; they
// are re-exported so the paths are unchanged.
pub use sp_wire::esp::redeem::{
    DEFAULT_MAX_MEMO_BYTES, FIXED_BYTES, FORMAT_VERSION, INPUT_BYTES, KEYSET_BYTES,
    MIN_REQUEST_BYTES, NoteResult, OUTPUT_BYTES, Reason, RedeemInput, RedeemOutput, RedeemRequest,
    RedeemResponse, TermsTotal, Totals, decode, decode_with, digest, encode, encoded_len,
    request_hash,
};
use sp_wire::keyset::is_keyset_id;

/// The default for the longest decline reason, in bytes
/// (`redeem.max_reason_bytes`).
pub const DEFAULT_MAX_REASON_BYTES: usize = 1024;

/// The largest message AIR's server takes (its WebSocket cap is 16 MiB; a client
/// allows 17 MiB for replies). A request sent over AIR is one message.
pub const AIR_MESSAGE_CAP: usize = 16 * 1024 * 1024;

/// What is kept below [`AIR_MESSAGE_CAP`] for everything around the request body:
/// the envelope (71 bytes) and its seal (80), AIR's own framing of a record, and
/// room to spare.
pub const AIR_ROOM: usize = 1024 * 1024;

/// The default ceiling on one encoded request: 15 MiB
/// (`redeem.max_request_bytes`), the AIR message cap less [`AIR_ROOM`], so that
/// every redemption the mint accepts can be sent over AIR, the only way a wallet
/// reaches the mint. A larger redemption is split by the wallet into several
/// requests, each under the ceiling (about 84,000 notes with no outputs coming
/// back). Raising the setting above this does not let a wallet send a larger
/// request: AIR carries no larger message.
pub const DEFAULT_MAX_REQUEST_BYTES: usize = AIR_MESSAGE_CAP - AIR_ROOM;

/// The default fee rate, in ESP units per encoded byte
/// (`redeem.fee_per_byte`): 0, so a redemption costs no fee unless the operator
/// sets one. Like every fee in the mint it is a setting, not a policy of the
/// code.
pub const DEFAULT_FEE_PER_BYTE: u128 = 0;

/// The settings a redemption uses. They come from the mint's config
/// (`config::Config::redeem_settings`); the defaults are the documented ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedeemSettings {
    /// ESP units per encoded byte. Taken once, when the request is accepted,
    /// and stored in the decision, the reply and the queue entry.
    pub fee_per_byte: u128,
    pub max_memo_bytes: usize,
    pub max_reason_bytes: usize,
}

impl Default for RedeemSettings {
    fn default() -> Self {
        RedeemSettings {
            fee_per_byte: DEFAULT_FEE_PER_BYTE,
            max_memo_bytes: DEFAULT_MAX_MEMO_BYTES,
            max_reason_bytes: DEFAULT_MAX_REASON_BYTES,
        }
    }
}

/// The fee for a request of `size` encoded bytes at `fee_per_byte`.
pub fn fee_for(size: u64, fee_per_byte: u128) -> u128 {
    u128::from(size).saturating_mul(fee_per_byte)
}

/// The decision, kept in the pending entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub totals: Totals,
    /// A minus the fee, or zero. This is what the queue entry owes.
    #[serde(with = "dec")]
    pub owed_esp: u128,
}

/// What an unfinished redemption holds (hex) and what it decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedeemPending {
    /// The nonces of the notes it burns.
    pub inputs: Vec<String>,
    /// The blind nonces of every decline and refund output.
    pub outputs: Vec<String>,
    pub plan: Plan,
    /// Every note the plan burns has been burned under this request's hash
    /// (written after the burn, before any signing). Only this proves the
    /// burn once a note's keyset has been deleted with its spent list.
    #[serde(default)]
    pub burned: bool,
}

/// A finished redemption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedeemRecord {
    pub plan: Plan,
    /// The signatures on `refund_outputs`, in the request's order.
    pub refund: Vec<SignedOutput>,
    /// The outputs to sign if the payout is declined. Kept until then.
    pub decline_outputs: Vec<RedeemOutput>,
    /// The keyset the request asked its outputs to be signed with. A decline is
    /// signed by the current keyset whatever this says.
    #[serde(default)]
    pub output_keyset: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputList {
    Decline,
    Refund,
}

impl OutputList {
    fn name(self) -> &'static str {
        match self {
            OutputList::Decline => "decline_outputs",
            OutputList::Refund => "refund_outputs",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedeemRejection {
    NoInputs,
    ZeroAmount,
    /// A note or an output amount is not a power of two. `what` names the list
    /// ("note", "decline output", "refund output") and `index` the position in
    /// it. Nothing was burned and no fee was taken.
    BadDenomination {
        what: &'static str,
        index: usize,
    },
    MemoInvalid {
        max: usize,
    },
    DuplicateBlindNonce,
    BlindNonceAlreadyUsed,
    /// The body is not a request in the canonical encoding.
    Malformed(String),
    /// The encoded request is larger than the mint accepts. Refused before it
    /// was parsed.
    TooLarge {
        size: Option<u64>,
        limit: u64,
    },
    /// The service's signature does not cover this request. Nothing was burned
    /// and no fee was taken.
    BadServiceSignature,
    /// An output blind nonce is held by another request that is not finished.
    NoteHeld,
    /// The genuine, unspent notes are worth less than the fee. `notes` says
    /// what the mint made of each input, in the request's order, so a wallet
    /// can tell the notes that are spent (it should stop offering them) from
    /// the ones that are only too small. Nothing was burned, so every `burned`
    /// is false.
    BelowFee {
        value: u128,
        fee: u128,
        notes: Vec<NoteResult>,
    },
    /// A list of outputs is more than the mint will reissue. `totals` says what
    /// it will.
    OutputsOverLimit {
        list: OutputList,
        totals: Totals,
    },
    /// The accepted notes do not cover the fee, and the rest is worth more than
    /// the shortfall, so `refund_outputs` are needed.
    RefundRequired {
        totals: Totals,
    },
    /// The output keyset is retired (`keyset_retired`) or not this mint's
    /// (`unknown_keyset`). Nothing was burned and no fee was taken.
    Keyset {
        code: &'static str,
        why: String,
    },
}

impl RedeemRejection {
    /// A short code for a caller that reads the body.
    pub fn code(&self) -> &'static str {
        match self {
            RedeemRejection::NoInputs => "no_inputs",
            RedeemRejection::Malformed(_) => sp_wire::codes::MALFORMED_REQUEST,
            RedeemRejection::TooLarge { .. } => sp_wire::codes::REQUEST_TOO_LARGE,
            RedeemRejection::ZeroAmount => "zero_amount",
            RedeemRejection::BadDenomination { .. } => crate::units::BAD_DENOMINATION,
            RedeemRejection::MemoInvalid { .. } => "memo_invalid",
            RedeemRejection::DuplicateBlindNonce => "duplicate_blind_nonce",
            RedeemRejection::BlindNonceAlreadyUsed => "blind_nonce_already_used",
            RedeemRejection::BadServiceSignature => "bad_service_signature",
            RedeemRejection::NoteHeld => sp_wire::codes::NOTE_HELD,
            RedeemRejection::BelowFee { .. } => "below_fee",
            RedeemRejection::OutputsOverLimit { .. } => "outputs_over_limit",
            RedeemRejection::RefundRequired { .. } => "refund_required",
            RedeemRejection::Keyset { code, .. } => code,
        }
    }

    /// Extra fields for the body of a refusal: the totals a service needs to
    /// rebuild its request.
    pub fn details(&self) -> Value {
        match self {
            RedeemRejection::BelowFee { value, fee, notes } => json!({
                "value_esp": value.to_string(),
                "fee_esp": fee.to_string(),
                // additive: older wallets ignore it
                "notes": notes,
            }),
            RedeemRejection::TooLarge { size, limit } => json!({
                "size_bytes": size,
                "limit_bytes": limit,
            }),
            RedeemRejection::OutputsOverLimit { list, totals } => json!({
                "list": list.name(),
                "totals": totals,
            }),
            RedeemRejection::RefundRequired { totals } => json!({ "totals": totals }),
            _ => json!({}),
        }
    }
}

impl fmt::Display for RedeemRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedeemRejection::NoInputs => write!(f, "no notes to redeem"),
            RedeemRejection::Malformed(why) => write!(f, "not a valid redemption request: {why}"),
            RedeemRejection::TooLarge { size, limit } => {
                match size {
                    Some(size) => write!(
                        f,
                        "the request is {size} bytes, more than the {limit} the mint accepts"
                    )?,
                    None => write!(
                        f,
                        "the request is larger than the {limit} bytes the mint accepts"
                    )?,
                }
                write!(
                    f,
                    ". Split it into several requests. Nothing was parsed, burned or charged"
                )
            }
            RedeemRejection::ZeroAmount => write!(f, "a note or an output has amount zero"),
            RedeemRejection::BadDenomination { what, index } => write!(
                f,
                "{what} {index}: ESP amounts are powers of two. Nothing was burned and no fee was taken"
            ),
            RedeemRejection::MemoInvalid { max } => write!(
                f,
                "the payout memo must not be empty and must be at most {max} bytes"
            ),
            RedeemRejection::DuplicateBlindNonce => {
                write!(f, "an output blind nonce is listed twice")
            }
            RedeemRejection::BlindNonceAlreadyUsed => {
                write!(f, "an output blind nonce was already used")
            }
            RedeemRejection::BadServiceSignature => write!(
                f,
                "the service's signature does not cover this request. Nothing was burned and no fee was taken"
            ),
            RedeemRejection::NoteHeld => write!(
                f,
                "an output in this request is held by another request that has not finished"
            ),
            RedeemRejection::BelowFee { value, fee, .. } => write!(
                f,
                "the genuine, unspent notes are worth {value} ESP units, less than the fee of {fee}. Nothing was burned and no fee was taken"
            ),
            RedeemRejection::OutputsOverLimit { list, totals } => write!(
                f,
                "{} total more than the mint will reissue for the notes it accepts (accepted {}, rejected but genuine {}, fee {}). Nothing was burned",
                list.name(),
                totals.accepted_esp,
                totals.rejected_esp,
                totals.fee_esp
            ),
            RedeemRejection::Keyset { why, .. } => write!(f, "{why}"),
            RedeemRejection::RefundRequired { totals } => write!(
                f,
                "the accepted notes ({} ESP units) do not cover the fee of {}, and the genuine notes that were rejected ({}) are worth more than the shortfall, so refund_outputs are needed. Nothing was burned",
                totals.accepted_esp, totals.fee_esp, totals.rejected_esp
            ),
        }
    }
}

#[derive(Debug)]
pub enum RedeemError {
    /// The request is refused. Nothing was burned.
    Rejected(RedeemRejection),
    /// A fault in the mint. A retry is safe.
    Internal(String),
}

impl fmt::Display for RedeemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedeemError::Rejected(r) => write!(f, "rejected: {r}"),
            RedeemError::Internal(e) => write!(f, "internal: {e}"),
        }
    }
}

impl Error for RedeemError {}

impl From<RedeemRejection> for RedeemError {
    fn from(r: RedeemRejection) -> Self {
        RedeemError::Rejected(r)
    }
}

fn internal<E: ToString>(e: E) -> RedeemError {
    RedeemError::Internal(e.to_string())
}

/// Amounts by service and day, in a stable order.
#[derive(Default)]
struct ByTerms(BTreeMap<(ServiceDid, u64), (ServiceDid, u128)>);

impl ByTerms {
    fn add(&mut self, service: ServiceDid, day: u64, units: u128) {
        let slot = self.0.entry((service, day)).or_insert((service, 0));
        slot.1 += units;
    }

    fn get(&self, service: &ServiceDid, day: u64) -> u128 {
        self.0.get(&(*service, day)).map_or(0, |slot| slot.1)
    }

    fn total(&self) -> u128 {
        self.0.values().map(|slot| slot.1).sum()
    }

    fn list(&self) -> Vec<TermsTotal> {
        self.0
            .iter()
            .map(|((_, day), (service, esp))| TermsTotal {
                service: *service,
                redeemable_after_day: *day,
                esp: *esp,
            })
            .collect()
    }
}

fn outputs_by_terms(list: &[RedeemOutput]) -> ByTerms {
    let mut by = ByTerms::default();
    for o in list {
        by.add(
            o.service,
            o.redeemable_after_day,
            u128::from(o.output.amount.units),
        );
    }
    by
}

/// Whether the outputs total at most `cap`, and for each service and day at
/// most `per_terms` allows.
fn within(list: &[RedeemOutput], cap: u128, per_terms: &ByTerms) -> bool {
    let asked = outputs_by_terms(list);
    asked.total() <= cap
        && asked
            .0
            .iter()
            .all(|((_, day), (service, esp))| *esp <= per_terms.get(service, *day))
}

/// The shape of the request. Nothing here touches the mint.
fn validate(request: &RedeemRequest, max_memo_bytes: usize) -> Result<(), RedeemRejection> {
    if request.inputs.is_empty() {
        return Err(RedeemRejection::NoInputs);
    }
    if request.memo.trim().is_empty() || request.memo.len() > max_memo_bytes {
        return Err(RedeemRejection::MemoInvalid {
            max: max_memo_bytes,
        });
    }
    if request.inputs.iter().any(|i| i.input.amount.units == 0) {
        return Err(RedeemRejection::ZeroAmount);
    }
    if let Some(index) = request
        .inputs
        .iter()
        .position(|i| !crate::units::is_denomination(i.input.amount.units))
    {
        return Err(RedeemRejection::BadDenomination {
            what: "note",
            index,
        });
    }
    if !is_keyset_id(&request.output_keyset)
        || request.inputs.iter().any(|i| !is_keyset_id(&i.keyset))
    {
        return Err(RedeemRejection::Malformed(
            "every note and the outputs need a keyset of 16 hex characters".into(),
        ));
    }
    let mut blind_nonces = HashSet::new();
    let lists = [
        ("decline output", &request.decline_outputs),
        ("refund output", &request.refund_outputs),
    ];
    for (what, list) in lists {
        if list.iter().any(|o| o.output.amount.units == 0) {
            return Err(RedeemRejection::ZeroAmount);
        }
        if let Some(index) = list
            .iter()
            .position(|o| !crate::units::is_denomination(o.output.amount.units))
        {
            return Err(RedeemRejection::BadDenomination { what, index });
        }
    }
    for o in request
        .decline_outputs
        .iter()
        .chain(request.refund_outputs.iter())
    {
        if !blind_nonces.insert(o.output.blind_nonce) {
            return Err(RedeemRejection::DuplicateBlindNonce);
        }
    }
    Ok(())
}

fn nonce_hex(input: &MintInput) -> String {
    hex::encode(input.note.nonce.0.serialize())
}

/// Decide every note, then check the fee and the limits on the outputs.
/// `held` holds the nonces of notes that another unfinished request will burn.
fn decide(
    gens: &Gens,
    request: &RedeemRequest,
    digest: [u8; 32],
    held: &HashSet<String>,
    fee_per_byte: u128,
    now_unix: u64,
) -> Result<Plan, RedeemError> {
    let mut notes = Vec::with_capacity(request.inputs.len());
    // genuine and not spent: the notes that count toward the value
    let mut counted = Vec::with_capacity(request.inputs.len());
    let mut seen = HashSet::new();
    let mut accepted_by = ByTerms::default();
    let mut rejected_by = ByTerms::default();

    for ri in &request.inputs {
        let claimed = Terms {
            service: ri.service,
            redeemable_after_day: ri.redeemable_after_day,
        };
        let named = gens.input_key(&ri.keyset, &ri.input, &claimed);
        let keyset_reason = match &named {
            Ok(_) => None,
            Err(crate::rotation::KeysetError::Retired(_)) => Some(Reason::KeysetRetired),
            // (an input's keyset is never "not current": previous-set notes
            // are accepted)
            Err(_) => Some(Reason::UnknownKeyset),
        };
        let genuine = match &named {
            Ok((logic, sk)) => {
                logic.verify_note_with_key(sk, &ri.input).is_ok()
                    && logic.verify_spend_authorization(&ri.input, digest).is_ok()
            }
            Err(_) => false,
        };
        let spent = if let (true, Ok((logic, _))) = (genuine, &named) {
            let listed_twice = !seen.insert(ri.input.note.nonce);
            listed_twice
                || held.contains(&nonce_hex(&ri.input))
                || logic.is_spent(ri.input.note.nonce).map_err(internal)?
        } else {
            false
        };
        let reason = if ri.service != request.service {
            Some(Reason::WrongService)
        } else if keyset_reason.is_some() {
            keyset_reason
        } else if !genuine {
            Some(Reason::BadProof)
        } else if spent {
            Some(Reason::AlreadySpent)
        } else if !claimed.is_redeemable_at(now_unix) {
            Some(Reason::Immature)
        } else {
            None
        };
        let units = u128::from(ri.input.amount.units);
        let accepted = reason.is_none();
        let counts = genuine && !spent;
        if accepted {
            accepted_by.add(ri.service, ri.redeemable_after_day, units);
        } else if counts {
            rejected_by.add(ri.service, ri.redeemable_after_day, units);
        }
        notes.push(NoteResult {
            accepted,
            reason,
            burned: accepted,
        });
        counted.push(counts);
    }

    let accepted = accepted_by.total();
    let rejected = rejected_by.total();
    let size_bytes = request.encoded_len();
    let fee = fee_for(size_bytes, fee_per_byte);
    let value = accepted + rejected;
    if value < fee {
        // nothing is burned when a request is refused
        for n in notes.iter_mut() {
            n.burned = false;
        }
        return Err(RedeemRejection::BelowFee { value, fee, notes }.into());
    }
    // What the accepted notes do not cover comes out of the rejected ones.
    let shortfall = fee.saturating_sub(accepted);
    if shortfall > 0 {
        for (note, counts) in notes.iter_mut().zip(&counted) {
            if *counts && !note.accepted {
                note.burned = true;
            }
        }
    }
    let owed = accepted.saturating_sub(fee);
    let totals = Totals {
        notes,
        accepted_esp: accepted,
        rejected_esp: rejected,
        fee_esp: fee,
        size_bytes,
        fee_per_byte,
        accepted_by_terms: accepted_by.list(),
        rejected_by_terms: rejected_by.list(),
    };

    if !within(&request.decline_outputs, owed, &accepted_by) {
        return Err(RedeemRejection::OutputsOverLimit {
            list: OutputList::Decline,
            totals,
        }
        .into());
    }
    // `rejected >= shortfall` here, because accepted + rejected >= fee.
    let refundable = if shortfall > 0 {
        rejected - shortfall
    } else {
        0
    };
    if shortfall > 0 && refundable > 0 && request.refund_outputs.is_empty() {
        return Err(RedeemRejection::RefundRequired { totals }.into());
    }
    if !within(&request.refund_outputs, refundable, &rejected_by) {
        return Err(RedeemRejection::OutputsOverLimit {
            list: OutputList::Refund,
            totals,
        }
        .into());
    }
    Ok(Plan {
        totals,
        owed_esp: owed,
    })
}

fn respond(
    queue_path: &Path,
    hash: &str,
    record: &RedeemRecord,
) -> Result<RedeemResponse, RedeemError> {
    let entry = if record.plan.owed_esp > 0 {
        Queue::open(queue_path)
            .map_err(internal)?
            .get(hash)
            .map(queue::Entry::view)
    } else {
        None
    };
    let totals = &record.plan.totals;
    Ok(RedeemResponse {
        notes: totals.notes.clone(),
        accepted_esp: totals.accepted_esp,
        rejected_esp: totals.rejected_esp,
        fee_esp: totals.fee_esp,
        size_bytes: totals.size_bytes,
        fee_per_byte: totals.fee_per_byte,
        owed_esp: record.plan.owed_esp,
        message: if record.plan.owed_esp > 0 {
            "payout queued".to_string()
        } else {
            "nothing owed, fee taken".to_string()
        },
        refund: record.refund.clone(),
        entry,
    })
}

/// Run a redemption at this fee rate and the default limits. `now_unix` is the
/// mint's clock, which decides maturity and stamps the queue entry.
pub fn redeem(
    logic: &MintLogic,
    master: &MasterSecret,
    responses: &mut Responses,
    queue_path: &Path,
    request: &RedeemRequest,
    fee_per_byte: u128,
    now_unix: u64,
) -> Result<RedeemResponse, RedeemError> {
    let settings = RedeemSettings {
        fee_per_byte,
        ..RedeemSettings::default()
    };
    redeem_with(
        logic, master, responses, queue_path, request, &settings, now_unix,
    )
}

/// Run a redemption with the mint's settings. The fee rate in `settings` is the
/// rate in force now: it is charged to a new request and written into its
/// decision, and a retry uses the stored decision, so the rate never changes for
/// a request once it has been accepted.
pub fn redeem_with(
    logic: &MintLogic,
    master: &MasterSecret,
    responses: &mut Responses,
    queue_path: &Path,
    request: &RedeemRequest,
    settings: &RedeemSettings,
    now_unix: u64,
) -> Result<RedeemResponse, RedeemError> {
    redeem_gens(
        &Gens::only(logic, master),
        responses,
        queue_path,
        request,
        settings,
        now_unix,
    )
}

/// [`redeem_with`] over both live key sets: each note is decided and burned in
/// the set that signed it, and the refund and decline outputs are signed with
/// the current set.
pub fn redeem_gens(
    gens: &Gens,
    responses: &mut Responses,
    queue_path: &Path,
    request: &RedeemRequest,
    settings: &RedeemSettings,
    now_unix: u64,
) -> Result<RedeemResponse, RedeemError> {
    let fee_per_byte = settings.fee_per_byte;
    validate(request, settings.max_memo_bytes)?;
    let digest = request.digest();
    let hash = request_hash(request);

    let mut stored_plan: Option<Plan> = None;
    let mut proven = false;
    match responses.get(&hash) {
        Some(Entry::RedeemDone(done)) => {
            let done = done.clone();
            return respond(queue_path, &hash, &done);
        }
        Some(Entry::RedeemPending(pending)) => {
            stored_plan = Some(pending.plan.clone());
            proven = pending.burned;
        }
        Some(_) => {
            return Err(internal(
                "something other than a redemption is stored under this request's hash",
            ));
        }
        None => {}
    }

    // Only the service may ask. Checked before anything else touches the mint.
    SECP256K1
        .verify_schnorr(
            &request.service_signature,
            &digest,
            &request.service.x_only(),
        )
        .map_err(|_| RedeemRejection::BadServiceSignature)?;

    let recovering = stored_plan.is_some();
    // The keyset for the refund and decline outputs. A request picked up again
    // after a crash, whose keyset retired since, signs with the current set.
    let (logic, master, out_keyset) =
        gens.signer(&request.output_keyset, recovering)
            .map_err(|e| RedeemRejection::Keyset {
                code: e.code(),
                why: e.why("the outputs"),
            })?;
    let plan = match stored_plan {
        Some(plan) => {
            if plan.totals.notes.len() != request.inputs.len() {
                return Err(internal("the stored decision does not match the request"));
            }
            plan
        }
        None => {
            // Everything other unfinished requests will burn or sign.
            let (mut held_inputs, mut held_outputs) = responses.redeem_holds(&hash);
            // Notes pending rollovers will burn.
            held_inputs.extend(responses.external_holds().iter().cloned());
            for (other, pending) in responses.pending_transfers() {
                if other != &hash {
                    held_inputs.extend(pending.inputs.iter().cloned());
                    held_outputs.extend(pending.outputs.iter().cloned());
                }
            }
            for (other, _, outputs) in responses.pending_exchanges() {
                if other != &hash {
                    held_outputs.extend(outputs.iter().cloned());
                }
            }
            let mut mine = Vec::new();
            for o in request
                .decline_outputs
                .iter()
                .chain(request.refund_outputs.iter())
            {
                if logic
                    .is_blind_nonce_used(&o.output.blind_nonce)
                    .map_err(internal)?
                {
                    return Err(RedeemRejection::BlindNonceAlreadyUsed.into());
                }
                mine.push(hex::encode(o.output.blind_nonce.0.serialize()));
            }
            if mine.iter().any(|n| held_outputs.contains(n)) {
                return Err(RedeemRejection::NoteHeld.into());
            }
            let plan = decide(gens, request, digest, &held_inputs, fee_per_byte, now_unix)?;
            let burns: Vec<String> = request
                .inputs
                .iter()
                .zip(&plan.totals.notes)
                .filter(|(_, note)| note.burned)
                .map(|(ri, _)| nonce_hex(&ri.input))
                .collect();
            responses
                .put(
                    &hash,
                    Entry::RedeemPending(RedeemPending {
                        burned: false,
                        inputs: burns,
                        outputs: mine,
                        plan: plan.clone(),
                    }),
                )
                .map_err(internal)?;
            plan
        }
    };

    // Burn what the decision names. On a retry, a note that is already spent was
    // burned by an earlier attempt of this same request, since no other request
    // could take it while the pending entry names it. Once every burn is done
    // that is recorded under the hash; a retry whose notes' keyset has since
    // been deleted (with its spent list) finishes only on that proof.
    if !proven {
        for (i, (ri, note)) in request.inputs.iter().zip(&plan.totals.notes).enumerate() {
            if !note.burned {
                continue;
            }
            let claimed = Terms {
                service: ri.service,
                redeemable_after_day: ri.redeemable_after_day,
            };
            let (logic, sk) = match gens.input_key(&ri.keyset, &ri.input, &claimed) {
                Ok(k) => k,
                // Proven burned when its keyset was deleted.
                Err(_) if recovering && gens.burn_proven(&ri.input) => continue,
                Err(e) => {
                    return Err(RedeemRejection::Keyset {
                        code: sp_wire::codes::BURN_NOT_PROVEN,
                        why: format!(
                            "note {i}: {}; this request was started before, but nothing stored proves its notes were burned under this request, so it cannot be finished without them",
                            e.why("its keyset")
                        ),
                    }
                    .into());
                }
            };
            if recovering && logic.is_spent(ri.input.note.nonce).map_err(internal)? {
                continue;
            }
            logic
                .redeem_with_key(&sk, &ri.input, digest)
                .map_err(internal)?;
        }
        if let Some(Entry::RedeemPending(p)) = responses.get(&hash) {
            let mut p = p.clone();
            p.burned = true;
            responses
                .put(&hash, Entry::RedeemPending(p))
                .map_err(internal)?;
        }
    }

    // Reissue what is left of the rejected notes, under their own terms.
    let mut refund = Vec::with_capacity(request.refund_outputs.len());
    for o in &request.refund_outputs {
        let terms = Terms {
            service: o.service,
            redeemable_after_day: o.redeemable_after_day,
        };
        let sk = master.key_for(o.output.amount, &terms);
        let signature = match logic.issue_with_key(&sk, &o.output) {
            Ok(outcome) => outcome.0,
            // Issued by an earlier attempt that stopped part way. Signing is
            // deterministic, so the same signature comes back.
            Err(MintOutputError::BlindNonceAlreadyUsed) if recovering => {
                bdhke::sign_message(&sk, &o.output.blind_nonce.0)
            }
            Err(e) => return Err(internal(e)),
        };
        refund.push(SignedOutput {
            signature,
            key: sk.public_key(SECP256K1),
            keyset: out_keyset.clone(),
        });
    }

    if plan.owed_esp > 0 {
        let mut queue = Queue::open(queue_path).map_err(internal)?;
        let entry = queue::Entry::open(
            &hash,
            request.service,
            plan.owed_esp,
            &request.memo,
            now_unix,
        )
        .with_fee(
            plan.totals.fee_per_byte,
            plan.totals.fee_esp,
            plan.totals.size_bytes,
        );
        match queue.add(entry) {
            Ok(()) => {}
            // Queued by an earlier attempt.
            Err(QueueError::Duplicate(_)) => {}
            Err(e) => return Err(internal(e)),
        }
    }

    let record = RedeemRecord {
        plan,
        refund,
        decline_outputs: request.decline_outputs.clone(),
        output_keyset: request.output_keyset.clone(),
    };
    // The ledger counts each burned note under its own day and each refund
    // output under its own day, in the same write that finishes the entry (see
    // `ledger`). The decline outputs are counted if the payout is declined.
    let mut movements = Movements::new();
    for (ri, note) in request.inputs.iter().zip(&record.plan.totals.notes) {
        if note.burned {
            movements.redeem(ri.redeemable_after_day, u128::from(ri.input.amount.units));
        }
    }
    for o in &request.refund_outputs {
        movements.issue(o.redeemable_after_day, u128::from(o.output.amount.units));
    }
    responses
        .finish(&hash, Entry::RedeemDone(record.clone()), &movements)
        .map_err(internal)?;
    respond(queue_path, &hash, &record)
}

/// What a decline did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Declined {
    pub entry_id: String,
    pub outputs: usize,
    #[serde(with = "dec")]
    pub reissued_esp: u128,
}

#[derive(Debug)]
pub enum DeclineError {
    /// The decline is refused and nothing was changed.
    Refused(String),
    /// A fault. Running the decline again is safe.
    Internal(String),
}

impl fmt::Display for DeclineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeclineError::Refused(why) => write!(f, "{why}"),
            DeclineError::Internal(e) => write!(f, "internal: {e}"),
        }
    }
}

impl Error for DeclineError {}

/// Decline the payout of an open queue entry: sign its stored decline outputs,
/// which reissue the accepted notes minus the fee, each under its original
/// service and day, then mark the entry declined with the reason and the
/// signatures. The service reads them by asking about its redemption again.
///
/// The fee is not returned. If this stops after signing and before the entry is
/// marked, run it again: signing is deterministic, so the same signatures come
/// out. Do not mark the entry paid in between.
pub fn decline(
    logic: &MintLogic,
    master: &MasterSecret,
    responses: &mut Responses,
    queue_path: &Path,
    entry_id: &str,
    reason: &str,
    now_unix: u64,
) -> Result<Declined, DeclineError> {
    decline_with(
        logic,
        master,
        responses,
        queue_path,
        entry_id,
        reason,
        DEFAULT_MAX_REASON_BYTES,
        now_unix,
    )
}

/// `decline`, with the longest reason set by the config.
#[allow(clippy::too_many_arguments)]
pub fn decline_with(
    logic: &MintLogic,
    master: &MasterSecret,
    responses: &mut Responses,
    queue_path: &Path,
    entry_id: &str,
    reason: &str,
    max_reason_bytes: usize,
    now_unix: u64,
) -> Result<Declined, DeclineError> {
    decline_gens(
        &Gens::only(logic, master),
        responses,
        queue_path,
        entry_id,
        reason,
        max_reason_bytes,
        now_unix,
    )
}

/// [`decline_with`] over the live key sets. The queue rule: the decline
/// outputs are signed with the keyset the redemption asked for if it is still
/// current or previous; if it retired before the decline, with the current
/// keyset. Either way each signature names the keyset that made it, so the
/// service unblinds with the right keys. Nothing is lost: blinding does not
/// depend on the key.
pub fn decline_gens(
    gens: &Gens,
    responses: &mut Responses,
    queue_path: &Path,
    entry_id: &str,
    reason: &str,
    max_reason_bytes: usize,
    now_unix: u64,
) -> Result<Declined, DeclineError> {
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > max_reason_bytes {
        return Err(DeclineError::Refused(format!(
            "a reason is required, and it may be at most {max_reason_bytes} bytes"
        )));
    }
    let mut queue = Queue::open(queue_path).map_err(|e| DeclineError::Internal(e.to_string()))?;
    match queue.get(entry_id) {
        None => return Err(DeclineError::Refused(format!("no entry {entry_id}"))),
        Some(entry) if entry.status != Status::Open => {
            return Err(DeclineError::Refused(format!(
                "entry {entry_id} is not open (it is {:?})",
                entry.status
            )));
        }
        Some(_) => {}
    }
    let record = match responses.get(entry_id) {
        Some(Entry::RedeemDone(record)) => record.clone(),
        _ => {
            return Err(DeclineError::Refused(format!(
                "entry {entry_id} has no stored redemption, so there is nothing to reissue"
            )));
        }
    };

    let (logic, master, keyset) = gens
        .signer(&record.output_keyset, true)
        .expect("a resumed signer falls back to the current keyset");
    let mut signatures = Vec::with_capacity(record.decline_outputs.len());
    let mut reissued: u128 = 0;
    for o in &record.decline_outputs {
        let terms = Terms {
            service: o.service,
            redeemable_after_day: o.redeemable_after_day,
        };
        let sk = master.key_for(o.output.amount, &terms);
        let signature = match logic.issue_with_key(&sk, &o.output) {
            Ok(outcome) => outcome.0,
            // Signed by an earlier run that stopped before the entry was marked.
            Err(MintOutputError::BlindNonceAlreadyUsed) => {
                bdhke::sign_message(&sk, &o.output.blind_nonce.0)
            }
            Err(e) => return Err(DeclineError::Internal(e.to_string())),
        };
        reissued += u128::from(o.output.amount.units);
        signatures.push(SignedOutput {
            signature,
            key: sk.public_key(SECP256K1),
            keyset: keyset.clone(),
        });
    }
    // The ledger counts the reissued notes under their own days, once per
    // entry, before the queue entry is marked: if this stops in between, running
    // it again signs the same outputs and counts nothing twice.
    let mut movements = Movements::new();
    for o in &record.decline_outputs {
        movements.issue(o.redeemable_after_day, u128::from(o.output.amount.units));
    }
    responses
        .count_decline(entry_id, &movements)
        .map_err(|e| DeclineError::Internal(e.to_string()))?;
    let count = signatures.len();
    queue
        .decline(entry_id, reason, signatures, now_unix)
        .map_err(|e| {
            if e.is_refusal() {
                DeclineError::Refused(e.to_string())
            } else {
                DeclineError::Internal(e.to_string())
            }
        })?;
    Ok(Declined {
        entry_id: entry_id.to_string(),
        outputs: count,
        reissued_esp: reissued,
    })
}

#[cfg(test)]
pub(crate) fn empty_plan() -> Plan {
    Plan {
        totals: Totals {
            notes: vec![],
            accepted_esp: 0,
            rejected_esp: 0,
            fee_esp: 0,
            size_bytes: 0,
            fee_per_byte: 0,
            accepted_by_terms: vec![],
            rejected_by_terms: vec![],
        },
        owed_esp: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    use mint_types::{Amount, BlindNonce, Nonce, Note};
    use rand::rngs::OsRng;
    use secp256k1::schnorr::Signature;
    use secp256k1::{Keypair, SecretKey};

    use crate::queue::Payment;
    use crate::responses::TransferPending;

    const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    /// Day 20_735.
    const NOW: u64 = 1_791_571_184;
    /// Days whose notes are redeemable at NOW.
    const PAST: u64 = 20_000;
    const PAST2: u64 = 20_500;
    /// A day that has not come at NOW.
    const FUTURE: u64 = 21_100;
    /// A test amount, a power of two (about $4.40); the fee tests below depend on
    /// its size.
    const ONE: u64 = 1 << 42;
    /// A note smaller than the fee of a request of two notes.
    const SMALL: u64 = 1 << 40;
    /// The fee rate in these tests: 2^31 ESP units a byte. With `MEMO` a request
    /// of one note is 512 bytes, so its fee is 2^40, a power of two: a note can
    /// be worth exactly that fee, and every note is a power of two.
    const RATE: u128 = 1 << 31;

    /// The fee of a request with this many inputs, decline outputs and refund
    /// outputs, with the memo `MEMO`.
    fn fee(inputs: usize, decline: usize, refund: usize) -> u64 {
        u64::try_from(fee_for(
            encoded_len(inputs, MEMO.len(), decline, refund),
            RATE,
        ))
        .unwrap()
    }

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

    fn other() -> ServiceDid {
        ServiceDid::from(other_keypair().public_key())
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("esp-mint-rd-{}-{name}", {
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
        logic: MintLogic,
        master: MasterSecret,
        responses: Responses,
        queue_path: PathBuf,
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
        let (logic, master) = crate::mint::open(&dir.join("esp")).unwrap();
        KS.with(|k| *k.borrow_mut() = crate::rotation::keyset_id(&master));
        let responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
        let queue_path = dir.join("esp").join("queue.json");
        Setup {
            dir,
            logic,
            master,
            responses,
            queue_path,
        }
    }

    /// An ESP note the service holds: what it claims for it, and the key that
    /// spends it.
    #[derive(Clone)]
    struct Held {
        note: Note,
        key: Keypair,
        units: u64,
        service: ServiceDid,
        day: u64,
    }

    /// A new output wanted: its keys and blinding factor.
    struct Wanted {
        nonce: Nonce,
        blinding_key: SecretKey,
        amount: u64,
        service: ServiceDid,
        day: u64,
    }

    /// (units, service, day)
    type Out = (u64, ServiceDid, u64);

    /// Split `total` into exactly `n` outputs that are powers of two, under the
    /// same terms: the bits of `total`, then the largest output halved until
    /// there are `n`. Needs `popcount(total) <= n <= total`.
    fn split_out_into(total: u64, n: usize, service: ServiceDid, day: u64) -> Vec<Out> {
        let mut outs = split_out(total, service, day);
        while outs.len() < n {
            let i = outs.iter().position(|o| o.0 > 1).unwrap();
            outs[i].0 /= 2;
            let half = outs[i];
            outs.insert(i + 1, half);
        }
        outs
    }

    /// The fewest outputs `n`, from `fixed` + 1 up, for which the amount to
    /// split, `rest_for(n)` (it falls as the fee for `n` outputs rises), and
    /// that amount plus one both split into exactly `n - fixed` powers of two.
    /// The fee depends on how many outputs there are, and how many there are
    /// depends on the fee.
    fn fewest_outputs(fixed: usize, rest_for: impl Fn(usize) -> u64) -> usize {
        (fixed + 1..1_000)
            .find(|&n| {
                let rest = rest_for(n);
                let k = n - fixed;
                [rest, rest + 1]
                    .iter()
                    .all(|v| v.count_ones() as usize <= k && k as u64 <= *v)
            })
            .unwrap()
    }

    /// A total split into powers of two, the way the wallet does: one output for
    /// each bit set, largest first, all under the same terms.
    fn split_out(total: u64, service: ServiceDid, day: u64) -> Vec<Out> {
        (0..64)
            .rev()
            .map(|bit| 1u64 << bit)
            .filter(|p| total & p != 0)
            .map(|p| (p, service, day))
            .collect()
    }

    fn dummy_signature() -> Signature {
        Signature::from_slice(&[0u8; 64]).unwrap()
    }

    fn hexn(note: &Note) -> String {
        hex::encode(note.nonce.0.serialize())
    }

    impl Setup {
        /// A note the mint has issued under these terms.
        fn held(&self, units: u64, service: ServiceDid, day: u64) -> Held {
            let terms = Terms {
                service,
                redeemable_after_day: day,
            };
            let key = Keypair::new(SECP256K1, &mut OsRng);
            let nonce = Nonce(key.public_key());
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
            Held {
                note: Note { nonce, signature },
                key,
                units,
                service,
                day,
            }
        }

        fn run(&mut self, request: &RedeemRequest) -> Result<RedeemResponse, RedeemError> {
            redeem(
                &self.logic,
                &self.master,
                &mut self.responses,
                &self.queue_path,
                request,
                RATE,
                NOW,
            )
        }

        /// (issued, redeemed) ESP units.
        fn totals(&self) -> (u64, u64) {
            let (issued, redeemed) = self.logic.audit_totals().unwrap();
            (issued.units, redeemed.units)
        }

        fn queue(&self) -> Queue {
            Queue::open(&self.queue_path).unwrap()
        }

        fn is_spent(&self, h: &Held) -> bool {
            self.logic.is_spent(h.note.nonce).unwrap()
        }

        /// Spend a note some other way, as a transfer would.
        fn spend_elsewhere(&self, h: &Held) {
            let terms = Terms {
                service: h.service,
                redeemable_after_day: h.day,
            };
            let sk = self.master.key_for(Amount::from_units(h.units), &terms);
            let input = MintInput {
                amount: Amount::from_units(h.units),
                note: h.note,
                spend_signature: SECP256K1.sign_schnorr(&[9u8; 32], &h.key),
            };
            self.logic.redeem_with_key(&sk, &input, [9u8; 32]).unwrap();
        }

        /// Burn one note of a request as the mint would.
        fn burn(&self, request: &RedeemRequest, index: usize) {
            let ri = &request.inputs[index];
            let terms = Terms {
                service: ri.service,
                redeemable_after_day: ri.redeemable_after_day,
            };
            let sk = self.master.key_for(ri.input.amount, &terms);
            self.logic
                .redeem_with_key(&sk, &ri.input, request.digest())
                .unwrap();
        }

        /// Write the pending entry the mint writes before it burns, and return
        /// the plan.
        fn pend(&mut self, request: &RedeemRequest) -> Plan {
            let plan = decide(
                &Gens::only(&self.logic, &self.master),
                request,
                request.digest(),
                &HashSet::new(),
                RATE,
                NOW,
            )
            .unwrap();
            let inputs = request
                .inputs
                .iter()
                .zip(&plan.totals.notes)
                .filter(|(_, n)| n.burned)
                .map(|(ri, _)| hexn(&ri.input.note))
                .collect();
            let outputs = request
                .decline_outputs
                .iter()
                .chain(request.refund_outputs.iter())
                .map(|o| hex::encode(o.output.blind_nonce.0.serialize()))
                .collect();
            self.responses
                .put(
                    &request_hash(request),
                    Entry::RedeemPending(RedeemPending {
                        burned: false,
                        inputs,
                        outputs,
                        plan: plan.clone(),
                    }),
                )
                .unwrap();
            plan
        }
    }

    fn outputs(list: &[Out]) -> (Vec<RedeemOutput>, Vec<Wanted>) {
        let mut outs = Vec::new();
        let mut wanted = Vec::new();
        for &(amount, svc, day) in list {
            let keypair = Keypair::new(SECP256K1, &mut OsRng);
            let nonce = Nonce(keypair.public_key());
            let (blind_point, blinding_key) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
            outs.push(RedeemOutput {
                service: svc,
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
                service: svc,
                day,
            });
        }
        (outs, wanted)
    }

    /// Build a request the way a service does. `spend_signer` signs every input
    /// instead of the note's own key, and `service_signer` signs for the service.
    fn build_with(
        ins: &[&Held],
        decline: &[Out],
        refund: &[Out],
        memo: &str,
        service_signer: &Keypair,
        spend_signer: Option<&Keypair>,
    ) -> (RedeemRequest, Vec<Wanted>, Vec<Wanted>) {
        let (decline_outputs, decline_wanted) = outputs(decline);
        let (refund_outputs, refund_wanted) = outputs(refund);
        let request = build_raw(
            ins,
            decline_outputs,
            refund_outputs,
            memo,
            service_signer,
            spend_signer,
        );
        (request, decline_wanted, refund_wanted)
    }

    /// The same, from outputs that are already made.
    fn build_raw(
        ins: &[&Held],
        decline_outputs: Vec<RedeemOutput>,
        refund_outputs: Vec<RedeemOutput>,
        memo: &str,
        service_signer: &Keypair,
        spend_signer: Option<&Keypair>,
    ) -> RedeemRequest {
        let mut inputs: Vec<RedeemInput> = ins
            .iter()
            .map(|h| RedeemInput {
                service: h.service,
                redeemable_after_day: h.day,
                keyset: ks(),
                input: MintInput {
                    amount: Amount::from_units(h.units),
                    note: h.note,
                    spend_signature: dummy_signature(),
                },
            })
            .collect();
        let sighash = digest(
            &service(),
            &ks(),
            &inputs,
            memo,
            &decline_outputs,
            &refund_outputs,
        );
        for (ri, h) in inputs.iter_mut().zip(ins) {
            ri.input.spend_signature =
                SECP256K1.sign_schnorr(&sighash, spend_signer.unwrap_or(&h.key));
        }
        let service_signature = SECP256K1.sign_schnorr(&sighash, service_signer);
        RedeemRequest {
            service: service(),
            output_keyset: ks(),
            inputs,
            memo: memo.to_string(),
            decline_outputs,
            refund_outputs,
            service_signature,
        }
    }

    fn build(ins: &[&Held], decline: &[Out], refund: &[Out]) -> RedeemRequest {
        build_with(ins, decline, refund, MEMO, &service_keypair(), None).0
    }

    /// 205 bytes, so that a request of one note and no outputs is 512 bytes.
    const MEMO: &str = "btc:bc1qpayhere-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    /// 123 bytes, so that a request of one note and one output is 512 bytes.
    const SHORT_MEMO: &str = "btc:bc1qpayhere-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    fn rejection(result: Result<RedeemResponse, RedeemError>) -> RedeemRejection {
        match result {
            Err(RedeemError::Rejected(r)) => r,
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    /// The same note, claimed under other terms.
    fn claiming(h: &Held, service: ServiceDid, day: u64) -> Held {
        Held {
            service,
            day,
            ..h.clone()
        }
    }

    /// A note the mint never issued.
    fn forged(units: u64) -> Held {
        let key = Keypair::new(SECP256K1, &mut OsRng);
        Held {
            note: Note {
                nonce: Nonce(key.public_key()),
                signature: key.public_key(),
            },
            key,
            units,
            service: service(),
            day: PAST,
        }
    }

    /// Check that a signed output unblinds to a note the mint accepts under the
    /// terms it was asked for.
    fn assert_signed(s: &Setup, signed: &SignedOutput, wanted: &Wanted) {
        let terms = Terms {
            service: wanted.service,
            redeemable_after_day: wanted.day,
        };
        let sk = s.master.key_for(Amount::from_units(wanted.amount), &terms);
        assert_eq!(signed.key, sk.public_key(SECP256K1));
        let unblinded =
            bdhke::unblind_message(&signed.signature, &wanted.blinding_key, &signed.key);
        assert!(bdhke::verify_message(
            &sk,
            unblinded,
            &wanted.nonce.as_hash_preimage()
        ));
    }

    fn reasons(response: &RedeemResponse) -> Vec<Option<Reason>> {
        response.notes.iter().map(|n| n.reason).collect()
    }

    fn done_record(s: &Setup, request: &RedeemRequest) -> RedeemRecord {
        match s.responses.get(&request_hash(request)) {
            Some(Entry::RedeemDone(record)) => record.clone(),
            other => panic!("expected a finished redemption, got {other:?}"),
        }
    }

    // ---- the happy path ----

    #[test]
    fn a_redemption_burns_the_notes_and_queues_the_payout_minus_the_fee() {
        let mut s = setup("happy");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, service(), PAST2);
        assert_eq!(s.totals(), (6 * ONE, 0));
        let request = build(
            &[&a, &b],
            &[(2 * ONE, service(), PAST), (2 * ONE, service(), PAST2)],
            &[],
        );
        let response = s.run(&request).unwrap();

        assert!(response.notes.iter().all(|n| n.accepted && n.burned));
        assert_eq!(reasons(&response), vec![None, None]);
        assert_eq!(response.accepted_esp, u128::from(6 * ONE));
        assert_eq!(response.rejected_esp, 0);
        assert_eq!(response.fee_esp, u128::from(fee(2, 2, 0)));
        assert_eq!(response.size_bytes, request.encode().len() as u64);
        assert_eq!(response.message, "payout queued");
        assert_eq!(response.owed_esp, u128::from(6 * ONE - fee(2, 2, 0)));
        assert!(response.refund.is_empty());
        let view = response.entry.clone().unwrap();
        assert_eq!(view.status, Status::Open);
        assert_eq!(view.owed_esp, u128::from(6 * ONE - fee(2, 2, 0)));

        assert!(s.is_spent(&a) && s.is_spent(&b));
        // the notes are redeemed and nothing is issued: the decline outputs wait
        assert_eq!(s.totals(), (6 * ONE, 6 * ONE));

        let queue = s.queue();
        assert_eq!(queue.len(), 1);
        let entry = queue.get(&request_hash(&request)).unwrap();
        assert_eq!(entry.service, service());
        assert_eq!(entry.owed_esp, u128::from(6 * ONE - fee(2, 2, 0)));
        assert_eq!(entry.memo, MEMO);
        assert_eq!(entry.created_unix, NOW);
        assert_eq!(entry.status, Status::Open);

        let record = done_record(&s, &request);
        assert_eq!(record.decline_outputs, request.decline_outputs);
        for o in &request.decline_outputs {
            assert!(!s.logic.is_blind_nonce_used(&o.output.blind_nonce).unwrap());
        }
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_request_with_no_decline_outputs_is_fine() {
        let mut s = setup("no-decline");
        let a = s.held(4 * ONE, service(), PAST);
        let request = build(&[&a], &[], &[]);
        let response = s.run(&request).unwrap();
        assert_eq!(response.owed_esp, u128::from(4 * ONE - fee(1, 0, 0)));
        assert!(s.is_spent(&a));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    // ---- the signature comes first ----

    #[test]
    fn a_bad_service_signature_means_no_burn_no_fee_and_no_trace() {
        let mut s = setup("bad-sig");
        let a = s.held(4 * ONE, service(), PAST);
        let totals = s.totals();
        let (request, _, _) = build_with(&[&a], &[], &[], MEMO, &other_keypair(), None);
        assert_eq!(
            rejection(s.run(&request)),
            RedeemRejection::BadServiceSignature
        );
        assert!(!s.is_spent(&a));
        assert_eq!(s.totals(), totals);
        assert!(s.responses.is_empty());
        assert!(s.queue().is_empty());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_signature_over_another_request_does_not_cover_this_one() {
        let mut s = setup("sig-other-request");
        let a = s.held(4 * ONE, service(), PAST);
        let mut request = build(&[&a], &[], &[]);
        request.memo = "btc:bc1qsomewhereelse".to_string();
        assert_eq!(
            rejection(s.run(&request)),
            RedeemRejection::BadServiceSignature
        );
        assert!(!s.is_spent(&a));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn the_service_signature_is_checked_before_the_notes_are_looked_at() {
        let mut s = setup("sig-first");
        // every note is junk, and the signature is wrong: the signature is what
        // is reported, not the fee
        let junk = forged(ONE / 2);
        let (request, _, _) = build_with(&[&junk], &[], &[], MEMO, &other_keypair(), None);
        assert_eq!(
            rejection(s.run(&request)),
            RedeemRejection::BadServiceSignature
        );
        assert!(s.responses.is_empty());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    // ---- each note on its own ----

    #[test]
    fn a_note_for_another_service_is_rejected_alone_and_left_unburned() {
        let mut s = setup("wrong-service");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, other(), PAST);
        let request = build(&[&a, &b], &[(2 * ONE, service(), PAST)], &[]);
        let response = s.run(&request).unwrap();

        assert_eq!(reasons(&response), vec![None, Some(Reason::WrongService)]);
        assert!(response.notes[0].burned);
        assert!(!response.notes[1].burned);
        assert_eq!(response.accepted_esp, u128::from(4 * ONE));
        assert_eq!(response.rejected_esp, u128::from(2 * ONE));
        assert_eq!(response.owed_esp, u128::from(4 * ONE - fee(2, 1, 0)));
        assert!(s.is_spent(&a));
        assert!(!s.is_spent(&b));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_note_claimed_under_the_wrong_terms_is_a_bad_proof_and_counts_for_nothing() {
        let mut s = setup("bad-proof");
        let a = s.held(4 * ONE, service(), PAST);
        let c = s.held(2 * ONE, service(), PAST);
        // the right service and amount, but a day it was not signed for
        let wrong_day = claiming(&c, service(), PAST2);
        // another service's note, claimed as ours: still not genuine under that
        // key, so BadProof and not WrongService
        let stolen = claiming(&s.held(ONE, other(), PAST), service(), PAST);
        let request = build(
            &[&a, &wrong_day, &stolen],
            &[(2 * ONE, service(), PAST)],
            &[],
        );
        let response = s.run(&request).unwrap();

        assert_eq!(
            reasons(&response),
            vec![None, Some(Reason::BadProof), Some(Reason::BadProof)]
        );
        assert_eq!(response.accepted_esp, u128::from(4 * ONE));
        assert_eq!(response.rejected_esp, 0);
        assert!(!s.is_spent(&c));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_spend_signature_by_the_wrong_key_is_a_bad_proof() {
        let mut s = setup("bad-spend");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, service(), PAST);
        let thief = Keypair::new(SECP256K1, &mut OsRng);
        let (request, _, _) =
            build_with(&[&a, &b], &[], &[], MEMO, &service_keypair(), Some(&thief));
        // every spend signature is wrong, so nothing is genuine and nothing is
        // worth anything: the request is below the fee
        match rejection(s.run(&request)) {
            RedeemRejection::BelowFee {
                value,
                fee: f,
                notes,
            } => {
                assert_eq!(value, 0);
                assert_eq!(f, u128::from(fee(2, 0, 0)));
                assert_eq!(
                    notes.iter().map(|n| n.reason).collect::<Vec<_>>(),
                    vec![Some(Reason::BadProof), Some(Reason::BadProof)]
                );
                assert!(notes.iter().all(|n| !n.accepted && !n.burned));
            }
            other => panic!("expected below_fee, got {other:?}"),
        }
        assert!(!s.is_spent(&a) && !s.is_spent(&b));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_spent_note_and_a_note_listed_twice_are_already_spent() {
        let mut s = setup("already-spent");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, service(), PAST);
        s.spend_elsewhere(&b);
        let request = build(&[&a, &b, &a], &[(2 * ONE, service(), PAST)], &[]);
        let response = s.run(&request).unwrap();

        assert_eq!(
            reasons(&response),
            vec![None, Some(Reason::AlreadySpent), Some(Reason::AlreadySpent)]
        );
        // the note listed twice counts once
        assert_eq!(response.accepted_esp, u128::from(4 * ONE));
        assert_eq!(response.rejected_esp, 0);
        assert_eq!(response.owed_esp, u128::from(4 * ONE - fee(3, 1, 0)));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn below_fee_says_which_notes_are_spent_and_burns_none() {
        let mut s = setup("below-fee-reasons");
        // two tiny notes, one of them spent by another request: what is left
        // is worth less than the fee
        let a = s.held(8, service(), PAST);
        let b = s.held(8, service(), PAST);
        s.spend_elsewhere(&b);
        let request = build(&[&a, &b], &[], &[]);
        let rejected = rejection(s.run(&request));
        let RedeemRejection::BelowFee { value, notes, .. } = &rejected else {
            panic!("expected below_fee, got {rejected:?}");
        };
        assert_eq!(*value, 8);
        assert_eq!(
            notes.iter().map(|n| n.reason).collect::<Vec<_>>(),
            vec![None, Some(Reason::AlreadySpent)]
        );
        assert!(notes.iter().all(|n| !n.burned));
        // the body a wallet reads carries the same list, and keeps the old fields
        let body = rejected.details();
        assert_eq!(body["value_esp"], "8");
        assert!(body["fee_esp"].is_string());
        assert_eq!(body["notes"][1]["reason"], "already_spent");
        assert_eq!(body["notes"][0]["reason"], Value::Null);
        // nothing was burned
        assert!(!s.is_spent(&a));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_note_that_is_not_mature_is_rejected_alone_and_stays_with_the_holder() {
        let mut s = setup("immature");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, service(), FUTURE);
        let request = build(&[&a, &b], &[(2 * ONE, service(), PAST)], &[]);
        let response = s.run(&request).unwrap();

        assert_eq!(reasons(&response), vec![None, Some(Reason::Immature)]);
        assert_eq!(response.owed_esp, u128::from(4 * ONE - fee(2, 1, 0)));
        assert_eq!(response.rejected_esp, u128::from(2 * ONE));
        assert!(s.is_spent(&a));
        assert!(!s.is_spent(&b));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_note_is_mature_from_the_start_of_its_day() {
        let mut s = setup("maturity");
        let today = NOW / 86_400;
        let a = s.held(2 * ONE, service(), today);
        let b = s.held(ONE, service(), today + 1);
        let request = build(&[&a, &b], &[], &[]);
        let response = s.run(&request).unwrap();
        assert_eq!(reasons(&response), vec![None, Some(Reason::Immature)]);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn the_first_reason_that_applies_is_the_one_given() {
        let mut s = setup("reason-order");
        // another service's note that is also spent: WrongService wins
        let a = s.held(4 * ONE, service(), PAST);
        let w = s.held(ONE, other(), PAST);
        s.spend_elsewhere(&w);
        // spent and not mature: AlreadySpent wins over Immature
        let f = s.held(ONE, service(), FUTURE);
        s.spend_elsewhere(&f);
        let request = build(&[&a, &w, &f], &[], &[]);
        let response = s.run(&request).unwrap();
        assert_eq!(
            reasons(&response),
            vec![None, Some(Reason::WrongService), Some(Reason::AlreadySpent)]
        );
        fs::remove_dir_all(&s.dir).unwrap();
    }

    // ---- amounts are powers of two ----

    #[test]
    fn a_note_or_an_output_that_is_not_a_power_of_two_is_refused_before_anything_is_burned_or_charged()
     {
        let mut s = setup("denomination");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, service(), FUTURE);
        // an odd note, issued directly: the mint holds it under that amount
        let odd = s.held(ONE + 5, service(), PAST);
        let totals = s.totals();

        let check = |s: &mut Setup, request: &RedeemRequest, what: &'static str, index: usize| {
            let r = rejection(s.run(request));
            assert_eq!(r, RedeemRejection::BadDenomination { what, index });
            assert_eq!(r.code(), "bad_denomination");
            assert_eq!(
                r.to_string(),
                format!(
                    "{what} {index}: ESP amounts are powers of two. Nothing was burned and no fee was taken"
                )
            );
        };

        // an incoming note
        let request = build(&[&a, &odd], &[], &[]);
        check(&mut s, &request, "note", 1);
        // a decline output, among good ones
        let request = build(
            &[&a],
            &[(ONE, service(), PAST), (ONE - 1, service(), PAST)],
            &[],
        );
        check(&mut s, &request, "decline output", 1);
        // a refund output
        let request = build(&[&a, &b], &[], &[(ONE + 1, service(), FUTURE)]);
        check(&mut s, &request, "refund output", 0);

        for h in [&a, &b, &odd] {
            assert!(!s.is_spent(h));
        }
        assert_eq!(s.totals(), (totals.0, totals.1));
        assert!(s.responses.is_empty());
        assert!(s.queue().is_empty());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn outputs_split_into_powers_of_two_are_reissued() {
        let mut s = setup("split-outputs");
        let a = s.held(4 * ONE, service(), PAST);
        // 4 ONE less the fee (two decline outputs or more), as powers of two
        let n = fewest_outputs(0, |n| 4 * ONE - fee(1, n, 0));
        let max = 4 * ONE - fee(1, n, 0);
        let decline = split_out_into(max, n, service(), PAST);
        assert!(decline.iter().all(|o| o.0.is_power_of_two()));
        let request = build(&[&a], &decline, &[]);
        assert_eq!(request.decline_outputs.len(), n);
        let response = s.run(&request).unwrap();
        assert_eq!(response.owed_esp, u128::from(max));
        assert!(response.entry.is_some());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    // ---- fee ----

    #[test]
    fn the_fee_is_sized_by_the_whole_request_and_a_request_below_it_is_refused_whole() {
        let mut s = setup("below-fee");
        let a = s.held(SMALL, service(), PAST);
        let junk = forged(8 * ONE);
        let totals = s.totals();
        let request = build(&[&a, &junk], &[], &[]);
        // the junk note is in the request, so it is in the size, but it is not value
        match rejection(s.run(&request)) {
            RedeemRejection::BelowFee { value, fee: f, .. } => {
                assert_eq!(value, u128::from(SMALL));
                assert_eq!(f, u128::from(fee(2, 0, 0)));
            }
            other => panic!("expected below_fee, got {other:?}"),
        }
        assert!(!s.is_spent(&a));
        assert_eq!(s.totals(), totals);
        assert!(s.responses.is_empty());
        assert!(s.queue().is_empty());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn exactly_the_fee_is_enough_and_leaves_nothing_owed() {
        let mut s = setup("exact-fee");
        let f = fee(1, 0, 0);
        let a = s.held(f, service(), PAST);
        let request = build(&[&a], &[], &[]);
        let response = s.run(&request).unwrap();
        assert_eq!(response.owed_esp, 0);
        assert_eq!(response.fee_esp, u128::from(f));
        assert_eq!(response.message, "nothing owed, fee taken");
        assert!(response.entry.is_none());
        assert!(s.is_spent(&a));
        assert!(s.queue().is_empty());
        assert_eq!(s.totals(), (f, f));
        // a retry returns the same answer and charges nothing more
        assert_eq!(s.run(&request).unwrap(), response);
        assert_eq!(s.totals(), (f, f));
        assert!(matches!(
            s.responses.get(&request_hash(&request)),
            Some(Entry::RedeemDone(_))
        ));

        // half the fee is below the fee (every note is a power of two, so there
        // is no note one unit short)
        let b = s.held(f / 2, service(), PAST);
        let request = build(&[&b], &[], &[]);
        assert!(matches!(
            rejection(s.run(&request)),
            RedeemRejection::BelowFee { .. }
        ));
        assert!(!s.is_spent(&b));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn accepted_notes_that_do_not_cover_the_fee_take_the_rest_from_the_rejected_ones() {
        let mut s = setup("shortfall");
        let a_units = SMALL;
        let a = s.held(a_units, service(), PAST);
        let b = s.held(4 * ONE, service(), FUTURE);
        // the accepted note is less than the fee, so the rest of the fee comes from
        // the immature note, and what is left of it may come back
        // (the fee depends on how many refund outputs there are, and the
        // refund is split into powers of two, so find the count that fits)
        let n = fewest_outputs(0, |n| 4 * ONE - (fee(2, 0, n) - a_units));
        let f = fee(2, 0, n);
        assert!(f > a_units);
        let shortfall = f - a_units;
        let max_refund = 4 * ONE - shortfall;
        let (request, _, refund_wanted) = build_with(
            &[&a, &b],
            &[],
            &split_out_into(max_refund, n, service(), FUTURE),
            MEMO,
            &service_keypair(),
            None,
        );
        let before = s.totals();
        let response = s.run(&request).unwrap();

        assert_eq!(reasons(&response), vec![None, Some(Reason::Immature)]);
        assert!(response.notes[0].burned);
        // burned though not accepted
        assert!(response.notes[1].burned);
        assert_eq!(response.fee_esp, u128::from(f));
        assert_eq!(response.owed_esp, 0);
        assert_eq!(response.message, "nothing owed, fee taken");
        assert!(response.entry.is_none());
        assert_eq!(response.refund.len(), refund_wanted.len());
        for (issued, wanted) in response.refund.iter().zip(&refund_wanted) {
            assert_signed(&s, issued, wanted);
        }
        assert!(s.is_spent(&a) && s.is_spent(&b));
        assert!(s.queue().is_empty());
        // both notes redeemed, the refund issued, and the difference is the fee
        let (issued, redeemed) = s.totals();
        assert_eq!(redeemed - before.1, a_units + 4 * ONE);
        assert_eq!(issued - before.0, max_refund);
        assert_eq!((issued - before.0) + f, redeemed - before.1);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_refund_may_be_less_than_the_most_allowed_and_keeps_its_terms() {
        let mut s = setup("refund-less");
        let b = s.held(4 * ONE, service(), FUTURE);
        let c = s.held(2 * ONE, other(), PAST);
        // nothing accepted: shortfall = 1, so up to 4 comes back, each part
        // under the terms of the notes it comes from
        let (request, _, refund_wanted) = build_with(
            &[&b, &c],
            &[],
            &[(2 * ONE, service(), FUTURE), (ONE, other(), PAST)],
            MEMO,
            &service_keypair(),
            None,
        );
        let response = s.run(&request).unwrap();
        assert_eq!(
            reasons(&response),
            vec![Some(Reason::Immature), Some(Reason::WrongService)]
        );
        assert_eq!(response.accepted_esp, 0);
        assert_eq!(response.refund.len(), 2);
        assert_signed(&s, &response.refund[0], &refund_wanted[0]);
        assert_signed(&s, &response.refund[1], &refund_wanted[1]);
        assert!(s.is_spent(&b) && s.is_spent(&c));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn without_refund_outputs_a_request_that_needs_them_is_refused_with_the_totals() {
        let mut s = setup("refund-required");
        let a = s.held(SMALL, service(), PAST);
        let b = s.held(4 * ONE, service(), FUTURE);
        let totals = s.totals();
        let request = build(&[&a, &b], &[], &[]);
        match rejection(s.run(&request)) {
            RedeemRejection::RefundRequired { totals: t } => {
                assert_eq!(t.accepted_esp, u128::from(SMALL));
                assert_eq!(t.rejected_esp, u128::from(4 * ONE));
                assert_eq!(t.fee_esp, u128::from(fee(2, 0, 0)));
                assert_eq!(t.size_bytes, encoded_len(2, MEMO.len(), 0, 0));
                assert_eq!(t.notes.len(), 2);
                assert!(t.notes[0].accepted);
                assert_eq!(t.notes[1].reason, Some(Reason::Immature));
                assert_eq!(t.rejected_by_terms.len(), 1);
                assert_eq!(t.rejected_by_terms[0].redeemable_after_day, FUTURE);
                assert_eq!(t.rejected_by_terms[0].esp, u128::from(4 * ONE));
            }
            other => panic!("expected RefundRequired, got {other:?}"),
        }
        assert!(!s.is_spent(&a) && !s.is_spent(&b));
        assert_eq!(s.totals(), totals);
        assert!(s.responses.is_empty());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn refund_outputs_over_the_limit_are_refused_before_anything_is_burned() {
        let mut s = setup("refund-over");
        let a_units = SMALL;
        let a = s.held(a_units, service(), PAST);
        let b = s.held(4 * ONE, service(), FUTURE);
        let n = fewest_outputs(0, |n| 4 * ONE - (fee(2, 0, n) - a_units));
        let max = 4 * ONE - (fee(2, 0, n) - a_units);
        let cases: Vec<Vec<Out>> = vec![
            // one unit more than the most allowed
            split_out_into(max + 1, n, service(), FUTURE),
            // terms that no rejected note has
            vec![(ONE, service(), PAST2)],
            // another service's terms
            vec![(ONE, other(), FUTURE)],
            // the accepted note's terms: it is burned for the fee, not refunded
            vec![(ONE / 16, service(), PAST)],
        ];
        for refund in cases {
            let request = build(&[&a, &b], &[], &refund);
            match rejection(s.run(&request)) {
                RedeemRejection::OutputsOverLimit { list, .. } => {
                    assert_eq!(list, OutputList::Refund)
                }
                other => panic!("expected OutputsOverLimit, got {other:?}"),
            }
        }
        // exactly the most allowed goes through
        let request = build(&[&a, &b], &[], &split_out_into(max, n, service(), FUTURE));
        assert!(s.run(&request).is_ok());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn rejected_notes_worth_exactly_the_shortfall_are_burned_and_nothing_comes_back() {
        let mut s = setup("exact-shortfall");
        let f = fee(1, 0, 0);
        let b = s.held(f, service(), FUTURE);
        let request = build(&[&b], &[], &[]);
        let response = s.run(&request).unwrap();
        assert!(response.notes[0].burned);
        assert!(!response.notes[0].accepted);
        assert!(response.refund.is_empty());
        assert!(s.is_spent(&b));
        assert_eq!(s.totals(), (f, f));

        // and a refund output is then too much
        // (the short memo makes this request 512 bytes too, so its fee is a
        // power of two and a note can be worth exactly that)
        let c = s.held(1 << 40, service(), FUTURE);
        let (request, _, _) = build_with(
            &[&c],
            &[],
            &[(1, service(), FUTURE)],
            SHORT_MEMO,
            &service_keypair(),
            None,
        );
        assert_eq!(fee_for(request.encoded_len(), RATE), u128::from(1u64 << 40));
        assert!(matches!(
            rejection(s.run(&request)),
            RedeemRejection::OutputsOverLimit {
                list: OutputList::Refund,
                ..
            }
        ));
        assert!(!s.is_spent(&c));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_request_of_all_rejected_notes_gets_them_back_minus_the_fee() {
        let mut s = setup("all-rejected");
        let b = s.held(4 * ONE, service(), FUTURE);
        let (request, _, refund_wanted) = build_with(
            &[&b],
            &[],
            &[(ONE, service(), FUTURE), (ONE, service(), FUTURE)],
            MEMO,
            &service_keypair(),
            None,
        );
        let response = s.run(&request).unwrap();
        assert_eq!(response.accepted_esp, 0);
        assert_eq!(response.refund.len(), 2);
        assert_signed(&s, &response.refund[0], &refund_wanted[0]);
        assert_signed(&s, &response.refund[1], &refund_wanted[1]);
        assert!(s.is_spent(&b));
        // the refunds are notes the service can hold and present later
        assert_eq!(s.totals(), (6 * ONE, 4 * ONE));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn spent_and_forged_notes_are_not_burned_to_make_up_a_shortfall() {
        let mut s = setup("shortfall-junk");
        let a = s.held(ONE / 2, service(), PAST);
        let b = s.held(ONE, service(), FUTURE);
        let spent = s.held(8 * ONE, service(), FUTURE);
        s.spend_elsewhere(&spent);
        let junk = forged(8 * ONE);
        // A = 0.5, R = 1 (the immature one), shortfall 0.5, so 0.5 can be refunded
        let request = build(
            &[&a, &b, &spent, &junk],
            &[],
            &[(ONE / 2, service(), FUTURE)],
        );
        let response = s.run(&request).unwrap();
        assert_eq!(
            reasons(&response),
            vec![
                None,
                Some(Reason::Immature),
                Some(Reason::AlreadySpent),
                Some(Reason::BadProof)
            ]
        );
        let burned: Vec<bool> = response.notes.iter().map(|n| n.burned).collect();
        assert_eq!(burned, vec![true, true, false, false]);
        assert_eq!(response.rejected_esp, u128::from(ONE));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    // ---- decline outputs ----

    #[test]
    fn decline_outputs_over_the_limit_are_refused_with_the_totals_to_rebuild_from() {
        let mut s = setup("decline-over");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(ONE, service(), PAST2);
        let totals = s.totals();
        let cases: Vec<Vec<Out>> = vec![
            // more than A minus the fee (4 - 1 = 3)
            vec![(2 * ONE, service(), PAST), (2 * ONE, service(), PAST2)],
            // within the total but more than that date holds
            vec![(2 * ONE, service(), PAST2)],
            // a date the accepted notes do not have
            vec![(ONE, service(), 20_001)],
            // another service
            vec![(ONE, other(), PAST)],
        ];
        for decline in cases {
            let n_decline = decline.len();
            let request = build(&[&a, &b], &decline, &[]);
            match rejection(s.run(&request)) {
                RedeemRejection::OutputsOverLimit { list, totals: t } => {
                    assert_eq!(list, OutputList::Decline);
                    assert_eq!(t.accepted_esp, u128::from(5 * ONE));
                    assert_eq!(t.rejected_esp, 0);
                    assert_eq!(t.fee_esp, u128::from(fee(2, n_decline, 0)));
                    assert_eq!(t.accepted_by_terms.len(), 2);
                    assert_eq!(t.accepted_by_terms[0].redeemable_after_day, PAST);
                    assert_eq!(t.accepted_by_terms[0].esp, u128::from(4 * ONE));
                    assert_eq!(t.accepted_by_terms[1].redeemable_after_day, PAST2);
                    assert_eq!(t.accepted_by_terms[1].esp, u128::from(ONE));
                }
                other => panic!("expected OutputsOverLimit, got {other:?}"),
            }
        }
        assert!(!s.is_spent(&a) && !s.is_spent(&b));
        assert_eq!(s.totals(), totals);
        assert!(s.responses.is_empty());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn decline_outputs_are_refused_when_a_note_the_wallet_counted_on_was_rejected() {
        let mut s = setup("decline-rebuild");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, service(), FUTURE);
        // the wallet built for A = 5, so asked for 4 back; the mint accepts only 3
        let request = build(
            &[&a, &b],
            &[(2 * ONE, service(), PAST), (2 * ONE, service(), FUTURE)],
            &[],
        );
        match rejection(s.run(&request)) {
            RedeemRejection::OutputsOverLimit { totals, .. } => {
                assert_eq!(totals.accepted_esp, u128::from(4 * ONE));
                assert_eq!(totals.rejected_esp, u128::from(2 * ONE));
                assert_eq!(totals.notes[1].reason, Some(Reason::Immature));
            }
            other => panic!("expected OutputsOverLimit, got {other:?}"),
        }
        // rebuilt from the totals, the same notes go through
        let request = build(&[&a, &b], &[(2 * ONE, service(), PAST)], &[]);
        assert!(s.run(&request).is_ok());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn decline_outputs_of_exactly_the_most_allowed_go_through() {
        let mut s = setup("decline-exact");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(ONE, service(), PAST2);
        // The most that can come back is A and B minus the fee. The fee depends on
        // how many outputs there are, and all but the first output (4 ONE) are
        // split into powers of two, so find the count that fits.
        let n = fewest_outputs(1, |n| ONE - fee(2, n, 0));
        let max = 5 * ONE - fee(2, n, 0);
        let outputs = |rest: u64| {
            [
                vec![(4 * ONE, service(), PAST)],
                split_out_into(rest, n - 1, service(), PAST2),
            ]
            .concat()
        };
        let request = build(&[&a, &b], &outputs(max - 4 * ONE + 1), &[]);
        // one unit over
        assert!(matches!(
            rejection(s.run(&request)),
            RedeemRejection::OutputsOverLimit { .. }
        ));
        let request = build(&[&a, &b], &outputs(max - 4 * ONE), &[]);
        let response = s.run(&request).unwrap();
        assert_eq!(response.owed_esp, u128::from(max));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn decline_outputs_are_refused_when_nothing_is_owed() {
        let mut s = setup("decline-nothing-owed");
        // (the short memo makes this request 512 bytes, so its fee is 2^40 and
        // a note can be worth exactly that)
        let a = s.held(1 << 40, service(), PAST);
        let (request, _, _) = build_with(
            &[&a],
            &[(1, service(), PAST)],
            &[],
            SHORT_MEMO,
            &service_keypair(),
            None,
        );
        assert_eq!(fee_for(request.encoded_len(), RATE), u128::from(1u64 << 40));
        assert!(matches!(
            rejection(s.run(&request)),
            RedeemRejection::OutputsOverLimit {
                list: OutputList::Decline,
                ..
            }
        ));
        assert!(!s.is_spent(&a));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn refund_outputs_are_refused_when_the_accepted_notes_cover_the_fee() {
        let mut s = setup("refund-not-needed");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(ONE, service(), FUTURE);
        let request = build(&[&a, &b], &[], &[(ONE / 2, service(), FUTURE)]);
        assert!(matches!(
            rejection(s.run(&request)),
            RedeemRejection::OutputsOverLimit {
                list: OutputList::Refund,
                ..
            }
        ));
        assert!(!s.is_spent(&a) && !s.is_spent(&b));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    // ---- the shape of the request ----

    fn fake_input(units: u64) -> RedeemInput {
        let h = forged(units);
        RedeemInput {
            service: service(),
            redeemable_after_day: PAST,
            keyset: ks(),
            input: MintInput {
                amount: Amount::from_units(units),
                note: h.note,
                spend_signature: dummy_signature(),
            },
        }
    }

    fn fake_output(units: u64) -> RedeemOutput {
        let key = Keypair::new(SECP256K1, &mut OsRng);
        RedeemOutput {
            service: service(),
            redeemable_after_day: PAST,
            output: MintOutput {
                amount: Amount::from_units(units),
                blind_nonce: BlindNonce(key.public_key()),
            },
        }
    }

    fn validate_default(request: &RedeemRequest) -> Result<(), RedeemRejection> {
        validate(request, DEFAULT_MAX_MEMO_BYTES)
    }

    fn fake_request(
        inputs: Vec<RedeemInput>,
        decline: Vec<RedeemOutput>,
        refund: Vec<RedeemOutput>,
    ) -> RedeemRequest {
        RedeemRequest {
            service: service(),
            output_keyset: ks(),
            inputs,
            memo: MEMO.to_string(),
            decline_outputs: decline,
            refund_outputs: refund,
            service_signature: dummy_signature(),
        }
    }

    #[test]
    fn there_is_no_cap_on_notes_or_outputs_only_on_the_size_of_the_request() {
        let many_inputs: Vec<RedeemInput> = (0..1500).map(|_| fake_input(1)).collect();
        let decline: Vec<RedeemOutput> = (0..1200).map(|_| fake_output(1)).collect();
        let refund: Vec<RedeemOutput> = (0..800).map(|_| fake_output(1)).collect();
        assert_eq!(
            validate_default(&fake_request(many_inputs, decline, refund)),
            Ok(())
        );
    }

    #[test]
    fn a_malformed_request_is_refused_before_the_mint_is_touched() {
        assert_eq!(
            validate_default(&fake_request(vec![], vec![], vec![])),
            Err(RedeemRejection::NoInputs)
        );
        assert_eq!(
            validate_default(&fake_request(vec![fake_input(0)], vec![], vec![])),
            Err(RedeemRejection::ZeroAmount)
        );
        assert_eq!(
            validate_default(&fake_request(
                vec![fake_input(1)],
                vec![fake_output(0)],
                vec![]
            )),
            Err(RedeemRejection::ZeroAmount)
        );
        assert_eq!(
            validate_default(&fake_request(
                vec![fake_input(1)],
                vec![],
                vec![fake_output(0)]
            )),
            Err(RedeemRejection::ZeroAmount)
        );
        // the same blind nonce in both lists
        let o = fake_output(1);
        assert_eq!(
            validate_default(&fake_request(vec![fake_input(1)], vec![o.clone()], vec![o])),
            Err(RedeemRejection::DuplicateBlindNonce)
        );
        for memo in ["", "   ", &"x".repeat(DEFAULT_MAX_MEMO_BYTES + 1)] {
            let mut request = fake_request(vec![fake_input(1)], vec![], vec![]);
            request.memo = memo.to_string();
            assert_eq!(
                validate_default(&request),
                Err(RedeemRejection::MemoInvalid {
                    max: DEFAULT_MAX_MEMO_BYTES
                })
            );
        }
        let mut request = fake_request(vec![fake_input(1)], vec![], vec![]);
        request.memo = "x".repeat(DEFAULT_MAX_MEMO_BYTES);
        assert_eq!(validate_default(&request), Ok(()));
    }

    #[test]
    fn only_powers_of_two_are_amounts() {
        let bad = |what, index| Err(RedeemRejection::BadDenomination { what, index });
        assert_eq!(
            validate_default(&fake_request(
                vec![fake_input(1), fake_input(6)],
                vec![],
                vec![]
            )),
            bad("note", 1)
        );
        assert_eq!(
            validate_default(&fake_request(
                vec![fake_input(1)],
                vec![fake_output(4), fake_output(3)],
                vec![]
            )),
            bad("decline output", 1)
        );
        assert_eq!(
            validate_default(&fake_request(
                vec![fake_input(1)],
                vec![],
                vec![fake_output(1), fake_output(2), fake_output(u64::MAX)]
            )),
            bad("refund output", 2)
        );
        assert_eq!(
            validate_default(&fake_request(
                vec![fake_input(1 << 63)],
                vec![fake_output(1 << 62)],
                vec![fake_output(2)]
            )),
            Ok(())
        );
    }

    #[test]
    fn an_output_blind_nonce_that_was_already_used_is_refused() {
        let mut s = setup("blind-used");
        let a = s.held(4 * ONE, service(), PAST);
        let request = build(&[&a], &[(ONE, service(), PAST)], &[]);
        // use the blind nonce first
        let terms = Terms {
            service: service(),
            redeemable_after_day: PAST,
        };
        let sk = s.master.key_for(Amount::from_units(ONE), &terms);
        s.logic
            .issue_with_key(&sk, &request.decline_outputs[0].output)
            .unwrap();
        assert_eq!(
            rejection(s.run(&request)),
            RedeemRejection::BlindNonceAlreadyUsed
        );
        assert!(!s.is_spent(&a));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    // ---- digest and hash ----

    #[test]
    fn the_digest_covers_the_terms_the_memo_and_both_lists() {
        let s = setup("digest");
        let a = s.held(4 * ONE, service(), PAST);
        let (request, _, _) = build_with(
            &[&a],
            &[(ONE, service(), PAST)],
            &[(ONE, service(), PAST)],
            MEMO,
            &service_keypair(),
            None,
        );
        let base = request.digest();

        let mut retagged = request.clone();
        retagged.inputs[0].redeemable_after_day += 1;
        assert_ne!(retagged.digest(), base);
        let mut other_service = request.clone();
        other_service.inputs[0].service = other();
        assert_ne!(other_service.digest(), base);
        let mut memo = request.clone();
        memo.memo.push('x');
        assert_ne!(memo.digest(), base);
        let mut other_signer = request.clone();
        other_signer.service = other();
        assert_ne!(other_signer.digest(), base);
        let mut swapped = request.clone();
        std::mem::swap(&mut swapped.decline_outputs, &mut swapped.refund_outputs);
        assert_ne!(swapped.digest(), base);
        let mut output_terms = request.clone();
        output_terms.decline_outputs[0].redeemable_after_day += 1;
        assert_ne!(output_terms.digest(), base);
        let mut output_amount = request.clone();
        output_amount.decline_outputs[0].output.amount = Amount::from_units(ONE + 1);
        assert_ne!(output_amount.digest(), base);
        // the spend signatures are not part of the digest, but are part of the hash
        let mut resigned = request.clone();
        resigned.inputs[0].input.spend_signature = dummy_signature();
        assert_eq!(resigned.digest(), base);
        assert_ne!(request_hash(&resigned), request_hash(&request));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn the_size_is_exact_and_a_request_survives_its_encoding() {
        let s = setup("encoding");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, other(), PAST2);
        let request = build(
            &[&a, &b],
            &[(ONE, service(), PAST)],
            &[(ONE, other(), PAST2), (1, service(), PAST)],
        );
        let bytes = request.encode();
        // 120 + 187 * 2 + the memo + 82 * 3
        assert_eq!(bytes.len(), 120 + 374 + MEMO.len() + 246);
        assert_eq!(request.encoded_len(), bytes.len() as u64);
        assert_eq!(encoded_len(2, MEMO.len(), 1, 2), bytes.len() as u64);
        assert_eq!(bytes[0], FORMAT_VERSION);

        let back = decode(&bytes).unwrap();
        assert_eq!(back.digest(), request.digest());
        assert_eq!(request_hash(&back), request_hash(&request));
        assert_eq!(back.encode(), bytes);
        assert_eq!(back.memo, MEMO);
        assert_eq!(back.inputs, request.inputs);
        assert_eq!(back.decline_outputs, request.decline_outputs);
        assert_eq!(back.refund_outputs, request.refund_outputs);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn one_input_and_one_output_have_the_sizes_the_readme_gives() {
        assert_eq!(INPUT_BYTES, 187);
        assert_eq!(OUTPUT_BYTES, 82);
        assert_eq!(FIXED_BYTES, 120);
        // an empty memo is not allowed, but the arithmetic still holds
        assert_eq!(encoded_len(0, 0, 0, 0), 120);
        assert_eq!(encoded_len(1, 0, 0, 0), 307);
        assert_eq!(encoded_len(0, 0, 1, 0), 202);
        // 220,000 notes with one output each: about 59 MB, so about four requests
        assert_eq!(
            encoded_len(220_000, 40, 220_000, 0),
            120 + 220_000 * 269 + 40
        );
        assert!(encoded_len(220_000, 40, 220_000, 0) > DEFAULT_MAX_REQUEST_BYTES as u64);
        // and the ceiling is about 84,000 notes with none coming back
        let most = (DEFAULT_MAX_REQUEST_BYTES as u64 - FIXED_BYTES - 40) / INPUT_BYTES;
        assert_eq!(most, 84109);
    }

    #[test]
    fn a_request_at_the_default_ceiling_fits_one_air_message() {
        // the ceiling is 15 MiB and AIR takes 16 MiB: the request body, the
        // envelope (71 bytes) and its seal (80) fit with the room to spare
        assert_eq!(DEFAULT_MAX_REQUEST_BYTES, 15 * 1024 * 1024);
        assert!(DEFAULT_MAX_REQUEST_BYTES + 71 + 80 + AIR_ROOM / 2 < AIR_MESSAGE_CAP);
        assert_eq!(DEFAULT_MAX_REQUEST_BYTES + AIR_ROOM, AIR_MESSAGE_CAP);
    }

    #[test]
    fn the_fee_is_the_rate_times_the_encoded_size() {
        assert_eq!(fee_for(0, 5), 0);
        // a rate chosen for the arithmetic; the default is 0 (below)
        const EXAMPLE_RATE: u128 = 1_000_000;
        assert_eq!(fee_for(1000, EXAMPLE_RATE), 1_000_000_000);
        // a typical request: five notes, one decline output, a 40 byte memo
        let typical = encoded_len(5, 40, 1, 0);
        assert_eq!(typical, 120 + 935 + 40 + 82);
        assert_eq!(fee_for(typical, EXAMPLE_RATE), 1_177_000_000);
        // a request at the ceiling
        let ceiling = DEFAULT_MAX_REQUEST_BYTES as u64;
        assert_eq!(ceiling, 15_728_640);
        assert_eq!(fee_for(ceiling, EXAMPLE_RATE), 15_728_640_000_000);
        // by default there is no fee, whatever the size
        assert_eq!(DEFAULT_FEE_PER_BYTE, 0);
        assert_eq!(fee_for(typical, DEFAULT_FEE_PER_BYTE), 0);
        assert_eq!(fee_for(ceiling, DEFAULT_FEE_PER_BYTE), 0);
        assert_eq!(RedeemSettings::default().fee_per_byte, 0);
        // no overflow however large the rate
        assert_eq!(fee_for(u64::MAX, u128::MAX), u128::MAX);
    }

    #[test]
    fn the_fee_taken_is_the_rate_times_the_measured_size() {
        let mut s = setup("fee-from-size");
        let a = s.held(4 * ONE, service(), PAST);
        let small = build(&[&a], &[], &[]);
        let r = s.run(&small).unwrap();
        assert_eq!(r.size_bytes, small.encode().len() as u64);
        assert_eq!(r.fee_esp, RATE * u128::from(r.size_bytes));
        assert_eq!(r.owed_esp, u128::from(4 * ONE) - r.fee_esp);
        // a second note in the request costs 187 bytes more
        let mut other_setup = setup("fee-from-size-2");
        let c = other_setup.held(4 * ONE, service(), PAST);
        let d = other_setup.held(4 * ONE, service(), PAST);
        let r2 = other_setup.run(&build(&[&c, &d], &[], &[])).unwrap();
        assert_eq!(r2.size_bytes, r.size_bytes + 187);
        assert_eq!(r2.fee_esp, r.fee_esp + RATE * 187);
        // the memo is in the size
        let e = other_setup.held(4 * ONE, service(), PAST);
        let longer = format!("{MEMO}-and-a-bit-more");
        let (long_memo, _, _) = build_with(&[&e], &[], &[], &longer, &service_keypair(), None);
        let r3 = other_setup.run(&long_memo).unwrap();
        assert_eq!(
            r3.size_bytes,
            r.size_bytes + (longer.len() - MEMO.len()) as u64
        );
        fs::remove_dir_all(&s.dir).unwrap();
        fs::remove_dir_all(&other_setup.dir).unwrap();
    }

    #[test]
    fn a_body_that_is_not_exactly_one_request_does_not_decode() {
        let s = setup("decode");
        let a = s.held(4 * ONE, service(), PAST);
        let request = build(&[&a], &[(ONE, service(), PAST)], &[]);
        let bytes = request.encode();
        assert!(decode(&bytes).is_ok());

        // every shorter body ends inside a field
        for len in 0..bytes.len() {
            assert!(decode(&bytes[..len]).is_err(), "decoded {len} bytes");
        }
        // bytes after the end
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode(&longer).unwrap_err().contains("after its end"));
        // another version
        let mut v = bytes.clone();
        v[0] = 4;
        assert!(decode(&v).unwrap_err().contains("version"));
        // version 1, which names no keysets
        v[0] = 1;
        assert!(decode(&v).unwrap_err().contains("no keysets"));
        // version 2, which names each service by its x-only key
        v[0] = 2;
        assert!(decode(&v).unwrap_err().contains("x-only"));
        // a service ID that is not a point
        let mut bad_key = bytes.clone();
        bad_key[1..34].copy_from_slice(&[0xff; 33]);
        assert!(decode(&bad_key).is_err());
        // a nonce that is not a point
        let mut bad_nonce = bytes.clone();
        bad_nonce[103..136].copy_from_slice(&[0u8; 33]);
        assert!(decode(&bad_nonce).is_err());
        // a count that is larger than the body, with nothing allocated for it
        let mut huge = bytes.clone();
        huge[42..46].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode(&huge).unwrap_err().contains("counts more"));
        // a memo longer than the limit
        let memo_at = 46 + 187;
        let mut long = bytes.clone();
        long[memo_at..memo_at + 2]
            .copy_from_slice(&((DEFAULT_MAX_MEMO_BYTES + 1) as u16).to_be_bytes());
        assert!(decode(&long).unwrap_err().contains("memo"));
        // a memo that is not UTF-8
        let mut not_utf8 = bytes.clone();
        not_utf8[memo_at + 2] = 0xff;
        assert!(decode(&not_utf8).unwrap_err().contains("UTF-8"));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn the_request_hash_covers_every_byte_that_is_measured() {
        let s = setup("hash-covers");
        let a = s.held(4 * ONE, service(), PAST);
        let request = build(&[&a], &[(ONE, service(), PAST)], &[]);
        let base = request_hash(&request);
        let bytes = request.encode();
        // flip one bit anywhere that still decodes: the hash changes
        let mut changed = 0;
        for at in 0..bytes.len() {
            let mut b = bytes.clone();
            b[at] ^= 1;
            if let Ok(other) = decode(&b) {
                assert_ne!(request_hash(&other), base, "byte {at}");
                changed += 1;
            }
        }
        assert!(changed > 100);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    // ---- idempotence and crashes ----

    #[test]
    fn the_same_request_twice_answers_the_same_and_burns_and_queues_once() {
        let mut s = setup("idempotent");
        let a = s.held(4 * ONE, service(), PAST);
        let request = build(&[&a], &[(2 * ONE, service(), PAST)], &[]);
        let first = s.run(&request).unwrap();
        let totals = s.totals();
        let second = s.run(&request).unwrap();
        assert_eq!(first, second);
        assert_eq!(s.totals(), totals);
        assert_eq!(s.queue().len(), 1);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_crash_after_the_pending_entry_and_before_the_burn_is_finished_by_a_retry() {
        let mut s = setup("crash-before-burn");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, service(), PAST);
        let request = build(&[&a, &b], &[(4 * ONE, service(), PAST)], &[]);
        s.pend(&request);
        assert!(!s.is_spent(&a));

        let response = s.run(&request).unwrap();
        assert_eq!(response.owed_esp, u128::from(6 * ONE - fee(2, 1, 0)));
        assert!(s.is_spent(&a) && s.is_spent(&b));
        assert_eq!(s.totals(), (6 * ONE, 6 * ONE));
        assert_eq!(s.queue().len(), 1);
        assert!(matches!(
            s.responses.get(&request_hash(&request)),
            Some(Entry::RedeemDone(_))
        ));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_crash_part_way_through_the_burn_burns_each_note_once() {
        let mut s = setup("crash-mid-burn");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, service(), PAST);
        let request = build(&[&a, &b], &[], &[]);
        s.pend(&request);
        s.burn(&request, 0);
        assert_eq!(s.totals(), (6 * ONE, 4 * ONE));

        let response = s.run(&request).unwrap();
        assert_eq!(response.owed_esp, u128::from(6 * ONE - fee(2, 0, 0)));
        assert_eq!(s.totals(), (6 * ONE, 6 * ONE));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_retry_decides_nothing_again_it_uses_the_stored_decision() {
        let mut s = setup("stored-decision");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, service(), PAST);
        let request = build(&[&a, &b], &[], &[]);
        let plan = s.pend(&request);
        // b is spent behind its back, after the decision was made and written
        // (as only a request that holds it could do)
        s.burn(&request, 1);
        let response = s.run(&request).unwrap();
        assert_eq!(response.notes, plan.totals.notes);
        assert_eq!(response.owed_esp, plan.owed_esp);
        assert_eq!(s.totals(), (6 * ONE, 6 * ONE));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_crash_after_the_refunds_were_signed_gives_the_same_signatures_on_retry() {
        let mut s = setup("crash-after-refund");
        let a = s.held(SMALL, service(), PAST);
        let b = s.held(4 * ONE, service(), FUTURE);
        let (request, _, refund_wanted) = build_with(
            &[&a, &b],
            &[],
            &[(2 * ONE, service(), FUTURE)],
            MEMO,
            &service_keypair(),
            None,
        );
        s.pend(&request);
        s.burn(&request, 0);
        s.burn(&request, 1);
        let terms = Terms {
            service: service(),
            redeemable_after_day: FUTURE,
        };
        let sk = s.master.key_for(Amount::from_units(2 * ONE), &terms);
        s.logic
            .issue_with_key(&sk, &request.refund_outputs[0].output)
            .unwrap();
        let totals = s.totals();

        let response = s.run(&request).unwrap();
        assert_eq!(response.refund.len(), 1);
        assert_signed(&s, &response.refund[0], &refund_wanted[0]);
        // nothing was burned or issued a second time
        assert_eq!(s.totals(), totals);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_crash_after_the_entry_was_queued_does_not_queue_it_twice() {
        let mut s = setup("crash-after-queue");
        let a = s.held(4 * ONE, service(), PAST);
        let request = build(&[&a], &[], &[]);
        let plan = s.pend(&request);
        s.burn(&request, 0);
        let mut queue = s.queue();
        queue
            .add(queue::Entry::open(
                &request_hash(&request),
                service(),
                plan.owed_esp,
                MEMO,
                NOW - 5,
            ))
            .unwrap();
        let response = s.run(&request).unwrap();
        assert_eq!(response.owed_esp, u128::from(4 * ONE - fee(1, 0, 0)));
        assert_eq!(s.queue().len(), 1);
        // the entry keeps the time it was first queued
        assert_eq!(
            s.queue().get(&request_hash(&request)).unwrap().created_unix,
            NOW - 5
        );
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn another_kind_of_request_under_the_same_hash_is_a_fault() {
        let mut s = setup("wrong-kind");
        let a = s.held(4 * ONE, service(), PAST);
        let request = build(&[&a], &[], &[]);
        s.responses
            .put(
                &request_hash(&request),
                Entry::Pending {
                    redeemable_after_day: 5,
                    inputs: vec![],
                    outputs: vec![],
                },
            )
            .unwrap();
        assert!(matches!(s.run(&request), Err(RedeemError::Internal(_))));
        assert!(!s.is_spent(&a));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    // ---- reservations ----

    #[test]
    fn a_note_held_by_an_unfinished_redemption_is_already_spent_for_another_request() {
        let mut s = setup("held-note");
        let a = s.held(4 * ONE, service(), PAST);
        let c = s.held(2 * ONE, service(), PAST);
        let first = build(&[&a], &[], &[]);
        s.pend(&first);

        let second = build(&[&a, &c], &[], &[]);
        let response = s.run(&second).unwrap();
        assert_eq!(reasons(&response), vec![Some(Reason::AlreadySpent), None]);
        assert_eq!(response.accepted_esp, u128::from(2 * ONE));
        assert!(!s.is_spent(&a));
        assert!(s.is_spent(&c));
        // the first can still finish
        let response = s.run(&first).unwrap();
        assert_eq!(response.owed_esp, u128::from(4 * ONE - fee(1, 0, 0)));
        assert!(s.is_spent(&a));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_note_held_by_an_unfinished_transfer_is_already_spent_for_a_redemption() {
        let mut s = setup("held-by-transfer");
        let a = s.held(4 * ONE, service(), PAST);
        let c = s.held(2 * ONE, service(), PAST);
        s.responses
            .put(
                "t1",
                Entry::TransferPending(TransferPending {
                    burned: false,
                    inputs: vec![hexn(&a.note)],
                    outputs: vec![],
                }),
            )
            .unwrap();
        let request = build(&[&a, &c], &[], &[]);
        let response = s.run(&request).unwrap();
        assert_eq!(reasons(&response), vec![Some(Reason::AlreadySpent), None]);
        assert!(!s.is_spent(&a));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn output_blind_nonces_held_by_other_requests_are_refused() {
        let mut s = setup("held-outputs");
        let a = s.held(4 * ONE, service(), PAST);
        let c = s.held(4 * ONE, service(), PAST);
        let d = s.held(4 * ONE, service(), PAST);
        let e = s.held(4 * ONE, service(), PAST);
        let key = service_keypair();

        // held by an unfinished redemption
        let first = build(&[&a], &[(ONE, service(), PAST)], &[]);
        s.pend(&first);
        let clash = build_raw(
            &[&c],
            first.decline_outputs.clone(),
            vec![],
            MEMO,
            &key,
            None,
        );
        assert_eq!(rejection(s.run(&clash)), RedeemRejection::NoteHeld);

        // held by a finished redemption, whose decline outputs may still be signed
        let done = build(&[&d], &[(ONE, service(), PAST)], &[]);
        s.run(&done).unwrap();
        let clash = build_raw(
            &[&e],
            done.decline_outputs.clone(),
            vec![],
            MEMO,
            &key,
            None,
        );
        assert_eq!(rejection(s.run(&clash)), RedeemRejection::NoteHeld);

        // held by an unfinished exchange
        let exchange_out = fake_output(ONE);
        s.responses
            .put(
                "x1",
                Entry::Pending {
                    redeemable_after_day: 5,
                    inputs: vec![],
                    outputs: vec![hex::encode(exchange_out.output.blind_nonce.0.serialize())],
                },
            )
            .unwrap();
        let clash = build_raw(&[&e], vec![exchange_out], vec![], MEMO, &key, None);
        assert_eq!(rejection(s.run(&clash)), RedeemRejection::NoteHeld);

        // held by an unfinished transfer, this time in the refund list
        let transfer_out = fake_output(ONE);
        s.responses
            .put(
                "t1",
                Entry::TransferPending(TransferPending {
                    burned: false,
                    inputs: vec![],
                    outputs: vec![hex::encode(transfer_out.output.blind_nonce.0.serialize())],
                }),
            )
            .unwrap();
        let clash = build_raw(&[&e], vec![], vec![transfer_out], MEMO, &key, None);
        assert_eq!(rejection(s.run(&clash)), RedeemRejection::NoteHeld);
        assert!(!s.is_spent(&e));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn the_holds_of_redemptions_are_listed_apart_from_the_asker_and_survive_a_reopen() {
        let mut s = setup("holds");
        let a = s.held(4 * ONE, service(), PAST);
        let c = s.held(4 * ONE, service(), PAST);
        let pending = build(&[&a], &[(ONE, service(), PAST)], &[]);
        let done = build(&[&c], &[(ONE, service(), PAST)], &[]);
        s.pend(&pending);
        s.run(&done).unwrap();

        let reopened = Responses::open(&s.dir.join("esp").join("responses.json")).unwrap();
        let (inputs, outputs) = reopened.redeem_holds("nobody");
        // the unfinished one holds its note and its output; the finished one's
        // note is spent, and only its decline output is still held
        assert_eq!(inputs.len(), 1);
        assert!(inputs.contains(&hexn(&a.note)));
        assert_eq!(outputs.len(), 2);

        let (inputs, outputs) = reopened.redeem_holds(&request_hash(&pending));
        assert!(inputs.is_empty());
        assert_eq!(outputs.len(), 1);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn big_amounts_survive_the_stored_file() {
        let mut s = setup("big");
        let big = u128::from(u64::MAX) * 1_000;
        let plan = Plan {
            totals: Totals {
                notes: vec![NoteResult {
                    accepted: false,
                    reason: Some(Reason::Immature),
                    burned: true,
                }],
                accepted_esp: big,
                rejected_esp: big + 1,
                fee_esp: 1_000_000,
                size_bytes: 385,
                fee_per_byte: 2_597,
                accepted_by_terms: vec![TermsTotal {
                    service: service(),
                    redeemable_after_day: PAST,
                    esp: big,
                }],
                rejected_by_terms: vec![],
            },
            owed_esp: big - 1_000_000,
        };
        let record = RedeemRecord {
            plan,
            refund: vec![],
            decline_outputs: vec![],
            output_keyset: String::new(),
        };
        s.responses
            .put("r", Entry::RedeemDone(record.clone()))
            .unwrap();
        let reopened = Responses::open(&s.dir.join("esp").join("responses.json")).unwrap();
        assert_eq!(reopened.get("r"), Some(&Entry::RedeemDone(record)));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    // ---- paid and declined ----

    fn pay(s: &Setup, request: &RedeemRequest) {
        let mut queue = s.queue();
        queue
            .complete(&Payment {
                service: service(),
                payment_ref: "txid:abc",
                entry_ids: &[request_hash(request)],
                allow_mixed_memos: false,
                now_unix: NOW + 10,
            })
            .unwrap();
    }

    #[test]
    fn asking_again_after_the_payout_shows_the_payment() {
        let mut s = setup("paid");
        let a = s.held(4 * ONE, service(), PAST);
        let request = build(&[&a], &[], &[]);
        s.run(&request).unwrap();
        pay(&s, &request);
        let again = s.run(&request).unwrap();
        let view = again.entry.unwrap();
        assert_eq!(view.status, Status::Completed);
        assert_eq!(view.payment_ref.as_deref(), Some("txid:abc"));
        assert_eq!(s.queue().len(), 1);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_decline_reissues_the_accepted_notes_minus_the_fee_under_their_own_terms() {
        let mut s = setup("decline");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, service(), PAST2);
        let (request, decline_wanted, _) = build_with(
            &[&a, &b],
            &[(2 * ONE, service(), PAST), (2 * ONE, service(), PAST2)],
            &[],
            MEMO,
            &service_keypair(),
            None,
        );
        s.run(&request).unwrap();
        let id = request_hash(&request);
        assert_eq!(s.totals(), (6 * ONE, 6 * ONE));

        let declined = decline(
            &s.logic,
            &s.master,
            &mut s.responses,
            &s.queue_path,
            &id,
            "uptime terms were not met",
            NOW + 60,
        )
        .unwrap();
        assert_eq!(declined.outputs, 2);
        assert_eq!(declined.reissued_esp, u128::from(4 * ONE));
        // 4 came back; the fee stays burned
        assert_eq!(s.totals(), (10 * ONE, 6 * ONE));

        let queue = s.queue();
        let entry = queue.get(&id).unwrap();
        assert_eq!(entry.status, Status::Declined);
        assert_eq!(
            entry.decline_reason.as_deref(),
            Some("uptime terms were not met")
        );
        assert_eq!(entry.declined_unix, Some(NOW + 60));
        assert_eq!(entry.decline_signatures.len(), 2);
        // each comes back with the service and day it had
        assert_signed(&s, &entry.decline_signatures[0], &decline_wanted[0]);
        assert_signed(&s, &entry.decline_signatures[1], &decline_wanted[1]);
        assert_eq!(decline_wanted[0].day, PAST);
        assert_eq!(decline_wanted[1].day, PAST2);

        // the service asks again and is told
        let again = s.run(&request).unwrap();
        let view = again.entry.unwrap();
        assert_eq!(view.status, Status::Declined);
        assert_eq!(
            view.decline_reason.as_deref(),
            Some("uptime terms were not met")
        );
        assert_eq!(view.decline_signatures, entry.decline_signatures);

        // it cannot be declined twice, or paid after
        assert!(matches!(
            decline(
                &s.logic,
                &s.master,
                &mut s.responses,
                &s.queue_path,
                &id,
                "again",
                NOW + 70
            ),
            Err(DeclineError::Refused(_))
        ));
        let mut queue = s.queue();
        assert!(
            queue
                .complete(&Payment {
                    service: service(),
                    payment_ref: "late",
                    entry_ids: std::slice::from_ref(&id),
                    allow_mixed_memos: false,
                    now_unix: NOW + 80,
                })
                .is_err()
        );
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_decline_that_stopped_after_signing_can_be_run_again() {
        let mut s = setup("decline-retry");
        let a = s.held(4 * ONE, service(), PAST);
        let (request, decline_wanted, _) = build_with(
            &[&a],
            &[(2 * ONE, service(), PAST)],
            &[],
            MEMO,
            &service_keypair(),
            None,
        );
        s.run(&request).unwrap();
        let id = request_hash(&request);
        // signed, then the process stopped before the entry was marked
        let terms = Terms {
            service: service(),
            redeemable_after_day: PAST,
        };
        let sk = s.master.key_for(Amount::from_units(2 * ONE), &terms);
        s.logic
            .issue_with_key(&sk, &request.decline_outputs[0].output)
            .unwrap();
        let issued = s.totals().0;

        let declined = decline(
            &s.logic,
            &s.master,
            &mut s.responses,
            &s.queue_path,
            &id,
            "late",
            NOW,
        )
        .unwrap();
        assert_eq!(declined.outputs, 1);
        assert_eq!(s.totals().0, issued);
        let queue = s.queue();
        assert_signed(
            &s,
            &queue.get(&id).unwrap().decline_signatures[0],
            &decline_wanted[0],
        );
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_decline_with_no_decline_outputs_just_closes_the_entry() {
        let mut s = setup("decline-empty");
        let a = s.held(4 * ONE, service(), PAST);
        let request = build(&[&a], &[], &[]);
        s.run(&request).unwrap();
        let id = request_hash(&request);
        let declined = decline(
            &s.logic,
            &s.master,
            &mut s.responses,
            &s.queue_path,
            &id,
            "no",
            NOW,
        )
        .unwrap();
        assert_eq!(declined.outputs, 0);
        assert_eq!(declined.reissued_esp, 0);
        assert_eq!(s.queue().get(&id).unwrap().status, Status::Declined);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_decline_is_refused_for_what_it_cannot_apply_to() {
        let mut s = setup("decline-refused");
        let a = s.held(4 * ONE, service(), PAST);
        let request = build(&[&a], &[(ONE, service(), PAST)], &[]);
        s.run(&request).unwrap();
        let id = request_hash(&request);
        let call = |s: &mut Setup, id: &str, reason: &str| {
            decline(
                &s.logic,
                &s.master,
                &mut s.responses,
                &s.queue_path,
                id,
                reason,
                NOW,
            )
        };
        // no such entry
        assert!(matches!(
            call(&mut s, "nope", "why"),
            Err(DeclineError::Refused(_))
        ));
        // no reason, or one that is too long
        assert!(matches!(
            call(&mut s, &id, "  "),
            Err(DeclineError::Refused(_))
        ));
        let long = "x".repeat(queue::DEFAULT_MAX_REASON_BYTES + 1);
        assert!(matches!(
            call(&mut s, &id, &long),
            Err(DeclineError::Refused(_))
        ));
        // an entry with no stored redemption behind it
        let mut queue = s.queue();
        queue
            .add(queue::Entry::open("manual", service(), 5, "m", NOW))
            .unwrap();
        assert!(matches!(
            call(&mut s, "manual", "why"),
            Err(DeclineError::Refused(_))
        ));
        // an entry that is already paid
        pay(&s, &request);
        assert!(matches!(
            call(&mut s, &id, "why"),
            Err(DeclineError::Refused(_))
        ));
        // nothing was signed along the way
        assert_eq!(s.totals(), (4 * ONE, 4 * ONE));
        assert_eq!(s.queue().get(&id).unwrap().status, Status::Completed);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    // ---- settings ----

    fn run_with(
        s: &mut Setup,
        request: &RedeemRequest,
        settings: &RedeemSettings,
    ) -> Result<RedeemResponse, RedeemError> {
        redeem_with(
            &s.logic,
            &s.master,
            &mut s.responses,
            &s.queue_path,
            request,
            settings,
            NOW,
        )
    }

    fn at_rate(rate: u128) -> RedeemSettings {
        RedeemSettings {
            fee_per_byte: rate,
            ..RedeemSettings::default()
        }
    }

    #[test]
    fn the_rate_in_force_is_stored_on_the_reply_and_the_queue_entry() {
        let mut s = setup("rate-stored");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(4 * ONE, service(), PAST);
        let first = build(&[&a], &[], &[]);
        let size = first.encode().len() as u128;

        let response = run_with(&mut s, &first, &at_rate(2_000_000_000)).unwrap();
        assert_eq!(response.fee_per_byte, 2_000_000_000);
        assert_eq!(response.fee_esp, size * 2_000_000_000);
        let id = request_hash(&first);
        let queue = s.queue();
        let entry = queue.get(&id).unwrap();
        assert_eq!(entry.fee_per_byte, 2_000_000_000);
        assert_eq!(entry.fee_esp, size * 2_000_000_000);
        assert_eq!(entry.size_bytes, size as u64);
        assert_eq!(entry.owed_esp, u128::from(4 * ONE) - size * 2_000_000_000);
        assert_eq!(response.entry.as_ref().unwrap().fee_per_byte, 2_000_000_000);

        // the operator changes the rate; a retry of the finished request still
        // shows the rate it was charged at, and the entry is not touched
        let retry = run_with(&mut s, &first, &at_rate(7)).unwrap();
        assert_eq!(retry, response);
        assert_eq!(s.queue().get(&id).unwrap().fee_per_byte, 2_000_000_000);

        // a new request is charged at the new rate
        let second = build(&[&b], &[], &[]);
        let later = run_with(&mut s, &second, &at_rate(7)).unwrap();
        assert_eq!(later.fee_per_byte, 7);
        assert_eq!(later.fee_esp, size * 7);
        assert_eq!(
            s.queue().get(&request_hash(&second)).unwrap().fee_per_byte,
            7
        );
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_request_decided_at_one_rate_is_finished_at_that_rate_after_a_change() {
        let mut s = setup("rate-pending");
        let a = s.held(4 * ONE, service(), PAST);
        let request = build(&[&a], &[], &[]);
        let size = request.encode().len() as u128;
        // decided and written at RATE, then the mint stops
        let plan = s.pend(&request);
        assert_eq!(plan.totals.fee_per_byte, RATE);
        // it comes back up with a different rate in force
        let response = run_with(&mut s, &request, &at_rate(RATE * 10)).unwrap();
        assert_eq!(response.fee_per_byte, RATE);
        assert_eq!(response.fee_esp, size * RATE);
        assert_eq!(
            s.queue().get(&request_hash(&request)).unwrap().fee_per_byte,
            RATE
        );
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn the_memo_and_reason_limits_come_from_the_settings() {
        let mut s = setup("limits");
        let a = s.held(4 * ONE, service(), PAST);
        let request = build(&[&a], &[], &[]);
        let short = RedeemSettings {
            max_memo_bytes: 10,
            ..at_rate(RATE)
        };
        assert_eq!(
            rejection(run_with(&mut s, &request, &short)),
            RedeemRejection::MemoInvalid { max: 10 }
        );
        assert!(
            decode_with(&request.encode(), 10)
                .unwrap_err()
                .contains("10 bytes")
        );
        assert!(decode_with(&request.encode(), MEMO.len()).is_ok());
        assert!(!s.is_spent(&a));
        // the same request passes at the default
        run_with(&mut s, &request, &at_rate(RATE)).unwrap();

        let id = request_hash(&request);
        let refused = decline_with(
            &s.logic,
            &s.master,
            &mut s.responses,
            &s.queue_path,
            &id,
            "too long a reason",
            5,
            NOW,
        );
        assert!(matches!(refused, Err(DeclineError::Refused(_))));
        let done = decline_with(
            &s.logic,
            &s.master,
            &mut s.responses,
            &s.queue_path,
            &id,
            "short",
            5,
            NOW,
        );
        assert!(done.is_ok());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    // ---- the per-day ledger ----

    fn day_of(s: &Setup, day: u64) -> (u128, u128) {
        let d = s.responses.ledger().day(day);
        (d.issued, d.redeemed)
    }

    #[test]
    fn a_finished_redemption_is_counted_once_under_each_notes_own_day() {
        let mut s = setup("ledger");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, service(), PAST2);
        let (request, _, _) = build_with(
            &[&a, &b],
            &[(2 * ONE, service(), PAST), (2 * ONE, service(), PAST2)],
            &[],
            MEMO,
            &service_keypair(),
            None,
        );
        assert_eq!(day_of(&s, PAST), (0, 0));
        s.run(&request).unwrap();
        // burned under their own days; the fee and the payout are not reissued,
        // and the decline outputs wait for a decline
        assert_eq!(day_of(&s, PAST), (0, u128::from(4 * ONE)));
        assert_eq!(day_of(&s, PAST2), (0, u128::from(2 * ONE)));
        // a retry, and a retry after a restart, count nothing more
        s.run(&request).unwrap();
        s.responses = Responses::open(&s.dir.join("esp").join("responses.json")).unwrap();
        s.run(&request).unwrap();
        assert_eq!(day_of(&s, PAST), (0, u128::from(4 * ONE)));
        assert_eq!(day_of(&s, PAST2), (0, u128::from(2 * ONE)));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn rejected_notes_burned_for_the_fee_and_their_refunds_are_counted_under_their_days() {
        let mut s = setup("ledger-refund");
        let b = s.held(4 * ONE, service(), FUTURE);
        let c = s.held(2 * ONE, other(), PAST);
        let (request, _, _) = build_with(
            &[&b, &c],
            &[],
            &[(2 * ONE, service(), FUTURE), (ONE, other(), PAST)],
            MEMO,
            &service_keypair(),
            None,
        );
        s.run(&request).unwrap();
        assert!(s.is_spent(&b) && s.is_spent(&c));
        assert_eq!(
            day_of(&s, FUTURE),
            (u128::from(2 * ONE), u128::from(4 * ONE))
        );
        assert_eq!(day_of(&s, PAST), (u128::from(ONE), u128::from(2 * ONE)));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_note_left_unburned_by_the_decision_is_not_counted() {
        let mut s = setup("ledger-unburned");
        let a = s.held(4 * ONE, service(), PAST);
        // immature: accepted nothing, and the accepted notes cover the fee
        // (there is no shortfall to take from it), so it is left alone
        let b = s.held(2 * ONE, service(), FUTURE);
        let (request, _, _) = build_with(&[&a, &b], &[], &[], MEMO, &service_keypair(), None);
        s.run(&request).unwrap();
        assert!(!s.is_spent(&b));
        assert_eq!(day_of(&s, FUTURE), (0, 0));
        assert_eq!(day_of(&s, PAST), (0, u128::from(4 * ONE)));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_decline_is_counted_under_the_decline_outputs_days_and_survives_a_restart() {
        let mut s = setup("ledger-decline");
        let a = s.held(4 * ONE, service(), PAST);
        let b = s.held(2 * ONE, service(), PAST2);
        let (request, _, _) = build_with(
            &[&a, &b],
            &[(2 * ONE, service(), PAST), (2 * ONE, service(), PAST2)],
            &[],
            MEMO,
            &service_keypair(),
            None,
        );
        s.run(&request).unwrap();
        let id = request_hash(&request);
        decline(
            &s.logic,
            &s.master,
            &mut s.responses,
            &s.queue_path,
            &id,
            "terms",
            NOW + 60,
        )
        .unwrap();
        assert_eq!(day_of(&s, PAST), (u128::from(2 * ONE), u128::from(4 * ONE)));
        assert_eq!(
            day_of(&s, PAST2),
            (u128::from(2 * ONE), u128::from(2 * ONE))
        );
        assert!(s.responses.ledger().decline_counted(&id));
        let reopened = Responses::open(&s.dir.join("esp").join("responses.json")).unwrap();
        assert_eq!(reopened.ledger(), s.responses.ledger());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_decline_run_again_after_it_was_counted_and_not_marked_counts_nothing_twice() {
        use crate::ledger::Movements;
        let mut s = setup("ledger-decline-crash");
        let a = s.held(4 * ONE, service(), PAST);
        let (request, _, _) = build_with(
            &[&a],
            &[(2 * ONE, service(), PAST), (ONE, service(), PAST)],
            &[],
            MEMO,
            &service_keypair(),
            None,
        );
        s.run(&request).unwrap();
        let id = request_hash(&request);
        // The crash: the ledger took the decline, the queue entry was not marked.
        let mut m = Movements::new();
        m.issue(PAST, u128::from(3 * ONE));
        assert!(s.responses.count_decline(&id, &m).unwrap());
        s.responses = Responses::open(&s.dir.join("esp").join("responses.json")).unwrap();
        assert!(s.responses.ledger().decline_counted(&id));
        // The decline is run again, and finishes.
        decline(
            &s.logic,
            &s.master,
            &mut s.responses,
            &s.queue_path,
            &id,
            "terms",
            NOW + 60,
        )
        .unwrap();
        assert_eq!(s.queue().get(&id).unwrap().status, Status::Declined);
        assert_eq!(day_of(&s, PAST), (u128::from(3 * ONE), u128::from(4 * ONE)));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_refused_decline_counts_nothing() {
        let mut s = setup("ledger-decline-refused");
        let a = s.held(4 * ONE, service(), PAST);
        let (request, _, _) = build_with(
            &[&a],
            &[(2 * ONE, service(), PAST)],
            &[],
            MEMO,
            &service_keypair(),
            None,
        );
        s.run(&request).unwrap();
        let id = request_hash(&request);
        let refused = decline_with(
            &s.logic,
            &s.master,
            &mut s.responses,
            &s.queue_path,
            &id,
            "a reason that is far too long",
            5,
            NOW,
        );
        assert!(matches!(refused, Err(DeclineError::Refused(_))));
        assert!(!s.responses.ledger().decline_counted(&id));
        assert_eq!(day_of(&s, PAST), (0, u128::from(4 * ONE)));
        let unknown = decline(
            &s.logic,
            &s.master,
            &mut s.responses,
            &s.queue_path,
            "no-such-entry",
            "terms",
            NOW,
        );
        assert!(matches!(unknown, Err(DeclineError::Refused(_))));
        assert!(!s.responses.ledger().decline_counted("no-such-entry"));
        fs::remove_dir_all(&s.dir).unwrap();
    }
}
