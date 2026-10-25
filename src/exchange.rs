//! The PSP-to-ESP exchange.
//!
//! A wallet sends PSP notes and blinded ESP outputs. The mint checks the
//! request, burns the PSP notes at the PSP's `/melt`, and signs the outputs
//! under keys derived for the service and the redeemable-after day. The date is
//! set by the mint (the day of issue plus `terms.maturity_days`, 365 by
//! default), never by the requester.
//!
//! The exchange is exact: the PSP notes, times 10^11, must equal the total of
//! the ESP outputs plus the fee. There is no excess to keep and no credit. A
//! request that does not match is refused before anything is burned. The
//! smallest exchange is `exchange.min_psp`, 1 PSP ($0.10, 10^11 ESP) by default.
//! Over and under thresholds belong to the PSP's BTC purchase only.
//!
//! The fee is `exchange.fee_per_byte` times the request's canonical size
//! (`fee::exchange_size`, which depends only on how many notes and outputs there
//! are). It is 0 by default, so there is no mint fee unless the operator sets
//! one. When it is set, it is paid in ESP on top of the exact amount: the notes
//! must be worth the outputs plus the fee, and the request is still checked as
//! exact against that total. The rate in force when the request is accepted is
//! stored on the reply (`fee_per_byte`, `fee_esp`, `size_bytes`) and kept for a
//! retry.
//!
//! The checks run cheapest first, and nothing is written or burned until all of
//! them pass: the shape of the request (counts, repeats, zero amounts), the
//! amounts, the spend signatures, the mint's database, the reservations of other
//! unfinished requests, and last the PSP.
//!
//! Order of events, and why it is safe to retry at any point:
//!
//! 1. Check the request. Nothing is written yet. The PSP notes and the ESP
//!    blind nonces must be unused, and no other unfinished request may hold
//!    any of them.
//! 2. Check the spend signatures, which are public. This is what proves the
//!    holder authorized exactly this request, because they cover the memo.
//! 3. Write a `pending` entry under the request hash. It lists the PSP note
//!    nonces and the output blind nonces, which reserves them.
//! 4. Burn the PSP notes. If the PSP refuses (its `/melt` answers `400`),
//!    nothing was burned, and the `pending` entry is removed again (see
//!    `withdraw`) and the request is answered `400`; for a retry, only once
//!    `/burns` shows none of the notes burned under this memo. A fault or a
//!    timeout leaves the entry.
//! 5. Sign the outputs and write a `done` entry.
//!
//! A retry of a done request returns the stored response. A retry of a pending
//! request starts again from step 4: if the PSP notes are already spent it
//! skips the burn, and outputs that were already issued are signed again
//! (signing is deterministic) instead of failing.
//!
//! The skip is taken only when the PSP says the notes were burned under this
//! request's memo. The PSP keeps the memo of every burn, and the memo is
//! `SHA-256` of the service and the outputs (see `memo`). Notes that are spent
//! under another memo, or with none on record, were spent by someone else, and
//! the exchange fails with `NoteSpentElsewhere` and signs nothing. (The memo is
//! the burn's label and not the request hash: the spend signatures cover the
//! memo, and the request hash covers the spend signatures, so the hash cannot be
//! the memo. Two requests with the same memo have the same service and outputs,
//! and the reserved blind nonces keep both from being live at once.)
//!
//! The reservation is what makes that skip safe. While a request is pending, no
//! other request (an exchange or a transfer) can use its PSP notes or its output
//! blind nonces, so a PSP note that is spent during a retry was burned by this
//! request. Without it, a second request for the same PSP notes, made after a
//! crash before the burn, could burn them and leave the first request to issue
//! its outputs on the strength of that burn.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use mint_core::MintLogic;
#[cfg(test)]
use mint_types::MintOutput;
use mint_types::{Amount, MintInput, MintOutputError, Nonce, melt_sighash};
use secp256k1::SECP256K1;
#[cfg(test)]
use sp_wire::ServiceDid;

use crate::fee;
use crate::keys::MasterSecret;
use crate::ledger::Movements;
use crate::responses::{Entry, Responses};
use crate::terms::Terms;
use crate::units::{self, ESP_PER_PSP};

// The request and response types, the memo and the constants live in sp-wire;
// they are re-exported so the paths are unchanged.
pub use sp_wire::esp::exchange::{ExchangeRequest, ExchangeResponse, MAX_ITEMS, memo};

/// The settings an exchange uses. They come from the mint's config
/// (`config::Config::exchange_settings`); the defaults are the documented ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExchangeSettings {
    /// The most PSP notes, and the most outputs, in one exchange.
    pub max_items: usize,
    /// Days after the day of issue that the new ESP notes become redeemable.
    pub maturity_days: u64,
    /// The smallest exchange, in PSP.
    pub min_psp: u64,
    /// ESP units charged for each byte of the request's canonical size
    /// (`fee::exchange_size`). 0 by default: the exchange has no mint fee.
    pub fee_per_byte: u128,
}

impl Default for ExchangeSettings {
    fn default() -> Self {
        ExchangeSettings {
            max_items: MAX_ITEMS,
            maturity_days: crate::terms::REDEEM_WINDOW_DAYS,
            min_psp: 1,
            fee_per_byte: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    NoInputs,
    NoOutputs,
    TooManyItems,
    ZeroAmount,
    /// An output amount is not a power of two. Nothing was burned.
    BadDenomination {
        index: usize,
    },
    DuplicateInput,
    DuplicateBlindNonce,
    BlindNonceAlreadyUsed,
    Overflow,
    /// The outputs total less than the smallest exchange (`exchange.min_psp`,
    /// 1 PSP, which is 10^11 ESP units or $0.10, by default).
    BelowMinimum {
        requested: u128,
        minimum: u128,
    },
    /// The PSP notes, times 10^11, do not equal the outputs' total.
    NotExact {
        paid: u128,
        requested: u128,
    },
    /// The mint charges a fee on this route, and the PSP notes do not equal the
    /// outputs' total plus the fee. `size_bytes` and `fee_per_byte` are what the
    /// fee was worked out from, so that the wallet can rebuild the request.
    NotExactWithFee {
        paid: u128,
        requested: u128,
        fee: u128,
        size_bytes: u64,
        fee_per_byte: u128,
    },
    /// A spend signature does not cover this request.
    BadSpendSignature,
    /// A PSP note is already spent.
    PspNoteSpent,
    /// PSP notes of a pending exchange were spent by something other than this
    /// exchange: under another memo, or with no memo on record. Nothing is
    /// signed. `spent` lists which of the request's notes they are, by position
    /// in `psp_inputs`, so that the wallet can mark exactly those as spent.
    NoteSpentElsewhere {
        spent: Vec<usize>,
    },
    /// A PSP note or an output blind nonce is held by another request that is
    /// not finished.
    NoteHeld,
    /// The PSP refused to burn the notes (its `/melt` answered `400`). Nothing
    /// was burned, so the request's entry is gone and it can be built again.
    PspRefusedBurn {
        why: String,
    },
    /// `psp_input_keysets` does not name one keyset per PSP note.
    MissingKeyset,
    /// The output keyset is missing, retired or not this mint's. Nothing was
    /// burned.
    Keyset {
        code: &'static str,
        why: String,
    },
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rejection::NoInputs => write!(f, "no PSP notes"),
            Rejection::NoOutputs => write!(f, "no outputs"),
            Rejection::TooManyItems => write!(
                f,
                "more notes or outputs than one exchange may have (exchange.max_items, {MAX_ITEMS} by default)"
            ),
            Rejection::ZeroAmount => write!(f, "an output has amount zero"),
            Rejection::BadDenomination { index } => write!(
                f,
                "output {index}: ESP amounts are powers of two. Nothing was burned"
            ),
            Rejection::DuplicateInput => write!(f, "a PSP note is listed twice"),
            Rejection::DuplicateBlindNonce => write!(f, "an output blind nonce is listed twice"),
            Rejection::BlindNonceAlreadyUsed => write!(f, "an output blind nonce was already used"),
            Rejection::Overflow => write!(f, "amounts are too large"),
            Rejection::BelowMinimum { requested, minimum } => write!(
                f,
                "the smallest exchange is {minimum} ESP units ({} PSP) but the outputs total {requested}",
                minimum / u128::from(ESP_PER_PSP)
            ),
            Rejection::NotExact { paid, requested } => {
                let (word, gap) = if paid > requested {
                    ("over", paid - requested)
                } else {
                    ("short", requested - paid)
                };
                write!(
                    f,
                    "an exchange must be exact: the PSP notes are worth {paid} ESP units ({} PSP) and the outputs total {requested}, which is {word} by {gap}. Nothing was burned",
                    paid / u128::from(ESP_PER_PSP)
                )
            }
            Rejection::NotExactWithFee {
                paid,
                requested,
                fee,
                size_bytes,
                fee_per_byte,
            } => {
                let wanted = requested.saturating_add(*fee);
                let (word, gap) = if paid > &wanted {
                    ("over", paid - wanted)
                } else {
                    ("short", wanted - paid)
                };
                write!(
                    f,
                    "an exchange must be exact: the outputs total {requested} ESP units and the fee is {fee} ({size_bytes} bytes at {fee_per_byte} ESP units per byte), so the PSP notes must be worth {wanted}. They are worth {paid}, which is {word} by {gap}. Nothing was burned"
                )
            }
            Rejection::BadSpendSignature => {
                write!(f, "a spend signature does not cover this request")
            }
            Rejection::PspNoteSpent => write!(f, "a PSP note is already spent"),
            Rejection::NoteSpentElsewhere { .. } => write!(
                f,
                "a PSP note was spent by a different request, not by this exchange, so this exchange cannot go ahead. Nothing was issued"
            ),
            Rejection::Keyset { why, .. } => write!(f, "{why}"),
            Rejection::MissingKeyset => write!(
                f,
                "every PSP note needs its keyset (psp_input_keysets, in order). Nothing was burned"
            ),
            Rejection::NoteHeld => write!(
                f,
                "a PSP note or an output blind nonce is held by another request that is not finished. Nothing was burned"
            ),
            Rejection::PspRefusedBurn { why } => write!(
                f,
                "the PSP refused to burn the notes: {why}. Nothing was burned or issued"
            ),
        }
    }
}

#[derive(Debug)]
pub enum ExchangeError {
    /// The request is refused. Nothing was burned.
    Rejected(Rejection),
    /// The PSP could not be reached, or its answer is not known or not usable
    /// (a fault, a timeout, a burn of another size than asked). Something may
    /// be burned, and the entry stays: a retry is safe. (A burn the PSP refused
    /// is a [`Rejection::PspRefusedBurn`] instead.)
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

impl ExchangeError {
    /// The PSP refused to burn the notes, so nothing was burned and the pending
    /// entry can go (see [`withdraw`]).
    pub fn is_burn_refusal(&self) -> bool {
        matches!(
            self,
            ExchangeError::Rejected(Rejection::PspRefusedBurn { .. })
        )
    }
}

impl From<Rejection> for ExchangeError {
    fn from(r: Rejection) -> Self {
        ExchangeError::Rejected(r)
    }
}

fn internal<E: ToString>(e: E) -> ExchangeError {
    ExchangeError::Internal(e.to_string())
}

/// Why the PSP's `/melt` did not burn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeltError {
    /// The PSP refused the melt (its `400`). A refused melt burns nothing and
    /// records nothing. (For a retry, an earlier melt of the same exchange may
    /// have run since; `burn` asks `/burns` before it takes a retry's refusal as
    /// it stands. A fresh request's refusal stands as it is.)
    Refused(String),
    /// The outcome is not known: the PSP could not be reached, timed out,
    /// answered with a fault or with something unreadable. The notes may or may
    /// not be burned.
    Unknown(String),
}

impl fmt::Display for MeltError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MeltError::Refused(e) | MeltError::Unknown(e) => write!(f, "{e}"),
        }
    }
}

/// What the PSP says about one note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Burn {
    pub spent: bool,
    /// The memo the note was burned under. `None` if it is not spent, or if it
    /// was spent with no memo on record.
    pub memo: Option<String>,
}

/// What the ESP mint needs from the PSP. `HttpPsp` is the real one.
pub trait Psp {
    /// Burn the notes, bound to `memo`. The PSP keeps the memo of the burn.
    /// Returns the PSP units burned.
    fn melt(&self, inputs: &[MintInput], memo: &str) -> Result<Amount, String>;
    /// [`Psp::melt`] with the keyset of each note named, as the PSP's `/melt`
    /// needs. A fake PSP in a test has one keyset and ignores the names.
    fn melt_named(
        &self,
        inputs: &[MintInput],
        keysets: &[String],
        memo: &str,
    ) -> Result<Amount, String> {
        let _ = keysets;
        self.melt(inputs, memo)
    }
    /// [`Psp::melt_named`], with a refusal told apart from "not known" (see
    /// [`MeltError`]). The default says every error is unknown, which keeps the
    /// entry: an implementation that can tell that nothing was burned overrides
    /// it (`HttpPsp` does, for a `400`).
    fn melt_checked(
        &self,
        inputs: &[MintInput],
        keysets: &[String],
        memo: &str,
    ) -> Result<Amount, MeltError> {
        self.melt_named(inputs, keysets, memo)
            .map_err(MeltError::Unknown)
    }
    /// For each nonce, in order: whether it is spent, and the memo it was
    /// burned under.
    fn burns(&self, nonces: &[Nonce]) -> Result<Vec<Burn>, String>;
    /// Whether each nonce is spent, in order.
    fn spent(&self, nonces: &[Nonce]) -> Result<Vec<bool>, String> {
        Ok(self.burns(nonces)?.into_iter().map(|b| b.spent).collect())
    }
}

/// The key a request is stored under (see `sp_wire::esp::exchange::request_hash`).
pub fn request_hash(request: &ExchangeRequest) -> Result<String, ExchangeError> {
    sp_wire::esp::exchange::request_hash(request).map_err(internal)
}

/// The PSP note nonces and the output blind nonces a pending exchange holds, as hex.
fn held_by(request: &ExchangeRequest) -> (Vec<String>, Vec<String>) {
    (
        request
            .psp_inputs
            .iter()
            .map(|i| hex::encode(i.note.nonce.0.serialize()))
            .collect(),
        request
            .outputs
            .iter()
            .map(|o| hex::encode(o.blind_nonce.0.serialize()))
            .collect(),
    )
}

/// The exact rule. `paid` is the PSP notes' value in ESP units and `requested`
/// is the outputs' total. The smallest exchange, in ESP units, is `minimum`
/// (the config's `exchange.min_psp`, 1 PSP by default), and the two must be
/// equal: the mint keeps no excess and records no credit.
pub fn check_exact_min(paid: u128, requested: u128, minimum: u128) -> Result<(), Rejection> {
    if requested < minimum {
        return Err(Rejection::BelowMinimum { requested, minimum });
    }
    if paid != requested {
        return Err(Rejection::NotExact { paid, requested });
    }
    Ok(())
}

/// The shape of the request: counts, repeats and output sizes (each a power of
/// two). Nothing here touches the mint.
fn validate_shape(request: &ExchangeRequest, settings: &ExchangeSettings) -> Result<(), Rejection> {
    if request.psp_inputs.is_empty() {
        return Err(Rejection::NoInputs);
    }
    if request.outputs.is_empty() {
        return Err(Rejection::NoOutputs);
    }
    if request.psp_input_keysets.len() != request.psp_inputs.len() {
        return Err(Rejection::MissingKeyset);
    }
    if request.psp_inputs.len() > settings.max_items || request.outputs.len() > settings.max_items {
        return Err(Rejection::TooManyItems);
    }
    let mut nonces = HashSet::new();
    for input in &request.psp_inputs {
        if !nonces.insert(input.note.nonce) {
            return Err(Rejection::DuplicateInput);
        }
    }
    let mut blind_nonces = HashSet::new();
    for (index, output) in request.outputs.iter().enumerate() {
        if output.amount.units == 0 {
            return Err(Rejection::ZeroAmount);
        }
        if !crate::units::is_denomination(output.amount.units) {
            return Err(Rejection::BadDenomination { index });
        }
        if !blind_nonces.insert(output.blind_nonce) {
            return Err(Rejection::DuplicateBlindNonce);
        }
    }
    Ok(())
}

/// The exact rule with the fee. `paid` is the PSP notes' value in ESP units,
/// `requested` the outputs' total, `fee` what the route charges. The notes must
/// be worth `requested + fee`, and that total must reach the smallest exchange.
fn check_amounts(
    paid: u128,
    requested: u128,
    fee: u128,
    size_bytes: u64,
    settings: &ExchangeSettings,
) -> Result<(), Rejection> {
    let minimum = u128::from(settings.min_psp).saturating_mul(u128::from(ESP_PER_PSP));
    if fee == 0 {
        return check_exact_min(paid, requested, minimum);
    }
    let wanted = requested.checked_add(fee).ok_or(Rejection::Overflow)?;
    if wanted < minimum {
        return Err(Rejection::BelowMinimum {
            requested: wanted,
            minimum,
        });
    }
    if paid != wanted {
        return Err(Rejection::NotExactWithFee {
            paid,
            requested,
            fee,
            size_bytes,
            fee_per_byte: settings.fee_per_byte,
        });
    }
    Ok(())
}

/// The phases of one exchange, and which of them may hold the mint's lock.
///
/// An exchange talks to the PSP twice (a look at the notes, then the burn), and
/// the PSP can be slow or not answer. The mint's lock must not be held across
/// those calls, or one slow PSP blocks every other request. So the exchange runs
/// in phases, and the server takes the lock only for the ones that touch the
/// mint, with the lock released around the ones that call the PSP:
///
/// 1. [`prepare_gens`] (lock): every check, as before. Nothing is written.
/// 2. [`precheck`] (no lock): a fresh request asks the PSP whether any note is
///    already spent, so a request that cannot succeed is refused before it
///    reserves anything.
/// 3. [`reserve_gens`] (lock): the checks that read the mint (the database and the
///    reservations of other requests) are made again, since the lock was let
///    go, and the `pending` entry is written. This reserves the PSP notes and
///    the output blind nonces and records the terms. After this, a crash at any
///    point is picked up by a retry.
/// 4. [`burn_phase`] (no lock): the PSP burns the notes, or on a retry says
///    whether it already did. If the PSP refuses the burn (for a retry, once
///    `/burns` shows none of the notes burned under this memo), [`withdraw`]
///    (lock) takes the `pending` entry out again, and the request is answered
///    `400`.
/// 5. [`finish_gens`] (lock): the entry is checked to still be the pending one
///    this request wrote, the outputs are signed and the `done` entry is written.
///
/// What keeps this safe is the `pending` entry, which is what the reservations
/// and the crash replay already rest on: it is written (phase 3) before the PSP
/// is asked to burn anything (phase 4), and only a `done` entry replaces it.
/// Whether two copies of one request are running at once is not for this module
/// to say (it is in-memory state); the server refuses the second while the
/// first is in the middle of these phases (see `server::InFlight`).
///
/// In tests, [`exchange_gens`] runs the five back to back.
///
/// What [`prepare_gens`] found.
#[derive(Debug)]
pub enum Prepared {
    /// The request is finished; this is its stored response.
    Done(ExchangeResponse),
    /// The request passed its checks. Carry on with the phases.
    Go(Plan),
}

/// What the later phases need to know about a request that passed
/// [`prepare_gens`]. It is not stored: a retry works it out again from the
/// request and the `pending` entry.
#[derive(Debug, Clone)]
pub struct Plan {
    hash: String,
    memo: String,
    nonces: Vec<Nonce>,
    psp_total: u128,
    redeemable_after_day: u64,
    recovering: bool,
    fee_per_byte: u128,
    fee_esp: u128,
    size_bytes: u64,
}

impl Plan {
    /// Whether this is a retry of a request whose `pending` entry is on file
    /// (so its burn may already have happened).
    pub fn recovering(&self) -> bool {
        self.recovering
    }
}

/// The signer for the request's keyset, or the refusal that goes with it.
/// `resumed` lets a request that is already on file finish with the current set
/// when its own has been retired since.
fn signer_for<'a>(
    gens: &crate::rotation::Gens<'a>,
    request: &ExchangeRequest,
    resumed: bool,
) -> Result<(&'a MintLogic, &'a MasterSecret, String), ExchangeError> {
    if request.keyset.is_empty() {
        return Err(Rejection::Keyset {
            code: sp_wire::codes::MISSING_KEYSET,
            why: "the outputs need a keyset (keyset). Nothing was burned".into(),
        }
        .into());
    }
    gens.signer(&request.keyset, resumed).map_err(|e| {
        ExchangeError::Rejected(Rejection::Keyset {
            code: e.code(),
            why: e.why("the outputs"),
        })
    })
}

/// Phase 1 (hold the lock). An exchange over the live key sets: the outputs are
/// signed with the keyset the request names (`keyset_retired` /
/// `unknown_keyset` otherwise, before anything is burned). A stored answer is
/// replayed as it is, whatever set is current now.
pub fn prepare_gens(
    gens: &crate::rotation::Gens,
    responses: &Responses,
    now_unix: u64,
    request: &ExchangeRequest,
    settings: &ExchangeSettings,
) -> Result<Prepared, ExchangeError> {
    // An empty keyset is refused first, before anything else is looked at.
    if request.keyset.is_empty() {
        signer_for(gens, request, false)?;
    }
    let stored = responses.get(&request_hash(request)?);
    if let Some(Entry::Done(done)) = stored {
        return Ok(Prepared::Done(done.clone()));
    }
    let resumed = matches!(stored, Some(Entry::Pending { .. }));
    let (logic, _, _) = signer_for(gens, request, resumed)?;
    let prepared = prepare(logic, responses, now_unix, request, settings)?;
    if let Prepared::Go(plan) = &prepared
        && !plan.recovering
    {
        unsigned_by_either(gens, request)?;
    }
    Ok(prepared)
}

/// The same outputs can be named under either live keyset, which makes two
/// requests with different hashes and one memo. A blind nonce either live set
/// has signed is used, whichever set this request names; else one burn would be
/// signed for twice. A retry is not looked at: its entry is on file already.
fn unsigned_by_either(
    gens: &crate::rotation::Gens,
    request: &ExchangeRequest,
) -> Result<(), ExchangeError> {
    for output in &request.outputs {
        if gens
            .is_blind_nonce_used(&output.blind_nonce)
            .map_err(internal)?
        {
            return Err(Rejection::BlindNonceAlreadyUsed.into());
        }
    }
    Ok(())
}

/// Phase 3 (hold the lock): check again and write the `pending` entry. Does
/// nothing for a retry, whose entry is already on file.
pub fn reserve_gens(
    gens: &crate::rotation::Gens,
    responses: &mut Responses,
    request: &ExchangeRequest,
    plan: &Plan,
) -> Result<(), ExchangeError> {
    let (logic, _, _) = signer_for(gens, request, plan.recovering)?;
    if !plan.recovering {
        unsigned_by_either(gens, request)?;
    }
    reserve(logic, responses, request, plan)
}

/// Phase 4, after the PSP refused the burn (hold the lock): take the request's
/// `pending` entry out again, which releases the PSP notes and the blind nonces
/// it held. Only a `pending` entry goes; if the hash holds anything else (a
/// finished answer), it stays. A refused melt burns nothing, so nothing is
/// owed for this entry, and the request, sent again, is a new one with every
/// check.
pub fn withdraw(responses: &mut Responses, plan: &Plan) -> Result<(), ExchangeError> {
    responses.remove_pending(&plan.hash).map_err(internal)?;
    Ok(())
}

/// Phase 5 (hold the lock): sign the outputs and write the `done` entry. An
/// exchange accepted before a rotation and finished after it, whose keyset
/// retired in between, is signed with the current set; the reply names the
/// keyset that signed. By now the notes may be burned, so a retired set is no
/// reason to stop.
pub fn finish_gens(
    gens: &crate::rotation::Gens,
    responses: &mut Responses,
    request: &ExchangeRequest,
    plan: &Plan,
) -> Result<ExchangeResponse, ExchangeError> {
    let (logic, master, id) = signer_for(gens, request, true)?;
    finish(logic, master, &id, responses, request, plan)
}

/// Test only: all five phases, back to back (see the phases above). The server
/// runs the phases itself, so that its lock is not held while the PSP is called.
#[cfg(test)]
pub fn exchange_gens(
    gens: &crate::rotation::Gens,
    psp: &dyn Psp,
    responses: &mut Responses,
    now_unix: u64,
    request: &ExchangeRequest,
    settings: &ExchangeSettings,
) -> Result<ExchangeResponse, ExchangeError> {
    let plan = match prepare_gens(gens, responses, now_unix, request, settings)? {
        Prepared::Done(response) => return Ok(response),
        Prepared::Go(plan) => plan,
    };
    precheck(psp, &plan)?;
    reserve_gens(gens, responses, request, &plan)?;
    if let Err(e) = burn_phase(psp, request, &plan) {
        if e.is_burn_refusal() {
            withdraw(responses, &plan)?;
        }
        return Err(e);
    }
    finish_gens(gens, responses, request, &plan)
}

/// Phase 1. Everything that can be checked without the PSP, cheapest first:
/// the shape, the stored answer, the amounts, the spend signatures, the mint's
/// database and the reservations of other requests. Writes nothing.
fn prepare(
    logic: &MintLogic,
    responses: &Responses,
    now_unix: u64,
    request: &ExchangeRequest,
    settings: &ExchangeSettings,
) -> Result<Prepared, ExchangeError> {
    validate_shape(request, settings)?;
    let hash = request_hash(request)?;
    let memo = memo(&request.service, &request.outputs);
    let nonces: Vec<Nonce> = request.psp_inputs.iter().map(|i| i.note.nonce).collect();

    let (redeemable_after_day, recovering) = match responses.get(&hash) {
        Some(Entry::Done(done)) => return Ok(Prepared::Done(done.clone())),
        Some(Entry::Pending {
            redeemable_after_day,
            ..
        }) => (*redeemable_after_day, true),
        Some(Entry::TransferPending(_)) => {
            return Err(internal("a transfer is stored under this request's hash"));
        }
        Some(Entry::RedeemPending(_)) | Some(Entry::RedeemDone(_)) => {
            return Err(internal("a redemption is stored under this request's hash"));
        }
        None => (
            Terms::new_at_days(request.service, now_unix, settings.maturity_days)
                .redeemable_after_day,
            false,
        ),
    };

    let psp_total = units::total(request.psp_inputs.iter().map(|i| i.amount.units));
    let paid = psp_total
        .checked_mul(u128::from(ESP_PER_PSP))
        .ok_or(Rejection::Overflow)?;
    let requested = units::total(request.outputs.iter().map(|o| o.amount.units));
    let size_bytes = fee::exchange_size(request.psp_inputs.len(), request.outputs.len());
    // The fee is fixed when the request is first accepted, at the rate in force
    // then. A request picked up again after a crash keeps it: what the notes
    // pay over the outputs is the fee it was accepted with, whatever the setting
    // says now.
    let (fee_per_byte, fee_esp) = if recovering {
        let fee_esp = paid.saturating_sub(requested);
        (fee::rate_of(fee_esp, size_bytes), fee_esp)
    } else {
        let fee_esp = fee::charge(size_bytes, settings.fee_per_byte);
        check_amounts(paid, requested, fee_esp, size_bytes, settings)?;
        (settings.fee_per_byte, fee_esp)
    };

    if !recovering {
        // The spend signatures. They are public to check, and cover the memo,
        // so a pending entry only ever exists for a request its holder signed.
        let sighash = melt_sighash(&request.psp_inputs, memo.as_bytes());
        for input in &request.psp_inputs {
            if logic.verify_spend_authorization(input, sighash).is_err() {
                return Err(Rejection::BadSpendSignature.into());
            }
        }
        check_free(logic, responses, request, &hash)?;
    }
    Ok(Prepared::Go(Plan {
        hash,
        memo,
        nonces,
        psp_total,
        redeemable_after_day,
        recovering,
        fee_per_byte,
        fee_esp,
        size_bytes,
    }))
}

/// The checks that read the mint: the database and the reservations of other
/// unfinished requests. They are made in phase 1, and again in phase 3 because
/// the lock was let go in between and another request may have got in.
fn check_free(
    logic: &MintLogic,
    responses: &Responses,
    request: &ExchangeRequest,
    hash: &str,
) -> Result<(), ExchangeError> {
    let (held_inputs, held_outputs) = held_by(request);
    // The mint's own database. The answer is held back until the reservations
    // below have been looked at, because a blind nonce that is used may be used
    // by an unfinished request, and then "held" is the truer answer.
    let mut blind_nonce_used = false;
    for output in &request.outputs {
        if logic
            .is_blind_nonce_used(&output.blind_nonce)
            .map_err(internal)?
        {
            blind_nonce_used = true;
            break;
        }
    }
    // Reservations. Keep clear of every unfinished request, so that a PSP note
    // or a blind nonce one of them will use cannot be taken by another request
    // first.
    for (other, inputs, outputs) in responses.pending_exchanges() {
        if other == hash {
            continue;
        }
        if inputs.iter().any(|n| held_inputs.contains(n))
            || outputs.iter().any(|n| held_outputs.contains(n))
        {
            return Err(Rejection::NoteHeld.into());
        }
    }
    for (other, pending) in responses.pending_transfers() {
        if other == hash {
            continue;
        }
        // A transfer's inputs are ESP notes, so only its outputs can clash.
        if pending.outputs.iter().any(|n| held_outputs.contains(n)) {
            return Err(Rejection::NoteHeld.into());
        }
    }
    // Same for a redemption: its blind nonces are held, unfinished or not.
    let (_, redeem_outputs) = responses.redeem_holds(hash);
    if held_outputs.iter().any(|n| redeem_outputs.contains(n)) {
        return Err(Rejection::NoteHeld.into());
    }
    // A pending rollover will sign its output blind nonces.
    if held_outputs
        .iter()
        .any(|n| responses.external_out_holds().contains(n))
    {
        return Err(Rejection::NoteHeld.into());
    }
    if blind_nonce_used {
        return Err(Rejection::BlindNonceAlreadyUsed.into());
    }
    Ok(())
}

/// Phase 2 (no lock). A fresh request asks the PSP whether any of its notes is
/// already spent, the last look before anything is written. A retry has its own
/// way of asking (phase 4). Nothing is written, so a failure here leaves
/// nothing behind.
pub fn precheck(psp: &dyn Psp, plan: &Plan) -> Result<(), ExchangeError> {
    if plan.recovering {
        return Ok(());
    }
    let spent = psp_spent(psp, &plan.nonces)?;
    if spent.iter().any(|s| *s) {
        return Err(Rejection::PspNoteSpent.into());
    }
    Ok(())
}

/// Phase 3. Write the `pending` entry, after checking again that nothing has
/// taken the notes or nonces since phase 1. A retry already has its entry.
fn reserve(
    logic: &MintLogic,
    responses: &mut Responses,
    request: &ExchangeRequest,
    plan: &Plan,
) -> Result<(), ExchangeError> {
    if plan.recovering {
        return Ok(());
    }
    if responses.get(&plan.hash).is_some() {
        return Err(internal(
            "this request was stored while it was being checked",
        ));
    }
    check_free(logic, responses, request, &plan.hash)?;
    let (inputs, outputs) = held_by(request);
    responses
        .put(
            &plan.hash,
            Entry::Pending {
                redeemable_after_day: plan.redeemable_after_day,
                inputs,
                outputs,
            },
        )
        .map_err(internal)
}

/// Phase 4 (no lock). The PSP burns the notes. For a retry, the PSP is asked
/// first what became of them: burned under this request's memo means an earlier
/// attempt did it, and the burn is skipped.
pub fn burn_phase(
    psp: &dyn Psp,
    request: &ExchangeRequest,
    plan: &Plan,
) -> Result<(), ExchangeError> {
    if !plan.recovering {
        return burn(psp, request, &plan.memo, plan.psp_total, false);
    }
    let burns = psp_burns(psp, &plan.nonces)?;
    // A note that is spent counts as burned by this exchange only if the PSP
    // says it was burned under this exchange's memo.
    let elsewhere: Vec<usize> = burns
        .iter()
        .enumerate()
        .filter(|(_, b)| b.spent && b.memo.as_deref() != Some(plan.memo.as_str()))
        .map(|(i, _)| i)
        .collect();
    if !elsewhere.is_empty() {
        return Err(Rejection::NoteSpentElsewhere { spent: elsewhere }.into());
    }
    if burns.iter().all(|b| b.spent) {
        // already burned by an earlier attempt
        Ok(())
    } else if burns.iter().any(|b| b.spent) {
        Err(ExchangeError::Internal(
            "some PSP notes are spent and some are not, which needs a person to look".into(),
        ))
    } else {
        burn(psp, request, &plan.memo, plan.psp_total, true)
    }
}

/// Phase 5. The entry must still be the pending one this request wrote; then the
/// outputs are signed and the `done` entry replaces it.
fn finish(
    logic: &MintLogic,
    master: &MasterSecret,
    keyset: &str,
    responses: &mut Responses,
    request: &ExchangeRequest,
    plan: &Plan,
) -> Result<ExchangeResponse, ExchangeError> {
    match responses.get(&plan.hash) {
        Some(Entry::Pending { .. }) => {}
        Some(Entry::Done(done)) => return Ok(done.clone()),
        _ => {
            return Err(internal(
                "the pending entry of this exchange is gone, which needs a person to look",
            ));
        }
    }
    let terms = Terms {
        service: request.service,
        redeemable_after_day: plan.redeemable_after_day,
    };
    let recovering = true;
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
        keyset: keyset.to_string(),
        service: request.service,
        redeemable_after_day: plan.redeemable_after_day,
        signatures,
        keys,
        fee_per_byte: plan.fee_per_byte,
        fee_esp: plan.fee_esp,
        size_bytes: plan.size_bytes,
    };
    // The ledger counts the outputs under the exchange's day, in the same write
    // that finishes the entry (see `ledger`).
    let mut movements = Movements::new();
    movements.issue(
        plan.redeemable_after_day,
        units::total(request.outputs.iter().map(|o| o.amount.units)),
    );
    responses
        .finish(&plan.hash, Entry::Done(response.clone()), &movements)
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

fn psp_burns(psp: &dyn Psp, nonces: &[Nonce]) -> Result<Vec<Burn>, ExchangeError> {
    let burns = psp.burns(nonces).map_err(ExchangeError::Psp)?;
    if burns.len() != nonces.len() {
        return Err(ExchangeError::Psp(
            "the PSP answered for a different number of notes".into(),
        ));
    }
    Ok(burns)
}

fn burn(
    psp: &dyn Psp,
    request: &ExchangeRequest,
    memo: &str,
    expected_psp_units: u128,
    recovering: bool,
) -> Result<(), ExchangeError> {
    let burned = match psp.melt_checked(&request.psp_inputs, &request.psp_input_keysets, memo) {
        Ok(burned) => burned,
        Err(MeltError::Unknown(e)) => return Err(ExchangeError::Psp(e)),
        // A fresh request has never melted, so its `400` is a refusal: notes
        // burned under its memo were burned by another request (the same
        // outputs under the other live keyset have the same memo), not by it.
        Err(MeltError::Refused(why)) if !recovering => {
            return Err(Rejection::PspRefusedBurn { why }.into());
        }
        Err(MeltError::Refused(why)) => {
            // A retry's `400` can be stale: an earlier attempt's melt that timed
            // out here may have run at the PSP since the retry looked at the
            // notes, and then this melt finds them spent. So before the entry
            // goes, ask what became of the notes. All burned under this memo:
            // the earlier attempt's melt ran, so the exchange goes on. Some of
            // them: for a person. None: the refusal stands.
            let nonces: Vec<Nonce> = request.psp_inputs.iter().map(|i| i.note.nonce).collect();
            let burns = psp_burns(psp, &nonces)?;
            let ours = burns
                .iter()
                .filter(|b| b.spent && b.memo.as_deref() == Some(memo))
                .count();
            return match ours {
                0 => Err(Rejection::PspRefusedBurn { why }.into()),
                n if n == burns.len() => Ok(()),
                _ => Err(ExchangeError::Psp(format!(
                    "the PSP refused the burn ({why}) but some of the notes are burned under this exchange's memo, which needs a person to look at"
                ))),
            };
        }
    };
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
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    use mint_core::keygen;
    use mint_core::store::Store;
    use mint_types::{BlindNonce, Note, gen_denominations};
    use rand::rngs::OsRng;
    use secp256k1::{Keypair, SecretKey};

    const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const NOW: u64 = 1_791_571_184;
    const ONE_PSP: u64 = 100_000_000_000;

    fn service() -> ServiceDid {
        ServiceDid::parse(&format!("02{G_X}")).unwrap()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("esp-mint-ex-{}-{name}", {
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

    /// A PSP mint in process, standing in for the HTTP one.
    struct FakePsp {
        logic: MintLogic,
        melts: Cell<u32>,
        /// The memo of each burn, by nonce, the way the real PSP keeps it.
        memos: RefCell<BTreeMap<String, String>>,
        /// The PSP cannot be reached: the notes are not burned.
        fail_before_burn: Cell<bool>,
        /// The PSP burns the notes and the reply is lost.
        fail_after_burn: Cell<bool>,
        /// The PSP cannot be asked about the notes (`/burns`).
        fail_burns: Cell<bool>,
        /// The next melt is held: it gets no answer, and the PSP runs it just
        /// before the melt that follows (a slow `/melt` that times out here).
        hold_melt: Cell<bool>,
        held: RefCell<Option<(Vec<MintInput>, String)>>,
    }

    impl FakePsp {
        fn new(dir: &Path) -> Self {
            let cfg = keygen::generate(&gen_denominations(2, Amount::from_units(1024)));
            let store = Store::open(&dir.join("psp-db")).unwrap();
            FakePsp {
                logic: MintLogic::new(cfg, store),
                melts: Cell::new(0),
                memos: RefCell::new(BTreeMap::new()),
                fail_before_burn: Cell::new(false),
                fail_after_burn: Cell::new(false),
                fail_burns: Cell::new(false),
                hold_melt: Cell::new(false),
                held: RefCell::new(None),
            }
        }

        /// Record the memo for the notes that are not spent yet, as the real PSP
        /// does after its checks and just before it burns.
        fn record(&self, inputs: &[MintInput], memo: &str) {
            for input in inputs {
                if !self.logic.is_spent(input.note.nonce).unwrap() {
                    self.memos
                        .borrow_mut()
                        .insert(nonce_key(&input.note.nonce), memo.to_string());
                }
            }
        }

        /// Someone else burns this note, under their own memo, at the PSP.
        fn burn_elsewhere(&self, note: Note, keypair: &Keypair, units: u64, memo: &str) {
            let unsigned = MintInput {
                amount: Amount::from_units(units),
                note,
                spend_signature: secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap(),
            };
            let sighash = melt_sighash(std::slice::from_ref(&unsigned), memo.as_bytes());
            let input = MintInput {
                spend_signature: SECP256K1.sign_schnorr(&sighash, keypair),
                ..unsigned
            };
            self.record(std::slice::from_ref(&input), memo);
            self.logic.melt(&[input], memo.as_bytes()).unwrap();
        }

        /// A note spent with no memo on record: one spent before the PSP kept
        /// memos, or burned by a rollover or a spend, which clear any memo an
        /// earlier melt left on it.
        fn burn_unrecorded(&self, note: Note, keypair: &Keypair, units: u64) {
            self.memos.borrow_mut().remove(&nonce_key(&note.nonce));
            let unsigned = MintInput {
                amount: Amount::from_units(units),
                note,
                spend_signature: secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap(),
            };
            let sighash = melt_sighash(std::slice::from_ref(&unsigned), b"old");
            let input = MintInput {
                spend_signature: SECP256K1.sign_schnorr(&sighash, keypair),
                ..unsigned
            };
            self.logic.melt(&[input], b"old").unwrap();
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
            let signature = bdhke::unblind_message(
                &outcome.0,
                &blinding_key,
                &self.logic.public_keys()[&amount],
            );
            (Note { nonce, signature }, keypair)
        }
    }

    impl Psp for FakePsp {
        fn melt(&self, inputs: &[MintInput], memo: &str) -> Result<Amount, String> {
            self.melt_checked(inputs, &[], memo)
                .map_err(|e| e.to_string())
        }

        /// The real PSP's `/melt`: every check first (a refusal records and burns
        /// nothing), then the record, then the burn.
        fn melt_checked(
            &self,
            inputs: &[MintInput],
            _keysets: &[String],
            memo: &str,
        ) -> Result<Amount, MeltError> {
            if self.fail_before_burn.get() {
                return Err(MeltError::Unknown("unreachable".into()));
            }
            let held = self.held.borrow_mut().take();
            if let Some((inputs, memo)) = held {
                self.record(&inputs, &memo);
                self.logic.melt(&inputs, memo.as_bytes()).unwrap();
            }
            if self.hold_melt.replace(false) {
                *self.held.borrow_mut() = Some((inputs.to_vec(), memo.to_string()));
                return Err(MeltError::Unknown("timed out".into()));
            }
            self.melts.set(self.melts.get() + 1);
            let sighash = melt_sighash(inputs, memo.as_bytes());
            for input in inputs {
                self.logic
                    .verify_note(input)
                    .and_then(|()| self.logic.verify_spend_authorization(input, sighash))
                    .map_err(|e| MeltError::Refused(e.to_string()))?;
                if self.logic.is_spent(input.note.nonce).unwrap() {
                    return Err(MeltError::Refused("a note is spent".into()));
                }
            }
            self.record(inputs, memo);
            let burned = self
                .logic
                .melt(inputs, memo.as_bytes())
                .map_err(|e| MeltError::Unknown(e.to_string()))?;
            if self.fail_after_burn.get() {
                return Err(MeltError::Unknown("timed out".into()));
            }
            Ok(burned)
        }

        fn burns(&self, nonces: &[Nonce]) -> Result<Vec<Burn>, String> {
            if self.fail_burns.get() {
                return Err("unreachable".into());
            }
            nonces
                .iter()
                .map(|n| {
                    let spent = self.logic.is_spent(*n).map_err(|e| e.to_string())?;
                    let memo = if spent {
                        self.memos.borrow().get(&nonce_key(n)).cloned()
                    } else {
                        None
                    };
                    Ok(Burn { spent, memo })
                })
                .collect()
        }
    }

    fn nonce_key(nonce: &Nonce) -> String {
        hex::encode(nonce.0.serialize())
    }

    struct Wanted {
        nonce: Nonce,
        blinding_key: SecretKey,
        amount: u64,
    }

    /// Split a total into powers of two, the way the wallet does: one note for
    /// each bit set, largest first. Zero stays as one zero, so that the zero
    /// test can build it.
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
    /// note that is more than one until there are `n`. Needs
    /// `split(total).len() <= n <= total`.
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

    /// Build a request the way a wallet does: each amount in `esp_amounts` is a
    /// total, split into powers of two. `psp_notes` are (note, key, units).
    /// `signer` signs the spend signatures, normally the note's own key.
    fn build(
        psp_notes: &[(Note, &Keypair, u64)],
        esp_amounts: &[u64],
        signer: Option<&Keypair>,
    ) -> (ExchangeRequest, Vec<Wanted>) {
        let amounts: Vec<u64> = esp_amounts.iter().flat_map(|&a| split(a)).collect();
        build_exact(psp_notes, &amounts, signer)
    }

    /// Like `build`, but each amount is an output as it stands, whatever it is.
    fn build_exact(
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
        (sign_request(psp_notes, outputs, signer), wanted)
    }

    /// A signed request for these outputs, which may be another request's.
    fn sign_request(
        psp_notes: &[(Note, &Keypair, u64)],
        outputs: Vec<MintOutput>,
        signer: Option<&Keypair>,
    ) -> ExchangeRequest {
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
        ExchangeRequest {
            service: service(),
            psp_input_keysets: vec!["00".repeat(8); inputs.len()],
            psp_inputs: inputs,
            keyset: ks(),
            outputs,
        }
    }

    #[test]
    fn every_keyset_field_is_in_the_exchange_request_hash() {
        let kp = Keypair::new(SECP256K1, &mut OsRng);
        let note = Note {
            nonce: Nonce(kp.public_key()),
            signature: kp.public_key(),
        };
        let base = sign_request(&[(note, &kp, 1)], vec![], None);
        let mut a = base.clone();
        a.psp_input_keysets = vec!["ab".repeat(8)];
        let mut b = base.clone();
        b.keyset = "cd".repeat(8);
        let h = |r: &ExchangeRequest| request_hash(r).unwrap();
        assert!(h(&base) != h(&a) && h(&base) != h(&b) && h(&a) != h(&b));
    }

    thread_local! {
        /// The keyset of this test's mint (set by `setup`), which requests name.
        static KS: std::cell::RefCell<String> = std::cell::RefCell::new("00".repeat(8));
    }

    fn ks() -> String {
        KS.with(|k| k.borrow().clone())
    }

    /// The smallest exchange a mint with the default settings takes, in ESP
    /// units.
    fn min_exchange() -> u128 {
        u128::from(ExchangeSettings::default().min_psp) * u128::from(ESP_PER_PSP)
    }

    /// A rotating ESP mint (the rotor `serve` opens), its stored responses and a
    /// fake PSP. `logic` is the rotor's current generation.
    struct Setup {
        dir: PathBuf,
        psp: FakePsp,
        rotor: crate::rotation::Rotor,
        logic: MintLogic,
        master: MasterSecret,
        responses: Responses,
    }

    fn setup(name: &str) -> Setup {
        let dir = scratch(name);
        let psp = FakePsp::new(&dir);
        let (rotor, logic) = crate::rotation::Rotor::open_at(&dir.join("esp"), 1, 1, NOW).unwrap();
        let master = rotor.current.master.clone();
        KS.with(|k| *k.borrow_mut() = rotor.current.id.clone());
        let responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
        Setup {
            dir,
            psp,
            rotor,
            logic,
            master,
            responses,
        }
    }

    impl Setup {
        fn run(&mut self, request: &ExchangeRequest) -> Result<ExchangeResponse, ExchangeError> {
            self.run_at(NOW, request, &ExchangeSettings::default())
        }

        /// The whole exchange, as the server runs it, at this time and under
        /// these settings.
        fn run_at(
            &mut self,
            now_unix: u64,
            request: &ExchangeRequest,
            settings: &ExchangeSettings,
        ) -> Result<ExchangeResponse, ExchangeError> {
            exchange_gens(
                &self.rotor.gens(&self.logic),
                &self.psp,
                &mut self.responses,
                now_unix,
                request,
                settings,
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
            assert!(bdhke::verify_message(
                &sk,
                unblinded,
                &w.nonce.as_hash_preimage()
            ));
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
        assert_eq!(response.signatures.len(), request.outputs.len());
        assert!(matches!(s.responses.get(&hash), Some(Entry::Done(_))));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    /// The phases by hand, on the default settings: what `prepare` decided.
    fn plan_of(s: &Setup, request: &ExchangeRequest) -> Plan {
        match prepare(
            &s.logic,
            &s.responses,
            NOW,
            request,
            &ExchangeSettings::default(),
        )
        .unwrap()
        {
            Prepared::Go(plan) => plan,
            Prepared::Done(_) => panic!("the request was already done"),
        }
    }

    fn reopen(s: &mut Setup) {
        s.responses = Responses::open(&s.dir.join("esp").join("responses.json")).unwrap();
    }

    #[test]
    fn the_phases_write_only_when_they_should_and_add_up_to_an_exchange() {
        let mut s = setup("phases");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let hash = request_hash(&request).unwrap();
        let id = crate::rotation::keyset_id(&s.master);

        // Checking writes nothing and does not touch the PSP's notes.
        let plan = plan_of(&s, &request);
        assert!(!plan.recovering());
        assert!(s.responses.get(&hash).is_none());
        precheck(&s.psp, &plan).unwrap();
        assert!(s.responses.get(&hash).is_none());

        // Reserving writes the pending entry, and still burns nothing.
        reserve(&s.logic, &mut s.responses, &request, &plan).unwrap();
        assert!(matches!(
            s.responses.get(&hash),
            Some(Entry::Pending { .. })
        ));
        assert_eq!(s.psp.melts.get(), 0);
        assert!(!s.psp.logic.is_spent(note.nonce).unwrap());

        // The burn writes nothing to the mint's own store.
        burn_phase(&s.psp, &request, &plan).unwrap();
        assert_eq!(s.psp.melts.get(), 1);
        assert!(matches!(
            s.responses.get(&hash),
            Some(Entry::Pending { .. })
        ));
        assert_eq!(s.esp_issued(), 0);

        // Finishing signs and replaces the entry.
        let response = finish(&s.logic, &s.master, &id, &mut s.responses, &request, &plan).unwrap();
        assert_eq!(response.signatures.len(), request.outputs.len());
        assert_eq!(s.responses.get(&hash), Some(&Entry::Done(response.clone())));
        assert_eq!(s.esp_issued(), ONE_PSP);

        // A request that is done is found done by the first phase.
        assert!(matches!(
            prepare(
                &s.logic,
                &s.responses,
                NOW,
                &request,
                &ExchangeSettings::default()
            ),
            Ok(Prepared::Done(done)) if done == response
        ));
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_crash_after_any_phase_is_picked_up_by_the_retry_and_burns_once() {
        // 0: after the checks. 1: after the PSP's look. 2: after the pending
        // entry is written (the lock is let go here, with the PSP not yet
        // asked to burn). 3: after the burn, before the signing.
        for stop in 0..4 {
            let mut s = setup(&format!("crash-after-{stop}"));
            let (note, keypair) = s.psp.note(1);
            let (request, wanted) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
            let hash = request_hash(&request).unwrap();
            let plan = plan_of(&s, &request);
            if stop >= 1 {
                precheck(&s.psp, &plan).unwrap();
            }
            if stop >= 2 {
                reserve(&s.logic, &mut s.responses, &request, &plan).unwrap();
            }
            if stop >= 3 {
                burn_phase(&s.psp, &request, &plan).unwrap();
            }
            // The mint restarts: whatever was in memory is gone.
            reopen(&mut s);
            let on_file = s.responses.get(&hash).is_some();
            assert_eq!(on_file, stop >= 2, "stop {stop}");

            let response = s.run(&request).unwrap();
            assert_eq!(s.psp.melts.get(), 1, "stop {stop}");
            assert_eq!(s.esp_issued(), ONE_PSP, "stop {stop}");
            assert!(s.psp.logic.is_spent(note.nonce).unwrap());
            assert_eq!(response.signatures.len(), wanted.len());
            assert!(matches!(s.responses.get(&hash), Some(Entry::Done(_))));
            assert_eq!(s.responses.pending_exchanges().count(), 0);
            fs::remove_dir_all(&s.dir).unwrap();
        }
    }

    #[test]
    fn a_request_that_got_in_between_the_checks_and_the_reservation_is_caught() {
        let mut s = setup("between");
        let (note, keypair) = s.psp.note(1);
        let (first, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let (second, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let (hash_a, hash_b) = (
            request_hash(&first).unwrap(),
            request_hash(&second).unwrap(),
        );
        // Both pass the checks, because neither has reserved anything yet.
        let plan_a = plan_of(&s, &first);
        let plan_b = plan_of(&s, &second);
        precheck(&s.psp, &plan_a).unwrap();
        precheck(&s.psp, &plan_b).unwrap();
        // The first reserves. The second finds it there, and writes nothing.
        reserve(&s.logic, &mut s.responses, &first, &plan_a).unwrap();
        match reserve(&s.logic, &mut s.responses, &second, &plan_b) {
            Err(ExchangeError::Rejected(r)) => assert_eq!(r, Rejection::NoteHeld),
            other => panic!("expected NoteHeld, got {other:?}"),
        }
        assert!(s.responses.get(&hash_b).is_none());
        assert!(matches!(
            s.responses.get(&hash_a),
            Some(Entry::Pending { .. })
        ));
        // The first goes on and finishes.
        burn_phase(&s.psp, &first, &plan_a).unwrap();
        let id = crate::rotation::keyset_id(&s.master);
        finish(&s.logic, &s.master, &id, &mut s.responses, &first, &plan_a).unwrap();
        assert_eq!(s.psp.melts.get(), 1);
        assert_eq!(s.esp_issued(), ONE_PSP);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_psp_that_cannot_be_asked_leaves_nothing_reserved() {
        let mut s = setup("psp-down-before");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let hash = request_hash(&request).unwrap();
        // The look at the notes fails before anything is written.
        s.psp.fail_burns.set(true);
        assert!(matches!(s.run(&request), Err(ExchangeError::Psp(_))));
        assert!(s.responses.get(&hash).is_none());
        assert_eq!(s.responses.pending_exchanges().count(), 0);
        assert_eq!(s.psp.melts.get(), 0);
        // Another request for the same note is not held back.
        s.psp.fail_burns.set(false);
        let (other, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        assert!(s.run(&other).is_ok());
        assert_eq!(s.psp.melts.get(), 1);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_burn_that_failed_leaves_the_entry_for_the_retry_and_nothing_else_stuck() {
        let mut s = setup("psp-down-during");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let hash = request_hash(&request).unwrap();
        // The PSP does not answer the burn. Whether it burned is not known, so
        // the entry stays; it is what the retry works from.
        s.psp.fail_before_burn.set(true);
        assert!(matches!(s.run(&request), Err(ExchangeError::Psp(_))));
        assert!(matches!(
            s.responses.get(&hash),
            Some(Entry::Pending { .. })
        ));
        s.psp.fail_before_burn.set(false);
        // The retry asks the PSP what became of the note and finishes.
        assert!(s.run(&request).is_ok());
        assert_eq!(s.psp.melts.get(), 1);
        assert_eq!(s.responses.pending_exchanges().count(), 0);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_refused_burn_drops_the_entry_so_a_rolled_over_note_cannot_pay_twice() {
        let mut s = setup("refused-burn");
        let (two, k2) = s.psp.note(2);
        let (one, k1) = s.psp.note(1);
        // The notes are worth 3 PSP, but the first is claimed as 4: 5 PSP in all.
        let (request, _) = build(&[(two, &k2, 4), (one, &k1, 1)], &[5 * ONE_PSP], None);
        let hash = request_hash(&request).unwrap();
        assert!(matches!(
            rejection(s.run(&request)),
            Rejection::PspRefusedBurn { .. }
        ));
        assert!(s.responses.get(&hash).is_none());
        assert!(!s.psp.logic.is_spent(two.nonce).unwrap());
        // The holder rolls both notes over at their true amounts. The PSP burns
        // them and leaves no memo on them.
        s.psp.burn_unrecorded(two, &k2, 2);
        s.psp.burn_unrecorded(one, &k1, 1);
        // Sent again, the request is a new one and meets every check.
        assert_eq!(rejection(s.run(&request)), Rejection::PspNoteSpent);
        assert_eq!(s.esp_issued(), 0);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_retry_whose_burn_is_refused_drops_the_entry_it_kept_after_a_lost_reply() {
        let mut s = setup("refused-retry");
        let (two, k2) = s.psp.note(2);
        let (request, _) = build(&[(two, &k2, 4)], &[4 * ONE_PSP], None);
        let hash = request_hash(&request).unwrap();
        s.psp.fail_before_burn.set(true);
        assert!(matches!(s.run(&request), Err(ExchangeError::Psp(_))));
        assert!(s.responses.get(&hash).is_some());
        // No note is spent, so the retry burns, and the PSP refuses.
        s.psp.fail_before_burn.set(false);
        assert!(matches!(
            rejection(s.run(&request)),
            Rejection::PspRefusedBurn { .. }
        ));
        assert!(s.responses.get(&hash).is_none());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_refusal_that_a_late_melt_of_this_exchange_caused_is_not_a_refusal() {
        let mut s = setup("late-melt");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let hash = request_hash(&request).unwrap();
        // The first melt times out here, and the PSP runs it later.
        s.psp.hold_melt.set(true);
        assert!(matches!(s.run(&request), Err(ExchangeError::Psp(_))));
        assert!(!s.psp.logic.is_spent(note.nonce).unwrap());
        // The retry looks at the note, finds it unspent, and sends its melt. The
        // PSP runs the first one just before it, so the second finds the note
        // spent and answers 400. The note was burned under this memo.
        assert!(s.run(&request).is_ok());
        assert!(matches!(s.responses.get(&hash), Some(Entry::Done(_))));
        assert_eq!(s.esp_issued(), ONE_PSP);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    /// Two exchanges of one note with the same service and outputs, so one memo
    /// and one set of spend signatures, that differ only in the keyset: the rival
    /// names the previous live set, the first the current one. The first is
    /// prepared and prechecked while the note is unspent; then the rival runs from
    /// start to finish and burns the note. Returns the first and its plan.
    fn rival_finishes_first(s: &mut Setup) -> (ExchangeRequest, Plan) {
        use std::sync::atomic::Ordering;
        s.rotor.first_issue = Some(NOW);
        s.rotor.clock.store(NOW + 3600, Ordering::SeqCst);
        s.rotor.refresh(&mut s.logic).unwrap();
        let (note, keypair) = s.psp.note(1);
        let (mut rival, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        rival.keyset = s.rotor.previous.as_ref().unwrap().0.id.clone();
        let mut first = rival.clone();
        first.keyset = s.rotor.current.id.clone();
        assert_ne!(request_hash(&first).unwrap(), request_hash(&rival).unwrap());
        let settings = ExchangeSettings::default();
        let gens = s.rotor.gens(&s.logic);
        let Ok(Prepared::Go(plan)) = prepare_gens(&gens, &s.responses, NOW, &first, &settings)
        else {
            panic!("the first exchange is not prepared");
        };
        precheck(&s.psp, &plan).unwrap();
        exchange_gens(&gens, &s.psp, &mut s.responses, NOW, &rival, &settings).unwrap();
        (first, plan)
    }

    /// Issued by both live sets.
    fn issued_by_both(s: &Setup) -> u64 {
        let previous = s.rotor.previous.as_ref().unwrap();
        s.esp_issued() + previous.1.audit_totals().unwrap().0.units
    }

    #[test]
    fn a_fresh_exchange_does_not_take_a_rivals_burn_for_its_own() {
        // Fails if a refused melt of a request that has never melted is looked up
        // in `/burns`: the note is burned under the same memo (by the rival), the
        // request goes on, and signs the outputs a second time for one burn.
        let mut s = setup("rival-burn");
        let (first, plan) = rival_finishes_first(&mut s);
        assert!(matches!(
            burn_phase(&s.psp, &first, &plan),
            Err(ExchangeError::Rejected(Rejection::PspRefusedBurn { .. }))
        ));
        assert_eq!(issued_by_both(&s), ONE_PSP);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn an_output_the_other_live_set_signed_is_used_for_an_exchange_too() {
        // Fails if the check for a used blind nonce looks only at the set the
        // request names: the first exchange is reserved and stays pending, and a
        // retry takes the note burned under the memo as burned by itself.
        let mut s = setup("rival-reserve");
        let (first, plan) = rival_finishes_first(&mut s);
        let reserved = reserve_gens(&s.rotor.gens(&s.logic), &mut s.responses, &first, &plan);
        assert!(matches!(
            reserved,
            Err(ExchangeError::Rejected(Rejection::BlindNonceAlreadyUsed))
        ));
        assert_eq!(s.responses.pending_exchanges().count(), 0);
        // Sent again, it is refused in the first phase.
        assert_eq!(rejection(s.run(&first)), Rejection::BlindNonceAlreadyUsed);
        assert_eq!(issued_by_both(&s), ONE_PSP);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn finishing_needs_the_pending_entry_to_be_there() {
        let mut s = setup("entry-gone");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let plan = plan_of(&s, &request);
        let id = crate::rotation::keyset_id(&s.master);
        // Nothing was reserved, so there is nothing to finish.
        assert!(matches!(
            finish(&s.logic, &s.master, &id, &mut s.responses, &request, &plan),
            Err(ExchangeError::Internal(_))
        ));
        assert_eq!(s.esp_issued(), 0);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn two_different_exchanges_of_the_same_psp_notes_cannot_both_go_ahead() {
        let mut s = setup("same-notes");
        let (note, keypair) = s.psp.note(1);
        let (first, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let (second, _) = build(&[(note, &keypair, 1)], &[ONE_PSP / 2, ONE_PSP / 2], None);
        let (hash_a, hash_b) = (
            request_hash(&first).unwrap(),
            request_hash(&second).unwrap(),
        );
        assert_ne!(hash_a, hash_b);

        // The first is validated and pending. The PSP cannot be reached, so
        // nothing is burned.
        s.psp.fail_before_burn.set(true);
        assert!(matches!(s.run(&first), Err(ExchangeError::Psp(_))));
        s.psp.fail_before_burn.set(false);
        assert!(!s.psp.logic.is_spent(note.nonce).unwrap());
        let (inputs, outputs) = held_by(&first);
        assert_eq!(
            s.responses.get(&hash_a),
            Some(&Entry::Pending {
                redeemable_after_day: NOW / 86_400 + 365,
                inputs,
                outputs,
            })
        );

        // The second asks for the same note and is refused. Nothing is burned,
        // nothing is stored under its hash, and nothing is issued.
        assert_eq!(rejection(s.run(&second)), Rejection::NoteHeld);
        assert_eq!(s.psp.melts.get(), 0);
        assert!(!s.psp.logic.is_spent(note.nonce).unwrap());
        assert!(s.responses.get(&hash_b).is_none());
        assert_eq!(s.esp_issued(), 0);

        // The first finishes on retry.
        let response = s.run(&first).unwrap();
        assert_eq!(s.psp.melts.get(), 1);
        assert_eq!(s.esp_issued(), ONE_PSP);

        // Once it is done, the second is still refused, now because the note is
        // spent, and a retry of the first still gets its stored answer.
        assert_eq!(rejection(s.run(&second)), Rejection::PspNoteSpent);
        assert_eq!(s.psp.melts.get(), 1);
        assert_eq!(s.esp_issued(), ONE_PSP);
        assert_eq!(s.run(&first).unwrap(), response);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn one_shared_psp_note_is_enough_to_hold_a_request_back() {
        let mut s = setup("one-shared");
        let (a, ka) = s.psp.note(1);
        let (b, kb) = s.psp.note(1);
        let (first, _) = build(&[(a, &ka, 1)], &[ONE_PSP], None);
        let (second, _) = build(&[(a, &ka, 1), (b, &kb, 1)], &[2 * ONE_PSP], None);
        s.psp.fail_before_burn.set(true);
        assert!(matches!(s.run(&first), Err(ExchangeError::Psp(_))));
        s.psp.fail_before_burn.set(false);
        assert_eq!(rejection(s.run(&second)), Rejection::NoteHeld);
        // the note that is not shared is untouched too
        assert!(!s.psp.logic.is_spent(a.nonce).unwrap());
        assert!(!s.psp.logic.is_spent(b.nonce).unwrap());
        assert_eq!(s.psp.melts.get(), 0);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_pending_exchange_holds_its_output_blind_nonces_against_other_notes() {
        let mut s = setup("held-output");
        let (a, ka) = s.psp.note(1);
        let (b, kb) = s.psp.note(1);
        let (first, _) = build(&[(a, &ka, 1)], &[ONE_PSP], None);
        // a different note, and the same output blind nonce
        let second = sign_request(&[(b, &kb, 1)], first.outputs.clone(), None);
        s.psp.fail_before_burn.set(true);
        assert!(matches!(s.run(&first), Err(ExchangeError::Psp(_))));
        s.psp.fail_before_burn.set(false);
        assert_eq!(rejection(s.run(&second)), Rejection::NoteHeld);
        assert!(!s.psp.logic.is_spent(b.nonce).unwrap());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_crash_between_the_burn_and_the_signing_cannot_be_used_to_burn_the_notes_again() {
        let mut s = setup("burn-crash");
        let (note, keypair) = s.psp.note(1);
        let (first, wanted) = build(&[(note, &keypair, 1)], &[ONE_PSP / 2, ONE_PSP / 2], None);
        let (second, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);

        // The PSP burns the note, the reply is lost, and the mint stops after it
        // has signed the first output only.
        s.psp.fail_after_burn.set(true);
        assert!(matches!(s.run(&first), Err(ExchangeError::Psp(_))));
        assert!(s.psp.logic.is_spent(note.nonce).unwrap());
        let terms = Terms::new_at(service(), NOW);
        let sk = s.master.key_for(first.outputs[0].amount, &terms);
        let signed_before_stop = s.logic.issue_with_key(&sk, &first.outputs[0]).unwrap().0;
        s.psp.fail_after_burn.set(false);

        // The mint restarts. Another request for the same note is refused as
        // held by the first, not taken as one for a note that is spent, and
        // nothing more is issued.
        s.responses = Responses::open(&s.dir.join("esp").join("responses.json")).unwrap();
        assert_eq!(rejection(s.run(&second)), Rejection::NoteHeld);
        assert_eq!(s.esp_issued(), first.outputs[0].amount.units);

        // The retry skips the burn, signs the first output again (the same
        // signature) and the second for the first time.
        let response = s.run(&first).unwrap();
        assert_eq!(s.psp.melts.get(), 1);
        assert_eq!(s.esp_issued(), ONE_PSP);
        assert_eq!(response.signatures.len(), first.outputs.len());
        assert_eq!(response.signatures[0], signed_before_stop);
        for (i, want) in wanted.iter().enumerate() {
            let sk = s.master.key_for(first.outputs[i].amount, &terms);
            assert_eq!(response.keys[i], sk.public_key(SECP256K1));
            let unblinded = bdhke::unblind_message(
                &response.signatures[i],
                &want.blinding_key,
                &response.keys[i],
            );
            assert!(bdhke::verify_message(
                &sk,
                unblinded,
                &want.nonce.as_hash_preimage()
            ));
        }

        // Done: the other request is now an ordinary double spend.
        assert_eq!(rejection(s.run(&second)), Rejection::PspNoteSpent);
        assert_eq!(s.esp_issued(), ONE_PSP);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn an_unfinished_transfer_holds_its_output_blind_nonces_against_an_exchange() {
        let mut s = setup("held-by-transfer");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        s.responses
            .put(
                "a-transfer",
                Entry::TransferPending(crate::responses::TransferPending {
                    burned: false,
                    inputs: vec!["02aa".into()],
                    outputs: vec![hex::encode(request.outputs[0].blind_nonce.0.serialize())],
                }),
            )
            .unwrap();
        assert_eq!(rejection(s.run(&request)), Rejection::NoteHeld);
        assert!(!s.psp.logic.is_spent(note.nonce).unwrap());
        assert_eq!(s.psp.melts.get(), 0);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_redemption_holds_its_output_blind_nonces_against_an_exchange() {
        use crate::redeem::{self, RedeemOutput, RedeemPending, RedeemRecord};
        let mut s = setup("held-by-redeem");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let nonce = request.outputs[0].blind_nonce;
        // unfinished: held until it finishes
        s.responses
            .put(
                "a-redemption",
                Entry::RedeemPending(RedeemPending {
                    burned: false,
                    inputs: vec![],
                    outputs: vec![hex::encode(nonce.0.serialize())],
                    plan: redeem::empty_plan(),
                }),
            )
            .unwrap();
        assert_eq!(rejection(s.run(&request)), Rejection::NoteHeld);
        // finished: its decline outputs may still be signed, so still held
        s.responses
            .put(
                "a-redemption",
                Entry::RedeemDone(RedeemRecord {
                    output_keyset: String::new(),
                    plan: redeem::empty_plan(),
                    refund: vec![],
                    decline_outputs: vec![RedeemOutput {
                        service: request.service,
                        redeemable_after_day: 21_000,
                        output: request.outputs[0].clone(),
                    }],
                }),
            )
            .unwrap();
        assert_eq!(rejection(s.run(&request)), Rejection::NoteHeld);
        assert!(!s.psp.logic.is_spent(note.nonce).unwrap());
        assert_eq!(s.psp.melts.get(), 0);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn notes_burned_by_someone_else_are_not_taken_as_this_exchanges() {
        let mut s = setup("elsewhere");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let hash = request_hash(&request).unwrap();

        // The exchange is validated and pending, and then the PSP cannot be
        // reached, so it burns nothing.
        s.psp.fail_before_burn.set(true);
        assert!(matches!(s.run(&request), Err(ExchangeError::Psp(_))));
        s.psp.fail_before_burn.set(false);
        assert!(!s.psp.logic.is_spent(note.nonce).unwrap());

        // The holder spends the same note at the PSP under another memo.
        s.psp.burn_elsewhere(note, &keypair, 1, "somewhere else");

        // The retry sees a spent note whose memo is not its own. It signs
        // nothing, and says why.
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::NoteSpentElsewhere { spent: vec![0] }
        );
        assert_eq!(s.esp_issued(), 0);
        assert!(matches!(
            s.responses.get(&hash),
            Some(Entry::Pending { .. })
        ));
        // and it keeps saying so
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::NoteSpentElsewhere { spent: vec![0] }
        );
        assert_eq!(s.esp_issued(), 0);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_spent_note_with_no_memo_on_record_is_not_taken_as_this_exchanges() {
        let mut s = setup("no-memo");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        s.psp.fail_before_burn.set(true);
        assert!(matches!(s.run(&request), Err(ExchangeError::Psp(_))));
        s.psp.fail_before_burn.set(false);
        s.psp.burn_unrecorded(note, &keypair, 1);
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::NoteSpentElsewhere { spent: vec![0] }
        );
        assert_eq!(s.esp_issued(), 0);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn one_note_burned_elsewhere_is_enough_to_stop_the_exchange() {
        let mut s = setup("one-elsewhere");
        let (a, ka) = s.psp.note(1);
        let (b, kb) = s.psp.note(1);
        let (request, _) = build(&[(a, &ka, 1), (b, &kb, 1)], &[2 * ONE_PSP], None);
        s.psp.fail_before_burn.set(true);
        assert!(matches!(s.run(&request), Err(ExchangeError::Psp(_))));
        s.psp.fail_before_burn.set(false);
        s.psp.burn_elsewhere(a, &ka, 1, "somewhere else");
        // not an internal fault, and the other note is not burned for it
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::NoteSpentElsewhere { spent: vec![0] }
        );
        assert!(!s.psp.logic.is_spent(b.nonce).unwrap());
        assert_eq!(s.esp_issued(), 0);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn notes_burned_under_this_exchanges_memo_are_taken_as_its_own() {
        // The case that must keep working: the burn happened under this memo, the
        // reply was lost, and the retry issues without burning again. The PSP
        // reports the memo the exchange sent.
        let mut s = setup("own-memo");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        s.psp.fail_after_burn.set(true);
        assert!(matches!(s.run(&request), Err(ExchangeError::Psp(_))));
        s.psp.fail_after_burn.set(false);
        let reported = s.psp.burns(&[note.nonce]).unwrap();
        assert_eq!(
            reported,
            vec![Burn {
                spent: true,
                memo: Some(memo(&request.service, &request.outputs)),
            }]
        );
        s.run(&request).unwrap();
        assert_eq!(s.psp.melts.get(), 1);
        assert_eq!(s.esp_issued(), ONE_PSP);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_recovered_exchange_keeps_the_original_day() {
        let mut s = setup("recover-day");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        s.psp.fail_after_burn.set(true);
        assert!(matches!(s.run(&request), Err(ExchangeError::Psp(_))));
        s.psp.fail_after_burn.set(false);
        // a month later
        let later = NOW + 30 * 86_400;
        let response = s
            .run_at(later, &request, &ExchangeSettings::default())
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
        assert!(matches!(s.run(&request), Err(ExchangeError::Psp(_))));
        // the first output was issued before the stop
        let terms = Terms::new_at(service(), NOW);
        let sk = s.master.key_for(request.outputs[0].amount, &terms);
        s.logic.issue_with_key(&sk, &request.outputs[0]).unwrap();
        s.psp.fail_after_burn.set(false);
        let response = s.run(&request).unwrap();
        assert_eq!(response.signatures.len(), request.outputs.len());
        assert_eq!(s.esp_issued(), ONE_PSP);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_mismatch_is_refused_before_anything_is_burned_whichever_way_it_is_off() {
        let mut s = setup("mismatch");
        let (note, keypair) = s.psp.note(2);
        let paid = 2 * u128::from(ONE_PSP);
        // one ESP unit short of the PSP value
        let (request, _) = build(&[(note, &keypair, 2)], &[2 * ONE_PSP - 1], None);
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::NotExact {
                paid,
                requested: paid - 1
            }
        );
        // one ESP unit over
        let (request, _) = build(&[(note, &keypair, 2)], &[2 * ONE_PSP + 1], None);
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::NotExact {
                paid,
                requested: paid + 1
            }
        );
        // too small an exchange, and one that is not exact, are both refused
        let (request, _) = build(&[(note, &keypair, 2)], &[ONE_PSP], None);
        assert!(matches!(
            rejection(s.run(&request)),
            Rejection::NotExact { .. }
        ));
        let (request, _) = build(&[(note, &keypair, 2)], &[ONE_PSP * 100 / 105], None);
        assert!(matches!(
            rejection(s.run(&request)),
            Rejection::BelowMinimum { .. }
        ));
        assert!(!s.psp.logic.is_spent(note.nonce).unwrap());
        assert_eq!(s.psp.melts.get(), 0);
        assert!(s.responses.is_empty());
        assert_eq!(s.esp_issued(), 0);
        // and the exact request still works afterwards
        let (request, _) = build(&[(note, &keypair, 2)], &[ONE_PSP, ONE_PSP], None);
        s.run(&request).unwrap();
        assert_eq!(s.esp_issued(), 2 * ONE_PSP);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn the_error_says_which_way_it_is_off() {
        let over = Rejection::NotExact {
            paid: 3 * u128::from(ONE_PSP),
            requested: 2 * u128::from(ONE_PSP),
        };
        let short = Rejection::NotExact {
            paid: 2 * u128::from(ONE_PSP),
            requested: 3 * u128::from(ONE_PSP),
        };
        assert!(over.to_string().contains("over by 100000000000"));
        assert!(short.to_string().contains("short by 100000000000"));
        assert!(over.to_string().contains("Nothing was burned"));
        let low = Rejection::BelowMinimum {
            requested: 5,
            minimum: u128::from(ONE_PSP),
        };
        assert!(
            low.to_string()
                .contains("smallest exchange is 100000000000 ESP units (1 PSP)")
        );
    }

    #[test]
    fn a_fee_is_paid_in_esp_on_top_of_the_exact_amount_and_the_rate_is_kept() {
        let mut s = setup("fee");
        let rate = 1_000u128;
        let with_fee = ExchangeSettings {
            fee_per_byte: rate,
            ..ExchangeSettings::default()
        };
        // The fee depends on how many outputs there are, and how many there are
        // depends on the fee, because each output is a power of two.
        let size = fee::exchange_size(1, split(ONE_PSP).len());
        let fee_esp = fee::charge(size, rate);
        let run = |s: &mut Setup, request: &ExchangeRequest, settings: &ExchangeSettings| {
            s.run_at(NOW, request, settings)
        };
        let (note, keypair) = s.psp.note(1);
        // The exact amount with no fee on top is refused under a fee, and says
        // what the fee is. Nothing is burned.
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        match rejection(run(&mut s, &request, &with_fee)) {
            Rejection::NotExactWithFee {
                fee,
                size_bytes,
                fee_per_byte,
                ..
            } => assert_eq!((fee, size_bytes, fee_per_byte), (fee_esp, size, rate)),
            other => panic!("expected NotExactWithFee, got {other:?}"),
        }
        assert!(!s.psp.logic.is_spent(note.nonce).unwrap());
        // With the fee left off the outputs, it goes through.
        // That takes the fewest outputs n for which the rest, ONE_PSP less the
        // fee for n outputs, splits into exactly n powers of two.
        let (n, rest, fee_esp, size) = (1..=MAX_ITEMS)
            .find_map(|n| {
                let size = fee::exchange_size(1, n);
                let fee_esp = fee::charge(size, rate);
                let rest = ONE_PSP - fee_esp as u64;
                (split(rest).len() <= n && n as u64 <= rest).then_some((n, rest, fee_esp, size))
            })
            .unwrap();
        let (request, _) = build_exact(&[(note, &keypair, 1)], &split_into(rest, n), None);
        assert_eq!(request.outputs.len(), n);
        let response = run(&mut s, &request, &with_fee).unwrap();
        assert_eq!(
            (response.fee_per_byte, response.fee_esp, response.size_bytes),
            (rate, fee_esp, size)
        );
        assert_eq!(s.esp_issued(), rest);
        // A retry after the rate was changed gets the reply stored at the old rate.
        let later = ExchangeSettings {
            fee_per_byte: rate * 5,
            ..ExchangeSettings::default()
        };
        assert_eq!(run(&mut s, &request, &later).unwrap(), response);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn with_no_fee_the_reply_says_so() {
        let mut s = setup("nofee");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let response = s.run(&request).unwrap();
        assert_eq!((response.fee_per_byte, response.fee_esp), (0, 0));
        assert_eq!(
            response.size_bytes,
            fee::exchange_size(1, request.outputs.len())
        );
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn the_smallest_exchange_is_one_psp() {
        assert_eq!(
            check_exact_min(u128::from(ONE_PSP), u128::from(ONE_PSP), min_exchange()),
            Ok(())
        );
        assert_eq!(
            check_exact_min(0, u128::from(ONE_PSP) - 1, min_exchange()),
            Err(Rejection::BelowMinimum {
                requested: u128::from(ONE_PSP) - 1,
                minimum: u128::from(ONE_PSP),
            })
        );
        // below the minimum is reported as such even when the PSP side is larger
        assert_eq!(
            check_exact_min(u128::from(ONE_PSP), 1, min_exchange()),
            Err(Rejection::BelowMinimum {
                requested: 1,
                minimum: u128::from(ONE_PSP),
            })
        );
        let mut s = setup("minimum");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP - 1], None);
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::BelowMinimum {
                requested: u128::from(ONE_PSP) - 1,
                minimum: u128::from(ONE_PSP),
            }
        );
        assert!(!s.psp.logic.is_spent(note.nonce).unwrap());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn exactness_is_checked_in_u128() {
        let one = u128::from(ONE_PSP);
        assert_eq!(
            check_exact_min(
                units::psp_to_esp(u64::MAX),
                units::psp_to_esp(u64::MAX),
                min_exchange()
            ),
            Ok(())
        );
        assert_eq!(
            check_exact_min(
                units::psp_to_esp(u64::MAX),
                units::psp_to_esp(u64::MAX) - 1,
                min_exchange()
            ),
            Err(Rejection::NotExact {
                paid: units::psp_to_esp(u64::MAX),
                requested: units::psp_to_esp(u64::MAX) - 1
            })
        );
        let many = units::total(std::iter::repeat_n(u64::MAX, MAX_ITEMS));
        assert_eq!(check_exact_min(many, many, min_exchange()), Ok(()));
        assert_eq!(
            check_exact_min(many + one, many, min_exchange()),
            Err(Rejection::NotExact {
                paid: many + one,
                requested: many
            })
        );
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
        let sighash = melt_sighash(
            &second.psp_inputs,
            memo(&service(), &second.outputs).as_bytes(),
        );
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
        assert_eq!(
            rejection(s.run(&dup_output)),
            Rejection::DuplicateBlindNonce
        );

        let mut dup_input = good.clone();
        dup_input.psp_inputs.push(dup_input.psp_inputs[0].clone());
        dup_input.psp_input_keysets.push("00".repeat(8));
        assert_eq!(rejection(s.run(&dup_input)), Rejection::DuplicateInput);

        let mut unnamed = good.clone();
        unnamed.psp_input_keysets.clear();
        assert_eq!(rejection(s.run(&unnamed)), Rejection::MissingKeyset);

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
    fn an_output_that_is_not_a_power_of_two_is_refused_before_anything_is_burned() {
        let mut s = setup("denomination");
        let (note, keypair) = s.psp.note(1);
        // the right total (1 PSP), but as one odd output and not as powers of two
        let (request, _) = build_exact(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let r = rejection(s.run(&request));
        assert_eq!(r, Rejection::BadDenomination { index: 0 });
        assert_eq!(
            r.to_string(),
            "output 0: ESP amounts are powers of two. Nothing was burned"
        );
        // one odd output among good ones names its place
        let mut amounts = split(ONE_PSP);
        let last = amounts.len() - 1;
        amounts[last] = 3;
        let (request, _) = build_exact(&[(note, &keypair, 1)], &amounts, None);
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::BadDenomination { index: last }
        );
        assert_eq!(s.psp.melts.get(), 0);
        assert!(!s.psp.logic.is_spent(note.nonce).unwrap());
        assert!(s.responses.is_empty());
        assert_eq!(s.esp_issued(), 0);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_total_split_into_powers_of_two_is_exchanged() {
        let mut s = setup("split");
        let (note, keypair) = s.psp.note(1);
        let amounts = split(ONE_PSP);
        assert!(amounts.iter().all(|a| a.is_power_of_two()));
        assert_eq!(amounts.iter().sum::<u64>(), ONE_PSP);
        let (request, _) = build_exact(&[(note, &keypair, 1)], &amounts, None);
        let response = s.run(&request).unwrap();
        assert_eq!(response.signatures.len(), amounts.len());
        assert_eq!(s.esp_issued(), ONE_PSP);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn amounts_at_the_u64_limit_do_not_overflow() {
        let mut s = setup("limits");
        let (note, keypair) = s.psp.note(1);
        // two outputs of 2^63 total more than a u64, and far more than 1 PSP
        let top = 1u64 << 63;
        let (request, _) = build_exact(&[(note, &keypair, 1)], &[top, top], None);
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::NotExact {
                paid: u128::from(ONE_PSP),
                requested: 2 * u128::from(top)
            }
        );
        // the largest note and the largest sum of notes still compute
        assert!(
            check_exact_min(
                units::psp_to_esp(u64::MAX),
                units::psp_to_esp(u64::MAX),
                min_exchange()
            )
            .is_ok()
        );
        let many = units::total(std::iter::repeat_n(u64::MAX, MAX_ITEMS));
        assert_eq!(many, u128::from(u64::MAX) * MAX_ITEMS as u128);
        assert!(check_exact_min(many, many, min_exchange()).is_ok());
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_large_note_is_exchanged_in_full() {
        let mut s = setup("large");
        let (note, keypair) = s.psp.note(1024);
        let (request, _) = build(&[(note, &keypair, 1024)], &[1024 * ONE_PSP], None);
        s.run(&request).unwrap();
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

    /// One US dollar of PSP is 10 PSP, and that is 10^12 ESP. With the default
    /// settings (a smallest exchange of 1 PSP, $0.10) 10 PSP exchange for
    /// exactly 10^12 ESP, one ESP unit more or less is not exact, and an output
    /// total under 1 PSP is below the minimum.
    #[test]
    fn ten_psp_a_dollar_exchange_for_exactly_ten_to_the_twelfth_esp() {
        const ONE_USD_ESP: u64 = 1_000_000_000_000;
        assert_eq!(ExchangeSettings::default().min_psp, 1);
        let mut s = setup("dollar");
        // 10 PSP for one ESP unit more is not exact, and nothing is burned
        let (n8, k8) = s.psp.note(8);
        let (n2, k2) = s.psp.note(2);
        let (request, _) = build(&[(n8, &k8, 8), (n2, &k2, 2)], &[ONE_USD_ESP + 1], None);
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::NotExact {
                paid: u128::from(ONE_USD_ESP),
                requested: u128::from(ONE_USD_ESP) + 1
            }
        );
        assert_eq!(s.psp.melts.get(), 0);
        assert_eq!(s.esp_issued(), 0);
        // and one unit less
        let (request, _) = build(&[(n8, &k8, 8), (n2, &k2, 2)], &[ONE_USD_ESP - 1], None);
        assert!(matches!(
            rejection(s.run(&request)),
            Rejection::NotExact { .. }
        ));
        // 10 PSP ($1) is exactly 10^12 ESP
        let (request, _) = build(&[(n8, &k8, 8), (n2, &k2, 2)], &[ONE_USD_ESP], None);
        s.run(&request).unwrap();
        assert_eq!(s.esp_issued(), ONE_USD_ESP);
        // less than 1 PSP ($0.10) is below the default minimum
        let (n1, k1) = s.psp.note(1);
        let (request, _) = build(&[(n1, &k1, 1)], &[ONE_PSP - 1], None);
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::BelowMinimum {
                requested: u128::from(ONE_PSP) - 1,
                minimum: u128::from(ONE_PSP)
            }
        );
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_finished_exchange_is_counted_once_in_the_ledger_under_its_day() {
        use crate::ledger::Day;
        let mut s = setup("ledger");
        let (note, keypair) = s.psp.note(4);
        let (request, _) = build(&[(note, &keypair, 4)], &[2 * ONE_PSP, 2 * ONE_PSP], None);
        let day = NOW / 86_400 + 365;
        assert_eq!(s.responses.ledger().day(day), Day::default());
        s.run(&request).unwrap();
        let counted = Day {
            issued: u128::from(4 * ONE_PSP),
            redeemed: 0,
        };
        assert_eq!(s.responses.ledger().day(day), counted);
        // the split at the time of issue, and a year on
        let ledger = s.responses.ledger();
        assert_eq!(ledger.split(NOW).unmatured, u128::from(4 * ONE_PSP));
        assert_eq!(ledger.split(NOW).matured, 0);
        assert_eq!(ledger.split(day * 86_400).matured, u128::from(4 * ONE_PSP));
        // a retry, and a retry after a restart, count nothing more
        s.run(&request).unwrap();
        s.responses = Responses::open(&s.dir.join("esp").join("responses.json")).unwrap();
        s.run(&request).unwrap();
        assert_eq!(s.responses.ledger().day(day), counted);
        assert_eq!(s.psp.melts.get(), 1);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn an_exchange_that_stopped_before_the_burn_counts_nothing_until_it_is_finished() {
        use crate::ledger::Day;
        let mut s = setup("ledger-recover");
        let (note, keypair) = s.psp.note(1);
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP], None);
        let day = NOW / 86_400 + 365;
        s.psp.fail_before_burn.set(true);
        assert!(matches!(s.run(&request), Err(ExchangeError::Psp(_))));
        s.psp.fail_before_burn.set(false);
        // pending on file, nothing counted, and a restart keeps it so
        s.responses = Responses::open(&s.dir.join("esp").join("responses.json")).unwrap();
        assert_eq!(s.responses.unfinished(), 1);
        assert_eq!(s.responses.ledger().day(day), Day::default());

        s.run(&request).unwrap();
        let counted = Day {
            issued: u128::from(ONE_PSP),
            redeemed: 0,
        };
        assert_eq!(s.responses.unfinished(), 0);
        assert_eq!(s.responses.ledger().day(day), counted);
        s.run(&request).unwrap();
        assert_eq!(s.responses.ledger().day(day), counted);
        fs::remove_dir_all(&s.dir).unwrap();
    }

    #[test]
    fn a_refused_exchange_counts_nothing() {
        let mut s = setup("ledger-refused");
        let (note, keypair) = s.psp.note(1);
        // one unit under the smallest exchange
        let (request, _) = build(&[(note, &keypair, 1)], &[ONE_PSP - 1], None);
        assert_eq!(
            rejection(s.run(&request)),
            Rejection::BelowMinimum {
                requested: u128::from(ONE_PSP) - 1,
                minimum: u128::from(ONE_PSP),
            }
        );
        assert_eq!(s.responses.ledger().days().count(), 0);
        fs::remove_dir_all(&s.dir).unwrap();
    }
}
