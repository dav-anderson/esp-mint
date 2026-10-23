//! Key rotation for ESP: at most two generations, current and previous, each
//! with its own master secret (the per-service, per-day keys are derived inside
//! it) and its own spent list (a mint-core store).
//!
//! Generation 0 is the mint as it was: `master_secret.hex` and `db/` at the top
//! of the network's data folder. Generation N is `gen-N/`. Rotation starts
//! `rotation.activation_hours` after the first issuance, recorded once in
//! `first_issue.json`, then one every `rotation.period_hours`. At each
//! rotation the oldest generation is deleted with its spent list; its totals
//! are kept in `retired.json` for `/audit`. mint-core is unchanged: each
//! generation is its own `MintLogic`.

use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use mint_core::MintLogic;
use mint_types::{MintInput, Nonce};
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};

use crate::keys::MasterSecret;
use crate::mint::{DB_DIRNAME, MASTER_SECRET_FILENAME};
use crate::terms::Terms;

// The rollover and rotation wire types, and the keyset hashing, live in
// sp-wire; they are re-exported so the paths are unchanged. `keyset_id` below
// stays here: it derives the ID from the master secret, which is the mint's.
pub use sp_wire::esp::hash_keysets;
pub use sp_wire::esp::rollover::{MAX_ROLLOVER_NOTES, RolloverRequest, RolloverResponse};
pub use sp_wire::keyset::{KeysetWindow, RotationResponse};

pub const FIRST_ISSUE_FILE: &str = "first_issue.json";
/// The most retired keyset IDs kept: 1 MB of 8-byte IDs (131,072). A
/// request naming a listed ID gets `keyset_retired` (its notes expired); any
/// other unknown ID gets `unknown_keyset`, so a wallet can tell expired notes
/// from junk and explain a loss. When the list is full the oldest ID is dropped
/// to make room, which only turns a very old `keyset_retired` into
/// `unknown_keyset`. 131,072 covers hourly rotation for about 15 years; a mint
/// rotating yearly never comes close. It is a constant, the same in every
/// mint, and deliberately not a setting: it is too cheap to be worth tuning.
pub const RETIRED_KEYSETS_CAP: usize = 131_072;
pub const RETIRED_FILE: &str = "retired.json";
/// The stored responses, in the same data directory (read at a retirement for
/// the notes unfinished requests hold).
pub const RESPONSES_FILE: &str = "responses.json";

/// The rotation rule, in seconds (the same as fsp-mint and psp-mint).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rotation {
    pub first_issue: Option<u64>,
    pub activation_secs: u64,
    pub period_secs: u64,
}

impl Rotation {
    pub fn activation(&self) -> Option<u64> {
        let first = self.first_issue?;
        (self.activation_secs > 0).then(|| first.saturating_add(self.activation_secs))
    }
    pub fn start_of(&self, epoch: u64) -> Option<u64> {
        let t0 = self.activation()?;
        (epoch >= 1).then(|| t0.saturating_add((epoch - 1).saturating_mul(self.period_secs.max(1))))
    }
    pub fn epoch_at(&self, now: u64) -> u64 {
        match self.activation() {
            Some(t0) if now >= t0 => 1 + (now - t0) / self.period_secs.max(1),
            _ => 0,
        }
    }
}

/// One generation's identity: its epoch, its master secret and its ID.
#[derive(Clone, Debug)]
pub struct Generation {
    pub epoch: u64,
    pub id: String,
    pub master: MasterSecret,
}

/// The keyset ID: 8 bytes of SHA-256 over a tag and a hash of the master
/// secret, so it names the generation and reveals nothing of the secret.
pub fn keyset_id(master: &MasterSecret) -> String {
    use sha2::{Digest, Sha256};
    let inner = Sha256::digest(master.to_hex().as_bytes());
    let mut h = Sha256::new();
    h.update(b"esp-mint/keyset-id/v1");
    h.update(inner);
    hex::encode(&h.finalize()[..8])
}

fn gen_dir(base: &Path, epoch: u64) -> PathBuf {
    if epoch == 0 {
        base.to_path_buf()
    } else {
        base.join(format!("gen-{epoch}"))
    }
}

fn exists(base: &Path, epoch: u64) -> bool {
    gen_dir(base, epoch).join(MASTER_SECRET_FILENAME).exists()
}

pub fn open_gen(base: &Path, epoch: u64) -> Result<(Generation, MintLogic), Box<dyn Error>> {
    let (logic, master) = crate::mint::open(&gen_dir(base, epoch))?;
    Ok((
        Generation {
            epoch,
            id: keyset_id(&master),
            master,
        },
        logic,
    ))
}

/// Delete a retired generation, crash-safely: its spent list and then its
/// master secret (the secret last, so a half-moved generation still opens and
/// is retired again) are renamed into `retiring-gen-N/`, which is then
/// removed. A crash part way leaves that folder, and `sweep_retiring` removes
/// it at the next start.
fn delete_gen(base: &Path, epoch: u64) -> Result<(), Box<dyn Error>> {
    let dir = gen_dir(base, epoch);
    let trash = base.join(format!("{RETIRING_PREFIX}{epoch}"));
    fs::create_dir_all(&trash)?;
    for name in [DB_DIRNAME, MASTER_SECRET_FILENAME] {
        let from = dir.join(name);
        if from.exists() {
            fs::rename(&from, trash.join(name))?;
        }
    }
    fs::File::open(base)?.sync_all()?;
    if epoch > 0 {
        let _ = fs::remove_dir_all(&dir);
    }
    fs::remove_dir_all(&trash)?;
    Ok(())
}

const RETIRING_PREFIX: &str = "retiring-gen-";

/// Finish deleting generations a crash left half deleted.
fn sweep_retiring(base: &Path) -> Result<(), Box<dyn Error>> {
    if let Ok(rd) = fs::read_dir(base) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with(RETIRING_PREFIX) {
                fs::remove_dir_all(e.path())?;
            }
        }
    }
    Ok(())
}

fn save_json<T: Serialize>(path: &Path, v: &T) -> Result<(), Box<dyn Error>> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(&serde_json::to_vec_pretty(v)?)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    if let Some(d) = path.parent() {
        fs::File::open(d)?.sync_all()?;
    }
    Ok(())
}

fn load_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<Option<T>, Box<dyn Error>> {
    match fs::read(path) {
        Ok(b) => {
            Ok(Some(serde_json::from_slice(&b).map_err(|e| {
                format!("{} is damaged: {e}", path.display())
            })?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Retired {
    epochs: Vec<u64>,
    /// The keyset IDs of the deleted generations, oldest first, so a request
    /// naming one is told `keyset_retired` rather than `unknown_keyset`.
    /// Written, and synced, before the generation is deleted.
    #[serde(default)]
    ids: Vec<String>,
    /// Burn proofs taken from a spent list just before it is deleted: the
    /// nonces (hex) that an unfinished request held and that were spent in
    /// the retiring set. Only the request holding a note can burn it, so each
    /// was burned by its holder. Written in the same save as the retired ID,
    /// before anything is deleted, so no crash can lose the proof with the
    /// list. Trimmed at each retirement to notes still held.
    #[serde(default)]
    burn_proofs: std::collections::BTreeSet<String>,
    issued: u64,
    redeemed: u64,
}

#[derive(Serialize, Deserialize)]
struct FirstIssue {
    first_issue: u64,
}

pub fn load_first_issue(base: &Path) -> Result<Option<u64>, Box<dyn Error>> {
    Ok(load_json::<FirstIssue>(&base.join(FIRST_ISSUE_FILE))?.map(|f| f.first_issue))
}

/// The two live generations, both with their databases open.
pub struct Gens<'a> {
    pub current: (&'a MintLogic, &'a MasterSecret),
    pub previous: Option<(&'a MintLogic, &'a MasterSecret)>,
    pub current_id: String,
    pub previous_id: Option<String>,
    /// The retired keyset IDs, oldest first (see [`RETIRED_KEYSETS_CAP`]).
    pub retired: &'a [String],
    /// Notes (nonce hex) proven burned when their keyset was deleted.
    pub burn_proofs: Option<&'a std::collections::BTreeSet<String>>,
}

impl<'a> Gens<'a> {
    /// Whether `input` was proven burned (by the request holding it) when its
    /// keyset was deleted: read from the deleted set's spent list just before
    /// the deletion, see `Retired::burn_proofs`.
    pub fn burn_proven(&self, input: &MintInput) -> bool {
        self.burn_proofs
            .is_some_and(|p| p.contains(&hex::encode(input.note.nonce.0.serialize())))
    }

    /// Which live generation `id` names; `keyset_retired` for a deleted one on
    /// the retired list, `unknown_keyset` for anything else.
    pub fn resolve(&self, id: &str) -> Result<Side, KeysetError> {
        if id == self.current_id {
            Ok(Side::Current)
        } else if self.previous.is_some() && self.previous_id.as_deref() == Some(id) {
            Ok(Side::Previous)
        } else if self.retired.iter().any(|r| r == id) {
            Err(KeysetError::Retired(id.to_string()))
        } else {
            Err(KeysetError::Unknown(id.to_string()))
        }
    }

    /// The live generation `id` names, with its ID.
    pub fn named(
        &self,
        id: &str,
    ) -> Result<(&'a MintLogic, &'a MasterSecret, String), KeysetError> {
        Ok(match self.resolve(id)? {
            Side::Current => (self.current.0, self.current.1, self.current_id.clone()),
            Side::Previous => {
                let (l, m) = self.previous.expect("resolved");
                (l, m, id.to_string())
            }
        })
    }

    /// The generation and key to check `input` with, by the keyset it names.
    pub fn input_key(
        &self,
        id: &str,
        input: &MintInput,
        terms: &Terms,
    ) -> Result<(&'a MintLogic, SecretKey), KeysetError> {
        let (l, m, _) = self.named(id)?;
        Ok((l, m.key_for(input.amount, terms)))
    }

    /// The generation to sign outputs with: the live one the request names,
    /// current or previous. A set that is not live is refused: a deleted one
    /// `keyset_retired`, anything else `unknown_keyset`. The exception is a
    /// request accepted earlier and finished now (`resumed`), and a queued
    /// decline or refund signed later: the burn is already done, so if the set
    /// it named has since been deleted it is signed by the current set
    /// (blinding does not depend on the key). The ID returned is the one that
    /// signs, and goes in the reply.
    pub fn signer(
        &self,
        id: &str,
        resumed: bool,
    ) -> Result<(&'a MintLogic, &'a MasterSecret, String), KeysetError> {
        match self.named(id) {
            Ok(found) => Ok(found),
            Err(_) if resumed => Ok((self.current.0, self.current.1, self.current_id.clone())),
            Err(e) => Err(e),
        }
    }

    /// Spent in either live generation.
    pub fn is_spent(&self, nonce: Nonce) -> Result<bool, String> {
        Ok(self.current.0.is_spent(nonce).map_err(|e| e.to_string())?
            || match self.previous {
                Some((p, _)) => p.is_spent(nonce).map_err(|e| e.to_string())?,
                None => false,
            })
    }
}

/// A live generation, as a keyset ID names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Current,
    Previous,
}

/// Why a keyset ID names no live generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeysetError {
    /// Deleted at a rotation: its notes expired.
    Retired(String),
    /// Never a keyset of this mint (or trimmed from the retired list).
    Unknown(String),
}

impl KeysetError {
    /// A message for `what` (such as "note 3", or "the outputs").
    pub fn why(&self, what: &str) -> String {
        match self {
            KeysetError::Retired(id) => format!(
                "{what}: keyset {id} was retired at a rotation and deleted; its notes expired. Nothing was burned"
            ),
            KeysetError::Unknown(id) => {
                format!("{what}: keyset {id} is not a keyset of this mint. Nothing was burned")
            }
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            KeysetError::Retired(_) => sp_wire::codes::KEYSET_RETIRED,
            KeysetError::Unknown(_) => sp_wire::codes::UNKNOWN_KEYSET,
        }
    }
}

/// The rotation state. The current `MintLogic` stays in `EspState::logic`;
/// this holds the current master secret, the previous generation and the
/// schedule.
pub struct Rotor {
    pub base: PathBuf,
    pub activation_hours: u64,
    pub period_hours: u64,
    pub first_issue: Option<u64>,
    pub current: Generation,
    pub previous: Option<(Generation, MintLogic)>,
    retired: Retired,
    /// The cap on retired keyset IDs: [`RETIRED_KEYSETS_CAP`] (smaller only
    /// in tests).
    retired_keep: usize,
    /// A fixed clock for tests; 0 is the system clock.
    pub clock: std::sync::Arc<AtomicU64>,
}

impl Rotor {
    pub fn open(
        base: &Path,
        activation_hours: u64,
        period_hours: u64,
    ) -> Result<(Rotor, MintLogic), Box<dyn Error>> {
        Self::open_at(base, activation_hours, period_hours, 0)
    }

    pub fn open_at(
        base: &Path,
        activation_hours: u64,
        period_hours: u64,
        clock: u64,
    ) -> Result<(Rotor, MintLogic), Box<dyn Error>> {
        fs::create_dir_all(base)?;
        sweep_retiring(base)?;
        let mut newest = 0;
        if let Ok(rd) = fs::read_dir(base) {
            for e in rd.flatten() {
                if let Some(n) = e
                    .file_name()
                    .to_str()
                    .and_then(|n| n.strip_prefix("gen-"))
                    .and_then(|n| n.parse::<u64>().ok())
                    && exists(base, n)
                {
                    newest = newest.max(n);
                }
            }
        }
        let (current, mut logic) = open_gen(base, newest)?;
        let mut r = Rotor {
            base: base.to_path_buf(),
            activation_hours,
            period_hours,
            first_issue: load_first_issue(base)?,
            current,
            previous: None,
            retired: load_json(&base.join(RETIRED_FILE))?.unwrap_or_default(),
            retired_keep: RETIRED_KEYSETS_CAP,
            clock: std::sync::Arc::new(AtomicU64::new(clock)),
        };
        if newest > 0 && exists(base, newest - 1) {
            r.previous = Some(open_gen(base, newest - 1)?);
        }
        for old in 0..newest.saturating_sub(1) {
            if exists(base, old) {
                let (g, l) = open_gen(base, old)?;
                r.retire(g, l)?;
            }
        }
        r.refresh(&mut logic)?;
        Ok((r, logic))
    }

    pub fn now(&self) -> u64 {
        match self.clock.load(Ordering::SeqCst) {
            0 => crate::server::now_secs(),
            t => t,
        }
    }

    pub fn rotation(&self) -> Rotation {
        Rotation {
            first_issue: self.first_issue,
            activation_secs: self.activation_hours.saturating_mul(3600),
            period_secs: self.period_hours.saturating_mul(3600),
        }
    }

    /// The ESP notes (nonce hex) unfinished requests hold, read from their
    /// stores on disk (every pending entry is written before its burn):
    /// transfers and redemptions in `responses.json`, rollovers in
    /// `rollovers.json`.
    fn held_on_disk(&self) -> Result<std::collections::HashSet<String>, Box<dyn Error>> {
        let mut held = std::collections::HashSet::new();
        let responses = crate::responses::Responses::open(&self.base.join(RESPONSES_FILE))
            .map_err(|e| e.to_string())?;
        held.extend(responses.redeem_holds("").0);
        for (_, p) in responses.pending_transfers() {
            held.extend(p.inputs.iter().cloned());
        }
        held.extend(Rollovers::open(&self.base)?.held_nonces(""));
        Ok(held)
    }

    fn retire(&mut self, g: Generation, logic: MintLogic) -> Result<(), Box<dyn Error>> {
        if !self.retired.epochs.contains(&g.epoch) {
            // Burn proofs from this set's spent list, the last moment it exists.
            let held = self.held_on_disk()?;
            self.retired.burn_proofs.retain(|n| held.contains(n));
            for n in &held {
                let Ok(bytes) = hex::decode(n) else { continue };
                let Ok(pk) = secp256k1::PublicKey::from_slice(&bytes) else {
                    continue;
                };
                if logic.is_spent(Nonce(pk)).map_err(|e| e.to_string())? {
                    self.retired.burn_proofs.insert(n.clone());
                }
            }
            let (i, d) = logic.audit_totals().map_err(|e| e.to_string())?;
            self.retired.epochs.push(g.epoch);
            self.retired.ids.push(g.id.clone());
            self.trim_retired();
            self.retired.issued = self.retired.issued.saturating_add(i.units);
            self.retired.redeemed = self.retired.redeemed.saturating_add(d.units);
            save_json(&self.base.join(RETIRED_FILE), &self.retired)?;
        }
        drop(logic);
        delete_gen(&self.base, g.epoch)
    }

    /// Record the first issuance once it has happened, and rotate as far as
    /// the clock says. The caller holds the mint lock on `current`.
    pub fn refresh(&mut self, current: &mut MintLogic) -> Result<(), Box<dyn Error>> {
        let now = self.now();
        if self.first_issue.is_none() {
            let issued = current.audit_totals().map_err(|e| e.to_string())?.0;
            if issued.units > 0 || self.current.epoch > 0 {
                save_json(
                    &self.base.join(FIRST_ISSUE_FILE),
                    &FirstIssue { first_issue: now },
                )?;
                self.first_issue = Some(now);
            }
        }
        let target = self.rotation().epoch_at(now);
        while self.current.epoch < target {
            let next = if target - self.current.epoch > 2 {
                target - 1
            } else {
                self.current.epoch + 1
            };
            let (g, logic) = open_gen(&self.base, next)?;
            let old_logic = std::mem::replace(current, logic);
            let old = std::mem::replace(&mut self.current, g);
            if let Some((pg, pl)) = self.previous.take() {
                self.retire(pg, pl)?;
            }
            println!(
                "key rotation: keyset {} (epoch {}) is now current; {} (epoch {}) is previous",
                self.current.id, self.current.epoch, old.id, old.epoch
            );
            self.previous = Some((old, old_logic));
        }
        Ok(())
    }

    /// Both live generations, for a request. `current` is the locked mint.
    pub fn gens<'a>(&'a self, current: &'a MintLogic) -> Gens<'a> {
        Gens {
            current: (current, &self.current.master),
            previous: self.previous.as_ref().map(|(g, l)| (l, &g.master)),
            current_id: self.current.id.clone(),
            previous_id: self.previous.as_ref().map(|(g, _)| g.id.clone()),
            retired: &self.retired.ids,
            burn_proofs: Some(&self.retired.burn_proofs),
        }
    }

    /// Test hook: a smaller cap than [`RETIRED_KEYSETS_CAP`], applied now and
    /// saved. Production always uses the constant.
    #[doc(hidden)]
    pub fn set_retired_keep(&mut self, keep: usize) -> Result<(), Box<dyn Error>> {
        self.retired_keep = keep;
        let before = self.retired.ids.len();
        self.trim_retired();
        if self.retired.ids.len() != before {
            save_json(&self.base.join(RETIRED_FILE), &self.retired)?;
        }
        Ok(())
    }

    fn trim_retired(&mut self) {
        let n = self.retired.ids.len();
        if n > self.retired_keep {
            self.retired.ids.drain(..n - self.retired_keep);
        }
    }

    /// Which live generation a keyset ID names: `keyset_retired` for a deleted
    /// one still on the list, `unknown_keyset` for anything else.
    pub fn resolve(&self, id: &str) -> Result<Side, KeysetError> {
        if id == self.current.id {
            Ok(Side::Current)
        } else if self.previous.as_ref().is_some_and(|(g, _)| g.id == id) {
            Ok(Side::Previous)
        } else if self.retired.ids.iter().any(|r| r == id) {
            Err(KeysetError::Retired(id.to_string()))
        } else {
            Err(KeysetError::Unknown(id.to_string()))
        }
    }

    pub fn retired_totals(&self) -> (u64, u64) {
        (self.retired.issued, self.retired.redeemed)
    }

    pub fn window(&self) -> RotationResponse {
        let r = self.rotation();
        let now = self.now();
        let win = |epoch: u64, id: &str| KeysetWindow {
            id: id.to_string(),
            epoch,
            starts: r.start_of(epoch),
            current_until: r.activation().map(|_| r.start_of(epoch + 1).unwrap_or(0)),
            retires: r.activation().map(|_| r.start_of(epoch + 2).unwrap_or(0)),
        };
        let current = win(self.current.epoch, &self.current.id);
        RotationResponse {
            active: r.activation().is_some_and(|t| now >= t),
            first_issue: self.first_issue,
            rotation_activation_hours: self.activation_hours,
            activation: r.activation(),
            rotation_period_hours: self.period_hours,
            next_rotation: current.current_until,
            previous: self.previous.as_ref().map(|(g, _)| win(g.epoch, &g.id)),
            current,
            now,
        }
    }

    pub fn describe(&self) -> Vec<String> {
        let w = self.window();
        let t = |o: Option<u64>| o.map(|v| v.to_string()).unwrap_or_else(|| "not yet".into());
        let mut out = vec![
            format!(
                "rotation: activation {} h after the first issue, period {} h{}",
                w.rotation_activation_hours,
                w.rotation_period_hours,
                if w.rotation_activation_hours == 0 {
                    " (off)"
                } else {
                    ""
                }
            ),
            format!(
                "  first issue: {}; activation: {}; next rotation: {} (Unix seconds)",
                t(w.first_issue),
                t(w.activation),
                t(w.next_rotation)
            ),
            format!(
                "  current keyset {} (epoch {})",
                w.current.id, w.current.epoch
            ),
        ];
        if let Some(p) = &w.previous {
            out.push(format!(
                "  previous keyset {} (epoch {}), retires at {}",
                p.id,
                p.epoch,
                t(p.retires)
            ));
        }
        out
    }
}

/// The schedule for `config`, from the files only (no database is opened).
pub fn describe_offline(base: &Path, activation_hours: u64, period_hours: u64) -> Vec<String> {
    let first = load_first_issue(base).ok().flatten();
    let r = Rotation {
        first_issue: first,
        activation_secs: activation_hours.saturating_mul(3600),
        period_secs: period_hours.saturating_mul(3600),
    };
    let e = r.epoch_at(crate::server::now_secs());
    let id = |epoch: u64| {
        fs::read_to_string(gen_dir(base, epoch).join(MASTER_SECRET_FILENAME))
            .ok()
            .and_then(|t| MasterSecret::from_hex(t.trim()))
            .map(|m| keyset_id(&m))
            .unwrap_or_else(|| "(made at the next start)".into())
    };
    let t = |o: Option<u64>| o.map(|v| v.to_string()).unwrap_or_else(|| "not yet".into());
    let mut out = vec![
        format!(
            "rotation: activation {activation_hours} h after the first issue, period {period_hours} h{}",
            if activation_hours == 0 { " (off)" } else { "" }
        ),
        format!(
            "  first issue: {}; activation: {}; next rotation: {} (Unix seconds)",
            t(first),
            t(r.activation()),
            t(r.activation().map(|_| r.start_of(e + 1).unwrap_or(0)))
        ),
        format!("  current keyset {} (epoch {e})", id(e)),
    ];
    if e > 0 {
        out.push(format!(
            "  previous keyset {} (epoch {}), retires at {}",
            id(e - 1),
            e - 1,
            t(r.start_of(e + 1))
        ));
    }
    out
}

// ---- the rollover swap ------------------------------------------------------

#[cfg(test)]
use mint_types::MintOutput;
use mint_types::MintOutputError;
use secp256k1::SECP256K1;
use std::collections::BTreeMap;

pub const ROLLOVERS_FILE: &str = "rollovers.json";

#[derive(Default, Serialize, Deserialize)]
pub struct Rollovers {
    answers: BTreeMap<String, RolloverResponse>,
    pending: BTreeMap<String, u64>,
    /// Pending rollovers (by request hash) whose inputs have all been burned
    /// under that hash, written after the burn and before any signing. Only
    /// this proves the burn once the inputs' keyset has been deleted with its
    /// spent list.
    #[serde(default)]
    burned: std::collections::BTreeSet<String>,
    /// The input nonces (hex) each pending rollover holds, written with the
    /// pending entry before anything is burned. No other request (rollover,
    /// transfer, redemption) may take them meanwhile.
    #[serde(default)]
    holds: BTreeMap<String, Vec<String>>,
    #[serde(skip)]
    path: PathBuf,
}

impl Rollovers {
    pub fn open(base: &Path) -> Result<Rollovers, Box<dyn Error>> {
        let path = base.join(ROLLOVERS_FILE);
        let mut r: Rollovers = load_json(&path)?.unwrap_or_default();
        r.path = path;
        Ok(r)
    }
    fn save(&self) -> Result<(), String> {
        save_json(&self.path, self).map_err(|e| e.to_string())
    }

    /// Record the rollover `id` as started under `epoch`, holding the notes
    /// (nonce hex) it is about to burn, and write the file. Done before anything
    /// is burned, so that no other request takes the notes meanwhile and a retry
    /// after a crash knows the rollover was begun.
    pub fn begin(&mut self, id: &str, epoch: u64, nonces: Vec<String>) -> Result<(), String> {
        self.pending.insert(id.to_string(), epoch);
        self.holds.insert(id.to_string(), nonces);
        self.save()
    }

    /// Record that every input of the pending rollover `id` has been burned
    /// under it, and write the file. Done after the burn and before any
    /// signing: it is what proves the burn once the inputs' keyset is deleted.
    pub fn mark_burned(&mut self, id: &str) -> Result<(), String> {
        self.burned.insert(id.to_string());
        self.save()
    }

    /// The notes (nonce hex) pending rollovers other than `except` hold.
    pub fn held_nonces(&self, except: &str) -> std::collections::HashSet<String> {
        self.holds
            .iter()
            .filter(|(h, _)| h.as_str() != except)
            .flat_map(|(_, n)| n.iter().cloned())
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RolloverError {
    Refused(String),
    /// `missing_keyset`, `keyset_retired` or `unknown_keyset`, with why.
    Keyset(&'static str, String),
    /// These inputs are already spent: every one of them, in order. The body
    /// says which, so the wallet can stop offering those notes
    /// (`code: note_spent_elsewhere`, `spent: [indexes]`).
    Spent(Vec<usize>),
    Internal(String),
}

/// Run a rollover. The caller holds the mint lock, the rotor and the store.
/// A note held by an unfinished transfer or redemption is refused.
pub fn rollover(
    gens: &Gens,
    rotor: &Rotor,
    store: &mut Rollovers,
    held: &std::collections::HashSet<String>,
    req: &RolloverRequest,
    max_notes: usize,
) -> Result<RolloverResponse, RolloverError> {
    use RolloverError::*;
    if req.inputs.is_empty() || req.inputs.len() > max_notes {
        return Err(Refused(format!("a rollover takes 1 to {max_notes} notes")));
    }
    let mut a: Vec<u64> = req.inputs.iter().map(|i| i.amount.units).collect();
    let mut b: Vec<u64> = req.outputs.iter().map(|o| o.amount.units).collect();
    a.sort_unstable();
    b.sort_unstable();
    if a != b {
        return Err(Refused("the outputs must have exactly the amounts of the inputs: a rollover only moves notes to the current keyset, under the same terms".into()));
    }
    if req.input_keysets.len() != req.inputs.len() || req.keyset.is_empty() {
        return Err(Keyset(
            sp_wire::codes::MISSING_KEYSET,
            "every input needs its keyset (input_keysets) and the outputs need one (keyset)".into(),
        ));
    }
    // Stored answers whose keyset retired are dropped: their notes can no
    // longer be spent, so no retry can use them.
    let before = store.answers.len();
    store.answers.retain(|_, a| gens.resolve(&a.keyset).is_ok());
    if store.answers.len() != before {
        store.save().map_err(Internal)?;
    }
    let id = req.hash();
    if let Some(done) = store.answers.get(&id) {
        return Ok(done.clone());
    }
    // A rollover resumed after a rotation finishes: inputs of a keyset that
    // retired meanwhile were burned before, and its outputs are signed with
    // the current set if theirs retired (the reply names the keyset).
    let resumed = store.pending.get(&id).copied();
    // Notes other pending rollovers hold.
    let others = store.held_nonces(&id);
    let proven = resumed.is_some() && store.burned.contains(&id);
    let terms = Terms {
        service: req.service,
        redeemable_after_day: req.redeemable_after_day,
    };
    let digest = req.digest();
    let mut seen = std::collections::HashSet::new();
    let mut plan = Vec::new();
    for (i, input) in req.inputs.iter().enumerate() {
        let (logic, sk) = match gens.input_key(&req.input_keysets[i], input, &terms) {
            Ok(k) => k,
            // Its keyset was deleted since the request was accepted: finished
            // without burning only if the stored state proves the burn.
            Err(_) if proven || gens.burn_proven(input) => continue,
            Err(e) if resumed.is_some() => return Err(burn_not_proven(i, &e)),
            Err(e) => return Err(Keyset(e.code(), e.why(&format!("input {i}")))),
        };
        logic.verify_note_with_key(&sk, input).map_err(|_| {
            Refused(format!(
                "input {i} is not a note of the current or previous keyset for these terms"
            ))
        })?;
        logic
            .verify_spend_authorization(input, digest)
            .map_err(|_| Refused(format!("input {i}: bad spend signature")))?;
        if !seen.insert(input.note.nonce) {
            return Err(Refused(format!("input {i} is in the request twice")));
        }
        let nonce_hex = hex::encode(input.note.nonce.0.serialize());
        if held.contains(&nonce_hex) || others.contains(&nonce_hex) {
            return Err(Refused(format!(
                "input {i} is held by an unfinished request"
            )));
        }
        let spent = logic
            .is_spent(input.note.nonce)
            .map_err(|e| Internal(e.to_string()))?;
        if spent && resumed.is_none() {
            // The first problem in order is this note. Say every spent note, not
            // only this one: the inputs after it are looked at for that alone (a
            // key that cannot be found or a note that is no good there is not
            // this answer's business), so the wallet drops them all in one go.
            let mut all = vec![i];
            for (j, later) in req.inputs.iter().enumerate().skip(i + 1) {
                let Ok((l, _)) = gens.input_key(&req.input_keysets[j], later, &terms) else {
                    continue;
                };
                if l.is_spent(later.note.nonce)
                    .map_err(|e| Internal(e.to_string()))?
                {
                    all.push(j);
                }
            }
            return Err(Spent(all));
        }
        plan.push((logic, sk, input, spent));
    }
    let (out_logic, master, out_id) = gens
        .signer(&req.keyset, resumed.is_some())
        .map_err(|e| Keyset(e.code(), e.why("the outputs")))?;
    if resumed.is_none() {
        for o in &req.outputs {
            if out_logic
                .is_blind_nonce_used(&o.blind_nonce)
                .map_err(|e| Internal(e.to_string()))?
            {
                return Err(Refused("an output's blind nonce was used before".into()));
            }
        }
        store
            .begin(
                &id,
                rotor.current.epoch,
                req.inputs
                    .iter()
                    .map(|i| hex::encode(i.note.nonce.0.serialize()))
                    .collect(),
            )
            .map_err(Internal)?;
    }
    for (logic, sk, input, spent) in plan {
        if !spent {
            logic
                .redeem_with_key(&sk, input, digest)
                .map_err(|e| Internal(e.to_string()))?;
        }
    }
    if !proven {
        store.mark_burned(&id).map_err(Internal)?;
    }
    let mut signatures = Vec::new();
    let mut keys = Vec::new();
    for o in &req.outputs {
        let sk = master.key_for(o.amount, &terms);
        let sig = match out_logic.issue_with_key(&sk, o) {
            Ok(out) => out.0,
            Err(MintOutputError::BlindNonceAlreadyUsed) if resumed.is_some() => {
                bdhke::sign_message(&sk, &o.blind_nonce.0)
            }
            Err(e) => return Err(Internal(e.to_string())),
        };
        signatures.push(sig);
        keys.push(sk.public_key(SECP256K1));
    }
    // The epoch of the set that signed: the wallet records it with the notes.
    let out_epoch = match &rotor.previous {
        Some((g, _)) if g.id == out_id => g.epoch,
        _ => rotor.current.epoch,
    };
    let answer = RolloverResponse {
        keyset: out_id,
        epoch: out_epoch,
        service: req.service,
        redeemable_after_day: req.redeemable_after_day,
        signatures,
        keys,
    };
    store.answers.insert(id.clone(), answer.clone());
    store.pending.remove(&id);
    store.burned.remove(&id);
    store.holds.remove(&id);
    store.save().map_err(Internal)?;
    Ok(answer)
}

/// A request resumed after its input's keyset was deleted, with no stored
/// proof that this request burned its inputs: refused, nothing signed.
fn burn_not_proven(i: usize, e: &KeysetError) -> RolloverError {
    RolloverError::Keyset(
        sp_wire::codes::BURN_NOT_PROVEN,
        format!(
            "input {i}: {}; this request was started before, but nothing stored proves its inputs were burned under this request, so it cannot be finished without them",
            e.why("its keyset")
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deletion_cut_short_by_a_crash_is_finished_and_the_old_set_retired() {
        let d = std::env::temp_dir().join(format!("esp-rot-sweep-{}", {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }));
        let _ = fs::remove_dir_all(&d);
        // Generations 0, 1 and 2 on disk, and a half-deleted generation 7.
        for e in 0..3 {
            drop(open_gen(&d, e).unwrap());
        }
        fs::create_dir_all(d.join("retiring-gen-7/db")).unwrap();
        let (r, _cur) = Rotor::open_at(&d, 1, 1, 1).unwrap();
        assert!(!d.join("retiring-gen-7").exists(), "swept at open");
        assert_eq!(r.current.epoch, 2);
        assert_eq!(r.previous.as_ref().unwrap().0.epoch, 1);
        // Generation 0 was retired: secret and spent list gone, totals kept.
        assert!(!d.join(MASTER_SECRET_FILENAME).exists() && !d.join(DB_DIRNAME).exists());
        assert!(!d.join("retiring-gen-0").exists());
        assert_eq!(r.retired_totals(), (0, 0));
        let _ = fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod retired_list_tests {
    use super::*;

    fn scratch(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("esp-rot-{n}-{}", {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn retired_ids_are_told_from_unknown_ones_and_trimmed_oldest_first() {
        let d = scratch("list");
        let t = 10_000;
        let (mut r, mut cur) = Rotor::open_at(&d, 1, 1, t).unwrap();
        r.first_issue = Some(t);
        let mut ids = vec![r.current.id.clone()];
        for k in 1..=4u64 {
            r.clock.store(t + 3600 * k, Ordering::SeqCst);
            r.refresh(&mut cur).unwrap();
            ids.push(r.current.id.clone());
        }
        for id in &ids[..3] {
            assert_eq!(r.resolve(id).unwrap_err().code(), "keyset_retired");
        }
        assert_eq!(r.resolve(&ids[3]), Ok(Side::Previous));
        assert_eq!(r.resolve(&ids[4]), Ok(Side::Current));
        assert_eq!(
            r.resolve(&"ab".repeat(8)).unwrap_err().code(),
            "unknown_keyset"
        );
        assert_eq!(RETIRED_KEYSETS_CAP, 131_072, "1 MB of 8-byte IDs");
        r.set_retired_keep(2).unwrap();
        assert_eq!(r.resolve(&ids[0]).unwrap_err().code(), "unknown_keyset");
        let saved: Retired = load_json(&d.join(RETIRED_FILE)).unwrap().unwrap();
        assert_eq!(saved.ids, ids[1..3].to_vec());
        assert_eq!(
            saved.epochs,
            vec![0, 1, 2],
            "audit bookkeeping is not trimmed"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn outputs_are_signed_by_the_live_set_named_and_a_set_that_is_not_live_is_refused() {
        let d = scratch("signer");
        let t = 10_000;
        let (mut r, mut cur) = Rotor::open_at(&d, 1, 1, t).unwrap();
        r.first_issue = Some(t);
        let mut ids = vec![r.current.id.clone()];
        for k in 1..=3u64 {
            r.clock.store(t + 3600 * k, Ordering::SeqCst);
            r.refresh(&mut cur).unwrap();
            ids.push(r.current.id.clone());
        }
        // ids[3] is current, ids[2] previous, ids[0] and ids[1] retired.
        let gens = r.gens(&cur);
        let who = |id: &str, resumed: bool| gens.signer(id, resumed).map(|s| s.2);
        assert_eq!(who(&ids[3], false), Ok(ids[3].clone()));
        assert_eq!(
            who(&ids[2], false),
            Ok(ids[2].clone()),
            "the previous set signs when it is named"
        );
        assert_eq!(who(&ids[0], false).unwrap_err().code(), "keyset_retired");
        assert_eq!(
            who(&"ab".repeat(8), false).unwrap_err().code(),
            "unknown_keyset"
        );
        // A request finished after its set was deleted is signed by the
        // current set; one whose set is still live keeps it.
        assert_eq!(who(&ids[0], true), Ok(ids[3].clone()));
        assert_eq!(who(&ids[2], true), Ok(ids[2].clone()));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_crash_after_the_id_is_listed_but_before_the_set_is_deleted_retires_it_once() {
        let d = scratch("crash");
        for e in 0..3 {
            drop(open_gen(&d, e).unwrap());
        }
        let (g0, _) = open_gen(&d, 0).unwrap();
        // The list was written, generation 0 not yet deleted.
        save_json(
            &d.join(RETIRED_FILE),
            &Retired {
                epochs: vec![0],
                ids: vec![g0.id.clone()],
                burn_proofs: Default::default(),
                issued: 0,
                redeemed: 0,
            },
        )
        .unwrap();
        let (r, _cur) = Rotor::open_at(&d, 1, 1, 1).unwrap();
        assert!(
            !d.join(MASTER_SECRET_FILENAME).exists(),
            "deleted at the restart"
        );
        let saved: Retired = load_json(&d.join(RETIRED_FILE)).unwrap().unwrap();
        assert_eq!(saved.ids, vec![g0.id.clone()], "listed once");
        assert_eq!(r.resolve(&g0.id).unwrap_err().code(), "keyset_retired");
        let _ = fs::remove_dir_all(&d);
    }

    /// A note of `logic`'s set, under `terms`, spent there by `digest`.
    fn spent_note(logic: &MintLogic, master: &MasterSecret, terms: &Terms) -> MintInput {
        let kp = secp256k1::Keypair::new(SECP256K1, &mut rand::rngs::OsRng);
        let nonce = Nonce(kp.public_key());
        let (b, r) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        let amount = mint_types::Amount::from_units(4);
        let sk = master.key_for(amount, terms);
        let out = logic
            .issue_with_key(
                &sk,
                &MintOutput {
                    amount,
                    blind_nonce: mint_types::BlindNonce(b),
                },
            )
            .unwrap();
        let digest = [7u8; 32];
        let mut input = MintInput {
            amount,
            note: mint_types::Note {
                nonce,
                signature: bdhke::unblind_message(&out.0, &r, &sk.public_key(SECP256K1)),
            },
            spend_signature: secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap(),
        };
        input.spend_signature = SECP256K1.sign_schnorr(&digest, &kp);
        logic.redeem_with_key(&sk, &input, digest).unwrap();
        input
    }

    /// Crash injection: a redemption and a transfer burned their notes and
    /// crashed before writing their `burned` flag; a rollover recorded itself
    /// and crashed before burning. At the retirement, the proof is taken from
    /// the spent list and saved with the retired ID: the burned notes are
    /// proven, the unburned one is not, and a proof is dropped once no
    /// unfinished request holds its note.
    #[test]
    fn burns_cut_off_by_a_crash_are_proven_from_the_spent_list_when_their_set_retires() {
        let d = scratch("proofs");
        let t = 10_000;
        let (mut r, mut cur) = Rotor::open_at(&d, 1, 1, t).unwrap();
        r.first_issue = Some(t);
        let terms = Terms {
            service: sp_wire::ServiceDid::from(
                secp256k1::Keypair::new(SECP256K1, &mut rand::rngs::OsRng).public_key(),
            ),
            redeemable_after_day: 1,
        };
        let redeemed = spent_note(&cur, &r.current.master, &terms);
        let transferred = spent_note(&cur, &r.current.master, &terms);
        let unburned = MintInput {
            note: mint_types::Note {
                nonce: Nonce(
                    secp256k1::Keypair::new(SECP256K1, &mut rand::rngs::OsRng).public_key(),
                ),
                ..redeemed.note
            },
            ..redeemed.clone()
        };
        let hex_of = |i: &MintInput| hex::encode(i.note.nonce.0.serialize());
        let mut responses = crate::responses::Responses::open(&d.join(RESPONSES_FILE)).unwrap();
        let totals = serde_json::json!({"notes": [], "accepted_esp": "0", "rejected_esp": "0",
            "fee_esp": "0", "size_bytes": 0, "fee_per_byte": "0",
            "accepted_by_terms": [], "rejected_by_terms": []});
        let pending: crate::redeem::RedeemPending = serde_json::from_value(serde_json::json!({
            "inputs": [hex_of(&redeemed)], "outputs": [],
            "plan": {"totals": totals, "owed_esp": "0"}, "burned": false}))
        .unwrap();
        responses
            .put("r1", crate::responses::Entry::RedeemPending(pending))
            .unwrap();
        responses
            .put(
                "t1",
                crate::responses::Entry::TransferPending(crate::responses::TransferPending {
                    inputs: vec![hex_of(&transferred)],
                    outputs: vec![],
                    burned: false,
                }),
            )
            .unwrap();
        let mut ro = Rollovers::open(&d).unwrap();
        ro.pending.insert("o1".into(), 0);
        ro.holds.insert("o1".into(), vec![hex_of(&unburned)]);
        ro.save().unwrap();
        // Two rotations: generation 0 becomes previous, then retires.
        for k in 1..=2u64 {
            r.clock.store(t + 3600 * k, Ordering::SeqCst);
            r.refresh(&mut cur).unwrap();
        }
        let saved: Retired = load_json(&d.join(RETIRED_FILE)).unwrap().unwrap();
        assert!(saved.burn_proofs.contains(&hex_of(&redeemed)));
        assert!(saved.burn_proofs.contains(&hex_of(&transferred)));
        assert!(!saved.burn_proofs.contains(&hex_of(&unburned)));
        let g = r.gens(&cur);
        assert!(g.burn_proven(&redeemed) && g.burn_proven(&transferred));
        assert!(!g.burn_proven(&unburned));
        // Restart: the proofs are read back.
        drop(g);
        drop(cur);
        drop(r);
        let (r2, cur2) = Rotor::open_at(&d, 1, 1, t + 2 * 3600).unwrap();
        assert!(r2.gens(&cur2).burn_proven(&redeemed));
        // Once the requests are finished, the next retirement drops the proofs.
        let mut responses = crate::responses::Responses::open(&d.join(RESPONSES_FILE)).unwrap();
        responses
            .put(
                "r1",
                crate::responses::Entry::TransferPending(crate::responses::TransferPending {
                    inputs: vec![],
                    outputs: vec![],
                    burned: true,
                }),
            )
            .unwrap();
        responses
            .put(
                "t1",
                crate::responses::Entry::TransferPending(crate::responses::TransferPending {
                    inputs: vec![],
                    outputs: vec![],
                    burned: true,
                }),
            )
            .unwrap();
        let (mut r3, mut cur3) = (r2, cur2);
        r3.first_issue = Some(t);
        r3.clock.store(t + 3 * 3600, Ordering::SeqCst);
        r3.refresh(&mut cur3).unwrap();
        let saved: Retired = load_json(&d.join(RETIRED_FILE)).unwrap().unwrap();
        assert!(saved.burn_proofs.is_empty(), "{:?}", saved.burn_proofs);
        let _ = fs::remove_dir_all(&d);
    }
}
