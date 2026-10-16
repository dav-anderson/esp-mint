//! The redemption queue: what the mint still owes services.
//!
//! One entry per redemption that leaves something owed, with the amount owed
//! (ESP), the payout memo, the service and a status. An entry is `open` until it
//! is `completed` (paid, with a payment reference) or `declined` (with the
//! operator's reason and the signatures on the reissued notes).
//!
//! `redeem::redeem` adds entries with `Queue::add`, using the request hash as
//! the entry id, so a retried request finds its entry already there. The payout
//! report (`payouts.rs`), the settle call and the decline call below work on
//! whatever is in the file.
//!
//! This is a placeholder store like `responses.rs`: one JSON object from entry
//! id to entry, rewritten in full on every change (temporary file, fsync, rename,
//! directory fsync). A missing file means no entries. An unreadable file is an
//! error and never an empty queue. Moving it into the AIR is deferred.
//!
//! Amounts are `u128` and are written as decimal strings, because JSON numbers
//! lose digits past 2^53 in most readers.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use secp256k1::{PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

/// ESP units in one US dollar.
pub const ESP_PER_USD: u128 = 1_000_000_000_000;

/// The default for the longest payment reference accepted
/// (`queue.max_payment_ref_bytes`).
pub const MAX_REF_LEN: usize = 256;

/// The default for the longest reason for a decline accepted
/// (`redeem.max_reason_bytes`). The limit is checked where the decline is made
/// (`redeem::decline_with`); the queue only needs a reason that is not empty.
pub const DEFAULT_MAX_REASON_BYTES: usize = 1024;

/// `u128` as a decimal string in JSON.
pub mod dec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug)]
pub enum QueueError {
    Io(io::Error),
    Corrupt(serde_json::Error),
    /// An entry with this id is already queued.
    Duplicate(String),
    /// The request is wrong: nothing was changed.
    Invalid(String),
    /// No entry has this id.
    Unknown(String),
    /// The entry is for another service.
    WrongService(String),
    /// The entry is not open (it is completed or declined).
    NotOpen {
        id: String,
        status: Status,
    },
    /// The entries have different payout memos and the caller did not allow it.
    MixedMemos(Vec<String>),
    /// A sum does not fit in `u128`.
    Overflow,
}

impl QueueError {
    /// True when the request was refused and nothing was changed, as opposed to a
    /// fault in the store.
    pub fn is_refusal(&self) -> bool {
        !matches!(
            self,
            QueueError::Io(_) | QueueError::Corrupt(_) | QueueError::Overflow
        )
    }
}

impl fmt::Display for QueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueueError::Io(e) => write!(f, "redemption queue: {e}"),
            QueueError::Corrupt(e) => write!(f, "redemption queue is not valid json: {e}"),
            QueueError::Duplicate(id) => write!(f, "entry {id} is already queued"),
            QueueError::Invalid(why) => write!(f, "{why}"),
            QueueError::Unknown(id) => write!(f, "no entry {id}"),
            QueueError::WrongService(id) => write!(f, "entry {id} is for another service"),
            QueueError::NotOpen { id, status } => {
                write!(f, "entry {id} is not open (it is {status:?})")
            }
            QueueError::MixedMemos(memos) => write!(
                f,
                "these entries have {} different payout memos ({}). Pay each destination on its own, or allow mixed memos if one payment really covers them",
                memos.len(),
                memos.join(" | ")
            ),
            QueueError::Overflow => write!(f, "the total does not fit in 128 bits"),
        }
    }
}

impl Error for QueueError {}

impl From<io::Error> for QueueError {
    fn from(e: io::Error) -> Self {
        QueueError::Io(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    Declined,
    Completed,
}

/// A blind signature on one output and the key it was made with: what a wallet
/// needs, with its blinding factor, to unblind the new note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOutput {
    pub signature: PublicKey,
    pub key: PublicKey,
    /// The keyset that signed it. Empty in an entry stored before keysets.
    #[serde(default)]
    pub keyset: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The redemption request hash.
    pub id: String,
    /// The service's DID public key (x-only).
    pub service: XOnlyPublicKey,
    /// ESP owed: the accepted total minus the fee.
    #[serde(with = "dec")]
    pub owed_esp: u128,
    /// The payout destination the service signed.
    pub memo: String,
    /// When the redemption was accepted, in unix seconds.
    pub created_unix: u64,
    pub status: Status,
    #[serde(default)]
    pub payment_ref: Option<String>,
    #[serde(default)]
    pub completed_unix: Option<u64>,
    /// When the mint declined to pay, in unix seconds.
    #[serde(default)]
    pub declined_unix: Option<u64>,
    /// Why the mint declined to pay.
    #[serde(default)]
    pub decline_reason: Option<String>,
    /// The signatures on the notes reissued because of the decline, in the order
    /// of the request's `decline_outputs`.
    #[serde(default)]
    pub decline_signatures: Vec<SignedOutput>,
    /// The fee rate this redemption was charged at, in ESP units per encoded
    /// byte: the rate in force when it was accepted. Zero on an entry that was
    /// queued without one.
    #[serde(default, with = "dec")]
    pub fee_per_byte: u128,
    /// The fee that was charged, in ESP units.
    #[serde(default, with = "dec")]
    pub fee_esp: u128,
    /// The size of the request the fee was sized by, in bytes.
    #[serde(default)]
    pub size_bytes: u64,
}

/// What a service is told about its entry when it asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryView {
    pub status: Status,
    #[serde(with = "dec")]
    pub owed_esp: u128,
    /// The rate the fee was charged at, and the fee, as stored when the request
    /// was accepted.
    #[serde(with = "dec")]
    pub fee_per_byte: u128,
    #[serde(with = "dec")]
    pub fee_esp: u128,
    pub payment_ref: Option<String>,
    pub decline_reason: Option<String>,
    pub decline_signatures: Vec<SignedOutput>,
}

impl Entry {
    /// A new open entry.
    pub fn open(
        id: &str,
        service: XOnlyPublicKey,
        owed_esp: u128,
        memo: &str,
        created_unix: u64,
    ) -> Self {
        Entry {
            id: id.to_string(),
            service,
            owed_esp,
            memo: memo.to_string(),
            created_unix,
            status: Status::Open,
            payment_ref: None,
            completed_unix: None,
            declined_unix: None,
            decline_reason: None,
            decline_signatures: Vec::new(),
            fee_per_byte: 0,
            fee_esp: 0,
            size_bytes: 0,
        }
    }

    /// Record the fee this redemption was charged, and the rate it was charged at.
    pub fn with_fee(mut self, fee_per_byte: u128, fee_esp: u128, size_bytes: u64) -> Self {
        self.fee_per_byte = fee_per_byte;
        self.fee_esp = fee_esp;
        self.size_bytes = size_bytes;
        self
    }

    pub fn view(&self) -> EntryView {
        EntryView {
            status: self.status,
            owed_esp: self.owed_esp,
            fee_per_byte: self.fee_per_byte,
            fee_esp: self.fee_esp,
            payment_ref: self.payment_ref.clone(),
            decline_reason: self.decline_reason.clone(),
            decline_signatures: self.decline_signatures.clone(),
        }
    }
}

/// Entries to mark paid.
pub struct Payment<'a> {
    pub service: XOnlyPublicKey,
    /// One reference for the whole payment (a txid, a wire number).
    pub payment_ref: &'a str,
    /// The exact entries that were paid, as listed in the report the operator
    /// paid from. An entry that is not in this list is never touched.
    pub entry_ids: &'a [String],
    /// Allow entries with different payout memos in one payment.
    pub allow_mixed_memos: bool,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Paid {
    pub service: XOnlyPublicKey,
    pub payment_ref: String,
    pub entries: usize,
    #[serde(with = "dec")]
    pub paid_esp: u128,
    pub paid_usd: String,
    pub entry_ids: Vec<String>,
}

pub struct Queue {
    path: PathBuf,
    rows: BTreeMap<String, Entry>,
    max_ref_bytes: usize,
}

impl Queue {
    /// Read the queue. A missing file is an empty queue.
    pub fn open(path: &Path) -> Result<Self, QueueError> {
        let rows = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(QueueError::Corrupt)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Queue {
            path: path.to_path_buf(),
            rows,
            max_ref_bytes: MAX_REF_LEN,
        })
    }

    /// Set the longest payment reference `complete` accepts. The default is
    /// `MAX_REF_LEN`; the mint sets it from `queue.max_payment_ref_bytes`.
    pub fn with_max_ref_bytes(mut self, max_ref_bytes: usize) -> Self {
        self.max_ref_bytes = max_ref_bytes;
        self
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.rows.get(id)
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.rows.values()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Queue a new open entry. An id that is already there is an error, so a
    /// retried redemption never queues twice.
    pub fn add(&mut self, entry: Entry) -> Result<(), QueueError> {
        if entry.id.is_empty() {
            return Err(QueueError::Invalid("an entry needs an id".into()));
        }
        if entry.status != Status::Open {
            return Err(QueueError::Invalid("a new entry must be open".into()));
        }
        if entry.owed_esp == 0 {
            return Err(QueueError::Invalid(
                "nothing is owed, so there is nothing to queue".into(),
            ));
        }
        if self.rows.contains_key(&entry.id) {
            return Err(QueueError::Duplicate(entry.id));
        }
        let mut next = self.rows.clone();
        next.insert(entry.id.clone(), entry);
        self.write(&next)?;
        self.rows = next;
        Ok(())
    }

    /// Mark exactly the listed entries completed with one payment reference.
    ///
    /// All or nothing. Nothing changes, in memory or in the file, unless every
    /// listed entry exists, is for this service and is open, the list has no
    /// repeats, the reference is not empty, and (unless allowed) the entries share
    /// one payout memo. If the file cannot be written the entries stay open.
    pub fn complete(&mut self, payment: &Payment<'_>) -> Result<Paid, QueueError> {
        let payment_ref = payment.payment_ref.trim();
        if payment_ref.is_empty() {
            return Err(QueueError::Invalid(
                "a payment reference is required".into(),
            ));
        }
        if payment_ref.len() > self.max_ref_bytes {
            return Err(QueueError::Invalid(format!(
                "the payment reference is longer than {} bytes",
                self.max_ref_bytes
            )));
        }
        if payment.entry_ids.is_empty() {
            return Err(QueueError::Invalid(
                "list the entry ids that were paid".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        let mut memos = BTreeSet::new();
        let mut total: u128 = 0;
        for id in payment.entry_ids {
            if !seen.insert(id.as_str()) {
                return Err(QueueError::Invalid(format!("entry {id} is listed twice")));
            }
            let entry = self
                .rows
                .get(id)
                .ok_or_else(|| QueueError::Unknown(id.clone()))?;
            if entry.service != payment.service {
                return Err(QueueError::WrongService(id.clone()));
            }
            if entry.status != Status::Open {
                return Err(QueueError::NotOpen {
                    id: id.clone(),
                    status: entry.status,
                });
            }
            memos.insert(entry.memo.clone());
            total = total
                .checked_add(entry.owed_esp)
                .ok_or(QueueError::Overflow)?;
        }
        if memos.len() > 1 && !payment.allow_mixed_memos {
            return Err(QueueError::MixedMemos(memos.into_iter().collect()));
        }

        let mut next = self.rows.clone();
        for id in payment.entry_ids {
            if let Some(entry) = next.get_mut(id) {
                entry.status = Status::Completed;
                entry.payment_ref = Some(payment_ref.to_string());
                entry.completed_unix = Some(payment.now_unix);
            }
        }
        self.write(&next)?;
        self.rows = next;
        Ok(Paid {
            service: payment.service,
            payment_ref: payment_ref.to_string(),
            entries: payment.entry_ids.len(),
            paid_esp: total,
            paid_usd: usd(total),
            entry_ids: payment.entry_ids.to_vec(),
        })
    }

    /// Mark an open entry declined, with the reason and the signatures on the
    /// notes reissued for it. Nothing changes unless the entry exists, is open,
    /// and the reason is not empty.
    pub fn decline(
        &mut self,
        id: &str,
        reason: &str,
        signatures: Vec<SignedOutput>,
        now_unix: u64,
    ) -> Result<(), QueueError> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(QueueError::Invalid(
                "a reason for the decline is required".into(),
            ));
        }
        let entry = self
            .rows
            .get(id)
            .ok_or_else(|| QueueError::Unknown(id.to_string()))?;
        if entry.status != Status::Open {
            return Err(QueueError::NotOpen {
                id: id.to_string(),
                status: entry.status,
            });
        }
        let mut next = self.rows.clone();
        if let Some(entry) = next.get_mut(id) {
            entry.status = Status::Declined;
            entry.declined_unix = Some(now_unix);
            entry.decline_reason = Some(reason.to_string());
            entry.decline_signatures = signatures;
        }
        self.write(&next)?;
        self.rows = next;
        Ok(())
    }

    fn write(&self, rows: &BTreeMap<String, Entry>) -> Result<(), QueueError> {
        let tmp = self.path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(rows).map_err(io::Error::other)?;
        let mut file = File::create(&tmp)?;
        file.write_all(text.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&tmp, &self.path)?;
        // Make the rename itself durable. Not every platform allows opening a
        // directory, so a failure here is ignored.
        if let Some(dir) = self.path.parent() {
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}

/// An ESP amount in US dollars, exactly: 12 decimal places, no rounding.
pub fn usd(esp: u128) -> String {
    format!("{}.{:012}", esp / ESP_PER_USD, esp % ESP_PER_USD)
}

/// A unix time as a UTC date, `YYYY-MM-DD`.
pub fn date(unix: u64) -> String {
    let z = (unix / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn service() -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(&hex::decode(G_X).unwrap()).unwrap()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("esp-mint-queue-{}-{name}", {
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

    #[test]
    fn dates_and_dollars() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_791_571_184), "2026-10-09");
        assert_eq!(date(4_102_444_800), "2100-01-01");
        assert_eq!(usd(15 * ESP_PER_USD), "15.000000000000");
        assert_eq!(usd(1), "0.000000000001");
        assert_eq!(usd(u128::MAX), "340282366920938463463374607.431768211455");
    }

    #[test]
    fn a_missing_file_is_empty_and_entries_survive_a_reopen_with_big_amounts() {
        let dir = scratch("reopen");
        let path = dir.join("queue.json");
        let mut queue = Queue::open(&path).unwrap();
        assert!(queue.is_empty());
        let big = u128::from(u64::MAX) * 1_000;
        queue
            .add(Entry::open("a", service(), big, "memo", 5))
            .unwrap();
        let again = Queue::open(&path).unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(again.get("a").unwrap().owed_esp, big);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_file_is_an_error_and_is_left_alone() {
        let dir = scratch("damaged");
        let path = dir.join("queue.json");
        fs::write(&path, "not json").unwrap();
        assert!(matches!(Queue::open(&path), Err(QueueError::Corrupt(_))));
        assert_eq!(fs::read_to_string(&path).unwrap(), "not json");
        fs::remove_dir_all(&dir).unwrap();
    }

    fn signed(n: u8) -> SignedOutput {
        let mut bytes = [0u8; 32];
        bytes[31] = n;
        let sk = secp256k1::SecretKey::from_slice(&bytes).unwrap();
        let pk = PublicKey::from_secret_key(secp256k1::SECP256K1, &sk);
        SignedOutput {
            signature: pk,
            key: pk,
            keyset: String::new(),
        }
    }

    #[test]
    fn a_decline_keeps_the_reason_and_the_signatures_across_a_reopen() {
        let dir = scratch("decline");
        let path = dir.join("queue.json");
        let mut queue = Queue::open(&path).unwrap();
        queue.add(Entry::open("a", service(), 5, "m", 1)).unwrap();
        queue.add(Entry::open("b", service(), 6, "m", 1)).unwrap();
        queue
            .decline("a", "  terms not met  ", vec![signed(3), signed(4)], 99)
            .unwrap();
        let again = Queue::open(&path).unwrap();
        let a = again.get("a").unwrap();
        assert_eq!(a.status, Status::Declined);
        assert_eq!(a.decline_reason.as_deref(), Some("terms not met"));
        assert_eq!(a.declined_unix, Some(99));
        assert_eq!(a.decline_signatures, vec![signed(3), signed(4)]);
        assert_eq!(a.view().status, Status::Declined);
        assert_eq!(again.get("b").unwrap().status, Status::Open);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_decline_is_refused_for_a_missing_closed_or_unexplained_entry() {
        let dir = scratch("decline-refused");
        let path = dir.join("queue.json");
        let mut queue = Queue::open(&path).unwrap();
        queue.add(Entry::open("a", service(), 5, "m", 1)).unwrap();
        assert!(matches!(
            queue.decline("nope", "why", vec![], 2),
            Err(QueueError::Unknown(_))
        ));
        assert!(queue.decline("a", "   ", vec![], 2).is_err());
        assert_eq!(queue.get("a").unwrap().status, Status::Open);
        queue.decline("a", "why", vec![], 2).unwrap();
        assert!(matches!(
            queue.decline("a", "again", vec![], 3),
            Err(QueueError::NotOpen { .. })
        ));
        assert_eq!(
            queue.get("a").unwrap().decline_reason.as_deref(),
            Some("why")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_entry_written_before_declines_existed_still_reads() {
        let dir = scratch("old-entry");
        let path = dir.join("queue.json");
        fs::write(
            &path,
            format!(
                r#"{{"a":{{"id":"a","service":"{G_X}","owed_esp":"5","memo":"m","created_unix":1,"status":"open"}}}}"#
            ),
        )
        .unwrap();
        let queue = Queue::open(&path).unwrap();
        let a = queue.get("a").unwrap();
        assert_eq!(a.declined_unix, None);
        assert!(a.decline_signatures.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_entry_is_queued_once_and_only_when_something_is_owed() {
        let dir = scratch("add");
        let mut queue = Queue::open(&dir.join("queue.json")).unwrap();
        queue.add(Entry::open("a", service(), 5, "m", 1)).unwrap();
        assert!(matches!(
            queue.add(Entry::open("a", service(), 9, "m", 2)),
            Err(QueueError::Duplicate(_))
        ));
        assert!(queue.add(Entry::open("b", service(), 0, "m", 2)).is_err());
        assert!(queue.add(Entry::open("", service(), 1, "m", 2)).is_err());
        assert_eq!(queue.get("a").unwrap().owed_esp, 5);
        assert_eq!(queue.len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }
}
