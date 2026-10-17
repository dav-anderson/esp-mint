//! Stored exchange state, keyed by request hash.
//!
//! This is a placeholder store: one JSON document, rewritten in full on every
//! change (temporary file, fsync, rename, directory fsync). It holds the entries,
//! by request hash, and the per-day ledger (`ledger`), so that one atomic write
//! changes both. A missing file means no entries. An unreadable file is an error
//! and never an empty store.
//!
//! Files written before 0.5.0 are a bare JSON object from request hash to entry.
//! They are read as they are, with an empty ledger, and the first change writes
//! the new shape (`{"entries": {...}, "ledger": {...}}`). There is no way back
//! to the old shape short of restoring a copy of the file: an older version
//! refuses the new one rather than reading it as entries.
//!
//! An entry is `pending` from just before the PSP notes are burned until the
//! ESP signatures are made, and `done` after that. A request that is retried
//! gets the stored response if it is done, and is carried on from where it
//! stopped if it is pending, so a crash after the burn never loses the notes.
//!
//! A pending entry also lists the notes it will burn and the blind nonces it
//! will sign, so that no other request can take those notes or nonces while it
//! is unfinished. That is what makes a retry safe: a note that is spent while a
//! request for it is pending was spent by that request. An exchange lists PSP
//! note nonces and ESP blind nonces. A transfer (see `transfer`), kept in the
//! same file under its own request hash, lists ESP note nonces and ESP blind
//! nonces. A redemption (see `redeem`) lists the ESP note nonces it burns and
//! the blind nonces of every output it may sign, and also keeps what it decided
//! about each note, so that a retry after a crash does the same thing again.
//! After it is done, its decline outputs stay reserved, because the operator may
//! still decline the payout and sign them.

use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::exchange::ExchangeResponse;
use crate::ledger::{Ledger, Movements};
use crate::redeem::{RedeemPending, RedeemRecord};

#[derive(Debug)]
pub enum ResponsesError {
    Io(io::Error),
    Corrupt(serde_json::Error),
}

impl fmt::Display for ResponsesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponsesError::Io(e) => write!(f, "stored responses: {e}"),
            ResponsesError::Corrupt(e) => write!(f, "stored responses are not valid json: {e}"),
        }
    }
}

impl Error for ResponsesError {}

impl From<io::Error> for ResponsesError {
    fn from(e: io::Error) -> Self {
        ResponsesError::Io(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// Externally tagged on purpose: serde cannot read a u128 through an internally
// tagged enum.
#[serde(rename_all = "snake_case")]
pub enum Entry {
    /// An exchange that is validated and authorized, and not yet finished. The
    /// terms are fixed here so that a retry on a later day still issues the same
    /// notes. The lists reserve the PSP notes it burns and the blind nonces it
    /// signs (hex), against every other request. An entry written before the
    /// lists existed has them empty and reserves nothing.
    Pending {
        redeemable_after_day: u64,
        #[serde(default)]
        inputs: Vec<String>,
        #[serde(default)]
        outputs: Vec<String>,
    },
    /// A transfer that is validated and authorized, and not yet finished. Some
    /// of its inputs may be burned and some of its outputs signed.
    TransferPending(TransferPending),
    /// A redemption that is validated and authorized, and not yet finished. Some
    /// of its notes may be burned and some of its refunds signed.
    RedeemPending(RedeemPending),
    /// A finished redemption.
    RedeemDone(RedeemRecord),
    /// The finished response. An exchange and a transfer answer in the same shape.
    Done(ExchangeResponse),
}

/// What an unfinished transfer holds, as hex, so that other requests can be kept
/// away from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferPending {
    /// The nonces of the notes the transfer burns.
    pub inputs: Vec<String>,
    /// The blind nonces of the notes the transfer signs.
    pub outputs: Vec<String>,
    /// Every input has been burned under this request's hash (written after
    /// the burn, before any signing). Only this proves the burn once an
    /// input's keyset has been deleted with its spent list.
    #[serde(default)]
    pub burned: bool,
}

/// The file as it is written since 0.5.0.
#[derive(Serialize, Deserialize)]
struct Stored {
    entries: BTreeMap<String, Entry>,
    ledger: Ledger,
}

/// [`Stored`], borrowed, for writing.
#[derive(Serialize)]
struct StoredRef<'a> {
    entries: &'a BTreeMap<String, Entry>,
    ledger: &'a Ledger,
}

/// Tells the two shapes of the file apart without reading the entries: only the
/// new one has a `ledger` member (a request hash is hex, so it never is one).
#[derive(Deserialize)]
struct Probe {
    #[serde(default)]
    ledger: Option<serde::de::IgnoredAny>,
}

pub struct Responses {
    path: PathBuf,
    rows: BTreeMap<String, Entry>,
    ledger: Ledger,
    /// Notes (nonce hex) held by unfinished requests stored elsewhere (pending
    /// rollovers), set by the server before a transfer or redemption. Not saved.
    external_holds: HashSet<String>,
}

impl Responses {
    pub fn open(path: &Path) -> Result<Self, ResponsesError> {
        let (rows, ledger) = match fs::read(path) {
            Ok(bytes) => {
                let probe: Probe =
                    serde_json::from_slice(&bytes).map_err(ResponsesError::Corrupt)?;
                if probe.ledger.is_some() {
                    let stored: Stored =
                        serde_json::from_slice(&bytes).map_err(ResponsesError::Corrupt)?;
                    (stored.entries, stored.ledger)
                } else {
                    let rows = serde_json::from_slice(&bytes).map_err(ResponsesError::Corrupt)?;
                    (rows, Ledger::default())
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (BTreeMap::new(), Ledger::default()),
            Err(e) => return Err(e.into()),
        };
        Ok(Responses {
            path: path.to_path_buf(),
            rows,
            ledger,
            external_holds: HashSet::new(),
        })
    }

    /// Set the notes pending rollovers hold (see `external_holds`).
    pub fn set_external_holds(&mut self, held: HashSet<String>) {
        self.external_holds = held;
    }

    pub fn external_holds(&self) -> &HashSet<String> {
        &self.external_holds
    }

    pub fn get(&self, hash: &str) -> Option<&Entry> {
        self.rows.get(hash)
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// The per-day ledger of ESP issued and redeemed (see `ledger`).
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// How many requests are unfinished: exchanges, transfers and redemptions
    /// whose entry is still pending. Their notes may be burned or signed already
    /// (mint-core counts that at once) while the ledger counts the request when
    /// it finishes.
    pub fn unfinished(&self) -> usize {
        self.rows
            .values()
            .filter(|e| {
                matches!(
                    e,
                    Entry::Pending { .. } | Entry::TransferPending(_) | Entry::RedeemPending(_)
                )
            })
            .count()
    }

    /// The transfers that are validated and not finished, by request hash.
    pub fn pending_transfers(&self) -> impl Iterator<Item = (&String, &TransferPending)> + '_ {
        self.rows.iter().filter_map(|(hash, entry)| match entry {
            Entry::TransferPending(pending) => Some((hash, pending)),
            _ => None,
        })
    }

    /// The exchanges that are validated and not finished, by request hash, with
    /// the PSP note nonces and the ESP blind nonces each one holds.
    pub fn pending_exchanges(
        &self,
    ) -> impl Iterator<Item = (&String, &Vec<String>, &Vec<String>)> + '_ {
        self.rows.iter().filter_map(|(hash, entry)| match entry {
            Entry::Pending {
                inputs, outputs, ..
            } => Some((hash, inputs, outputs)),
            _ => None,
        })
    }

    /// What the redemptions other than `except` hold, as hex: the ESP note
    /// nonces they will burn (unfinished ones only, since a finished one's notes
    /// are spent) and the blind nonces of the outputs they may sign (the
    /// decline outputs of a finished one stay held).
    pub fn redeem_holds(&self, except: &str) -> (HashSet<String>, HashSet<String>) {
        let mut inputs = HashSet::new();
        let mut outputs = HashSet::new();
        for (hash, entry) in &self.rows {
            if hash == except {
                continue;
            }
            match entry {
                Entry::RedeemPending(pending) => {
                    inputs.extend(pending.inputs.iter().cloned());
                    outputs.extend(pending.outputs.iter().cloned());
                }
                Entry::RedeemDone(record) => {
                    outputs.extend(
                        record
                            .decline_outputs
                            .iter()
                            .map(|o| hex::encode(o.output.blind_nonce.0.serialize())),
                    );
                }
                _ => {}
            }
        }
        (inputs, outputs)
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Insert or replace an entry and write the whole file.
    pub fn put(&mut self, hash: &str, entry: Entry) -> Result<(), ResponsesError> {
        let mut next = self.rows.clone();
        next.insert(hash.to_string(), entry);
        self.write(&next, &self.ledger)?;
        self.rows = next;
        Ok(())
    }

    /// [`put`](Self::put) the entry that finishes a request, and in the same
    /// write add its `movements` to the ledger. The movements are added only if
    /// the entry replaced is not a finished one already, so a request is never
    /// counted twice, and a crash can not leave it finished and not counted, or
    /// counted and not finished.
    pub fn finish(
        &mut self,
        hash: &str,
        entry: Entry,
        movements: &Movements,
    ) -> Result<(), ResponsesError> {
        let counted = matches!(
            self.rows.get(hash),
            Some(Entry::Done(_)) | Some(Entry::RedeemDone(_))
        );
        let mut next = self.rows.clone();
        next.insert(hash.to_string(), entry);
        let mut ledger = self.ledger.clone();
        if !counted {
            ledger.apply(movements);
        }
        self.write(&next, &ledger)?;
        self.rows = next;
        self.ledger = ledger;
        Ok(())
    }

    /// Add the `movements` of the decline of queue entry `id`, once. The queue
    /// entry is marked in another file, so this is counted by `id` instead of
    /// by a finished entry: run again after a crash it adds nothing. Returns
    /// whether it added them.
    pub fn count_decline(
        &mut self,
        id: &str,
        movements: &Movements,
    ) -> Result<bool, ResponsesError> {
        if self.ledger.decline_counted(id) {
            return Ok(false);
        }
        let mut ledger = self.ledger.clone();
        ledger.apply_decline(id, movements);
        self.write(&self.rows, &ledger)?;
        self.ledger = ledger;
        Ok(true)
    }

    fn write(&self, rows: &BTreeMap<String, Entry>, ledger: &Ledger) -> Result<(), ResponsesError> {
        let tmp = self.path.with_extension("json.tmp");
        let stored = StoredRef {
            entries: rows,
            ledger,
        };
        let text = serde_json::to_string_pretty(&stored).map_err(io::Error::other)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Day;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("esp-mint-resp-{}-{name}", {
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
    fn a_missing_file_is_empty_and_entries_survive_a_reopen() {
        let dir = scratch("reopen");
        let path = dir.join("responses.json");
        let mut store = Responses::open(&path).unwrap();
        assert!(store.is_empty());
        let entry = Entry::Pending {
            redeemable_after_day: 21_100,
            inputs: vec![],
            outputs: vec![],
        };
        store.put("abc", entry.clone()).unwrap();
        let again = Responses::open(&path).unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(again.get("abc"), Some(&entry));
        assert_eq!(again.get("other"), None);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pending_transfers_survive_a_reopen_and_are_listed_apart_from_the_rest() {
        let dir = scratch("transfers");
        let path = dir.join("responses.json");
        let mut store = Responses::open(&path).unwrap();
        let held = TransferPending {
            burned: false,
            inputs: vec!["02aa".into(), "02bb".into()],
            outputs: vec!["03cc".into()],
        };
        store
            .put("t1", Entry::TransferPending(held.clone()))
            .unwrap();
        store
            .put(
                "e1",
                Entry::Pending {
                    redeemable_after_day: 5,
                    inputs: vec![],
                    outputs: vec![],
                },
            )
            .unwrap();
        let again = Responses::open(&path).unwrap();
        assert_eq!(again.len(), 2);
        assert_eq!(again.get("t1"), Some(&Entry::TransferPending(held.clone())));
        let listed: Vec<(&String, &TransferPending)> = again.pending_transfers().collect();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, "t1");
        assert_eq!(listed[0].1, &held);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pending_exchanges_keep_their_reservations_across_a_reopen() {
        let dir = scratch("exchanges");
        let path = dir.join("responses.json");
        let mut store = Responses::open(&path).unwrap();
        store
            .put(
                "e1",
                Entry::Pending {
                    redeemable_after_day: 5,
                    inputs: vec!["02aa".into()],
                    outputs: vec!["03bb".into(), "03cc".into()],
                },
            )
            .unwrap();
        store
            .put(
                "t1",
                Entry::TransferPending(TransferPending {
                    burned: false,
                    inputs: vec!["02dd".into()],
                    outputs: vec!["03ee".into()],
                }),
            )
            .unwrap();
        let again = Responses::open(&path).unwrap();
        let listed: Vec<_> = again.pending_exchanges().collect();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, "e1");
        assert_eq!(listed[0].1, &vec!["02aa".to_string()]);
        assert_eq!(listed[0].2, &vec!["03bb".to_string(), "03cc".to_string()]);
        assert_eq!(again.pending_transfers().count(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_pending_entry_written_before_the_reservations_still_reads() {
        let dir = scratch("old-pending");
        let path = dir.join("responses.json");
        fs::write(&path, r#"{"abc":{"pending":{"redeemable_after_day":5}}}"#).unwrap();
        let store = Responses::open(&path).unwrap();
        assert_eq!(
            store.get("abc"),
            Some(&Entry::Pending {
                redeemable_after_day: 5,
                inputs: vec![],
                outputs: vec![],
            })
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_file_is_an_error_and_is_left_alone() {
        let dir = scratch("damaged");
        let path = dir.join("responses.json");
        fs::write(&path, "not json").unwrap();
        assert!(matches!(
            Responses::open(&path),
            Err(ResponsesError::Corrupt(_))
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), "not json");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let dir = scratch("tmp");
        let path = dir.join("responses.json");
        let mut store = Responses::open(&path).unwrap();
        store
            .put(
                "h",
                Entry::Pending {
                    redeemable_after_day: 1,
                    inputs: vec![],
                    outputs: vec![],
                },
            )
            .unwrap();
        assert!(!dir.join("responses.json.tmp").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    fn done(day: u64) -> Entry {
        Entry::Done(ExchangeResponse {
            keyset: String::new(),
            service: secp256k1::XOnlyPublicKey::from_slice(
                &hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                    .unwrap(),
            )
            .unwrap(),
            redeemable_after_day: day,
            signatures: vec![],
            keys: vec![],
            fee_per_byte: 0,
            fee_esp: 0,
            size_bytes: 0,
        })
    }

    fn pending(day: u64) -> Entry {
        Entry::Pending {
            redeemable_after_day: day,
            inputs: vec![],
            outputs: vec![],
        }
    }

    fn issued(day: u64, units: u128) -> Movements {
        let mut m = Movements::new();
        m.issue(day, units);
        m
    }

    #[test]
    fn a_file_from_before_the_ledger_reads_with_an_empty_ledger_and_is_upgraded_by_the_next_write()
    {
        let dir = scratch("upgrade");
        let path = dir.join("responses.json");
        // the old shape: a bare object from request hash to entry
        fs::write(&path, r#"{"abc":{"pending":{"redeemable_after_day":5}}}"#).unwrap();
        let mut store = Responses::open(&path).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.ledger(), &Ledger::default());
        // reading does not rewrite it
        assert!(!fs::read_to_string(&path).unwrap().contains("ledger"));

        store.finish("abc", done(5), &issued(5, 70)).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"entries\"") && text.contains("\"ledger\""));
        let again = Responses::open(&path).unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(again.get("abc"), Some(&done(5)));
        assert_eq!(again.ledger().day(5).issued, 70);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_empty_old_file_is_an_empty_store() {
        let dir = scratch("empty-old");
        let path = dir.join("responses.json");
        fs::write(&path, "{}").unwrap();
        let store = Responses::open(&path).unwrap();
        assert!(store.is_empty());
        assert_eq!(store.ledger(), &Ledger::default());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_older_version_refuses_the_new_file_rather_than_reading_it_as_entries() {
        let dir = scratch("downgrade");
        let path = dir.join("responses.json");
        let mut store = Responses::open(&path).unwrap();
        store.finish("abc", done(5), &issued(5, 1)).unwrap();
        let bytes = fs::read(&path).unwrap();
        // what 0.4.0 did with the file
        assert!(serde_json::from_slice::<BTreeMap<String, Entry>>(&bytes).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn finishing_a_request_counts_it_in_the_same_write_and_only_once() {
        let dir = scratch("finish");
        let path = dir.join("responses.json");
        let mut store = Responses::open(&path).unwrap();
        store.put("h", pending(7)).unwrap();
        assert_eq!(store.unfinished(), 1);
        assert_eq!(store.ledger().day(7), Day::default());

        store.finish("h", done(7), &issued(7, 100)).unwrap();
        assert_eq!(store.unfinished(), 0);
        assert_eq!(store.ledger().day(7).issued, 100);
        // the file has both, as one document
        let again = Responses::open(&path).unwrap();
        assert_eq!(again.get("h"), Some(&done(7)));
        assert_eq!(again.ledger().day(7).issued, 100);

        // finishing what is finished already counts nothing
        store.finish("h", done(7), &issued(7, 100)).unwrap();
        assert_eq!(store.ledger().day(7).issued, 100);
        assert_eq!(Responses::open(&path).unwrap().ledger().day(7).issued, 100);
        // a second request is counted on its own
        store.finish("k", done(7), &issued(7, 5)).unwrap();
        assert_eq!(store.ledger().day(7).issued, 105);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_decline_is_counted_once_by_its_id_and_survives_a_reopen() {
        let dir = scratch("decline");
        let path = dir.join("responses.json");
        let mut store = Responses::open(&path).unwrap();
        assert!(store.count_decline("e1", &issued(3, 40)).unwrap());
        assert!(!store.count_decline("e1", &issued(3, 40)).unwrap());
        let mut again = Responses::open(&path).unwrap();
        assert!(again.ledger().decline_counted("e1"));
        assert!(!again.count_decline("e1", &issued(3, 40)).unwrap());
        assert_eq!(again.ledger().day(3).issued, 40);
        assert_eq!(again.len(), 0, "the ledger rows are not entries");
        assert!(again.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_torn_write_leaves_the_old_file_and_its_ledger_whole() {
        let dir = scratch("torn");
        let path = dir.join("responses.json");
        let mut store = Responses::open(&path).unwrap();
        store.finish("h", done(7), &issued(7, 100)).unwrap();
        drop(store);
        // A write that stopped before the rename: a half-written temporary file
        // beside the real one.
        let full = serde_json::to_string_pretty(&StoredRef {
            entries: &BTreeMap::new(),
            ledger: &Ledger::default(),
        })
        .unwrap();
        fs::write(path.with_extension("json.tmp"), &full[..full.len() / 2]).unwrap();

        let mut store = Responses::open(&path).unwrap();
        assert_eq!(store.get("h"), Some(&done(7)));
        assert_eq!(store.ledger().day(7).issued, 100);
        // and the next write replaces the leftover
        store.finish("k", done(7), &issued(7, 1)).unwrap();
        assert!(!path.with_extension("json.tmp").exists());
        assert_eq!(Responses::open(&path).unwrap().ledger().day(7).issued, 101);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_write_that_fails_changes_neither_the_entries_nor_the_ledger() {
        let dir = scratch("failed");
        // the folder does not exist, so the temporary file can not be made
        let path = dir.join("missing").join("responses.json");
        let mut store = Responses::open(&path).unwrap();
        assert!(store.finish("h", done(7), &issued(7, 100)).is_err());
        assert!(store.is_empty());
        assert_eq!(store.ledger(), &Ledger::default());
        assert!(store.count_decline("e1", &issued(7, 1)).is_err());
        assert!(!store.ledger().decline_counted("e1"));
        assert!(store.put("h", pending(7)).is_err());
        assert!(store.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_ledger_is_an_error_and_not_an_empty_one() {
        let dir = scratch("damaged-ledger");
        let path = dir.join("responses.json");
        fs::write(
            &path,
            r#"{"entries":{},"ledger":{"days":{"5":{"issued":"x"}}}}"#,
        )
        .unwrap();
        assert!(matches!(
            Responses::open(&path),
            Err(ResponsesError::Corrupt(_))
        ));
        fs::write(&path, r#"{"entries":{},"ledger":5}"#).unwrap();
        assert!(matches!(
            Responses::open(&path),
            Err(ResponsesError::Corrupt(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_unfinished_requests_are_counted_as_unfinished() {
        let dir = scratch("unfinished");
        let path = dir.join("responses.json");
        let mut store = Responses::open(&path).unwrap();
        store.put("e", pending(1)).unwrap();
        store
            .put(
                "t",
                Entry::TransferPending(TransferPending {
                    burned: true,
                    inputs: vec![],
                    outputs: vec![],
                }),
            )
            .unwrap();
        store.put("d", done(1)).unwrap();
        assert_eq!(store.unfinished(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }
}
