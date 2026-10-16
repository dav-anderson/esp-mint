//! Stored exchange state, keyed by request hash.
//!
//! This is a placeholder store: one JSON object from request hash to entry,
//! rewritten in full on every change (temporary file, fsync, rename, directory
//! fsync). A missing file means no entries. An unreadable file is an error and
//! never an empty store.
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

pub struct Responses {
    path: PathBuf,
    rows: BTreeMap<String, Entry>,
    /// Notes (nonce hex) held by unfinished requests stored elsewhere (pending
    /// rollovers), set by the server before a transfer or redemption. Not saved.
    external_holds: HashSet<String>,
}

impl Responses {
    pub fn open(path: &Path) -> Result<Self, ResponsesError> {
        let rows = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(ResponsesError::Corrupt)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Responses {
            path: path.to_path_buf(),
            rows,
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
        self.write(&next)?;
        self.rows = next;
        Ok(())
    }

    fn write(&self, rows: &BTreeMap<String, Entry>) -> Result<(), ResponsesError> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
