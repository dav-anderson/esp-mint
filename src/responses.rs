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

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::exchange::ExchangeResponse;

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
    /// Validated and authorized. The terms are fixed here so that a retry on a
    /// later day still issues the same notes.
    Pending {
        redeemable_after_day: u64,
        credit_esp: u128,
    },
    Done(ExchangeResponse),
}

pub struct Responses {
    path: PathBuf,
    rows: BTreeMap<String, Entry>,
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
        })
    }

    pub fn get(&self, hash: &str) -> Option<&Entry> {
        self.rows.get(hash)
    }

    pub fn len(&self) -> usize {
        self.rows.len()
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
        let dir = std::env::temp_dir().join(format!("esp-mint-resp-{}-{name}", std::process::id()));
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
            credit_esp: u128::from(u64::MAX) * 1_000,
        };
        store.put("abc", entry.clone()).unwrap();
        let again = Responses::open(&path).unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(again.get("abc"), Some(&entry));
        assert_eq!(again.get("other"), None);
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
                    credit_esp: 0,
                },
            )
            .unwrap();
        assert!(!dir.join("responses.json.tmp").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
