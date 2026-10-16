//! Opening the ESP mint.
//!
//! ESP has no fixed key table, because the signing key depends on the amount
//! and the terms and is derived from the master secret (see `keys`). The
//! `MintLogic` here has an empty table and is used only through
//! `issue_with_key` and `redeem_with_key`. It still keeps the spent set, the
//! used blind nonces and the issued and redeemed totals in its database.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::Path;

use mint_core::MintLogic;
use mint_core::store::Store;
use mint_types::MintConfig;

use crate::keys::{self, MasterSecret};

pub const MASTER_SECRET_FILENAME: &str = "master_secret.hex";
pub const DB_DIRNAME: &str = "db";

pub fn open(data_dir: &Path) -> Result<(MintLogic, MasterSecret), Box<dyn Error>> {
    fs::create_dir_all(data_dir)?;
    let master = keys::load_or_generate(&data_dir.join(MASTER_SECRET_FILENAME))?;
    let store = Store::open(&data_dir.join(DB_DIRNAME))?;
    let logic = MintLogic::new(
        MintConfig {
            sk: BTreeMap::new(),
        },
        store,
    );
    Ok((logic, master))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A restart must never open the mint's data while another process (or the
    /// old one, still shutting down) has it open. The database refuses a second
    /// open, so the new process stops with an error and the supervisor starts it
    /// again after its delay. This is a requirement of the storage (see
    /// DESIGN.md, "What the storage must provide").
    #[test]
    fn the_same_data_cannot_be_opened_twice_at_once() {
        let dir = std::env::temp_dir().join(format!("esp-mint-open-twice-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = open(&dir).unwrap();
        assert!(open(&dir).is_err());
        drop(first);
        let _ = fs::remove_dir_all(&dir);
    }
}
