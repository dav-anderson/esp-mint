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
