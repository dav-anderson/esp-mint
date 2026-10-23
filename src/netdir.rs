//! Each network has its own data folder: `<ESP_DATA_DIR>/<network>` (`main`,
//! `regtest`, `signet`, `testnet`). The config file stays in `ESP_DATA_DIR`.
//!
//! A data folder from before this split, with the mint's files directly in
//! `ESP_DATA_DIR`, is not read: the mint makes a fresh folder for the network
//! beside them and starts empty.

use std::path::{Path, PathBuf};

pub fn network_dir(base: &Path, network: &str) -> PathBuf {
    base.join(network)
}
