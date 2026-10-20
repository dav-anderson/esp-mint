//! The mint's own DID key: the key wallets seal their AIR requests to, and the
//! one the mint signs its AIR replies with.
//!
//! It is the ESP mint's, not the PSP's. The PSP and the ESP each have their own
//! DID (their own `mint_did_key.json`), so they can share one AIR server and
//! their mailboxes do not collide, and a wallet that knows the SPI's DIDs asks
//! each mint by its own.
//!
//! The key is a local file for now (`mint_did_key.json`, `0600` permissions, in
//! the network's data folder), the same format as psp-mint's. Moving it into the
//! AIR keystore is deferred. It is made on first use, and a file that is there
//! but damaged is an error, never a reason to make a new key: every request
//! sealed to the old key would be lost, and a wallet that has the DID built in
//! would be asking a mint that cannot answer.

use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::Path;

pub use sp_wire::seal::{PublicKey, SecretKey};

/// The name of the key file in the network's data folder.
pub const KEY_FILENAME: &str = "mint_did_key.json";

/// Read the mint's DID key from `path`, or make one if there is no file.
pub fn load_or_generate(path: &Path) -> Result<SecretKey, Box<dyn Error>> {
    if path.exists() {
        let text = fs::read_to_string(path)?;
        return serde_json::from_str::<SecretKey>(text.trim()).map_err(|e| {
            Box::<dyn Error>::from(format!("{}: not a DID key file: {e}", path.display()))
        });
    }
    let secret = SecretKey::new();
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(serde_json::to_string(&secret)?.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(secret)
}

/// The mint's DID: 33 bytes, compressed, as hex (66 characters). What a wallet
/// is given as `air.esp_did`, and what the operator puts into the wallet's
/// built-in DID at the first SPI deploy.
pub fn public_key_hex(secret: &SecretKey) -> String {
    secret.public_key().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "esp-mint-did-{}-{name}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_key_is_made_once_and_read_back_the_same() {
        let dir = scratch("once");
        let path = dir.join(KEY_FILENAME);
        let first = load_or_generate(&path).unwrap();
        let again = load_or_generate(&path).unwrap();
        assert_eq!(public_key_hex(&first), public_key_hex(&again));
        assert_eq!(public_key_hex(&first).len(), 66);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_key_file_is_an_error_not_a_new_key() {
        let dir = scratch("damaged");
        let path = dir.join(KEY_FILENAME);
        fs::write(&path, "not a key").unwrap();
        let err = load_or_generate(&path).unwrap_err().to_string();
        assert!(err.contains("not a DID key file"), "{err}");
        // and the file is as it was
        assert_eq!(fs::read_to_string(&path).unwrap(), "not a key");
        fs::remove_dir_all(&dir).unwrap();
    }
}
