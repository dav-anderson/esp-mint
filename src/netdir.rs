//! Each network has its own data folder: `<ESP_DATA_DIR>/<network>` (`main`,
//! `regtest`, `signet`, `testnet`). The config file stays in `ESP_DATA_DIR`.
//!
//! Before this, the mint's files sat directly in `ESP_DATA_DIR`, and they were
//! regtest files (nothing else ran). The mint refuses to start while they are
//! there, and `esp-mint migrate` moves them into `regtest/`: a rename, never a
//! copy or a delete, refused if `regtest/` already holds a file of the same name.

use std::fs;
use std::path::{Path, PathBuf};

/// The files a pre-network data folder held.
pub const LEGACY_ITEMS: [&str; 4] = ["master_secret.hex", "db", "responses.json", "queue.json"];

pub fn network_dir(base: &Path, network: &str) -> PathBuf {
    base.join(network)
}

pub fn legacy_items(base: &Path) -> Vec<&'static str> {
    LEGACY_ITEMS
        .iter()
        .copied()
        .filter(|n| fs::symlink_metadata(base.join(n)).is_ok())
        .collect()
}

/// Refuse to run while old files sit directly in `base`.
pub fn refuse_legacy(base: &Path) -> Result<(), String> {
    let items = legacy_items(base);
    if items.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{} still holds mint files from before networks had their own folders ({}). They are from regtest. Run `esp-mint migrate` once to move them into {}/ (nothing is deleted), then start again",
        base.display(),
        items.join(", "),
        network_dir(base, "regtest").display()
    ))
}

/// Move the old files into `<base>/regtest/`. Returns what was moved.
pub fn migrate_to_regtest(base: &Path) -> Result<Vec<&'static str>, String> {
    let items = legacy_items(base);
    if items.is_empty() {
        return Err(format!(
            "nothing to migrate: {} has no mint files of its own",
            base.display()
        ));
    }
    let target = network_dir(base, "regtest");
    let clash: Vec<&str> = items
        .iter()
        .copied()
        .filter(|n| fs::symlink_metadata(target.join(n)).is_ok())
        .collect();
    if !clash.is_empty() {
        return Err(format!(
            "{} already holds {}: nothing was moved. Move them aside by hand first",
            target.display(),
            clash.join(", ")
        ));
    }
    fs::create_dir_all(&target).map_err(|e| format!("cannot make {}: {e}", target.display()))?;
    for n in &items {
        fs::rename(base.join(n), target.join(n)).map_err(|e| format!("cannot move {n}: {e}"))?;
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("esp-netdir-{name}-{}", {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn old_files_are_refused_then_moved_into_regtest_without_loss() {
        let d = dir("migrate");
        assert!(refuse_legacy(&d).is_ok());
        fs::write(d.join("master_secret.hex"), "ab").unwrap();
        fs::create_dir_all(d.join("db")).unwrap();
        fs::write(d.join("db").join("x"), "1").unwrap();
        fs::write(d.join("esp-mint.toml"), "").unwrap();
        assert!(refuse_legacy(&d).unwrap_err().contains("esp-mint migrate"));
        assert_eq!(
            migrate_to_regtest(&d).unwrap(),
            vec!["master_secret.hex", "db"]
        );
        assert_eq!(
            fs::read_to_string(d.join("regtest/master_secret.hex")).unwrap(),
            "ab"
        );
        assert_eq!(fs::read_to_string(d.join("regtest/db/x")).unwrap(), "1");
        assert!(d.join("esp-mint.toml").exists(), "the config file stays");
        assert!(refuse_legacy(&d).is_ok());
        assert!(migrate_to_regtest(&d).is_err(), "nothing left to move");
        // A clash moves nothing.
        fs::write(d.join("responses.json"), "{}").unwrap();
        fs::write(d.join("regtest/responses.json"), "{}").unwrap();
        assert!(
            migrate_to_regtest(&d)
                .unwrap_err()
                .contains("nothing was moved")
        );
        assert!(d.join("responses.json").exists());
        assert_eq!(network_dir(&d, "main"), d.join("main"));
        fs::remove_dir_all(&d).unwrap();
    }
}
