//! The live snapshot: a copy of the network's data folder taken while `serve`
//! keeps its sockets, so that a backup never has to stop the mint.
//!
//! `serve` takes one on `SIGUSR1` (`main.rs`). It stops answering the way a
//! stop does (stops the AIR listener, lets the requests being answered
//! finish, drops every handle on the mint's data so that sled flushes and closes
//! its files), calls [`take`] on the quiet folder, and opens everything again.
//! Nothing writes to the folder while it is copied, and the copy is a folder that
//! opens as a mint. While it runs the listening sockets stay open, so a client
//! that connects waits in the backlog, and a wallet's request waits in its
//! mailbox slot on the AIR server.
//!
//! **Where.** `<data folder>/snapshots/<UTC time>/` (`20261023T101500Z`, so that
//! the names sort by time), made with permissions `0700`, with the file
//! `snapshots/LATEST` naming the newest complete one. `LATEST` is written last
//! (temp file, fsync, rename), so a reader that follows it never sees a folder
//! that is not finished. A folder without it being named is a failed one;
//! [`take`] removes what it made when it fails.
//!
//! **What is in it.** Everything in the network's folder except `snapshots`
//! itself: the signing keys and master secrets of every generation (the
//! snapshot is as secret as the folder is), the ESP's database, the stored
//! responses, the payout queue, the rotation state and the AIR counter. The mint's
//! DID key (`mint_did_key.json`) is in the folder, so it is in the snapshot too;
//! it is the one file a backup that leaves this machine has to keep out (the
//! operator keeps that key offline, and `spi` leaves it out of what it copies).
//!
//! **The pause.** It lasts as long as it takes to drop the handles, copy the
//! folder and open it again: the copy is linear in the size of the folder (every
//! byte is read, written and fsynced), and sled's open time grows with the size of
//! its log. It is short for a small mint and grows with the database.
//!
//! Snapshots are not pruned here; the operator (or `spi`) removes old ones.

use std::fs;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// The folder, in the network's data folder, that holds the snapshots.
pub const DIR: &str = "snapshots";
/// The file, in [`DIR`], that names the newest complete snapshot.
pub const LATEST: &str = "LATEST";

/// `20261023T101500Z` for a unix time: sortable, and safe in a file name.
pub fn stamp(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rest = unix_secs % 86_400;
    // Days since 1970-01-01 to a civil date (proleptic Gregorian), after Howard
    // Hinnant's `civil_from_days`.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

fn private_dir(path: &Path) -> Result<(), String> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("make {}: {e}", path.display()))
}

fn sync_dir(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("fsync {}: {e}", path.display()))
}

/// Copy `from` to `to` (which does not exist), file by file, each fsynced. The
/// folders it makes are `0700`; a file keeps the permissions it had.
fn copy_tree(from: &Path, to: &Path, skip: Option<&str>) -> Result<(), String> {
    private_dir(to)?;
    let entries = fs::read_dir(from).map_err(|e| format!("read {}: {e}", from.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read {}: {e}", from.display()))?;
        let name = entry.file_name();
        if skip.is_some_and(|s| name == s) {
            continue;
        }
        let source = entry.path();
        let target = to.join(&name);
        let kind = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", source.display()))?;
        if kind.is_dir() {
            copy_tree(&source, &target, None)?;
        } else {
            fs::copy(&source, &target)
                .map_err(|e| format!("copy {} to {}: {e}", source.display(), target.display()))?;
            fs::File::open(&target)
                .and_then(|f| f.sync_all())
                .map_err(|e| format!("fsync {}: {e}", target.display()))?;
        }
    }
    sync_dir(to)
}

/// Copy `data_dir` (whose mint must not be open) to `snapshots/<stamp>` inside
/// it, then name it in `snapshots/LATEST`. Returns the new folder. A name taken
/// by an earlier snapshot of the same second gets `-1`, `-2`... after it, which
/// still sorts after the earlier one. On any failure the folder it made is
/// removed and `LATEST` still names the snapshot it named before.
pub fn take(data_dir: &Path, stamp: &str) -> Result<PathBuf, String> {
    let root = data_dir.join(DIR);
    private_dir(&root)?;
    let mut name = stamp.to_string();
    let mut n = 0u32;
    while root.join(&name).exists() {
        n += 1;
        name = format!("{stamp}-{n}");
    }
    let target = root.join(&name);
    let result = copy_tree(data_dir, &target, Some(DIR)).and_then(|()| {
        // The newest complete snapshot is named last, atomically.
        let temp = root.join(format!("{LATEST}.tmp"));
        let mut file =
            fs::File::create(&temp).map_err(|e| format!("make {}: {e}", temp.display()))?;
        file.write_all(format!("{name}\n").as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("write {}: {e}", temp.display()))?;
        fs::rename(&temp, root.join(LATEST))
            .map_err(|e| format!("rename {}: {e}", temp.display()))?;
        sync_dir(&root)
    });
    match result {
        Ok(()) => Ok(target),
        Err(why) => {
            // Best effort: what is left over is not named by `LATEST`, so it is
            // never taken for a snapshot, and the next one does not need it gone.
            if let Err(e) = fs::remove_dir_all(&target) {
                eprintln!("esp-mint: could not remove the failed snapshot: {e}");
            }
            Err(why)
        }
    }
}

/// The newest complete snapshot, as `LATEST` names it.
pub fn latest(data_dir: &Path) -> Result<Option<PathBuf>, String> {
    let file = data_dir.join(DIR).join(LATEST);
    match fs::read_to_string(&file) {
        Ok(text) => Ok(Some(data_dir.join(DIR).join(text.trim()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read {}: {e}", file.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("esp-mint-snapshot-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A folder like a network's: files, a sub-folder, and one file nobody else
    /// may read.
    fn seeded(name: &str) -> PathBuf {
        let dir = scratch(name);
        fs::write(dir.join("mint_keys.json"), b"keys").unwrap();
        fs::write(dir.join("air_mailbox_next"), b"7").unwrap();
        fs::create_dir_all(dir.join("db").join("deeper")).unwrap();
        fs::write(dir.join("db").join("blob"), b"sled").unwrap();
        fs::write(dir.join("db").join("deeper").join("conf"), b"conf").unwrap();
        fs::set_permissions(
            dir.join("mint_keys.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        dir
    }

    #[test]
    fn a_stamp_is_the_utc_time_and_sorts_by_time() {
        assert_eq!(stamp(0), "19700101T000000Z");
        assert_eq!(stamp(1_700_000_000), "20231114T221320Z");
        // A leap day, and the second before the next day.
        assert_eq!(stamp(951_782_400), "20000229T000000Z");
        assert_eq!(stamp(951_868_799), "20000229T235959Z");
        assert_eq!(stamp(951_868_800), "20000301T000000Z");
        let mut stamps: Vec<String> = [3_000_000_000u64, 0, 1_700_000_000, 951_782_400]
            .iter()
            .map(|t| stamp(*t))
            .collect();
        let as_made = stamps.clone();
        stamps.sort();
        assert_eq!(
            stamps,
            vec![
                as_made[1].clone(),
                as_made[3].clone(),
                as_made[2].clone(),
                as_made[0].clone()
            ]
        );
    }

    #[test]
    fn a_snapshot_is_a_private_copy_of_everything_but_the_snapshots() {
        let dir = seeded("copy");
        let first = take(&dir, "20260101T000000Z").unwrap();
        assert_eq!(first, dir.join("snapshots").join("20260101T000000Z"));
        assert_eq!(fs::read(first.join("mint_keys.json")).unwrap(), b"keys");
        assert_eq!(fs::read(first.join("air_mailbox_next")).unwrap(), b"7");
        assert_eq!(fs::read(first.join("db").join("blob")).unwrap(), b"sled");
        assert_eq!(
            fs::read(first.join("db").join("deeper").join("conf")).unwrap(),
            b"conf"
        );
        // The snapshots are not copied into themselves.
        assert!(!first.join("snapshots").exists());
        // Private: the folders are 0700 and the key file kept its 0600.
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join("snapshots")), 0o700);
        assert_eq!(mode(&first), 0o700);
        assert_eq!(mode(&first.join("db").join("deeper")), 0o700);
        assert_eq!(mode(&first.join("mint_keys.json")), 0o600);
        // The live folder is as it was.
        assert_eq!(fs::read(dir.join("mint_keys.json")).unwrap(), b"keys");

        // A second snapshot does not contain the first, and LATEST moves to it.
        fs::write(dir.join("air_mailbox_next"), b"9").unwrap();
        let second = take(&dir, "20260102T000000Z").unwrap();
        assert!(!second.join("snapshots").exists());
        assert_eq!(fs::read(second.join("air_mailbox_next")).unwrap(), b"9");
        assert_eq!(fs::read(first.join("air_mailbox_next")).unwrap(), b"7");
        assert_eq!(latest(&dir).unwrap(), Some(second));
        assert!(!dir.join("snapshots").join("LATEST.tmp").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn two_snapshots_in_one_second_do_not_overwrite_each_other() {
        let dir = seeded("same-second");
        let a = take(&dir, "20260101T000000Z").unwrap();
        let b = take(&dir, "20260101T000000Z").unwrap();
        assert_eq!(a.file_name().unwrap(), "20260101T000000Z");
        assert_eq!(b.file_name().unwrap(), "20260101T000000Z-1");
        assert!(a.join("mint_keys.json").is_file() && b.join("mint_keys.json").is_file());
        assert_eq!(latest(&dir).unwrap(), Some(b));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn there_is_no_latest_until_a_snapshot_is_complete() {
        let dir = seeded("none");
        assert_eq!(latest(&dir).unwrap(), None);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_snapshot_is_removed_and_latest_still_names_the_one_before() {
        let dir = seeded("failed");
        let good = take(&dir, "20260101T000000Z").unwrap();
        // A link to nothing cannot be copied, whoever runs the test, and the
        // other files may or may not have been copied before it is reached.
        std::os::unix::fs::symlink(dir.join("nothing-here"), dir.join("dangling")).unwrap();
        let err = take(&dir, "20260103T000000Z").unwrap_err();
        assert!(
            err.starts_with("copy ") && err.contains("dangling"),
            "{err}"
        );
        assert!(!dir.join("snapshots").join("20260103T000000Z").exists());
        assert_eq!(latest(&dir).unwrap(), Some(good.clone()));
        assert_eq!(fs::read(good.join("mint_keys.json")).unwrap(), b"keys");
        // With the cause gone, the next snapshot is made and is named.
        fs::remove_file(dir.join("dangling")).unwrap();
        let next = take(&dir, "20260103T000000Z").unwrap();
        assert_eq!(latest(&dir).unwrap(), Some(next));
        fs::remove_dir_all(&dir).unwrap();
    }
}
