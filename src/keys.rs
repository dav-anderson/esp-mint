use std::error::Error;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::Path;

use mint_types::Amount;
use secp256k1::SecretKey;
use sha2::{Digest, Sha256};

use crate::terms::Terms;

const KEY_TAG: &[u8] = b"esp-mint/key/v1";

#[derive(Clone, Eq, PartialEq)]
pub struct MasterSecret([u8; 32]);

impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterSecret(..)")
    }
}

impl MasterSecret {
    pub fn generate() -> Self {
        Self(SecretKey::new(&mut rand::thread_rng()).secret_bytes())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(text: &str) -> Option<Self> {
        let bytes = hex::decode(text.trim()).ok()?;
        Some(Self(bytes.try_into().ok()?))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn key_for(&self, amount: Amount, terms: &Terms) -> SecretKey {
        for counter in 0..=u8::MAX {
            let mut hasher = Sha256::new();
            hasher.update(KEY_TAG);
            hasher.update(self.0);
            hasher.update(amount.units.to_be_bytes());
            hasher.update(terms.to_bytes());
            hasher.update([counter]);
            if let Ok(key) = SecretKey::from_slice(&hasher.finalize()) {
                return key;
            }
        }
        unreachable!("256 consecutive hashes outside the curve order")
    }
}

pub fn load_or_generate(path: &Path) -> Result<MasterSecret, Box<dyn Error>> {
    if path.exists() {
        let text = fs::read_to_string(path)?;
        return MasterSecret::from_hex(&text).ok_or_else(|| {
            Box::<dyn Error>::from(format!(
                "{}: not a 64 character hex master secret",
                path.display()
            ))
        });
    }
    let secret = MasterSecret::generate();
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(secret.to_hex().as_bytes())?;
    file.write_all(b"\n")?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_wire::ServiceDid;
    use std::path::PathBuf;

    const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// The DID whose key is the generator: `02` and its x coordinate.
    fn service() -> ServiceDid {
        ServiceDid::parse(&format!("02{G_X}")).unwrap()
    }

    fn master() -> MasterSecret {
        MasterSecret::from_bytes([0x42; 32])
    }

    fn terms() -> Terms {
        Terms::new_at(service(), 1_791_571_184)
    }

    fn key_hex(master: &MasterSecret, units: u64, terms: &Terms) -> String {
        hex::encode(
            master
                .key_for(Amount::from_units(units), terms)
                .secret_bytes(),
        )
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("esp-mint-{}-{name}", {
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
    fn known_answers_from_an_independent_implementation() {
        assert_eq!(
            key_hex(&master(), 4, &terms()),
            "5ff28eeec15916b32e6f28c49c2ff02185955cc01557b5fee0b0401ff16fef42"
        );
        assert_eq!(
            key_hex(&master(), 8, &terms()),
            "79d12470d22577b2358a1f3e42ef00abe501708dfb115b766a3dab6360dc7edc"
        );
        let later = Terms {
            redeemable_after_day: terms().redeemable_after_day + 1,
            ..terms()
        };
        assert_eq!(
            key_hex(&master(), 4, &later),
            "90186260e583ae776750a5814875f593af007f46d4e7bee8d50fba519c649d6c"
        );
    }

    #[test]
    fn every_input_changes_the_key() {
        let base = key_hex(&master(), 4, &terms());
        assert_ne!(base, key_hex(&master(), 2, &terms()));
        assert_ne!(
            base,
            key_hex(&MasterSecret::from_bytes([0x43; 32]), 4, &terms())
        );
        let other_service = Terms {
            service: ServiceDid::parse(
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            )
            .unwrap(),
            ..terms()
        };
        assert_ne!(base, key_hex(&master(), 4, &other_service));
        // The parity byte is part of the service, so it is part of the key.
        let odd_parity = Terms {
            service: ServiceDid::parse(&format!("03{G_X}")).unwrap(),
            ..terms()
        };
        assert_ne!(base, key_hex(&master(), 4, &odd_parity));
    }

    #[test]
    fn master_secret_hex_round_trip_and_rejects_bad_input() {
        let m = master();
        assert_eq!(MasterSecret::from_hex(&m.to_hex()), Some(m));
        assert_eq!(MasterSecret::from_hex("abcd"), None);
        assert_eq!(MasterSecret::from_hex("zz"), None);
        assert_eq!(format!("{:?}", master()), "MasterSecret(..)");
    }

    #[test]
    fn generated_once_then_reloaded() {
        let dir = scratch("master");
        let path = dir.join("master_secret.hex");
        let first = load_or_generate(&path).unwrap();
        assert_eq!(load_or_generate(&path).unwrap(), first);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_file_is_an_error_not_a_new_secret() {
        let dir = scratch("damaged");
        let path = dir.join("master_secret.hex");
        fs::write(&path, "not hex").unwrap();
        let e = load_or_generate(&path).unwrap_err().to_string();
        assert!(
            e.contains("not a 64 character hex master secret")
                && e.contains(&path.display().to_string()),
            "{e}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "not hex");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("mode");
        let path = dir.join("master_secret.hex");
        load_or_generate(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
