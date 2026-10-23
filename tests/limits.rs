//! The ceilings and the fee settings over AIR: a reload of the config file
//! changes what the next request sees (the ceiling and the rates). The 413 for a
//! body over its ceiling, on every call, is in `air_info.rs`.
//!
//! The calls go to esp-mint's own AIR listener on a real `air_server` (see
//! `common`); a refusal is read as its HTTP status and body.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use esp_mint::config::{self, Config};
use esp_mint::exchange::{Burn, Psp};
use esp_mint::server::EspState;
use mint_types::{Amount, MintInput, Nonce};

const CEILING: usize = 4096;

struct NoPsp;

impl Psp for NoPsp {
    fn melt(&self, _inputs: &[MintInput], _memo: &str) -> Result<Amount, String> {
        Err("not used".into())
    }

    fn burns(&self, _nonces: &[Nonce]) -> Result<Vec<Burn>, String> {
        Err("not used".into())
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("esp-mint-limits-{}-{name}", {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn start(dir: &Path) -> (common::Air, Arc<EspState>) {
    let cfg = Config {
        exchange_max_request_bytes: CEILING,
        transfer_max_request_bytes: CEILING,
        rollover_max_request_bytes: CEILING,
        redeem_max_request_bytes: CEILING,
        ..Config::default()
    };
    // The state `serve` builds, on the system clock.
    let state = Arc::new(EspState::open(&dir.join("esp"), Box::new(NoPsp), cfg, 0).unwrap());
    (common::Air::start(&state, &dir.join("air")), state)
}

#[test]
fn a_reload_changes_the_ceiling_and_the_rates_for_the_next_request_only() {
    let dir = scratch("reload");
    let (air, state) = start(&dir);
    let (status, fees) = air.get_json("/fees");
    assert_eq!(status, 200);
    assert_eq!(fees["exchange"]["fee_per_byte"], "0");
    assert_eq!(fees["transfer"]["fee_per_byte"], "0");
    assert_eq!(fees["exchange"]["size"]["per_input"], 146);
    assert_eq!(fees["redeem"]["size"]["per_input"], 187);
    assert_eq!(fees["exchange"]["max_request_bytes"], CEILING as u64);
    assert_eq!(fees["rollover"]["max_request_bytes"], CEILING as u64);
    assert_eq!(fees["rollover"]["max_items"], 1000);

    // a request of 5000 bytes is over the ceiling now ...
    assert_eq!(air.post_bytes("/exchange", &vec![b'x'; 5000]).0, 413);

    // ... and after the file changes and the mint reloads, it is not, and the
    // rates in force are the new ones
    let data = dir.join("esp");
    std::fs::write(
        data.join(config::FILE_NAME),
        "[exchange]\nmax_request_bytes = 65536\nfee_per_byte = 7\n[transfer]\nfee_per_byte = 9\n",
    )
    .unwrap();
    let before = state.config.current();
    state.config.reload(&data, &|_: &str| None).unwrap();
    assert_eq!(air.post_bytes("/exchange", &vec![b'x'; 5000]).0, 400);
    let (status, fees) = air.get_json("/fees");
    assert_eq!(status, 200);
    assert_eq!(fees["exchange"]["fee_per_byte"], "7");
    assert_eq!(fees["transfer"]["fee_per_byte"], "9");
    // the settings a request took before the reload are untouched
    assert_eq!(before.exchange_fee_per_byte, 0);
    drop(air);
    std::fs::remove_dir_all(&dir).unwrap();
}
