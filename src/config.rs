//! The ESP mint's settings: one file, `esp-mint.toml`, with environment
//! overrides.
//!
//! Nothing that an operator might want to tune is a constant in the code. Every
//! fee, rate, limit, period, address and timeout is a setting listed in `SPECS`
//! (which is also what the README's table and the startup log are made from),
//! with its default, its unit and what it affects.
//!
//! Where the values come from, strongest first:
//!
//! 1. an environment variable (the `env` column of `SPECS`);
//! 2. the file `esp-mint.toml` in the data directory, or the file `ESP_CONFIG`
//!    names (which must exist);
//! 3. the default.
//!
//! The file is TOML in sections (`[redeem]`, `max_memo_bytes = 128`). A key
//! the mint does not know is an error, so a misspelt setting never silently
//! does nothing. So is a value of the wrong type or out of range: the mint
//! lists every problem and does not start. The admin token is a secret and is
//! read from `ESP_ADMIN_TOKEN` only; it is never in the file.
//!
//! Reloading: send the running mint `SIGHUP`. It reads the file and the
//! environment again, checks the result, and swaps it in all at once, or keeps
//! the old values and says why. A request already running finishes with the
//! values it started with, and every request is charged at the rate in force
//! when it was accepted. The settings marked "restart" in `SPECS` (addresses and
//! the PSP client) are read once and are not changed by a reload: the mint says
//! so, and the new value takes effect at the next start.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sp_wire::storage::StoragePolicy;
use std::sync::{Arc, RwLock};

use crate::exchange::{self, ExchangeSettings};
use crate::queue;
use crate::redeem::{self, RedeemSettings};
use crate::terms::REDEEM_WINDOW_DAYS;
use crate::transfer::TransferSettings;

/// The name of the file looked for in the data directory.
pub const FILE_NAME: &str = "esp-mint.toml";
/// The environment variable that names a config file elsewhere.
pub const FILE_ENV: &str = "ESP_CONFIG";
/// The default ceiling on one exchange, transfer or admin request body (1 MiB).
pub const DEFAULT_SMALL_REQUEST_BYTES: usize = 1024 * 1024;
/// The smallest ceiling accepted for those routes: a request with one note and
/// one output has to fit.
pub const MIN_SMALL_REQUEST_BYTES: u64 = 4096;

/// One setting, as documented.
pub struct Spec {
    /// `section.name`, as in the file.
    pub key: &'static str,
    /// The environment variable that overrides it.
    pub env: &'static str,
    /// The default, as written in the file.
    pub default: &'static str,
    pub units: &'static str,
    /// Whether a running mint picks up a change on `SIGHUP`.
    pub reload: bool,
    pub what: &'static str,
}

/// A network setting's canonical name: `main` (or `mainnet`), `regtest`,
/// `signet`, `testnet`. The same names psp-mint reports.
pub fn network_name(value: &str) -> Result<&'static str, String> {
    match value.trim() {
        "main" | "mainnet" => Ok("main"),
        "regtest" => Ok("regtest"),
        "signet" => Ok("signet"),
        "testnet" => Ok("testnet"),
        other => Err(format!(
            "`{other}` is not a network: use main, regtest, signet or testnet"
        )),
    }
}

/// Check what the PSP's `/health` said about its network against ours.
pub fn check_psp_network(expected: &str, reported: Option<&str>) -> Result<(), String> {
    match reported {
        Some(n) if n == expected => Ok(()),
        Some(n) => Err(format!(
            "the PSP is on {n}, but this mint is set to {expected} (server.network, ESP_NETWORK). Refusing to start"
        )),
        None => Err(format!(
            "the PSP's /health does not say which network it is on, so it cannot be checked against {expected}. Refusing to start; update psp-mint"
        )),
    }
}

pub const SPECS: &[Spec] = &[
    Spec {
        key: "server.network",
        env: "ESP_NETWORK",
        default: "main",
        units: "network",
        reload: false,
        what: "The Bitcoin network of the PSP this mint burns at: main, regtest, signet or testnet. At startup the mint asks the PSP (`GET /health`) and refuses to start if the PSP is on another network. Reported in `/health`.",
    },
    Spec {
        key: "server.bind",
        env: "ESP_BIND",
        default: "127.0.0.1:3100",
        units: "host:port",
        reload: false,
        what: "The public API's address.",
    },
    Spec {
        key: "server.admin_bind",
        env: "ESP_ADMIN_BIND",
        default: "127.0.0.1:3101",
        units: "host:port",
        reload: false,
        what: "The operator's listener (payout report, settle, decline). Must be a loopback address.",
    },
    Spec {
        key: "psp.url",
        env: "ESP_PSP_URL",
        default: "http://127.0.0.1:3000",
        units: "URL",
        reload: false,
        what: "The PSP mint (`psp-mint serve`) where PSP notes are burned and looked up.",
    },
    Spec {
        key: "psp.timeout_secs",
        env: "ESP_PSP_TIMEOUT_SECS",
        default: "30",
        units: "seconds",
        reload: false,
        what: "How long a call to the PSP may take before the exchange fails and can be retried.",
    },
    Spec {
        key: "psp.startup_retry_secs",
        env: "ESP_PSP_STARTUP_RETRY_SECS",
        default: "5",
        units: "seconds",
        reload: false,
        what: "At startup the mint asks the PSP which network it is on. If the PSP cannot be reached, the mint waits this long and asks again, for as long as it takes, so that starting the mint before the PSP (or after a power cut) needs no one to start it again. A PSP that answers with another network, or with none, is not waited for: the mint stops with a message.",
    },
    Spec {
        key: "terms.maturity_days",
        env: "ESP_MATURITY_DAYS",
        default: "365",
        units: "days",
        reload: true,
        what: "How long after the day of issue a new exchange's ESP notes become redeemable. Fixed into each exchange when it is first accepted; notes already issued keep theirs.",
    },
    Spec {
        key: "rotation.activation_hours",
        env: "ESP_ROTATION_ACTIVATION_HOURS",
        default: "8760",
        units: "hours",
        reload: false,
        what: "Hours from the mint's first issuance (recorded once in first_issue.json) to its first key rotation. 0 = never rotate (one key set, one spent list).",
    },
    Spec {
        key: "rotation.period_hours",
        env: "ESP_ROTATION_PERIOD_HOURS",
        default: "87600",
        units: "hours",
        reload: false,
        what: "Hours between key rotations (10 years). Notes of the previous key set stay good until the next rotation; then that set and its spent list are deleted.",
    },
    Spec {
        key: "exchange.max_items",
        env: "ESP_EXCHANGE_MAX_ITEMS",
        default: "1000",
        units: "notes",
        reload: true,
        what: "The most PSP notes, and the most ESP outputs, in one exchange.",
    },
    Spec {
        key: "exchange.min_psp",
        env: "ESP_EXCHANGE_MIN_PSP",
        default: "1",
        units: "PSP (10 PSP = $1)",
        reload: true,
        what: "The smallest exchange, in PSP. 1 PSP is $0.10 (10 PSP = $1). Below it the exchange is refused before anything is burned.",
    },
    Spec {
        key: "exchange.max_request_bytes",
        env: "ESP_EXCHANGE_MAX_BYTES",
        default: "1048576",
        units: "bytes",
        reload: true,
        what: "The ceiling on one exchange request body (1 MiB). A larger body is refused with 413 before it is parsed: nothing is burned, nothing is charged.",
    },
    Spec {
        key: "exchange.fee_per_byte",
        env: "ESP_EXCHANGE_FEE_PER_BYTE",
        default: "0",
        units: "ESP units per canonical byte",
        reload: true,
        what: "The exchange fee rate. 0 means no mint fee. If set, a request pays this times its canonical size (48 + 146 per PSP note + 41 per output bytes), paid in ESP on top of the exact amount, at the rate in force when it is accepted; the rate is stored on the reply.",
    },
    Spec {
        key: "transfer.max_items",
        env: "ESP_TRANSFER_MAX_ITEMS",
        default: "1000",
        units: "notes",
        reload: true,
        what: "The most notes, and the most outputs, in one transfer.",
    },
    Spec {
        key: "transfer.max_request_bytes",
        env: "ESP_TRANSFER_MAX_BYTES",
        default: "1048576",
        units: "bytes",
        reload: true,
        what: "The ceiling on one transfer request body (1 MiB). A larger body is refused with 413 before it is parsed: nothing is burned, nothing is charged.",
    },
    Spec {
        key: "rollover.max_items",
        env: "ESP_ROLLOVER_MAX_ITEMS",
        default: "1000",
        units: "notes",
        reload: true,
        what: "The most notes in one rollover. More is refused before anything is burned.",
    },
    Spec {
        key: "rollover.max_request_bytes",
        env: "ESP_ROLLOVER_MAX_BYTES",
        default: "1048576",
        units: "bytes",
        reload: true,
        what: "The ceiling on one rollover request body (1 MiB). A larger body is refused with 413 before it is parsed: nothing is burned, nothing is charged.",
    },
    Spec {
        key: "transfer.fee_per_byte",
        env: "ESP_TRANSFER_FEE_PER_BYTE",
        default: "0",
        units: "ESP units per canonical byte",
        reload: true,
        what: "The transfer fee rate. 0 means no mint fee (the AIR send fee covers a transfer). If set, a request pays this times its canonical size (120 + 146 per note + 41 per output bytes), paid in ESP on top of the exact amount, at the rate in force when it is accepted; the rate is stored on the reply.",
    },
    Spec {
        key: "redeem.fee_per_byte",
        env: "ESP_REDEEM_FEE_PER_BYTE",
        default: "0",
        units: "ESP units per encoded byte",
        reload: true,
        what: "The redemption fee rate. 0 means no mint fee. If set, a request pays this times its encoded size, at the rate in force when it is accepted; the rate is stored on the reply and on the queue entry.",
    },
    Spec {
        key: "redeem.max_request_bytes",
        env: "ESP_REDEEM_MAX_BYTES",
        default: "67108864",
        units: "bytes",
        reload: true,
        what: "The ceiling on one encoded redemption request (64 MiB). A larger body is refused with 413 before it is parsed: no burn, no fee.",
    },
    Spec {
        key: "redeem.max_memo_bytes",
        env: "ESP_REDEEM_MAX_MEMO_BYTES",
        default: "256",
        units: "bytes",
        reload: true,
        what: "The longest payout memo in a redemption request.",
    },
    Spec {
        key: "redeem.max_reason_bytes",
        env: "ESP_REDEEM_MAX_REASON_BYTES",
        default: "1024",
        units: "bytes",
        reload: true,
        what: "The longest reason the operator may give when declining a payout.",
    },
    Spec {
        key: "admin.max_request_bytes",
        env: "ESP_ADMIN_MAX_BYTES",
        default: "1048576",
        units: "bytes",
        reload: false,
        what: "The ceiling on one request body on the operator's listener (1 MiB).",
    },
    Spec {
        key: "queue.max_payment_ref_bytes",
        env: "ESP_QUEUE_MAX_REF_BYTES",
        default: "256",
        units: "bytes",
        reload: true,
        what: "The longest payment reference accepted when an entry is marked paid.",
    },
    Spec {
        key: "storage.mint_state",
        env: "ESP_STORAGE_MINT_STATE",
        default: "",
        units: "service DIDs (66 hex characters)",
        reload: false,
        what: "Which AIR services keep this mint's state (keys, spent lists, records), as an ordered list of service IDs: index 0 is the primary and the rest are secondaries, in the order they would be promoted. A service ID is the service's AIR DID, a 33-byte compressed key in hex (66 characters, starting 02 or 03); the old 32-byte x-only form is refused. In the environment the IDs are separated by commas; in the file it is an array of strings or one such string. One entry: that service holds the state and the mint keeps a local backup copy. Empty (the default): local only. At most 8, no duplicates. Setting only for now: nothing reads or writes the AIR yet (see DESIGN.md in sandbox-mint, \"AIR storage requirements\").",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub network: String,
    pub bind: String,
    pub admin_bind: String,
    pub psp_url: String,
    pub psp_timeout_secs: u64,
    pub psp_startup_retry_secs: u64,
    pub maturity_days: u64,
    pub rotation_activation_hours: u64,
    pub rotation_period_hours: u64,
    pub exchange_max_items: usize,
    pub exchange_min_psp: u64,
    pub exchange_max_request_bytes: usize,
    pub exchange_fee_per_byte: u64,
    pub transfer_max_items: usize,
    pub transfer_max_request_bytes: usize,
    pub transfer_fee_per_byte: u64,
    pub rollover_max_items: usize,
    pub rollover_max_request_bytes: usize,
    pub admin_max_request_bytes: usize,
    pub redeem_fee_per_byte: u64,
    pub redeem_max_request_bytes: usize,
    pub redeem_max_memo_bytes: usize,
    pub redeem_max_reason_bytes: usize,
    pub queue_max_payment_ref_bytes: usize,
    /// Which AIR services keep this mint's state (setting only for now).
    pub storage_mint_state: StoragePolicy,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            network: "main".into(),
            bind: "127.0.0.1:3100".into(),
            admin_bind: "127.0.0.1:3101".into(),
            psp_url: "http://127.0.0.1:3000".into(),
            psp_timeout_secs: 30,
            psp_startup_retry_secs: 5,
            maturity_days: REDEEM_WINDOW_DAYS,
            rotation_activation_hours: 8760,
            rotation_period_hours: 87600,
            exchange_max_items: exchange::MAX_ITEMS,
            exchange_min_psp: 1,
            exchange_max_request_bytes: DEFAULT_SMALL_REQUEST_BYTES,
            exchange_fee_per_byte: 0,
            transfer_max_items: exchange::MAX_ITEMS,
            transfer_max_request_bytes: DEFAULT_SMALL_REQUEST_BYTES,
            transfer_fee_per_byte: 0,
            rollover_max_items: crate::rotation::MAX_ROLLOVER_NOTES,
            rollover_max_request_bytes: DEFAULT_SMALL_REQUEST_BYTES,
            admin_max_request_bytes: DEFAULT_SMALL_REQUEST_BYTES,
            redeem_fee_per_byte: redeem::DEFAULT_FEE_PER_BYTE as u64,
            redeem_max_request_bytes: redeem::DEFAULT_MAX_REQUEST_BYTES,
            redeem_max_memo_bytes: redeem::DEFAULT_MAX_MEMO_BYTES,
            redeem_max_reason_bytes: redeem::DEFAULT_MAX_REASON_BYTES,
            queue_max_payment_ref_bytes: queue::MAX_REF_LEN,
            storage_mint_state: StoragePolicy::default(),
        }
    }
}

fn whole<T: std::str::FromStr>(key: &str, value: &str) -> Result<T, String> {
    value
        .trim()
        .parse()
        .map_err(|_| format!("{key} = `{value}` is not a whole number (no sign, no decimals)"))
}

impl Config {
    /// The current value of a setting, as it is written in the file.
    pub fn get(&self, key: &str) -> Option<String> {
        Some(match key {
            "server.network" => self.network.clone(),
            "server.bind" => self.bind.clone(),
            "server.admin_bind" => self.admin_bind.clone(),
            "psp.url" => self.psp_url.clone(),
            "psp.timeout_secs" => self.psp_timeout_secs.to_string(),
            "psp.startup_retry_secs" => self.psp_startup_retry_secs.to_string(),
            "terms.maturity_days" => self.maturity_days.to_string(),
            "rotation.activation_hours" => self.rotation_activation_hours.to_string(),
            "rotation.period_hours" => self.rotation_period_hours.to_string(),
            "exchange.max_items" => self.exchange_max_items.to_string(),
            "exchange.min_psp" => self.exchange_min_psp.to_string(),
            "exchange.max_request_bytes" => self.exchange_max_request_bytes.to_string(),
            "exchange.fee_per_byte" => self.exchange_fee_per_byte.to_string(),
            "transfer.max_items" => self.transfer_max_items.to_string(),
            "transfer.max_request_bytes" => self.transfer_max_request_bytes.to_string(),
            "transfer.fee_per_byte" => self.transfer_fee_per_byte.to_string(),
            "rollover.max_items" => self.rollover_max_items.to_string(),
            "rollover.max_request_bytes" => self.rollover_max_request_bytes.to_string(),
            "admin.max_request_bytes" => self.admin_max_request_bytes.to_string(),
            "redeem.fee_per_byte" => self.redeem_fee_per_byte.to_string(),
            "redeem.max_request_bytes" => self.redeem_max_request_bytes.to_string(),
            "redeem.max_memo_bytes" => self.redeem_max_memo_bytes.to_string(),
            "redeem.max_reason_bytes" => self.redeem_max_reason_bytes.to_string(),
            "queue.max_payment_ref_bytes" => self.queue_max_payment_ref_bytes.to_string(),
            "storage.mint_state" => self.storage_mint_state.to_config_string(),
            _ => return None,
        })
    }

    /// Set one setting from text. Only checks that the text is the right kind of
    /// value; `validate` checks the ranges.
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        match key {
            "server.network" => self.network = network_name(value)?.to_string(),
            "server.bind" => self.bind = value.trim().to_string(),
            "server.admin_bind" => self.admin_bind = value.trim().to_string(),
            "psp.url" => self.psp_url = value.trim().to_string(),
            "psp.timeout_secs" => self.psp_timeout_secs = whole(key, value)?,
            "psp.startup_retry_secs" => self.psp_startup_retry_secs = whole(key, value)?,
            "terms.maturity_days" => self.maturity_days = whole(key, value)?,
            "rotation.activation_hours" => self.rotation_activation_hours = whole(key, value)?,
            "rotation.period_hours" => self.rotation_period_hours = whole(key, value)?,
            "exchange.max_items" => self.exchange_max_items = whole(key, value)?,
            "exchange.min_psp" => self.exchange_min_psp = whole(key, value)?,
            "exchange.max_request_bytes" => self.exchange_max_request_bytes = whole(key, value)?,
            "exchange.fee_per_byte" => self.exchange_fee_per_byte = whole(key, value)?,
            "transfer.max_items" => self.transfer_max_items = whole(key, value)?,
            "transfer.max_request_bytes" => self.transfer_max_request_bytes = whole(key, value)?,
            "transfer.fee_per_byte" => self.transfer_fee_per_byte = whole(key, value)?,
            "rollover.max_items" => self.rollover_max_items = whole(key, value)?,
            "rollover.max_request_bytes" => self.rollover_max_request_bytes = whole(key, value)?,
            "admin.max_request_bytes" => self.admin_max_request_bytes = whole(key, value)?,
            "redeem.fee_per_byte" => self.redeem_fee_per_byte = whole(key, value)?,
            "redeem.max_request_bytes" => self.redeem_max_request_bytes = whole(key, value)?,
            "redeem.max_memo_bytes" => self.redeem_max_memo_bytes = whole(key, value)?,
            "redeem.max_reason_bytes" => self.redeem_max_reason_bytes = whole(key, value)?,
            "queue.max_payment_ref_bytes" => self.queue_max_payment_ref_bytes = whole(key, value)?,
            "storage.mint_state" => {
                self.storage_mint_state =
                    StoragePolicy::parse(value).map_err(|e| format!("{key} = `{value}`: {e}"))?
            }
            other => return Err(format!("unknown setting `{other}`")),
        }
        Ok(())
    }

    /// Check every value and say everything that is wrong, not just the first.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut problems = Vec::new();
        let mut range = |key: &str, value: u64, low: u64, high: u64, why: &str| {
            if value < low || value > high {
                problems.push(format!(
                    "{key} = {value} is out of range: it must be from {low} to {high} ({why})"
                ));
            }
        };
        range("psp.timeout_secs", self.psp_timeout_secs, 1, 600, "seconds");
        range(
            "psp.startup_retry_secs",
            self.psp_startup_retry_secs,
            1,
            3600,
            "seconds",
        );
        range(
            "rotation.activation_hours",
            self.rotation_activation_hours,
            0,
            10_000_000,
            "hours; 0 turns rotation off",
        );
        range(
            "rotation.period_hours",
            self.rotation_period_hours,
            1,
            10_000_000,
            "hours; at least 1",
        );
        range(
            "terms.maturity_days",
            self.maturity_days,
            0,
            3650,
            "days; 0 makes notes redeemable the day they are issued",
        );
        range(
            "exchange.max_items",
            self.exchange_max_items as u64,
            1,
            100_000,
            "notes",
        );
        range(
            "exchange.min_psp",
            self.exchange_min_psp,
            1,
            1_000_000,
            "PSP; the exchange is exact in whole PSP",
        );
        range(
            "transfer.max_items",
            self.transfer_max_items as u64,
            1,
            100_000,
            "notes",
        );
        range(
            "rollover.max_items",
            self.rollover_max_items as u64,
            1,
            100_000,
            "notes",
        );
        for (key, value) in [
            (
                "exchange.max_request_bytes",
                self.exchange_max_request_bytes,
            ),
            (
                "transfer.max_request_bytes",
                self.transfer_max_request_bytes,
            ),
            (
                "rollover.max_request_bytes",
                self.rollover_max_request_bytes,
            ),
            ("admin.max_request_bytes", self.admin_max_request_bytes),
        ] {
            range(
                key,
                value as u64,
                MIN_SMALL_REQUEST_BYTES,
                1 << 30,
                "bytes; a request with one note and one output has to fit, and 1 GiB is the most the mint will hold in memory",
            );
        }
        for (key, value) in [
            ("exchange.fee_per_byte", self.exchange_fee_per_byte),
            ("transfer.fee_per_byte", self.transfer_fee_per_byte),
            ("redeem.fee_per_byte", self.redeem_fee_per_byte),
        ] {
            range(
                key,
                value,
                0,
                1_000_000_000_000_000,
                "ESP units per byte; 0 means no fee",
            );
        }
        range(
            "redeem.max_request_bytes",
            self.redeem_max_request_bytes as u64,
            redeem::MIN_REQUEST_BYTES,
            1 << 30,
            "bytes; the smallest possible request is 290 bytes, and 1 GiB is the most the mint will hold in memory",
        );
        range(
            "redeem.max_memo_bytes",
            self.redeem_max_memo_bytes as u64,
            1,
            1024,
            "bytes",
        );
        range(
            "redeem.max_reason_bytes",
            self.redeem_max_reason_bytes as u64,
            1,
            4096,
            "bytes",
        );
        range(
            "queue.max_payment_ref_bytes",
            self.queue_max_payment_ref_bytes as u64,
            1,
            4096,
            "bytes",
        );
        for (key, value) in [
            ("server.bind", &self.bind),
            ("server.admin_bind", &self.admin_bind),
        ] {
            if value.parse::<std::net::SocketAddr>().is_err() {
                problems.push(format!(
                    "{key} = `{value}` is not an address like 127.0.0.1:3100"
                ));
            }
        }
        match self.admin_bind.parse::<std::net::SocketAddr>() {
            Ok(addr) if !addr.ip().is_loopback() => problems.push(format!(
                "server.admin_bind = `{}` is not a loopback address. The admin routes are for the operator on this machine only",
                self.admin_bind
            )),
            _ => {}
        }
        if !(self.psp_url.starts_with("http://") || self.psp_url.starts_with("https://")) {
            problems.push(format!(
                "psp.url = `{}` must start with http:// or https://",
                self.psp_url
            ));
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }

    pub fn exchange_settings(&self) -> ExchangeSettings {
        ExchangeSettings {
            max_items: self.exchange_max_items,
            maturity_days: self.maturity_days,
            min_psp: self.exchange_min_psp,
            fee_per_byte: u128::from(self.exchange_fee_per_byte),
        }
    }

    pub fn transfer_settings(&self) -> TransferSettings {
        TransferSettings {
            max_items: self.transfer_max_items,
            fee_per_byte: u128::from(self.transfer_fee_per_byte),
        }
    }

    pub fn redeem_settings(&self) -> RedeemSettings {
        RedeemSettings {
            fee_per_byte: u128::from(self.redeem_fee_per_byte),
            max_memo_bytes: self.redeem_max_memo_bytes,
            max_reason_bytes: self.redeem_max_reason_bytes,
        }
    }

    /// The settings that cannot change while the mint runs, put back to what the
    /// running mint has. Returns the keys whose new value was therefore ignored.
    fn keep_restart_only(&mut self, running: &Config) -> Vec<&'static str> {
        let mut ignored = Vec::new();
        for spec in SPECS.iter().filter(|s| !s.reload) {
            if self.get(spec.key) != running.get(spec.key) {
                ignored.push(spec.key);
            }
        }
        self.bind = running.bind.clone();
        self.admin_bind = running.admin_bind.clone();
        self.psp_url = running.psp_url.clone();
        self.psp_timeout_secs = running.psp_timeout_secs;
        self.psp_startup_retry_secs = running.psp_startup_retry_secs;
        self.admin_max_request_bytes = running.admin_max_request_bytes;
        self.storage_mint_state = running.storage_mint_state.clone();
        ignored
    }
}

/// Where a value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Default,
    File,
    Env(&'static str),
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Default => write!(f, "default"),
            Source::File => write!(f, "file"),
            Source::Env(name) => write!(f, "env {name}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    pub config: Config,
    pub sources: BTreeMap<&'static str, Source>,
    /// The file that was read, if there was one.
    pub file: Option<PathBuf>,
}

impl Loaded {
    /// One line for each setting, for the startup log.
    pub fn describe(&self) -> Vec<String> {
        SPECS
            .iter()
            .map(|spec| {
                let value = self.config.get(spec.key).unwrap_or_default();
                let source = self
                    .sources
                    .get(spec.key)
                    .cloned()
                    .unwrap_or(Source::Default);
                format!("  {} = {} {} ({source})", spec.key, value, spec.units)
            })
            .collect()
    }
}

/// Where the file is: `ESP_CONFIG` if set (and then it must exist), otherwise
/// `esp-mint.toml` in the data directory (and then it may be missing).
pub fn file_path(data_dir: &Path, env: &dyn Fn(&str) -> Option<String>) -> (PathBuf, bool) {
    match env(FILE_ENV) {
        Some(path) if !path.is_empty() => (PathBuf::from(path), true),
        _ => (data_dir.join(FILE_NAME), false),
    }
}

/// Read the file text into `(key, value)` pairs, rejecting anything that is not
/// a known `[section]` of plain values.
fn parse_file(text: &str) -> Result<Vec<(String, String)>, Vec<String>> {
    let table: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| vec![format!("not valid TOML: {}", e.message())])?;
    let mut pairs = Vec::new();
    let mut problems = Vec::new();
    for (section, body) in &table {
        let Some(body) = body.as_table() else {
            problems.push(format!(
                "`{section}` must be a [section] of settings, not a single value"
            ));
            continue;
        };
        for (name, value) in body {
            let key = format!("{section}.{name}");
            if !SPECS.iter().any(|s| s.key == key) {
                problems.push(format!("unknown setting `{key}`"));
                continue;
            }
            match value {
                toml::Value::Integer(n) => pairs.push((key, n.to_string())),
                toml::Value::String(s) => pairs.push((key, s.clone())),
                toml::Value::Array(items) if key.starts_with("storage.") => {
                    let ids: Vec<&str> = items.iter().filter_map(|v| v.as_str()).collect();
                    if ids.len() == items.len() {
                        pairs.push((key, ids.join(",")));
                    } else {
                        problems.push(format!(
                            "{key} must be a list of strings (service IDs), not {items:?}"
                        ));
                    }
                }
                _ => problems.push(format!(
                    "{key} must be a whole number or a string, not {}",
                    value.type_str()
                )),
            }
        }
    }
    if problems.is_empty() {
        Ok(pairs)
    } else {
        Err(problems)
    }
}

/// Load the settings: defaults, then the file, then the environment, then check.
/// `env` looks up an environment variable.
pub fn load(data_dir: &Path, env: &dyn Fn(&str) -> Option<String>) -> Result<Loaded, Vec<String>> {
    let (path, must_exist) = file_path(data_dir, env);
    let mut config = Config::default();
    let mut sources: BTreeMap<&'static str, Source> = BTreeMap::new();
    let mut problems = Vec::new();
    let mut file = None;

    match fs::read_to_string(&path) {
        Ok(text) => {
            file = Some(path.clone());
            match parse_file(&text) {
                Ok(pairs) => {
                    for (key, value) in pairs {
                        match config.set(&key, &value) {
                            Ok(()) => {
                                if let Some(spec) = SPECS.iter().find(|s| s.key == key) {
                                    sources.insert(spec.key, Source::File);
                                }
                            }
                            Err(e) => problems.push(format!("{}: {e}", path.display())),
                        }
                    }
                }
                Err(list) => {
                    problems.extend(list.into_iter().map(|p| format!("{}: {p}", path.display())))
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && !must_exist => {}
        Err(e) => problems.push(format!("cannot read config file {}: {e}", path.display())),
    }

    for spec in SPECS {
        if let Some(value) = env(spec.env) {
            if value.is_empty() {
                continue;
            }
            match config.set(spec.key, &value) {
                Ok(()) => {
                    sources.insert(spec.key, Source::Env(spec.env));
                }
                Err(e) => problems.push(format!("environment variable {}: {e}", spec.env)),
            }
        }
    }

    if problems.is_empty() {
        if let Err(list) = config.validate() {
            problems.extend(list);
        }
    }
    if problems.is_empty() {
        Ok(Loaded {
            config,
            sources,
            file,
        })
    } else {
        Err(problems)
    }
}

/// The running mint's settings, swapped all at once on a reload.
pub struct Handle {
    inner: RwLock<Arc<Config>>,
}

impl Handle {
    pub fn new(config: Config) -> Self {
        Handle {
            inner: RwLock::new(Arc::new(config)),
        }
    }

    /// The settings now in force. A request takes this once, at the start, and
    /// uses it throughout.
    pub fn current(&self) -> Arc<Config> {
        match self.inner.read() {
            Ok(guard) => Arc::clone(&guard),
            // A writer only swaps a pointer, so a poisoned lock still holds a
            // whole config.
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    fn replace(&self, config: Config) {
        let next = Arc::new(config);
        match self.inner.write() {
            Ok(mut guard) => *guard = next,
            Err(poisoned) => *poisoned.into_inner() = next,
        }
    }

    /// Read the file and the environment again. On success the new settings are
    /// in force at once, except the ones that need a restart, which keep their
    /// running value. On any problem nothing changes. Returns what to log.
    pub fn reload(
        &self,
        data_dir: &Path,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Vec<String>, Vec<String>> {
        let loaded = load(data_dir, env)?;
        let running = self.current();
        let mut next = loaded.config;
        let ignored = next.keep_restart_only(&running);
        let mut lines = Vec::new();
        for spec in SPECS {
            let before = running.get(spec.key).unwrap_or_default();
            let after = next.get(spec.key).unwrap_or_default();
            if before != after {
                lines.push(format!(
                    "  {} changed from {before} to {after} {}",
                    spec.key, spec.units
                ));
            }
        }
        for key in ignored {
            lines.push(format!(
                "  {key} is changed in the file but needs a restart, so it stays {}",
                running.get(key).unwrap_or_default()
            ));
        }
        if lines.is_empty() {
            lines.push("  no setting changed".to_string());
        }
        self.replace(next);
        Ok(lines)
    }
}

impl Default for Handle {
    fn default() -> Self {
        Handle::new(Config::default())
    }
}

/// The real environment.
pub fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("esp-mint-cfg-{}-{name}", {
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

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn the_storage_policy_comes_from_the_file_and_the_environment() {
        const A: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        const B: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        let dir = scratch("storage");
        let first = load(&dir, &no_env).unwrap();
        assert!(first.config.storage_mint_state.is_local_only());
        assert_eq!(first.config.get("storage.mint_state").as_deref(), Some(""));

        fs::write(
            dir.join(FILE_NAME),
            format!("[storage]\nmint_state = [\"{A}\", \"{B}\"]\n"),
        )
        .unwrap();
        let l = load(&dir, &no_env).unwrap();
        let p = &l.config.storage_mint_state;
        assert_eq!(p.primary().unwrap().to_hex(), A);
        assert_eq!(p.secondaries().len(), 1);
        assert_eq!(l.sources["storage.mint_state"], Source::File);
        assert_eq!(
            l.config.get("storage.mint_state").unwrap(),
            format!("{A},{B}")
        );

        // The environment wins over the file. One entry is valid.
        let l = load(&dir, &env_of(&[("ESP_STORAGE_MINT_STATE", A)])).unwrap();
        assert_eq!(l.config.storage_mint_state.to_config_string(), A);
        assert!(l.config.storage_mint_state.secondaries().is_empty());
        assert_eq!(
            l.sources["storage.mint_state"],
            Source::Env("ESP_STORAGE_MINT_STATE")
        );

        // One string in the file works too, and so does an empty list.
        fs::write(
            dir.join(FILE_NAME),
            format!("[storage]\nmint_state = \"{B}, {A}\"\n"),
        )
        .unwrap();
        let l = load(&dir, &no_env).unwrap();
        assert_eq!(l.config.storage_mint_state.primary().unwrap().to_hex(), B);
        fs::write(dir.join(FILE_NAME), "[storage]\nmint_state = []\n").unwrap();
        let l = load(&dir, &no_env).unwrap();
        assert!(l.config.storage_mint_state.is_local_only());

        // Every kind of mistake is refused, naming the variable or the setting.
        let twice = format!("{A},{A}");
        let p = load(&dir, &env_of(&[("ESP_STORAGE_MINT_STATE", twice.as_str())])).unwrap_err();
        assert!(
            p.iter()
                .any(|x| x.contains("ESP_STORAGE_MINT_STATE") && x.contains("listed twice")),
            "{p:?}"
        );
        let gap = format!("{A},,{B}");
        let p = load(&dir, &env_of(&[("ESP_STORAGE_MINT_STATE", gap.as_str())])).unwrap_err();
        assert!(p.iter().any(|x| x.contains("entry 2")), "{p:?}");
        let p = load(&dir, &env_of(&[("ESP_STORAGE_MINT_STATE", "not-a-key")])).unwrap_err();
        assert!(p.iter().any(|x| x.contains("must be hex")), "{p:?}");
        // The 32-byte x-only form of wire version 2 is refused, and says why.
        let old_form = &A[2..];
        let p = load(&dir, &env_of(&[("ESP_STORAGE_MINT_STATE", old_form)])).unwrap_err();
        assert!(p.iter().any(|x| x.contains("x-only")), "{p:?}");
        fs::write(dir.join(FILE_NAME), "[storage]\nmint_state = [1]\n").unwrap();
        let p = load(&dir, &no_env).unwrap_err();
        assert!(p.iter().any(|x| x.contains("list of strings")), "{p:?}");
        fs::write(dir.join(FILE_NAME), "[storage]\nwallet = \"x\"\n").unwrap();
        let p = load(&dir, &no_env).unwrap_err();
        assert!(
            p.iter()
                .any(|x| x.contains("unknown setting `storage.wallet`")),
            "{p:?}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn with_no_file_and_no_environment_every_setting_is_its_documented_default() {
        let dir = scratch("defaults");
        let loaded = load(&dir, &no_env).unwrap();
        assert_eq!(loaded.config, Config::default());
        assert!(loaded.file.is_none());
        assert!(loaded.sources.is_empty());
        for spec in SPECS {
            assert_eq!(
                loaded.config.get(spec.key).as_deref(),
                Some(spec.default),
                "{} default in SPECS",
                spec.key
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_spec_has_a_getter_a_setter_and_a_unique_key_and_variable() {
        let mut keys = std::collections::HashSet::new();
        let mut envs = std::collections::HashSet::new();
        for spec in SPECS {
            assert!(keys.insert(spec.key), "{} twice", spec.key);
            assert!(envs.insert(spec.env), "{} twice", spec.env);
            let mut c = Config::default();
            let value = c.get(spec.key).unwrap();
            c.set(spec.key, &value).unwrap();
            assert_eq!(c, Config::default());
            assert!(spec.env.starts_with("ESP_"));
            assert!(!spec.what.is_empty() && !spec.units.is_empty());
        }
        assert!(Config::default().get("nope").is_none());
        assert!(Config::default().set("nope", "1").is_err());
    }

    #[test]
    fn the_defaults_are_the_ones_the_design_sets() {
        let c = Config::default();
        assert_eq!(c.maturity_days, 365);
        assert_eq!(c.redeem_fee_per_byte, 0);
        assert_eq!(c.redeem_max_request_bytes, 64 * 1024 * 1024);
        assert_eq!(c.redeem_max_memo_bytes, 256);
        assert_eq!(c.redeem_max_reason_bytes, 1024);
        assert_eq!(c.exchange_max_items, 1000);
        assert_eq!(c.exchange_min_psp, 1);
        assert_eq!(c.transfer_max_items, 1000);
        assert_eq!(c.rollover_max_items, 1000);
        assert_eq!(c.rollover_max_request_bytes, 1024 * 1024);
        // exchange and transfer: 1 MiB ceilings and no fee, so nothing changes
        // for a wallet that does not know about them
        assert_eq!(c.exchange_max_request_bytes, 1024 * 1024);
        assert_eq!(c.transfer_max_request_bytes, 1024 * 1024);
        assert_eq!(c.admin_max_request_bytes, 1024 * 1024);
        assert_eq!(c.exchange_fee_per_byte, 0);
        assert_eq!(c.transfer_fee_per_byte, 0);
        // every fee defaults to 0
        assert_eq!(c.redeem_settings().fee_per_byte, 0);
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn the_file_overrides_defaults_and_the_environment_overrides_the_file() {
        let dir = scratch("layers");
        fs::write(
            dir.join(FILE_NAME),
            "[redeem]\nfee_per_byte = 2000000\nmax_memo_bytes = 128\n[terms]\nmaturity_days = 30\n[psp]\nurl = \"http://10.0.0.5:3000\"\n",
        )
        .unwrap();
        let loaded = load(&dir, &env_of(&[("ESP_REDEEM_FEE_PER_BYTE", "3000000")])).unwrap();
        let c = &loaded.config;
        assert_eq!(c.redeem_fee_per_byte, 3_000_000);
        assert_eq!(c.redeem_max_memo_bytes, 128);
        assert_eq!(c.maturity_days, 30);
        assert_eq!(c.psp_url, "http://10.0.0.5:3000");
        assert_eq!(c.redeem_max_request_bytes, 64 * 1024 * 1024);
        assert_eq!(
            loaded.sources.get("redeem.fee_per_byte"),
            Some(&Source::Env("ESP_REDEEM_FEE_PER_BYTE"))
        );
        assert_eq!(
            loaded.sources.get("redeem.max_memo_bytes"),
            Some(&Source::File)
        );
        assert_eq!(loaded.sources.get("redeem.max_request_bytes"), None);
        assert_eq!(loaded.file, Some(dir.join(FILE_NAME)));
        // the log has a line for every setting, with where it came from
        let lines = loaded.describe();
        assert_eq!(lines.len(), SPECS.len());
        assert!(
            lines
                .iter()
                .any(|l| l.contains("redeem.fee_per_byte = 3000000")
                    && l.contains("env ESP_REDEEM_FEE_PER_BYTE"))
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("terms.maturity_days = 30") && l.contains("(file)"))
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("exchange.max_items = 1000") && l.contains("(default)"))
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_config_file_named_by_the_environment_must_exist() {
        let dir = scratch("named");
        let named = dir.join("elsewhere.toml");
        let env = env_of(&[("ESP_CONFIG", named.to_str().unwrap())]);
        let problems = load(&dir, &env).unwrap_err();
        assert!(problems[0].contains("cannot read config file"));
        fs::write(&named, "[terms]\nmaturity_days = 7\n").unwrap();
        assert_eq!(load(&dir, &env).unwrap().config.maturity_days, 7);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unknown_key_a_wrong_type_and_bad_toml_are_all_refused_with_a_clear_message() {
        let dir = scratch("bad-file");
        let write = |text: &str| fs::write(dir.join(FILE_NAME), text).unwrap();

        write("[redeem]\nfee_per_bite = 5\n");
        let p = load(&dir, &no_env).unwrap_err();
        assert!(
            p.iter()
                .any(|m| m.contains("unknown setting `redeem.fee_per_bite`")),
            "{p:?}"
        );

        write("[tims]\nmaturity_days = 5\n");
        let p = load(&dir, &no_env).unwrap_err();
        assert!(
            p.iter()
                .any(|m| m.contains("unknown setting `tims.maturity_days`")),
            "{p:?}"
        );

        write("maturity_days = 5\n");
        let p = load(&dir, &no_env).unwrap_err();
        assert!(p.iter().any(|m| m.contains("must be a [section]")), "{p:?}");

        write("[redeem]\nfee_per_byte = 1.5\n");
        let p = load(&dir, &no_env).unwrap_err();
        assert!(
            p.iter()
                .any(|m| m.contains("redeem.fee_per_byte must be a whole number or a string")),
            "{p:?}"
        );

        write("[redeem]\nfee_per_byte = \"lots\"\n");
        let p = load(&dir, &no_env).unwrap_err();
        assert!(
            p.iter().any(|m| m.contains("`lots` is not a whole number")),
            "{p:?}"
        );

        write("[redeem\nfee_per_byte = 5\n");
        let p = load(&dir, &no_env).unwrap_err();
        assert!(p.iter().any(|m| m.contains("not valid TOML")), "{p:?}");
        assert!(p[0].contains(FILE_NAME));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn out_of_range_values_are_listed_all_at_once() {
        let dir = scratch("ranges");
        fs::write(
            dir.join(FILE_NAME),
            "[redeem]\nfee_per_byte = 2000000000000000\nmax_request_bytes = 100\nmax_memo_bytes = 5000\n[terms]\nmaturity_days = 99999\n[server]\nadmin_bind = \"0.0.0.0:3101\"\n",
        )
        .unwrap();
        let problems = load(&dir, &no_env).unwrap_err();
        let all = problems.join("\n");
        assert!(
            all.contains("redeem.fee_per_byte = 2000000000000000 is out of range"),
            "{all}"
        );
        assert!(
            all.contains("redeem.max_request_bytes = 100 is out of range"),
            "{all}"
        );
        assert!(
            all.contains("redeem.max_memo_bytes = 5000 is out of range"),
            "{all}"
        );
        assert!(
            all.contains("terms.maturity_days = 99999 is out of range"),
            "{all}"
        );
        assert!(all.contains("not a loopback address"), "{all}");
        assert!(problems.len() >= 5);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_bad_environment_value_names_the_variable() {
        let dir = scratch("bad-env");
        let p = load(&dir, &env_of(&[("ESP_REDEEM_MAX_BYTES", "64MB")])).unwrap_err();
        assert!(
            p[0].contains("environment variable ESP_REDEEM_MAX_BYTES"),
            "{p:?}"
        );
        let p = load(&dir, &env_of(&[("ESP_PSP_URL", "ftp://x")])).unwrap_err();
        assert!(p[0].contains("psp.url"), "{p:?}");
        let p = load(&dir, &env_of(&[("ESP_BIND", "localhost")])).unwrap_err();
        assert!(p[0].contains("server.bind"), "{p:?}");
        // an empty variable is the same as not set
        assert!(load(&dir, &env_of(&[("ESP_REDEEM_MAX_BYTES", "")])).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_settings_become_the_settings_structs_the_mint_uses() {
        let c = Config {
            maturity_days: 30,
            exchange_max_items: 10,
            exchange_min_psp: 5,
            redeem_fee_per_byte: 7,
            redeem_max_memo_bytes: 99,
            redeem_max_reason_bytes: 55,
            exchange_fee_per_byte: 11,
            transfer_fee_per_byte: 13,
            transfer_max_items: 20,
            ..Config::default()
        };
        let e = c.exchange_settings();
        assert_eq!((e.max_items, e.maturity_days, e.min_psp), (10, 30, 5));
        assert_eq!(e.fee_per_byte, 11);
        let t = c.transfer_settings();
        assert_eq!((t.max_items, t.fee_per_byte), (20, 13));
        let r = c.redeem_settings();
        assert_eq!(
            (r.fee_per_byte, r.max_memo_bytes, r.max_reason_bytes),
            (7, 99, 55)
        );
    }

    #[test]
    fn a_reload_swaps_in_the_new_values_and_keeps_the_old_ones_on_any_problem() {
        let dir = scratch("reload");
        let handle = Handle::new(load(&dir, &no_env).unwrap().config);
        assert_eq!(handle.current().redeem_fee_per_byte, 0);
        let before = handle.current();

        fs::write(dir.join(FILE_NAME), "[redeem]\nfee_per_byte = 5000000\n").unwrap();
        let lines = handle.reload(&dir, &no_env).unwrap();
        assert_eq!(handle.current().redeem_fee_per_byte, 5_000_000);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("redeem.fee_per_byte changed from 0 to 5000000"))
        );
        // a request that took its settings before still has the old ones
        assert_eq!(before.redeem_fee_per_byte, 0);

        // a bad file changes nothing
        fs::write(
            dir.join(FILE_NAME),
            "[redeem]\nfee_per_byte = 2000000000000000\n",
        )
        .unwrap();
        assert!(handle.reload(&dir, &no_env).is_err());
        assert_eq!(handle.current().redeem_fee_per_byte, 5_000_000);

        // removing the file puts the defaults back
        fs::remove_file(dir.join(FILE_NAME)).unwrap();
        handle.reload(&dir, &no_env).unwrap();
        assert_eq!(handle.current().redeem_fee_per_byte, 0);
        // and nothing changing says so
        let lines = handle.reload(&dir, &no_env).unwrap();
        assert_eq!(lines, vec!["  no setting changed".to_string()]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_reload_does_not_change_addresses_or_the_psp_client_and_says_so() {
        let dir = scratch("reload-restart");
        let handle = Handle::new(load(&dir, &no_env).unwrap().config);
        fs::write(
            dir.join(FILE_NAME),
            "[server]\nbind = \"127.0.0.1:4100\"\n[psp]\nurl = \"http://127.0.0.1:4000\"\ntimeout_secs = 5\n[terms]\nmaturity_days = 10\n",
        )
        .unwrap();
        let lines = handle.reload(&dir, &no_env).unwrap();
        let c = handle.current();
        assert_eq!(c.bind, "127.0.0.1:3100");
        assert_eq!(c.psp_url, "http://127.0.0.1:3000");
        assert_eq!(c.psp_timeout_secs, 30);
        assert_eq!(c.psp_startup_retry_secs, 5);
        assert_eq!(c.maturity_days, 10);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("server.bind is changed in the file but needs a restart"))
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("psp.url is changed in the file but needs a restart"))
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("psp.timeout_secs is changed in the file but needs a restart"))
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_restart_only_settings_are_exactly_the_ones_a_reload_cannot_apply() {
        let restart: Vec<&str> = SPECS.iter().filter(|s| !s.reload).map(|s| s.key).collect();
        assert_eq!(
            restart,
            vec![
                "server.network",
                "server.bind",
                "server.admin_bind",
                "psp.url",
                "psp.timeout_secs",
                "psp.startup_retry_secs",
                "rotation.activation_hours",
                "rotation.period_hours",
                "admin.max_request_bytes",
                "storage.mint_state"
            ]
        );
    }

    #[test]
    fn the_per_route_ceilings_and_fees_are_checked_and_listed_with_their_problems() {
        let dir = scratch("route-limits");
        fs::write(
            dir.join(FILE_NAME),
            "[exchange]\nmax_request_bytes = 100\nfee_per_byte = 2000000000000000\n[transfer]\nmax_request_bytes = 5000000000\n",
        )
        .unwrap();
        let all = load(&dir, &no_env).unwrap_err().join("\n");
        assert!(
            all.contains("exchange.max_request_bytes = 100 is out of range"),
            "{all}"
        );
        assert!(
            all.contains("exchange.fee_per_byte = 2000000000000000 is out of range"),
            "{all}"
        );
        assert!(
            all.contains("transfer.max_request_bytes = 5000000000 is out of range"),
            "{all}"
        );
        // the environment overrides the file, so it can put every bad value right
        let fixed = load(
            &dir,
            &env_of(&[
                ("ESP_EXCHANGE_MAX_BYTES", "65536"),
                ("ESP_EXCHANGE_FEE_PER_BYTE", "0"),
                ("ESP_TRANSFER_MAX_BYTES", "4096"),
                ("ESP_ROLLOVER_MAX_BYTES", "8192"),
                ("ESP_ROLLOVER_MAX_ITEMS", "50"),
            ]),
        )
        .unwrap();
        assert_eq!(fixed.config.exchange_fee_per_byte, 0);
        assert_eq!(fixed.config.transfer_max_request_bytes, 4096);
        assert_eq!(fixed.config.rollover_max_request_bytes, 8192);
        assert_eq!(fixed.config.rollover_max_items, 50);
        fs::write(dir.join(FILE_NAME), "").unwrap();
        let ok = load(
            &dir,
            &env_of(&[
                ("ESP_EXCHANGE_MAX_BYTES", "65536"),
                ("ESP_EXCHANGE_FEE_PER_BYTE", "3"),
                ("ESP_TRANSFER_FEE_PER_BYTE", "4"),
            ]),
        )
        .unwrap();
        assert_eq!(ok.config.exchange_max_request_bytes, 65536);
        assert_eq!(ok.config.exchange_fee_per_byte, 3);
        assert_eq!(ok.config.transfer_fee_per_byte, 4);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_reload_changes_the_exchange_and_transfer_rates_for_the_next_request() {
        let dir = scratch("reload-rates");
        let handle = Handle::new(load(&dir, &no_env).unwrap().config);
        let before = handle.current();
        assert_eq!(before.exchange_settings().fee_per_byte, 0);
        fs::write(
            dir.join(FILE_NAME),
            "[exchange]\nfee_per_byte = 5\nmax_request_bytes = 8192\n[transfer]\nfee_per_byte = 6\n",
        )
        .unwrap();
        let lines = handle.reload(&dir, &no_env).unwrap();
        let after = handle.current();
        assert_eq!(after.exchange_settings().fee_per_byte, 5);
        assert_eq!(after.transfer_settings().fee_per_byte, 6);
        assert_eq!(after.exchange_max_request_bytes, 8192);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("exchange.fee_per_byte changed from 0 to 5"))
        );
        // the settings a request already took are not touched
        assert_eq!(before.exchange_settings().fee_per_byte, 0);
        fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;

    #[test]
    fn the_network_is_a_setting_checked_against_the_psp() {
        let mut c = Config::default();
        assert_eq!(c.network, "main");
        c.set("server.network", "mainnet").unwrap();
        assert_eq!(c.get("server.network").as_deref(), Some("main"));
        c.set("server.network", "regtest").unwrap();
        assert!(c.set("server.network", "moon").is_err());
        assert_eq!(check_psp_network("regtest", Some("regtest")), Ok(()));
        let e = check_psp_network("main", Some("regtest")).unwrap_err();
        assert!(
            e.contains("Refusing to start") && e.contains("regtest"),
            "{e}"
        );
        assert!(check_psp_network("main", None).is_err());
        let spec = SPECS.iter().find(|s| s.key == "server.network").unwrap();
        assert_eq!(
            (spec.env, spec.default, spec.reload),
            ("ESP_NETWORK", "main", false)
        );
    }
}
