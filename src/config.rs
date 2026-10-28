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
//! environment again, checks the result, and applies it without stopping, or
//! keeps the old values and says why. A request already running finishes with
//! the values it started with, and every request is charged at the rate in force
//! when it was accepted. Each setting is one of two kinds (`reload` in `SPECS`):
//!
//! - **live**: swapped in at once, for the next request;
//! - **needs a restart** (`reload` false: the addresses, the network, the PSP
//!   address, rotation, the storage list, the AIR settings and the admin body
//!   ceiling): these shape something that is opened once when a process starts (a
//!   socket, the databases, the AIR connection), so they cannot be swapped under a
//!   running request. A `SIGHUP` that changes one names it in the log; the old
//!   value stays in force until the mint is restarted, which is a brief downtime.
//!
//! A reload stops nothing and refuses no connection. `spi reload` sends the
//! `SIGHUP`.

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

// ---- the caps ----------------------------------------------------------------
//
// Every size ceiling and every fee rate has a hard cap (and a ceiling a floor),
// checked when the settings load, so that no setting can reach a value that
// breaks the mint's own routes. The numbers and the reasoning are in DESIGN.md,
// "Caps on sizes and fees"; the sums are checked at compile time below.

/// The most any request ceiling (`*.max_request_bytes`) may be: 15 MiB, the
/// largest message AIR carries (16 MiB) less the room kept for the envelope, its
/// seal and AIR's framing ([`redeem::AIR_ROOM`]). A higher ceiling would let the
/// mint take a request that no wallet can send.
pub const MAX_REQUEST_BYTES_CAP: u64 = redeem::DEFAULT_MAX_REQUEST_BYTES as u64;
/// The least a ceiling on a JSON request (exchange, transfer, rollover, or the
/// operator's listener) may be: 16 KiB. The largest one-note request is about
/// 8.1 KB: one note and 64 outputs (one amount splits into at most 64 powers of
/// two), each at its widest in JSON.
pub const MIN_SMALL_REQUEST_BYTES: u64 = 16 * 1024;
/// The least `redeem.max_request_bytes` may be: 12 KiB. A wallet sizes a
/// redemption for the worst case of 64 decline and 64 refund outputs a service
/// and day can need, which is 10,803 bytes for one note and no memo, and 11,827
/// with the longest memo the mint allows ([`MAX_MEMO_BYTES_CAP`]).
pub const MIN_REDEEM_REQUEST_BYTES: u64 = 12 * 1024;
/// The longest `redeem.max_memo_bytes` may be.
pub const MAX_MEMO_BYTES_CAP: u64 = 1024;
/// The most outputs one amount can need: a `u64` splits into at most 64 powers
/// of two. The wallet's `MAX_OUTPUTS_PER_TERMS` is the same number.
pub const MAX_OUTPUTS_ONE_AMOUNT: u64 = 64;
/// The least `exchange.max_items` and `transfer.max_items` may be: the outputs
/// one amount can need, so that a one-note request always fits.
pub const MIN_ITEMS: u64 = MAX_OUTPUTS_ONE_AMOUNT;

/// The smallest `stream.record_max_bytes`: 1 MiB, which holds a bucket of 256
/// services (34 + 256 x 2,145 = 549,154 bytes) with room for a bucket that
/// the hash filled past the average.
pub const MIN_STREAM_RECORD_BYTES: u64 = 1024 * 1024;

/// The largest `stream.record_max_bytes`: AIR's 16 MiB message cap less the
/// 1 MiB the mint keeps free (`sp_wire::air_request::stream::RECORD_MAX_BYTES`).
pub const MAX_STREAM_RECORD_BYTES: u64 = sp_wire::air_request::stream::RECORD_MAX_BYTES as u64;

/// The largest `stream.max_services`.
pub const MAX_STREAM_SERVICES: u64 = 100_000;
/// The most `*.max_items` may be: 25,000. At about 500 bytes for a note and an
/// output in JSON (the widest pair is 501) a request of that many is 12.5 MB,
/// which fits [`MAX_REQUEST_BYTES_CAP`]; a higher count could not.
pub const MAX_ITEMS_CAP: u64 = 25_000;
/// The smallest note a fee is held against: 1 PSP of ESP, 10^11 units ($0.10).
/// That is the smallest exchange the mint takes (`exchange.min_psp` is at least
/// 1). Smaller ESP notes exist only as the pieces of a larger exchange, and are
/// worth less than any fee above 0 whatever the rate.
pub const SMALLEST_NOTE_ESP: u64 = crate::units::ESP_PER_PSP;
/// The most `exchange.fee_per_byte` and `transfer.fee_per_byte` may be:
/// 30,000,000 ESP units a byte, which makes the worst one-note request (2,891
/// canonical bytes) cost 86.7 billion units, under the smallest note.
pub const EXCHANGE_FEE_CAP: u64 = 30_000_000;
pub const TRANSFER_FEE_CAP: u64 = 30_000_000;
/// The most `redeem.fee_per_byte` may be: 8,000,000 ESP units a byte, which
/// makes the worst one-note redemption (11,827 bytes) cost 94.6 billion units,
/// under the smallest note.
pub const REDEEM_FEE_CAP: u64 = 8_000_000;

const _: () = {
    use sp_wire::esp::redeem as wire;
    // the worst one-note redemption at the wallet's sizing, with the longest memo
    let redeem_worst = wire::FIXED_BYTES
        + wire::INPUT_BYTES
        + MAX_MEMO_BYTES_CAP
        + 2 * MAX_OUTPUTS_ONE_AMOUNT * wire::OUTPUT_BYTES;
    assert!(MIN_REDEEM_REQUEST_BYTES >= redeem_worst);
    assert!(REDEEM_FEE_CAP * redeem_worst <= SMALLEST_NOTE_ESP);
    // the worst one-note exchange and transfer, in canonical bytes
    let exchange_worst = crate::fee::EXCHANGE_FIXED_BYTES
        + crate::fee::INPUT_BYTES
        + MAX_OUTPUTS_ONE_AMOUNT * crate::fee::OUTPUT_BYTES;
    let transfer_worst = crate::fee::TRANSFER_FIXED_BYTES
        + crate::fee::INPUT_BYTES
        + MAX_OUTPUTS_ONE_AMOUNT * crate::fee::OUTPUT_BYTES;
    assert!(EXCHANGE_FEE_CAP * exchange_worst <= SMALLEST_NOTE_ESP);
    assert!(TRANSFER_FEE_CAP * transfer_worst <= SMALLEST_NOTE_ESP);
    // a request of the most items fits the largest request ceiling (the widest
    // JSON note-and-output pair is 501 bytes)
    assert!(MAX_ITEMS_CAP * 501 < MAX_REQUEST_BYTES_CAP);
    // the widest JSON request this mint takes, one note and 64 outputs of a
    // transfer, is 8,056 bytes; the smallest ceiling is twice that, near enough
    assert!(MIN_SMALL_REQUEST_BYTES >= 2 * 8_056);
};

/// Settings that were taken out, with the environment variable each had and what
/// replaces it. A file or an environment that still names one is refused with this
/// text, not with "unknown setting".
pub const REMOVED: &[(&str, &str, &str)] = &[(
    "air.enabled",
    "ESP_AIR_ENABLED",
    "`air.enabled` is gone: the AIR listener always runs, because AIR is the only way wallets reach this mint (there is no HTTP API for them). Remove air.enabled; serve needs air.server and air.host (ESP_AIR_SERVER, ESP_AIR_HOST)",
)];

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
        what: "The Bitcoin network of the PSP this mint burns at: main, regtest, signet or testnet. At startup the mint asks the PSP (`GET /health`, a local call inside the SPI) and refuses to start if the PSP is on another network. Reported in mint info (over AIR) and in `/health`.",
    },
    Spec {
        key: "server.bind",
        env: "ESP_BIND",
        default: "127.0.0.1:3100",
        units: "host:port",
        reload: false,
        what: "The address of the HTTP API that is left: `/audit` (the operator's report) and `/health` (read by `spi` and the health monitor). Must be a loopback address: wallets reach this mint over AIR only, never over HTTP.",
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
        reload: true,
        what: "How long a call to the PSP may take before the exchange fails and can be retried.",
    },
    Spec {
        key: "psp.startup_retry_secs",
        env: "ESP_PSP_STARTUP_RETRY_SECS",
        default: "5",
        units: "seconds",
        reload: true,
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
        key: "stream.days_ahead",
        env: "ESP_STREAM_DAYS_AHEAD",
        default: "2",
        units: "days",
        reload: true,
        what: "How many days of per-service keys the mint publishes ahead on its AIR stream, for the current key set: the day a new exchange gets (today + terms.maturity_days) and the days after it, so a wallet finds the keys it checks a reply against before the reply needs them. 1 to 30. A day costs 2,145 bytes for each service (the DID and 64 keys), in every record of the stream, and the mint keeps no more than stream.max_services services; the days a request signed under stay published for as long as their key set is live, whatever this says. A wallet reads only the day of its own exchange and the days of its own notes.",
    },
    Spec {
        key: "stream.record_max_bytes",
        env: "ESP_STREAM_RECORD_MAX_BYTES",
        default: "4194304",
        units: "bytes",
        reload: true,
        what: "The most bytes of one record of the per-service key stream (4 MiB): 34 bytes of header and 2,145 for each service, so 1,955 services at the default. While every service fits one record for a day, one record holds them all; past it the services are grouped into buckets of about 256 by a hash of the service ID, and a wallet reads its service's bucket. 1,048,576 (1 MiB; a bucket of 256 services is 549,154 bytes) to 15,728,640 (15 MiB: AIR carries at most 16 MiB in one message and the mint keeps 1 MiB free for the envelope, the seal and the framing). A change applies to days the mint starts publishing afterwards; a record already written is never changed.",
    },
    Spec {
        key: "stream.max_services",
        env: "ESP_STREAM_MAX_SERVICES",
        default: "1000",
        units: "services",
        reload: true,
        what: "The most services whose keys the mint publishes. The mint learns a service from its first exchange; once it knows this many, an exchange for a service it does not know is refused (`400`, code `service_limit`) before anything is burned, and the services it has go on as before. 1 to 100,000. The keys of one service for one day are 2,145 bytes, so 1,000 services are 2.1 MB a day for each key set the mint is publishing, and 100,000 services 214.5 MB. Making a day's keys for a service is 64 key derivations.",
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
        what: "The most PSP notes, and the most ESP outputs, in one exchange. 64 to 25000: at least the 64 outputs one amount can need, at most what fits one AIR message.",
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
        what: "The ceiling on one exchange request body (1 MiB). A larger body is refused with 413 before it is parsed: nothing is burned, nothing is charged. 16384 to 15728640 (15 MiB: the most one AIR message carries).",
    },
    Spec {
        key: "exchange.fee_per_byte",
        env: "ESP_EXCHANGE_FEE_PER_BYTE",
        default: "0",
        units: "ESP units per canonical byte",
        reload: true,
        what: "The exchange fee rate. 0 means no mint fee. If set, a request pays this times its canonical size (49 + 146 per PSP note + 41 per output bytes), paid in ESP on top of the exact amount, at the rate in force when it is accepted; the rate is stored on the reply. 0 to 30000000: the cap keeps the worst one-note exchange under the value of the smallest note (1 PSP, 10^11 ESP units).",
    },
    Spec {
        key: "transfer.max_items",
        env: "ESP_TRANSFER_MAX_ITEMS",
        default: "1000",
        units: "notes",
        reload: true,
        what: "The most notes, and the most outputs, in one transfer. 64 to 25000.",
    },
    Spec {
        key: "transfer.max_request_bytes",
        env: "ESP_TRANSFER_MAX_BYTES",
        default: "1048576",
        units: "bytes",
        reload: true,
        what: "The ceiling on one transfer request body (1 MiB). A larger body is refused with 413 before it is parsed: nothing is burned, nothing is charged. 16384 to 15728640 (15 MiB: the most one AIR message carries).",
    },
    Spec {
        key: "rollover.max_items",
        env: "ESP_ROLLOVER_MAX_ITEMS",
        default: "1000",
        units: "notes",
        reload: true,
        what: "The most notes in one rollover. More is refused before anything is burned. 1 to 25000.",
    },
    Spec {
        key: "rollover.max_request_bytes",
        env: "ESP_ROLLOVER_MAX_BYTES",
        default: "1048576",
        units: "bytes",
        reload: true,
        what: "The ceiling on one rollover request body (1 MiB). A larger body is refused with 413 before it is parsed: nothing is burned, nothing is charged. 16384 to 15728640 (15 MiB: the most one AIR message carries).",
    },
    Spec {
        key: "transfer.fee_per_byte",
        env: "ESP_TRANSFER_FEE_PER_BYTE",
        default: "0",
        units: "ESP units per canonical byte",
        reload: true,
        what: "The transfer fee rate. 0 means no mint fee (the AIR send fee covers a transfer). If set, a request pays this times its canonical size (121 + 146 per note + 41 per output bytes), paid in ESP on top of the exact amount, at the rate in force when it is accepted; the rate is stored on the reply. 0 to 30000000, as for the exchange.",
    },
    Spec {
        key: "redeem.fee_per_byte",
        env: "ESP_REDEEM_FEE_PER_BYTE",
        default: "0",
        units: "ESP units per encoded byte",
        reload: true,
        what: "The redemption fee rate. 0 means no mint fee. If set, a request pays this times its encoded size, at the rate in force when it is accepted; the rate is stored on the reply and on the queue entry. 0 to 8000000: the cap keeps the worst one-note redemption (11,827 bytes) under the value of the smallest note (1 PSP, 10^11 ESP units).",
    },
    Spec {
        key: "redeem.max_request_bytes",
        env: "ESP_REDEEM_MAX_BYTES",
        default: "15728640",
        units: "bytes",
        reload: true,
        what: "The ceiling on one encoded redemption request (15 MiB: AIR carries at most 16 MiB in one message, so every redemption the mint takes can be sent over AIR; the wallet splits a larger one). A larger body is refused with 413 before it is parsed: no burn, no fee. A higher value does not let a wallet send a larger request: AIR carries no larger message, so 15 MiB is also the most this setting takes. 12288 to 15728640: the least is a one-note redemption at the wallet's worst-case sizing (64 decline and 64 refund outputs, 10,803 bytes) with the longest memo the mint allows.",
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
        what: "The ceiling on one request body on the operator's listener (1 MiB). 16384 to 15728640 (15 MiB: the most one AIR message carries).",
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
    Spec {
        key: "air.server",
        env: "ESP_AIR_SERVER",
        default: "",
        units: "AIR server name (66 hex characters)",
        reload: false,
        what: "The AIR server the listener holds reads on and writes replies to: its identity, a public key in AIR's compressed hex form (66 characters). The listener checks the server's signed challenge against it. Required by serve: the AIR listener always runs, because AIR is the only way wallets reach this mint. The PSP and the ESP can use the same AIR server: their DIDs differ, so their mailboxes do. Until the AIR resolves a DID to a server (upstream item 4), this is configuration.",
    },
    Spec {
        key: "air.host",
        env: "ESP_AIR_HOST",
        default: "",
        units: "host or IP, no port",
        reload: false,
        what: "Where that AIR server is: a host name or an IP (127.0.0.1 for the SPI's own AIR server). No port: the AIR client always uses 5702 (ws). Required by serve, with air.server.",
    },
    Spec {
        key: "air.held_reads",
        env: "ESP_AIR_HELD_READS",
        default: "16",
        units: "reads",
        reload: false,
        what: "How many mailbox slots the listener holds a read on, ahead of the next unfinished one. More lets more wallets be answered at once without waiting for a slot to be reached; each held read costs the AIR server about 2 KB. The AIR server closes the whole session at its 257th held read, so the most accepted is 200. The requests themselves are answered one at a time, in slot order, as the mint runs one request at a time.",
    },
    Spec {
        key: "air.timeout_secs",
        env: "ESP_AIR_TIMEOUT_SECS",
        default: "10",
        units: "seconds",
        reload: false,
        what: "How long the AIR server may take to answer one Create or Read before the listener counts the try as failed (a reply is tried three times).",
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
    /// Days of per-service keys published ahead (`stream.days_ahead`).
    pub stream_days_ahead: u64,
    /// The most bytes of one stream record (`stream.record_max_bytes`).
    pub stream_record_max_bytes: usize,
    /// The most services whose keys are published (`stream.max_services`).
    pub stream_max_services: usize,
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
    /// The AIR server's name (its public key, 66 hex characters).
    pub air_server: String,
    /// The AIR server's host or IP, no port.
    pub air_host: String,
    pub air_held_reads: u32,
    pub air_timeout_secs: u64,
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
            stream_days_ahead: 2,
            stream_record_max_bytes: 4 * 1024 * 1024,
            stream_max_services: 1000,
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
            air_server: String::new(),
            air_host: String::new(),
            air_held_reads: 16,
            air_timeout_secs: 10,
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
            "stream.days_ahead" => self.stream_days_ahead.to_string(),
            "stream.record_max_bytes" => self.stream_record_max_bytes.to_string(),
            "stream.max_services" => self.stream_max_services.to_string(),
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
            "air.server" => self.air_server.clone(),
            "air.host" => self.air_host.clone(),
            "air.held_reads" => self.air_held_reads.to_string(),
            "air.timeout_secs" => self.air_timeout_secs.to_string(),
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
            "stream.days_ahead" => self.stream_days_ahead = whole(key, value)?,
            "stream.record_max_bytes" => self.stream_record_max_bytes = whole(key, value)?,
            "stream.max_services" => self.stream_max_services = whole(key, value)?,
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
            "air.server" => self.air_server = value.trim().to_string(),
            "air.host" => self.air_host = value.trim().to_string(),
            "air.held_reads" => self.air_held_reads = whole(key, value)?,
            "air.timeout_secs" => self.air_timeout_secs = whole(key, value)?,
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
            "stream.days_ahead",
            self.stream_days_ahead,
            1,
            30,
            "days; at least the day a new exchange gets",
        );
        range(
            "stream.record_max_bytes",
            self.stream_record_max_bytes as u64,
            MIN_STREAM_RECORD_BYTES,
            MAX_STREAM_RECORD_BYTES,
            "bytes; a bucket of 256 services must fit, and 15 MiB is the most one AIR message carries with 1 MiB kept free",
        );
        range(
            "stream.max_services",
            self.stream_max_services as u64,
            1,
            MAX_STREAM_SERVICES,
            "services",
        );
        range(
            "exchange.max_items",
            self.exchange_max_items as u64,
            MIN_ITEMS,
            MAX_ITEMS_CAP,
            "notes; at least the 64 outputs one amount can need, and at most what fits one AIR message",
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
            MIN_ITEMS,
            MAX_ITEMS_CAP,
            "notes; at least the 64 outputs one amount can need, and at most what fits one AIR message",
        );
        range(
            "rollover.max_items",
            self.rollover_max_items as u64,
            1,
            MAX_ITEMS_CAP,
            "notes; at most what fits one AIR message",
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
                MAX_REQUEST_BYTES_CAP,
                "bytes; a one-note request with 64 outputs has to fit, and 15 MiB is the most one AIR message carries",
            );
        }
        for (key, value, cap) in [
            (
                "exchange.fee_per_byte",
                self.exchange_fee_per_byte,
                EXCHANGE_FEE_CAP,
            ),
            (
                "transfer.fee_per_byte",
                self.transfer_fee_per_byte,
                TRANSFER_FEE_CAP,
            ),
            (
                "redeem.fee_per_byte",
                self.redeem_fee_per_byte,
                REDEEM_FEE_CAP,
            ),
        ] {
            range(
                key,
                value,
                0,
                cap,
                "ESP units per byte; 0 means no fee, and the cap keeps a one-note request under the value of the smallest note, 10^11 units",
            );
        }
        range(
            "redeem.max_request_bytes",
            self.redeem_max_request_bytes as u64,
            MIN_REDEEM_REQUEST_BYTES,
            MAX_REQUEST_BYTES_CAP,
            "bytes; a one-note redemption at the wallet's worst-case sizing is 11,827 bytes, and 15 MiB is the most one AIR message carries",
        );
        range(
            "redeem.max_memo_bytes",
            self.redeem_max_memo_bytes as u64,
            1,
            MAX_MEMO_BYTES_CAP,
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
        range(
            "air.held_reads",
            u64::from(self.air_held_reads),
            1,
            200,
            "reads; the AIR server closes the session at its 257th",
        );
        range("air.timeout_secs", self.air_timeout_secs, 1, 600, "seconds");
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
        match self.bind.parse::<std::net::SocketAddr>() {
            Ok(addr) if !addr.ip().is_loopback() => problems.push(format!(
                "server.bind = `{}` is not a loopback address. Wallets reach this mint over AIR only; what is left on this address (/audit and /health) is for the operator and the SPI on this machine",
                self.bind
            )),
            _ => {}
        }
        if !(self.psp_url.starts_with("http://") || self.psp_url.starts_with("https://")) {
            problems.push(format!(
                "psp.url = `{}` must start with http:// or https://",
                self.psp_url
            ));
        }
        // What is set is checked when the settings load; that both are set is
        // checked by `serve` (`require_air`), so the other commands do not need
        // them.
        if !self.air_server.is_empty()
            && let Err(e) = sp_wire::seal::parse_public_key(&self.air_server)
        {
            problems.push(format!(
                "air.server = `{}` is not an AIR server name (a public key of 66 hex characters): {e}",
                self.air_server
            ));
        }
        if !self.air_host.is_empty()
            && let Some(why) = sp_wire::air_request::host_problem(&self.air_host)
        {
            problems.push(format!("air.host = `{}` {why}", self.air_host));
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }

    /// What the key stream reads (`stream`).
    pub fn stream_settings(&self) -> crate::stream::Settings {
        crate::stream::Settings {
            days_ahead: self.stream_days_ahead,
            record_max_bytes: self.stream_record_max_bytes,
            max_services: self.stream_max_services,
            maturity_days: self.maturity_days,
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

    /// What `serve` needs: the AIR server and its host, because the AIR
    /// listener always runs (AIR is the only way wallets reach this mint). The
    /// error names every one that is not set. The other commands do not need
    /// them.
    pub fn require_air(&self) -> Result<(), String> {
        let mut missing = Vec::new();
        if self.air_server.is_empty() {
            missing.push("air.server (ESP_AIR_SERVER)");
        }
        if self.air_host.is_empty() {
            missing.push("air.host (ESP_AIR_HOST)");
        }
        if missing.is_empty() {
            return Ok(());
        }
        Err(format!(
            "serve needs the AIR settings, because AIR is the only way wallets reach this mint, and {} {} not set. air.server is the AIR server's name (a public key of 66 hex characters) and air.host where to reach it (a host name or IP, no port)",
            missing.join(" and "),
            if missing.len() == 1 { "is" } else { "are" }
        ))
    }

    /// The AIR listener's settings (call [`Config::require_air`] first).
    /// `state_dir` is the network's data folder.
    pub fn air_listener(&self, state_dir: &Path) -> crate::air_listener::Settings {
        crate::air_listener::Settings {
            server: sp_wire::air_request::client::ServerRef {
                name: self.air_server.clone(),
                host: self.air_host.clone(),
            },
            held_reads: self.air_held_reads,
            timeout_secs: self.air_timeout_secs,
            state_dir: state_dir.to_path_buf(),
        }
    }

    pub fn redeem_settings(&self) -> RedeemSettings {
        RedeemSettings {
            fee_per_byte: u128::from(self.redeem_fee_per_byte),
            max_memo_bytes: self.redeem_max_memo_bytes,
            max_reason_bytes: self.redeem_max_reason_bytes,
        }
    }

    /// The settings that need a restart, put back to what the running mint has
    /// until it is restarted. Returns the keys whose new value was therefore held
    /// back.
    fn keep_restart_only(&mut self, running: &Config) -> Vec<&'static str> {
        let mut ignored = Vec::new();
        for spec in SPECS.iter().filter(|s| !s.reload) {
            if self.get(spec.key) != running.get(spec.key) {
                ignored.push(spec.key);
            }
        }
        self.network = running.network.clone();
        self.bind = running.bind.clone();
        self.admin_bind = running.admin_bind.clone();
        self.psp_url = running.psp_url.clone();
        self.rotation_activation_hours = running.rotation_activation_hours;
        self.rotation_period_hours = running.rotation_period_hours;
        self.admin_max_request_bytes = running.admin_max_request_bytes;
        self.storage_mint_state = running.storage_mint_state.clone();
        self.air_server = running.air_server.clone();
        self.air_host = running.air_host.clone();
        self.air_held_reads = running.air_held_reads;
        self.air_timeout_secs = running.air_timeout_secs;
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
            if let Some((_, _, why)) = REMOVED.iter().find(|(k, _, _)| *k == key) {
                problems.push((*why).to_string());
                continue;
            }
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

    for (_, name, why) in REMOVED {
        if env(name).is_some_and(|v| !v.is_empty()) {
            problems.push(format!("environment variable {name}: {why}"));
        }
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

    if problems.is_empty()
        && let Err(list) = config.validate()
    {
        problems.extend(list);
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

    /// Read the file and the environment again. On success the live settings are
    /// in force at once. The settings that need a restart keep their running
    /// value until the mint is restarted; which of them changed is in the answer.
    /// On any problem nothing changes. Returns what to log.
    pub fn reload(
        &self,
        data_dir: &Path,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Reloaded, Vec<String>> {
        let loaded = load(data_dir, env)?;
        let running = self.current();
        let mut next = loaded.config;
        // What the file says, for the lines about the settings held back.
        let loaded_values: std::collections::BTreeMap<&'static str, String> = SPECS
            .iter()
            .filter(|spec| !spec.reload)
            .map(|spec| (spec.key, next.get(spec.key).unwrap_or_default()))
            .collect();
        let needs_restart = next.keep_restart_only(&running);
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
        for key in &needs_restart {
            lines.push(format!(
                "  {key} is changed in the file from {} to {}: it needs a restart (a brief downtime) and waits for one",
                running.get(key).unwrap_or_default(),
                loaded_values.get(key).cloned().unwrap_or_default()
            ));
        }
        if lines.is_empty() {
            lines.push("  no setting changed".to_string());
        }
        self.replace(next);
        Ok(Reloaded {
            lines,
            needs_restart,
        })
    }
}

/// What a reload did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloaded {
    /// What to log, one line for each setting that changed.
    pub lines: Vec<String>,
    /// The settings that changed in the file but need a restart (`reload` false
    /// in `SPECS`): they keep their running value until the mint is restarted.
    /// Empty when every change was live.
    pub needs_restart: Vec<&'static str>,
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
        assert_eq!(
            Config::default().set("nope", "1").unwrap_err(),
            "unknown setting `nope`"
        );
    }

    #[test]
    fn the_defaults_are_the_ones_the_design_sets() {
        let c = Config::default();
        assert_eq!(c.maturity_days, 365);
        assert_eq!(
            (
                c.stream_days_ahead,
                c.stream_record_max_bytes,
                c.stream_max_services
            ),
            (2, 4_194_304, 1000)
        );
        assert_eq!(c.redeem_fee_per_byte, 0);
        assert_eq!(c.redeem_max_request_bytes, 15 * 1024 * 1024);
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
        // The AIR listener's defaults; the server and the host have none
        assert!(c.air_server.is_empty() && c.air_host.is_empty());
        assert_eq!((c.air_held_reads, c.air_timeout_secs), (16, 10));
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn the_air_listener_always_runs_and_serve_needs_a_server_and_a_host() {
        const SERVER: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let dir = scratch("air");
        // The settings load without them (the other commands do not need them),
        // and serve names both.
        let bare = load(&dir, &no_env).unwrap();
        let e = bare.config.require_air().unwrap_err();
        assert!(
            e.contains("ESP_AIR_SERVER") && e.contains("ESP_AIR_HOST"),
            "{e}"
        );
        assert!(e.contains("are not set"), "{e}");
        // One set: only the other is named.
        let host = load(&dir, &env_of(&[("ESP_AIR_HOST", "127.0.0.1")])).unwrap();
        let e = host.config.require_air().unwrap_err();
        assert!(
            e.contains("ESP_AIR_SERVER") && !e.contains("ESP_AIR_HOST"),
            "{e}"
        );
        assert!(e.contains("is not set"), "{e}");

        // From the file, then the environment on top.
        fs::write(
            dir.join(FILE_NAME),
            format!("[air]\nserver = \"{SERVER}\"\nhost = \"127.0.0.1\"\nheld_reads = 8\n"),
        )
        .unwrap();
        let on = load(&dir, &no_env).unwrap();
        assert!(on.config.require_air().is_ok());
        let s = on.config.air_listener(&dir);
        assert_eq!((s.held_reads, s.timeout_secs), (8, 10));
        assert_eq!(s.server.name, SERVER);
        assert_eq!(s.server.host, "127.0.0.1");
        assert_eq!(s.state_dir, dir);
        assert_eq!(on.sources["air.host"], Source::File);
        let env = load(&dir, &env_of(&[("ESP_AIR_HOST", "10.0.0.2")])).unwrap();
        assert_eq!(env.config.air_listener(&dir).server.host, "10.0.0.2");
        assert_eq!(env.sources["air.host"], Source::Env("ESP_AIR_HOST"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn air_enabled_is_gone_and_says_so_from_the_file_and_the_environment() {
        let dir = scratch("air-enabled-gone");
        for text in ["[air]\nenabled = true\n", "[air]\nenabled = false\n"] {
            fs::write(dir.join(FILE_NAME), text).unwrap();
            let p = load(&dir, &no_env).unwrap_err();
            assert!(
                p.iter()
                    .any(|x| x.contains("`air.enabled` is gone") && x.contains("air.server")),
                "{p:?}"
            );
            assert!(!p.iter().any(|x| x.contains("unknown setting")), "{p:?}");
        }
        fs::remove_file(dir.join(FILE_NAME)).unwrap();
        let p = load(&dir, &env_of(&[("ESP_AIR_ENABLED", "true")])).unwrap_err();
        assert!(
            p.iter().any(
                |x| x.contains("environment variable ESP_AIR_ENABLED") && x.contains("is gone")
            ),
            "{p:?}"
        );
        // An empty variable is the same as not set.
        assert!(load(&dir, &env_of(&[("ESP_AIR_ENABLED", "")])).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn server_bind_must_be_a_loopback_address() {
        let dir = scratch("bind-loopback");
        let p = load(&dir, &env_of(&[("ESP_BIND", "0.0.0.0:3100")])).unwrap_err();
        assert!(
            p.iter()
                .any(|x| x.contains("server.bind") && x.contains("not a loopback address")),
            "{p:?}"
        );
        assert!(load(&dir, &env_of(&[("ESP_BIND", "127.0.0.1:4100")])).is_ok());
        assert!(load(&dir, &env_of(&[("ESP_BIND", "[::1]:4100")])).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_air_mistake_is_refused_naming_the_setting() {
        const SERVER: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let dir = scratch("air-mistakes");
        let on = |extra: &[(&'static str, &'static str)]| {
            let mut pairs = vec![("ESP_AIR_SERVER", SERVER), ("ESP_AIR_HOST", "127.0.0.1")];
            pairs.extend_from_slice(extra);
            load(&dir, &env_of(&pairs))
        };
        assert!(on(&[]).is_ok());
        for (extra, named) in [
            (("ESP_AIR_SERVER", "zz"), "air.server"),
            (("ESP_AIR_HOST", "http://127.0.0.1"), "air.host"),
            (("ESP_AIR_HOST", "127.0.0.1:5702"), "air.host"),
            (("ESP_AIR_HELD_READS", "0"), "air.held_reads"),
            (("ESP_AIR_HELD_READS", "201"), "air.held_reads"),
            (("ESP_AIR_TIMEOUT_SECS", "0"), "air.timeout_secs"),
        ] {
            let p = on(&[extra]).unwrap_err();
            assert!(
                p.iter().any(|x| x.contains(named)),
                "{extra:?} should name {named}: {p:?}"
            );
        }
        fs::remove_dir_all(&dir).unwrap();
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
        assert_eq!(c.redeem_max_request_bytes, 15 * 1024 * 1024);
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
        let lines = handle.reload(&dir, &no_env).unwrap().lines;
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
        let problems = handle.reload(&dir, &no_env).unwrap_err();
        assert!(
            problems.iter().any(|p| p.contains(
                "redeem.fee_per_byte = 2000000000000000 is out of range: it must be from 0 to 8000000"
            )),
            "{problems:?}"
        );
        assert_eq!(handle.current().redeem_fee_per_byte, 5_000_000);

        // removing the file puts the defaults back
        fs::remove_file(dir.join(FILE_NAME)).unwrap();
        handle.reload(&dir, &no_env).unwrap();
        assert_eq!(handle.current().redeem_fee_per_byte, 0);
        // and nothing changing says so
        let lines = handle.reload(&dir, &no_env).unwrap().lines;
        assert_eq!(lines, vec!["  no setting changed".to_string()]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_reload_holds_back_addresses_and_the_psp_address_until_a_restart_and_says_so() {
        let dir = scratch("reload-restart");
        let handle = Handle::new(load(&dir, &no_env).unwrap().config);
        fs::write(
            dir.join(FILE_NAME),
            "[server]\nbind = \"127.0.0.1:4100\"\n[psp]\nurl = \"http://127.0.0.1:4000\"\n[terms]\nmaturity_days = 10\n",
        )
        .unwrap();
        let reloaded = handle.reload(&dir, &no_env).unwrap();
        let c = handle.current();
        // The live setting is in force at once; the others keep their running value.
        assert_eq!(c.bind, "127.0.0.1:3100");
        assert_eq!(c.psp_url, "http://127.0.0.1:3000");
        assert_eq!(c.maturity_days, 10);
        // The answer names exactly the ones that wait for a restart, in the
        // order of `SPECS`.
        assert_eq!(reloaded.needs_restart, vec!["server.bind", "psp.url"]);
        for (key, from, to) in [
            ("server.bind", "127.0.0.1:3100", "127.0.0.1:4100"),
            ("psp.url", "http://127.0.0.1:3000", "http://127.0.0.1:4000"),
        ] {
            let expected = format!(
                "  {key} is changed in the file from {from} to {to}: it needs a restart (a brief downtime) and waits for one"
            );
            assert!(reloaded.lines.contains(&expected), "{:?}", reloaded.lines);
        }
        assert!(
            reloaded
                .lines
                .iter()
                .any(|l| l.contains("terms.maturity_days changed from"))
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_reload_changes_the_psp_timeout_and_startup_retry_with_no_restart() {
        let dir = scratch("reload-psp-live");
        let handle = Handle::new(load(&dir, &no_env).unwrap().config);
        assert_eq!(handle.current().psp_timeout_secs, 30);
        assert_eq!(handle.current().psp_startup_retry_secs, 5);
        fs::write(
            dir.join(FILE_NAME),
            "[psp]\ntimeout_secs = 12\nstartup_retry_secs = 2\n",
        )
        .unwrap();
        let reloaded = handle.reload(&dir, &no_env).unwrap();
        assert_eq!(reloaded.needs_restart, Vec::<&str>::new());
        assert_eq!(handle.current().psp_timeout_secs, 12);
        assert_eq!(handle.current().psp_startup_retry_secs, 2);
        for line in [
            "  psp.timeout_secs changed from 30 to 12 seconds",
            "  psp.startup_retry_secs changed from 5 to 2 seconds",
        ] {
            assert!(
                reloaded.lines.contains(&line.to_string()),
                "{line:?} not in {:?}",
                reloaded.lines
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_reload_holds_back_the_network_and_the_rotation_hours_too() {
        let dir = scratch("reload-network");
        let handle = Handle::new(load(&dir, &no_env).unwrap().config);
        let running = handle.current();
        fs::write(
            dir.join(FILE_NAME),
            "[server]\nnetwork = \"regtest\"\n[rotation]\nactivation_hours = 3\nperiod_hours = 5\n",
        )
        .unwrap();
        let reloaded = handle.reload(&dir, &no_env).unwrap();
        let c = handle.current();
        // The running mint is still the one it was: a request must not see the
        // network or the rotation change under it.
        assert_eq!(c.network, running.network);
        assert_eq!(
            c.rotation_activation_hours,
            running.rotation_activation_hours
        );
        assert_eq!(c.rotation_period_hours, running.rotation_period_hours);
        assert_eq!(
            reloaded.needs_restart,
            vec![
                "server.network",
                "rotation.activation_hours",
                "rotation.period_hours"
            ]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_reload_that_changes_only_live_settings_names_nothing_to_restart() {
        let dir = scratch("reload-live-only");
        let handle = Handle::new(load(&dir, &no_env).unwrap().config);
        fs::write(dir.join(FILE_NAME), "[redeem]\nfee_per_byte = 7\n").unwrap();
        let reloaded = handle.reload(&dir, &no_env).unwrap();
        assert_eq!(reloaded.needs_restart, Vec::<&str>::new());
        assert_eq!(handle.current().redeem_fee_per_byte, 7);
        // A bad file asks for nothing and changes nothing.
        fs::write(dir.join(FILE_NAME), "[server]\nbind = \"not an address\"\n").unwrap();
        let before = handle.current();
        assert!(handle.reload(&dir, &no_env).is_err());
        assert_eq!(*handle.current(), *before);
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
                "rotation.activation_hours",
                "rotation.period_hours",
                "admin.max_request_bytes",
                "storage.mint_state",
                "air.server",
                "air.host",
                "air.held_reads",
                "air.timeout_secs"
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
                ("ESP_TRANSFER_MAX_BYTES", "16384"),
                ("ESP_ROLLOVER_MAX_BYTES", "32768"),
                ("ESP_ROLLOVER_MAX_ITEMS", "50"),
            ]),
        )
        .unwrap();
        assert_eq!(fixed.config.exchange_fee_per_byte, 0);
        assert_eq!(fixed.config.transfer_max_request_bytes, 16384);
        assert_eq!(fixed.config.rollover_max_request_bytes, 32768);
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
            "[exchange]\nfee_per_byte = 5\nmax_request_bytes = 32768\n[transfer]\nfee_per_byte = 6\n",
        )
        .unwrap();
        let lines = handle.reload(&dir, &no_env).unwrap().lines;
        let after = handle.current();
        assert_eq!(after.exchange_settings().fee_per_byte, 5);
        assert_eq!(after.transfer_settings().fee_per_byte, 6);
        assert_eq!(after.exchange_max_request_bytes, 32768);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("exchange.fee_per_byte changed from 0 to 5"))
        );
        // the settings a request already took are not touched
        assert_eq!(before.exchange_settings().fee_per_byte, 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    // ---- the caps: a value past one is refused when the settings load ----

    /// A settings file that sets `key` (`section.name`) to `value` is refused at
    /// load, and the message names the setting, the value and the range.
    fn refused_at_load(key: &str, value: u64, range: &str) {
        let (section, name) = key.split_once('.').unwrap();
        let dir = scratch(&format!("cap-{section}-{name}-{value}"));
        fs::write(
            dir.join(FILE_NAME),
            format!("[{section}]\n{name} = {value}\n"),
        )
        .unwrap();
        let problems = load(&dir, &no_env).unwrap_err();
        let want = format!("{key} = {value} is out of range: it must be from {range} (");
        assert!(problems.iter().any(|p| p.contains(&want)), "{problems:?}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_stream_settings_are_refused_outside_their_ranges() {
        refused_at_load("stream.days_ahead", 0, "1 to 30");
        refused_at_load("stream.days_ahead", 31, "1 to 30");
        refused_at_load("stream.record_max_bytes", 1_048_575, "1048576 to 15728640");
        refused_at_load("stream.record_max_bytes", 15_728_641, "1048576 to 15728640");
        refused_at_load("stream.max_services", 0, "1 to 100000");
        refused_at_load("stream.max_services", 100_001, "1 to 100000");
    }

    #[test]
    fn the_stream_settings_come_from_the_file_and_the_environment_and_reload_live() {
        let dir = scratch("stream-layers");
        fs::write(
            dir.join(FILE_NAME),
            "[stream]\ndays_ahead = 5\nmax_services = 77\n",
        )
        .unwrap();
        let loaded = load(&dir, &env_of(&[("ESP_STREAM_RECORD_MAX_BYTES", "2097152")])).unwrap();
        assert_eq!(
            loaded.config.stream_settings(),
            crate::stream::Settings {
                days_ahead: 5,
                record_max_bytes: 2_097_152,
                max_services: 77,
                maturity_days: 365,
            }
        );
        assert_eq!(
            loaded.sources.get("stream.record_max_bytes"),
            Some(&Source::Env("ESP_STREAM_RECORD_MAX_BYTES"))
        );
        assert_eq!(loaded.sources.get("stream.days_ahead"), Some(&Source::File));
        for key in [
            "stream.days_ahead",
            "stream.record_max_bytes",
            "stream.max_services",
        ] {
            let spec = SPECS.iter().find(|s| s.key == key).unwrap();
            assert!(spec.reload, "{key} applies without a restart");
        }
        // the defaults
        let defaults = Config::default().stream_settings();
        assert_eq!(
            (
                defaults.days_ahead,
                defaults.record_max_bytes,
                defaults.max_services
            ),
            (2, 4_194_304, 1_000)
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn exchange_max_items_past_its_cap_is_refused_at_load() {
        refused_at_load("exchange.max_items", 25_001, "64 to 25000");
        refused_at_load("exchange.max_items", 63, "64 to 25000");
    }

    #[test]
    fn transfer_max_items_past_its_cap_is_refused_at_load() {
        refused_at_load("transfer.max_items", 25_001, "64 to 25000");
        refused_at_load("transfer.max_items", 63, "64 to 25000");
    }

    #[test]
    fn rollover_max_items_past_its_cap_is_refused_at_load() {
        refused_at_load("rollover.max_items", 25_001, "1 to 25000");
    }

    #[test]
    fn exchange_max_request_bytes_past_its_cap_is_refused_at_load() {
        refused_at_load(
            "exchange.max_request_bytes",
            15_728_641,
            "16384 to 15728640",
        );
        refused_at_load("exchange.max_request_bytes", 16_383, "16384 to 15728640");
    }

    #[test]
    fn transfer_max_request_bytes_past_its_cap_is_refused_at_load() {
        refused_at_load(
            "transfer.max_request_bytes",
            15_728_641,
            "16384 to 15728640",
        );
        refused_at_load("transfer.max_request_bytes", 16_383, "16384 to 15728640");
    }

    #[test]
    fn rollover_max_request_bytes_past_its_cap_is_refused_at_load() {
        refused_at_load(
            "rollover.max_request_bytes",
            15_728_641,
            "16384 to 15728640",
        );
        refused_at_load("rollover.max_request_bytes", 16_383, "16384 to 15728640");
    }

    #[test]
    fn admin_max_request_bytes_past_its_cap_is_refused_at_load() {
        refused_at_load("admin.max_request_bytes", 15_728_641, "16384 to 15728640");
        refused_at_load("admin.max_request_bytes", 16_383, "16384 to 15728640");
    }

    #[test]
    fn redeem_max_request_bytes_past_its_cap_is_refused_at_load() {
        // above what one AIR message carries, and below one note at the
        // wallet's worst-case sizing (10,803 bytes and the longest memo)
        refused_at_load("redeem.max_request_bytes", 15_728_641, "12288 to 15728640");
        refused_at_load("redeem.max_request_bytes", 12_287, "12288 to 15728640");
    }

    #[test]
    fn redeem_max_memo_bytes_past_its_cap_is_refused_at_load() {
        // the memo is part of the redemption a wallet sizes for
        refused_at_load("redeem.max_memo_bytes", 1_025, "1 to 1024");
    }

    #[test]
    fn exchange_fee_per_byte_past_its_cap_is_refused_at_load() {
        refused_at_load("exchange.fee_per_byte", 30_000_001, "0 to 30000000");
    }

    #[test]
    fn transfer_fee_per_byte_past_its_cap_is_refused_at_load() {
        refused_at_load("transfer.fee_per_byte", 30_000_001, "0 to 30000000");
    }

    #[test]
    fn redeem_fee_per_byte_past_its_cap_is_refused_at_load() {
        refused_at_load("redeem.fee_per_byte", 8_000_001, "0 to 8000000");
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
        assert_eq!(
            c.set("server.network", "moon").unwrap_err(),
            "`moon` is not a network: use main, regtest, signet or testnet"
        );
        assert_eq!(check_psp_network("regtest", Some("regtest")), Ok(()));
        let e = check_psp_network("main", Some("regtest")).unwrap_err();
        assert!(
            e.contains("Refusing to start") && e.contains("regtest"),
            "{e}"
        );
        let e = check_psp_network("main", None).unwrap_err();
        assert!(
            e.contains("does not say which network it is on") && e.contains("main"),
            "{e}"
        );
        let spec = SPECS.iter().find(|s| s.key == "server.network").unwrap();
        assert_eq!(
            (spec.env, spec.default, spec.reload),
            ("ESP_NETWORK", "main", false)
        );
    }
}
