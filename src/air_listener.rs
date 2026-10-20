//! The AIR listener: answers a wallet's requests over AIR. It always runs in
//! `serve` (AIR is the only way wallets reach this mint; `air.server` and
//! `air.host` are required). The calls are **mint info** (the status, wire
//! version and network), **keysets** and **rotation**, **fees**, and the four
//! that change state, **rollover**, **exchange**, **transfer** and **redeem**;
//! each reply body is built by `server::air_served` from the call's outcome
//! function. `GET /audit` and the operator's routes are not wallet-facing; they
//! stay on HTTP, loopback only.
//!
//! The design (REQUEST-DESIGN.md in sandbox-mint, sections 13 to 16) and the wire
//! (envelopes, addresses, signing) are in `sp_wire::air_request`; this module is
//! the mint's loop around them, the same as psp-mint's with one difference, given
//! last:
//!
//! - The mint holds reads on the next `air.held_reads` mailbox slots of its DID
//!   (`mailbox_secret(DID, j)`; anyone can write a slot, only the mint can open
//!   it). The DID is the ESP's own (`mint_did_key.json` in the network's data
//!   folder, not the PSP's), so the PSP and the ESP can share an AIR server
//!   without their mailboxes meeting. A slot that fills is opened with the DID
//!   key, answered with what the call of the request's kind returns now,
//!   signed with the same key, sealed to the wallet's one-off key `R`, and
//!   `Create`d in the reply cell only the wallet and the mint can compute.
//! - **Create first, no read-then-write.** The reply cell is write-once, so the
//!   first `Create` wins and a second comes back as the stored record, which
//!   means "already answered". A retry that reached the mint twice, a copied
//!   cell and two mint processes all end with one reply.
//! - **A request that changes state is not applied twice.** Exchange, transfer,
//!   redeem and rollover are idempotent by request hash in the mint itself (it
//!   stores the answer before it burns, and a resend gets
//!   the stored answer or finishes the interrupted request), so the listener
//!   needs nothing of its own: a crash between answering and writing the
//!   counter replays the slot, and the replay is the same request.
//! - **The counter `next`** (the lowest slot not yet finished) is a text file,
//!   `air_mailbox_next`, in the network's data folder with the rest of the
//!   mint's local state. It is only an optimisation: without it the mint starts
//!   at slot 0, and an answered request finds its reply cell taken and is
//!   skipped. It is written (temp file, fsync, rename) after each slot is
//!   finished.
//! - **Garbage is skipped.** A cell that does not open, is malformed, is of an
//!   unknown kind or names a key that is not one is logged and skipped, and
//!   changes no state.
//! - **A call the mint cannot answer now** (a 5xx outcome: a poisoned
//!   lock, a failed rotation step, a PSP that could not be reached or refused
//!   the burn) gets a signed reply with status `unavailable` and no body, so the
//!   wallet fails at once and says why, instead of waiting out its tries. A
//!   refusal (a 4xx) is a signed reply with status `refused` and the call's JSON.
//! - **If the AIR client gives up** (the session was refused or killed: more than
//!   [`LOST_LIMIT`] held reads end within [`LOST_WINDOW_SECS`] seconds, or a
//!   `Create` fails three times) the listener returns an error and ends, and
//!   `esp-mint serve` exits with status 1, so that the service manager starts it
//!   again (from `next`): a mint that no wallet can reach is not left running.
//!
//! **The one difference from psp-mint: each request is answered on a blocking
//! thread** (`spawn_blocking`). An exchange calls the PSP with a blocking HTTP
//! client (the local call inside the SPI), which must not run on an async
//! thread, and a redemption reads and writes files. The requests are still
//! answered one at a time, in slot order, so a slow exchange (a slow PSP, up to
//! `psp.timeout_secs`) holds up the requests behind it, as a slow request holds
//! the mint lock.
//!
//! Held reads left behind by a stopped listener are never cleaned up by the AIR
//! server (upstream item 17); with the default of 16 a handful of restarts costs
//! little.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sp_wire::ServiceDid;
use sp_wire::air_request::addr::{self, mailbox_secret};
use sp_wire::air_request::client::{self, Client, Event, Put, ServerRef};
use sp_wire::air_request::{KIND_MINT_INFO, MintInfo, Served, answer_request};
use sp_wire::seal::SecretKey;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// The file, in the network's data folder, that holds the counter `next`.
pub const NEXT_FILE: &str = "air_mailbox_next";

/// More than this many held reads ending within [`LOST_WINDOW_SECS`] seconds
/// means the AIR session is gone (a rejected session ends all of them at once).
/// Supervision constants of the listener, not operator settings.
pub const LOST_LIMIT: usize = 5;
/// See [`LOST_LIMIT`].
pub const LOST_WINDOW_SECS: u64 = 10;

/// How many times a failed `Create` of a reply is tried before the listener gives up.
const CREATE_TRIES: u32 = 3;

/// What the listener needs. Built from the settings (`air.*`) by
/// [`crate::config::Config::air_listener`].
#[derive(Clone, Debug)]
pub struct Settings {
    /// The AIR server to hold reads on and `Create` replies at.
    pub server: ServerRef,
    /// Mailbox slots with a held read (`air.held_reads`).
    pub held_reads: u32,
    /// How long the server may take to answer one `Create` or `Read` (`air.timeout_secs`).
    pub timeout_secs: u64,
    /// The network's data folder: where `air_mailbox_next` is.
    pub state_dir: PathBuf,
}

fn next_path(dir: &Path) -> PathBuf {
    dir.join(NEXT_FILE)
}

/// The stored counter, or 0 when there is none.
pub fn read_next(dir: &Path) -> Result<u32, String> {
    match std::fs::read_to_string(next_path(dir)) {
        Ok(text) => text
            .trim()
            .parse()
            .map_err(|e| format!("{}: {e}", next_path(dir).display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(format!("read {}: {e}", next_path(dir).display())),
    }
}

/// Write the counter durably: temp file, fsync, rename.
pub fn write_next(dir: &Path, next: u32) -> Result<(), String> {
    let tmp = dir.join(format!("{NEXT_FILE}.tmp"));
    let mut file = std::fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    file.write_all(next.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, next_path(dir)).map_err(|e| e.to_string())
}

/// The held reads on the next K slots.
struct Window<'a> {
    client: &'a Client,
    did: ServiceDid,
    held: BTreeMap<u32, JoinHandle<()>>,
    /// First slot that has no held read yet.
    requested: u32,
    k: u32,
    tx: mpsc::UnboundedSender<Event>,
}

impl Window<'_> {
    /// Keep held reads on the K slots from `next`.
    async fn top_up(&mut self, next: u32) {
        let from = self.requested;
        while self.requested < next.saturating_add(self.k) {
            self.hold(self.requested).await;
            self.requested += 1;
        }
        if self.requested > from {
            println!(
                "AIR listener: holding mailbox slots {from}..{} ({} held)",
                self.requested,
                self.held.len()
            );
        }
    }

    async fn hold(&mut self, slot: u32) {
        let key = mailbox_secret(&self.did, slot).public_key();
        let handle = client::hold(self.client, key, slot, self.tx.clone()).await;
        self.held.insert(slot, handle);
    }
}

/// What the listener does with a request: given its kind and its body, the
/// reply to it, or `None` for a kind not served (the cell is skipped). The
/// mint's is [`crate::server::air_served`].
pub type Serve = dyn Fn(u8, &[u8]) -> Option<Served> + Send + Sync;

/// A [`Serve`] that answers mint info with `info` (what the mint reports now,
/// asked for at each request) and nothing else. For tests of the listener that
/// do not need a mint.
pub fn mint_info_only(
    info: impl Fn() -> MintInfo + Send + Sync + 'static,
) -> impl Fn(u8, &[u8]) -> Option<Served> + Send + Sync + 'static {
    move |kind, _| {
        (kind == KIND_MINT_INFO)
            .then(|| Served::Body(serde_json::to_vec(&info()).expect("mint info is JSON")))
    }
}

/// Run the listener until it fails, or until `stop` resolves (then `Ok`). It
/// never ends on its own otherwise. `serve` is called for each cell that is read
/// and opens to a request, and says what the mint answers now.
pub async fn run(
    settings: &Settings,
    key: &SecretKey,
    serve: &Arc<Serve>,
    stop: impl Future<Output = ()>,
) -> Result<(), String> {
    tokio::pin!(stop);
    let did = addr::key_to_did(&key.public_key());
    let client = client::connect(&settings.server).await.map_err(|e| e.0)?;
    let mut next = read_next(&settings.state_dir)?;
    println!(
        "AIR listener: mint {did} on AIR server {} ({}), next slot {next}, {} held reads",
        settings.server.name.trim(),
        settings.server.host.trim(),
        settings.held_reads
    );
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut window = Window {
        client: &client,
        did,
        held: BTreeMap::new(),
        requested: next,
        k: settings.held_reads,
        tx,
    };
    window.top_up(next).await;

    let mut pending: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut losses: VecDeque<Instant> = VecDeque::new();
    loop {
        while let Some(bytes) = pending.remove(&next) {
            window.held.remove(&next);
            handle_fill(&client, key, serve, settings.timeout_secs, next, &bytes).await?;
            next += 1;
            write_next(&settings.state_dir, next)?;
            window.top_up(next).await;
        }
        let event = tokio::select! {
            event = rx.recv() => event,
            _ = &mut stop => return Ok(()),
        };
        match event {
            Some(Event::Filled(slot, bytes)) => {
                pending.insert(slot, bytes);
            }
            Some(Event::Lost(slot)) => {
                let now = Instant::now();
                losses.push_back(now);
                while losses
                    .front()
                    .map(|t| now.duration_since(*t) > Duration::from_secs(LOST_WINDOW_SECS))
                    .unwrap_or(false)
                {
                    losses.pop_front();
                }
                println!(
                    "AIR listener: held read on slot {slot} ended ({} in the last {LOST_WINDOW_SECS} s)",
                    losses.len()
                );
                if losses.len() > LOST_LIMIT {
                    return Err(format!(
                        "the AIR session is gone (more than {LOST_LIMIT} held reads ended in \
                         {LOST_WINDOW_SECS} s). esp-mint exits so that it is started again, which resumes \
                         from slot {next}"
                    ));
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                if slot >= next {
                    window.hold(slot).await;
                }
            }
            None => return Err("the listener's event channel closed".into()),
        }
    }
}

/// Answer one filled slot, or skip it. `Err` only when the reply could not be
/// written after several tries (the AIR server is not taking `Create`s).
async fn handle_fill(
    client: &Client,
    key: &SecretKey,
    serve: &Arc<Serve>,
    timeout_secs: u64,
    slot: u32,
    sealed: &[u8],
) -> Result<(), String> {
    // On a blocking thread: an exchange calls the PSP with a blocking HTTP
    // client, and a redemption reads and writes files (see the module docs).
    let (key, serve, sealed) = (key.clone(), Arc::clone(serve), sealed.to_vec());
    let answered = tokio::task::spawn_blocking(move || {
        answer_request(&key, &sealed, addr::now_secs(), &*serve)
    })
    .await
    .map_err(|e| format!("the thread that answered slot {slot} failed: {e}"))?;
    let answer = match answered {
        Ok(answer) => answer,
        Err(reason) => {
            println!("AIR listener: slot {slot} skipped: {reason}");
            return Ok(());
        }
    };
    let id = hex::encode(answer.request.request_id);
    // Create first, no read-then-write: the first Create wins, a later one comes
    // back as `Taken` (already answered).
    let mut last = String::new();
    for attempt in 1..=CREATE_TRIES {
        match client::create(
            client,
            &answer.reply_cell,
            answer.sealed_reply.clone(),
            timeout_secs,
        )
        .await
        {
            Ok(Put::Created(_)) => {
                println!("AIR listener: slot {slot} answered request {id}");
                return Ok(());
            }
            Ok(Put::Taken) => {
                println!("AIR listener: slot {slot} request {id} was already answered");
                return Ok(());
            }
            Err(e) => {
                last = e.0;
                eprintln!(
                    "AIR listener: reply to request {id} not written (try {attempt}): {last}"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    Err(format!(
        "could not write the reply to request {id} after {CREATE_TRIES} tries: {last}"
    ))
}

/// Run the listener on the calling thread, with a runtime of its own, until it
/// fails. For a thread of its own: `serve` starts one so that the HTTP API's
/// runtime and the listener never share a thread. A panic in `serve` is a failed
/// answer thread, which ends the listener with an error.
pub fn run_blocking(
    settings: &Settings,
    key: &SecretKey,
    serve: &Arc<Serve>,
) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start a runtime: {e}"))?;
    runtime.block_on(run(settings, key, serve, std::future::pending()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "esp-mint-air-{}-{name}-{}",
            std::process::id(),
            addr::now_secs()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_counter_starts_at_zero_and_survives_a_write() {
        let dir = scratch("next");
        assert_eq!(read_next(&dir).unwrap(), 0);
        write_next(&dir, 7).unwrap();
        assert_eq!(read_next(&dir).unwrap(), 7);
        write_next(&dir, 8).unwrap();
        assert_eq!(read_next(&dir).unwrap(), 8);
        assert!(!dir.join(format!("{NEXT_FILE}.tmp")).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_counter_is_an_error_not_a_reset() {
        let dir = scratch("damaged");
        std::fs::write(next_path(&dir), "not a number").unwrap();
        assert!(read_next(&dir).unwrap_err().contains(NEXT_FILE));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
