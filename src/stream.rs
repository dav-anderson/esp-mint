//! The ESP mint's key stream (ROADMAP item 31, finding P2-04, the mint
//! fingerprinting attack).
//!
//! An ESP key is per (generation, amount, service, day), so a mint that signs one
//! user's outputs for a day of its own, or with a key of its own, could
//! recognise that user's notes when they come back. This module publishes what
//! the mint really signs with, on AIR, under the mint's DID, where every wallet
//! reads the same bytes (`sp_wire::air_request::stream` has the cells and the
//! records). A wallet checks each key in each reply against it.
//!
//! **What is published.**
//!
//! - *The control stream* (`Cell::Control`, records 0, 1, 2, ...): the maturity
//!   rule `m` (`terms.maturity_days`) and the live generations (epoch and key-set
//!   ID of the current one, and of the previous one while it is live). A new
//!   record is written whenever one of those changes, never before.
//! - *The day records* (`Cell::Day`): for a generation and a redeemable-after day,
//!   the 64 public keys (2^0 to 2^63) of every service the mint knows. One shared
//!   record holds every service until the record would pass
//!   `stream.record_max_bytes`; then the services are grouped into fixed buckets
//!   by a hash of the service DID (`sp_wire::air_request::stream::bucket_of`) and
//!   a wallet reads its service's bucket. A record is 34 bytes of header and
//!   2,145 bytes for each service (the DID and 64 keys of 33 bytes).
//!
//! **Which days.** Two kinds, both for the live generations only:
//!
//! - *the window*: the days `today + m` up to `today + m + stream.days_ahead - 1`,
//!   for the current generation. A new exchange gets the day `today + m`, so these
//!   are published before any exchange needs them.
//! - *the days in use*: a day that a finished request signed under (an exchange,
//!   a refund or decline, a rollover, a transfer), for both live generations. A
//!   refund, a decline and a rollover sign for the note's own day, which may be
//!   long past; its keys are published at the latest by the time the request is
//!   answered, for the generation that signs it.
//!
//! **When a day stops being kept.** AIR cells cannot be deleted, so nothing is
//! ever removed from the stream. What this mint keeps is its own state for the
//! day (`stream.json`), and it keeps it for as long as the generation that signed
//! the day's notes is live: a note of a generation that has been deleted can no
//! longer be redeemed or rolled over, so that is the point at which every note of
//! the generation has passed its redeem window. A note that was rolled over to
//! the next generation is a note of that generation, and the rollover published
//! the day for it. There is no timer.
//!
//! **Services.** The mint learns a service when a request finishes for it (a new
//! service always starts with an exchange, because ESP is made by exchanges
//! only). The services are kept in order in `stream.json`, at most
//! `stream.max_services`: an exchange for a service the mint does not have is
//! refused with `service_limit` before anything is burned once the list is full.
//! A service that is added later is published as a new *batch* of every day that
//! is kept: a part, one for each bucket the batch's services fall in. A batch
//! never holds more services in a bucket than one record may hold, so no record
//! passes the size setting; a wallet reads the parts of its bucket from part 0
//! until it finds its service.
//!
//! **Layout.** A day has a bucket count `K` fixed when its first batch is
//! planned (`buckets_for`: 1 while one record holds every service the mint knows,
//! else the services divided by 256, rounded up). Batch 0 writes part 0 of every
//! bucket, even an empty one, so the day's `K` can be read from the first part
//! of bucket 0. A later batch writes one part for each bucket it has services
//! in, numbered after the parts the bucket has. Every part is made from the
//! services list and the batch ends in `stream.json` and the generation's master
//! secret only, so writing it again writes the same bytes.
//!
//! **Crash safety.** A batch is planned and saved before it is written, and it is
//! marked done after. A crash in between leaves a planned batch, which the next
//! pass writes again; a cell that already holds the same bytes is "already
//! stored". A cell that holds other bytes is an error that is printed, never
//! written over.
//!
//! **Not on the request path.** A finished request only *notes* its services and
//! days (a local file write); the writer thread (`serve` runs it) publishes. A
//! wallet that reads before the cell is written waits for it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use mint_types::Amount;
use secp256k1::{PublicKey, SECP256K1};
use serde::{Deserialize, Serialize};
use sp_wire::ServiceDid;
use sp_wire::air_request::client::{self, ServerRef};
use sp_wire::air_request::delivery::Written;
use sp_wire::air_request::stream::{
    Cell, ControlRecord, DayCell, DayRecord, ESP_KEYS_PER_SERVICE, GenerationRef, ServiceKeys,
    bucket_of, buckets_for, read_cell, services_per_record, write_cell,
};
use sp_wire::seal::SecretKey;

use crate::keys::MasterSecret;
use crate::rotation::Rotor;
use crate::terms::{SECONDS_PER_DAY, Terms};

/// The state file, in the network's data folder.
pub const STATE_FILE: &str = "stream.json";

/// The code of the refusal an exchange gets for a service the mint cannot add.
pub const SERVICE_LIMIT: &str = "service_limit";

/// Seconds between two passes of the writer when nothing woke it.
pub const TICK_SECS: u64 = 5;

/// Seconds the writer waits after a pass that failed.
pub const RETRY_SECS: u64 = 30;

/// Writes of at most this many bytes get the AIR timeout setting as it is; a
/// bigger one gets one more timeout for each started mebibyte.
const WRITE_MIB: usize = 1 << 20;

/// The settings the stream reads (see `config`): `stream.days_ahead`,
/// `stream.record_max_bytes`, `stream.max_services` and `terms.maturity_days`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// How many days, from `today + m`, are published ahead for the current generation.
    pub days_ahead: u64,
    /// The most bytes of one record.
    pub record_max_bytes: usize,
    /// The most services the mint adds.
    pub max_services: usize,
    /// The maturity rule `m`.
    pub maturity_days: u64,
}

/// One live generation, as the stream needs it: its epoch, key-set ID and master secret.
#[derive(Clone, Debug)]
pub struct LiveGen {
    pub epoch: u64,
    pub id: [u8; 8],
    pub master: MasterSecret,
}

/// The live generations: the current one and, while there is one, the previous.
#[derive(Clone, Debug)]
pub struct Live {
    pub current: LiveGen,
    pub previous: Option<LiveGen>,
}

fn gen_of(epoch: u64, id: &str, master: &MasterSecret) -> Result<LiveGen, String> {
    let bytes = hex::decode(id).map_err(|e| format!("key set ID {id}: {e}"))?;
    let id: [u8; 8] = bytes
        .try_into()
        .map_err(|_| format!("key set ID {id} is not 8 bytes"))?;
    Ok(LiveGen {
        epoch,
        id,
        master: master.clone(),
    })
}

impl Live {
    /// The live generations of `rotor`.
    pub fn of(rotor: &Rotor) -> Result<Live, String> {
        let current = gen_of(
            rotor.current.epoch,
            &rotor.current.id,
            &rotor.current.master,
        )?;
        let previous = match &rotor.previous {
            Some((g, _)) => Some(gen_of(g.epoch, &g.id, &g.master)?),
            None => None,
        };
        Ok(Live { current, previous })
    }

    fn gens(&self) -> Vec<&LiveGen> {
        let mut gens = vec![&self.current];
        gens.extend(self.previous.as_ref());
        gens
    }
}

/// The days a new exchange can get now, published ahead: `today + m` for
/// `days_ahead` days.
pub fn window(now_unix: u64, maturity_days: u64, days_ahead: u64) -> Vec<u64> {
    let first = (now_unix / SECONDS_PER_DAY).saturating_add(maturity_days);
    (0..days_ahead.max(1))
        .map(|i| first.saturating_add(i))
        .collect()
}

/// What `stream.json` keeps for one day of one generation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct DayState {
    /// The bucket count; 0 until the day's first batch is planned.
    buckets: u32,
    /// The services list length each planned batch reaches, in order.
    batch_ends: Vec<u32>,
    /// How many of the planned batches are written.
    done: u32,
}

/// The fields of the last control record written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ControlFields {
    maturity_days: u64,
    current_epoch: u64,
    current_id: String,
    previous: Option<(u64, String)>,
}

impl ControlFields {
    fn of(m: u64, live: &Live) -> ControlFields {
        ControlFields {
            maturity_days: m,
            current_epoch: live.current.epoch,
            current_id: hex::encode(live.current.id),
            previous: live.previous.as_ref().map(|g| (g.epoch, hex::encode(g.id))),
        }
    }

    fn record(&self, index: u32) -> Result<ControlRecord, String> {
        let id = |text: &str| -> Result<[u8; 8], String> {
            hex::decode(text)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| format!("key set ID {text} is not 8 bytes"))
        };
        Ok(ControlRecord {
            index,
            maturity_days: self.maturity_days,
            current: GenerationRef {
                epoch: self.current_epoch,
                id: id(&self.current_id)?,
            },
            previous: match &self.previous {
                Some((epoch, text)) => Some(GenerationRef {
                    epoch: *epoch,
                    id: id(text)?,
                }),
                None => None,
            },
        })
    }

    fn from_record(r: &ControlRecord) -> ControlFields {
        ControlFields {
            maturity_days: r.maturity_days,
            current_epoch: r.current.epoch,
            current_id: hex::encode(r.current.id),
            previous: r.previous.map(|g| (g.epoch, hex::encode(g.id))),
        }
    }
}

/// Everything the stream keeps on disk.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct State {
    /// The services, in the order they were added (DID, 66 hex characters).
    services: Vec<String>,
    /// The days kept, by `"<generation ID hex>:<day>"`.
    days: BTreeMap<String, DayState>,
    /// How many control records are written.
    control_count: u32,
    /// The fields of the last one.
    control_last: Option<ControlFields>,
}

fn day_key(generation: &[u8; 8], day: u64) -> String {
    format!("{}:{day}", hex::encode(generation))
}

fn parse_day_key(key: &str) -> Option<([u8; 8], u64)> {
    let (g, d) = key.split_once(':')?;
    Some((hex::decode(g).ok()?.try_into().ok()?, d.parse().ok()?))
}

/// What a pass of the writer did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Published {
    /// Control records written.
    pub control: usize,
    /// Day-record parts written (a part that was already stored is not counted).
    pub parts: usize,
    /// The bytes of those parts.
    pub bytes: usize,
}

impl Published {
    /// Whether anything was written.
    pub fn is_empty(&self) -> bool {
        self.control == 0 && self.parts == 0
    }
}

/// The wake-up and stop signal of the writer thread.
#[derive(Default)]
struct Signal {
    flags: Mutex<(bool, bool)>,
    changed: Condvar,
}

/// The handle that stops the writer thread: it outlives the borrow of the
/// mint's state, so `serve` can stop the thread while the state is being closed.
#[derive(Clone)]
pub struct Control(Arc<Signal>);

impl Control {
    /// Ask the writer to stop.
    pub fn stop(&self) {
        lock(&self.0.flags).1 = true;
        self.0.changed.notify_all();
    }
}

/// The ESP mint's stream: the services it knows, what is written of each day and
/// the way to write the rest. See the module documentation.
pub struct Stream {
    server: ServerRef,
    timeout_secs: u64,
    key: [u8; 32],
    path: PathBuf,
    state: Mutex<State>,
    /// Held for a whole pass, so only one writer runs at a time. Taken before `state`.
    writing: Mutex<()>,
    signal: Arc<Signal>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn save(path: &Path, state: &State) -> Result<(), String> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    };
    write().map_err(|e| format!("cannot save {}: {e}", path.display()))
}

/// The services of the batch that ends at `end` and starts at `start` in
/// `services`, by bucket.
fn members(
    services: &[String],
    start: usize,
    end: usize,
    buckets: u32,
) -> Result<BTreeMap<u32, Vec<ServiceDid>>, String> {
    let mut by_bucket: BTreeMap<u32, Vec<ServiceDid>> = BTreeMap::new();
    for text in &services[start..end] {
        let did = ServiceDid::parse(text).map_err(|e| format!("service {text}: {e}"))?;
        by_bucket
            .entry(bucket_of(&did, buckets))
            .or_default()
            .push(did);
    }
    Ok(by_bucket)
}

/// Where the next batch of a day ends: from `start`, as far as no bucket gets
/// more than `per_record` services in it. At least one service when there is
/// one, so a day always makes progress.
fn plan_end(
    services: &[String],
    start: usize,
    buckets: u32,
    per_record: usize,
) -> Result<usize, String> {
    let mut counts: HashMap<u32, usize> = HashMap::new();
    let mut end = start;
    for text in &services[start..] {
        let did = ServiceDid::parse(text).map_err(|e| format!("service {text}: {e}"))?;
        let b = bucket_of(&did, buckets);
        let c = counts.entry(b).or_insert(0);
        if *c >= per_record.max(1) {
            break;
        }
        *c += 1;
        end += 1;
    }
    Ok(end)
}

/// For batch `j`: the part number each of its buckets gets. Batch 0 has part 0
/// of every bucket; a later batch numbers a bucket after the parts the bucket
/// already has (batch 0's, and the earlier batches that had services in it).
fn part_numbers(
    services: &[String],
    batch_ends: &[u32],
    j: usize,
    buckets: u32,
) -> Result<BTreeMap<u32, u32>, String> {
    let mut have: BTreeMap<u32, u32> = (0..buckets).map(|b| (b, 0)).collect();
    let mut start = 0usize;
    for (i, end) in batch_ends.iter().enumerate().take(j + 1) {
        let end = *end as usize;
        let here = members(services, start, end, buckets)?;
        if i == j {
            let mut parts = BTreeMap::new();
            for b in 0..buckets {
                if i == 0 || here.contains_key(&b) {
                    parts.insert(b, have[&b]);
                }
            }
            return Ok(parts);
        }
        for b in 0..buckets {
            if i == 0 || here.contains_key(&b) {
                *have.get_mut(&b).expect("every bucket is in the map") += 1;
            }
        }
        start = end;
    }
    Err("batch number out of range".into())
}

/// One service's 64 public keys for one day under one generation.
pub fn service_keys(master: &MasterSecret, service: ServiceDid, day: u64) -> ServiceKeys {
    let terms = Terms {
        service,
        redeemable_after_day: day,
    };
    let keys: Vec<PublicKey> = (0..ESP_KEYS_PER_SERVICE)
        .map(|bit| {
            master
                .key_for(Amount::from_units(1u64 << bit), &terms)
                .public_key(SECP256K1)
        })
        .collect();
    ServiceKeys {
        service,
        keys: keys.try_into().expect("64 keys were made for 64 amounts"),
    }
}

impl Stream {
    /// Open the stream of the mint whose DID key is `key`, with the state saved
    /// in `data_dir` (none if there is no file yet). `server` and `timeout_secs`
    /// are the AIR server and `air.timeout_secs`.
    pub fn open(
        data_dir: &Path,
        server: ServerRef,
        timeout_secs: u64,
        key: &SecretKey,
    ) -> Result<Stream, String> {
        let path = data_dir.join(STATE_FILE);
        let state = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("{} is damaged: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        Ok(Stream {
            server,
            timeout_secs,
            key: key.to_array(),
            path,
            state: Mutex::new(state),
            writing: Mutex::new(()),
            signal: Arc::new(Signal::default()),
        })
    }

    /// How many services the mint knows.
    pub fn service_count(&self) -> usize {
        lock(&self.state).services.len()
    }

    /// The maturity rule m of the last control record written (or found in AIR),
    /// if one is. A new exchange is dated with this m, not with a
    /// `terms.maturity_days` that was reloaded and is not published yet: a wallet
    /// checks the day it is given against the m it reads on the stream, so a day
    /// under a rule it cannot read yet would be refused as a key mismatch.
    pub fn published_maturity_days(&self) -> Option<u64> {
        lock(&self.state)
            .control_last
            .as_ref()
            .map(|c| c.maturity_days)
    }

    /// Whether `service` is known or there is room for it under `max_services`.
    pub fn has_room_for(&self, service: &ServiceDid, max_services: usize) -> bool {
        let state = lock(&self.state);
        let text = service.to_hex();
        state.services.len() < max_services || state.services.contains(&text)
    }

    /// Record that a request finished for `terms`: their services join the list
    /// if they are new, and each day is kept for both live generations. Writes
    /// `stream.json` if anything changed and wakes the writer. Nothing goes over
    /// the network.
    pub fn note(&self, live: &Live, terms: &[Terms]) -> Result<(), String> {
        let mut state = lock(&self.state);
        let mut new_services: Vec<String> = Vec::new();
        let mut new_days: Vec<String> = Vec::new();
        for t in terms {
            let text = t.service.to_hex();
            if !state.services.contains(&text) && !new_services.contains(&text) {
                new_services.push(text);
            }
            for g in live.gens() {
                let key = day_key(&g.id, t.redeemable_after_day);
                if !state.days.contains_key(&key) && !new_days.contains(&key) {
                    new_days.push(key);
                }
            }
        }
        if new_services.is_empty() && new_days.is_empty() {
            return Ok(());
        }
        let services_before = state.services.len();
        state.services.extend(new_services);
        for key in &new_days {
            state.days.insert(key.clone(), DayState::default());
        }
        if let Err(e) = save(&self.path, &state) {
            // Put back what was added: a service that is not on disk must not
            // be in memory, or a retry would find nothing to add and say "done".
            state.services.truncate(services_before);
            for key in &new_days {
                state.days.remove(key);
            }
            return Err(e);
        }
        drop(state);
        self.wake();
        Ok(())
    }

    /// Ask the writer to run now.
    pub fn wake(&self) {
        lock(&self.signal.flags).0 = true;
        self.signal.changed.notify_all();
    }

    /// The handle that stops the writer.
    pub fn control(&self) -> Control {
        Control(Arc::clone(&self.signal))
    }

    /// Wait up to `dur` for a wake-up or a stop. `true` means stop.
    pub fn wait(&self, dur: Duration) -> bool {
        let mut flags = lock(&self.signal.flags);
        if !flags.0 && !flags.1 {
            flags = self
                .signal
                .changed
                .wait_timeout(flags, dur)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        flags.0 = false;
        flags.1
    }

    fn write_secs(&self, len: usize) -> u64 {
        self.timeout_secs
            .saturating_mul(1 + (len / WRITE_MIB) as u64)
    }

    /// Write one cell. `Ok(true)` when it was created, `Ok(false)` when it
    /// already held these bytes, `Err` when it holds other bytes or the write failed.
    fn write(&self, cell: &Cell, bytes: &[u8]) -> Result<bool, String> {
        let (server, key, secs) = (&self.server, self.key, self.write_secs(bytes.len()));
        let connect = self.timeout_secs;
        let written = client::block_on_new_runtime(|| async move {
            let client =
                tokio::time::timeout(Duration::from_secs(connect), client::connect(server))
                    .await
                    .map_err(|_| format!("no connection to the AIR server within {connect} s"))?
                    .map_err(|e| e.0)?;
            let key = SecretKey::from_array(key)
                .map_err(|_| "the mint's key is not a valid secret key".to_string())?;
            write_cell(&client, &key, cell, bytes, secs)
                .await
                .map_err(|e| e.0)
        })
        .map_err(|e| e.0)??;
        match written {
            Written::Created => Ok(true),
            Written::AlreadyStored => Ok(false),
            Written::Different => Err(format!(
                "AIR cell {cell:?} already holds other bytes than this mint would write: it is left alone"
            )),
        }
    }

    /// Read a cell (for the control stream's recovery).
    fn read(&self, cell: &Cell) -> Result<Option<Vec<u8>>, String> {
        let (server, secs) = (&self.server, self.timeout_secs);
        let mint = {
            let key = SecretKey::from_array(self.key)
                .map_err(|_| "the mint's key is not a valid secret key".to_string())?;
            sp_wire::air_request::addr::key_to_did(&key.public_key())
        };
        client::block_on_new_runtime(|| async move {
            let client = tokio::time::timeout(Duration::from_secs(secs), client::connect(server))
                .await
                .map_err(|_| format!("no connection to the AIR server within {secs} s"))?
                .map_err(|e| e.0)?;
            read_cell(&client, &mint, cell, secs).await.map_err(|e| e.0)
        })
        .map_err(|e| e.0)?
    }

    /// One pass of the writer: the control stream, then every day that is kept
    /// for a live generation (the window of the current generation and the days
    /// noted). `now_unix` is the mint's clock. Only one pass runs at a time.
    pub fn publish(
        &self,
        settings: &Settings,
        live: &Live,
        now_unix: u64,
    ) -> Result<Published, String> {
        let _writing = lock(&self.writing);
        let mut done = Published::default();
        self.prune(live)?;
        done.control = self.publish_control(settings, live)?;
        self.keep_window(settings, live, now_unix)?;
        let keys: Vec<String> = lock(&self.state).days.keys().cloned().collect();
        for key in keys {
            let Some((id, day)) = parse_day_key(&key) else {
                return Err(format!(
                    "{STATE_FILE}: `{key}` is not a generation and a day"
                ));
            };
            let Some(gen_) = live.gens().into_iter().find(|g| g.id == id) else {
                continue;
            };
            let (parts, bytes) = self.sync_day(settings, gen_, day, &key)?;
            done.parts += parts;
            done.bytes += bytes;
        }
        Ok(done)
    }

    /// Forget the days of a generation that is no longer live.
    fn prune(&self, live: &Live) -> Result<(), String> {
        let ids: BTreeSet<String> = live.gens().iter().map(|g| hex::encode(g.id)).collect();
        let mut state = lock(&self.state);
        let gone: Vec<String> = state
            .days
            .keys()
            .filter(|key| !key.split_once(':').is_some_and(|(g, _)| ids.contains(g)))
            .cloned()
            .collect();
        if gone.is_empty() {
            return Ok(());
        }
        let removed: Vec<(String, DayState)> = gone
            .into_iter()
            .filter_map(|key| state.days.remove(&key).map(|st| (key, st)))
            .collect();
        if let Err(e) = save(&self.path, &state) {
            state.days.extend(removed);
            return Err(e);
        }
        Ok(())
    }

    /// Keep the window days of the current generation.
    fn keep_window(&self, settings: &Settings, live: &Live, now_unix: u64) -> Result<(), String> {
        let mut state = lock(&self.state);
        let added: Vec<String> = window(now_unix, settings.maturity_days, settings.days_ahead)
            .into_iter()
            .map(|day| day_key(&live.current.id, day))
            .filter(|key| !state.days.contains_key(key))
            .collect();
        if added.is_empty() {
            return Ok(());
        }
        for key in &added {
            state.days.insert(key.clone(), DayState::default());
        }
        if let Err(e) = save(&self.path, &state) {
            for key in &added {
                state.days.remove(key);
            }
            return Err(e);
        }
        Ok(())
    }

    /// Write a control record if `m` or the live generations differ from the
    /// last one written. Returns how many were written.
    fn publish_control(&self, settings: &Settings, live: &Live) -> Result<usize, String> {
        let wanted = ControlFields::of(settings.maturity_days, live);
        let mut written = 0usize;
        // A few rounds at most: each round either finishes or adopts a record
        // that was already in the cell (written by an earlier run that stopped
        // before it saved).
        for _ in 0..8 {
            let (index, last) = {
                let state = lock(&self.state);
                (state.control_count, state.control_last.clone())
            };
            if last.as_ref() == Some(&wanted) {
                return Ok(written);
            }
            let record = wanted.record(index)?;
            let cell = Cell::Control { index };
            let adopted = match self.write(&cell, &record.encode()) {
                Ok(created) => {
                    written += usize::from(created);
                    wanted.clone()
                }
                Err(why) => {
                    let bytes = self.read(&cell)?.ok_or_else(|| {
                        format!("control record {index} could not be written: {why}")
                    })?;
                    let other = ControlRecord::decode(&bytes)
                        .map_err(|e| format!("control record {index} in AIR: {}", e.0))?;
                    ControlFields::from_record(&other)
                }
            };
            let mut state = lock(&self.state);
            let before = (state.control_count, state.control_last.clone());
            state.control_count = index + 1;
            state.control_last = Some(adopted);
            if let Err(e) = save(&self.path, &state) {
                (state.control_count, state.control_last) = before;
                return Err(e);
            }
        }
        Err("the control stream did not settle after 8 records".into())
    }

    /// Write whatever is missing of one day of one generation. Returns the parts
    /// and bytes written.
    fn sync_day(
        &self,
        settings: &Settings,
        generation: &LiveGen,
        day: u64,
        key: &str,
    ) -> Result<(usize, usize), String> {
        let per_record = services_per_record(settings.record_max_bytes);
        let (mut parts, mut bytes) = (0usize, 0usize);
        loop {
            // Plan the next batch if all the planned ones are written, and save
            // the plan before anything is written (under the lock); else take
            // the planned one that is not written yet.
            let (services, day_state, batch) = {
                let mut state = lock(&self.state);
                let n = state.services.len();
                if n == 0 {
                    return Ok((parts, bytes));
                }
                let (buckets, covered, done, planned) = {
                    let st = state.days.get(key).ok_or("the day is not kept")?;
                    (
                        st.buckets,
                        st.batch_ends.last().copied().unwrap_or(0) as usize,
                        st.done as usize,
                        st.batch_ends.len(),
                    )
                };
                let set_buckets = buckets == 0;
                let buckets = if set_buckets {
                    buckets_for(n, settings.record_max_bytes)
                } else {
                    buckets
                };
                let caught_up = done == planned;
                if caught_up && covered >= n && !set_buckets {
                    // Everything the mint knows is written for this day.
                    return Ok((parts, bytes));
                }
                let end = if caught_up && covered < n {
                    Some(plan_end(&state.services, covered, buckets, per_record)?)
                } else {
                    None
                };
                if set_buckets || end.is_some() {
                    let st = state.days.get_mut(key).ok_or("the day is not kept")?;
                    if set_buckets {
                        st.buckets = buckets;
                    }
                    if let Some(end) = end {
                        st.batch_ends.push(end as u32);
                    }
                    if let Err(e) = save(&self.path, &state) {
                        if let Some(st) = state.days.get_mut(key) {
                            if set_buckets {
                                st.buckets = 0;
                            }
                            if end.is_some() {
                                st.batch_ends.pop();
                            }
                        }
                        return Err(e);
                    }
                }
                let st = state.days.get(key).ok_or("the day is not kept")?;
                if st.done as usize == st.batch_ends.len() {
                    // Only the bucket count was set and there is nothing to
                    // write for it (no service yet beyond the covered ones).
                    return Ok((parts, bytes));
                }
                (state.services.clone(), st.clone(), st.done as usize)
            };
            // Write the batch (no lock held).
            let (p, b) =
                self.write_batch(settings, generation, day, &services, &day_state, batch)?;
            parts += p;
            bytes += b;
            let mut state = lock(&self.state);
            let st = state.days.get_mut(key).ok_or("the day is not kept")?;
            let before = st.done;
            st.done = st.done.max(batch as u32 + 1);
            if let Err(e) = save(&self.path, &state) {
                if let Some(st) = state.days.get_mut(key) {
                    st.done = before;
                }
                return Err(e);
            }
        }
    }

    fn write_batch(
        &self,
        settings: &Settings,
        generation: &LiveGen,
        day: u64,
        services: &[String],
        st: &DayState,
        batch: usize,
    ) -> Result<(usize, usize), String> {
        let start = if batch == 0 {
            0
        } else {
            st.batch_ends[batch - 1] as usize
        };
        let end = st.batch_ends[batch] as usize;
        let here = members(services, start, end, st.buckets)?;
        let numbers = part_numbers(services, &st.batch_ends, batch, st.buckets)?;
        let (mut parts, mut bytes) = (0usize, 0usize);
        for (bucket, part) in numbers {
            let list = here.get(&bucket).cloned().unwrap_or_default();
            let record = DayRecord {
                generation: generation.id,
                day,
                bucket,
                buckets: st.buckets,
                part,
                services: list
                    .iter()
                    .map(|did| service_keys(&generation.master, *did, day))
                    .collect(),
            };
            let encoded = record.encode();
            if encoded.len()
                > settings
                    .record_max_bytes
                    .max(sp_wire::air_request::stream::DAY_HEADER_BYTES)
            {
                return Err(format!(
                    "a day record of {} services would be {} bytes, over stream.record_max_bytes = {}",
                    list.len(),
                    encoded.len(),
                    settings.record_max_bytes
                ));
            }
            let cell = Cell::Day(DayCell {
                generation: generation.id,
                day,
                bucket,
                part,
            });
            if self.write(&cell, &encoded)? {
                parts += 1;
                bytes += encoded.len();
            }
        }
        Ok((parts, bytes))
    }

    /// The days kept for `generation` (for the operator's log and the tests).
    pub fn days_kept(&self, generation: &[u8; 8]) -> Vec<u64> {
        lock(&self.state)
            .days
            .keys()
            .filter_map(|k| parse_day_key(k))
            .filter(|(g, _)| g == generation)
            .map(|(_, d)| d)
            .collect()
    }
}

/// The bytes of the records of one generation's one day for `services` services
/// (the figure the README gives: 34 bytes a record, 2,145 a service).
pub fn day_bytes(services: usize, records: usize) -> usize {
    records * sp_wire::air_request::stream::DAY_HEADER_BYTES
        + services * sp_wire::air_request::stream::SERVICE_ENTRY_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Keypair;

    /// The DID whose key is the public key of the secret `[n; 32]`.
    fn did(n: u8) -> ServiceDid {
        ServiceDid::from(
            Keypair::from_seckey_slice(SECP256K1, &[n; 32])
                .unwrap()
                .public_key(),
        )
    }

    fn texts(list: &[u8]) -> Vec<String> {
        list.iter().map(|n| did(*n).to_hex()).collect()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("esp-mint-stream-{}-{name}", {
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

    fn server() -> ServerRef {
        ServerRef {
            name: "00".repeat(33),
            host: "127.0.0.1".into(),
        }
    }

    fn gen_of_byte(byte: u8, epoch: u64) -> LiveGen {
        LiveGen {
            epoch,
            id: [byte; 8],
            master: MasterSecret::from_bytes([0x42; 32]),
        }
    }

    fn live(current: u8, previous: Option<u8>) -> Live {
        Live {
            current: gen_of_byte(current, 5),
            previous: previous.map(|b| gen_of_byte(b, 4)),
        }
    }

    fn terms(n: u8, day: u64) -> Terms {
        Terms {
            service: did(n),
            redeemable_after_day: day,
        }
    }

    fn open(dir: &Path) -> Stream {
        Stream::open(dir, server(), 10, &SecretKey::from_array([9; 32]).unwrap()).unwrap()
    }

    /// Fails if the window starts anywhere but at today + m, is not
    /// `days_ahead` long, or can be empty.
    #[test]
    fn the_window_starts_at_today_plus_m_and_is_days_ahead_long() {
        // day 20,000, five seconds in
        let now = 20_000 * 86_400 + 5;
        assert_eq!(window(now, 365, 2), vec![20_365, 20_366]);
        assert_eq!(window(now, 0, 1), vec![20_000]);
        assert_eq!(window(now, 30, 3), vec![20_030, 20_031, 20_032]);
        assert_eq!(window(now + 86_400 - 6, 365, 1), vec![20_365]);
        assert_eq!(window(now + 86_400 - 5, 365, 1), vec![20_366]);
        assert_eq!(window(now, 365, 0), vec![20_365], "never empty");
    }

    /// The keys are the ones the mint signs with (`key_for`), worked out outside
    /// this crate: SHA-256 of `esp-mint/key/v1`, the master secret `[0x42; 32]`,
    /// the amount as 8 bytes big-endian, the 33-byte service ID and the day as 8
    /// bytes big-endian, and a counter byte 0, as a secret key; then its public
    /// key. Fails if the key for an amount, a service or a day is not the one
    /// the mint signs with.
    #[test]
    fn a_services_keys_are_the_keys_the_mint_signs_with() {
        let master = MasterSecret::from_bytes([0x42; 32]);
        let keys = service_keys(&master, did(1), 20_365);
        assert_eq!(keys.service, did(1));
        let hex_of =
            |units: u64| hex::encode(keys.key_for(Amount::from_units(units)).unwrap().serialize());
        assert_eq!(
            hex_of(1),
            "03a3ef15d7674597f48af0009b992de9034ad8bf1dac4ad67fd8b838b8459ff2ed"
        );
        assert_eq!(
            hex_of(2),
            "034362bf0745c63808c75e515edc6869b0df507bcb928ea128bd034c091143c761"
        );
        assert_eq!(
            hex_of(1 << 63),
            "020c588b0b8cc5a1fadac54a5776f96510308b0017aea066b0277bef156dd006dd"
        );
        let next_day = service_keys(&master, did(1), 20_366);
        assert_eq!(
            hex::encode(next_day.keys[0].serialize()),
            "0222bb1c21d1a7453f9d2d8d5a857739a9d86328ce62dad68d211bab89ff0d557c"
        );
        let other = service_keys(&master, did(2), 20_365);
        assert_eq!(
            hex::encode(other.keys[0].serialize()),
            "02f4f155ca30cb8539c61756df654c557ea8d27ed95c48757eb9977e6228e81102"
        );
    }

    /// Eight services in the order 1 to 8, in two buckets: by the hash of the
    /// DID (`sp-wire`'s golden table) key(1), key(2), key(5), key(6) and key(7)
    /// are bucket 1 and key(3), key(4) and key(8) bucket 0. With room for 2
    /// services a record, a batch ends before a bucket would get a third:
    /// services 1, 2 (bucket 1) and 3, 4 (bucket 0) make the first batch, and 5
    /// would be the bucket 1's third; 5 and 6 make the second; 7 and 8 the
    /// third. Fails if a batch can hold more services in a bucket than a record
    /// may, or if a batch is empty.
    #[test]
    fn a_batch_ends_before_a_bucket_passes_what_a_record_holds() {
        let services = texts(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(plan_end(&services, 0, 2, 2).unwrap(), 4);
        assert_eq!(plan_end(&services, 4, 2, 2).unwrap(), 6);
        assert_eq!(plan_end(&services, 6, 2, 2).unwrap(), 8);
        // room for all: one batch
        assert_eq!(plan_end(&services, 0, 2, 100).unwrap(), 8);
        // one bucket, room for 3
        assert_eq!(plan_end(&services, 0, 1, 3).unwrap(), 3);
        assert_eq!(plan_end(&services, 3, 1, 3).unwrap(), 6);
        assert_eq!(plan_end(&services, 6, 1, 3).unwrap(), 8);
        // always at least one service, whatever the room
        assert_eq!(plan_end(&services, 0, 2, 0).unwrap(), 1);
    }

    /// With the batches of the test above (ends 4, 6, 8) and two buckets: batch 0
    /// has part 0 of both buckets; batch 1 has services of bucket 1 only, so it
    /// is bucket 1's part 1 and writes nothing for bucket 0; batch 2 has
    /// service 7 (bucket 1) and service 8 (bucket 0): part 1 of bucket 0 (it has
    /// part 0 only) and part 2 of bucket 1 (parts 0 and 1). Fails if a part
    /// number repeats, skips or is written for a bucket that has nothing in
    /// the batch (except in batch 0).
    #[test]
    fn a_batch_adds_parts_numbered_after_the_ones_a_bucket_has() {
        let services = texts(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let ends = [4u32, 6, 8];
        let numbers = |j| part_numbers(&services, &ends, j, 2).unwrap();
        assert_eq!(numbers(0), BTreeMap::from([(0, 0), (1, 0)]));
        assert_eq!(numbers(1), BTreeMap::from([(1, 1)]));
        assert_eq!(numbers(2), BTreeMap::from([(0, 1), (1, 2)]));
        let third = members(&services, 6, 8, 2).unwrap();
        assert_eq!(third[&1], vec![did(7)]);
        assert_eq!(third[&0], vec![did(8)]);
        assert!(part_numbers(&services, &ends, 3, 2).is_err());
    }

    /// Fails if a service is learned twice, if a day is not kept for both live
    /// generations, if the state is not on disk after a note (a service that is
    /// only in memory would be lost by a restart) or if the room check lets a
    /// service past the cap.
    #[test]
    fn a_note_adds_the_service_once_and_keeps_the_day_for_both_live_generations() {
        let dir = scratch("note");
        let stream = open(&dir);
        let both = live(0x11, Some(0x22));
        stream
            .note(
                &both,
                &[
                    terms(1, 20_365),
                    terms(1, 20_366),
                    terms(2, 20_365),
                    terms(1, 20_365),
                ],
            )
            .unwrap();
        assert_eq!(stream.service_count(), 2);
        assert_eq!(stream.days_kept(&[0x11; 8]), vec![20_365, 20_366]);
        assert_eq!(stream.days_kept(&[0x22; 8]), vec![20_365, 20_366]);
        // the same again changes nothing
        stream.note(&both, &[terms(2, 20_365)]).unwrap();
        assert_eq!(stream.service_count(), 2);
        // a restart reads it back
        let again = open(&dir);
        assert_eq!(again.service_count(), 2);
        assert_eq!(again.days_kept(&[0x11; 8]), vec![20_365, 20_366]);
        // room for a known service at any cap, for a new one only under it
        assert!(again.has_room_for(&did(1), 2));
        assert!(!again.has_room_for(&did(3), 2));
        assert!(again.has_room_for(&did(3), 3));
        assert!(
            again.has_room_for(&did(1), 1),
            "a known service is never refused"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Fails if a note that could not be saved is kept in memory: a retry would
    /// then find nothing to add, say "done", and the service would be lost at the
    /// next restart.
    #[test]
    fn a_note_that_cannot_be_saved_leaves_nothing_behind() {
        let dir = scratch("unsaved").join("not-there");
        let stream = open(&dir);
        let err = stream
            .note(&live(0x11, None), &[terms(1, 20_365)])
            .unwrap_err();
        assert!(err.contains("cannot save"), "{err}");
        assert_eq!(stream.service_count(), 0);
        assert_eq!(stream.days_kept(&[0x11; 8]), Vec::<u64>::new());
    }

    /// A generation that is no longer live loses its days (every note of it
    /// has passed its redeem window: the generation is deleted), and the
    /// window is kept for the current generation only.
    #[test]
    fn days_of_a_generation_that_is_gone_are_forgotten_and_the_window_is_the_current_ones() {
        let dir = scratch("prune");
        let stream = open(&dir);
        stream
            .note(&live(0x11, Some(0x22)), &[terms(1, 20_000)])
            .unwrap();
        // a rotation: 0x33 is current, 0x11 previous, 0x22 is deleted
        let after = live(0x33, Some(0x11));
        stream.prune(&after).unwrap();
        assert_eq!(stream.days_kept(&[0x22; 8]), Vec::<u64>::new());
        assert_eq!(stream.days_kept(&[0x11; 8]), vec![20_000]);
        let settings = Settings {
            days_ahead: 2,
            record_max_bytes: 4 << 20,
            max_services: 10,
            maturity_days: 365,
        };
        stream
            .keep_window(&settings, &after, 20_000 * 86_400)
            .unwrap();
        assert_eq!(stream.days_kept(&[0x33; 8]), vec![20_365, 20_366]);
        assert_eq!(
            stream.days_kept(&[0x11; 8]),
            vec![20_000],
            "no window for the previous"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The control record carries `m` and both generations; what is written
    /// reads back the same.
    #[test]
    fn a_control_record_is_made_from_m_and_the_live_generations() {
        let fields = ControlFields::of(365, &live(0x11, Some(0x22)));
        let record = fields.record(3).unwrap();
        assert_eq!(
            record,
            ControlRecord {
                index: 3,
                maturity_days: 365,
                current: GenerationRef {
                    epoch: 5,
                    id: [0x11; 8]
                },
                previous: Some(GenerationRef {
                    epoch: 4,
                    id: [0x22; 8]
                }),
            }
        );
        assert_eq!(ControlFields::from_record(&record), fields);
        let alone = ControlFields::of(0, &live(0x11, None));
        assert_eq!(alone.record(0).unwrap().previous, None);
        assert_ne!(fields, ControlFields::of(364, &live(0x11, Some(0x22))));
    }

    /// The figure the README gives: 34 bytes a record, 2,145 a service.
    #[test]
    fn a_days_size_is_34_bytes_a_record_and_2145_a_service() {
        assert_eq!(day_bytes(0, 1), 34);
        assert_eq!(day_bytes(1, 1), 2_179);
        assert_eq!(day_bytes(1_000, 1), 2_145_034);
        // a bucket of 256 services
        assert_eq!(day_bytes(256, 1), 549_154);
    }
}
