//! The real `esp-mint serve` run as a process, with a scratch data folder, a
//! stand-in PSP and the in-process AIR server (`sp_wire::air_request::local_server`,
//! on port 5702, so these tests take turns with each other and need that port
//! free), sent the signals an operator (or `spi`) sends.
//!
//! What they check:
//!
//! - `SIGHUP` with a live setting changes it with nothing restarted, the PSP
//!   client's timeout and retry included.
//! - `SIGHUP` with a setting that needs a restart (an address, an AIR setting)
//!   names it, says it waits for a restart, and leaves the running values and the
//!   process as they were.
//! - `SIGUSR1` takes a snapshot while the mint serves, the snapshot restores to a
//!   mint with the same audit, and a snapshot taken while the PSP is down leaves
//!   the mint serving (it does not wait for the PSP again).
//! - `SIGTERM` ends the mint with status 0 and its own stop line, while serving
//!   and while waiting for the PSP.
//!
//! There are no sleeps for synchronisation: each wait is a bounded poll on the
//! condition the test needs (a line in the mint's log, a file, an answer).
//!
//! The mint's output goes to a log file in the scratch folder, which the tests
//! read.

mod common;

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use esp_mint::config::Config;
use esp_mint::psp_client::HttpPsp;
use esp_mint::server::EspState;
use serde_json::Value;
use sp_wire::ServiceDid;
use sp_wire::WIRE_VERSION;
use sp_wire::air_request::ask::{AskConfig, AskError, InFlight, Verified, ask};
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::{KIND_FEES, KIND_KEYSETS};

// ---- the scratch world ---------------------------------------------------------

fn scratch(name: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "esp-mint-serve-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// An address on this machine that was free a moment ago.
fn free_addr() -> String {
    let free = TcpListener::bind("127.0.0.1:0").unwrap();
    free.local_addr().unwrap().to_string()
}

/// Wait, up to two minutes, until `condition` holds. Only the polling interval is
/// a sleep; what the test waits for is the condition.
fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

// One test at a time on the AIR server and on its port, which `common::server`
// makes sure of; this keeps the tests' own mints from overlapping as well.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// A PSP that answers `GET /health` with its network, which is all `serve` asks
/// of it at start. It can be stopped, after which nothing listens at its address.
struct StandInPsp {
    url: String,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl StandInPsp {
    fn start(network: &'static str) -> StandInPsp {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let thread = thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            thread::spawn(move || answer_health(stream, network));
                        }
                        Err(_) => thread::sleep(Duration::from_millis(10)),
                    }
                }
                // The listener is dropped here: the port refuses connections.
            }
        });
        StandInPsp {
            url,
            stop,
            thread: Some(thread),
        }
    }

    /// Stop listening; returns when the port is closed.
    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn answer_health(mut stream: TcpStream, network: &str) {
    stream.set_nonblocking(false).unwrap();
    let mut seen = Vec::new();
    let mut chunk = [0u8; 1024];
    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => seen.extend_from_slice(&chunk[..n]),
        }
    }
    let body = format!("{{\"network\":\"{network}\"}}");
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(reply.as_bytes());
}

/// One HTTP GET, as a client that closes the connection after the answer: the
/// status and the body. A refused connection, a reset or a timeout is an `Err`.
fn http_get(addr: &str, path: &str) -> Result<(u16, String), String> {
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .map_err(|e| format!("write {addr}{path}: {e}"))?;
    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .map_err(|e| format!("read {addr}{path}: {e}"))?;
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("{addr}{path}: no complete answer: {raw:?}"))?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("{addr}{path}: no status in {head:?}"))?;
    Ok((status, body.to_string()))
}

fn health(addr: &str) -> Result<Value, String> {
    let (status, body) = http_get(addr, "/health")?;
    if status != 200 {
        return Err(format!("{addr}/health answered {status}: {body}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("{addr}/health: {e}: {body}"))
}

// ---- the mint as a process -----------------------------------------------------

/// A running `esp-mint serve` and what is needed to reach and signal it.
struct Mint {
    child: Child,
    api: String,
    admin: String,
    log: PathBuf,
    did: ServiceDid,
}

fn settings_file(api: &str, admin: &str) -> String {
    format!("[server]\nbind = \"{api}\"\nadmin_bind = \"{admin}\"\n")
}

/// The environment of a run: nothing of the machine's, a data folder, the AIR
/// server and the PSP. The two addresses are in the settings file, so that a
/// test can change them there.
fn env_of(base: &Path, air: &ServerRef, psp: &str) -> Vec<(String, String)> {
    vec![
        ("ESP_DATA_DIR".into(), base.display().to_string()),
        ("ESP_AIR_SERVER".into(), air.name.clone()),
        ("ESP_AIR_HOST".into(), air.host.clone()),
        ("ESP_PSP_URL".into(), psp.to_string()),
    ]
}

impl Mint {
    /// Write the settings file with fresh addresses, make the mint's DID, and
    /// start `serve`. Returns before it is up.
    fn start_unready(base: &Path, air: &ServerRef, psp: &str) -> Mint {
        let (api, admin) = (free_addr(), free_addr());
        fs::write(base.join("esp-mint.toml"), settings_file(&api, &admin)).unwrap();
        let env = env_of(base, air, psp);
        let pubkey = Command::new(env!("CARGO_BIN_EXE_esp-mint"))
            .arg("pubkey")
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .output()
            .unwrap();
        assert!(pubkey.status.success(), "{pubkey:?}");
        let did = ServiceDid::parse(String::from_utf8(pubkey.stdout).unwrap().trim()).unwrap();
        let log = base.join("esp-mint.log");
        let out = fs::File::create(&log).unwrap();
        let err = out.try_clone().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_esp-mint"))
            .arg("serve")
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .unwrap();
        Mint {
            child,
            api,
            admin,
            log,
            did,
        }
    }

    fn start(base: &Path, air: &ServerRef, psp: &str) -> Mint {
        let mint = Mint::start_unready(base, air, psp);
        wait_until("the mint to answer /health", || health(&mint.api).is_ok());
        mint
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Send the process a signal, as `kill -USR1 <pid>` does.
    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .arg(format!("-{name}"))
            .arg(self.pid().to_string())
            .status()
            .unwrap();
        assert!(status.success(), "kill -{name} {}", self.pid());
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn wait_for_log(&self, text: &str) {
        wait_until(&format!("`{text}` in the mint's log"), || {
            self.log().contains(text)
        });
    }

    /// Stop it with `SIGTERM`, check it ends cleanly (status 0), and return its
    /// whole log.
    fn stop(mut self) -> String {
        self.signal("TERM");
        let mut status = None;
        wait_until("the mint to end after SIGTERM", || {
            status = self.child.try_wait().unwrap();
            status.is_some()
        });
        let log = self.log();
        assert_eq!(status.unwrap().code(), Some(0), "{status:?}\n{log}");
        log
    }
}

impl Drop for Mint {
    fn drop(&mut self) {
        // A test that failed leaves nothing running. Both fail only if it ended.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The wallet side: one request over AIR, the way the wallet sends it.
#[derive(Clone)]
struct Wallet {
    cfg: AskConfig,
}

impl Wallet {
    fn new(server: &ServerRef, mint: ServiceDid) -> Wallet {
        Wallet {
            cfg: AskConfig {
                server: server.clone(),
                mint,
                wire_version: WIRE_VERSION,
                network: "main".to_string(),
                reply_wait_secs: 60,
                attempts: 3,
                max_skew_secs: 300,
                timeout_secs: 20,
            },
        }
    }

    fn ask(&self, kind: u8) -> Result<Verified, AskError> {
        let cfg = self.cfg.clone();
        block_on_new_runtime(move || async move {
            let client = client::connect(&cfg.server).await?;
            let mut flight = InFlight::with_body(kind, Vec::new());
            ask(&client, &cfg, &mut flight, &mut |_| Ok(())).await
        })
        .map_err(AskError::from)
        .and_then(|r| r)
    }

    fn json(&self, kind: u8) -> Value {
        let reply = self.ask(kind).unwrap();
        assert!(!reply.refused());
        serde_json::from_slice(reply.body()).unwrap()
    }
}

// ---- the tests -----------------------------------------------------------------

#[test]
fn a_reload_of_live_settings_changes_them_with_no_restart() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let server = common::server();
    let psp = StandInPsp::start("main");
    let base = scratch("live");
    let mint = Mint::start(&base, &server, &psp.url);
    let pid = mint.pid();
    let wallet = Wallet::new(&server, mint.did);
    assert_eq!(wallet.json(KIND_FEES)["redeem"]["fee_per_byte"], "0");

    // A fee, and the two PSP settings that used to need a restart.
    let mut file = settings_file(&mint.api, &mint.admin);
    file.push_str(
        "[redeem]\nfee_per_byte = 5000000\n[psp]\ntimeout_secs = 12\nstartup_retry_secs = 2\n",
    );
    fs::write(base.join("esp-mint.toml"), file).unwrap();
    mint.signal("HUP");
    wait_until("the new redeem fee to be in force", || {
        wallet.json(KIND_FEES)["redeem"]["fee_per_byte"] == "5000000"
    });

    let log = mint.log();
    for line in [
        "redeem.fee_per_byte changed from 0 to 5000000",
        "psp.timeout_secs changed from 30 to 12 seconds",
        "psp.startup_retry_secs changed from 5 to 2 seconds",
    ] {
        assert!(log.contains(line), "{line:?} not in {log}");
    }
    assert!(!log.contains("need a restart"), "{log}");
    assert!(!log.contains("needs a restart"), "{log}");
    // The same process, started once.
    assert_eq!(mint.pid(), pid);
    assert_eq!(log.matches("AIR listener starting").count(), 1, "{log}");
    mint.stop();
}

#[test]
fn a_reload_of_an_address_and_an_air_setting_names_them_and_waits_for_a_restart() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let server = common::server();
    let psp = StandInPsp::start("main");
    let base = scratch("restart-only");
    let mint = Mint::start(&base, &server, &psp.url);
    let pid = mint.pid();
    let wallet = Wallet::new(&server, mint.did);

    // A new API address, a new AIR setting and a live setting, in one reload.
    let new_api = free_addr();
    fs::write(
        base.join("esp-mint.toml"),
        format!(
            "{}[air]\nheld_reads = 8\n[redeem]\nfee_per_byte = 5000000\n",
            settings_file(&new_api, &mint.admin)
        ),
    )
    .unwrap();
    mint.signal("HUP");
    // The live setting is in force, which shows the reload ran to its end.
    wait_until("the new redeem fee to be in force", || {
        wallet.json(KIND_FEES)["redeem"]["fee_per_byte"] == "5000000"
    });

    let log = mint.log();
    for line in [
        format!(
            "server.bind is changed in the file from {} to {new_api}: it needs a restart (a brief downtime) and waits for one",
            mint.api
        ),
        "air.held_reads is changed in the file from 16 to 8: it needs a restart (a brief downtime) and waits for one".to_string(),
        "server.bind, air.held_reads need a restart, which is a brief downtime, so they keep their running values until the mint is restarted".to_string(),
    ] {
        assert!(log.contains(&line), "{line:?} not in {log}");
    }
    // The running values are unchanged: the old address still answers, the new
    // one is not listened on, and the AIR listener was not started again.
    assert!(health(&mint.api).is_ok());
    assert!(TcpStream::connect(&new_api).is_err());
    assert!(!log.contains("air.held_reads = 8"), "{log}");
    assert_eq!(mint.pid(), pid);
    assert_eq!(log.matches("AIR listener starting").count(), 1, "{log}");
    mint.stop();
}

#[test]
fn a_snapshot_is_taken_while_serving_and_restores_to_a_mint_with_the_same_audit() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let server = common::server();
    let psp = StandInPsp::start("main");
    let base = scratch("snapshot");

    // A mint that has something to audit: ESP issued under a day far ahead. It is
    // made and closed here, so the process below opens it as an existing mint.
    {
        let state = EspState::open(
            &base.join("main"),
            Box::new(HttpPsp::new("http://127.0.0.1:1").unwrap()),
            Config::default(),
            0,
        )
        .unwrap();
        common::record_issued(&state, 100_000, 12_345);
    }

    let mint = Mint::start(&base, &server, &psp.url);
    let pid = mint.pid();
    let did = mint.did;
    let wallet = Wallet::new(&server, did);
    let keysets = wallet.json(KIND_KEYSETS);
    let audit = |addr: &str| -> Value {
        let (status, body) = http_get(addr, "/audit").unwrap();
        assert_eq!(status, 200, "{body}");
        let mut value: Value = serde_json::from_str(&body).unwrap();
        // The day changes at midnight, not with the data.
        value.as_object_mut().unwrap().remove("as_of_day");
        value
    };
    let before = audit(&mint.api);
    assert_eq!(before["outstanding_unmatured"], 12_345, "{before}");

    mint.signal("USR1");
    let latest = base.join("main").join("snapshots").join("LATEST");
    wait_until("the snapshot to be named in LATEST", || latest.is_file());
    mint.wait_for_log("esp-mint: snapshot written to");
    // Serving again, the same process, the same books.
    wait_until("the mint to answer again", || health(&mint.api).is_ok());
    assert_eq!(mint.pid(), pid);
    assert_eq!(audit(&mint.api), before);
    assert_eq!(wallet.json(KIND_KEYSETS), keysets);

    let name = fs::read_to_string(&latest).unwrap();
    let snapshot = base.join("main").join("snapshots").join(name.trim());
    assert!(snapshot.is_dir());
    assert_eq!(
        fs::metadata(&snapshot).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(snapshot.join(esp_mint::did::KEY_FILENAME).is_file());
    mint.stop();

    // Restore: the snapshot is the network's folder of a new base, and a mint
    // started on it reports the same books and the same keys.
    let restored_base = scratch("snapshot-restored");
    copy_dir(&snapshot, &restored_base.join("main"));
    let restored = Mint::start(&restored_base, &server, &psp.url);
    // Same DID: the snapshot carries the mint's key, so wallets find it where it was.
    assert_eq!(restored.did, did);
    assert_eq!(audit(&restored.api), before);
    assert_eq!(wallet.json(KIND_KEYSETS), keysets);
    restored.stop();
}

#[test]
fn a_snapshot_taken_while_the_psp_is_down_leaves_the_mint_serving() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let server = common::server();
    let mut psp = StandInPsp::start("main");
    let base = scratch("snapshot-psp-down");
    let mint = Mint::start(&base, &server, &psp.url);
    let wallet = Wallet::new(&server, mint.did);
    let keysets = wallet.json(KIND_KEYSETS);

    // The PSP goes away, and then the snapshot is asked for. The mint was up
    // with the PSP before, so it opens again without asking it.
    psp.stop();
    mint.signal("USR1");
    mint.wait_for_log("esp-mint: snapshot written to");
    mint.wait_for_log("esp-mint: opening the mint again with the settings it was running with");
    wait_until("the mint to answer again", || health(&mint.api).is_ok());
    assert_eq!(wallet.json(KIND_KEYSETS), keysets);

    let log = mint.log();
    assert!(!log.contains("cannot ask the PSP"), "{log}");
    mint.stop();
}

#[test]
fn sigterm_while_serving_ends_the_mint_with_status_0_and_says_it_stopped() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let server = common::server();
    let psp = StandInPsp::start("main");
    let base = scratch("sigterm");
    let mint = Mint::start(&base, &server, &psp.url);
    // `stop` checks the status is 0.
    let log = mint.stop();
    assert_eq!(log.matches("shutting down").count(), 1, "{log}");
    assert_eq!(
        log.matches("esp-mint: stopped, the data is closed").count(),
        1,
        "{log}"
    );
    assert!(!log.contains("panicked"), "{log}");
}

#[test]
fn sigterm_while_waiting_for_the_psp_ends_the_mint_cleanly() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let server = common::server();
    let base = scratch("psp-wait");
    // Nothing listens at the PSP's address, so `serve` waits for it.
    let dead_psp = format!("http://{}", free_addr());
    let mint = Mint::start_unready(&base, &server, &dead_psp);
    mint.wait_for_log("cannot ask the PSP");
    assert!(mint.log().contains("Trying again every 5 s"));
    // The sockets are already listening, so a client waits in the queue.
    assert!(TcpStream::connect(&mint.api).is_ok());
    let log = mint.stop();
    assert!(
        log.contains("shutting down before the PSP answered"),
        "{log}"
    );
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}
