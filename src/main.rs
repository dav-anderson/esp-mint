use std::env;
use std::error::Error;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use esp_mint::admin::{self, AdminState};
use esp_mint::air_listener;
use esp_mint::config;
use esp_mint::did;
use esp_mint::netdir;
use esp_mint::payouts;
use esp_mint::psp_client::HttpPsp;
use esp_mint::server::{self, EspState};
use esp_mint::snapshot;
use tokio::sync::{mpsc, oneshot, watch};

/// How long the HTTP servers get to finish the requests they are answering when
/// the mint is closed (for a snapshot or an exit). A request still running then
/// is cut off, so that every handle on the mint's data can be dropped.
const DRAIN_SECS: u64 = 30;

/// Load the settings, or say everything that is wrong with them.
fn load_config(data_dir: &std::path::Path) -> Result<config::Loaded, Box<dyn Error>> {
    config::load(data_dir, &config::process_env).map_err(|problems| {
        let mut text = String::from("the settings are not valid:");
        for problem in problems {
            text.push_str("\n  ");
            text.push_str(&problem);
        }
        text.into()
    })
}

/// What a signal asks of the running mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    /// `SIGHUP`: read the settings again.
    Reload,
    /// `SIGUSR1`: take a snapshot of the data folder.
    Snapshot,
    /// `SIGTERM` or `SIGINT`: stop.
    Stop,
}

/// The two listening sockets: the API (`server.bind`) and the operator's
/// (`server.admin_bind`). They belong to the process, not to one run of the mint
/// in it, so that they stay open, and keep queueing connections, while the mint's
/// data is closed and opened again for a snapshot.
#[derive(Default)]
struct Sockets {
    api: Option<TcpListener>,
    admin: Option<TcpListener>,
}

/// What a run of the mint ended with. The data it had open is closed (every
/// handle on it is dropped) before it returns.
enum Outcome {
    /// Stop the process.
    Exit,
    /// Copy the data folder, and then open it again.
    Snapshot(PathBuf),
}

/// What lives as long as the process (see [`Sockets`]).
struct Ctx {
    runtime: tokio::runtime::Runtime,
    /// The signals, in the order they arrived. Made once, before anything else is
    /// opened, so that a signal that arrives while the mint is closed (during a
    /// snapshot) waits here, and is never met by the default action, which for
    /// `SIGHUP` and `SIGUSR1` ends the process.
    events: mpsc::UnboundedReceiver<Event>,
    /// Set by `SIGTERM` and `SIGINT`, for the places that wait without looking at
    /// `events` (the wait for the PSP).
    stop: Arc<AtomicBool>,
    base: PathBuf,
    sockets: Sockets,
    /// The settings the mint was running with when it was closed for a snapshot:
    /// the live ones as they were last reloaded, the restart-only ones as the
    /// process started with them. The mint opens again with these, not with what
    /// the file says now, and does not wait for the PSP (it was up before).
    /// `None` until the first snapshot.
    running: Option<config::Config>,
}

/// Run the ESP mint: the AIR listener (the only way wallets reach it), the
/// loopback HTTP API that is left (`/audit`, `/health`) and the operator's
/// listener.
///
/// The settings are in `esp-mint.toml` in the data directory (or the file
/// `ESP_CONFIG` names), each with an environment variable that overrides it.
/// `esp-mint config` lists them all with the values in use. They are logged at
/// startup, and a bad value stops the mint with a message that says which.
///
/// **Signals** (a reload and a snapshot stop neither the mint's service nor
/// refuse a connection):
///
/// - `SIGHUP` reads the settings again. A setting that reloads live changes for
///   the next request. A setting that needs a restart (`reload` false in
///   `config.rs`: the addresses, rotation, the storage list, the AIR settings and
///   the admin body ceiling) is named in the log and keeps its running value
///   until the mint is restarted.
/// - `SIGUSR1` takes a snapshot of the data folder (`snapshot.rs`): the mint is
///   closed, the folder copied, and the mint opened again with the settings it
///   was running with, without waiting for the PSP.
/// - `SIGTERM` and `SIGINT` stop the mint after the requests it is answering.
///
/// Two things are not settings. `ESP_DATA_DIR` (default `~/.esp-mint`) says where
/// the master secret, the mint's database, the stored responses and the config
/// file are, and `ESP_ADMIN_TOKEN` (optional, a secret, so never in a file) makes
/// the operator's routes need `Authorization: Bearer <token>`.
fn serve() -> Result<(), Box<dyn Error>> {
    // The signals come first. From here on `SIGHUP` and `SIGUSR1` are events,
    // not the end of the process.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (events, stop) = listen_for_signals(&runtime)?;
    say_network()?;
    let mut ctx = Ctx {
        runtime,
        events,
        stop,
        base: data_dir()?,
        sockets: Sockets::default(),
        running: None,
    };
    loop {
        match run_once(&mut ctx)? {
            Outcome::Exit => {
                // After every thread is joined and every handle on the data is
                // dropped.
                println!("esp-mint: stopped, the data is closed");
                return Ok(());
            }
            Outcome::Snapshot(dir) => {
                match snapshot::take(&dir, &snapshot::stamp(server::now_secs())) {
                    Ok(path) => println!("esp-mint: snapshot written to {}", path.display()),
                    Err(why) => eprintln!(
                        "esp-mint: the snapshot failed and was removed, still serving: {why}"
                    ),
                }
            }
        }
    }
}

/// Turn `SIGHUP`, `SIGUSR1`, `SIGTERM` and `SIGINT` into [`Event`]s.
fn listen_for_signals(
    runtime: &tokio::runtime::Runtime,
) -> Result<(mpsc::UnboundedReceiver<Event>, Arc<AtomicBool>), Box<dyn Error>> {
    use tokio::signal::unix::{SignalKind, signal};
    let (mut hangup, mut usr1, mut term, mut interrupt) = runtime.block_on(async {
        Ok::<_, std::io::Error>((
            signal(SignalKind::hangup())?,
            signal(SignalKind::user_defined1())?,
            signal(SignalKind::terminate())?,
            signal(SignalKind::interrupt())?,
        ))
    })?;
    let (send, events) = mpsc::unbounded_channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = Arc::clone(&stop);
    runtime.spawn(async move {
        loop {
            let event = tokio::select! {
                _ = hangup.recv() => Event::Reload,
                _ = usr1.recv() => Event::Snapshot,
                _ = term.recv() => Event::Stop,
                _ = interrupt.recv() => Event::Stop,
            };
            if event == Event::Stop {
                stopping.store(true, Ordering::SeqCst);
            }
            if send.send(event).is_err() {
                return;
            }
        }
    });
    Ok((events, stop))
}

/// One run of the mint: open everything, serve until a signal asks for something
/// else, close everything, and say what to do next. Every handle on the mint's
/// data (the sled databases, the stored responses) is dropped before this
/// returns, which flushes it and releases its file lock; the sockets are not.
///
/// The first run reads the settings and waits for the PSP, to check its network.
/// A run after a snapshot does neither: it opens with the settings the mint was
/// running with (`Ctx::running`), and the PSP, which was up before, is not asked,
/// so that a snapshot taken while the PSP is down does not leave this mint
/// unavailable.
fn run_once(ctx: &mut Ctx) -> Result<Outcome, Box<dyn Error>> {
    let reopening = ctx.running.is_some();
    let cfg = match ctx.running.take() {
        Some(cfg) => {
            println!("esp-mint: opening the mint again with the settings it was running with");
            cfg
        }
        None => {
            let loaded = load_config(&ctx.base)?;
            match &loaded.file {
                Some(file) => println!(
                    "esp-mint settings from {}, and the environment:",
                    file.display()
                ),
                None => {
                    println!("esp-mint settings: no config file, so defaults and the environment:")
                }
            }
            for line in loaded.describe() {
                println!("{line}");
            }
            loaded.config
        }
    };
    // AIR is the only way wallets reach this mint: without its server and host
    // there is nothing to serve.
    cfg.require_air()?;
    // Everything that can be refused is refused before the data folder is made.
    let admin_token = match env::var("ESP_ADMIN_TOKEN") {
        Ok(token) if token.is_empty() => return Err("ESP_ADMIN_TOKEN is set but empty".into()),
        Ok(token) => Some(token),
        Err(_) => None,
    };
    let data_dir = netdir::network_dir(&ctx.base, &cfg.network);
    std::fs::create_dir_all(&data_dir)?;
    let api_bind: SocketAddr = cfg
        .bind
        .parse()
        .map_err(|e| format!("server.bind `{}`: {e}", cfg.bind))?;
    let admin_bind = admin::check_loopback(&cfg.admin_bind)?;
    // The sockets before anything slow: from here on a client that connects waits
    // in the backlog, and is answered when the mint is up, instead of being refused.
    ensure_sockets(ctx, api_bind, admin_bind)?;
    // The AIR listener answers wallets' requests on a thread of its own, with
    // the mint's own DID key (made on first use). Read before `cfg` moves into
    // the settings handle.
    let air = cfg.air_listener(&data_dir);
    let did_key = did::load_or_generate(&data_dir.join(did::KEY_FILENAME))?;

    // The blocking client is made here, outside the async runtime (it makes one
    // of its own), and it is dropped with the state, also outside it.
    let psp_url = cfg.psp_url.clone();
    let psp = HttpPsp::with_timeout(&cfg.psp_url, cfg.psp_timeout_secs)?;
    // A reload of `psp.timeout_secs` is stored here; the client reads it at
    // every call.
    let psp_timeout = psp.timeout_handle();
    if !reopening {
        // The PSP must be on our network, or PSP notes from one chain would buy
        // ESP on another. An unreachable PSP is refused too: the network cannot
        // be checked. It is not given up on: the mint may be started before the
        // PSP, or after a power cut that took both down, and nobody should have
        // to start it again. `psp.startup_retry_secs` is read from the file at
        // every try, so a change made while the mint waits is used at once.
        let (base, fallback) = (ctx.base.clone(), cfg.psp_startup_retry_secs);
        let retry_secs = move || {
            load_config(&base)
                .map(|loaded| loaded.config.psp_startup_retry_secs)
                .unwrap_or(fallback)
        };
        let reported = match wait_for_psp(&psp, &psp_url, &retry_secs, &ctx.stop) {
            Ok(reported) => reported,
            Err(Stopped) => {
                println!("shutting down before the PSP answered");
                return Ok(Outcome::Exit);
            }
        };
        config::check_psp_network(&cfg.network, reported.as_deref())?;
        println!(
            "esp-mint on {}: the PSP at {psp_url} is on the same network",
            cfg.network
        );
    }
    // The mint, the rotor, the stored responses and the queue, on the system
    // clock (`0`).
    let state = Arc::new(EspState::open(&data_dir, Box::new(psp), cfg, 0)?);
    for line in state
        .rotor
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .describe()
    {
        println!("{line}");
    }

    // Dropped (stopped and joined) before `state`, on every way out.
    let mut running = Running::start(air, did_key, &state)?;

    // The HTTP servers run on a runtime of their own for this run, which is
    // dropped at its end, so that no task they started can hold the state.
    let http = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("esp-http")
        .build()?;
    let (mut servers, shutdown) = http.block_on(start_servers(
        &ctx.sockets,
        &state,
        &data_dir,
        admin_token,
        &psp_url,
    ))?;

    let decision = ctx.runtime.block_on(watch_events(
        &mut ctx.events,
        &mut servers,
        &state,
        &ctx.base,
        &psp_timeout,
    ));

    // Stop answering, in this order: the AIR listener (a wallet's request now
    // waits in its mailbox slot), then the HTTP servers (they finish the requests
    // they have, for at most DRAIN_SECS, and the kernel queues the connections
    // that arrive), then the watch thread.
    running.stop_air();
    if !matches!(decision, Decision::ServersEnded(_)) {
        // Fails only if the servers already ended, which the join below reports.
        let _ = shutdown.send(true);
        // The timeout is made inside the runtime: `tokio::time::timeout` needs
        // its timer when it is created.
        let drained = ctx.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(DRAIN_SECS), &mut servers).await
        });
        match drained {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(why))) => return Err(why.into()),
            Ok(Err(e)) => return Err(format!("the server task failed: {e}").into()),
            Err(_) => eprintln!(
                "esp-mint: the HTTP servers still had requests running after {DRAIN_SECS} s; they are cut off"
            ),
        }
    }
    // Drops every task and connection the runtime still has.
    http.shutdown_timeout(Duration::from_secs(5));
    running.stop_watch();

    // Nothing but this function holds the state now: the last handle goes here,
    // outside any async context, and the databases flush and unlock.
    let running_settings = (*state.config.current()).clone();
    let released = Arc::try_unwrap(state);
    match (released, &decision) {
        (Ok(state), _) => drop(state),
        (Err(_), Decision::Snapshot) => {
            return Err(
                "the snapshot is refused: a task still holds the mint's data, so a copy of it would not be whole and it cannot be opened again in this process. Exiting so that a supervisor starts the mint again"
                    .into(),
            );
        }
        (Err(_), _) => eprintln!(
            "esp-mint: warning: a thread still held the mint's data when it was closed, so the databases may not have been flushed"
        ),
    }

    match decision {
        Decision::Exit => Ok(Outcome::Exit),
        Decision::Snapshot => {
            ctx.running = Some(running_settings);
            Ok(Outcome::Snapshot(data_dir))
        }
        Decision::ServersEnded(Ok(())) => Err("the HTTP servers ended on their own".into()),
        Decision::ServersEnded(Err(why)) => Err(why.into()),
    }
}

/// Bind whichever of the two sockets is not open yet. They are bound once, at
/// the first run, and kept for the life of the process; their addresses are
/// restart-only settings, so they cannot change meanwhile.
fn ensure_sockets(ctx: &mut Ctx, api: SocketAddr, admin: SocketAddr) -> Result<(), Box<dyn Error>> {
    for (slot, want, name) in [
        (&mut ctx.sockets.api, api, "API"),
        (&mut ctx.sockets.admin, admin, "operator's"),
    ] {
        if slot.is_none() {
            *slot = Some(bind(want, name)?);
        }
    }
    Ok(())
}

/// Listen on `addr`; the socket is non-blocking (a flag that copies of it share).
fn bind(addr: SocketAddr, name: &str) -> Result<TcpListener, String> {
    let listener = TcpListener::bind(addr)
        .map_err(|e| format!("cannot listen on {addr} ({name} socket): {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("{addr}: {e}"))?;
    Ok(listener)
}

/// The two HTTP servers, on copies of the listening sockets (the originals stay
/// open for as long as the process lives), as a task of their own that ends when
/// `shutdown` is set to true, after it has finished the requests it is answering.
async fn start_servers(
    sockets: &Sockets,
    state: &Arc<EspState>,
    data_dir: &Path,
    admin_token: Option<String>,
    psp_url: &str,
) -> Result<
    (
        tokio::task::JoinHandle<Result<(), String>>,
        watch::Sender<bool>,
    ),
    Box<dyn Error>,
> {
    let (Some(api), Some(admin_socket)) = (&sockets.api, &sockets.admin) else {
        return Err("the listening sockets are not open".into());
    };
    let listener = tokio::net::TcpListener::from_std(api.try_clone()?)?;
    let admin_listener = tokio::net::TcpListener::from_std(admin_socket.try_clone()?)?;
    println!(
        "esp-mint api (/audit, /health) listening on http://{}, burning PSP at {psp_url}",
        listener.local_addr()?
    );
    println!(
        "esp-mint admin listening on http://{}",
        admin_listener.local_addr()?
    );
    let app = server::router(Arc::clone(state));
    let admin_app = admin::router(Arc::new(AdminState {
        queue_path: server::queue_path(data_dir),
        lock: Mutex::new(()),
        token: admin_token,
        esp: Arc::clone(state),
    }));
    let (shutdown, stop) = watch::channel(false);
    let mut stop_api = stop.clone();
    let mut stop_admin = stop;
    let task = tokio::spawn(async move {
        let api = async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stop_api.wait_for(|stopped| *stopped).await;
                })
                .await
        };
        let admin = async move {
            axum::serve(admin_listener, admin_app)
                .with_graceful_shutdown(async move {
                    let _ = stop_admin.wait_for(|stopped| *stopped).await;
                })
                .await
        };
        tokio::try_join!(api, admin)
            .map(|_| ())
            .map_err(|e| format!("an HTTP server failed: {e}"))
    });
    Ok((task, shutdown))
}

/// What the signals decided.
enum Decision {
    Exit,
    Snapshot,
    /// The HTTP servers ended without being asked to.
    ServersEnded(Result<(), String>),
}

/// Serve until a signal asks for the mint to be closed, answering `SIGHUP` on
/// the way. The HTTP servers are a task of their own, so a reload here never
/// delays a connection.
async fn watch_events(
    events: &mut mpsc::UnboundedReceiver<Event>,
    servers: &mut tokio::task::JoinHandle<Result<(), String>>,
    state: &Arc<EspState>,
    base: &Path,
    psp_timeout: &AtomicU64,
) -> Decision {
    loop {
        tokio::select! {
            ended = &mut *servers => {
                return Decision::ServersEnded(
                    ended.unwrap_or_else(|e| Err(format!("the server task failed: {e}"))),
                );
            }
            event = events.recv() => {
                let Some(event) = event else { return Decision::Exit };
                match event {
                    Event::Stop => {
                        println!("shutting down");
                        return Decision::Exit;
                    }
                    Event::Snapshot => {
                        println!("esp-mint: SIGUSR1, taking a snapshot");
                        return Decision::Snapshot;
                    }
                    Event::Reload => match state.config.reload(base, &config::process_env) {
                        Ok(reloaded) => {
                            // The PSP client reads its timeout at every call.
                            psp_timeout.store(
                                state.config.current().psp_timeout_secs,
                                Ordering::Relaxed,
                            );
                            println!("esp-mint: SIGHUP, settings read again:");
                            for line in &reloaded.lines {
                                println!("{line}");
                            }
                            if !reloaded.needs_restart.is_empty() {
                                println!(
                                    "esp-mint: {} need a restart, which is a brief downtime, so they keep their running values until the mint is restarted",
                                    reloaded.needs_restart.join(", ")
                                );
                            }
                        }
                        Err(problems) => {
                            eprintln!("esp-mint: SIGHUP, the settings are not valid, so none changed:");
                            for problem in problems {
                                eprintln!("  {problem}");
                            }
                        }
                    },
                }
            }
        }
    }
}

/// What runs beside the HTTP servers: the AIR listener and the watch thread.
/// Dropping it stops and joins both, so that no thread outlives the mint's data.
struct Running {
    air_stop: Option<oneshot::Sender<()>>,
    air: Option<JoinHandle<()>>,
    watch_stop: Option<std::sync::mpsc::Sender<()>>,
    watch: Option<JoinHandle<()>>,
}

impl Running {
    /// Start the AIR listener on its own thread. It answers every wallet-facing
    /// request (`server::air_served`). If it fails (the AIR client gave up) it
    /// says so and the mint exits with status 1, so that the service manager
    /// starts it again and the listener resumes from the stored slot counter: a
    /// mint that no wallet can reach is not left running.
    ///
    /// A poisoned lock means a thread panicked holding the mint, and every later
    /// request would fail. The watch thread exits the process, so that a
    /// supervisor can start a fresh one.
    fn start(
        air: air_listener::Settings,
        did: did::SecretKey,
        state: &Arc<EspState>,
    ) -> Result<Running, Box<dyn Error>> {
        println!(
            "esp-mint AIR listener: this mint's DID is {} (wallets use it as air.esp_did)",
            did::public_key_hex(&did)
        );
        let (air_stop, stopped) = oneshot::channel::<()>();
        let serving = Arc::clone(state);
        let air_thread = thread::Builder::new()
            .name("air-listener".into())
            .spawn(move || {
                let serve: Arc<air_listener::Serve> =
                    Arc::new(move |kind: u8, body: &[u8]| server::air_served(&serving, kind, body));
                // A dropped sender stops it as well.
                let stop = async move {
                    let _ = stopped.await;
                };
                match air_listener::run_blocking(&air, &did, &serve, stop) {
                    Ok(()) => println!("AIR listener: stopped"),
                    Err(e) => {
                        eprintln!("AIR listener failed: {e}\nExiting so that a supervisor can restart the process");
                        std::process::exit(1);
                    }
                }
            })?;
        println!("AIR listener starting");

        let (watch_stop, watch_rx) = std::sync::mpsc::channel::<()>();
        let watched = Arc::clone(state);
        let watch_thread = thread::Builder::new().name("watch".into()).spawn(move || {
            loop {
                if let Some(why) = server::fatal(&watched) {
                    eprintln!("fatal: {why}. Exiting so that a supervisor can restart the process");
                    std::process::exit(1);
                }
                match watch_rx.recv_timeout(Duration::from_secs(1)) {
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    _ => return,
                }
            }
        })?;
        Ok(Running {
            air_stop: Some(air_stop),
            air: Some(air_thread),
            watch_stop: Some(watch_stop),
            watch: Some(watch_thread),
        })
    }

    /// Stop the AIR listener once the slots it has read are answered, and wait
    /// until its thread has ended.
    fn stop_air(&mut self) {
        if let Some(stop) = self.air_stop.take() {
            // Fails only if the listener already ended.
            let _ = stop.send(());
        }
        if let Some(thread) = self.air.take()
            && thread.join().is_err()
        {
            eprintln!("esp-mint: the AIR listener thread ended in a panic");
        }
    }

    fn stop_watch(&mut self) {
        if let Some(stop) = self.watch_stop.take() {
            // Fails only if the watch thread already ended.
            let _ = stop.send(());
        }
        if let Some(thread) = self.watch.take()
            && thread.join().is_err()
        {
            eprintln!("esp-mint: the watch thread ended in a panic");
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop_air();
        self.stop_watch();
    }
}

/// The wait for the PSP was ended by `SIGTERM` or `SIGINT`.
struct Stopped;

/// Ask the PSP which network it is on, and ask again every `retry_secs()` (read
/// afresh at each try) until it answers. Only an unreachable PSP is waited for (it may not have started yet);
/// what it answers is checked by the caller. The log gets the first failure and
/// then one line a minute. `SIGTERM` and `SIGINT` end the wait (they are events
/// now, so the default action no longer does): the waits between asks are short
/// slices that look at `stop`, and an ask in progress is ended by the client's own
/// timeout (`psp.timeout_secs`).
fn wait_for_psp(
    psp: &HttpPsp,
    url: &str,
    retry_secs: &dyn Fn() -> u64,
    stop: &AtomicBool,
) -> Result<Option<String>, Stopped> {
    const SLICE: Duration = Duration::from_millis(200);
    let mut failures = 0u64;
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err(Stopped);
        }
        match psp.network() {
            Ok(network) => {
                if failures > 0 {
                    println!("esp-mint: the PSP at {url} answers now");
                }
                return Ok(network);
            }
            Err(e) => {
                let retry_secs = retry_secs();
                let log_every = (60 / retry_secs.max(1)).max(1);
                if failures.is_multiple_of(log_every) {
                    eprintln!(
                        "esp-mint: cannot ask the PSP at {url} which network it is on: {e}. Trying again every {retry_secs} s (start psp-mint serve)"
                    );
                }
                failures += 1;
                let mut waited = Duration::ZERO;
                while waited < Duration::from_secs(retry_secs) {
                    if stop.load(Ordering::SeqCst) {
                        return Err(Stopped);
                    }
                    thread::sleep(SLICE);
                    waited += SLICE;
                }
            }
        }
    }
}

fn data_dir() -> Result<PathBuf, Box<dyn Error>> {
    // A service names the directory and may have no home directory at all.
    if let Ok(dir) = env::var("ESP_DATA_DIR")
        && !dir.is_empty()
    {
        return Ok(PathBuf::from(dir));
    }
    let home = env::var("HOME").map_err(|_| "HOME is not set: set ESP_DATA_DIR")?;
    Ok(PathBuf::from(format!("{home}/.esp-mint")))
}

/// Say which network this run is on and where its data is, on stderr, as
/// psp-mint does: `esp-mint on regtest: data in /home/me/.esp-mint/regtest`.
/// Every command that reads the settings says it first, `pubkey` too (a DID made
/// on the wrong network looks the same as a right one), and on stderr, so that
/// `ESP_DID=$(esp-mint pubkey)` captures only the DID. A command that cannot
/// read its settings says why instead, since it cannot know the network.
fn say_network() -> Result<(), Box<dyn Error>> {
    let base = data_dir()?;
    let network = load_config(&base)?.config.network;
    eprintln!(
        "esp-mint on {network}: data in {}",
        netdir::network_dir(&base, &network).display()
    );
    Ok(())
}

/// The data folder of the configured network.
fn net_dir() -> Result<PathBuf, Box<dyn Error>> {
    let base = data_dir()?;
    let network = load_config(&base)?.config.network;
    Ok(netdir::network_dir(&base, &network))
}

const USAGE: &str = "\
esp-mint <command>

  serve                 Run the AIR listener (needs air.server and air.host),
                        the loopback /audit and /health, and the operator's
                        listener.
  config                Print the settings in use and where each came from.
  pubkey                Print the mint's DID (66 hex characters), making its
                        key file on first use. Wallets use it as air.esp_did.
  payouts [--json]      The payout report: what is owed to each service.
  pay <service> <ref> <entry id>... [--mixed-memos]
                        Mark exactly those entries paid, with one payment
                        reference. --mixed-memos if one payment covers entries
                        with different memos. Asks the running serve, on its
                        operator listener.
  decline <entry id> --reason TEXT
                        Decline a payout and sign its stored decline outputs.
                        Asks the running serve, on its operator listener.
  --help                Print this text.
  --version             Print the version of esp-mint and of the libraries it was
                        built with.

Settings: esp-mint.toml in ESP_DATA_DIR (default ~/.esp-mint) or the file
ESP_CONFIG names, then ESP_... variables. The network is main unless
server.network (ESP_NETWORK) says otherwise.";

/// `esp-mint config`: every setting with the value in use and where it came from.
fn run_config() -> Result<String, Box<dyn Error>> {
    let loaded = load_config(&data_dir()?)?;
    let mut out = match &loaded.file {
        Some(file) => format!("settings from {}, and the environment:\n", file.display()),
        None => "no config file, so defaults and the environment:\n".to_string(),
    };
    for line in loaded.describe() {
        out.push_str(&line);
        out.push('\n');
    }
    let c = &loaded.config;
    for line in esp_mint::rotation::describe_offline(
        &netdir::network_dir(&data_dir()?, &c.network),
        c.rotation_activation_hours,
        c.rotation_period_hours,
    ) {
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// `esp-mint decline <entry id> --reason TEXT`: ask the running mint, on its
/// admin listener, to decline the entry's payout.
fn run_decline(args: &[String]) -> Result<String, Box<dyn Error>> {
    let mut entry_id: Option<&str> = None;
    let mut reason: Option<&str> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "--reason" {
            reason = Some(
                rest.next()
                    .ok_or("--reason needs the text of the reason")?
                    .as_str(),
            );
        } else if arg.starts_with("--") {
            return Err(format!("unknown option {arg}\n{USAGE}").into());
        } else if entry_id.is_none() {
            entry_id = Some(arg.as_str());
        } else {
            return Err(format!("only one entry id can be declined at a time\n{USAGE}").into());
        }
    }
    let (Some(entry_id), Some(reason)) = (entry_id, reason) else {
        return Err(USAGE.into());
    };
    ask_serve(
        "payouts/decline",
        &serde_json::json!({"entry_id": entry_id, "reason": reason}),
    )
}

/// `esp-mint pay <service> <ref> <entry id>... [--mixed-memos]`: ask the running
/// mint, on its admin listener, to mark the entries paid. The queue file is
/// written by `serve` alone, under the lock that keeps its writers apart, so
/// `pay` needs `serve` running, as `decline` does; it never opens the queue to
/// write it.
fn run_pay(args: &[String]) -> Result<String, Box<dyn Error>> {
    let pay = payouts::parse_pay(args)?;
    ask_serve(
        "payouts/pay",
        &serde_json::json!({
            "service": hex::encode(pay.service.serialize()),
            "payment_ref": pay.payment_ref,
            "entry_ids": pay.entry_ids,
            "mixed_memos": pay.mixed_memos,
        }),
    )
}

/// `POST` `body` to `route` on the running mint's admin listener and return its
/// plain-text answer, or its refusal as the error. The listener is the one
/// `server.admin_bind` names (it must be a loopback address) and the bearer
/// token is `ESP_ADMIN_TOKEN`, when set. If nothing answers there, the error
/// says so and nothing has been changed.
fn ask_serve(route: &str, body: &serde_json::Value) -> Result<String, Box<dyn Error>> {
    let bind = load_config(&data_dir()?)?.config.admin_bind;
    admin::check_loopback(&bind)?;
    let client = reqwest::blocking::Client::new();
    let mut request = client
        .post(format!("http://{bind}/{route}?format=text"))
        .json(body);
    if let Ok(token) = env::var("ESP_ADMIN_TOKEN") {
        request = request.bearer_auth(token);
    }
    let response = request.send().map_err(|e| {
        format!(
            "could not reach the mint's admin listener at {bind}: {e}. Is `esp-mint serve` running?"
        )
    })?;
    let ok = response.status().is_success();
    let body = response.text()?;
    if ok {
        Ok(body)
    } else {
        Err(body.trim_end().to_string().into())
    }
}

fn main() {
    // An error is printed as plain text, not as the debug form of the value
    // (`Error: "usage:\n ..."`), which is what returning it from `main` does.
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    // Answered before any setting is read, so it needs no data folder and writes
    // nothing: it is safe to run while `serve` is up.
    if args.iter().any(|a| a == "--version" || a == "-V") {
        for line in esp_mint::version::lines() {
            println!("{line}");
        }
        return Ok(());
    }
    // `serve` says it itself, after it has made its signal handlers.
    if let Some("config" | "pubkey" | "payouts" | "pay" | "decline") =
        args.first().map(String::as_str)
    {
        say_network()?;
    }
    match args.first().map(String::as_str) {
        Some("serve") => serve(),
        Some("config") => {
            print!("{}", run_config()?);
            Ok(())
        }
        // Makes the DID key file if there is none, and nothing else.
        Some("pubkey") => {
            let dir = net_dir()?;
            std::fs::create_dir_all(&dir)?;
            let key = did::load_or_generate(&dir.join(did::KEY_FILENAME))?;
            println!("{}", did::public_key_hex(&key));
            Ok(())
        }
        // Reads the queue file only. It never opens the mint's database, so it
        // can run while `serve` is up.
        Some("payouts") => {
            print!(
                "{}",
                payouts::run_payouts(&server::queue_path(&net_dir()?), &args[1..])?
            );
            Ok(())
        }
        // Both write the queue, so both ask the running `serve` (the one
        // writer, under its queue lock) on its admin listener.
        Some("pay") => {
            print!("{}", run_pay(&args[1..])?);
            Ok(())
        }
        // Signs, so it asks the running `serve` on its admin listener.
        Some("decline") => {
            print!("{}", run_decline(&args[1..])?);
            Ok(())
        }
        // Asking for help is not an error: the usage goes to stdout and the
        // exit status is 0. A command that is missing or unknown prints the same
        // text to stderr, as plain text, and exits with 2.
        Some("--help") | Some("-h") | Some("help") => {
            println!("{USAGE}");
            Ok(())
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}
