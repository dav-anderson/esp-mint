use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use esp_mint::admin::{self, AdminState};
use esp_mint::config;
use esp_mint::netdir;
use esp_mint::payouts;
use esp_mint::psp_client::HttpPsp;
use esp_mint::responses::Responses;
use esp_mint::server::{self, EspState};

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

/// Run the ESP mint's HTTP API.
///
/// The settings are in `esp-mint.toml` in the data directory (or the file
/// `ESP_CONFIG` names), each with an environment variable that overrides it.
/// `esp-mint config` lists them all with the values in use. They are logged at
/// startup, and a bad value stops the mint with a message that says which. Send
/// the running mint `SIGHUP` to read them again: everything except the
/// addresses, the PSP client and the admin body ceiling changes for the next
/// request, and those say so and wait for a restart.
///
/// Two things are not settings. `ESP_DATA_DIR` (default `~/.esp-mint`) says where
/// the master secret, the mint's database, the stored responses and the config
/// file are, and `ESP_ADMIN_TOKEN` (optional, a secret, so never in a file) makes
/// the operator's routes need `Authorization: Bearer <token>`.
fn serve() -> Result<(), Box<dyn Error>> {
    let base = data_dir()?;
    let loaded = load_config(&base)?;
    match &loaded.file {
        Some(file) => println!(
            "esp-mint settings from {}, and the environment:",
            file.display()
        ),
        None => println!("esp-mint settings: no config file, so defaults and the environment:"),
    }
    for line in loaded.describe() {
        println!("{line}");
    }
    let cfg = loaded.config;
    netdir::refuse_legacy(&base)?;
    let data_dir = netdir::network_dir(&base, &cfg.network);
    std::fs::create_dir_all(&data_dir)?;
    println!(
        "esp-mint on {}: data in {}",
        cfg.network,
        data_dir.display()
    );
    let bind = cfg.bind.clone();
    let psp_url = cfg.psp_url.clone();
    let admin_bind = admin::check_loopback(&cfg.admin_bind)?;
    let admin_token = match env::var("ESP_ADMIN_TOKEN") {
        Ok(token) if token.is_empty() => return Err("ESP_ADMIN_TOKEN is set but empty".into()),
        Ok(token) => Some(token),
        Err(_) => None,
    };

    let (rotor, logic) = esp_mint::rotation::Rotor::open(
        &data_dir,
        cfg.rotation_activation_hours,
        cfg.rotation_period_hours,
    )?;
    for line in rotor.describe() {
        println!("{line}");
    }
    let master = rotor.current.master.clone();
    let rollovers = esp_mint::rotation::Rollovers::open(&data_dir)?;
    let responses = Responses::open(&data_dir.join("responses.json"))?;
    // The blocking client is made here, before the async runtime exists.
    let psp = HttpPsp::with_timeout(&cfg.psp_url, cfg.psp_timeout_secs)?;
    // The PSP must be on our network, or PSP notes from one chain would buy ESP
    // on another. An unreachable PSP is refused too: the network cannot be
    // checked.
    // It is not given up on: the mint may be started before the PSP, or after a
    // power cut that took both down, and nobody should have to start it again.
    let reported = wait_for_psp(&psp, &psp_url, cfg.psp_startup_retry_secs);
    config::check_psp_network(&cfg.network, reported.as_deref())?;
    println!(
        "esp-mint on {}: the PSP at {psp_url} is on the same network",
        cfg.network
    );
    let state = Arc::new(EspState {
        logic: Mutex::new(logic),
        master,
        psp: Box::new(psp),
        responses: Mutex::new(responses),
        queue_path: queue_path(&data_dir),
        queue_lock: Mutex::new(()),
        config: config::Handle::new(cfg),
        rotor: Some(Mutex::new(rotor)),
        rollovers: Some(Mutex::new(rollovers)),
        in_flight: Default::default(),
    });

    // A poisoned lock means a thread panicked holding the mint, and every later
    // request would fail. Exit so that a supervisor can start a fresh process.
    let watch = Arc::clone(&state);
    thread::spawn(move || {
        loop {
            if let Some(why) = server::fatal(&watch) {
                eprintln!("fatal: {why}. Exiting so that a supervisor can restart the process");
                std::process::exit(1);
            }
            thread::sleep(Duration::from_secs(1));
        }
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let app = server::router(Arc::clone(&state));
    let admin_app = admin::router(Arc::new(AdminState {
        queue_path: queue_path(&data_dir),
        lock: Mutex::new(()),
        token: admin_token,
        esp: Some(Arc::clone(&state)),
    }));
    let reload_state = Arc::clone(&state);
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&bind).await?;
        let admin_listener = tokio::net::TcpListener::bind(admin_bind).await?;
        println!("esp-mint api listening on http://{bind}, burning PSP at {psp_url}");
        println!("esp-mint admin listening on http://{admin_bind}");

        // SIGHUP: read the settings again. A bad file changes nothing.
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let Ok(mut hangup) = signal(SignalKind::hangup()) else {
                eprintln!("could not listen for SIGHUP, so settings change only on restart");
                return;
            };
            while hangup.recv().await.is_some() {
                match reload_state.config.reload(&base, &config::process_env) {
                    Ok(lines) => {
                        println!("esp-mint: SIGHUP, settings read again:");
                        for line in lines {
                            println!("{line}");
                        }
                    }
                    Err(problems) => {
                        eprintln!("esp-mint: SIGHUP, the settings are not valid, so none changed:");
                        for problem in problems {
                            eprintln!("  {problem}");
                        }
                    }
                }
            }
        });

        let api = async {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    shutdown_signal().await;
                    println!("shutting down");
                })
                .await
        };
        let admin = async {
            axum::serve(admin_listener, admin_app)
                .with_graceful_shutdown(async {
                    shutdown_signal().await;
                })
                .await
        };
        tokio::try_join!(api, admin)?;
        Ok::<(), Box<dyn Error>>(())
    })
}

/// Ask the PSP which network it is on, and ask again every `retry_secs` until it
/// answers. Only an unreachable PSP is waited for (it may not have started yet);
/// what it answers is checked by the caller. The log gets the first failure and
/// then one line a minute.
fn wait_for_psp(psp: &HttpPsp, url: &str, retry_secs: u64) -> Option<String> {
    let log_every = (60 / retry_secs.max(1)).max(1);
    let mut failures = 0u64;
    loop {
        match psp.network() {
            Ok(network) => {
                if failures > 0 {
                    println!("esp-mint: the PSP at {url} answers now");
                }
                return network;
            }
            Err(e) => {
                if failures % log_every == 0 {
                    eprintln!(
                        "esp-mint: cannot ask the PSP at {url} which network it is on: {e}. Trying again every {retry_secs} s (start psp-mint serve)"
                    );
                }
                failures += 1;
                thread::sleep(Duration::from_secs(retry_secs));
            }
        }
    }
}

/// Resolves on SIGINT (Ctrl-C) or SIGTERM, which is what `launchd` and
/// `systemd` send to stop a service. The server then stops taking new
/// connections, lets the requests it is answering finish, and returns, and the
/// process exits with status 0.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).ok();
    let terminate = async {
        match term.as_mut() {
            Some(t) => {
                t.recv().await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate => {}
    }
}

fn data_dir() -> Result<PathBuf, Box<dyn Error>> {
    // A service names the directory and may have no home directory at all.
    if let Ok(dir) = env::var("ESP_DATA_DIR") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    let home = env::var("HOME").map_err(|_| "HOME is not set: set ESP_DATA_DIR")?;
    Ok(PathBuf::from(format!("{home}/.esp-mint")))
}

/// The data folder of the configured network, after refusing old files.
fn net_dir() -> Result<PathBuf, Box<dyn Error>> {
    let base = data_dir()?;
    let network = load_config(&base)?.config.network;
    netdir::refuse_legacy(&base)?;
    Ok(netdir::network_dir(&base, &network))
}

fn queue_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("queue.json")
}

const USAGE: &str = "\
esp-mint <command>

  serve                 Run the public API and the operator's listener.
  config                Print the settings in use and where each came from.
  payouts [--json]      The payout report: what is owed to each service.
  pay <service> <ref> <entry id>... [--mixed-memos]
                        Mark exactly those entries paid, with one payment
                        reference. --mixed-memos if one payment covers entries
                        with different memos.
  decline <entry id> --reason TEXT
                        Decline a payout and sign its stored decline outputs.
                        Asks the running serve, on its operator listener.
  migrate               Once: move files from before the per-network split into
                        <ESP_DATA_DIR>/regtest.
  --help                Print this text.

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
    let bind = load_config(&data_dir()?)?.config.admin_bind;
    admin::check_loopback(&bind)?;
    let client = reqwest::blocking::Client::new();
    let mut request = client
        .post(format!("http://{bind}/payouts/decline?format=text"))
        .json(&serde_json::json!({"entry_id": entry_id, "reason": reason}));
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
    match args.first().map(String::as_str) {
        Some("serve") => serve(),
        Some("config") => {
            print!("{}", run_config()?);
            Ok(())
        }
        // These read and write the queue file only. They never open the mint's
        // database, so they can run while `serve` is up.
        Some("migrate") => {
            let moved = netdir::migrate_to_regtest(&data_dir()?)?;
            println!("moved into regtest/: {}", moved.join(", "));
            Ok(())
        }
        Some("payouts") => {
            print!(
                "{}",
                payouts::run_payouts(&queue_path(&net_dir()?), &args[1..])?
            );
            Ok(())
        }
        Some("pay") => {
            let now = server::now_secs();
            print!(
                "{}",
                payouts::run_pay(&queue_path(&net_dir()?), &args[1..], now)?
            );
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
