use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use esp_mint::admin::{self, AdminState};
use esp_mint::payouts;
use esp_mint::psp_client::HttpPsp;
use esp_mint::responses::Responses;
use esp_mint::server::{self, EspState};
use esp_mint::mint;

fn setting(key: &str, default: String) -> String {
    env::var(key).unwrap_or(default)
}

/// Run the ESP mint's HTTP API.
///
/// Settings are environment variables:
///
/// - `ESP_DATA_DIR`, default `~/.esp-mint`: the master secret, the mint's
///   database and the stored responses.
/// - `ESP_BIND`, default `127.0.0.1:3100`.
/// - `ESP_PSP_URL`, default `http://127.0.0.1:3000`: `psp-mint serve`.
/// - `ESP_ADMIN_BIND`, default `127.0.0.1:3101`: the operator's routes (the
///   payout report and settle). It must be a loopback address.
/// - `ESP_ADMIN_TOKEN`, optional: if set, the operator's routes need
///   `Authorization: Bearer <token>`.
fn serve() -> Result<(), Box<dyn Error>> {
    let home = env::var("HOME")?;
    let data_dir = PathBuf::from(setting("ESP_DATA_DIR", format!("{home}/.esp-mint")));
    let bind = setting("ESP_BIND", "127.0.0.1:3100".to_string());
    let psp_url = setting("ESP_PSP_URL", "http://127.0.0.1:3000".to_string());
    let admin_bind = admin::check_loopback(&setting("ESP_ADMIN_BIND", "127.0.0.1:3101".to_string()))?;
    let admin_token = match env::var("ESP_ADMIN_TOKEN") {
        Ok(token) if token.is_empty() => return Err("ESP_ADMIN_TOKEN is set but empty".into()),
        Ok(token) => Some(token),
        Err(_) => None,
    };

    let (logic, master) = mint::open(&data_dir)?;
    let responses = Responses::open(&data_dir.join("responses.json"))?;
    // The blocking client is made here, before the async runtime exists.
    let psp = HttpPsp::new(&psp_url)?;
    let state = Arc::new(EspState {
        logic: Mutex::new(logic),
        master,
        psp: Box::new(psp),
        responses: Mutex::new(responses),
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
    }));
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&bind).await?;
        let admin_listener = tokio::net::TcpListener::bind(admin_bind).await?;
        println!("esp-mint api listening on http://{bind}, burning PSP at {psp_url}");
        println!("esp-mint admin listening on http://{admin_bind}");
        let api = async {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                    println!("shutting down");
                })
                .await
        };
        let admin = async {
            axum::serve(admin_listener, admin_app)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
        };
        tokio::try_join!(api, admin)?;
        Ok::<(), Box<dyn Error>>(())
    })
}

fn data_dir() -> Result<PathBuf, Box<dyn Error>> {
    let home = env::var("HOME")?;
    Ok(PathBuf::from(setting("ESP_DATA_DIR", format!("{home}/.esp-mint"))))
}

fn queue_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("queue.json")
}

const USAGE: &str = "usage:
  esp-mint serve
  esp-mint payouts [--json]
  esp-mint pay <service> <ref> <entry id>... [--mixed-memos]";

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => serve(),
        // These read and write the queue file only. They never open the mint's
        // database, so they can run while `serve` is up.
        Some("payouts") => {
            print!("{}", payouts::run_payouts(&queue_path(&data_dir()?), &args[1..])?);
            Ok(())
        }
        Some("pay") => {
            let now = server::now_secs();
            print!("{}", payouts::run_pay(&queue_path(&data_dir()?), &args[1..], now)?);
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}
