use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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
fn serve() -> Result<(), Box<dyn Error>> {
    let home = env::var("HOME")?;
    let data_dir = PathBuf::from(setting("ESP_DATA_DIR", format!("{home}/.esp-mint")));
    let bind = setting("ESP_BIND", "127.0.0.1:3100".to_string());
    let psp_url = setting("ESP_PSP_URL", "http://127.0.0.1:3000".to_string());

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
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&bind).await?;
        println!("esp-mint api listening on http://{bind}, burning PSP at {psp_url}");
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
                println!("shutting down");
            })
            .await?;
        Ok::<(), Box<dyn Error>>(())
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    match env::args().nth(1).as_deref() {
        Some("serve") => serve(),
        _ => Err("usage: esp-mint serve".into()),
    }
}
