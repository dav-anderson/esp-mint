//! The ceilings and the fee settings over HTTP: an over-ceiling body on each
//! route is refused with 413 before it is parsed, and a reload changes what the
//! next request sees.
//!
//! Plain tests with their own runtime, because they use the blocking HTTP client.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Router;
use esp_mint::config::{self, Config, Handle};
use esp_mint::exchange::{Burn, Psp};
use esp_mint::responses::Responses;
use esp_mint::server::{self, EspState};
use mint_types::{Amount, MintInput, Nonce};
use tokio::runtime::Runtime;

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

fn serve(rt: &Runtime, app: Router) -> String {
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    rt.spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn start(rt: &Runtime, dir: &Path) -> (String, Arc<EspState>) {
    let (logic, master) = esp_mint::mint::open(&dir.join("esp")).unwrap();
    let responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
    let cfg = Config {
        exchange_max_request_bytes: CEILING,
        transfer_max_request_bytes: CEILING,
        rollover_max_request_bytes: CEILING,
        redeem_max_request_bytes: CEILING,
        ..Config::default()
    };
    let state = Arc::new(EspState {
        logic: Mutex::new(logic),
        master,
        psp: Box::new(NoPsp),
        responses: Mutex::new(responses),
        queue_path: dir.join("esp").join("queue.json"),
        queue_lock: Mutex::new(()),
        config: Handle::new(cfg),
        rotor: None,
        rollovers: None,
        in_flight: Default::default(),
    });
    (serve(rt, server::router(Arc::clone(&state))), state)
}

fn post(url: &str, body: Vec<u8>) -> (u16, serde_json::Value) {
    let response = reqwest::blocking::Client::new()
        .post(url)
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .unwrap();
    let status = response.status().as_u16();
    let text = response.text().unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
    )
}

#[test]
fn a_body_over_the_ceiling_is_refused_before_it_is_parsed_on_every_route() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("ceilings");
    let (base, state) = start(&rt, &dir);
    for route in ["exchange", "transfer", "rollover", "redeem"] {
        let url = format!("{base}/{route}");
        // not a request at all, and too big: 413, not 400, so it was never parsed
        let (status, body) = post(&url, vec![b'x'; CEILING + 1]);
        assert_eq!(status, 413, "{route}");
        assert_eq!(body["code"], "request_too_large", "{route}");
        assert_eq!(body["limit_bytes"], CEILING as u64, "{route}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("Nothing was parsed, burned or charged")
        );
        // the same junk within the ceiling is read and found not to be a request
        let (status, body) = post(&url, vec![b'x'; CEILING]);
        assert_eq!(status, 400, "{route}");
        assert_eq!(body["code"], "malformed_request", "{route}");
    }
    // nothing was written
    assert!(state.responses.lock().unwrap().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_reload_changes_the_ceiling_and_the_rates_for_the_next_request_only() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("reload");
    let (base, state) = start(&rt, &dir);
    let fees: serde_json::Value = reqwest::blocking::get(format!("{base}/fees"))
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(fees["exchange"]["fee_per_byte"], "0");
    assert_eq!(fees["transfer"]["fee_per_byte"], "0");
    assert_eq!(fees["exchange"]["size"]["per_input"], 146);
    assert_eq!(fees["redeem"]["size"]["per_input"], 186);
    assert_eq!(fees["exchange"]["max_request_bytes"], CEILING as u64);
    assert_eq!(fees["rollover"]["max_request_bytes"], CEILING as u64);
    assert_eq!(fees["rollover"]["max_items"], 1000);

    // a request of 5000 bytes is over the ceiling now ...
    let url = format!("{base}/exchange");
    assert_eq!(post(&url, vec![b'x'; 5000]).0, 413);

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
    assert_eq!(post(&url, vec![b'x'; 5000]).0, 400);
    let fees: serde_json::Value = reqwest::blocking::get(format!("{base}/fees"))
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(fees["exchange"]["fee_per_byte"], "7");
    assert_eq!(fees["transfer"]["fee_per_byte"], "9");
    // the settings a request took before the reload are untouched
    assert_eq!(before.exchange_fee_per_byte, 0);
    std::fs::remove_dir_all(&dir).unwrap();
}
