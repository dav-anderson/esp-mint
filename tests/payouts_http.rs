//! The operator's HTTP routes, over a real listener on a loopback port.
//!
//! The client is blocking, so these are plain tests with their own runtime, as
//! in `exchange.rs`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use esp_mint::admin::{self, AdminState};
use esp_mint::config::Config;
use esp_mint::exchange::{Burn, Psp};
use esp_mint::queue::{Entry, Queue};
use esp_mint::server::{self, EspState};
use mint_types::{Amount, MintInput, Nonce};
use serde_json::{Value, json};
use sp_wire::ServiceDid;
use tokio::runtime::Runtime;

const G_DID: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ONE_USD: u128 = 1_000_000_000_000;
const DAY1: u64 = 20_735 * 86_400;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("esp-mint-admin-{}-{name}", {
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

/// The routes under test never reach the PSP.
struct NoPsp;

impl Psp for NoPsp {
    fn melt(&self, _inputs: &[MintInput], _memo: &str) -> Result<Amount, String> {
        Err("an operator route does not use the PSP".into())
    }

    fn burns(&self, _nonces: &[Nonce]) -> Result<Vec<Burn>, String> {
        Err("an operator route does not use the PSP".into())
    }
}

fn service() -> ServiceDid {
    ServiceDid::parse(G_DID).unwrap()
}

/// The mint `serve` builds on `dir` and its admin router, whose queue is
/// `dir/queue.json`.
fn start(rt: &Runtime, dir: &Path, token: Option<&str>) -> String {
    let esp = Arc::new(EspState::open(dir, Box::new(NoPsp), Config::default(), 0).unwrap());
    let state = Arc::new(AdminState {
        queue_path: server::queue_path(dir),
        lock: Mutex::new(()),
        token: token.map(str::to_string),
        esp,
    });
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let app = admin::router(state);
    rt.spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn seed(path: &Path) {
    let mut q = Queue::open(path).unwrap();
    q.add(Entry::open("e1", service(), 10 * ONE_USD, "btc:x", DAY1))
        .unwrap();
    q.add(Entry::open(
        "e2",
        service(),
        5 * ONE_USD,
        "btc:x",
        DAY1 + 86_400,
    ))
    .unwrap();
}

#[test]
fn the_report_comes_as_json_and_as_plain_text() {
    let dir = scratch("report");
    let path = dir.join("queue.json");
    seed(&path);
    let rt = Runtime::new().unwrap();
    let base = start(&rt, &dir, None);
    let client = reqwest::blocking::Client::new();

    let json: Value = client
        .get(format!("{base}/payouts"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(json[0]["service"], G_DID);
    assert_eq!(json[0]["owed_esp"], "15000000000000");
    assert_eq!(json[0]["owed_usd"], "15.000000000000");
    assert_eq!(json[0]["entries"], 2);
    assert_eq!(json[0]["entry_ids"], json!(["e1", "e2"]));
    assert_eq!(json[0]["memo_mismatch"], false);

    let response = client
        .get(format!("{base}/payouts?format=text"))
        .send()
        .unwrap();
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let text = response.text().unwrap();
    assert!(text.contains(&format!("service {G_DID}")));
    assert!(text.contains("owed     15.000000000000 USD"));

    let bad = client
        .get(format!("{base}/payouts?format=xml"))
        .send()
        .unwrap();
    assert_eq!(bad.status(), 400);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn paying_marks_only_the_listed_entries_and_a_refusal_changes_nothing() {
    let dir = scratch("pay");
    let path = dir.join("queue.json");
    seed(&path);
    let rt = Runtime::new().unwrap();
    let base = start(&rt, &dir, None);
    let client = reqwest::blocking::Client::new();
    let pay = |body: Value| {
        client
            .post(format!("{base}/payouts/pay"))
            .json(&body)
            .send()
            .unwrap()
    };

    // an entry that lands after the report is not in the list, so it stays open
    Queue::open(&path)
        .unwrap()
        .add(Entry::open(
            "e3",
            service(),
            3 * ONE_USD,
            "btc:x",
            DAY1 + 2 * 86_400,
        ))
        .unwrap();

    let refused = pay(json!({"service": G_DID, "payment_ref": "w1", "entry_ids": ["e1", "nope"]}));
    assert_eq!(refused.status(), 400);
    assert!(
        refused.json::<Value>().unwrap()["error"]
            .as_str()
            .unwrap()
            .contains("nope")
    );
    let q = Queue::open(&path).unwrap();
    assert!(q.entries().all(|e| e.payment_ref.is_none()));

    let ok = pay(json!({"service": G_DID, "payment_ref": "wire-1", "entry_ids": ["e1", "e2"]}));
    assert_eq!(ok.status(), 200);
    let paid: Value = ok.json().unwrap();
    assert_eq!(paid["entries"], 2);
    assert_eq!(paid["paid_esp"], "15000000000000");
    assert_eq!(paid["payment_ref"], "wire-1");

    let q = Queue::open(&path).unwrap();
    assert_eq!(q.get("e3").unwrap().payment_ref, None);
    let again = pay(json!({"service": G_DID, "payment_ref": "wire-2", "entry_ids": ["e1"]}));
    assert_eq!(again.status(), 400);

    let text = client
        .post(format!("{base}/payouts/pay?format=text"))
        .json(&json!({"service": G_DID, "payment_ref": "wire-3", "entry_ids": ["e3"]}))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(text.contains("marked 1 entry completed") && text.contains("3.000000000000 USD"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_token_is_required_when_one_is_set() {
    let dir = scratch("token");
    let path = dir.join("queue.json");
    seed(&path);
    let rt = Runtime::new().unwrap();
    let base = start(&rt, &dir, Some("s3cret"));
    let client = reqwest::blocking::Client::new();

    assert_eq!(
        client
            .get(format!("{base}/payouts"))
            .send()
            .unwrap()
            .status(),
        401
    );
    let wrong = client
        .get(format!("{base}/payouts"))
        .header("Authorization", "Bearer nope")
        .send()
        .unwrap();
    assert_eq!(wrong.status(), 401);
    let unauth_pay = client
        .post(format!("{base}/payouts/pay"))
        .json(&json!({"service": G_DID, "payment_ref": "w", "entry_ids": ["e1"]}))
        .send()
        .unwrap();
    assert_eq!(unauth_pay.status(), 401);
    assert_eq!(
        Queue::open(&path).unwrap().get("e1").unwrap().payment_ref,
        None
    );
    let ok = client
        .get(format!("{base}/payouts"))
        .header("Authorization", "Bearer s3cret")
        .send()
        .unwrap();
    assert_eq!(ok.status(), 200);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_bad_token_is_refused_before_the_format_is_looked_at() {
    let dir = scratch("token-format");
    seed(&dir.join("queue.json"));
    let rt = Runtime::new().unwrap();
    let base = start(&rt, &dir, Some("s3cret"));
    let client = reqwest::blocking::Client::new();

    // No token and a format the route does not know: the caller is told it is not
    // allowed, not that its format is wrong.
    let response = client
        .get(format!("{base}/payouts?format=xml"))
        .send()
        .unwrap();
    assert_eq!(response.status(), 401);
    let body: Value = response.json().unwrap();
    assert_eq!(body["error"], "missing or wrong admin token");

    let wrong = client
        .get(format!("{base}/payouts?format=xml"))
        .header("Authorization", "Bearer nope")
        .send()
        .unwrap();
    assert_eq!(wrong.status(), 401);

    // A bad token with the text format gets its refusal as plain text.
    let text = client
        .get(format!("{base}/payouts?format=text"))
        .header("Authorization", "Bearer nope")
        .send()
        .unwrap();
    assert_eq!(text.status(), 401);
    assert_eq!(
        text.text().unwrap(),
        "error: missing or wrong admin token\n"
    );

    // With the right token the format is checked, as before.
    let bad_format = client
        .get(format!("{base}/payouts?format=xml"))
        .header("Authorization", "Bearer s3cret")
        .send()
        .unwrap();
    assert_eq!(bad_format.status(), 400);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_bad_token_is_refused_before_the_body_is_parsed() {
    let dir = scratch("token-body");
    seed(&dir.join("queue.json"));
    let rt = Runtime::new().unwrap();
    let base = start(&rt, &dir, Some("s3cret"));
    let client = reqwest::blocking::Client::new();
    let post = |path: &str, token: Option<&str>, body: &str| {
        let mut request = client
            .post(format!("{base}{path}"))
            .header("content-type", "application/json")
            .body(body.to_string());
        if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        request.send().unwrap()
    };

    for path in ["/payouts/pay", "/payouts/decline"] {
        // Not JSON at all, and JSON of the wrong shape, with no token and a
        // wrong one: the caller is told it is not allowed, nothing more.
        for body in ["this is not json", "{}"] {
            for token in [None, Some("nope")] {
                let response = post(path, token, body);
                assert_eq!(response.status(), 401, "{path} {token:?} {body}");
                let json: Value = response.json().unwrap();
                assert_eq!(json["error"], "missing or wrong admin token");
            }
        }
        // And a format the route does not know is not looked at either.
        let response = client
            .post(format!("{base}{path}?format=xml"))
            .header("content-type", "application/json")
            .body("this is not json")
            .send()
            .unwrap();
        assert_eq!(response.status(), 401, "{path} with a bad format");

        // With the right token the body is read, as before.
        let response = post(path, Some("s3cret"), "this is not json");
        assert_eq!(response.status(), 400, "{path} with bad JSON");
        let json: Value = response.json().unwrap();
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .starts_with("the request body is not valid"),
            "{json}"
        );
        let response = post(path, Some("s3cret"), "{}");
        assert_eq!(
            response.status(),
            422,
            "{path} with JSON of the wrong shape"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_admin_bind_must_be_loopback() {
    assert!(admin::check_loopback("127.0.0.1:3101").is_ok());
    assert!(admin::check_loopback("[::1]:3101").is_ok());
    assert!(admin::check_loopback("0.0.0.0:3101").is_err());
    assert!(admin::check_loopback("192.168.1.5:3101").is_err());
    assert!(admin::check_loopback("localhost").is_err());
}

/// Send only the headers of a request that says it is `length` bytes, and
/// return the status and the body of the reply.
fn declared(base: &str, path: &str, length: usize) -> (u16, Value) {
    use std::io::{Read, Write};
    let addr = base.trim_start_matches("http://");
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply);
    let status = reply[9..12].parse().unwrap();
    let body = reply.split("\r\n\r\n").nth(1).unwrap_or("");
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

#[test]
fn an_operator_body_over_the_ceiling_gets_the_same_413_as_the_public_routes() {
    let dir = scratch("ceiling");
    let path = dir.join("queue.json");
    seed(&path);
    let rt = Runtime::new().unwrap();
    let before = std::fs::read(&path).unwrap();
    let base = start(&rt, &dir, None);
    const MIB: usize = 1024 * 1024;
    for route in ["/payouts/pay", "/payouts/decline"] {
        let (status, body) = declared(&base, route, MIB + 1);
        assert_eq!(status, 413, "{route}");
        assert_eq!(body["code"], "request_too_large", "{route}");
        assert_eq!(body["size_bytes"], (MIB + 1) as u64, "{route}");
        assert_eq!(body["limit_bytes"], MIB as u64, "{route}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("at most 1048576 bytes")
        );
    }
    // A chunked body with no length is read only up to the ceiling.
    let chunked = rt.block_on(async {
        use std::io::{Read, Write};
        let addr = base.trim_start_matches("http://").to_string();
        tokio::task::spawn_blocking(move || {
            let mut stream = std::net::TcpStream::connect(&addr).unwrap();
            write!(
                stream,
                "POST /payouts/pay HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let chunk = vec![b' '; 64 * 1024];
            for _ in 0..17 {
                if write!(stream, "{:x}\r\n", chunk.len()).is_err()
                    || stream.write_all(&chunk).is_err()
                    || stream.write_all(b"\r\n").is_err()
                {
                    break;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n");
            let mut reply = String::new();
            let _ = stream.read_to_string(&mut reply);
            reply
        })
        .await
        .unwrap()
    });
    assert!(chunked.starts_with("HTTP/1.1 413"), "{chunked}");
    assert!(chunked.contains("\"size_bytes\":null"), "{chunked}");
    // Under the ceiling the route still answers as before, and nothing was paid.
    let response = reqwest::blocking::Client::new()
        .post(format!("{base}/payouts/pay"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .unwrap();
    assert_ne!(response.status().as_u16(), 413);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// What one run of the `esp-mint` binary printed and how it ended.
struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run `esp-mint args` as the operator does: an empty environment but the data
/// folder `data`, the operator's listener at `base` (as `ESP_ADMIN_BIND`) and
/// the admin token, when there is one.
fn esp_mint(data: &Path, base: &str, token: Option<&str>, args: &[&str]) -> Ran {
    let mut command = Command::new(env!("CARGO_BIN_EXE_esp-mint"));
    command
        .args(args)
        .env_clear()
        .env("ESP_DATA_DIR", data)
        .env("ESP_ADMIN_BIND", base.trim_start_matches("http://"));
    if let Some(token) = token {
        command.env("ESP_ADMIN_TOKEN", token);
    }
    let out = command
        .stdin(Stdio::null())
        .output()
        .expect("the esp-mint binary runs");
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

/// A data folder whose `main` folder (the default network's) holds the queue
/// `serve` works on, with two open entries; and the operator's listener over it.
fn data_with_serve(rt: &Runtime, name: &str, token: Option<&str>) -> (PathBuf, String) {
    let data = scratch(name);
    let net = data.join("main");
    std::fs::create_dir_all(&net).unwrap();
    seed(&server::queue_path(&net));
    let base = start(rt, &net, token);
    (data, base)
}

#[test]
fn the_pay_command_settles_through_the_running_serve_and_sends_its_token() {
    let rt = Runtime::new().unwrap();
    let (data, base) = data_with_serve(&rt, "cli-pay", Some("s3cret"));
    let queue = server::queue_path(&data.join("main"));
    let payment_refs = || -> Vec<Option<String>> {
        let q = Queue::open(&queue).unwrap();
        ["e1", "e2"]
            .map(|id| q.get(id).unwrap().payment_ref.clone())
            .to_vec()
    };

    // Without the token serve refuses, and the entries stay open.
    let ran = esp_mint(&data, &base, None, &["pay", G_DID, "wire-1", "e1", "e2"]);
    assert_eq!((ran.code, ran.stdout.as_str()), (Some(1), ""));
    assert!(
        ran.stderr
            .ends_with("error: missing or wrong admin token\n"),
        "{}",
        ran.stderr
    );
    assert_eq!(payment_refs(), [None, None]);

    // An entry serve does not know is serve's refusal, word for word.
    let ran = esp_mint(&data, &base, Some("s3cret"), &["pay", G_DID, "w0", "nope"]);
    assert_eq!((ran.code, ran.stdout.as_str()), (Some(1), ""));
    assert!(
        ran.stderr.ends_with("error: no entry nope\n"),
        "{}",
        ran.stderr
    );
    assert_eq!(payment_refs(), [None, None]);

    // With it, serve settles both entries under the reference.
    let ran = esp_mint(
        &data,
        &base,
        Some("s3cret"),
        &["pay", G_DID, "wire-1", "e1", "e2"],
    );
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    assert_eq!(
        ran.stdout,
        format!(
            "marked 2 entries completed for {G_DID}: 15.000000000000 USD (15000000000000 ESP), payment reference wire-1\n"
        )
    );
    assert_eq!(
        payment_refs(),
        [Some("wire-1".to_string()), Some("wire-1".to_string())]
    );
    std::fs::remove_dir_all(&data).unwrap();
}

#[test]
fn two_pays_of_the_same_entries_at_once_settle_them_once() {
    let rt = Runtime::new().unwrap();
    let (data, base) = data_with_serve(&rt, "cli-pay-twice", None);
    let racers = ["wire-a", "wire-b"].map(|payment_ref| {
        let (data, base) = (data.clone(), base.clone());
        thread::spawn(move || {
            esp_mint(&data, &base, None, &["pay", G_DID, payment_ref, "e1", "e2"])
        })
    });
    let ran: Vec<Ran> = racers.into_iter().map(|t| t.join().unwrap()).collect();

    // Exactly one of them settled; the other was told the entry is not open.
    let winners: Vec<usize> = (0..2).filter(|&i| ran[i].code == Some(0)).collect();
    assert_eq!(
        winners.len(),
        1,
        "{:?}",
        ran.iter().map(|r| &r.stderr).collect::<Vec<_>>()
    );
    let (won, lost) = (winners[0], 1 - winners[0]);
    assert_eq!(ran[lost].code, Some(1));
    assert_eq!(ran[lost].stdout, "");
    assert!(
        ran[lost]
            .stderr
            .ends_with("error: entry e1 is not open (it is Completed)\n"),
        "{}",
        ran[lost].stderr
    );
    let winning_ref = ["wire-a", "wire-b"][won];
    assert!(
        ran[won]
            .stdout
            .ends_with(&format!("payment reference {winning_ref}\n"))
    );
    let q = Queue::open(&server::queue_path(&data.join("main"))).unwrap();
    for id in ["e1", "e2"] {
        assert_eq!(q.get(id).unwrap().payment_ref.as_deref(), Some(winning_ref));
    }
    std::fs::remove_dir_all(&data).unwrap();
}
