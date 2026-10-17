//! The operator's HTTP routes, over a real listener on a loopback port.
//!
//! The client is blocking, so these are plain tests with their own runtime, as
//! in `http.rs`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use esp_mint::admin::{self, AdminState};
use esp_mint::queue::{Entry, Queue};
use secp256k1::XOnlyPublicKey;
use serde_json::{Value, json};
use tokio::runtime::Runtime;

const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
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

fn service() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&hex::decode(G_X).unwrap()).unwrap()
}

fn start(rt: &Runtime, queue_path: &Path, token: Option<&str>) -> String {
    let state = Arc::new(AdminState {
        queue_path: queue_path.to_path_buf(),
        lock: Mutex::new(()),
        token: token.map(str::to_string),
        esp: None,
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
    let base = start(&rt, &path, None);
    let client = reqwest::blocking::Client::new();

    let json: Value = client
        .get(format!("{base}/payouts"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(json[0]["service"], G_X);
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
    assert!(text.contains(&format!("service {G_X}")));
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
    let base = start(&rt, &path, None);
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

    let refused = pay(json!({"service": G_X, "payment_ref": "w1", "entry_ids": ["e1", "nope"]}));
    assert_eq!(refused.status(), 400);
    assert!(
        refused.json::<Value>().unwrap()["error"]
            .as_str()
            .unwrap()
            .contains("nope")
    );
    let q = Queue::open(&path).unwrap();
    assert!(q.entries().all(|e| e.payment_ref.is_none()));

    let ok = pay(json!({"service": G_X, "payment_ref": "wire-1", "entry_ids": ["e1", "e2"]}));
    assert_eq!(ok.status(), 200);
    let paid: Value = ok.json().unwrap();
    assert_eq!(paid["entries"], 2);
    assert_eq!(paid["paid_esp"], "15000000000000");
    assert_eq!(paid["payment_ref"], "wire-1");

    let q = Queue::open(&path).unwrap();
    assert_eq!(q.get("e3").unwrap().payment_ref, None);
    let again = pay(json!({"service": G_X, "payment_ref": "wire-2", "entry_ids": ["e1"]}));
    assert_eq!(again.status(), 400);

    let text = client
        .post(format!("{base}/payouts/pay?format=text"))
        .json(&json!({"service": G_X, "payment_ref": "wire-3", "entry_ids": ["e3"]}))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(text.contains("marked 1 entry completed") && text.contains("3.000000000000 USD"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_failed_write_is_a_500_and_leaves_the_entry_open() {
    let dir = scratch("fault");
    let path = dir.join("sub").join("queue.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    seed(&path);
    let rt = Runtime::new().unwrap();
    let base = start(&rt, &path, None);
    let client = reqwest::blocking::Client::new();

    // Make the temporary file's path a directory, so the write cannot start.
    std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
    let response = client
        .post(format!("{base}/payouts/pay"))
        .json(&json!({"service": G_X, "payment_ref": "w", "entry_ids": ["e1"]}))
        .send()
        .unwrap();
    assert_eq!(response.status(), 500);
    let q = Queue::open(&path).unwrap();
    assert_eq!(q.get("e1").unwrap().payment_ref, None);
    let json: Value = client
        .get(format!("{base}/payouts"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(json[0]["entry_ids"], json!(["e1", "e2"]));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_token_is_required_when_one_is_set() {
    let dir = scratch("token");
    let path = dir.join("queue.json");
    seed(&path);
    let rt = Runtime::new().unwrap();
    let base = start(&rt, &path, Some("s3cret"));
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
        .json(&json!({"service": G_X, "payment_ref": "w", "entry_ids": ["e1"]}))
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
    let base = start(&rt, &path, None);
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
