//! The PSP client and a connection the PSP's local API loses.
//!
//! When psp-mint stops its local API (a snapshot, a stop), a connection that the
//! API had accepted but whose request it had not yet read is closed, and the
//! request is lost. No server can avoid that, so the client tries a read again:
//! `GET /health` and `POST /burns` change nothing at the PSP. `POST /melt` burns
//! notes and is sent once; its caller asks `/burns` before it tries again.
//!
//! The stand-in PSP here closes the first connection it accepts without
//! answering, as the stopping API does, and answers the next one.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use esp_mint::exchange::Psp;
use esp_mint::psp_client::HttpPsp;

/// What the stand-in does with the connection it accepts as the n-th (from 0):
/// `None` closes it unanswered, `Some(body)` answers `200` with that JSON. Past
/// the end of the list every connection is closed.
fn stand_in(script: Vec<Option<&'static str>>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let n = count.fetch_add(1, Ordering::SeqCst);
            match script.get(n).copied().flatten() {
                Some(body) => answer(stream, body),
                None => drop(stream),
            }
        }
    });
    (url, accepted)
}

fn answer(mut stream: TcpStream, body: &str) {
    // Read the whole request head, and the body that follows it, so that the
    // connection is not reset under the answer.
    let mut seen = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => seen.extend_from_slice(&chunk[..n]),
        }
        if let Some(at) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&seen[..head_end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while seen.len() < head_end + length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => seen.extend_from_slice(&chunk[..n]),
        }
    }
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(reply.as_bytes());
}

#[test]
fn health_is_asked_again_after_a_connection_closed_unanswered() {
    let (url, accepted) = stand_in(vec![None, Some(r#"{"network":"regtest"}"#)]);
    let psp = HttpPsp::with_timeout(&url, 10).unwrap();
    assert_eq!(psp.network(), Ok(Some("regtest".to_string())));
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

#[test]
fn burns_are_asked_again_after_a_connection_closed_unanswered() {
    let (url, accepted) = stand_in(vec![None, Some(r#"{"burns":[]}"#)]);
    let psp = HttpPsp::with_timeout(&url, 10).unwrap();
    assert_eq!(psp.burns(&[]), Ok(vec![]));
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

#[test]
fn a_read_that_keeps_losing_its_connection_gives_up_after_three_tries() {
    let (url, accepted) = stand_in(vec![]);
    let psp = HttpPsp::with_timeout(&url, 10).unwrap();
    let why = psp.network().unwrap_err();
    assert!(why.starts_with("psp /health:"), "{why}");
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
}

#[test]
fn a_melt_is_sent_once_because_it_burns_notes() {
    let (url, accepted) = stand_in(vec![None, Some(r#"{"burned":0}"#)]);
    let psp = HttpPsp::with_timeout(&url, 10).unwrap();
    let why = psp.melt_named(&[], &[], "memo").unwrap_err();
    assert!(why.starts_with("psp /melt:"), "{why}");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}
