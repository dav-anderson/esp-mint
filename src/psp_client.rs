//! The real PSP, over HTTP: `POST /melt` and `POST /burns` on `psp-mint serve`.
//! `/burns` says, for each note, whether it is spent and the memo it was burned
//! under, which is how a retry tells its own burn from someone else's.
//!
//! The client is blocking, so it must be created and dropped outside an async
//! runtime, and called from a blocking thread.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mint_server::api::{MeltRequest, MeltResponse};
use mint_types::{Amount, MintInput, Nonce};
use serde::{Deserialize, Serialize};

use crate::exchange::{Burn, Psp};

/// Body of the PSP's `POST /melt`: mint-core's melt and the keyset of each
/// note (psp-mint's `PspMeltRequest`).
#[derive(Serialize)]
struct PspMelt<'a> {
    #[serde(flatten)]
    melt: MeltRequest,
    keysets: &'a [String],
}

/// Body of the PSP's `POST /burns`.
#[derive(Serialize)]
struct BurnsRequest<'a> {
    nonces: &'a [Nonce],
}

#[derive(Deserialize)]
struct BurnsResponse {
    burns: Vec<WireBurn>,
}

#[derive(Deserialize)]
struct WireBurn {
    spent: bool,
    memo: Option<String>,
}

/// How many times a read is tried when the connection is lost before the PSP
/// answers (the local API closes a connection it had accepted but not yet read
/// when it stops for a snapshot), and how long to wait between tries.
const READ_TRIES: u32 = 3;
const READ_RETRY_WAIT: Duration = Duration::from_millis(100);

pub struct HttpPsp {
    base: String,
    client: reqwest::blocking::Client,
    /// `psp.timeout_secs`, read at every call, so that a reload changes it.
    timeout_secs: Arc<AtomicU64>,
}

impl HttpPsp {
    /// A client with the default timeout (`psp.timeout_secs`, 30 seconds).
    pub fn new(base: &str) -> Result<Self, reqwest::Error> {
        Self::with_timeout(base, 30)
    }

    /// A client whose calls give up after `timeout_secs` seconds.
    pub fn with_timeout(base: &str, timeout_secs: u64) -> Result<Self, reqwest::Error> {
        Ok(HttpPsp {
            base: base.trim_end_matches('/').to_string(),
            client: reqwest::blocking::Client::builder().build()?,
            timeout_secs: Arc::new(AtomicU64::new(timeout_secs)),
        })
    }

    /// The place the timeout is kept: store a new number of seconds in it and
    /// the next call uses it. `serve` does that when `psp.timeout_secs` is
    /// reloaded.
    pub fn timeout_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.timeout_secs)
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs.load(Ordering::Relaxed))
    }

    /// Send a read, which changes nothing at the PSP, again if the connection
    /// was lost before an answer came. A timeout is not tried again (the call
    /// already took as long as it may), and neither is a call that was answered.
    fn read(
        &self,
        send: impl Fn() -> reqwest::Result<reqwest::blocking::Response>,
    ) -> reqwest::Result<reqwest::blocking::Response> {
        let mut tries = 1;
        loop {
            match send() {
                Err(e) if tries < READ_TRIES && !e.is_timeout() => {
                    tries += 1;
                    std::thread::sleep(READ_RETRY_WAIT);
                }
                other => return other,
            }
        }
    }

    /// The network the PSP reports in `GET /health` (`None` if it does not
    /// say). `/health` answers `503` while the PSP is unwell, and the network is
    /// in that body too.
    pub fn network(&self) -> Result<Option<String>, String> {
        let response = self
            .read(|| {
                self.client
                    .get(format!("{}/health", self.base))
                    .timeout(self.timeout())
                    .send()
            })
            .map_err(|e| format!("psp /health: {e}"))?;
        let body: serde_json::Value = response.json().map_err(|e| format!("psp /health: {e}"))?;
        Ok(body
            .get("network")
            .and_then(|n| n.as_str())
            .map(str::to_string))
    }

    /// `POST` `body` to `path`. `idempotent`: the call only reads (`/burns`), so
    /// it is tried again if the connection is lost. `/melt` burns notes, so it is
    /// sent once; its caller looks the burn up with `/burns` before it tries again.
    fn post<Q: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &Q,
        idempotent: bool,
    ) -> Result<R, String> {
        let send = || {
            self.client
                .post(format!("{}{path}", self.base))
                .timeout(self.timeout())
                .json(body)
                .send()
        };
        let response = if idempotent { self.read(send) } else { send() }
            .map_err(|e| format!("psp {path}: {e}"))?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().unwrap_or_default();
            return Err(format!("psp {path} returned {status}: {text}"));
        }
        response.json().map_err(|e| format!("psp {path}: {e}"))
    }
}

impl Psp for HttpPsp {
    fn melt(&self, inputs: &[MintInput], memo: &str) -> Result<Amount, String> {
        self.melt_named(inputs, &[], memo)
    }

    fn melt_named(
        &self,
        inputs: &[MintInput],
        keysets: &[String],
        memo: &str,
    ) -> Result<Amount, String> {
        let melted: MeltResponse = self.post(
            "/melt",
            &PspMelt {
                melt: MeltRequest {
                    inputs: inputs.to_vec(),
                    memo: memo.to_string(),
                },
                keysets,
            },
            false,
        )?;
        Ok(melted.burned)
    }

    fn burns(&self, nonces: &[Nonce]) -> Result<Vec<Burn>, String> {
        let reply: BurnsResponse = self.post("/burns", &BurnsRequest { nonces }, true)?;
        Ok(reply
            .burns
            .into_iter()
            .map(|b| Burn {
                spent: b.spent,
                memo: b.memo,
            })
            .collect())
    }
}
