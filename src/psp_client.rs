//! The real PSP, over HTTP: `POST /melt` and `POST /check-state` on `psp-mint serve`.
//!
//! The client is blocking, so it must be created and dropped outside an async
//! runtime, and called from a blocking thread.

use std::time::Duration;

use mint_server::api::{
    CheckStateRequest, CheckStateResponse, MeltRequest, MeltResponse,
};
use mint_types::{Amount, MintInput, Nonce};

use crate::exchange::Psp;

pub struct HttpPsp {
    base: String,
    client: reqwest::blocking::Client,
}

impl HttpPsp {
    pub fn new(base: &str) -> Result<Self, reqwest::Error> {
        Ok(HttpPsp {
            base: base.trim_end_matches('/').to_string(),
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
        })
    }

    fn post<Q: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &Q,
    ) -> Result<R, String> {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .json(body)
            .send()
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
        let melted: MeltResponse = self.post(
            "/melt",
            &MeltRequest {
                inputs: inputs.to_vec(),
                memo: memo.to_string(),
            },
        )?;
        Ok(melted.burned)
    }

    fn spent(&self, nonces: &[Nonce]) -> Result<Vec<bool>, String> {
        let checked: CheckStateResponse = self.post(
            "/check-state",
            &CheckStateRequest {
                nonces: nonces.to_vec(),
            },
        )?;
        Ok(checked.spent)
    }
}
