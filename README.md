# esp-mint

ESP is the encumbered point. It is obtained by exchanging PSP at 10^11 ESP for 1 PSP (10 PSP = $1 = 10^12 ESP). Each ESP note is bound to terms: one service that alone may redeem it, and a date before which nobody can. Every ESP amount the mint signs or accepts is a power of two (1, 2, 4, ...), so notes of one size look alike; an amount that is not is refused `400` with code `bad_denomination` before anything is burned or charged. The wallet does the splitting. Why, and every route it applies to, is in [DESIGN.md](DESIGN.md), "ESP amounts are powers of two".

## Building

esp-mint builds from tagged dependencies: mint-core at `v0.1.3` and `sp-wire` at `v0.4.0` (git tags). **The AIR listener needs AIR.** esp-mint asks sp-wire for its `seal` and `air-client` features (the mint's DID key, and the transport, see "The AIR listener"), which build the `air` and `air_server` crates; both are not tagged upstream, so until sp-wire's next release is tagged esp-mint is built against the local `sp-wire`, `air` and `air_server` folders with a git-ignored `.cargo/config.toml` (the same file as psp-mint's: copy it, and see psp-mint's README, "Building", for why). Run `cargo update -p sp-wire` once after adding the patches, check that `cargo tree --all-features -i air` shows the local AIR folder, and run `git restore Cargo.lock` before committing (a lock file that names a local path would not build from GitHub). To test against unpushed local copies of `sp-wire` or mint-core, `source ~/sandbox-mint/scripts/local-git.sh` points git at the local folders and their local tags (the recipe, with the plain `[patch]` form, is in the top-level README in `sandbox-mint`).

## Run

```
cargo run -- config
ESP_NETWORK=regtest cargo run -- serve
```

esp-mint asks the PSP for its network at startup. If the PSP cannot be reached it waits and asks again (`psp.startup_retry_secs`), so psp-mint can start first or second; it stops with a message if the PSP reports another network or none. `config` prints every setting and where it came from without starting the mint.

## Commands

| Command | What it does |
|---|---|
| `serve` | Runs the public API and the operator's listener. |
| `config` | Prints the settings in use. |
| `payouts [--json]` | The payout report: what is owed to each service. |
| `pay <service> <ref> <entry id>...` | Marks exactly those entries paid, with one payment reference. `--mixed-memos` if one payment covers entries with different memos. |
| `decline <entry id> --reason TEXT` | Declines a payout and signs its stored decline outputs. |
| `migrate` | Moves files from before the per-network split into `regtest/`. |
| `pubkey` | Prints the mint's AIR DID (66 hex characters), making the key file `mint_did_key.json` if there is none. This is the wallet's `air.esp_did`. |
| `--help` | Prints the commands and exits with status 0. An unknown or missing command prints the same text on standard error and exits with status 2. |

How `payouts`, `pay` and `decline` work is in [DESIGN.md](DESIGN.md), "Payout report" and "Declined and paid". The operator's HTTP routes (`GET /payouts`, `POST /payouts/pay`, `POST /payouts/decline`) are on the loopback listener `ESP_ADMIN_BIND`, with `ESP_ADMIN_TOKEN` as a bearer token if it is set.

## Settings

**Network.** esp-mint is on mainnet unless `server.network` (`ESP_NETWORK`) says otherwise; for a regtest PSP run `ESP_NETWORK=regtest cargo run -- serve`. Start the PSP first: the mint will not start without asking it. `/health` returns `{"status": "ok", "network": "...", "wire_version": 2}`. Its data lives in `ESP_DATA_DIR/<network>/` (default `~/.esp-mint/<network>/`). Files from before the split, at the top of `ESP_DATA_DIR`, make `serve` refuse to start with a message; `esp-mint migrate` moves them into `regtest/` (all development so far was regtest), moving nothing if the target holds any of them and deleting nothing. The config file stays at the top.

Nothing an operator might tune is a constant in the code. Each setting has a default, can be set in one file, `esp-mint.toml` in the data directory (or the file `ESP_CONFIG` names, which must exist), and can be overridden by an environment variable, which wins over the file. The file is TOML in sections:

```toml
[redeem]
max_memo_bytes = 128

[exchange]
max_request_bytes = 1048576
fee_per_byte = 0
```

`esp-mint serve` reads the settings at startup, logs every one with its value and where it came from (default, file or environment variable), and refuses to start if any value is not a whole number, is out of range, or is not a setting (a misspelt key is an error, not a silent no-op). All the problems are listed at once. `esp-mint config` prints the same list without starting the mint.

**Reload.** Send the running mint `SIGHUP` (`kill -HUP <pid>`). It reads the file and the environment again, checks them, and swaps them in all at once, or keeps the old values and logs why. Everything marked SIGHUP in the table takes effect for the next request; a request already running finishes with the values it started with. Addresses, the PSP client and the operator listener's body ceiling are read once, so a change to them waits for a restart; the mint says so in its log. Reloading is safe because every request takes the settings once at its start, and every charge is made at the rate in force when the request is accepted.

Two things are not settings: `ESP_DATA_DIR` (default `~/.esp-mint`: the config file; and per network, in `<network>/`, the master secret, `db/`, `responses.json` and `queue.json`) and `ESP_ADMIN_TOKEN` (a secret, so never in a file; if set, the operator's routes need `Authorization: Bearer <token>`).

| Setting (`esp-mint.toml`) | Environment variable | Default | Units | Reload | What it affects |
|---|---|---|---|---|---|
| `[server] bind` | `ESP_BIND` | `127.0.0.1:3100` | host:port | restart | The public API's address. |
| `[server] admin_bind` | `ESP_ADMIN_BIND` | `127.0.0.1:3101` | host:port | restart | The operator's listener (payout report, settle, decline). Must be a loopback address. |
| `[server] network` | `ESP_NETWORK` | `main` | network | restart | The Bitcoin network of the PSP: `main`, `regtest`, `signet`, `testnet`. At startup `serve` asks the PSP's `GET /health`, waits for it if it cannot be reached, and refuses to start if it reports another network or none. Reported in this mint's `/health`. |
| `[psp] url` | `ESP_PSP_URL` | `http://127.0.0.1:3000` | URL | restart | The PSP mint (`psp-mint serve`) where PSP notes are burned and looked up. |
| `[psp] timeout_secs` | `ESP_PSP_TIMEOUT_SECS` | `30` | seconds | restart | How long a call to the PSP may take before the exchange fails and can be retried. |
| `[psp] startup_retry_secs` | `ESP_PSP_STARTUP_RETRY_SECS` | `5` | seconds | restart | At startup the mint asks the PSP which network it is on. If the PSP cannot be reached it waits this long and asks again, for as long as it takes. A PSP that answers with another network, or with none, is not waited for: the mint stops with a message. |
| `[terms] maturity_days` | `ESP_MATURITY_DAYS` | `365` | days | SIGHUP | How long after the day of issue a new exchange's ESP notes become redeemable. Fixed into each exchange when it is first accepted; notes already issued keep theirs. |
| `[exchange] max_items` | `ESP_EXCHANGE_MAX_ITEMS` | `1000` | notes | SIGHUP | The most PSP notes, and the most ESP outputs, in one exchange. |
| `[exchange] min_psp` | `ESP_EXCHANGE_MIN_PSP` | `1` | PSP (10 PSP = $1) | SIGHUP | The smallest exchange, in PSP. 1 PSP is $0.10 (10 PSP = $1). Below it the exchange is refused before anything is burned. |
| `[exchange] max_request_bytes` | `ESP_EXCHANGE_MAX_BYTES` | `1048576` | bytes | SIGHUP | The ceiling on one exchange request body (1 MiB). A larger body is refused with 413 before it is parsed: nothing is burned, nothing is charged. |
| `[exchange] fee_per_byte` | `ESP_EXCHANGE_FEE_PER_BYTE` | `0` | ESP units per canonical byte | SIGHUP | The exchange fee rate. 0 means no mint fee. If set, a request pays this times its canonical size (49 + 146 per PSP note + 41 per output bytes), paid in ESP on top of the exact amount, at the rate in force when it is accepted; the rate is stored on the reply. |
| `[transfer] max_items` | `ESP_TRANSFER_MAX_ITEMS` | `1000` | notes | SIGHUP | The most notes, and the most outputs, in one transfer. |
| `[transfer] max_request_bytes` | `ESP_TRANSFER_MAX_BYTES` | `1048576` | bytes | SIGHUP | The ceiling on one transfer request body (1 MiB). A larger body is refused with 413 before it is parsed: nothing is burned, nothing is charged. |
| `[rollover] max_items` | `ESP_ROLLOVER_MAX_ITEMS` | `1000` | notes | SIGHUP | The most notes in one rollover. More is refused `400` before anything is burned. |
| `[rollover] max_request_bytes` | `ESP_ROLLOVER_MAX_BYTES` | `1048576` | bytes | SIGHUP | The ceiling on one rollover request body (1 MiB). A larger body is refused with 413 before it is parsed: nothing is burned, nothing is charged. |
| `[transfer] fee_per_byte` | `ESP_TRANSFER_FEE_PER_BYTE` | `0` | ESP units per canonical byte | SIGHUP | The transfer fee rate. 0 means no mint fee (the AIR send fee covers a transfer). If set, a request pays this times its canonical size (121 + 146 per note + 41 per output bytes), paid in ESP on top of the exact amount, at the rate in force when it is accepted; the rate is stored on the reply. |
| `[redeem] fee_per_byte` | `ESP_REDEEM_FEE_PER_BYTE` | `0` | ESP units per encoded byte | SIGHUP | The redemption fee rate. 0 means no mint fee. If set, a request pays this times its encoded size, at the rate in force when it is accepted; the rate is stored on the reply and on the queue entry. |
| `[redeem] max_request_bytes` | `ESP_REDEEM_MAX_BYTES` | `15728640` | bytes | SIGHUP | The ceiling on one encoded redemption request (15 MiB: AIR carries at most 16 MiB in one message, so every redemption the mint takes can be sent over AIR; the wallet splits a larger one into several requests). A larger body is refused with 413 before it is parsed: no burn, no fee. Raised above 15 MiB, larger requests can come over HTTP only. |
| `[redeem] max_memo_bytes` | `ESP_REDEEM_MAX_MEMO_BYTES` | `256` | bytes | SIGHUP | The longest payout memo in a redemption request. |
| `[redeem] max_reason_bytes` | `ESP_REDEEM_MAX_REASON_BYTES` | `1024` | bytes | SIGHUP | The longest reason the operator may give when declining a payout. |
| `[rotation] activation_hours` | `ESP_ROTATION_ACTIVATION_HOURS` | `8760` | whole hours | restart | Hours from the first issue to the first key rotation. **0 turns rotation off.** 0 to 10,000,000. See [DESIGN.md](DESIGN.md), "Key rotation". |
| `[rotation] period_hours` | `ESP_ROTATION_PERIOD_HOURS` | `87600` | whole hours | restart | Hours between rotations (10 years). 1 to 10,000,000: no policy minimum, but 0 is refused here (it is an off switch only in psp-mint). |
| `[admin] max_request_bytes` | `ESP_ADMIN_MAX_BYTES` | `1048576` | bytes | restart | The ceiling on one request body on the operator's listener (1 MiB). |
| `[queue] max_payment_ref_bytes` | `ESP_QUEUE_MAX_REF_BYTES` | `256` | bytes | SIGHUP | The longest payment reference accepted when an entry is marked paid. |
| `[storage] mint_state` | `ESP_STORAGE_MINT_STATE` | none (local only) | service DIDs | restart | Service IDs (each a 33-byte AIR DID: 66 hex characters starting `02` or `03`; comma-separated) that will keep the mint's state; index 0 is the primary. One is valid; at most 8. **Setting only: nothing reads or writes the AIR yet.** See [DESIGN.md](DESIGN.md), "Storage policy". |
| `[air] enabled` | `ESP_AIR_ENABLED` | `false` | bool | restart | Run the AIR listener beside the HTTP server. Exactly `true` or `false`. Off, nothing in the `air.*` rows is used or checked beyond its type and range. See "The AIR listener". |
| `[air] server` | `ESP_AIR_SERVER` | empty | public key | restart | The AIR server's name: its public key, the compressed hex AIR prints (66 characters). Required when `air.enabled` is true. The client checks the server's signed challenge against it. The PSP and the ESP can name the same server: their DIDs differ, so their mailboxes do. |
| `[air] host` | `ESP_AIR_HOST` | empty | host or IP | restart | The AIR server's host name or IP, no scheme, no path, no port (the AIR client always dials port 5702). `127.0.0.1` for the server bundled with the SPI on this machine. Required when `air.enabled` is true. |
| `[air] held_reads` | `ESP_AIR_HELD_READS` | `16` | slots | restart | How many mailbox slots ahead of the counter the listener holds a read on. 1 to 200 (the AIR server refuses a session's 257th held read and closes it). |
| `[air] timeout_secs` | `ESP_AIR_TIMEOUT_SECS` | `10` | seconds | restart | How long the AIR server may take to answer one `Create` or `Read` before that step fails. 1 to 600. |

**Every fee defaults to 0.** The three fee settings, `[exchange] fee_per_byte`, `[transfer] fee_per_byte` and `[redeem] fee_per_byte`, are all `0`: the mint charges nothing unless the operator sets a rate. Each can be set from `0` to 10^15 and is changed on `SIGHUP`; a request is charged at the rate in force when it is accepted, and the rate is stored with its reply.

## The AIR listener

A wallet can ask this mint for everything it asks over HTTP except the operator's routes, over AIR instead: **mint info** (what `GET /health` reports: `status`, `wire_version`, `network`), **keysets** (`GET /keysets`), **rotation** (`GET /rotation`), **fees** (`GET /fees`) and the four calls that change state, **rollover** (`POST /rollover`), **exchange** (`POST /exchange`), **transfer** (`POST /transfer`) and **redeem** (`POST /redeem`). Each is answered with a reply signed by the mint. `GET /audit` and the operator's routes are not wallet-facing and are HTTP only; the exchange's call to the PSP (`/melt`, `/burns`) stays a local call inside the SPI; there is no `GET /keys` (the keys of a note arrive in the reply that signs it), so a request for the keys is not answered. With `air.enabled = true` (and `air.server` and `air.host` set) `serve` starts a thread beside the HTTP server that answers them. The HTTP routes stay, for local use. Off by default; with it off the mint is exactly what it was.

- **How it works.** The listener holds reads on the next `air.held_reads` (16) mailbox slots of the mint's DID on the configured AIR server. When a wallet writes a sealed request into one, the listener opens it with the mint's DID key, answers with what the HTTP route of the request's kind returns now (the body byte for byte: the route and the listener call the same functions), signs the reply with the same key, seals it to the wallet's one-off key and writes it into the reply cell only that wallet and the mint can find. The reply cell is write-once, so the first write wins: a request that reached the mint twice, or two mint processes, give one reply. A request of a kind this mint does not serve is logged and skipped.
- **The ESP's own DID.** The key is `mint_did_key.json` in the network's data folder (`~/.esp-mint/<network>`), made with mode 0600 the first time `serve` starts with `air.enabled`; a file that is there but damaged stops the mint and is never replaced (a new key would lose every request sealed to the old one). **It is not the PSP's key.** The PSP and the ESP each have their own DID, so they can share one AIR server (and one `air.server` and `air.host`) and their mailboxes never meet. `esp-mint pubkey` prints the DID (66 hex characters), making the key if there is none; the wallet's `air.esp_did` is that value. The kind of a request names a call, not a mint: the same kind sent to the PSP's DID and to the ESP's DID gets each one's own reply.
- **Exchange, transfer, redeem and rollover** take the same body as the route (JSON, except the redemption, which is the canonical binary encoding, sent as it is). They go through the same ceiling (`exchange.max_request_bytes`, `transfer.max_request_bytes`, `rollover.max_request_bytes`, `redeem.max_request_bytes`: nothing is widened), the same parse and the same checks, in the same order, as the route. **A resent request is not applied twice:** each of the four stores its answer by request hash before it burns anything (the same guarantee as over HTTP), so a retry, a copy in another slot, a copy over HTTP, a crash between answering and writing the counter and a wallet that starts over all get the stored answer or finish the interrupted request. The in-flight guard is shared with HTTP: the same request arriving while it is being processed is refused `409 in_progress`.
- **Refusals.** A `400` is a signed reply with status `refused` and the route's JSON, unchanged (`code`, `error`, `spent` and the rest). Any other `4xx` (`404` for `rotation` on a mint that does not rotate, `409` `in_progress`, `413` `request_too_large`) is a signed `refused` too, with the route's JSON and one more field, **`"http_status": N`**, so the wallet can tell a refusal of its notes (a `400`, which cancels a pending exchange and frees the notes) from a `404`, `409` or `413` (which it treats as HTTP's non-400: an error, nothing cancelled). A `5xx` (a poisoned lock, a failed rotation step, a PSP that could not be reached or refused the burn: HTTP's `502`) is a signed reply with status `unavailable` and no body, so the wallet fails at once with the reason. A retry after `unavailable` is safe, as it is after a `5xx` over HTTP.
- **Privacy.** The request, body included, is sealed to the mint's DID, so the AIR server sees only that a request of some size was written: not the notes, the amounts or the memo. The reply is sealed to the wallet's one-off key.
- **One request at a time.** Each request is answered on a blocking thread (`spawn_blocking`), because an exchange calls the PSP with a blocking HTTP client and a redemption writes files, as the HTTP handlers do. The requests are answered one by one, in slot order, so a slow exchange (up to `psp.timeout_secs` for a slow PSP) holds up the requests behind it, and a long rollover holding the mint lock does the same. The HTTP API is not held up by this, only by the lock, as before.
- **Size.** The listener has no ceiling of its own, and the mint's ceilings apply as over HTTP. A full rollover of 1000 notes is about half a megabyte and goes as one record (a test runs it). **AIR's WebSocket messages are capped at 16 MiB (17 MiB for a client)**, so the redeem ceiling defaults to 15 MiB, the cap less 1 MiB for the envelope, its seal and AIR's framing: every redemption the mint accepts fits one AIR message, and the wallet (which reads the ceiling from `GET /fees`) splits a larger one into several requests. An operator who raises `redeem.max_request_bytes` above 15 MiB can take larger redemptions over HTTP only (REQUEST-DESIGN.md section 16.3).
- **Junk is skipped.** A slot that does not open, is malformed, is of an unknown kind or names a key that is not one is logged and skipped and changes no state.
- **The counter** (`next`, the lowest slot not finished) is the text file `air_mailbox_next` in the network's data folder, with the rest of the mint's local state, and **not** under `storage.mint_state`: it is only an optimisation. Without it the listener starts at slot 0 and an answered slot finds its reply cell taken and is passed over. It is written by temp file, fsync and rename after each slot is finished, so a crash between answering and writing it repeats a slot, which is harmless because the mint answers a repeated request from its stored answer. A damaged counter file stops the listener with a message; it is never replaced.
- **If the AIR client gives up** (more than five held reads end within ten seconds, which is what a session the server refused or closed looks like, or a reply could not be written after three tries) the listener logs `AIR listener failed: ...` and ends. The HTTP API keeps running. Restart esp-mint to start it again; it resumes from the counter. A restart of the AIR server needs nothing: the client reconnects and its held reads resume.
- **Held reads left behind by a stopped listener are never cleaned up by the AIR server** (upstream item 17); with 16, a handful of restarts costs little.
- **The AIR server** is the one bundled with the SPI, reached over loopback; its name is `air.server` and its host `air.host`. Resolving the server from the mint's DID is upstream item 4; until then both are settings.

## HTTP API

`esp-mint serve` runs the API. Its settings are in "Settings" below (`esp-mint.toml` and environment variables).

| Route | What it does |
|---|---|
| `POST /exchange` | Body: `{"service": "<DID hex, 66 characters>", "psp_inputs": [...], "outputs": [...]}`. `409` (`in_progress`) if the same request is being processed now. `200` with the response (see [DESIGN.md](DESIGN.md), "The exchange"). `400` if the request is refused, with `{"error": ...}` (an output that is not a power of two has `"code": "bad_denomination"`), `413` if the body is over `exchange.max_request_bytes`, and also `"code": "note_spent_elsewhere"` and `"spent": [...]` when PSP notes in the request were spent by a different request (see [DESIGN.md](DESIGN.md), "Burn memos"). `502` if the PSP could not be reached or refused the burn. `500` for a fault in the mint. A retry is safe after a `502` or `500`. |
| `POST /transfer` | Body: `{"service": "<DID hex, 66 characters>", "redeemable_after_day": N, "inputs": [...], "outputs": [...], "service_signature": "<hex>"}`. `200` with the response (same shape as the exchange's). `400` if the request is refused, with `{"error": ...}` (nothing was burned; an input that is already spent also carries `"code": "note_spent_elsewhere"` and `"spent": [position]`), `413` if the body is over `transfer.max_request_bytes`. `500` for a fault in the mint, and a retry is safe. See [DESIGN.md](DESIGN.md), "Transfer to the service". |
| `POST /redeem` | Body: the redemption request in its binary encoding (see [DESIGN.md](DESIGN.md), "Redemption"). `200` with the answer, `400` if refused (nothing burned; `code` says why), `413` over the ceiling, `500` for a fault. |
| `POST /rollover` | Body: the rollover request (one service and day, `input_keysets`, `keyset`, inputs, outputs). `200` with the new signatures, `413` if the body is over `rollover.max_request_bytes`, `400` if refused (nothing burned; `code`: `keyset_retired`, `unknown_keyset`, `missing_keyset`, `burn_not_proven`, or `note_spent_elsewhere` with `spent`: the positions of the inputs that are spent). See [DESIGN.md](DESIGN.md), "Key rotation". |
| `GET /keysets` | `{current, previous}` keyset IDs. On every mint, rotating or not. |
| `GET /rotation` | Whether rotation is on, the first-issue time, and the current and previous keysets with their start and retirement times. |
| `GET /fees` | The fee rates, size formulas and ceilings now in force. |
| `GET /audit` | `issued`, `redeemed`, `outstanding`, in ESP units, and the outstanding split by whether its redeemable-after day has come: `outstanding_matured`, `outstanding_unmatured` and `outstanding_unsplit` (ESP issued before 0.5.0, whose day was not kept; zero on a mint that has run 0.5.0 from its first note). Also `requests_unfinished` (exchanges, transfers and redemptions still pending, which the split does not count yet) and `as_of_day` (the day, since the Unix epoch, that "has come" is measured at). The three parts add up to `outstanding`, except for what a request in the middle of being finished has done and the split does not count yet. See [DESIGN.md](DESIGN.md), "The audit split". |
| `GET /health` | `200` while the locks are sound, `503` otherwise. The body has `status`, `network` and `wire_version` (an integer: the version of the wire format this mint speaks; a wallet refuses a mint whose number is not its own). |

The process exits with status 1 if a lock is poisoned, so a supervisor can restart it. The mint's lock is taken for the steps that touch the mint and let go while an exchange waits on the PSP, so a slow PSP holds up only the exchange that is waiting on it (see [DESIGN.md](DESIGN.md), "Not holding the lock while the PSP is called"). The same exchange sent again while it is being processed gets `409` with `code: "in_progress"` and is not processed twice; send it again in a moment. There is no authentication and no TLS: a note authorizes its own spend, so a caller can only burn notes they hold. Bind to localhost. Only one process can open the mint's database.

## Wire version

The request and response types come from [`sp-wire`](../sp-wire/README.md), and `GET /health` returns `wire_version`. A wallet refuses a mint whose number is not its own. Details in [DESIGN.md](DESIGN.md), "Wire format and versions".

## Tests

```
cargo test
cargo fmt --check
```

The integration tests in `tests/` run the HTTP routes (`http.rs`, `transfer_http.rs`, `redeem_http.rs`, `payouts_http.rs`, `limits_http.rs`) against a real mint in the process. `tests/air_info.rs` runs the AIR listener against a real `air_server` started in the test process and a real mint (with a stand-in PSP for the exchange): mint info, keysets, rotation and fees compared byte for byte with the HTTP routes; rollover, exchange, transfer and redeem compared with HTTP and resent (over AIR and over HTTP) without being applied twice, including after a replayed slot; a rollover of 1000 notes; refusals with the `http_status` of a non-400 and the `413` before the parse; a PSP that cannot be reached and a poisoned mint (signed `unavailable`); tampered, forged, wrong-kind, wrong-mint and replayed replies for each call; and the ESP and a second mint sharing one AIR server. Those tests need port 5702 free (the AIR client always dials it; upstream item 12), so run them with nothing else on it.

## Documentation

- [DESIGN.md](DESIGN.md): how esp-mint works and why: keys, the exchange, the transfer, redemption and the payout queue, fees, ceilings, key rotation.
- [CHANGELOG.md](CHANGELOG.md): what was built and what changed.
- [ROADMAP.md](../sandbox-mint/ROADMAP.md) (in `sandbox-mint`): left to do and not decided yet, for every repo.
- [psp-mint](../psp-mint/README.md), [fsp-mint](../fsp-mint/README.md) and [ecash-wallet](../ecash-wallet/README.md): the other parts.
- [OPERATIONS.md](../sandbox-mint/OPERATIONS.md) (in `sandbox-mint`): running the mints as services: `launchd` and `systemd` definitions, install and uninstall, the health monitor.
- [sandbox-mint README](../sandbox-mint/README.md): the family of repos.
