# Changelog

esp-mint 0.1.2 builds on `sp-wire` 0.2.0 (wire version 2) and mint-core 0.1.3. Nothing was recorded per version before this file; the section below is everything the README said about what was built and when.

## 0.7.0 (unreleased)

**Wallets reach this mint over AIR only.** Builds on `sp-wire` with `seal` and `air-client`, as 0.6.0 does.

- **Behaviour change: HTTP is gone for these calls.** `POST /exchange`, `/transfer`, `/redeem` and `/rollover` and `GET /keysets`, `/rotation` and `/fees` are removed; a request for one is a `404`. The same calls are answered by the AIR listener (mint info 1, keysets 3, rotation 4, rollover 5, fees 7, exchange 8, transfer 9, redeem 10), with the same bodies, ceilings, checks and refusals. What is left on `server.bind` is `GET /audit` and `GET /health` (the SPI polls `/health`), and the operator's routes on `server.admin_bind` are unchanged. The handlers, their `Json` and `Bytes` extractors and the per-route layers are deleted; `server::router` is `/audit` and `/health`.
- **Behaviour change: AIR is required.** `serve` needs `air.server` and `air.host` (`ESP_AIR_SERVER`, `ESP_AIR_HOST`) and names any that is missing; the other commands do not. The AIR listener always runs, and **esp-mint exits with status 1 if the listener fails**, where it used to log and carry on with HTTP only, so that a supervisor restarts it (it resumes from the stored slot counter).
- **Behaviour change: `air.enabled` and `ESP_AIR_ENABLED` are removed.** A file or an environment that names them is refused with a message that says they are gone. Remove them.
- **Behaviour change: `server.bind` must be a loopback address**, checked when the settings are read (every command). It was the public API's address; what it serves now is for the operator and the SPI on this machine.
- `redeem.rs` and `admin.rs` lose the notes that said a ceiling above 15 MiB takes larger requests over HTTP only: it takes requests no wallet can send.
- Tests: the integration tests now call the mint over AIR on a real `air_server` (`tests/common/mod.rs`); `tests/air_info.rs` no longer compares with the HTTP routes. The `*_http.rs` files keep their names. `hold_http.rs` hands the overlapping calls of its first two tests to the mint in the test process (the AIR listener answers one request at a time, so it cannot overlap them) and runs the PSP timeout over AIR, where the PSP's `502` is a signed "unavailable" (`503` in the helper). A test that nothing but `/audit` and `/health` answers over HTTP replaces the one for the documented routes; new config tests cover the removed settings and the loopback check.
- Tests: the two test helpers that match what the mint serves (`served_call` in `tests/common/mod.rs` and `served_body` in `tests/air_info.rs`) handle sp-wire's new `Served::Ignored` (a request answered with no reply, which psp-mint's kind 15 uses) by failing the test. esp-mint never returns it. No mint behaviour changes.

## 0.6.0, AIR listener (unreleased)

**AIR 3.0.0 (unreleased).** Comments and docs follow sp-wire's move to air 3.0.0 (`ff41c09`) and air_server 1.0.0 (`ec6ac1f`); no code changes. The local AIR checkouts for a build are now on the branch `air3-export-secretkey` (3.0.0 plus the `SecretKey` export), and air_server is at 1.0.0.

- **An AIR listener answers a wallet's calls, beside the HTTP server. Off unless `air.enabled` is true.** Mint info, keysets, rotation, fees, rollover, exchange, transfer and redeem (request kinds 1, 3, 4, 7, 5, 8, 9 and 10 of `sp_wire::air_request`), each with a reply signed by the mint's DID key. The body is the body of the HTTP route and is built by the same function (the routes were split into functions that return the status and the JSON, and thin handlers; HTTP behaviour is unchanged), so the two cannot differ, and a test compares the bytes. The request is sealed to the mint's DID, so the notes in an exchange, a transfer, a redemption or a rollover are not visible to the AIR server.
- **The ESP's own DID.** `mint_did_key.json` in the network's data folder, made on first use when `air.enabled` is true and never replaced if damaged; new module `did`. It is not the PSP's, so both can share one AIR server. New command `esp-mint pubkey` prints the DID (the wallet's `air.esp_did`).
- **Idempotent.** A resent exchange, transfer, redemption or rollover (over AIR, over HTTP, in another slot, after a replayed slot) is answered from the stored answer and nothing is applied twice; no new mint logic was needed, since each already stores its answer by request hash before it burns.
- **Refusals.** A `400` is a signed `refused` reply with the route's JSON. Another `4xx` (`404`, `409 in_progress`, `413`) is `refused` with the JSON plus `"http_status": N`, so a wallet does not take it for a refusal of its notes. A `5xx`, including the `502` of an unreachable PSP, is a signed `unavailable`.
- **`redeem.max_request_bytes` defaults to 15 MiB (was 64 MiB).** AIR's WebSocket messages are capped at 16 MiB, so a redemption between about 16 and 64 MiB would have been accepted over HTTP and could not be sent over AIR. The default is now the cap less 1 MiB (`redeem::AIR_MESSAGE_CAP`, `AIR_ROOM`), which fits about 84,000 notes with no outputs coming back; the wallet splits a larger redemption into several requests as it already did, from the ceiling `GET /fees` reports. **A mint that sets `ESP_REDEEM_MAX_BYTES` or `redeem.max_request_bytes` itself is not changed**, and may take larger requests over HTTP only. `GET /fees` reports the new number; the default's docs, the fee example and the size tests moved with it.
- **Each request is answered on a blocking thread**, because an exchange calls the PSP with a blocking client; requests are answered one at a time, in slot order, so a slow exchange holds up those behind it (README, "The AIR listener").
- New settings `air.enabled`, `air.server`, `air.host`, `air.held_reads`, `air.timeout_secs` (`ESP_AIR_*`). New dependencies: sp-wire with its `seal` and `air-client` features; tokio `time` and `sync`. New `air_listener::run`, `run_blocking`, `Serve`, `read_next`, `write_next`; `server::air_served`, `server::mint_info`, `server::rollover_outcome`.
- Tests in `tests/air_info.rs`: every moved call against a real mint and a real `air_server`, compared with HTTP; the four state-changing calls resent over AIR and HTTP and after a replayed slot without being applied twice; a rollover of 1000 notes; ceilings (`413` and the `http_status`); refusals; a PSP that cannot be reached and a poisoned mint (`unavailable`); tampered, forged, wrong-kind, wrong-mint and stale replies for each call; the ESP and a second mint on one AIR server.

## 0.6.0 (unreleased)

**Wire version 3: every service ID is the 33-byte AIR DID.** Builds on `sp-wire` 0.5.0 (`WIRE_VERSION` 3) and mint-core 0.1.3. `Cargo.toml` still names `sp-wire` by `tag = "v0.4.0"`: the tag moves to the new release when it is made, and until then the build uses a local `[patch]` (see the README of `sp-wire`). There is no migration and no dual format: a 64-character (x-only) service is refused, with a message that says to use the DID.

- **The service in the terms, the exchange, transfer, rollover and redeem requests, the queue and the payout report is `sp_wire::ServiceDid`** (33 bytes, 66 hex characters in JSON, in `queue.json` and `responses.json`, and in `esp-mint pay <service>` and `POST /payouts/pay`). A signature is still BIP340: it is checked against `ServiceDid::x_only()`, which is never an ID.
- **Every derived key changes.** The terms are 41 bytes (was 40) and are an input of the key derivation, so a note issued by 0.5.0 does not verify, and the `known_answers` test has new values (computed by an independent model, which first reproduced the old ones). Existing master secrets still load.
- **Redeem encoding version 3.** The request is `120 + 187 per note + memo + 82 per output` bytes (was `119 / 186 / 81`). A version 2 request is refused with a message that says so.
- **Canonical sizes for the exchange and transfer fees** are one byte larger, because the request holds a 33-byte service: the fixed part of an exchange is 49 (was 48) and of a transfer 121 (was 120). Fee rates are unchanged and 0 by default.
- **`queue.json` and `responses.json` from 0.5.0 do not load** (they hold x-only services). Empty or delete them on a mint with no live notes; there is nothing to migrate.
- `storage.mint_state` takes DIDs, not x-only keys, and no longer reduces a 33-byte key.
- Tests: fixtures use the DID `02` + the generator's x; the config storage test checks that the x-only form is refused; the payout command and the decode test check their refusal messages; the sizes in the redeem tests follow `sp-wire` 0.5.0 (the two test memos are 205 and 123 bytes so that a request of one note is still exactly 512 bytes).
- Documentation: README and DESIGN.md say 66 hex characters and the new sizes; DESIGN.md "Wire format and versions" describes version 3.

## 0.5.0 (2026-10-17)

- **`esp-mint --help` prints plain usage and exits 0**, with every command described (it printed `Error: "usage:\n ..."` as a debug string and exited 1). A missing or unknown command prints the same text on standard error and exits 2. Every error of every command is now printed as `error: ...` in plain text, not as the debug form of the value.
- **Every fee defaults to 0.** `redeem.fee_per_byte` (`ESP_REDEEM_FEE_PER_BYTE`) was 1,000,000 ESP units a byte and is now 0, like `exchange.fee_per_byte` and `transfer.fee_per_byte`; `DEFAULT_FEE_PER_BYTE` is 0. It is still a setting. Its range is now 0 to 10^15 (it was 1 to 10^15, so 0 was refused), and the dollar text is gone from the README, the setting's description and the code comment. **A mint that relied on the old default must set the rate** (`[redeem] fee_per_byte` or the variable) to keep charging it. Tests: the defaults, the reload (from 0, and a value over the range is the bad file), the range test, `DEFAULT_FEE_PER_BYTE`, and a new `redeem_http` test that a redemption at the default pays no fee and owes the whole amount.
- Lint cleanups, no change in behaviour: `Clone` on a `Copy` value in `transfer.rs`; test helpers take `&Path` instead of `&PathBuf`.
- Documentation: the storage requirements are the numbered set (1 to 8) in DESIGN.md, and the health monitor and service files are described by the SPI repository, not by a folder outside this repo.
- **`GET /audit` splits the outstanding ESP into matured and unmatured.** New fields: `outstanding_matured` (under redeemable-after days that have come), `outstanding_unmatured` (days still ahead), `outstanding_unsplit` (ESP issued before this version, whose day was not kept; zero on a mint that has run it from its first note), `requests_unfinished` and `as_of_day`. `issued`, `redeemed` and `outstanding` are as before. The parts add up to `outstanding`, except for what a request in the middle of being finished has done and the split does not count yet. Needed by SPI, whose audit showed a warning without it.
- **A per-day ledger of ESP issued and redeemed** (`src/ledger.rs`), kept in `responses.json` next to the stored requests and changed in the same atomic write that finishes a request, so it survives restarts and torn writes and counts nothing twice (see DESIGN.md, "The audit split"). An exchange counts its outputs as issued; a transfer its inputs as redeemed and its outputs as issued (the difference is the fee); a redemption each burned note as redeemed and each refund as issued, under each note's own day; a decline its decline outputs as issued, once per queue entry (it is marked in `queue.json`, so it is counted by the entry's id). A rollover counts nothing.
- **`responses.json` has a new shape**: `{"entries": {...}, "ledger": {...}}`. The old shape (a bare object of entries) is read as it is with an empty ledger, and the first change writes the new one. **An older version refuses the new file.** Copy `responses.json` before upgrading if going back must stay possible.
- **History before this version can not be split by day.** It shows as `outstanding_unsplit` and falls as the old notes are redeemed.
- **API change in the library:** `redeem::decline`, `decline_with` and `decline_gens` take `&mut Responses` (they count the decline), and `Responses::put` is joined by `finish` and `count_decline`. The admin route is unchanged.
- Tests: the ledger (day boundary, days that are behind, the one-time decline, amounts beyond 64 bits); `Responses` (the old file shape, the new one, a torn write, a failed write, a damaged ledger, counting once); the exchange, the transfer (with and without a fee, and stopped part way), the redemption (burned notes, refunds, notes left alone) and the decline (counted, counted before a crash, refused) each counted once, also after a restart; `/audit` at a day boundary, with unsplit history, and with a request unfinished; over HTTP, an exchange that matures at once and one that does not, a restart, a retry, ESP the ledger never saw, a transfer that moves nothing, and a decline.

## 0.4.0 (2026-10-16)

- **Setting `storage.mint_state` (`ESP_STORAGE_MINT_STATE`): which AIR services will keep this mint's state.** An ordered list of service IDs (index 0 the primary, the rest secondaries); one entry is valid, empty (the default) means local only, at most 8, no duplicates. Config and validation only: nothing reads or writes the AIR, the state is still local files. The parser and checks are `sp_wire::storage` (sp-wire 0.4.0), shared with the other mints and the wallet. In `esp-mint.toml` the value is an array of strings or one string. DESIGN.md has "Storage policy (setting only)"; the planned behaviour is in sandbox-mint's DESIGN.md, "AIR storage requirements". It is a restart setting (marked so in `SPECS`): a `SIGHUP` reload keeps the running list and logs that a change needs a restart.
- `sp-wire` is now the `v0.4.0` tag. Tests: the setting from the file and the environment, both forms, and every kind of refusal.

## 0.3.0 (2026-10-16)

- **ESP amounts must be powers of two.** The exchange, the transfer and the redemption refuse any amount that is not a power of two (zero included), with `400` and code `bad_denomination` (the same as the FSP mint), before anything is burned or charged. Checked: the exchange's outputs; the transfer's inputs and outputs; the redemption's input notes, decline outputs and refund outputs. Rollover is unchanged (its outputs must equal its inputs). Why: notes of one size look alike, so an amount no longer identifies a holder. New in `src/units.rs`: `BAD_DENOMINATION` and `is_denomination`. No setting for a largest denomination was added.
- Tests: odd amounts are refused before any burn (unit tests and over HTTP, on all three routes, with the PSP note or ESP notes still spendable afterwards, and no fee taken on a redemption); totals split into powers of two round-trip; the existing amount tests moved to power-of-two sizes, including the redemption fee boundary tests. A fee-dependent request needs a count of outputs that fits the amount left after the fee (see DESIGN.md).
- **Behaviour change for requests stored before this version:** a pending exchange or a transfer (pending or done) with an amount that is not a power of two is refused if sent again. Upgrade with no pending exchanges or transfers. A wallet must be on the matching version.

- **The exchange no longer holds the mint's lock while it waits on the PSP.** It runs in five phases (check, look at the notes, reserve, burn, finish) and the lock is held for the three that touch the mint, with the `pending` entry written before the burn as before. A slow or hung PSP holds up only the request waiting on it. New in `exchange`: `prepare_gens`, `precheck`, `reserve_gens`, `burn_phase`, `finish_gens` (and `exchange_gens`, which runs them back to back). New in `server`: `EspState::in_flight` (the hashes being worked on, in memory), `InFlight`, `IN_PROGRESS`. A copy of a request that arrives while the same one is being processed gets `409` `in_progress` and is not processed twice. `EspState` has a new field, `in_flight`.
- Tests: the phases by hand (what each writes and when); a crash after each phase, with a restart and a retry, burns once; a request that got in between the check and the reservation is caught; a PSP that cannot be asked leaves nothing reserved; a failed burn leaves the entry for the retry. Over HTTP (`tests/hold_http.rs`): an exchange stuck at the PSP does not block an unrelated exchange or the read routes; the same request sent twice while stuck gets `409` and the PSP sees one burn; a PSP timeout leaves nothing running and the retry finishes.
- **Running as a service.** SIGTERM now stops the mint the way Ctrl-C does (both listeners drain and the process exits 0); before, only SIGINT did, and a service manager's stop killed it. At startup the mint waits for an unreachable PSP and asks again every `psp.startup_retry_secs` (new setting, `ESP_PSP_STARTUP_RETRY_SECS`, default 5, restart-only) instead of exiting; a PSP on another network, or that names none, still stops it. `ESP_DATA_DIR` no longer needs `HOME` to be set. `launchd` and `systemd` definitions, the env and monitor settings examples and `sp-health-monitor.sh` are in `sandbox-mint/ops`, with the steps in `sandbox-mint/OPERATIONS.md`. Test: the same data cannot be opened twice at once. The config tests list the new setting.
- DESIGN.md: "Not holding the lock while the PSP is called" and "What the storage must provide" (the guarantees the AIR storage has to meet).
- Docs: a decline over the AIR is a plain message, most often "these notes are not mature yet; wait until they mature and try again" (DESIGN.md, "Declined and paid"). ESP is not split for holders, because they convert it to FSP straight away.

## 0.2.0

- **New outputs are signed with the live key set the request names, current or previous.** Before, a request naming the previous set was refused `400 keyset_not_current`. Now only a set that is not live is refused: `keyset_retired` for a deleted one, `unknown_keyset` for anything else, both before anything is burned. This covers the exchange, the transfer, the rollover and a redemption's decline and refund outputs. A queued decline or refund is signed with the set the request named while it is still live, and with the current set once that has been deleted. `keyset_not_current` is no longer sent; `sp-wire` keeps the name reserved.
- Tests: outputs naming the previous set are signed by it; an unknown set gets `unknown_keyset` with nothing burned; a unit test that `Gens::signer` signs with the named live set, refuses a deleted one `keyset_retired` and an unknown one `unknown_keyset`.
- **`POST /rollover` has a size limit and a note cap of its own.** Before, it had no configured ceiling (only the HTTP library's own default applied) and held the note cap as a constant. `rollover.max_request_bytes` (`ESP_ROLLOVER_MAX_BYTES`, default 1 MiB, reloaded on SIGHUP) is the ceiling: a larger body is refused `413` before it is parsed. `rollover.max_items` (`ESP_ROLLOVER_MAX_ITEMS`, default 1000, the old `MAX_ROLLOVER_NOTES`) is the most notes in one rollover. Both are served on `GET /fees` under `rollover`. Tests: the defaults and environment overrides; a rollover body over the ceiling gets `413` on a rotating and a non-rotating mint; a rollover over the note cap gets `400` and burns nothing.

## Moved from the README

The sections and sentences below were in the README and describe what was built, when, or what changed. They are kept here word for word. A short fragment is a part of a sentence that was cut out; the rest of the sentence stays in the README or DESIGN.md under the same heading.

### Status (as it was in the README)

esp-mint is built and tested: the PSP-to-ESP exchange, the transfer to the service, redemption with its payout queue and report, per-byte and optional fees, key rotation, and a settings file reloaded on SIGHUP. What is left, and what waits on the AIR, is under "Left to do". The whole family and its status are in the top-level `~/sandbox-mint/README.md`.

### Units and amounts

The top PSP denomination went up by 16 to 2^24 (25 keys instead of 21), which covers the same dollar range.

### The exchange

Built.

An entry written before the reservation existed has no lists and holds nothing. It still reads, and finishes as before.

- A pending exchange from before the PSP kept memos, whose notes were already burned, would fail with `NoteSpentElsewhere` on retry, since there is no memo on record. Upgrade with no pending exchanges.

### The issued total

Before v0.1.3, mint-core's `issue_with_key` marked the output's blind nonce used and then added its amount to the issued total as two separate writes. A crash in the window between them left the total permanently short by that output: a retry saw the nonce already used, treated the output as issued, and signed it again without adding to the total, so nothing ever added the missing amount. From v0.1.3 the mark and the total are one sled transaction, so a crash leaves both or neither, and the retry's "already used, so already counted" is true. The same holds for the transfer, the redemption refunds and a rollover. The fix stops new drift. It does not repair a total that was already short before the upgrade.

The issued total is exact across a crash from mint-core v0.1.3 on (see "The issued total" under "The exchange"). Before it, a crash between the nonce mark and the total left the total permanently short.

### Wire version

, so the paths did not change

(2: version 1 was the first release, and version 2 changed only the sealed PSP payload, which this mint does not handle, so no ESP byte moved)

Nothing was changed on the wire by moving the types: the golden values were captured from this mint before the move, and `sp-wire` reproduces them.

### Transfer to the service

Built.

Redemption, when it is built, must check for held notes in the same way.

### Redemption

Built.

### Key rotation

(before, a crash between recording a rollover and its burn let another request burn the note, and the retry would then have signed for it)

- **Upgrade note.** The exchange and transfer hash tags moved to v2, so an entry left pending by an older version is not found by a retry from a new wallet; finish pending requests before upgrading.
