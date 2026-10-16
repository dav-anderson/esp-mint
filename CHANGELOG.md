# Changelog

esp-mint 0.1.2 builds on `sp-wire` 0.2.0 (wire version 2) and mint-core 0.1.3. Nothing was recorded per version before this file; the section below is everything the README said about what was built and when.

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
