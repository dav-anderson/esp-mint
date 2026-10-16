# esp-mint

ESP is the encumbered point. It is obtained by exchanging PSP at 10^11 ESP for 1 PSP (10 PSP = $1 = 10^12 ESP). Each ESP note is bound to terms: one service that alone may redeem it, and a date before which nobody can.

## Status

esp-mint is built and tested: the PSP-to-ESP exchange, the transfer to the service, redemption with its payout queue and report, per-byte and optional fees, key rotation, and a settings file reloaded on SIGHUP. What is left, and what waits on the AIR, is under "Left to do". The whole family and its status are in the top-level `~/sandbox-mint/README.md`.

Source map: terms and the date rule (`src/terms.rs`), unit constants and checked sums (`src/units.rs`; both are re-exports of `sp-wire`, see "Wire format and versions"), per-terms key derivation (`src/keys.rs`), the exchange (`src/exchange.rs`), stored responses (`src/responses.rs`), the PSP client (`src/psp_client.rs`), the API (`src/server.rs`), the transfer (`src/transfer.rs`), redemption (`src/redeem.rs`), the queue and payout report (`src/queue.rs`, `src/payouts.rs`, `src/admin.rs`), fees (`src/fee.rs`), rotation (`src/rotation.rs`) and settings (`src/config.rs`).

esp-mint builds from tagged dependencies: mint-core at `v0.1.3` and `sp-wire` at `v0.1.0` (git tags). It does not use the `air` crate, so nothing else is needed. To test against unpushed local copies of `sp-wire` or mint-core, `source ~/sandbox-mint/scripts/local-git.sh` points git at the local folders and their local tags (the recipe, with the plain `[patch]` form, is in the top-level README in `sandbox-mint`).

## Keys

ESP does not use one key per denomination. Every combination of amount and terms has its own signing key, so a note's terms are bound into its signature and editing them breaks it. There are too many combinations to store, so the key is derived on demand from one master secret:

```
key = SHA-256("esp-mint/key/v1" || master || amount || service || redeemable_after_day || counter)
```

- `master` is 32 bytes, `amount` and `redeemable_after_day` are 8 bytes big-endian, `service` is 32 bytes, and `counter` is one byte starting at 0.
- If the hash is not a valid secp256k1 secret key, the counter goes up by one and the hash is taken again. This has a negligible chance of happening.
- The tests include known answers computed with an independent Python implementation.
- The mint returns the matching public key with each signature, because the wallet needs it to unblind.

The master secret is a file of 64 hex characters, `master_secret.hex`, with `0600` permissions. It is generated the first time it is needed and never overwritten. If the file exists but is damaged, that is an error and not a reason to make a new one. If it is lost, every ESP note already issued becomes unredeemable. Protecting it is listed under "Left to do".

## Units and amounts

| | Worth |
|---|---|
| 1 PSP | 0.10 USD (10 PSP = 1 USD) |
| 1 ESP unit | 10^-12 USD |
| 1 FSP unit | 10^-12 USD |

- 1 PSP = 10^11 ESP, so 10 PSP = $1 = 10^12 ESP. ESP to FSP is 1:1, so an FSP mint uses the same unit.
- **Why ten PSP to the dollar, and not a thousand.** A finer PSP unit gives more precision, but the PSP purchase is paid with a Bitcoin transaction whose OP_RETURN carries one 41-byte entry (an 8-byte amount and a 33-byte point) for every PSP note the wallet asks for, and that space is limited and is not raised. A purchase is split into powers of two, so each factor of 2 in the unit adds about one more possible output. Going from 1 PSP to the dollar to 10 adds about 3.3 denominations (a worst case of 4 more outputs, 164 bytes); going to 1000 would add about 10 (a worst case of 10 more, 410 bytes), about three times the added payload for precision the purchase does not need. Ten to the dollar keeps the precision at a small cost. The top PSP denomination went up by 16 to 2^24 (25 keys instead of 21), which covers the same dollar range. The rate is `ESP_PER_PSP` in `src/units.rs`.
- Amounts are `u64`, so one note is worth at most about 1.8e19 units, which is about $18.4 million (184,467,440 PSP when converted to ESP).
- A request can hold many notes. Every sum, and every PSP-to-ESP conversion (PSP units times 10^11), is computed in `u128` or with checked arithmetic, so an overflow is an error and never wraps.
- The constants and helpers are in `src/units.rs`, with tests at the limits: the largest PSP that fits one note, one PSP over it, `u64::MAX` sums, and totals that exceed one note.

## The exchange

Built.

1. The wallet sends PSP notes and blinded outputs to the ESP mint, along with the service ID it wants. It does not send a date. The outputs can have any non-zero amount, and a request holds at most 1000 notes and 1000 outputs. The smallest exchange is 1 PSP ($0.10, 10^11 ESP) by default (`exchange.min_psp`).
2. The PSP notes, times 10^11, must equal the total of the ESP outputs exactly, or the request is refused before anything is burned. See "Exact amounts and the minimum". The mint charges no exchange fee. The request is an AIR message, and its cost is paid in AIR currency and charged by AIR messaging, not by this mint.
3. The mint checks everything it can before it burns: no other unfinished request holds any of the PSP notes or output blind nonces (see "Reservation" below), the output blind nonces are unused, the PSP notes are unspent at the PSP (`/burns`), and every note's spend signature verifies over the memo below. The spend signatures are public to check, and they cover the memo, so only the holder of the notes can authorize this request.
4. The ESP mint calls the PSP's `/melt` with the notes. The memo is the hex of `SHA-256("esp-mint/exchange/v1" || service || each output's amount and blind nonce)`, and the wallet's spend signatures cover that memo. The burn is bound to this one request. The PSP keeps the memo of every burn (see "Burn memos" below). The mint checks that the PSP burned exactly the amount it expected.
5. If the burn succeeds, the ESP mint derives the keys for the terms and issues each output with `MintLogic::issue_with_key`. It uses that method and not `issue` because the key depends on the note's terms as well as its amount. See the docs on `MintLogic::issue_with_key` in mint-core.
6. It returns the service, the redeemable-after day, one blind signature per output in the request's order, and the public key each was signed with (the wallet needs it to unblind).

**Retries.** Responses are stored by request hash, `SHA-256("esp-mint/exchange-request/v2" || memo || length || the PSP inputs as JSON || keysets)`, where *keysets* is the number of PSP input keysets, each `psp_input_keysets` entry with its length, then the output `keyset` with its length (8-byte big-endian lengths). The hash covers the inputs, spend signatures included, and every keyset field, so a request with different inputs never gets another request's response. The stored state has two steps:

- `pending` is written after the checks in step 3 and before the burn. It fixes the redeemable-after day, so a retry on a later day still gets the original terms. It also lists the nonces of the PSP notes and the output blind nonces (hex), which reserves them (see "Reservation" below).
- `done` is written after the signatures are made and holds the response.

A retry of a done request returns the stored response and burns nothing. A retry of a pending request carries on: if the PSP notes are all spent it skips the burn (the earlier attempt burned them and its reply was lost), and outputs that were already issued are signed again, which gives the same signature because signing is deterministic. If only some of the PSP notes are spent, it stops with an internal error for a person to look at. The skip is taken only for notes the PSP says were burned under this request's memo (see "Burn memos"). A request that failed because the PSP could not be reached leaves a `pending` entry that holds its notes until the retry finishes it. The retry checks the PSP again.

**Reservation.** Until an exchange is done, no other request can use a PSP note or an output blind nonce its pending entry names. A second exchange that names any of them, with a different request hash, is refused with `400` ("held by another request that is not finished") before anything is burned, whether the first is waiting for the PSP, has burned and stopped, or has issued some outputs. A transfer whose outputs would reuse a held blind nonce is refused in the same way, and an exchange is refused if an unfinished transfer holds one of its output blind nonces. A retry of the same request is not blocked by its own entry. Once the first is done, a second exchange of the same PSP notes is refused because the notes are spent. This is what makes the skip above safe: while a request is pending, a PSP note that is spent was burned by that request. Without it, a holder who signed two different exchanges of the same notes could have the second burn them after a crash before the first one's burn, and the first one's retry would then take the notes as burned by itself and issue its outputs as well, so one set of PSP notes would pay for two sets of ESP. The tests cover two different exchanges of the same notes, one note shared out of several, a shared output blind nonce, and a crash between the burn and the signing (with a restart in the middle).

An entry written before the reservation existed has no lists and holds nothing. It still reads, and finishes as before.

**Burn memos.** The reservation stops other requests to this mint from taking a pending exchange's PSP notes. It cannot stop the holder spending those notes somewhere else at the PSP (PSP notes are bearer notes) in the gap between the pending entry and the burn. So the PSP keeps the memo each note was burned under (`POST /burns`, see the psp-mint README), and a retry checks it:

- On a retry of a pending exchange, the mint asks the PSP about the PSP notes. If none is spent, it burns. If all are spent and each one's memo is this request's memo, it was burned by this exchange, so the mint skips the burn and issues.
- If any note is spent under a different memo, or with no memo on record, the exchange fails with `NoteSpentElsewhere` (`400`: "a PSP note was spent by a different request, not by this exchange, so this exchange cannot go ahead. Nothing was issued"). Nothing is signed. The pending entry stays, so a retry gets the same answer, and its output blind nonces stay held.
- If some notes are spent under this memo and some are not, it is still an internal error for a person to look at. The PSP burns all of a request's notes together, so this is not expected.
- The memo is the burn's label, not the request hash. The wallet's spend signatures cover the memo, and the request hash covers the spend signatures, so the hash cannot be the memo. The memo is a hash of the service and the outputs. Two requests with the same memo have the same service and the same output blind nonces, and the reservation keeps both from being live at once, so a note burned under this memo was burned for this exchange.
- A pending exchange from before the PSP kept memos, whose notes were already burned, would fail with `NoteSpentElsewhere` on retry, since there is no memo on record. Upgrade with no pending exchanges.
- The `400` body carries `"code": "note_spent_elsewhere"` and `"spent": [positions]`, the positions in `psp_inputs` of the notes that were spent elsewhere (`Rejection::NoteSpentElsewhere { spent }`). The wallet uses them to mark exactly those notes as spent, not to hand them back as spendable (see the ecash-wallet README). Notes of the request that are not spent are freed. Check the PSP's records for who burned the others.

The tests cover a retry after the mint's own burn (it issues without burning again), a note burned under another memo, a note spent with no memo on record, one note of several burned elsewhere, and both cases over HTTP.

**The issued total (fixed in mint-core v0.1.3).** Before v0.1.3, mint-core's `issue_with_key` marked the output's blind nonce used and then added its amount to the issued total as two separate writes. A crash in the window between them left the total permanently short by that output: a retry saw the nonce already used, treated the output as issued, and signed it again without adding to the total, so nothing ever added the missing amount. From v0.1.3 the mark and the total are one sled transaction, so a crash leaves both or neither, and the retry's "already used, so already counted" is true. The same holds for the transfer, the redemption refunds and a rollover. The fix stops new drift. It does not repair a total that was already short before the upgrade. sled is a stand-in for the storage the mint will have in the AIR, and that storage must keep the same rule as mint-core v0.1.3: marking an output's blind nonce used and adding its amount to the issued total are one atomic step.

**Wallet.** `ecash-wallet exchange --service <x-only hex> --psp N` builds this request, sends it to `/exchange` and unblinds the reply into ESP notes (see the ecash-wallet README). The wallet picks PSP notes worth at least N and asks for all of their value, so the request is always exact: N PSP of ESP, plus any difference as extra ESP notes under the same terms (change). It saves the request, the blinding factors and the new spend keys before sending, so after a timeout `exchange --resume <id>` sends the same request again and gets the stored response. A `400` means nothing was burned and the wallet frees its PSP notes. Each ESP note is stored with its spend key, its amount and its terms (service and redeemable-after day).

## Wire format and versions

The request and response bodies, the terms, the canonical redeem encoding, the request hashes, the unit constants and the error codes are defined in the `sp-wire` crate, not here. `esp-mint` re-exports them (`esp_mint::exchange::ExchangeRequest`, `esp_mint::redeem::RedeemRequest`, `esp_mint::queue::Status`, `esp_mint::rotation::RolloverRequest`, `esp_mint::terms::Terms`, `esp_mint::units::*`, and so on), so the paths did not change. The PSP and FSP mints and the wallet build against the same crate, so they cannot drift from this mint by a byte. What stays here is everything that is the mint's own: storage, the queue, fees, validation, settlement and config. The key-set ID derivation `rotation::keyset_id` stays too, because it needs the master secret.

`GET /health` returns `wire_version`, the crate's `WIRE_VERSION` (1 to start). **Changing any encoded byte or JSON field in `sp-wire` means bumping `WIRE_VERSION`**, and a wallet refuses a mint that reports another number. Golden-bytes and size tests in `sp-wire` fail if a byte moves. Nothing was changed on the wire by moving the types: the golden values were captured from this mint before the move, and `sp-wire` reproduces them.

## HTTP API

`esp-mint serve` runs the API. Its settings are in "Settings" below (`esp-mint.toml` and environment variables).

| Route | What it does |
|---|---|
| `POST /exchange` | Body: `{"service": "<x-only hex>", "psp_inputs": [...], "outputs": [...]}`. `200` with the response above. `400` if the request is refused, with `{"error": ...}`, `413` if the body is over `exchange.max_request_bytes`, and also `"code": "note_spent_elsewhere"` and `"spent": [...]` when PSP notes in the request were spent by a different request (see "Burn memos"). `502` if the PSP could not be reached or refused the burn. `500` for a fault in the mint. A retry is safe after a `502` or `500`. |
| `POST /transfer` | Body: `{"service": "<x-only hex>", "redeemable_after_day": N, "inputs": [...], "outputs": [...], "service_signature": "<hex>"}`. `200` with the response (same shape as the exchange's). `400` if the request is refused, with `{"error": ...}` (nothing was burned; an input that is already spent also carries `"code": "note_spent_elsewhere"` and `"spent": [position]`), `413` if the body is over `transfer.max_request_bytes`. `500` for a fault in the mint, and a retry is safe. See "Transfer to the service". |
| `POST /redeem` | Body: the redemption request in its binary encoding (see "Redemption"). `200` with the answer, `400` if refused (nothing burned; `code` says why), `413` over the ceiling, `500` for a fault. |
| `POST /rollover` | Body: the rollover request (one service and day, `input_keysets`, `keyset`, inputs, outputs). `200` with the new signatures, `400` if refused (nothing burned; `code`: `keyset_not_current`, `keyset_retired`, `unknown_keyset`, `missing_keyset`, `burn_not_proven`, or `note_spent_elsewhere` with `spent`: the positions of the inputs that are spent). See "Key rotation". |
| `GET /keysets` | `{current, previous}` keyset IDs. On every mint, rotating or not. |
| `GET /rotation` | Whether rotation is on, the first-issue time, and the current and previous keysets with their start and retirement times. |
| `GET /fees` | The fee rates, size formulas and ceilings now in force. |
| `GET /audit` | `issued`, `redeemed`, `outstanding`, in ESP units. |
| `GET /health` | `200` while the locks are sound, `503` otherwise. The body has `status`, `network` and `wire_version` (an integer: the version of the wire format this mint speaks; a wallet refuses a mint whose number is not its own). |

The process exits with status 1 if a lock is poisoned, so a supervisor can restart it. One request runs at a time, holding the mint and the stored responses (and waiting on the PSP) until it is done, which is fine for development and not a design for load. There is no authentication and no TLS: a note authorizes its own spend, so a caller can only burn notes they hold. Bind to localhost. Only one process can open the mint's database.

## Transfer to the service

Built.

An app that pays a service with ESP hands the service the notes, and with them each note's spend secret. The app cannot spend those notes itself, because transfer and redeem both need the service's signature. The risk is that the same note is presented twice, to the same service or to different ones, so a note the service was handed may already have been used. When it accepts ESP notes, the service asks the ESP mint to swap them for fresh notes that only the service controls, with the same terms. A note can be swapped only once, so a second presentation fails. This also covers the design doc's step of checking that the points have not been spent, so there is no separate verify call.

- **Request.** `POST /transfer` takes the service (x-only), the redeemable-after day, the ESP inputs, the blinded outputs the service chose, and the service's signature. One request covers one set of terms, and a request holds at most 1000 inputs and 1000 outputs.
- **Digest.** `SHA-256("esp-mint/transfer/v1" || service || redeemable_after_day || input count || each input's amount and nonce || output count || each output's amount and blind nonce)`. The terms are 40 bytes (the service, then the day, big-endian). Every input is signed over the digest by the note's own nonce key, which the service now holds, and the service signs it with its key (Schnorr, x-only, the key named in the terms). The spend signatures are not part of the digest.
- **Only the named service.** The service signature is checked first. Each input is then checked against the key the mint derives for its amount and for the request's terms, so a note named for another service, or for another day, does not verify (`BadNote`). The outputs are signed under the same terms, so the new notes name the same service and the same day. An app cannot move ESP to another service or to a peer: nothing it can sign changes whose key must sign the request.
- **Exact.** The inputs and the outputs must have the same total, summed in `u128`, or the request is refused before anything is burned, with an error that says whether it is over or short and by how much. Zero amounts, repeated inputs and repeated output blind nonces are refused. There is no minimum.
- **No fee.** The request is an AIR message, and the AIR send fee covers it. The mint charges nothing.
- **Result.** The inputs are burned with `MintLogic::redeem_with_key` and the outputs are signed with `MintLogic::issue_with_key`. The inputs count as redeemed and the outputs as issued, by the same amount, so `/audit` shows both rising together and `outstanding` unchanged. Nothing is burned out of circulation and no value is created.
- **Double presentation.** The service issues FSP only after its transfer succeeds, one FSP unit for each ESP unit. If the note was already presented, the transfer fails with `AlreadySpent` and no FSP is issued.

**Order of events.**

1. Check the shape of the request and the totals. Nothing is written.
2. A stored finished response for this request hash is returned as it is.
3. Check the service signature, then each input (genuine under its derived key, spend signature over the digest, not spent), and that no output blind nonce is used. Refuse if any input or output blind nonce is held by another unfinished transfer (`NoteHeld`).
4. Write a `pending` entry that lists the input nonces and the output blind nonces.
5. Burn the inputs, sign the outputs, and write the `done` entry.

**Retries and crashes.** Responses are stored by request hash, `SHA-256("esp-mint/transfer-request/v2" || digest || service signature || each input's spend signature || keysets)`, with *keysets* encoded as for the exchange (every `input_keysets` entry and the output `keyset`, each length-prefixed, so two requests that differ only in a keyset never share a hash), in `responses.json` next to the exchange's entries (the tags keep the two apart). A retry of a done request returns the stored response and changes nothing. A retry of a pending request carries on: an input that is already spent is skipped, and an output that was already issued is signed again, which gives the same signature because signing is deterministic.

The pending entry also keeps other requests away, as the exchange's does (see "Reservation" under "The exchange"). Until a transfer is done, no other request can use a note or an output blind nonce it names. So an input that is spent while a transfer of it is pending was spent by that transfer, and a retry can skip it safely. Without this, a second request for the same note, made between a crash and the retry, could burn the note and leave the first request to issue outputs for a note it did not burn. Redemption, when it is built, must check for held notes in the same way.

The issued total is exact across a crash from mint-core v0.1.3 on (see "The issued total" under "The exchange"). Before it, a crash between the nonce mark and the total left the total permanently short.

**Wallet.** The app side is `hand-over` and the service side is `receive` and `transfer` (see the ecash-wallet README). The app hands over whole notes that add up to the amount, because it cannot split an ESP note. The service takes them in, builds the request with fresh blinded outputs and sends it to `/transfer`. Handing the notes to the service is an AIR message, which is deferred. For now it is a file.

## Redemption

Built. `POST /redeem` on the public listener; the payout queue and the operator's routes are on the loopback admin listener.

Only the owner of a service's DID key may redeem ESP for that service. The service ID in a note's terms is that DID public key (x-only). Holders cannot cash out at the mint: they spend or transfer their notes to the service (see "Transfer to the service"), and the service redeems.

### The request and its encoding

The body of `POST /redeem` is one binary encoding, not JSON, so that its length is exactly the size the fee is charged on and the ceiling can be enforced before anything is parsed. The same bytes, minus the signatures, are what the signatures cover, and the same bytes are what the request hash covers. All integers are big-endian.

| Field | Bytes | What it is |
|---|---|---|
| version | 1 | `2`. Version 1 (no keysets) is refused with a message saying so; any other value is refused. |
| service | 32 | The service's x-only DID key. |
| output keyset | 8 | The keyset the decline and refund outputs ask to be signed by. |
| input count | 4 | |
| each input | **186** | claimed service 32, claimed redeemable-after day 8, keyset 8 (the set that signed the note), amount 8, note nonce 33, note signature 33, spend signature 64 |
| memo length | 2 | At most `redeem.max_memo_bytes` (256), not empty. |
| memo | 0 to 256 | The payout destination, UTF-8. |
| decline output count | 4 | |
| each decline output | **81** | service 32, redeemable-after day 8, amount 8, blind nonce 33 |
| refund output count | 4 | |
| each refund output | **81** | same shape |
| service signature | 64 | Schnorr, by the service's DID key. |

So the **size** is `119 + 186 × notes + memo bytes + 81 × (decline outputs + refund outputs)`. Every field is fixed size except the memo (at most 256 bytes) and, on the operator's decline, the reason (at most 1024 bytes, UTF-8). There are no other free-form fields. Decoding is strict: the length must match exactly, keys must be valid points, counts are checked against the bytes that remain before anything is allocated, and an unknown version, a trailing byte or a bad memo is refused as `malformed_request`.

- **Each input is tagged** with the service and the redeemable-after day it claims. The mint checks the note against the key it derives for that amount and that tag. A tag naming another service is `WrongService`; a tag that does not match the note is `BadProof`. The tags are part of the request hash.
- **Digest and hash.** The digest every signature covers is `SHA-256("esp-mint/redeem/v2" || the encoding without the spend signatures and the service signature)`. Each input is signed over it by the note's own nonce key, and the service signs it with its DID key. The request hash, which is the key everything is stored under, is `SHA-256("esp-mint/redeem-request/v2" || the whole encoding)`.
- **Measured sizes.** One input is 186 bytes and one output is 81 (the keysets add 8 bytes per input and 8 for the output keyset). With one output per note that is 267 bytes a note, so the briefing's example of 10,000 users with about 22 power-of-two notes each (220,000 notes) is about 58.7 MB (56.0 MiB), under the 64 MiB (67,108,864 byte) ceiling. If the service asks for one decline output per date rather than per note, which is what the wallet does by default, the inputs dominate: 220,000 × 186 is about 40.9 MB. The ceiling would fit about 360,800 notes with a 40-byte memo and no outputs. The estimate of 50 to 60 MB is therefore right for one output per note and high for the usual one output per date. In practice small payments happen in FSP, so a redemption carries a few large notes per user, far fewer than 22.

### The fee

**Fee = `redeem.fee_per_byte` × the canonical encoded size of the whole request**: every note, accepted or rejected, both output lists and the memo. There is no flat fee and no per-note fee. The size is measured on the one encoding the request hash covers, so the service computes the fee before it sends. The rate is a setting; the placeholder is **10^6 ESP units a byte** (10^12 ESP units is 1 PSP, about $1, so that is $0.000001 a byte or $1 a MiB). Worked examples:

| Request | Size | Fee (ESP units) | Fee (USD) |
|---|---|---|---|
| 5 notes, 1 decline output, 40-byte memo | 119 + 930 + 40 + 81 = 1,170 bytes | 1,170,000,000 | $0.001170 |
| 1 note, no outputs, 40-byte memo | 345 bytes | 345,000,000 | $0.000345 |
| a 64 MiB request (the ceiling) | 67,108,864 bytes | 67,108,864,000,000 | about $67.11 |

**Why this rate.** 10^6 ESP units a byte (about $1 a MiB) is the current setting. It is charged per byte because what spam costs the mint grows with the size of a request, while a typical request of a few notes is about a kilobyte and pays about a tenth of a cent. The rate is expected to come down once there is real usage data. For example, a request with 3 notes, 3 outputs and a 15-byte memo is 935 bytes and pays 935,000,000 ESP units, about $0.0009.

The fee is never returned. A request is charged at the rate in force when it is accepted, and that rate is stored on the reply and on the queue entry (`fee_per_byte`, `fee_esp`, `size_bytes`).

### The ceiling

A request body over `redeem.max_request_bytes` (64 MiB) is refused with `413` and `code: request_too_large` **before it is parsed or its signature checked**: no burn, no fee. A body that declares its length is refused without reading any of it; one that does not is read only as far as the ceiling. It is 64 MiB because a service with hundreds of thousands of notes still fits in one request, and because the mint holds a request in memory while it checks it, so some ceiling has to exist; the setting is there to move it. There is no cap on the number of notes, outputs or dates: the ceiling is the only limit. A service with more than fits **splits** the redemption into several requests: each pays its own per-byte fee, is stored under its own request hash, and gets its own queue entry (the payout report groups entries by service). Splitting is the wallet's job (see the ecash-wallet README).

### What the mint does

1. **Size**, then **shape**: at least one note, no zero amount, a memo that is not empty and fits, no output blind nonce twice, version and lengths right. Anything else is `malformed_request`.
2. A stored reply for this request hash is returned as it is (see "Crash safety").
3. **Signature first.** The service's signature over the digest is checked before anything that touches the mint. If it fails, the request is refused (`bad_service_signature`). Nothing is burned and no fee is charged, because nobody authorized it.
4. **Each note is decided on its own.** It is accepted if all of these hold, and otherwise rejected with the first reason that applies, in this order: its tagged service is the key that signed (`WrongService`); its signature is genuine under the key derived for its amount and tag, and its spend signature verifies (`BadProof`); it is not spent, not listed twice and not held by another unfinished request (`AlreadySpent`); its redeemable-after day has come by the mint's clock (`Immature`). Mixed dates are allowed in one request.
5. **Value.** Let V be the total of the notes that are genuine and unspent, accepted or not (summed in `u128`), A the accepted total and R the rest, so V = A + R. Spent and forged notes count for nothing.
6. **Fee check.** If V is below the fee, the request is refused (`below_fee`, with `value_esp`, `fee_esp` and `notes`: what the mint made of each input, in the request's order, with the reason for each one it did not accept), nothing is burned and no fee is charged. The per-note list lets a wallet stop offering notes the mint calls spent (`already_spent`) or forged (`bad_proof`). It is an additive field: a caller that ignores it sees the old body.
7. **How the fee is taken.** If A is at least the fee, it comes out of the payout and the rejected notes are not touched. If A is less than the fee, the whole of A goes to the fee and the shortfall comes out of the genuine rejected notes: the mint burns them and reissues `refund_outputs`, which may total at most R minus the shortfall, and for each service and date at most the rejected notes with those terms. If R is more than the shortfall the refunds are required (`refund_required`, with the totals).
8. **Output limits, before any burn.** `decline_outputs` may total at most A minus the fee, and for each service and date at most the accepted notes with those terms; `refund_outputs` must be empty when A covers the fee. If either list breaks its limits the **whole request is refused before anything is burned** (`outputs_over_limit`), and the refusal reports the accepted total per service and date (`totals`), so the wallet can rebuild. By default the wallet builds decline outputs from the notes it already knows are mature and named for the service, and takes the fee from the date holding the most value.
9. **Nothing owed.** If A is at most the fee, no queue entry is made. The stored reply says "nothing owed, fee taken", and a retry returns it.
10. **Otherwise** the mint burns the accepted notes and adds one queue entry for A minus the fee, holding the amount, the memo, the service, the rate and fee, and the `decline_outputs`.

### Every refusal and rejection

| Where | Code / reason | Meaning | Burned? Fee? |
|---|---|---|---|
| HTTP, `413` | `request_too_large` | Body over `redeem.max_request_bytes`. Not read or parsed. | No, no |
| `400` | `malformed_request` | Not a valid encoding (version, length, key, counts, memo not UTF-8). | No, no |
| `400` | `no_inputs`, `zero_amount`, `memo_invalid`, `duplicate_blind_nonce`, `blind_nonce_already_used` | Shape and field limits. | No, no |
| `400` | `bad_service_signature` | The service did not sign this. | No, no |
| `400` | `note_held` | An output blind nonce is held by another unfinished request. | No, no |
| `400` | `below_fee` | V is less than the fee. `notes` says why each rejected input was. | No, no |
| `400` | `outputs_over_limit` | A list is over its limits; `totals` says what it may be. | No, no |
| `400` | `refund_required` | Accepted notes do not cover the fee and the rest is worth more than the shortfall; `totals` says what to refund. | No, no |
| per note | `WrongService`, `BadProof`, `AlreadySpent`, `Immature` | The note is rejected, others go on. | Not burned (unless taken for a shortfall) |
| `500` | | A fault in the mint. A retry is safe. | |

### Declined and paid

The mint pays out by hand in BTC, USD or another agreed method, then marks the entry completed with a payment reference (`esp-mint pay`). The USD value of an amount is the amount divided by 10^12. Before paying, the mint checks that the service met its terms. This is manual for now, because uptime cannot be checked by a machine yet. If a payout fails, the entry stays open and is retried. Notes are never reissued because of a failed payout.

If the terms were not met, the operator declines: `esp-mint decline <entry id> --reason TEXT` (or `POST /payouts/decline` on the admin listener, `{"entry_id", "reason"}`). The mint signs the stored decline outputs, marks the entry declined, and stores the signatures and the reason (at most `redeem.max_reason_bytes`, 1024) on the entry. The service **resends the same request** (same hash), and the reply carries the entry's status: **open**, **completed** with the payment reference, or **declined** with the reason and the signatures. Each output keeps its original service and date; there is no reset. The fee is not returned.

**This is a development stand-in.** Delivery of the decline over a request-and-reply is temporary; it will be replaced by delivery over the AIR. The decline outputs' blind nonces stay reserved while the entry is open, and for good after it, so that nothing else can be issued on them.

### Crash safety and reservations

The decision is made once and written into a `redeem_pending` entry under the request hash before anything is burned. The entry names the notes it burns and the blind nonces of every output it may sign, and it holds the decision itself (which notes were accepted and why not, the fee, its rate and size, what is owed), so a retry after a crash does exactly the same thing: it skips the notes already burned, signs again any refund already issued (signing is deterministic), and adds the queue entry if it is missing without adding a second. A retry after the reply is stored returns the stored reply. Other requests are kept away like exchange and transfer: while a redemption is unfinished, its notes look spent to another redemption (`AlreadySpent`) and an exchange or transfer cannot use them, and its output blind nonces are held against every route.

### The payout queue

Entries live in `queue.json`: one per redemption that owes something, with the service, the amount owed, the memo, the fee and rate, and the status (open, completed, declined). `esp-mint payouts` is the report, grouped by service; `esp-mint pay` marks entries completed. See "Payout report".


## Payout report

Redemption entries are paid by hand (see "Redemption"). The report adds up what is owed to each service so the operator pays each one once, and `pay` then records the payment. Both work on the queue file, `queue.json` in the data directory. It is a development placeholder like `responses.json`: one JSON file, rewritten whole on every change. Redemption adds the entries this report reads: an id (the request hash), the service, the amount owed in ESP, the payout memo, the time and a status.

**The report.** `esp-mint payouts` prints it as text and `esp-mint payouts --json` as JSON. For each service with open entries it shows:

- the service ID (its DID public key, x-only hex);
- the total owed in ESP and in USD at 10^12 ESP per $1 (exact, 12 decimal places), summed in `u128`;
- the number of entries, and the dates of the oldest and newest;
- the entry IDs, oldest first;
- the payout memos, each with the entries and the amount under it.

Declined and completed entries are left out. If one service's entries have different payout memos, every memo is shown and the group is flagged `memo_mismatch` (`MEMO MISMATCH` in the text). The mint does not choose between them. The operator decides where to pay and settles each memo's entries on its own. For example, XYZ redeems $10 on day 1 and $5 on day 2 to the same destination, and the report shows one line owing $15.000000000000 for 2 entries.

**Settling.** After paying, run `esp-mint pay <service> <ref> <entry id>...`, with the exact entry IDs from the report and one payment reference (a txid, a wire number). It marks exactly those entries completed with that reference, and nothing else. An entry queued after the report was run is not in the list, so it stays open for the next report. It is all or nothing: nothing changes unless every listed entry exists, belongs to that service and is open, no ID is repeated, the reference is not empty, and the entries share one payout memo. If they have different memos the command refuses and names them; `--mixed-memos` overrides that when one payment really covers them. If the payout itself failed, do not run `pay`, and the entries stay open and are retried. If the file cannot be written, the command fails and the entries stay open.

**HTTP.** The routes are on their own listener (`ESP_ADMIN_BIND`), not on the public API's port:

| Route | What it does |
|---|---|
| `GET /payouts` | The report, as JSON. `?format=text` for plain text. Amounts are decimal strings, because they can pass 2^53. |
| `POST /payouts/pay` | Body `{"service": "<hex>", "payment_ref": "...", "entry_ids": ["..."], "mixed_memos": false}`. `200` with what was paid, `400` if refused (nothing changed), `500` if the file could not be written (the entries stay open). `?format=text` for plain text. |

A body over `admin.max_request_bytes` (1 MiB) is refused with `413` before it is parsed, with the same JSON body as the public routes (`error`, `code: "request_too_large"`, `size_bytes`, `limit_bytes`), even with `?format=text`. Nothing is changed.

Each request reads the queue file afresh, so a change made by `esp-mint pay` shows at once. `payouts` and `pay` on the command line never open the mint's database, so they run while `serve` is up. Two processes settling at the same moment is a race and is not guarded: use one of them at a time.

## Settings and fees

**Network.** esp-mint is on mainnet unless `server.network` (`ESP_NETWORK`) says otherwise; for a regtest PSP run `ESP_NETWORK=regtest cargo run -- serve`. Start the PSP first: the mint will not start without asking it. `/health` returns `{"status": "ok", "network": "...", "wire_version": 1}`. Its data lives in `ESP_DATA_DIR/<network>/` (default `~/.esp-mint/<network>/`). Files from before the split, at the top of `ESP_DATA_DIR`, make `serve` refuse to start with a message; `esp-mint migrate` moves them into `regtest/` (all development so far was regtest), moving nothing if the target holds any of them and deleting nothing. The config file stays at the top. *Why:* keys and spent notes of one network must never be used on another, the same reason psp-mint and the wallet split theirs.


Nothing an operator might tune is a constant in the code. Each setting has a default, can be set in one file, `esp-mint.toml` in the data directory (or the file `ESP_CONFIG` names, which must exist), and can be overridden by an environment variable, which wins over the file. The file is TOML in sections:

```toml
[redeem]
fee_per_byte = 1000000

[exchange]
max_request_bytes = 1048576
fee_per_byte = 0
```

`esp-mint serve` reads the settings at startup, logs every one with its value and where it came from (default, file or environment variable), and refuses to start if any value is not a whole number, is out of range, or is not a setting (a misspelt key is an error, not a silent no-op). All the problems are listed at once. `esp-mint config` prints the same list without starting the mint.

**Reload.** Send the running mint `SIGHUP` (`kill -HUP <pid>`). It reads the file and the environment again, checks them, and swaps them in all at once, or keeps the old values and logs why. Everything marked SIGHUP in the table takes effect for the next request; a request already running finishes with the values it started with. Addresses, the PSP client and the operator listener's body ceiling are read once, so a change to them waits for a restart; the mint says so in its log. Reloading is safe because every request takes the settings once at its start, and every charge is made at the rate in force when the request is accepted.

**The rate in force is stored.** A request is charged at the rate in force when it is accepted. The reply carries `fee_per_byte`, `fee_esp` and `size_bytes`, and the queue entry for a redemption carries the same, so a retry (which returns the stored reply) and an audit see the rate that was charged, whatever the setting is now. A request picked up again after a crash keeps its fee too: it is stored in the pending entry (redemption) or follows from what the request pays over what it asks for (exchange and transfer).

Two things are not settings: `ESP_DATA_DIR` (default `~/.esp-mint`: the config file; and per network, in `<network>/`, the master secret, `db/`, `responses.json` and `queue.json`) and `ESP_ADMIN_TOKEN` (a secret, so never in a file; if set, the operator's routes need `Authorization: Bearer <token>`).

| Setting (`esp-mint.toml`) | Environment variable | Default | Units | Reload | What it affects |
|---|---|---|---|---|---|
| `[server] bind` | `ESP_BIND` | `127.0.0.1:3100` | host:port | restart | The public API's address. |
| `[server] admin_bind` | `ESP_ADMIN_BIND` | `127.0.0.1:3101` | host:port | restart | The operator's listener (payout report, settle, decline). Must be a loopback address. |
| `[server] network` | `ESP_NETWORK` | `main` | network | restart | The Bitcoin network of the PSP: `main`, `regtest`, `signet`, `testnet`. At startup `serve` asks the PSP's `GET /health` and refuses to start if the PSP reports another network, reports none, or cannot be reached. Reported in this mint's `/health`. |
| `[psp] url` | `ESP_PSP_URL` | `http://127.0.0.1:3000` | URL | restart | The PSP mint (`psp-mint serve`) where PSP notes are burned and looked up. |
| `[psp] timeout_secs` | `ESP_PSP_TIMEOUT_SECS` | `30` | seconds | restart | How long a call to the PSP may take before the exchange fails and can be retried. |
| `[terms] maturity_days` | `ESP_MATURITY_DAYS` | `365` | days | SIGHUP | How long after the day of issue a new exchange's ESP notes become redeemable. Fixed into each exchange when it is first accepted; notes already issued keep theirs. |
| `[exchange] max_items` | `ESP_EXCHANGE_MAX_ITEMS` | `1000` | notes | SIGHUP | The most PSP notes, and the most ESP outputs, in one exchange. |
| `[exchange] min_psp` | `ESP_EXCHANGE_MIN_PSP` | `1` | PSP (10 PSP = $1) | SIGHUP | The smallest exchange, in PSP. 1 PSP is $0.10 (10 PSP = $1). Below it the exchange is refused before anything is burned. |
| `[exchange] max_request_bytes` | `ESP_EXCHANGE_MAX_BYTES` | `1048576` | bytes | SIGHUP | The ceiling on one exchange request body (1 MiB). A larger body is refused with 413 before it is parsed: nothing is burned, nothing is charged. |
| `[exchange] fee_per_byte` | `ESP_EXCHANGE_FEE_PER_BYTE` | `0` | ESP units per canonical byte | SIGHUP | The exchange fee rate. 0 means no mint fee. If set, a request pays this times its canonical size (48 + 146 per PSP note + 41 per output bytes), paid in ESP on top of the exact amount, at the rate in force when it is accepted; the rate is stored on the reply. |
| `[transfer] max_items` | `ESP_TRANSFER_MAX_ITEMS` | `1000` | notes | SIGHUP | The most notes, and the most outputs, in one transfer. |
| `[transfer] max_request_bytes` | `ESP_TRANSFER_MAX_BYTES` | `1048576` | bytes | SIGHUP | The ceiling on one transfer request body (1 MiB). A larger body is refused with 413 before it is parsed: nothing is burned, nothing is charged. |
| `[transfer] fee_per_byte` | `ESP_TRANSFER_FEE_PER_BYTE` | `0` | ESP units per canonical byte | SIGHUP | The transfer fee rate. 0 means no mint fee (the AIR send fee covers a transfer). If set, a request pays this times its canonical size (120 + 146 per note + 41 per output bytes), paid in ESP on top of the exact amount, at the rate in force when it is accepted; the rate is stored on the reply. |
| `[redeem] fee_per_byte` | `ESP_REDEEM_FEE_PER_BYTE` | `1000000` | ESP units per encoded byte | SIGHUP | The redemption fee rate. A request pays this times its encoded size, at the rate in force when it is accepted; the rate is stored on the reply and on the queue entry. 10^6 units is $0.000001, so $1 per MiB. Placeholder. |
| `[redeem] max_request_bytes` | `ESP_REDEEM_MAX_BYTES` | `67108864` | bytes | SIGHUP | The ceiling on one encoded redemption request (64 MiB). A larger body is refused with 413 before it is parsed: no burn, no fee. |
| `[redeem] max_memo_bytes` | `ESP_REDEEM_MAX_MEMO_BYTES` | `256` | bytes | SIGHUP | The longest payout memo in a redemption request. |
| `[redeem] max_reason_bytes` | `ESP_REDEEM_MAX_REASON_BYTES` | `1024` | bytes | SIGHUP | The longest reason the operator may give when declining a payout. |
| `[rotation] activation_hours` | `ESP_ROTATION_ACTIVATION_HOURS` | `8760` | whole hours | restart | Hours from the first issue to the first key rotation. **0 turns rotation off.** 0 to 10,000,000. See "Key rotation". |
| `[rotation] period_hours` | `ESP_ROTATION_PERIOD_HOURS` | `87600` | whole hours | restart | Hours between rotations (10 years). 1 to 10,000,000: no policy minimum, but 0 is refused here (it is an off switch only in psp-mint). |
| `[admin] max_request_bytes` | `ESP_ADMIN_MAX_BYTES` | `1048576` | bytes | restart | The ceiling on one request body on the operator's listener (1 MiB). |
| `[queue] max_payment_ref_bytes` | `ESP_QUEUE_MAX_REF_BYTES` | `256` | bytes | SIGHUP | The longest payment reference accepted when an entry is marked paid. |

### Ceilings and the order of checks

Every route that takes a body has a ceiling on its size, set per route and enforced at the HTTP layer before anything is parsed: a body whose `Content-Length` is over it is refused with `413` without reading any of it, and one that does not say is read only up to the ceiling. Nothing is parsed, checked, burned or charged for it. The body of the `413` is `{"code": "request_too_large", "size_bytes": N or null, "limit_bytes": L, "error": ...}`.

| Route | Ceiling (default) | Why |
|---|---|---|
| `POST /redeem` | 64 MiB (`redeem.max_request_bytes`) | A service's whole redemption, up to hundreds of thousands of notes, in one binary body. See "Redemption". |
| `POST /exchange` | 1 MiB (`exchange.max_request_bytes`) | At most `exchange.max_items` (1000) notes and outputs, about 0.5 MB of JSON. |
| `POST /transfer` | 1 MiB (`transfer.max_request_bytes`) | The same shape and size as an exchange. |
| operator routes | 1 MiB (`admin.max_request_bytes`) | Loopback only; small JSON. Same `413` body as the public routes. |

After the size, every route checks in the same order, cheapest first, and nothing is written or burned until all have passed: **size, then shape and field limits** (counts, repeats, zero amounts, lengths), **the amounts** (exactness, fee), **signatures**, **the mint's database** (spent notes, used blind nonces), **reservations** held by other unfinished requests, and last anything that is written or burned. (An answer found in the database is held back until the reservations have been looked at, because a note that is spent may be spent by an unfinished request, and then "held" is the truer answer. The exchange asks the PSP last of all.)

### Fees on the exchange and the transfer

Both default to 0: there is no mint fee, and behavior is as it was. They are 0 because those requests are AIR messages whose cost the AIR charges, and a mint fee on top would charge twice. The setting is there so the operator can set one without a code change. If `exchange.fee_per_byte` or `transfer.fee_per_byte` is set above 0:

- The fee is `rate × canonical size`, in ESP units, where the canonical size depends only on how many notes and outputs the request has: **exchange** `48 + 146 × PSP notes + 41 × outputs` bytes; **transfer** `120 + 146 × notes + 41 × outputs` bytes (a note is its keyset 8, amount 8, nonce 33, note signature 33, spend signature 64; an output is amount 8, blind nonce 33; the fixed parts are the service, the output keyset, the counts, and for a transfer the day and the service signature). The size does not depend on the JSON, so the wallet knows the fee before it picks its output amounts.
- It is paid in ESP on top of the exact amount: the notes must be worth the outputs **plus** the fee, and the request is still checked as exact against that total. An exchange of 1 PSP at 1000 ESP units a byte, one note and one output (235 bytes), has a fee of 235,000 ESP units, so its output is 10^11 − 235,000. The fee comes out of what the wallet asks for, so the wallet never needs a second note to pay it.
- A request that is not exact against that total is refused before anything is burned, with `code: "not_exact"` and the `fee_esp`, `size_bytes`, `fee_per_byte`, `paid_esp`, `outputs_esp` and `required_esp` the wallet needs to rebuild it.
- `GET /fees` returns the rates, ceilings, limits and size formulas now in force for all three routes, so a wallet reads them rather than assuming.

## Exact amounts and the minimum

An exchange is exact. The PSP notes, times 10^11, must equal the total of the ESP outputs, summed in `u128`. If they differ, in either direction, the request is refused before anything is burned, with an error that says whether it is over or short and by how much. The mint keeps no excess and records no credit, and there is no `credit_esp`.

The smallest exchange is 1 PSP (10^11 ESP, $0.10) by default; `exchange.min_psp` sets it. An outputs total below that is refused with its own error. Because PSP notes are whole units, an exact exchange is always a whole number of PSP.

The over and under thresholds (1% under, 10% over) apply to the PSP's BTC purchase only. See the psp-mint README.

A wallet that holds more PSP than it wants to hand a service asks for all of the PSP it spends: the amount for the service, and the rest as extra ESP notes under the same terms (the same service and redeemable-after day). That change is ESP, so it cannot be turned back into PSP. See the ecash-wallet README.

## Key rotation

esp-mint rotates (`ESP_ROTATION_ACTIVATION_HOURS`, `ESP_ROTATION_PERIOD_HOURS`; restart-only) its keys with the same scheme as fsp-mint (see the fsp-mint README, "Key rotation", for the full how and why): `rotation.activation_hours` after the first issue (default 8760; **0 turns rotation off**; the first-issue time written once to the network's data folder), then every `rotation.period_hours` (default **87600**, 10 years, because ESP is held until it matures and then redeemed, not spent daily; whole hours, at least 1, no policy minimum). Unlike psp-mint, esp-mint does not accept `period_hours = 0` as an off switch: use `activation_hours = 0`. At most two key sets and two spent lists, current and previous; the oldest is deleted with its list at each rotation.

How it fits ESP:
- The per-service, per-day keys are derived inside each key set (the epoch's secret takes the place of the one master secret), so a note's terms stay bound into its signature.
- Redemption and transfer accept notes of the current and previous sets. A swap keeps the note's service and day.
- Queue, decline and refund outputs are signed with the current set.
- Generation 0 is the existing `master_secret.hex` and `db/` (existing data unchanged); generation N lives in `gen-N/`, with `first_issue.json`, `retired.json` (totals of deleted generations, for `/audit`) and `rollovers.json` beside them.
- **`GET /keysets`**: public, read-only, on every mint (rotating or not): `{current, previous}` keyset IDs. ESP keys are derived per amount and terms, so they are not listed; each reply's `keys` carry them. Wallets and fsp-mint read `current` to name the keyset their new outputs ask for.
- **`GET /rotation`**: public, read-only, the same shape as fsp-mint's. The wallet uses it to time its staggered swap (the 72-hour cap applies at a ten-year period). `config` also prints it.
- **`POST /rollover`**: swaps notes (one service and day per request) for the same amounts, same service and same day on the current set. Inputs sign a digest of the service, day and transaction; notes held by a pending transfer or redemption are refused. Crash-safe like psp-mint's: recorded before the burn, a retry gets the stored answer or is finished.
- **Exchange inputs name their PSP keyset.** `POST /exchange` takes `psp_input_keysets` (one per PSP note, in order; `400 missing_keyset` otherwise, before anything is burned) and forwards them to psp-mint's `/melt`, which verifies each note by that keyset (a retired or unknown one comes back from the PSP as a `502` with its `keyset_retired` / `unknown_keyset` reason; nothing is burned).
- **ESP's own notes are keyset-addressed.** Transfer (`input_keysets`, `keyset`), rollover (`input_keysets`, `keyset`), exchange (`keyset` for its outputs) and redemption (a keyset per input and an `output keyset` in the binary encoding) name the set that signed each note and the set the outputs should be signed by. Each note is verified only by the set it names, and inputs may be notes of either live set. **New signing uses the current set only:** outputs that name the previous set are refused `400 keyset_not_current` ("…is the previous keyset; new outputs are signed only by the current keyset K. Re-blind the outputs for K and send the request again. Nothing was burned"), and the wallet re-blinds and resends. A missing keyset is `missing_keyset`, a listed one `keyset_retired`, anything else `unknown_keyset`, all before anything is burned. A stored answer is replayed by request hash before any keyset check, so replays are unaffected. Notes are never matched to a keyset by guessing: a note is checked only under the keyset it names. Redemption (keysets in its v2 encoding) and rollover (the whole request) hashes already covered every keyset field. Every signed reply names the keyset that actually signed it (`keyset` on transfer, exchange and rollover answers and on each decline/refund signature set), including a stored answer replayed by request hash, and the wallet unblinds with that set's keys.
- **Queued redemptions (the queue rule).** A redemption's decline and refund outputs are signed later, when the operator decides. The request's output keyset is stored with it. Decline and refund outputs are signed with the current key set (the same "new signing is current-only" rule), whatever the request named, and the stored signatures name the set used. Nothing is lost: the outputs are blinded independently of the key, so any live set can sign them.
- **A request resumed after a rotation** (pending when the mint stopped, then retried after a rotation) is signed by the current set. It may skip inputs of a set that has since retired **only if the stored state proves they were burned under that same request hash**. Two proofs count: the request's own flag (transfers and redemptions set `burned: true` in their pending entry, rollovers add the hash to a `burned` list in `rollovers.json`, after the last burn and before signing), and the **retirement proof**. The burns live in mint-core's spent list, a different store, so they cannot share one atomic write with a flag; instead, when a key set is about to be deleted, the mint reads every note an unfinished request holds (pending transfers and redemptions in `responses.json`, pending rollovers in `rollovers.json`), checks each against the retiring spent list, and saves the spent ones as burn proofs **in the same write as the retired keyset ID**, before anything is deleted (`retired.json`, `burn_proofs`; trimmed at each retirement to notes still held). Since only the request holding a note can burn it, a held note that is spent was burned by its holder. So a crash between the last burn and the flag no longer strands a request. Without either proof (the crash came before the burn) the retry is refused `400 burn_not_proven` (nothing burned, nothing signed).
- **Pending rollovers hold their notes.** A rollover saves the nonces of its inputs (`holds` in `rollovers.json`) with its pending entry, before burning. Another rollover, a transfer or a redemption naming one of them is refused as held until it finishes (before, a crash between recording a rollover and its burn let another request burn the note, and the retry would then have signed for it).
- **Upgrade note.** The exchange and transfer hash tags moved to v2, so an entry left pending by an older version is not found by a retry from a new wallet; finish pending requests before upgrading.
- **`exchange` / `exchange_with`** (one-keyset helpers) exist only under `#[cfg(test)]`; the server and every caller use `exchange_gens`.
- **Retired keyset list (fixed cap, not a setting).** When a rotation deletes a key set, its 8-byte keyset ID is appended to `retired.json`, written and synced *before* anything is deleted (a crash in between leaves the set listed and still on disk; the next start deletes it without listing it twice). A request naming a listed ID gets `keyset_retired` (those notes expired); an ID that is neither live nor listed gets `unknown_keyset` (junk, or never this mint's). That lets the mint tell genuinely expired notes from junk, so a wallet can explain a loss. The list is a cache capped at 1 MB of 8-byte IDs, **131,072 entries**, a constant in code and the same in every mint (`RETIRED_KEYSETS_CAP`); when full, the oldest ID is dropped. That covers hourly rotation for about 15 years, and a yearly mint never comes close; dropping only turns a very old `keyset_retired` answer into `unknown_keyset`. It is deliberately not configurable, an exception to "nothing hard-coded": it is too cheap to be worth tuning. In the file each ID is 16 hex characters, so a full list is about 2.5 to 3.5 MB of JSON on disk (quotes, commas and indentation included).
- **Deletion is crash-safe.** The retiring set's spent list and keys are renamed into `retiring-gen-N/` (keys last) and that folder is removed; a crash leaves the folder and the next start removes it. Stored responses are kept: they are bounded by their own retention and a retry may still need one.
- ESP left untouched for a full cycle (10 to 20 years by default) is lost.
- **The audit counts a rollover as a burn plus a re-issue.** `GET /audit` adds the rolled-over notes to `redeemed` (they are burned) and the new notes to `issued`, so a rollover raises both totals by the same amount and leaves `outstanding` unchanged. After a rotation the two totals are larger than the value ever bought, by the amount rolled over. Read `outstanding`, not either total alone.
- mint-core needs no change: the keyset is chosen in esp-mint before mint-core's primitives are called.

### Spent list

The spent list itself is left as it is (in the sled database). A **redeem deadline** (a date after which a matured note can no longer be redeemed, so that its entry could be dropped) was considered and declined. It is not built and not planned.

## Fees and junk requests

Fees are charged on requests that carry value. A request that carries no value (malformed, unverifiable, or a replay of a spent note) is refused before anything can be charged, so fees do not stop junk requests; the size ceilings and the order of checks (cheap checks first) bound their cost. Per-DID and per-connection rate limits at the AIR layer are a possible further mitigation, not yet explored.

## Left to do

The items every repo shares (all traffic over the AIR except local processes on one machine, the local store and the AIR storage rule, the AIR path dependency, the shared wire format, and the mint-core swap limit) are listed once in the top-level `~/sandbox-mint/README.md`. This list has only this repo's own items.

- **Decline delivery (deferred to the AIR).** A decline is collected by the service sending its request again. That is a development stand-in: it moves to an AIR message to the service's DID. It is on the AIR list with the other deliveries.
- **Payouts are manual**, in BTC, USD or another agreed method, for now.
- **Redemption store (deferred to the AIR).** The queue and the stored responses move into the AIR. Until then they are local files.
- **Terms check.** The mint decides by hand whether a service met its terms. How to check uptime by machine is not designed.
- **ESP denominations.** The exchange accepts any non-zero output amount, and a key is derived for each. Whether amounts should be restricted to a ladder, to limit how much an amount reveals, is not decided.
- **Reload of the admin ceiling and addresses.** `server.bind`, `server.admin_bind`, `psp.url`, `psp.timeout_secs` and `admin.max_request_bytes` need a restart.
- **Splitting ESP.** Only the named service can move ESP, so a holder cannot split a note, and a payment must be a set of whole notes that adds up exactly. Apps should exchange in the sizes they will pay. Whether the mint should offer a holder-side split is not decided.
- **Delivery of the notes to the service (deferred to the AIR).** The hand-over is a file. It will be an AIR message to the service's DID.
- **Hold time.** The API holds the mint lock while it waits on the PSP. A slow PSP blocks every ESP request.
- **Local store.** esp-mint's own state is `db/` (sled), `responses.json`, `queue.json`, `rollovers.json` and the master secret. Only one process can open the mint, so there is one instance and an outage while it restarts, and a live `db/` must not be copied as a backup. The AIR storage that replaces sled must keep the rule from mint-core v0.1.3: marking an output's blind nonce used and adding its amount to the issued total are one atomic step.
- **Master secret protection (deferred to the AIR).** It is a plain file with `0600` permissions. The mint keystore moves into the AIR, and how the secret is protected there is not decided.
- **Placeholders.** `terms.maturity_days` (365) and `redeem.fee_per_byte` (10^6 ESP units a byte, $1 a MiB) are placeholders, now settings.

## Not decided yet

How the service receives the reissued notes when a redemption is declined, and how a declined entry is explained to the service.
