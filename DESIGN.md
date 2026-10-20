# esp-mint: design notes

How esp-mint is built, and why. The README has the build, the settings, the commands and the calls; this file has the reasoning and the behaviour of each call. **Calls are named here by the route they had when they were HTTP (`POST /exchange`, `GET /fees` and so on).** Those routes are gone: wallets send the same bodies over AIR (README, "The AIR listener" and "The calls"), and the status codes below are the mint's own decisions, which travel as a signed refusal or "unavailable". Only `GET /audit`, `GET /health` and the operator's routes are HTTP. The sections were moved here from the README as they were, except where noted in [CHANGELOG.md](CHANGELOG.md).

## Keys

ESP does not use one key per denomination. Every combination of amount and terms has its own signing key, so a note's terms are bound into its signature and editing them breaks it. There are too many combinations to store, so the key is derived on demand from one master secret:

```
key = SHA-256("esp-mint/key/v1" || master || amount || service || redeemable_after_day || counter)
```

- `master` is 32 bytes, `amount` and `redeemable_after_day` are 8 bytes big-endian, `service` is 33 bytes (the service's AIR DID, as in the terms), and `counter` is one byte starting at 0.
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
- **Why ten PSP to the dollar, and not a thousand.** A finer PSP unit gives more precision, but the PSP purchase is paid with a Bitcoin transaction whose OP_RETURN carries one 41-byte entry (an 8-byte amount and a 33-byte point) for every PSP note the wallet asks for, and that space is limited and is not raised. A purchase is split into powers of two, so each factor of 2 in the unit adds about one more possible output. Going from 1 PSP to the dollar to 10 adds about 3.3 denominations (a worst case of 4 more outputs, 164 bytes); going to 1000 would add about 10 (a worst case of 10 more, 410 bytes), about three times the added payload for precision the purchase does not need. Ten to the dollar keeps the precision at a small cost. The rate is `ESP_PER_PSP` in `src/units.rs`.
- **ESP notes are powers of two**, so notes of one size look alike; see "ESP amounts are powers of two".
- Amounts are `u64`, so one note is worth at most about 1.8e19 units, which is about $18.4 million (184,467,440 PSP when converted to ESP).
- A request can hold many notes. Every sum, and every PSP-to-ESP conversion (PSP units times 10^11), is computed in `u128` or with checked arithmetic, so an overflow is an error and never wraps.
- The constants and helpers are in `src/units.rs`, with tests at the limits: the largest PSP that fits one note, one PSP over it, `u64::MAX` sums, and totals that exceed one note.

## The exchange

1. The wallet sends PSP notes and blinded outputs to the ESP mint, along with the service ID it wants (the service's AIR DID: its 33-byte compressed public key, 66 hex characters). It does not send a date. Every output amount must be a power of two (see "ESP amounts are powers of two"), and a request holds at most 1000 notes and 1000 outputs. The smallest exchange is 1 PSP ($0.10, 10^11 ESP) by default (`exchange.min_psp`).
2. The PSP notes, times 10^11, must equal the total of the ESP outputs exactly, or the request is refused before anything is burned. See "Exact amounts and the minimum". The mint charges no exchange fee. The request is an AIR message, and its cost is paid in AIR currency and charged by AIR messaging, not by this mint.
3. The mint checks everything it can before it burns: no other unfinished request holds any of the PSP notes or output blind nonces (see "Reservation" below), the output blind nonces are unused, the PSP notes are unspent at the PSP (`/burns`), and every note's spend signature verifies over the memo below. The spend signatures are public to check, and they cover the memo, so only the holder of the notes can authorize this request.
4. The ESP mint calls the PSP's `/melt` with the notes. The memo is the hex of `SHA-256("esp-mint/exchange/v1" || service || each output's amount and blind nonce)`, and the wallet's spend signatures cover that memo. The burn is bound to this one request. The PSP keeps the memo of every burn (see "Burn memos" below). The mint checks that the PSP burned exactly the amount it expected.
5. If the burn succeeds, the ESP mint derives the keys for the terms and issues each output with `MintLogic::issue_with_key`. It uses that method and not `issue` because the key depends on the note's terms as well as its amount. See the docs on `MintLogic::issue_with_key` in mint-core.
6. It returns the service, the redeemable-after day, one blind signature per output in the request's order, and the public key each was signed with (the wallet needs it to unblind).

**Retries.** Responses are stored by request hash, `SHA-256("esp-mint/exchange-request/v2" || memo || length || the PSP inputs as JSON || keysets)`, where *keysets* is the number of PSP input keysets, each `psp_input_keysets` entry with its length, then the output `keyset` with its length (8-byte big-endian lengths). The hash covers the inputs, spend signatures included, and every keyset field, so a request with different inputs never gets another request's response. The stored state has two steps:

- `pending` is written after the checks in step 3 and before the burn. It fixes the redeemable-after day, so a retry on a later day still gets the original terms. It also lists the nonces of the PSP notes and the output blind nonces (hex), which reserves them (see "Reservation" below).
- `done` is written after the signatures are made and holds the response.

A retry of a done request returns the stored response and burns nothing. A retry of a pending request carries on: if the PSP notes are all spent it skips the burn (the earlier attempt burned them and its reply was lost), and outputs that were already issued are signed again, which gives the same signature because signing is deterministic. If only some of the PSP notes are spent, it stops with an internal error for a person to look at. The skip is taken only for notes the PSP says were burned under this request's memo (see [DESIGN.md](DESIGN.md), "Burn memos"). A request that failed because the PSP could not be reached leaves a `pending` entry that holds its notes until the retry finishes it. The retry checks the PSP again.

**Reservation.** Until an exchange is done, no other request can use a PSP note or an output blind nonce its pending entry names. A second exchange that names any of them, with a different request hash, is refused with `400` ("held by another request that is not finished") before anything is burned, whether the first is waiting for the PSP, has burned and stopped, or has issued some outputs. A transfer whose outputs would reuse a held blind nonce is refused in the same way, and an exchange is refused if an unfinished transfer holds one of its output blind nonces. A retry of the same request is not blocked by its own entry. Once the first is done, a second exchange of the same PSP notes is refused because the notes are spent. This is what makes the skip above safe: while a request is pending, a PSP note that is spent was burned by that request. Without it, a holder who signed two different exchanges of the same notes could have the second burn them after a crash before the first one's burn, and the first one's retry would then take the notes as burned by itself and issue its outputs as well, so one set of PSP notes would pay for two sets of ESP. The tests cover two different exchanges of the same notes, one note shared out of several, a shared output blind nonce, and a crash between the burn and the signing (with a restart in the middle).

**Burn memos.** The reservation stops other requests to this mint from taking a pending exchange's PSP notes. It cannot stop the holder spending those notes somewhere else at the PSP (PSP notes are bearer notes) in the gap between the pending entry and the burn. So the PSP keeps the memo each note was burned under (`POST /burns`, see the psp-mint README), and a retry checks it:

- On a retry of a pending exchange, the mint asks the PSP about the PSP notes. If none is spent, it burns. If all are spent and each one's memo is this request's memo, it was burned by this exchange, so the mint skips the burn and issues.
- If any note is spent under a different memo, or with no memo on record, the exchange fails with `NoteSpentElsewhere` (`400`: "a PSP note was spent by a different request, not by this exchange, so this exchange cannot go ahead. Nothing was issued"). Nothing is signed. The pending entry stays, so a retry gets the same answer, and its output blind nonces stay held.
- If some notes are spent under this memo and some are not, it is still an internal error for a person to look at. The PSP burns all of a request's notes together, so this is not expected.
- The memo is the burn's label, not the request hash. The wallet's spend signatures cover the memo, and the request hash covers the spend signatures, so the hash cannot be the memo. The memo is a hash of the service and the outputs. Two requests with the same memo have the same service and the same output blind nonces, and the reservation keeps both from being live at once, so a note burned under this memo was burned for this exchange.

- The `400` body carries `"code": "note_spent_elsewhere"` and `"spent": [positions]`, the positions in `psp_inputs` of the notes that were spent elsewhere (`Rejection::NoteSpentElsewhere { spent }`). The wallet uses them to mark exactly those notes as spent, not to hand them back as spendable (see the ecash-wallet README). Notes of the request that are not spent are freed. Check the PSP's records for who burned the others.

The tests cover a retry after the mint's own burn (it issues without burning again), a note burned under another memo, a note spent with no memo on record, one note of several burned elsewhere, and both cases over AIR.

**The issued total.** From mint-core v0.1.3 the nonce mark and the total are one sled transaction.  sled is a stand-in for the storage the mint will have in the AIR, and that storage must keep the same rule as mint-core v0.1.3: marking an output's blind nonce used and adding its amount to the issued total are one atomic step.

### Not holding the lock while the PSP is called

The exchange calls the PSP twice (a look at the notes, then the burn) and a PSP can be slow or not answer. The mint's lock (the mint and the stored responses) is not held across either call, so a slow PSP holds up only the request that is waiting on it. A transfer, a redemption, `/audit` and an unrelated exchange go on as usual. The exchange runs in five phases, and the lock is held in three of them:

1. **Check (lock).** Every check there was before, in the same order: shape, stored answer, amounts, spend signatures, the mint's database, the reservations of other requests. Nothing is written.
2. **Look at the notes (no lock).** A new request asks the PSP whether any note is already spent, and is refused `400` if one is. Nothing is written, so a PSP that cannot be asked leaves nothing behind (`502`, and a retry starts clean).
3. **Reserve (lock).** The database and reservation checks are made again, because the lock was let go and another request may have got in, and then the `pending` entry is written: the request hash, the day, the PSP note nonces and the output blind nonces. This is the reservation; it is on file before the PSP is asked to burn anything.
4. **Burn (no lock).** The PSP burns the notes. A retry asks the PSP what became of them first, as in "Burn memos".
5. **Finish (lock).** The entry is checked to be the pending one this request wrote, the outputs are signed, and the `done` entry replaces it. A key set that retired in the meantime does not stop it: the notes may be burned, so it is signed with the current set, as for any pending request.

**Guarantees kept.**

- *No two requests burn the same PSP notes.* The reservation in phase 3 is written under the lock, after the check that nobody else holds the notes, so two different requests for one note are serialized there: the second gets `400` (held by another request) without reaching the PSP.
- *No request is recorded twice.* The entry is keyed by the request hash.
- *Crash-safe by request hash.* A crash after any phase leaves the mint as one of three things: nothing written (before phase 3), a `pending` entry with the notes not burned, or a `pending` entry with the notes burned, and the retry works out which from the PSP's memo of the burn. The unit tests stop after each phase, restart, and retry.

**The same request twice at once.** A request that is `pending` on file is a retry to carry on with, whether it was left by a crash or is being worked on right now. Without the lock held, a second copy that arrives while the first waits at the PSP would be taken for a retry and would call the PSP too. The server keeps the hashes it is working on in memory (`EspState::in_flight`). A copy that arrives while its hash is there is answered `409` with `code: "in_progress"` and is not processed: nothing is burned or written, and the wallet keeps its request and sends it again (it treats any answer other than `400` as "not known", keeps the request pending and offers `--resume`). The set is not storage and nothing of it survives: a restart empties it, which is right, since nothing is running after one and the `pending` entry on file is a crashed request to carry on. The place is given up however the request ends, including a panic, so a failed request leaves no mark.

**A PSP timeout.** The PSP client gives up after `psp.timeout_secs` (30 by default), and the request is answered `502`. Nothing is running, no lock is held, and no mark is left in memory. What is on file depends on where it stopped. A failure in phase 2 left nothing. A failure in phase 4 leaves the `pending` entry, because whether the PSP burned is not known and the entry is how the retry finds out; the retry asks the PSP and either burns or skips the burn. The entry holds the notes against other requests until then, as it did before, and the notes are not stuck: the retry of that request frees them, and a note the holder spent somewhere else in the meantime makes the retry answer `note_spent_elsewhere`, which tells the wallet to mark it spent. An exchange that is never retried keeps holding its notes; that is the cost of not knowing whether the burn happened, and it was so before this change.

**What this does not change.** The lock is still taken for every phase that reads or writes the mint, so everything the mint writes is still written by one request at a time. The checks, their order and their answers are the same. The one new answer is `409 in_progress`; the code is `server::IN_PROGRESS` and is not in `sp-wire` yet.

**Wallet.** `ecash-wallet exchange --service <DID hex> --psp N` builds this request, sends it to `/exchange` and unblinds the reply into ESP notes (see the ecash-wallet README). The wallet picks PSP notes worth at least N and asks for all of their value, so the request is always exact: N PSP of ESP, plus any difference as extra ESP notes under the same terms (change). It saves the request, the blinding factors and the new spend keys before sending, so after a timeout `exchange --resume <id>` sends the same request again and gets the stored response. A `400` means nothing was burned and the wallet frees its PSP notes. Each ESP note is stored with its spend key, its amount and its terms (service and redeemable-after day).

## Wire format and versions

The request and response bodies, the terms, the canonical redeem encoding, the request hashes, the unit constants and the error codes are defined in the `sp-wire` crate, not here. `esp-mint` re-exports them (`esp_mint::exchange::ExchangeRequest`, `esp_mint::redeem::RedeemRequest`, `esp_mint::queue::Status`, `esp_mint::rotation::RolloverRequest`, `esp_mint::terms::Terms`, `esp_mint::units::*`, and so on). The PSP and FSP mints and the wallet build against the same crate, so they cannot drift from this mint by a byte. What stays here is everything that is the mint's own: storage, the queue, fees, validation, settlement and config. The key-set ID derivation `rotation::keyset_id` stays too, because it needs the master secret.

`GET /health` returns `wire_version`, the crate's `WIRE_VERSION`. **Changing any encoded byte or JSON field in `sp-wire` means bumping `WIRE_VERSION`**, and a wallet refuses a mint that reports another number. Golden-bytes and size tests in `sp-wire` fail if a byte moves.

**Wire version 3: the service ID is the 33-byte DID.** Before it, a service was named by its 32-byte x-only key. Now every service in the terms, the exchange, transfer, rollover and redeem requests, the queue and the payout report is the full DID, `sp_wire::ServiceDid` (66 hex characters in JSON and on the command line). What this changes in the mint: the terms are 41 bytes, so **every key the mint derives is different** (the terms are an input of the key derivation, `src/keys.rs`) and a note issued under version 2 does not verify; the transfer and redeem digests and request hashes cover 33-byte services; the redeem encoding is version 3 and its sizes are 120 / 187 / 82; the canonical sizes of an exchange and a transfer (`src/fee.rs`) are one byte larger (49 and 121 fixed); and `queue.json` and `responses.json` written before it do not load, since they hold x-only services. There is no migration and no dual format (nothing was live). A signature is still BIP340, made and checked against the x-only half of the DID (`ServiceDid::x_only`), which is never used as an ID. The parity byte is part of the ID: `02<x>` and `03<x>` are two services that share one x-only key, and a note or request naming one is `WrongService` for a request signed as the other.

## Transfer to the service

An app that pays a service with ESP hands the service the notes, and with them each note's spend secret. The app cannot spend those notes itself, because transfer and redeem both need the service's signature. The risk is that the same note is presented twice, to the same service or to different ones, so a note the service was handed may already have been used. When it accepts ESP notes, the service asks the ESP mint to swap them for fresh notes that only the service controls, with the same terms. A note can be swapped only once, so a second presentation fails. This also covers the design doc's step of checking that the points have not been spent, so there is no separate verify call.

- **Request.** `POST /transfer` takes the service (its 33-byte DID), the redeemable-after day, the ESP inputs, the blinded outputs the service chose, and the service's signature. One request covers one set of terms, and a request holds at most 1000 inputs and 1000 outputs.
- **Digest.** `SHA-256("esp-mint/transfer/v1" || service || redeemable_after_day || input count || each input's amount and nonce || output count || each output's amount and blind nonce)`. The terms are 41 bytes (the service's DID, then the day, big-endian). Every input is signed over the digest by the note's own nonce key, which the service now holds, and the service signs it with its key (Schnorr, checked against the x-only half of the DID named in the terms). The spend signatures are not part of the digest.
- **Only the named service.** The service signature is checked first. Each input is then checked against the key the mint derives for its amount and for the request's terms, so a note named for another service, or for another day, does not verify (`BadNote`). The outputs are signed under the same terms, so the new notes name the same service and the same day. An app cannot move ESP to another service or to a peer: nothing it can sign changes whose key must sign the request.
- **Exact.** The inputs and the outputs must have the same total, summed in `u128`, or the request is refused before anything is burned, with an error that says whether it is over or short and by how much. Zero amounts, amounts that are not a power of two (inputs and outputs both), repeated inputs and repeated output blind nonces are refused. There is no minimum.
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

The pending entry also keeps other requests away, as the exchange's does (see "Reservation" under "The exchange"). Until a transfer is done, no other request can use a note or an output blind nonce it names. So an input that is spent while a transfer of it is pending was spent by that transfer, and a retry can skip it safely. Without this, a second request for the same note, made between a crash and the retry, could burn the note and leave the first request to issue outputs for a note it did not burn.

**Wallet.** The app side is `hand-over` and the service side is `receive` and `transfer` (see the ecash-wallet README). The app hands over whole notes that add up to the amount, because it cannot split an ESP note. The service takes them in, builds the request with fresh blinded outputs (the total split into the fewest powers of two) and sends it to `/transfer`. Handing the notes to the service is an AIR message, which is deferred. For now it is a file.

## Redemption

`POST /redeem` (the redeem call over AIR); the payout queue and the operator's routes are on the loopback admin listener.

Only the owner of a service's DID key may redeem ESP for that service. The service ID in a note's terms is that DID, the full 33-byte compressed key (the parity byte is part of the ID; the x-only half is only what a signature is checked against). Holders cannot cash out at the mint: they spend or transfer their notes to the service (see "Transfer to the service"), and the service redeems.

### The request and its encoding

The body of `POST /redeem` is one binary encoding, not JSON, so that its length is exactly the size the fee is charged on and the ceiling can be enforced before anything is parsed. The same bytes, minus the signatures, are what the signatures cover, and the same bytes are what the request hash covers. All integers are big-endian.

| Field | Bytes | What it is |
|---|---|---|
| version | 1 | `3`. Version 1 (no keysets) and version 2 (services named by their 32-byte x-only key) are refused with a message saying so; any other value is refused. |
| service | 33 | The service's AIR DID (compressed key). |
| output keyset | 8 | The keyset the decline and refund outputs ask to be signed by. |
| input count | 4 | |
| each input | **187** | claimed service 33, claimed redeemable-after day 8, keyset 8 (the set that signed the note), amount 8, note nonce 33, note signature 33, spend signature 64 |
| memo length | 2 | At most `redeem.max_memo_bytes` (256), not empty. |
| memo | 0 to 256 | The payout destination, UTF-8. |
| decline output count | 4 | |
| each decline output | **82** | service 33, redeemable-after day 8, amount 8, blind nonce 33 |
| refund output count | 4 | |
| each refund output | **82** | same shape |
| service signature | 64 | Schnorr, by the service's DID key. |

So the **size** is `120 + 187 × notes + memo bytes + 82 × (decline outputs + refund outputs)`. Every field is fixed size except the memo (at most 256 bytes) and, on the operator's decline, the reason (at most 1024 bytes, UTF-8). There are no other free-form fields. Decoding is strict: the length must match exactly, keys must be valid points, counts are checked against the bytes that remain before anything is allocated, and an unknown version, a trailing byte or a bad memo is refused as `malformed_request`.

- **Each input is tagged** with the service and the redeemable-after day it claims. The mint checks the note against the key it derives for that amount and that tag. A tag naming another service is `WrongService`; a tag that does not match the note is `BadProof`. The tags are part of the request hash.
- **Digest and hash.** The digest every signature covers is `SHA-256("esp-mint/redeem/v2" || the encoding without the spend signatures and the service signature)`. Each input is signed over it by the note's own nonce key, and the service signs it with its DID key. The request hash, which is the key everything is stored under, is `SHA-256("esp-mint/redeem-request/v2" || the whole encoding)`.
- **Measured sizes.** One input is 187 bytes and one output is 82 (the keysets add 8 bytes per input and 8 for the output keyset; each service is its 33-byte DID). With one output per note that is 269 bytes a note, so the briefing's example of 10,000 users with about 22 power-of-two notes each (220,000 notes) is about 59.2 MB (56.4 MiB), over the 15 MiB (15,728,640 byte) ceiling, so the wallet splits it into four requests. If the service asks for one decline output per date rather than per note, which is what the wallet does by default, the inputs dominate: 220,000 × 187 is about 41.1 MB. The ceiling fits about 84,100 notes with a 40-byte memo and no outputs. The estimate of 50 to 60 MB is therefore right for one output per note and high for the usual one output per date. In practice small payments happen in FSP, so a redemption carries a few large notes per user, far fewer than 22.

### The fee

**Fee = `redeem.fee_per_byte` × the canonical encoded size of the whole request**: every note, accepted or rejected, both output lists and the memo. There is no flat fee and no per-note fee. The size is measured on the one encoding the request hash covers, so the service computes the fee before it sends. The rate is a setting and **defaults to 0**: like the exchange and transfer fees, the mint charges nothing until the operator sets a rate (0 to 10^15 ESP units a byte). What a rate should be is not decided here. Worked examples of the size, with a rate of 10^6 ESP units a byte chosen only for the arithmetic:

| Request | Size | Fee at 10^6 units a byte |
|---|---|---|
| 5 notes, 1 decline output, 40-byte memo | 120 + 935 + 40 + 82 = 1,177 bytes | 1,177,000,000 |
| 1 note, no outputs, 40-byte memo | 347 bytes | 347,000,000 |
| a 15 MiB request (the ceiling) | 15,728,640 bytes | 15,728,640,000,000 |

**Why it is per byte.** If a fee is set, it is charged per byte because what a request costs the mint grows with its size, while a typical request of a few notes is about a kilobyte. With the default of 0 a request of any size pays nothing, so the ceiling on one request (`redeem.max_request_bytes`) and the limits on outputs are what bound it.

The fee is never returned. A request is charged at the rate in force when it is accepted, and that rate is stored on the reply and on the queue entry (`fee_per_byte`, `fee_esp`, `size_bytes`).

### The ceiling

A request body over `redeem.max_request_bytes` (15 MiB) is refused with `413` and `code: request_too_large` **before it is parsed or its signature checked**: no burn, no fee. A body that declares its length is refused without reading any of it; one that does not is read only as far as the ceiling. It is 15 MiB because that is the most one AIR message carries (16 MiB, less 1 MiB for the envelope, its seal and AIR's framing; `AIR_MESSAGE_CAP` and `AIR_ROOM` in `redeem.rs`), so every redemption the mint accepts can be sent over AIR, and because the mint holds a request in memory while it checks it, so some ceiling has to exist; the setting is there to move it. There is no cap on the number of notes, outputs or dates: the ceiling is the only limit. A service with more than fits **splits** the redemption into several requests: each pays its own per-byte fee, is stored under its own request hash, and gets its own queue entry (the payout report groups entries by service). Splitting is the wallet's job (see the ecash-wallet README).

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
| `413` | `request_too_large` | Body over `redeem.max_request_bytes`. Not read or parsed. | No, no |
| `400` | `malformed_request` | Not a valid encoding (version, length, key, counts, memo not UTF-8). | No, no |
| `400` | `no_inputs`, `zero_amount`, `memo_invalid`, `duplicate_blind_nonce`, `blind_nonce_already_used` | Shape and field limits. | No, no |
| `400` | `bad_denomination` | A note, a decline output or a refund output is not a power of two. The message names which and its position. | No, no |
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

**What a decline says.** Over the AIR a decline is a plain message to the service's DID: the reason text and the signatures. The reason is free text written by the operator (`--reason`, at most 1024 bytes), and no code or structure is needed because a person reads it. The most common one is that the notes are not mature yet ("these notes are not mature yet; wait until they mature and try again"), after which the service redeems again. That question is closed. The mint adds nothing to explain a decline beyond that text.

**This is a development stand-in.** Delivery of the decline over a request-and-reply is temporary; it will be replaced by delivery over the AIR. The decline outputs' blind nonces stay reserved while the entry is open, and for good after it, so that nothing else can be issued on them.

### Crash safety and reservations

The decision is made once and written into a `redeem_pending` entry under the request hash before anything is burned. The entry names the notes it burns and the blind nonces of every output it may sign, and it holds the decision itself (which notes were accepted and why not, the fee, its rate and size, what is owed), so a retry after a crash does exactly the same thing: it skips the notes already burned, signs again any refund already issued (signing is deterministic), and adds the queue entry if it is missing without adding a second. A retry after the reply is stored returns the stored reply. Other requests are kept away like exchange and transfer: while a redemption is unfinished, its notes look spent to another redemption (`AlreadySpent`) and an exchange or transfer cannot use them, and its output blind nonces are held against every route.

### The payout queue

Entries live in `queue.json`: one per redemption that owes something, with the service, the amount owed, the memo, the fee and rate, and the status (open, completed, declined). `esp-mint payouts` is the report, grouped by service; `esp-mint pay` marks entries completed. See "Payout report".

## Payout report

Redemption entries are paid by hand (see [DESIGN.md](DESIGN.md), "Redemption"). The report adds up what is owed to each service so the operator pays each one once, and `pay` then records the payment. Both work on the queue file, `queue.json` in the data directory. It is a development placeholder like `responses.json`: one JSON file, rewritten whole on every change. Redemption adds the entries this report reads: an id (the request hash), the service, the amount owed in ESP, the payout memo, the time and a status.

**The report.** `esp-mint payouts` prints it as text and `esp-mint payouts --json` as JSON. For each service with open entries it shows:

- the service ID (its 33-byte DID, 66 hex characters);
- the total owed in ESP and in USD at 10^12 ESP per $1 (exact, 12 decimal places), summed in `u128`;
- the number of entries, and the dates of the oldest and newest;
- the entry IDs, oldest first;
- the payout memos, each with the entries and the amount under it.

Declined and completed entries are left out. If one service's entries have different payout memos, every memo is shown and the group is flagged `memo_mismatch` (`MEMO MISMATCH` in the text). The mint does not choose between them. The operator decides where to pay and settles each memo's entries on its own. For example, XYZ redeems $10 on day 1 and $5 on day 2 to the same destination, and the report shows one line owing $15.000000000000 for 2 entries.

**Settling.** After paying, run `esp-mint pay <service> <ref> <entry id>...`, with the exact entry IDs from the report and one payment reference (a txid, a wire number). It marks exactly those entries completed with that reference, and nothing else. An entry queued after the report was run is not in the list, so it stays open for the next report. It is all or nothing: nothing changes unless every listed entry exists, belongs to that service and is open, no ID is repeated, the reference is not empty, and the entries share one payout memo. If they have different memos the command refuses and names them; `--mixed-memos` overrides that when one payment really covers them. If the payout itself failed, do not run `pay`, and the entries stay open and are retried. If the file cannot be written, the command fails and the entries stay open.

**HTTP.** The operator's routes are on their own listener (`ESP_ADMIN_BIND`), not on `server.bind`:

| Route | What it does |
|---|---|
| `GET /payouts` | The report, as JSON. `?format=text` for plain text. Amounts are decimal strings, because they can pass 2^53. |
| `POST /payouts/pay` | Body `{"service": "<hex>", "payment_ref": "...", "entry_ids": ["..."], "mixed_memos": false}`. `200` with what was paid, `400` if refused (nothing changed), `500` if the file could not be written (the entries stay open). `?format=text` for plain text. |

A body over `admin.max_request_bytes` (1 MiB) is refused with `413` before it is parsed, with the same JSON body as the calls (`error`, `code: "request_too_large"`, `size_bytes`, `limit_bytes`), even with `?format=text`. Nothing is changed.

Each request reads the queue file afresh, so a change made by `esp-mint pay` shows at once. `payouts` and `pay` on the command line never open the mint's database, so they run while `serve` is up. Two processes settling at the same moment is a race and is not guarded: use one of them at a time.

### Ceilings and the order of checks

Every call that takes a body has a ceiling on its size, set per call and checked before anything is parsed (`post_served`, and the redeem call, which takes bytes): a body over it is refused with `413` without being read as a request. On the operator's listener the ceiling is enforced at the HTTP layer: a body whose `Content-Length` is over it is refused without reading any of it, and one that does not say is read only up to the ceiling. Nothing is parsed, checked, burned or charged for it. The body of the `413` is `{"code": "request_too_large", "size_bytes": N or null, "limit_bytes": L, "error": ...}`.

| Route | Ceiling (default) | Why |
|---|---|---|
| `POST /redeem` | 15 MiB (`redeem.max_request_bytes`) | A redemption of up to about 84,000 notes (none coming back) in one binary body; the wallet splits a larger one. See "Redemption". |
| `POST /exchange` | 1 MiB (`exchange.max_request_bytes`) | At most `exchange.max_items` (1000) notes and outputs, about 0.5 MB of JSON. |
| `POST /transfer` | 1 MiB (`transfer.max_request_bytes`) | The same shape and size as an exchange. |
| `POST /rollover` | 1 MiB (`rollover.max_request_bytes`) | At most `rollover.max_items` (1000) notes; the same shape as a transfer. |
| operator routes | 1 MiB (`admin.max_request_bytes`) | Loopback only; small JSON. Same `413` body as the calls. |

After the size, every route checks in the same order, cheapest first, and nothing is written or burned until all have passed: **size, then shape and field limits** (counts, repeats, zero amounts, amounts that are not a power of two, lengths), **the amounts** (exactness, fee), **signatures**, **the mint's database** (spent notes, used blind nonces), **reservations** held by other unfinished requests, and last anything that is written or burned. (An answer found in the database is held back until the reservations have been looked at, because a note that is spent may be spent by an unfinished request, and then "held" is the truer answer. The exchange asks the PSP last of all.)

### Fees on the exchange and the transfer

Both default to 0: there is no mint fee, and behavior is as it was. They are 0 because those requests are AIR messages whose cost the AIR charges, and a mint fee on top would charge twice. The setting is there so the operator can set one without a code change. If `exchange.fee_per_byte` or `transfer.fee_per_byte` is set above 0:

- The fee is `rate × canonical size`, in ESP units, where the canonical size depends only on how many notes and outputs the request has: **exchange** `49 + 146 × PSP notes + 41 × outputs` bytes; **transfer** `121 + 146 × notes + 41 × outputs` bytes (a note is its keyset 8, amount 8, nonce 33, note signature 33, spend signature 64; an output is amount 8, blind nonce 33; the fixed parts are the service, the output keyset, the counts, and for a transfer the day and the service signature). The size does not depend on the JSON, so the wallet knows the fee before it picks its output amounts.
- It is paid in ESP on top of the exact amount: the notes must be worth the outputs **plus** the fee, and the request is still checked as exact against that total. An exchange of 1 PSP at 1000 ESP units a byte, one note and one output (235 bytes), has a fee of 235,000 ESP units, so its output is 10^11 − 235,000. The fee comes out of what the wallet asks for, so the wallet never needs a second note to pay it.
- A request that is not exact against that total is refused before anything is burned, with `code: "not_exact"` and the `fee_esp`, `size_bytes`, `fee_per_byte`, `paid_esp`, `outputs_esp` and `required_esp` the wallet needs to rebuild it.
- `GET /fees` returns the rates, ceilings, limits and size formulas now in force for all three routes, so a wallet reads them rather than assuming.

## ESP amounts are powers of two

Every ESP amount the mint signs or accepts is a power of two (1, 2, 4, ... 2^63). Zero is not one. The check is `units::is_denomination`, and the error code is `bad_denomination`, the same as the FSP mint's.

**Why.** A note's amount is public: it is part of the note, and the mint derives a different signing key for each amount and terms. If any amount were allowed, the amount would work as a fingerprint. A service that is handed notes of 83,917,422,011 and 4,101 units could recognise the same notes again wherever it sees them, and tie a transfer to the exchange that made them. When every note is a power of two, notes of the same size look alike, and the total a holder owns is spread over at most 64 sizes instead of being a number that identifies them. The PSP and FSP mints already work this way (a PSP purchase is split into powers of two, and the FSP mint refuses anything else), so this brings ESP in line.

**Every route that signs ESP applies it:**

- **Exchange.** Each output must be a power of two. The PSP notes are PSP-denominated and are not checked here (the PSP mint checks them).
- **Transfer.** Each input and each output.
- **Redemption.** Each input note, and each decline and refund output. The totals of those lists need not be powers of two, only the individual amounts.
- **Rollover.** Not changed: the outputs must have exactly the amounts of the inputs, so it adds no new amount. See below.

**Order.** The check is part of the shape check, before the stored-response lookup, before any signature, database or PSP call, and before anything is burned or charged. A redemption refused for it takes no fee. The messages end "Nothing was burned" (and "no fee was taken" for redemption), the way the PSP and FSP wording does.

**Splitting is the wallet's job.** The mint never splits or merges. The wallet splits an exchange or transfer total into the fewest powers of two (the binary representation of the total, so a total of 7 is 4, 2 and 1), including the change from an exchange. It splits the amount a redemption refunds or declines the same way.

**The fee and the number of outputs depend on each other.** When a fee per byte is set, the fee is the rate times the request's size, and the size depends on how many outputs there are. With any-amount outputs the wallet picked the count and then computed the fee. With powers of two the count of outputs follows from the amount left after the fee, and that amount follows from the count. The wallet resolves this by trying counts upward: for a count n it takes the total less the fee for n outputs, and accepts n if that amount needs at most n notes in binary and is at least n (so it can be split into exactly n notes by halving the largest). When a redemption has several services or days, each one's total is first split into the fewest notes, and the extra notes needed to reach n are cut from the largest note of the days the fee came out of (the wallet takes the fee from the day with the most value first). A day the fee did not touch keeps the fewest notes its amount allows. Only when the days the fee touched have nothing left to halve are the others cut. The smallest such n is used. The fee is paid with the exact amount the mint expects, so a wallet that gets this wrong is told by the mint (`not_exact`, with the numbers needed to rebuild).

**No largest-denomination setting.** A cap such as "no note above 2^40" was optional in the brief and is not built. The largest note is bounded by the `u64` amount (2^63), and a total that large is split into several notes of 2^63 or less. A cap would add a setting and a failure mode, and its only effect would be more, smaller notes. It can be added to the wallet's split without a change to the mint.

**Requests from before this rule.** The shape check runs before the stored-response lookup everywhere except the exchange's finished replay, so:

- A finished exchange is still replayed from its stored response (a wallet that lost the reply can fetch it again).
- An exchange stored as pending with a non-power-of-two output is refused if it is sent again, and a transfer stored with one is refused whether it is pending or done. A refused pending request keeps holding its inputs and output blind nonces. This is a change from the behaviour before, and it should not occur if the mint has no pending exchanges or transfers when it is upgraded, which is already the advice for upgrading (see "Burn memos"). A transfer that was done before the upgrade cannot be fetched again by resending it.
- Rollover is not changed. It requires the outputs to have exactly the amounts of the inputs (see "Key rotation"), so it adds no amount that is not already in a note, and refusing notes from before this rule would strand them.

**Why ESP is not split further for holders.** A holder converts ESP to FSP straight away, and FSP is split by the FSP mint, so a holder does not keep ESP notes long enough for the amounts to matter. Splitting an ESP holding after the exchange is therefore not built. See the ecash-wallet README.

## Exact amounts and the minimum

An exchange is exact. The PSP notes, times 10^11, must equal the total of the ESP outputs, summed in `u128`. If they differ, in either direction, the request is refused before anything is burned, with an error that says whether it is over or short and by how much. The mint keeps no excess and records no credit, and there is no `credit_esp`.

The smallest exchange is 1 PSP (10^11 ESP, $0.10) by default; `exchange.min_psp` sets it. An outputs total below that is refused with its own error. Because PSP notes are whole units, an exact exchange is always a whole number of PSP.

The price tolerance (default 1%) and the reconciliation target (default 10%) apply to the PSP's BTC purchase only. See the psp-mint README.

A wallet that holds more PSP than it wants to hand a service asks for all of the PSP it spends: the amount for the service, and the rest as extra ESP notes under the same terms (the same service and redeemable-after day). That change is ESP, so it cannot be turned back into PSP. See the ecash-wallet README.

## Key rotation

esp-mint rotates (`ESP_ROTATION_ACTIVATION_HOURS`, `ESP_ROTATION_PERIOD_HOURS`; restart-only) its keys with the same scheme as fsp-mint (see [fsp-mint DESIGN.md](../fsp-mint/DESIGN.md), "Key rotation", for the full how and why): `rotation.activation_hours` after the first issue (default 8760; **0 turns rotation off**; the first-issue time written once to the network's data folder), then every `rotation.period_hours` (default **87600**, 10 years, because ESP is held until it matures and then redeemed, not spent daily; whole hours, at least 1, no policy minimum). Unlike psp-mint, esp-mint does not accept `period_hours = 0` as an off switch: use `activation_hours = 0`. At most two key sets and two spent lists, current and previous; the oldest is deleted with its list at each rotation.

How it fits ESP:
- The per-service, per-day keys are derived inside each key set (the epoch's secret takes the place of the one master secret), so a note's terms stay bound into its signature.
- Redemption and transfer accept notes of the current and previous sets. A swap keeps the note's service and day.
- Queue, decline and refund outputs are signed with the set the request named while it is live, and with the current set if that has been deleted by the time the operator decides.
- Generation 0 is the existing `master_secret.hex` and `db/` (existing data unchanged); generation N lives in `gen-N/`, with `first_issue.json`, `retired.json` (totals of deleted generations, for `/audit`) and `rollovers.json` beside them.
- **`GET /keysets`**: public, read-only, on every mint (rotating or not): `{current, previous}` keyset IDs. ESP keys are derived per amount and terms, so they are not listed; each reply's `keys` carry them. Wallets and fsp-mint read `current` to name the keyset their new outputs ask for.
- **`GET /rotation`**: public, read-only, the same shape as fsp-mint's. The wallet uses it to time its staggered swap (the 72-hour cap applies at a ten-year period). `config` also prints it.
- **`POST /rollover`**: swaps notes (one service and day per request) for the same amounts, same service and same day on the keyset the request names (current or previous). Inputs sign a digest of the service, day and transaction; notes held by a pending transfer or redemption are refused. Crash-safe like psp-mint's: recorded before the burn, a retry gets the stored answer or is finished.
- **Exchange inputs name their PSP keyset.** `POST /exchange` takes `psp_input_keysets` (one per PSP note, in order; `400 missing_keyset` otherwise, before anything is burned) and forwards them to psp-mint's `/melt`, which verifies each note by that keyset (a retired or unknown one comes back from the PSP as a `502` with its `keyset_retired` / `unknown_keyset` reason; nothing is burned).
- **ESP's own notes are keyset-addressed.** Transfer (`input_keysets`, `keyset`), rollover (`input_keysets`, `keyset`), exchange (`keyset` for its outputs) and redemption (a keyset per input and an `output keyset` in the binary encoding) name the set that signed each note and the set the outputs should be signed by. Each note is verified only by the set it names, and inputs may be notes of either live set. **New signing uses the live set the request names:** outputs that name the current or the previous set are signed by it, so a request built just before a rotation is signed as asked and does not have to be built again. A missing keyset is `missing_keyset`, a listed one `keyset_retired`, anything else `unknown_keyset`, all before anything is burned. A stored answer is replayed by request hash before any keyset check, so replays are unaffected. Notes are never matched to a keyset by guessing: a note is checked only under the keyset it names. Redemption (keysets in its v2 encoding) and rollover (the whole request) hashes already covered every keyset field. Every signed reply names the keyset that actually signed it (`keyset` on transfer, exchange and rollover answers and on each decline/refund signature set), including a stored answer replayed by request hash, and the wallet unblinds with that set's keys.
- **Queued redemptions (the queue rule).** A redemption's decline and refund outputs are signed later, when the operator decides. The request's output keyset is stored with it. Decline and refund outputs are signed with the set the request named if it is still live when the operator decides, and otherwise with the current key set, and the stored signatures name the set used. Nothing is lost: the outputs are blinded independently of the key, so any live set can sign them.
- **A request resumed after a rotation** (pending when the mint stopped, then retried after a rotation) is signed by the set it named while that is live, and by the current set once it has been deleted. It may skip inputs of a set that has since retired **only if the stored state proves they were burned under that same request hash**. Two proofs count: the request's own flag (transfers and redemptions set `burned: true` in their pending entry, rollovers add the hash to a `burned` list in `rollovers.json`, after the last burn and before signing), and the **retirement proof**. The burns live in mint-core's spent list, a different store, so they cannot share one atomic write with a flag; instead, when a key set is about to be deleted, the mint reads every note an unfinished request holds (pending transfers and redemptions in `responses.json`, pending rollovers in `rollovers.json`), checks each against the retiring spent list, and saves the spent ones as burn proofs **in the same write as the retired keyset ID**, before anything is deleted (`retired.json`, `burn_proofs`; trimmed at each retirement to notes still held). Since only the request holding a note can burn it, a held note that is spent was burned by its holder. So a crash between the last burn and the flag no longer strands a request. Without either proof (the crash came before the burn) the retry is refused `400 burn_not_proven` (nothing burned, nothing signed).
- **Pending rollovers hold their notes.** A rollover saves the nonces of its inputs (`holds` in `rollovers.json`) with its pending entry, before burning. Another rollover, a transfer or a redemption naming one of them is refused as held until it finishes.

- **`exchange` / `exchange_with`** (one-keyset helpers) exist only under `#[cfg(test)]`; the server and every caller use `exchange_gens`.
- **Retired keyset list (fixed cap, not a setting).** When a rotation deletes a key set, its 8-byte keyset ID is appended to `retired.json`, written and synced *before* anything is deleted (a crash in between leaves the set listed and still on disk; the next start deletes it without listing it twice). A request naming a listed ID gets `keyset_retired` (those notes expired); an ID that is neither live nor listed gets `unknown_keyset` (junk, or never this mint's). That lets the mint tell genuinely expired notes from junk, so a wallet can explain a loss. The list is a cache capped at 1 MB of 8-byte IDs, **131,072 entries**, a constant in code and the same in every mint (`RETIRED_KEYSETS_CAP`); when full, the oldest ID is dropped. That covers hourly rotation for about 15 years, and a yearly mint never comes close; dropping only turns a very old `keyset_retired` answer into `unknown_keyset`. It is deliberately not configurable, an exception to "nothing hard-coded": it is too cheap to be worth tuning. In the file each ID is 16 hex characters, so a full list is about 2.5 to 3.5 MB of JSON on disk (quotes, commas and indentation included).
- **Deletion is crash-safe.** The retiring set's spent list and keys are renamed into `retiring-gen-N/` (keys last) and that folder is removed; a crash leaves the folder and the next start removes it. Stored responses are kept: they are bounded by their own retention and a retry may still need one.
- ESP left untouched for a full cycle (10 to 20 years by default) is lost.
- **The audit counts a rollover as a burn plus a re-issue.** `GET /audit` adds the rolled-over notes to `redeemed` (they are burned) and the new notes to `issued`, so a rollover raises both totals by the same amount and leaves `outstanding` unchanged. After a rotation the two totals are larger than the value ever bought, by the amount rolled over. Read `outstanding`, not either total alone.
- mint-core needs no change: the keyset is chosen in esp-mint before mint-core's primitives are called.

### Spent list

The spent list itself is left as it is (in the sled database). A **redeem deadline** (a date after which a matured note can no longer be redeemed, so that its entry could be dropped) was considered and declined. It is not built and not planned.

## The audit split

`GET /audit` adds up mint-core's counters, which say how much ESP is outstanding. An operator who plans payouts also needs to know *when* it can be redeemed, and a note's day (`redeemable_after_day`, part of its terms) is something only the mint sees, each time it signs or burns a note. So the mint keeps a **per-day ledger**: for each day, the ESP units signed under it (`issued`) and burned under it (`redeemed`). Outstanding for a day is the difference. A day is *matured* if the mint's clock is on that day or past it, the same rule it applies to a note (`Terms::is_redeemable_at`), and *unmatured* otherwise. The audit adds the days up: `outstanding_matured` is what a service could redeem today, `outstanding_unmatured` is what it could not yet. The code is `src/ledger.rs`; the ledger is stored by `Responses`.

**What counts, and when.** A request's movements are fixed by the request, and added once, when the request finishes:

| Event | Movements |
|---|---|
| Exchange finished | `issued` += the outputs, under the exchange's day. The fee is paid in PSP on top, so it is not ESP and not issued. |
| Transfer finished | `redeemed` += the inputs and `issued` += the outputs, under the notes' day. The difference is the fee, which is burned and not reissued. |
| Redemption finished | `redeemed` += each note the decision burned, under its own day; `issued` += each refund output, under its own day. The redemption fee and the payout come out of burned notes and are not reissued. |
| Decline of a payout | `issued` += each decline output, under its own day. |
| Rollover | Nothing: it moves notes to the current key set under the same terms. |

**Why it survives restarts and torn writes.** The ledger is in `responses.json`, in the same JSON document as the stored requests (`{"entries": {...}, "ledger": {...}}`), and that document is replaced by one atomic write (temporary file, fsync, rename, directory fsync) on every change. An exchange, transfer or redemption is added to the ledger in the very write that turns its entry into the finished one, and only if the entry it replaces is not finished already (`Responses::finish`). So:

- a crash before the write leaves the old file, with the request unfinished and not counted, and the retry finishes it and counts it;
- a crash after the write leaves it finished and counted, and a retry is answered from the entry and counts nothing;
- a half-written temporary file is ignored, and replaced by the next write;
- a request is never counted without being finished, or finished without being counted, and never twice.

A decline is the one exception, because it is marked in another file (`queue.json`). It is counted by the queue entry's id (`Responses::count_decline`, which keeps the ids it has counted in the ledger), before the entry is marked. The outputs are signed first, which is safe to repeat (signing is deterministic), so if the mint stops between counting and marking, running the decline again signs the same outputs, counts nothing a second time, and marks the entry.

**What it does not do, and what that shows.**

- *The counters move first.* mint-core adds to its counters as each note is burned or signed. The ledger adds a whole request when it finishes. While a request is unfinished the two differ by what it has done so far. `requests_unfinished` says how many there are; a request that stays unfinished keeps the difference there until it is finished by a retry or looked at by a person.
- *History before 0.5.0 is not in it.* Earlier versions kept neither the amounts nor the days of what they signed, so the ledger starts empty on an existing mint. `outstanding_unsplit` is `outstanding` minus the split parts, never below zero: what the counters say is outstanding and the ledger can not place. It is exactly the old ESP still outstanding, and it falls as that is redeemed. On a mint that has run 0.5.0 from its first note it is zero. A day is counted only while it is ahead (issued more than redeemed): a day that is behind means old notes were redeemed or reissued under it, and those come out of the unsplit part, not out of another day.
- *Per-day detail is not exposed.* The ledger has one line per day; `/audit` gives only the two sums and the rest. A listing by day is a small addition if it is needed.
- *Notes of a deleted key set* are counted like the others: the ledger is not per key set, and the counters of a deleted set stay in `retired.json`.

**The file shape.** Before 0.5.0, `responses.json` was a bare object from request hash to entry. It is still read as it is, with an empty ledger, and the first change writes the new shape. An older version refuses the new shape (its entries would not parse) rather than reading it as the old one, so going back needs the old file restored from a copy. Take a copy of `responses.json` before the upgrade.

## Fees and junk requests

Fees are charged on requests that carry value. A request that carries no value (malformed, unverifiable, or a replay of a spent note) is refused before anything can be charged, so fees do not stop junk requests; the size ceilings and the order of checks (cheap checks first) bound their cost. Per-DID and per-connection rate limits at the AIR layer are a possible further mitigation, not yet explored.

## What the storage must provide

The mint's state is in files and a sled database today. Both are stand-ins for the storage the AIR will provide, and none of the logic depends on them: the exchange, the transfer and the redemption read and write through `Responses` (the stored requests), the queue, the rollover store and the mint-core store. What the AIR storage that replaces them has to guarantee is the list below. Each item is a requirement that the code relies on now.

1. **Atomic writes of one entry.** Writing an entry (a `pending`, a `done`, a queue entry) is all or nothing. A reader after a crash sees the entry as it was or as it became, never a mix. The stand-in does this by writing a new file and renaming it.
2. **Durable before it returns.** A write that has returned survives a crash and a restart. The exchange relies on this for the `pending` entry: it must be on file before the PSP is asked to burn, or a crash after the burn would lose the notes.
3. **Read your own writes.** A read after a write, in the same process, sees it.
4. **A single writer, and a check-and-write that is one step.** At any time one process owns the data. The mint takes its own lock around "check that nothing holds these notes, then write the reservation", and relies on nobody else writing in between. If the AIR storage has more than one writer, it must offer that step as one atomic operation (a compare-and-set or a transaction), because the mint's lock would not cover the others. A second process opening the same data must be refused.
5. **Recovery shows everything that was durable and nothing else.** After a restart, every entry whose write had returned is there, and an entry whose write had not returned is either there whole or not there. The retry of a request depends on this: it finds a `pending` entry and works out from the PSP what happened.
6. **The mint-core v0.1.3 rule.** Marking an output's blind nonce used and adding its amount to the issued total are one atomic step; so are marking an input spent and adding its amount to the redeemed total.
7. **Listing.** The pending entries can be listed, since the reservation checks read them all.
8. **More than one change in one atomic write.** A request's finishing entry and its movements on the per-day ledger are one write (see "The audit split"). The stand-in does this because they are in one file. The AIR storage needs a transaction over several keys, or the ledger has to be derived from the entries instead.

The mint needs no delete, no rollback of a write, and no ordering between two different entries, apart from items 2, 4 and 8. If the AIR storage cannot give one of these, the code that depends on it has to change; the list is here so that is known in advance.

## Storage policy (setting only)

`storage.mint_state` (`ESP_STORAGE_MINT_STATE`) names the AIR services that will keep this mint's state: an ordered list of service IDs, index 0 the primary and the rest secondaries in promotion order. A service ID is the service's AIR DID: a 33-byte compressed key in hex (66 characters, starting `02` or `03`). The 32-byte x-only form is refused with a message that says to use the DID. In the environment the IDs are comma-separated; in `esp-mint.toml` the value is an array of strings or one string. One entry is valid (that service holds the state and the mint keeps a local backup copy); empty, the default, means local only; at most 8, no duplicates, no empty entry. The parser and checks are `sp_wire::storage` (sp-wire), shared by all three mints and the wallet, so a list means the same thing everywhere.

This is configuration and validation only. **Nothing reads or writes the AIR yet:** the state is still in local files, whatever the list says. The mint logs the list at startup like any setting (it is a restart setting: `SIGHUP` keeps the running list and says a change needs a restart, because only the mint itself will change its list, when it promotes a secondary). What the list will do, and what the mint's storage layer must then provide (eight numbered requirements: 1 a spend is written to the primary and at least one secondary before the mint answers, batched; 2 a local backup copy with one service; 3 only the mint promotes a secondary and updates its config; 4 writes carry a sequence number, so a returning primary is overwritten from the working copy; 5 the wallet file carries a version and is merged; 6 networks stay apart; 7 the mint's own local copy is the primary, fsynced, with external services as backup only and no cap; 8 a request's finishing entry and its ledger movements are one atomic write, which only esp-mint's per-day ledger needs), is that list: it is the whole set, and nothing else is promised. That replication belongs in mint-core's storage layer and is a candidate for AIR upstream. The mint's own local copy is the primary and every listed service is a backup (decided 2026-10-17): every spend is fsynced before the mint answers and replicated to the backups while they are reachable; while every backup is unreachable, unreplicated spends are queued and copied out in order to the first backup that returns. There is no cap: the mint carries on with no limit and never refuses or holds spends for replication, and `/health` only reports a degraded state while backups are behind. None of this is built.

## The AIR listener (mint info, keysets, rotation, fees, rollover, exchange, transfer, redeem)

The long form is `air-sandbox/REQUEST-DESIGN.md` in sandbox-mint (sections 13 to 16); the wire is `sp_wire::air_request`. What is specific to this mint, and where it differs from psp-mint's listener:

- **Placement.** Two new modules, `air_listener.rs` (the loop) and `did.rs` (the mint's own DID key), and one thread started by `serve` after the HTTP server's pieces exist, with a runtime of its own so that the HTTP runtime and the listener never share a thread. It always runs; `serve` refuses to start without `air.server` and `air.host`, and exits with status 1 if the listener fails. What it answers with is `server::air_served(state, kind, body)`.
- **One outcome function per call.** Each call is a function that returns `(StatusCode, serde_json::Value)`: `run_exchange`, `run_transfer`, `run_redeem`, `fees_body`, `keysets_outcome`, `rotation_outcome` and `rollover_outcome`. `air_served` calls them; `post_served` does what was done around the handler (ceiling, then parse, then the function), and `served_of` turns the status and JSON into an answer, a refusal or "unavailable". (They returned a status and JSON because they were HTTP handlers; they are kept that way, and the status is what `served_of` maps.)
- **Kinds.** `sp_wire::air_request` gave this mint four kinds of its own (`KIND_FEES` 7, `KIND_EXCHANGE` 8, `KIND_TRANSFER` 9, `KIND_REDEEM` 10) and it reuses mint info, keysets, rotation and rollover (1, 3, 4, 5) because the JSON is the PSP's JSON in kind: a kind names a call, not a mint, and the DID says which mint. Keys (2) and check-state (6) are not served: the ESP has no keys call and no check-state, and a mint skips a kind it does not serve. See REQUEST-DESIGN.md, section 16.
- **The ESP's own DID.** `mint_did_key.json`, the same file format as psp-mint's and its own key. It is made the first time `serve` starts (the `pubkey` command makes it too), and a file that exists but cannot be read is an error and never replaced. The PSP and ESP can share an AIR server: a request is sealed to one DID and sits in a slot only that DID's key derives, so neither listener sees the other's requests. The wallet carries both DIDs (`BUILTIN_SPI_DID`, `BUILTIN_ESP_DID`, placeholders until the first SPI deploy).
- **Blocking work off the async thread.** psp-mint's listener answers on its runtime's thread, which is fine for its calls (a short lock and a serialisation). An exchange here calls the PSP with `reqwest::blocking`, which must not run on an async thread, and a redemption reads and writes `queue.json` and `responses.json`. So `air_listener` answers each opened request with `tokio::task::spawn_blocking` and waits for it before the next slot. The listener takes an `Arc<Serve>`, where `Serve` is `dyn Fn(u8, &[u8]) -> Option<Served> + Send + Sync`, for that reason (a kind and a body to a body, to "unavailable", to a refusal, or to `None` for a kind not served, which is skipped). A panic in `serve` ends the listener as a crash would, which is how the tests simulate a mint dying after it opened a request.
- **Why one at a time.** The mint's own work is serialised by its lock (the lock is let go while an exchange waits for the PSP, see "Not holding the lock while the PSP is called"), so answering requests in parallel would mostly queue on the lock. What one at a time costs is that a slow PSP holds up the requests behind a slow exchange, for up to `psp.timeout_secs`, and a long rollover (holding the lock) does the same. Both are bounded, and `/audit` and `/health` are not held up by the listener. A listener that answers several at once, with the counter moved over the contiguous finished prefix, is a candidate when the storage moves (ROADMAP).
- **Idempotency is the mint's own.** Exchange, transfer, redeem and rollover each store their answer by request hash before anything is burned, and the in-flight guard (`EspState.in_flight`) refuses the same request while it is being processed with `409 in_progress`. A resend over AIR (a new request id and the same body), a replay of a slot after a crash between answering and writing `next`, and a wallet that starts over all reach the same code, so the stored answer comes back and nothing is applied twice. The listener needed nothing new: it creates the reply first and treats `Taken` as answered, and a replayed slot calls `serve` again, which is safe because `serve` is idempotent for these calls. The tests resend each of the four over AIR and straight to the mint, replay slots after resetting the counter, and check the audit totals and the queue (one entry for a redemption, not two).
- **Refusals and `http_status`.** A refusal of the notes (400) is told from the other 4xx by the status. The status is one byte of a signed reply, so a 400 is `STATUS_REFUSED` with the route's JSON unchanged and any other 4xx is `STATUS_REFUSED` with the JSON plus `"http_status": N`. The wallet maps a refusal without `http_status` as a 400 and one with it as that status (an error, never "the mint refused my notes"; a refused exchange cancels the pending exchange and frees its notes, which a `409 in_progress` or a `404` must not). A `5xx` is `STATUS_UNAVAILABLE` with no body, as in psp-mint, including the `502` of a PSP that could not be reached; a retry is safe.
- **Unavailable instead of silence, create-first, the counter, supervision, limits.** As in psp-mint's listener: a signed `unavailable` costs a wallet no waiting; the reply is created first and a taken cell means answered; `air_mailbox_next` is local state, not mint state, and is not under the storage policy; more than five held reads ending within ten seconds ends the listener; `air.held_reads` stops at 200.
- **Size.** The request body length in the envelope is a `u32`, so the envelope has no ceiling of its own and the mint's ceilings apply. A rollover of 1000 notes is about half a megabyte and a test sends it. The transport has a cap: AIR's WebSocket message cap is 16 MiB (17 MiB for a client). So the redeem ceiling's default is 15 MiB (`redeem::DEFAULT_MAX_REQUEST_BYTES` = `AIR_MESSAGE_CAP` less `AIR_ROOM`, 1 MiB for the 71-byte envelope, its 80-byte seal and AIR's framing), and a request the mint accepts always fits one message. A test pins the arithmetic. The wallet reads the ceiling from the fees call and already splits a larger redemption into several requests, so nothing changed there. An operator who raises the setting above 15 MiB takes requests that no wallet can send, since there is no other way in (REQUEST-DESIGN.md section 16.3).
- **Privacy.** The request is sealed to the mint's DID with the notes in it, so the AIR server sees the size of a request and not its content. That covers the note bodies of the exchange, the transfer and the redemption, which are all in the sealed body; the reply is sealed to the wallet's one-off key.
- **What this mint does not serve over AIR.** `GET /audit`, `GET /health` and the operator's routes (operator and SPI only; `/health` is SPI-local like `/audit`, and stays on HTTP: `spi start`, `spi status` and the health monitor run on the SPI's own machine and poll it). No keys call: the keys arrive in the reply bodies of exchange, transfer and rollover. The exchange's PSP calls are not AIR calls.

## Running as a service

`esp-mint serve` runs under `launchd` (macOS) or `systemd` (Linux) as a user that is not root, with its data directory (`ESP_DATA_DIR`) and settings file (`ESP_CONFIG`) named in an env file, so it needs no home directory and reads nothing it was not given. The definitions, the install and uninstall steps and the health monitor are in the README of the SPI repository ("Running as services"): `spi install` generates the systemd units or launchd property lists, the env and settings files and the health monitor from its `spi.toml`, and prints the root steps to put them in place.

**Failure and restart.** A fatal fault (a poisoned lock) makes the process exit with status 1, and the service manager starts it again after a delay that grows (systemd) or is fixed (launchd) and never gives up. A restart is picked up from what is on disk by the same rules as a crash: the `pending` entry of an exchange, transfer or redemption is what a retry works from.

**The PSP at startup.** `serve` asks the PSP which network it is on. If the PSP cannot be reached, it asks again every `psp.startup_retry_secs` (5 by default), without limit, and logs the first failure and then one line a minute, so the mint can be started before the PSP or after a power cut with nobody to start it again. Two answers are not waited for, because waiting would not change them: a PSP on another network, and a PSP that does not say which network it is on. The mint stops with a message, and the service manager starts it again after its delay, which is the same as waiting but visible in the log.

**Stopping.** SIGTERM and SIGINT stop both listeners gracefully: no new connections, the requests being answered finish (an exchange waiting on the PSP finishes or times out at `psp.timeout_secs`), and the process exits with status 0. Nothing needs flushing at that point, because every write is complete when the request that made it returns (see "What the storage must provide"). A kill or a power cut during a request leaves the entry the request had written, which the retry finishes.

**Opening the data twice.** The database allows one process at a time (a second open fails with an error; there is a test), so a new process that starts while the old one is still stopping cannot open the data. It exits with an error and the service manager starts it again after its delay. This is item 4 of "What the storage must provide", and the AIR storage has to give the same refusal or an equivalent single-writer guarantee.

**Health.** `GET /health` is `200` while the locks are sound and `503` after, and the process also exits when a lock is poisoned. The health monitor that `spi install` sets up (`sp-health-monitor.sh`, see the SPI README, "The health monitor") polls it and reports or restarts a mint that stays unhealthy (interval, thresholds and action are settings of the monitor, in its file and environment). It catches a mint that is up but hung or wrong, which the exit-on-fault cannot.

## Source map

Source map: terms and the date rule (`src/terms.rs`), unit constants and checked sums (`src/units.rs`; both are re-exports of `sp-wire`, see "Wire format and versions"), per-terms key derivation (`src/keys.rs`), the exchange (`src/exchange.rs`), stored responses (`src/responses.rs`), the per-day ledger (`src/ledger.rs`), the PSP client (`src/psp_client.rs`), the API (`src/server.rs`), the AIR listener and the mint's DID key (`src/air_listener.rs`, `src/did.rs`), the transfer (`src/transfer.rs`), redemption (`src/redeem.rs`), the queue and payout report (`src/queue.rs`, `src/payouts.rs`, `src/admin.rs`), fees (`src/fee.rs`), rotation (`src/rotation.rs`) and settings (`src/config.rs`).

## Settings

*Why:* keys and spent notes of one network must never be used on another, the same reason psp-mint and the wallet split theirs.

**The rate in force is stored.** A request is charged at the rate in force when it is accepted. The reply carries `fee_per_byte`, `fee_esp` and `size_bytes`, and the queue entry for a redemption carries the same, so a retry (which returns the stored reply) and an audit see the rate that was charged, whatever the setting is now. A request picked up again after a crash keeps its fee too: it is stored in the pending entry (redemption) or follows from what the request pays over what it asks for (exchange and transfer).
