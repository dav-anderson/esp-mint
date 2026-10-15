# esp-mint

ESP is the encumbered point. It is obtained by exchanging PSP at 10^12 ESP for 1 PSP. Each ESP note is bound to terms: one service that alone may redeem it, and a date before which nobody can.

## Status

Built:

- The terms and the date rule (`src/terms.rs`).
- The unit constants and checked sums (`src/units.rs`).
- Per-terms key derivation and the master secret file (`src/keys.rs`).
- The PSP-to-ESP exchange (`src/exchange.rs`), its stored responses (`src/responses.rs`), the PSP client (`src/psp_client.rs`) and the HTTP API (`src/server.rs`, run with `esp-mint serve`).

Designed but not built: transfer, redemption and the redeem fee. See "Transfer to the service", "Redemption", "Fees" and "Left to do".

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
| 1 PSP | 1 USD |
| 1 ESP unit | 10^-12 USD |
| 1 FSP unit | 10^-12 USD |

- 1 PSP = 10^12 ESP. ESP to FSP is 1:1, so an FSP mint uses the same unit.
- Amounts are `u64`, so one note is worth at most about 1.8e19 units, which is about $18.4 million (18,446,744 PSP when converted to ESP).
- A request can hold many notes. Every sum, and every PSP-to-ESP conversion (PSP units times 10^12), is computed in `u128` or with checked arithmetic, so an overflow is an error and never wraps.
- The constants and helpers are in `src/units.rs`, with tests at the limits: the largest PSP that fits one note, one PSP over it, `u64::MAX` sums, and totals that exceed one note.

## The exchange

Built.

1. The wallet sends PSP notes and blinded outputs to the ESP mint, along with the service ID it wants. It does not send a date. The outputs can have any non-zero amount, and a request holds at most 1000 notes and 1000 outputs.
2. The PSP notes, times 10^12, must be worth at least the total of the ESP outputs, or the request is rejected before anything is burned. The mint charges no exchange fee. The request is a JAMJAR message, and its cost is paid in JAMJAR currency and charged by JAMJAR messaging, not by this mint. Excess below 10% of the outputs' total is kept by the mint, so wallets should send exact amounts. Excess of 10% or more is recorded as credit in the response (`credit_esp`). See "Overpayment".
3. The mint checks everything it can before it burns: the output blind nonces are unused, the PSP notes are unspent at the PSP (`/check-state`), and every note's spend signature verifies over the memo below. The spend signatures are public to check, and they cover the memo, so only the holder of the notes can authorize this request.
4. The ESP mint calls the PSP's `/melt` with the notes. The memo is the hex of `SHA-256("esp-mint/exchange/v1" || service || each output's amount and blind nonce)`, and the wallet's spend signatures cover that memo. The burn is bound to this one request. The mint checks that the PSP burned exactly the amount it expected.
5. If the burn succeeds, the ESP mint derives the keys for the terms and issues each output with `MintLogic::issue_with_key`. It uses that method and not `issue` because the key depends on the note's terms as well as its amount. See the docs on `MintLogic::issue_with_key` in mint-core.
6. It returns the service, the redeemable-after day, one blind signature per output in the request's order, the public key each was signed with (the wallet needs it to unblind), and `credit_esp`.

**Retries.** Responses are stored by request hash, `SHA-256("esp-mint/exchange-request/v1" || memo || the PSP inputs as JSON)`. The hash covers the inputs, spend signatures included, so a request with different inputs never gets another request's response. The stored state has two steps:

- `pending` is written after the checks in step 3 and before the burn. It fixes the redeemable-after day, so a retry on a later day still gets the original terms.
- `done` is written after the signatures are made and holds the response.

A retry of a done request returns the stored response and burns nothing. A retry of a pending request carries on: if the PSP notes are all spent it skips the burn (the earlier attempt burned them and its reply was lost), and outputs that were already issued are signed again, which gives the same signature because signing is deterministic. If only some of the PSP notes are spent, it stops with an internal error for a person to look at. A request that failed because the PSP could not be reached leaves a `pending` entry that is harmless: the retry checks the PSP again.

Not yet handled: a crash between the mint marking an output's blind nonce used and adding its amount to the issued total would leave the issued total short by that output, until the retry finishes it.

## HTTP API

`esp-mint serve` runs the API. Settings are environment variables:

| Variable | Default |
|---|---|
| `ESP_DATA_DIR` | `~/.esp-mint` (the master secret, `db/` and `responses.json`) |
| `ESP_BIND` | `127.0.0.1:3100` |
| `ESP_PSP_URL` | `http://127.0.0.1:3000` (`psp-mint serve`) |

| Route | What it does |
|---|---|
| `POST /exchange` | Body: `{"service": "<x-only hex>", "psp_inputs": [...], "outputs": [...]}`. `200` with the response above. `400` if the request is refused, with `{"error": ...}`. `502` if the PSP could not be reached or refused the burn. `500` for a fault in the mint. A retry is safe after a `502` or `500`. |
| `GET /audit` | `issued`, `redeemed`, `outstanding`, in ESP units. |
| `GET /health` | `200` while the locks are sound, `503` otherwise. |

The process exits with status 1 if a lock is poisoned, so a supervisor can restart it. One request runs at a time, holding the mint and the stored responses (and waiting on the PSP) until it is done, which is fine for development and not a design for load. There is no authentication and no TLS: a note authorizes its own spend, so a caller can only burn notes they hold. Bind to localhost. Only one process can open the mint's database.

## Transfer to the service

Designed, not built.

An app that pays a service with ESP hands over the notes, and with them each note's spend secret. The app cannot spend those notes itself, because transfer and redeem both need the service's signature. The risk is that the same note is presented twice, to the same service or to different ones, so a note the service was handed may already have been used. When it accepts ESP notes, the service asks the ESP mint to swap each one for a fresh note that only the service controls, with the same terms. A note can be swapped only once, so a second presentation fails. This also covers the design doc's step of checking that the points have not been spent, so there is no separate verify call.

- **Request.** The service's ESP inputs, fresh blinded outputs that the service chose, and the terms. One request covers one set of terms.
- **Digest.** `SHA-256("esp-mint/transfer/v1" || terms || the inputs || the outputs)`. Every input is signed over it by the note's own nonce key, which the service now holds. The service also signs it with its x-only key from the terms. Only the named service can ask for a transfer.
- **Checks.** Before anything is burned: every input is genuine under the key derived for its amount and terms, all signatures verify, the output blind nonces are unused (`MintLogic::is_blind_nonce_used`), and the inputs and outputs have the same total (summed in `u128`). The mint charges no transfer fee. The request is a JAMJAR message, and its cost is paid in JAMJAR currency and charged by JAMJAR messaging.
- **Result.** The inputs are burned with `MintLogic::redeem_with_key` and the outputs are signed under the same terms with `MintLogic::issue_with_key`.
- **Double presentation.** The service issues FSP only after its transfer succeeds, one FSP unit for each ESP unit. If the note was already presented, the transfer fails and no FSP is issued.

## Redemption

Designed, not built.

Only the owner of a service's DID key may redeem ESP for that service. The service ID in a note's terms is that DID public key (x-only). Holders cannot cash out at the mint: they spend or transfer their notes to the service (see "Transfer to the service"), and the service redeems.

- **Request.** The service's DID key, the ESP notes it presents, a payout memo, and two lists of fresh blinded outputs, each tagged with a service and a date: `decline_outputs` and `refund_outputs` (both below). The notes may be for any mix of services and dates. Notes for other services are rejected one by one, not as a group.
- **Request hash.** `SHA-256("esp-mint/redeem/v1" || service || the inputs || the memo || both output lists with their terms)`. Each input is signed over it by the note's own nonce key, and the service signs it with its DID key (Schnorr). The memo carries the payout destination, so a signature cannot be redirected.
- **Signature first.** The mint verifies the service's signature before it does anything else. If it fails, the request is refused. Nothing is burned and no fee is charged, because nobody authorized it.
- **Each note is decided on its own.** A note is accepted if all of these hold, and otherwise rejected with the first reason that applies:
  - its service is the key that signed the request (`WrongService`);
  - its signature is genuine under the key derived for its amount and terms, and its spend signature verifies (`BadProof`);
  - it is not spent, and not listed twice (`AlreadySpent`);
  - its redeemable-after day has come, by the mint's own clock (`Immature`).

  Mixed dates are allowed in one request. One immature note no longer rejects the others.
- **Response.** Every note is reported as accepted or rejected, with its reason.
- **Value.** Let V be the total of the notes that are genuine and unspent, accepted or not (summed in `u128`). Let A be the accepted total and R the rest, so V = A + R. Spent and forged notes count for nothing.
- **Fee.** 10^12 ESP (1 PSP, about $1) for every request that passes the signature check, whatever happens to it. It is sized against the whole request (V), not the accepted amount, so a request full of junk notes still pays, which discourages DoS. It is burned and never returned, even if the payout is declined. If V is below the fee, the whole request is refused, nothing is burned, and no fee is charged.
- **How the fee is taken.**
  - If A is at least the fee, it comes out of the payout. The rejected notes are not touched and stay with the holder, unburned.
  - If A is less than the fee, the whole of A goes to the fee and the shortfall comes out of the rejected notes. The mint burns the genuine rejected notes and reissues `refund_outputs`, which may total at most R minus the shortfall. For each service and date, the refund outputs may total at most the rejected notes with that service and date. If the request carries no usable `refund_outputs`, it is refused and nothing is burned. This also covers a request where every note is rejected: the holder gets the notes back minus the fee.
- **On acceptance.** The mint burns the accepted notes and adds one queue entry for A minus the fee (or nothing owed, if A is the fee or less). A duplicate submission is rejected at the checks because its notes are spent. The entry holds the amount owed, the payout memo, the service, and the `decline_outputs`. The queue is the record of what the mint still owes. An entry is open until it is completed or declined.
- **Terms check.** Before paying, the mint checks that the service met its terms. This is manual for now, because uptime cannot be checked by a machine yet.
- **Paid.** The mint pays out by hand in BTC, USD or another agreed method, then marks the entry completed with a payment reference. The USD value of an amount is the amount divided by 10^12. If a payout fails, the entry stays open and is retried. Notes are never reissued because of a failed payout.
- **Declined.** If the mint declines to pay because the terms were not met, it reissues only the accepted notes, signing each of `decline_outputs` with `MintLogic::issue_with_key`, and marks the entry declined. Each output keeps its original service and redeemable-after day. There is no reset: a note redeemable after a given day is reissued with that same day. The fee is not returned.
- **Limits on `decline_outputs`.** These are checked before anything is burned.
  - For each service and date, the outputs may total at most the accepted notes with that service and date. Value cannot move between dates.
  - Together they may total at most A minus the fee.
  - All sums are `u128` or checked.
- **Idempotence.** Responses are stored by request hash, so a retry of the same request returns the same result and the same queue entry, and never burns or charges twice.

## Fees

The only explicit mint fee in ESP is the redeem fee, paid in ESP and burned. It is a placeholder of 10^12 ESP (1 PSP, about $1) set in config. It is charged once per request that passes the signature check, however the request ends. See "Redemption".

There is no exchange fee and no transfer fee. Those requests are JAMJAR messages, and their cost is paid in JAMJAR currency and charged by JAMJAR messaging, not by the mints. Services set their FSP fees in their own FSP mints.

## Overpayment

The same rule as the PSP applies to an exchange.

- **Below 10% over** (the PSP notes times 10^12, against the total of the ESP outputs): the mint keeps the excess.
- **10% or more over:** the mint issues the requested outputs and records the excess as credit against the request hash.

The procedure for credit, a **placeholder that is not built**: the mint sends a message to the payer's DID over JAMJAR, signed with the mint's DID key, saying how much credit there is and asking for a new request for the remainder. The buyer's reply is a JAMJAR message, paid for by the buyer in JAMJAR currency (PSP, ESP or FSP). JAMJAR messaging does not exist yet, and exchange requests do not yet carry a reply DID, so today the credit would only be recorded. An underpayment is not tolerated on the ESP: the request is rejected before anything is burned.

## Left to do

- **Transfer and redemption.** Designed above, not built. The exchange is built and its API runs. Transfer and redemption will use the same stored-response pattern.
- **Redemption queue.** How entries are approved, declined and completed. Payouts are manual, in BTC, USD or another agreed method, for now.
- **Redemption store (deferred to the AIR).** The queue and the stored responses move into the AIR. Until then they are local files.
- **Terms check.** The mint decides by hand whether a service met its terms. How to check uptime by machine is not designed.
- **Overpayment credit.** The credit is recorded only. The JAMJAR message to the payer's DID is a placeholder and the exchange request has no reply DID field yet.
- **Retries and crash safety for transfer and redemption.** The exchange stores its response by request hash and recovers from a crash after the burn. The transfer and the redeem also burn inputs and then issue outputs or queue an entry, and mint-core's `swap` does not do both in one step. They need the same treatment: the same signatures for a transfer, and the same queue entry or reissued notes for a redeem.
- **ESP denominations.** The exchange accepts any non-zero output amount, and a key is derived for each. Whether amounts should be restricted to a ladder, to limit how much an amount reveals, is not decided.
- **Hold time.** The API holds the mint lock while it waits on the PSP. A slow PSP blocks every ESP request.
- **Local store is for development.** The mint's database (sled) is on local disk only while the other pieces are built. It will eventually be stored in the JAMJAR. Until then: only one process can open the mint, so there is one instance and an outage while it restarts; a live `db/` must not be copied as a backup (stop the process first, or the copy may be inconsistent); and the data directory is on local disk, so losing it loses the keys and the state.
- **Master secret protection (deferred to the AIR).** It is a plain file with `0600` permissions. The mint keystore moves into the AIR, and how the secret is protected there is not decided.
- **API over the AIR (deferred).** All mint API calls will travel over the AIR. HTTP is the development transport.
- **Redeem window.** 365 days is a placeholder.
- **Redeem fee amount.** 10^12 ESP (1 PSP, about $1) is a placeholder.

## Not decided yet

How the service receives the reissued notes when a redemption is declined, and how a declined entry is explained to the service.
