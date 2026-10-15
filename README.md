# esp-mint

ESP is the encumbered point. It is obtained by exchanging PSP at 10^12 ESP for 1 PSP. Each ESP note is bound to terms: one service that alone may redeem it, and a date before which nobody can.

## Status

Built:

- The terms and the date rule (`src/terms.rs`).
- The unit constants and checked sums (`src/units.rs`).
- Per-terms key derivation and the master secret file (`src/keys.rs`).

Designed but not built: the PSP-to-ESP exchange, transfer, redemption, the redeem fee, and the HTTP API. See "Amounts", "The exchange", "Transfer to the service", "Redemption", "Fees" and "Left to do".

## Terms

- **Service** is an x-only public key (32 bytes). It can be any key. There is no registry of services.
- **Redeemable-after day** is a UTC day number, the Unix time in seconds divided by 86400, rounded down.
- **The ESP mint sets the date, not the requester.** It is the day of issue plus 365 days. This 12 month window is a placeholder. A note is redeemable from the start of that UTC day.
- Time is always passed in as a parameter, so the rules can be tested without a clock.

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

Designed, not built.

1. The wallet sends PSP notes and blinded outputs to the ESP mint, along with the service ID it wants. It does not send a date.
2. The PSP notes, times 10^12, must be worth at least the total of the ESP outputs, or the request is rejected. The mint charges no exchange fee. The request is a JAMJAR message, and its cost is paid in JAMJAR currency and charged by JAMJAR messaging, not by this mint. Excess below 10% of the outputs' total is kept by the mint, so wallets should send exact amounts. Excess of 10% or more is recorded as credit against the request hash. See "Overpayment".
3. The ESP mint calls the PSP's `/melt` with the notes. The memo is the hex of `SHA-256("esp-mint/exchange/v1" || service || each output's amount and blind nonce)`, and the wallet's spend signatures cover that memo. The burn is bound to this one request, and only the note holder can authorize it. The ESP mint checks everything it can before calling, so the burn only happens for a request it will honor.
4. If the burn succeeds, the ESP mint derives the keys for the terms and issues each output with `MintLogic::issue_with_key`. It uses that method and not `issue` because the key depends on the note's terms as well as its amount. See the docs on `MintLogic::issue_with_key` in mint-core.
5. It returns the signatures, the terms, and the public key for each amount.

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

A redemption is a batch. One request redeems many notes for one service, and the notes may have different redeemable-after days.

- **Request.** The service's ESP notes (all for the one service), a payout memo, and fresh blinded outputs, each tagged with a date. The outputs are used only if the payout is declined (below).
- **Digest.** `SHA-256("esp-mint/redeem/v1" || service || the inputs || the memo || the outputs with their dates)`. Each input's nonce key signs it, and so does the service's x-only key. The memo carries the payout destination, so a signature cannot be redirected.
- **Maturity.** If any note in the request is not yet mature (its redeemable-after day has not come, by the mint's own clock), the whole request is rejected and nothing is burned, not even the fee. It never enters the queue.
- **Checks.** If every note is mature, the mint checks everything it can before burning: every input is genuine under the key derived for its amount and terms, all signatures verify, the output blind nonces are unused, and the outputs fit the limits for a decline (below).
- **On acceptance.** The mint burns all the notes at once and adds one queue entry for the batch. Only valid, unburned notes can enter, so a duplicate submission is rejected at the checks. The entry holds the amount owed (the batch total minus the ESP redeem fee), the payout memo, the service, and the dated blinded outputs. The queue is the record of what the mint still owes. An entry is open until it is completed or declined.
- **Terms check.** Before paying, the mint checks that the service met its terms. This is manual for now, because uptime cannot be checked by a machine yet.
- **Paid.** The mint pays out by hand in BTC or USD, then marks the entry completed with a payment reference. The USD value of an amount is the amount divided by 10^12. If a payout fails, the entry stays open and is retried. Notes are never reissued because of a failed payout.
- **Declined.** If the mint declines to pay because the terms were not met, it does not keep the notes. It reissues each output under its own date, signing it with `MintLogic::issue_with_key`, and marks the entry declined. There is no reset: a note redeemable after a given day is reissued with that same day, not a later one.
- **Limits on the outputs.** These are checked before anything is burned.
  - For each date, the outputs with that date may total at most the inputs with that date. Value cannot move from one date to another.
  - The outputs together may total at most the inputs minus the ESP redeem fee, which comes out of the batch. The requester chooses which date gives up the fee, by how much it asks for under each date.
  - All sums are `u128` or checked.
- **Fee.** The ESP redeem fee is charged whenever a request is accepted, whether the payout is made or declined, and is burned. It covers the cost of serving the request and discourages DoS.

## Fees

The only explicit mint fee in ESP is the redeem fee, paid in ESP and burned. It is a placeholder of 1 ESP unit set in config. One ESP unit is worth 10^-12 USD, so the real amount still needs to be set.

There is no exchange fee and no transfer fee. Those requests are JAMJAR messages, and their cost is paid in JAMJAR currency and charged by JAMJAR messaging, not by the mints. Services set their FSP fees in their own FSP mints.

## Overpayment

The same rule as the PSP applies to an exchange.

- **Below 10% over** (the PSP notes times 10^12, against the total of the ESP outputs): the mint keeps the excess.
- **10% or more over:** the mint issues the requested outputs and records the excess as credit against the request hash.

The procedure for credit, a **placeholder that is not built**: the mint sends a message to the payer's DID over JAMJAR, signed with the mint's DID key, saying how much credit there is and asking for a new request for the remainder. The buyer's reply is a JAMJAR message, paid for by the buyer in JAMJAR currency (PSP, ESP or FSP). JAMJAR messaging does not exist yet, and exchange requests do not yet carry a reply DID, so today the credit would only be recorded. An underpayment is not tolerated on the ESP: the request is rejected before anything is burned.

## Left to do

- **The exchange, transfer and redemption.** Everything above. The PSP side exists: `psp-mint serve` runs the PSP's HTTP API (`/keys`, `/melt`, `/check-state`, `/audit`) in the same process as its payment scanner. The ESP mint still needs a client for it.
- **Redemption queue.** Where the queue is stored, and how entries are approved, declined and completed. Payouts are manual, in BTC or USD, for now.
- **Terms check.** The mint decides by hand whether a service met its terms. How to check uptime by machine is not designed.
- **Overpayment credit.** The credit is recorded only. The JAMJAR message to the payer's DID is a placeholder and the exchange request has no reply DID field yet.
- **Retries and crash safety.** The exchange, transfer and redeem all burn inputs and then issue outputs or queue an entry, and mint-core's `swap` does not do both in one step. If the process dies between them, the caller loses the notes. Storing the response by request hash would let a retry return the same result: the same signatures for an exchange or transfer, and the same queue entry or reissued notes for a redeem.
- **Local store is for development.** The mint's database (sled) is on local disk only while the other pieces are built. It will eventually be stored in the JAMJAR. Until then: only one process can open the mint, so there is one instance and an outage while it restarts; a live `db/` must not be copied as a backup (stop the process first, or the copy may be inconsistent); and the data directory is on local disk, so losing it loses the keys and the state.
- **Master secret protection.** It is a plain file with `0600` permissions. How the real secret is protected is not decided.
- **Redeem window.** 365 days is a placeholder.
- **Redeem fee amount.** 1 ESP unit (10^-12 USD) is a placeholder.

## Not decided yet

How the service receives the reissued notes when a redemption is declined, and how a declined entry is explained to the service.
