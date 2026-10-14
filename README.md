# esp-mint

ESP is the encumbered point. It is obtained by exchanging PSP at 1 ESP for 1 PSP. Each ESP note is bound to terms: one service that alone may redeem it, and a date before which nobody can.

## Status

Built:

- The terms and the date rule (`src/terms.rs`).
- Per-terms key derivation and the master secret file (`src/keys.rs`).

Designed but not built: the PSP-to-ESP exchange, transfer, redemption, fees, and the HTTP API. See "The exchange", "Transfer to the service", "Redemption", "Fees" and "Left to do".

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

## The exchange

Designed, not built.

1. The wallet sends PSP notes and blinded outputs to the ESP mint, along with the service ID it wants. It does not send a date.
2. The PSP notes must be worth at least the outputs plus the exchange fee. The rate is 1 to 1, a placeholder. Any excess is kept by the mint, so wallets should send exact amounts.
3. The ESP mint calls the PSP's `/melt` with the notes. The memo is the hex of `SHA-256("esp-mint/exchange/v1" || service || each output's amount and blind nonce)`, and the wallet's spend signatures cover that memo. The burn is bound to this one request, and only the note holder can authorize it. The ESP mint checks everything it can before calling, so the burn only happens for a request it will honor.
4. If the burn succeeds, the ESP mint derives the keys for the terms and issues each output with `MintLogic::issue_with_key`. It uses that method and not `issue` because the key depends on the note's terms as well as its amount. See the docs on `MintLogic::issue_with_key` in mint-core.
5. It returns the signatures, the terms, and the public key for each amount.

## Transfer to the service

Designed, not built.

An app that pays a service with ESP hands over the notes, and with them each note's spend secret. For the next 12 months the app could still spend those notes, so the service must not rely on what the app gave it. When it accepts ESP notes, the service asks the ESP mint to swap each one for a fresh note that only the service controls, with the same terms. This also covers the design doc's step of checking that the points have not been spent, so there is no separate verify call.

- **Request.** The service's ESP inputs, fresh blinded outputs that the service chose, and the terms. One request covers one set of terms.
- **Digest.** `SHA-256("esp-mint/transfer/v1" || terms || the inputs || the outputs)`. Every input is signed over it by the note's own nonce key, which the service now holds. The service also signs it with its x-only key from the terms. Only the named service can ask for a transfer.
- **Checks.** Before anything is burned: every input is genuine under the key derived for its amount and terms, all signatures verify, the output blind nonces are unused (`MintLogic::is_blind_nonce_used`), and the inputs are worth at least the outputs plus the transfer fee.
- **Result.** The inputs are burned with `MintLogic::redeem_with_key` and the outputs are signed under the same terms with `MintLogic::issue_with_key`.
- **Front-running.** The service issues FSP only after its transfer succeeds. If the app spends a note first, the service's transfer fails and no FSP is issued.

## Redemption

Designed, not built.

- **Request.** The service's ESP notes, a payout memo, and the terms.
- **Digest.** `SHA-256("esp-mint/redeem/v1" || terms || the inputs || the memo)`. Each input's nonce key signs it, and so does the service's x-only key. The memo carries the payout destination, so a signature cannot be redirected.
- **Time gate.** The mint refuses before the redeemable-after day, using its own clock.
- **Checks.** All of them pass before anything is burned, as in a transfer. A policy hook decides whether the service met its terms. It defaults to "met". What to do when terms are not met is not decided.
- **Payout.** The notes are burned and the service is paid the total minus the redeem fee. Per the design doc, the payment is in bitcoin or another agreed method and is not instant.

## Fees

Every request to the issuer carries a small payment, to cover the cost of serving it. The currency follows the design doc.

| Request | Paid in | Fee is |
|---|---|---|
| Exchange | PSP, burned through the PSP | PSP inputs minus ESP outputs |
| Transfer | ESP | ESP inputs minus outputs |
| Redeem | ESP | ESP inputs minus the payout |

The fee notes are burned and not reissued. Each fee is 1 unit for now, a placeholder set in config.

## Left to do

- **The exchange, transfer and redemption.** Everything above. They need the PSP to run mintd's HTTP API in-process.
- **Bitcoin payout.** Paying a service on redemption.
- **Retries.** If the process dies after notes are burned and before the signatures are returned, the caller loses them. Storing the response by request hash would let a retry return the same signatures.
- **Master secret protection.** It is a plain file with `0600` permissions. How the real secret is protected is not decided.
- **Redeem window.** 365 days is a placeholder.
- **Exchange rate.** 1 ESP per PSP is a placeholder. Scaling up the unit ratio, so that ESP is issued at a higher ratio to PSP, is deferred. The ratio is not set, but it needs to be decided at some point.
- **Fee amounts.** 1 unit per request is a placeholder.

## Not decided yet

What happens to a note whose terms are not met, for example if the service had outages before redemption.
