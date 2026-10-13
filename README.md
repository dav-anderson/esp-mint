# esp-mint

ESP is the encumbered point. It is obtained by exchanging PSP at 1 ESP for 1 PSP. Each ESP note is bound to terms: one service that alone may redeem it, and a date before which nobody can.

## Status

Built:

- The terms and the date rule (`src/terms.rs`).
- Per-terms key derivation and the master secret file (`src/keys.rs`).

Designed but not built: the PSP-to-ESP exchange, redemption, the verify call, and the HTTP API. See "The exchange" and "Left to do".

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
2. The ESP mint requires the PSP notes to add up to exactly the requested outputs. The rate is 1 to 1, a placeholder.
3. The ESP mint calls the PSP's `/melt` with the notes. The memo is the hex of a hash that commits to the service and the outputs, and the wallet's spend signatures cover that memo. The burn is bound to this one request, and only the note holder can authorize it.
4. If the burn succeeds, the ESP mint derives the keys for the terms and issues each output with `MintLogic::issue_with_key`. It uses that method and not `issue` because the key depends on the note's terms as well as its amount. See the docs on `MintLogic::issue_with_key` in mint-core.
5. It returns the signatures, the terms, and the public key for each amount.

Redemption is a separate step. Only the named service can redeem a note, only on or after the redeemable-after day, and the issuer refuses a melt before that day. The issuer also offers a verify call so a service can check a note it is handed.

## Left to do

- **The exchange.** Everything in "The exchange" above. It needs the PSP to run mintd's HTTP API in-process.
- **Retries.** If the process dies after the PSP notes are burned and before the signatures are returned, the wallet loses them. Storing the response by request hash would let a retry return the same signatures.
- **Redemption and the verify call.** Not started.
- **Master secret protection.** It is a plain file with `0600` permissions. How the real secret is protected is not decided.
- **Redeem window.** 365 days is a placeholder.
- **Exchange rate.** 1 ESP per PSP is a placeholder.

## Not decided yet

What happens to a note whose terms are not met, for example if the service had outages before redemption.
