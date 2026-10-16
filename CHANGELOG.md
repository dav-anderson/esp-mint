# Changelog

esp-mint 0.1.2 builds on `sp-wire` 0.2.0 (wire version 2) and mint-core 0.1.3. Nothing was recorded per version before this file; the section below is everything the README said about what was built and when.

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
