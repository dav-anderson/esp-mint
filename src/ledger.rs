//! The per-day ledger: ESP issued and redeemed, by redeemable-after day.
//!
//! mint-core counts what a key set issued and burned, and `/audit` adds the
//! counters up. They say how much ESP is outstanding, but not when it can be
//! redeemed. A note's day is part of its terms (see `terms`), and the mint sees
//! it each time it signs or burns a note, so the mint can keep the split itself.
//! That is this ledger: for each day, the ESP units signed under it (`issued`)
//! and burned under it (`redeemed`). What is outstanding for a day is the
//! difference. A day that has come by the mint's clock is *matured*, the rest
//! are *unmatured*, which is what the operator needs to know to plan payouts.
//!
//! **Where it is kept, and why that is safe.** The ledger lives in the stored
//! responses file (`responses`), in the same JSON document as the entries, so
//! one atomic write (temporary file, fsync, rename, directory fsync) replaces
//! both. A request's movements are applied in the very write that turns its
//! entry into the finished one, and only if the entry was not finished before.
//! So a crash can not leave a request counted without being finished, and a
//! retry of a finished request is answered from the entry and counts nothing
//! twice. A torn write leaves the old file whole, ledger included, because the
//! rename never happened.
//!
//! The movements are fixed by the request, not by what was signed or burned
//! before a crash: the whole request is counted once, at the end. mint-core's
//! counters move as each note is signed or burned. So while a request is
//! unfinished the two disagree by what it has done so far, and `/audit` says how
//! many requests are unfinished.
//!
//! **What counts.**
//!
//! | event | movements |
//! |---|---|
//! | exchange finished | `issued` += the outputs, under the exchange's day |
//! | transfer finished | `redeemed` += the inputs and `issued` += the outputs, under the notes' day; the difference is the fee |
//! | redemption finished | `redeemed` += each burned note, under its own day; `issued` += each refund output, under its own day |
//! | decline | `issued` += each decline output, under its own day (once per queue entry) |
//! | rollover | nothing: it moves notes to the current key set under the same terms |
//!
//! The exchange fee is paid in PSP on top of the outputs and is never ESP, so it
//! is not issued. The redemption fee and the payout come out of burned notes and
//! are not reissued, so they stay out of `issued`.
//!
//! **History before 0.5.0 is not in it.** The responses of earlier versions do
//! not keep the amounts or the days of what they signed, so the ledger starts
//! empty on an existing mint and counts from the upgrade on. [`Ledger::split`]
//! gives the split of what it knows, and `/audit` reports the rest as
//! `outstanding_unsplit`: what the counters say is outstanding beyond that. It
//! shrinks as the old notes are redeemed, and is zero on a mint that has run
//! 0.5.0 from its first note.
//!
//! A day is counted only while it is ahead (issued more than redeemed). A day
//! that is behind means notes from before the ledger were redeemed or reissued
//! under it; those come out of the unsplit part, so they are not subtracted from
//! the known part of another day.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sp_wire::dec;

use crate::terms::SECONDS_PER_DAY;

/// What one redeemable-after day has issued and redeemed, in ESP units.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Day {
    #[serde(with = "dec")]
    pub issued: u128,
    #[serde(with = "dec")]
    pub redeemed: u128,
}

impl Day {
    /// Issued minus redeemed. Negative for a day whose notes were issued before
    /// the ledger began.
    pub fn net(&self) -> i128 {
        i128::try_from(self.issued)
            .unwrap_or(i128::MAX)
            .saturating_sub(i128::try_from(self.redeemed).unwrap_or(i128::MAX))
    }
}

/// What a request changes, by day. Built by the request as it finishes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Movements {
    days: BTreeMap<u64, Day>,
}

impl Movements {
    pub fn new() -> Self {
        Self::default()
    }

    /// `units` of ESP signed under `day`.
    pub fn issue(&mut self, day: u64, units: u128) -> &mut Self {
        let d = self.days.entry(day).or_default();
        d.issued = d.issued.saturating_add(units);
        self
    }

    /// `units` of ESP burned under `day`.
    pub fn redeem(&mut self, day: u64, units: u128) -> &mut Self {
        let d = self.days.entry(day).or_default();
        d.redeemed = d.redeemed.saturating_add(units);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.days.is_empty()
    }

    pub fn days(&self) -> impl Iterator<Item = (&u64, &Day)> + '_ {
        self.days.iter()
    }
}

/// The ledger as it is stored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// By redeemable-after day.
    #[serde(default)]
    days: BTreeMap<u64, Day>,
    /// The queue entries whose decline has been counted. A decline is signed and
    /// then marked in the queue file, a different file, so it cannot be counted
    /// by the same write as its mark; it is counted by this id instead, and a
    /// decline run again after a crash counts nothing twice.
    #[serde(default)]
    declined: BTreeSet<String>,
}

/// The ledger's split of the outstanding ESP at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Split {
    /// Outstanding under days that have come.
    pub matured: u128,
    /// Outstanding under days still ahead.
    pub unmatured: u128,
}

/// Whether `day` has come by the clock at `now_unix`. The rule is the one the
/// mint applies to a note (`Terms::is_redeemable_at`): the day of `now_unix`
/// is at or past the note's day.
pub fn has_matured(day: u64, now_unix: u64) -> bool {
    now_unix / SECONDS_PER_DAY >= day
}

impl Ledger {
    /// Add `movements`.
    pub(crate) fn apply(&mut self, movements: &Movements) {
        for (day, m) in movements.days() {
            let d = self.days.entry(*day).or_default();
            d.issued = d.issued.saturating_add(m.issued);
            d.redeemed = d.redeemed.saturating_add(m.redeemed);
        }
    }

    /// Add `movements` for the decline of queue entry `id`, unless it has been
    /// counted. Returns whether it was added.
    pub(crate) fn apply_decline(&mut self, id: &str, movements: &Movements) -> bool {
        if !self.declined.insert(id.to_string()) {
            return false;
        }
        self.apply(movements);
        true
    }

    /// Whether the decline of `id` has been counted.
    pub fn decline_counted(&self, id: &str) -> bool {
        self.declined.contains(id)
    }

    /// What `day` has issued and redeemed.
    pub fn day(&self, day: u64) -> Day {
        self.days.get(&day).copied().unwrap_or_default()
    }

    /// The days the ledger has seen, oldest first.
    pub fn days(&self) -> impl Iterator<Item = (&u64, &Day)> + '_ {
        self.days.iter()
    }

    /// The outstanding ESP the ledger knows, split by whether its day has come
    /// at `now_unix`. A day that is behind counts as nothing (see the module
    /// documentation).
    pub fn split(&self, now_unix: u64) -> Split {
        let mut split = Split {
            matured: 0,
            unmatured: 0,
        };
        for (day, d) in &self.days {
            let net = d.net();
            if net <= 0 {
                continue;
            }
            let net = net as u128;
            if has_matured(*day, now_unix) {
                split.matured = split.matured.saturating_add(net);
            } else {
                split.unmatured = split.unmatured.saturating_add(net);
            }
        }
        split
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = SECONDS_PER_DAY;

    fn moves(f: impl FnOnce(&mut Movements)) -> Movements {
        let mut m = Movements::new();
        f(&mut m);
        m
    }

    #[test]
    fn a_day_is_matured_from_the_start_of_its_day_and_not_before() {
        assert!(!has_matured(10, 10 * DAY - 1));
        assert!(has_matured(10, 10 * DAY));
        assert!(has_matured(10, 11 * DAY));
        assert!(has_matured(0, 0));
    }

    #[test]
    fn the_rule_is_the_one_the_mint_applies_to_a_note() {
        use crate::terms::Terms;
        let key = sp_wire::ServiceDid::parse(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        for day in [0u64, 1, 20_000, 21_100] {
            let terms = Terms {
                service: key,
                redeemable_after_day: day,
            };
            for now in [0, day * DAY, (day * DAY).saturating_sub(1), (day + 1) * DAY] {
                assert_eq!(has_matured(day, now), terms.is_redeemable_at(now));
            }
        }
    }

    #[test]
    fn movements_add_up_by_day() {
        let mut l = Ledger::default();
        l.apply(&moves(|m| {
            m.issue(5, 100).issue(5, 50).issue(9, 7).redeem(5, 30);
        }));
        l.apply(&moves(|m| {
            m.redeem(5, 20);
        }));
        assert_eq!(
            l.day(5),
            Day {
                issued: 150,
                redeemed: 50
            }
        );
        assert_eq!(l.day(5).net(), 100);
        assert_eq!(l.day(9).net(), 7);
        assert_eq!(l.day(77), Day::default());
    }

    #[test]
    fn the_split_follows_the_clock_across_a_day_boundary() {
        let mut l = Ledger::default();
        l.apply(&moves(|m| {
            m.issue(10, 100).issue(11, 40).redeem(10, 25);
        }));
        let before = l.split(10 * DAY - 1);
        assert_eq!((before.matured, before.unmatured), (0, 115));
        let on_ten = l.split(10 * DAY);
        assert_eq!((on_ten.matured, on_ten.unmatured), (75, 40));
        let on_eleven = l.split(11 * DAY);
        assert_eq!((on_eleven.matured, on_eleven.unmatured), (115, 0));
    }

    #[test]
    fn a_day_that_is_behind_counts_as_nothing_and_takes_nothing_from_another() {
        let mut l = Ledger::default();
        // Notes from before the ledger were redeemed under day 10.
        l.apply(&moves(|m| {
            m.redeem(10, 60).issue(11, 40);
        }));
        let s = l.split(20 * DAY);
        assert_eq!((s.matured, s.unmatured), (40, 0));
        assert_eq!(l.day(10).net(), -60);
    }

    #[test]
    fn a_decline_is_counted_once_per_entry() {
        let mut l = Ledger::default();
        let m = moves(|m| {
            m.issue(10, 30);
        });
        assert!(!l.decline_counted("e1"));
        assert!(l.apply_decline("e1", &m));
        assert!(l.decline_counted("e1"));
        assert!(!l.apply_decline("e1", &m));
        assert_eq!(l.day(10).issued, 30);
        assert!(l.apply_decline("e2", &m));
        assert_eq!(l.day(10).issued, 60);
    }

    #[test]
    fn it_reads_back_what_it_wrote_with_amounts_beyond_u64() {
        let mut l = Ledger::default();
        let big = u128::from(u64::MAX) * 4;
        l.apply(&moves(|m| {
            m.issue(3, big).redeem(3, 1);
        }));
        l.apply_decline("e1", &Movements::new());
        let text = serde_json::to_string(&l).unwrap();
        let back: Ledger = serde_json::from_str(&text).unwrap();
        assert_eq!(back, l);
        assert_eq!(back.day(3).issued, big);
    }
}
