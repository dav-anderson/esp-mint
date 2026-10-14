//! Units.
//!
//! - PSP is worth 1 USD a unit.
//! - ESP and FSP are worth 10^-12 USD a unit.
//! - 1 PSP = 10^12 ESP, and ESP to FSP is 1:1.
//!
//! Amounts are `u64`, so one note is worth at most `u64::MAX` units, about
//! $18.4 million of ESP or FSP. A request can hold many notes, so every sum and
//! every PSP-to-ESP conversion is done in `u128` and never wraps.

/// ESP units in one PSP unit.
pub const ESP_PER_PSP: u64 = 1_000_000_000_000;

/// The most PSP whose ESP value still fits in one `u64` note (18,446,744).
pub const MAX_PSP_PER_NOTE: u64 = u64::MAX / ESP_PER_PSP;

/// The ESP value of a PSP amount. The largest result, for `u64::MAX` PSP, is
/// about 1.8e31, which fits in `u128`.
pub fn psp_to_esp(psp: u64) -> u128 {
    u128::from(psp) * u128::from(ESP_PER_PSP)
}

/// The sum of amounts. A `u128` cannot overflow by adding `u64` values unless
/// there are 2^64 of them.
pub fn total(amounts: impl IntoIterator<Item = u64>) -> u128 {
    amounts.into_iter().map(u128::from).sum()
}

/// A sum as one note's amount, or `None` if it is more than `u64::MAX`.
pub fn as_note_amount(units: u128) -> Option<u64> {
    u64::try_from(units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_psp_is_ten_to_the_twelfth_esp() {
        assert_eq!(ESP_PER_PSP, 10u64.pow(12));
        assert_eq!(psp_to_esp(0), 0);
        assert_eq!(psp_to_esp(1), 1_000_000_000_000);
        assert_eq!(psp_to_esp(1_048_576), 1_048_576_000_000_000_000);
    }

    #[test]
    fn the_largest_psp_that_fits_one_note_is_18_446_744() {
        assert_eq!(MAX_PSP_PER_NOTE, 18_446_744);
        let at_limit = psp_to_esp(MAX_PSP_PER_NOTE);
        assert_eq!(at_limit, 18_446_744_000_000_000_000);
        assert_eq!(as_note_amount(at_limit), Some(18_446_744_000_000_000_000));
    }

    #[test]
    fn one_psp_more_does_not_fit_one_note() {
        let over = psp_to_esp(MAX_PSP_PER_NOTE + 1);
        assert_eq!(over, 18_446_745_000_000_000_000);
        assert!(over > u128::from(u64::MAX));
        assert_eq!(as_note_amount(over), None);
    }

    #[test]
    fn converting_the_largest_psp_does_not_overflow() {
        assert_eq!(
            psp_to_esp(u64::MAX),
            u128::from(u64::MAX) * 1_000_000_000_000u128
        );
    }

    #[test]
    fn a_note_amount_is_exactly_the_u64_range() {
        assert_eq!(as_note_amount(0), Some(0));
        assert_eq!(as_note_amount(u128::from(u64::MAX)), Some(u64::MAX));
        assert_eq!(as_note_amount(u128::from(u64::MAX) + 1), None);
        assert_eq!(as_note_amount(u128::MAX), None);
    }

    #[test]
    fn sums_do_not_wrap_at_the_limit() {
        assert_eq!(total([]), 0);
        assert_eq!(total([1, 2, 3]), 6);
        assert_eq!(total([u64::MAX]), u128::from(u64::MAX));
        assert_eq!(total([u64::MAX, 1]), u128::from(u64::MAX) + 1);
        assert_eq!(total([u64::MAX, u64::MAX]), 2 * u128::from(u64::MAX));
        // a batch whose total no longer fits one note is still summed exactly
        let sum = total([u64::MAX / 2 + 1, u64::MAX / 2 + 1]);
        assert_eq!(sum, 1u128 << 64);
        assert_eq!(as_note_amount(sum), None);
    }

    #[test]
    fn a_thousand_full_notes_sum_exactly() {
        assert_eq!(total(vec![u64::MAX; 1000]), 1000 * u128::from(u64::MAX));
    }
}
