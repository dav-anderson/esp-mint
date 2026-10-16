//! Sizes and fees for the exchange and the transfer.
//!
//! Both routes take JSON, so the length of the body says little about the work a
//! request is. Their optional per-byte fee is charged on the request's
//! **canonical size** instead: the number of bytes the same request would take
//! with every field at its fixed width. That size depends only on how many
//! notes and outputs the request has, so a wallet knows the fee before it picks
//! its output amounts and there is nothing to iterate on.
//!
//! | part | bytes | made of |
//! |---|---|---|
//! | one input (a note and its spend signature) | 146 | keyset 8, amount 8, nonce 33, note signature 33, spend signature 64 |
//! | one output | 41 | amount 8, blind nonce 33 |
//! | exchange, fixed part | 48 | service 32, output keyset 8, input count 4, output count 4 |
//! | transfer, fixed part | 120 | service 32, redeemable-after day 8, output keyset 8, input count 4, output count 4, service signature 64 |
//!
//! The fee is `rate × size`, in ESP units, at the rate in force when the request
//! is accepted. It is paid on top of the exact amount: the notes must be worth
//! the outputs plus the fee, and the request is checked as exact against that
//! total. By default the rate is 0 on both routes, so nothing changes.

/// One input: keyset 8, amount 8, nonce 33, note signature 33, spend signature 64.
pub const INPUT_BYTES: u64 = 146;
/// One output: amount 8, blind nonce 33.
pub const OUTPUT_BYTES: u64 = 41;
/// An exchange without its notes and outputs: service 32, output keyset 8 and
/// two counts of 4.
pub const EXCHANGE_FIXED_BYTES: u64 = 48;
/// A transfer without its notes and outputs: service 32, day 8, output keyset 8,
/// two counts of 4, service signature 64.
pub const TRANSFER_FIXED_BYTES: u64 = 120;

fn size(fixed: u64, inputs: usize, outputs: usize) -> u64 {
    fixed
        .saturating_add(INPUT_BYTES.saturating_mul(inputs as u64))
        .saturating_add(OUTPUT_BYTES.saturating_mul(outputs as u64))
}

/// The canonical size of an exchange with this many PSP notes and outputs.
pub fn exchange_size(inputs: usize, outputs: usize) -> u64 {
    size(EXCHANGE_FIXED_BYTES, inputs, outputs)
}

/// The canonical size of a transfer with this many notes and outputs.
pub fn transfer_size(inputs: usize, outputs: usize) -> u64 {
    size(TRANSFER_FIXED_BYTES, inputs, outputs)
}

/// `size × rate`, in ESP units. Saturates rather than wrapping, so an absurd
/// rate can only make a request unaffordable.
pub fn charge(size_bytes: u64, fee_per_byte: u128) -> u128 {
    u128::from(size_bytes).saturating_mul(fee_per_byte)
}

/// The rate a charge was made at, worked back from the fee and the size. Used
/// when a request is picked up again after a crash: its inputs and outputs fix
/// the fee it paid, and the rate follows from that, whatever the setting is now.
pub fn rate_of(fee_esp: u128, size_bytes: u64) -> u128 {
    fee_esp / u128::from(size_bytes.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_follow_the_fixed_widths() {
        assert_eq!(exchange_size(0, 0), 48);
        assert_eq!(exchange_size(1, 1), 48 + 146 + 41);
        assert_eq!(transfer_size(0, 0), 120);
        assert_eq!(transfer_size(3, 5), 120 + 3 * 146 + 5 * 41);
    }

    #[test]
    fn the_fee_is_rate_times_size_and_saturates() {
        assert_eq!(charge(219, 0), 0);
        assert_eq!(charge(219, 1_000), 219_000);
        assert_eq!(charge(u64::MAX, u128::MAX), u128::MAX);
    }

    #[test]
    fn the_rate_is_recovered_from_the_fee() {
        let size = exchange_size(2, 3);
        assert_eq!(rate_of(charge(size, 7), size), 7);
        assert_eq!(rate_of(0, size), 0);
        assert_eq!(rate_of(5, 0), 5);
    }
}
