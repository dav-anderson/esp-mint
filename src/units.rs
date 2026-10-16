//! Units. The constants and the conversions live in `sp-wire`, so the mints and
//! the wallet share one definition; this re-exports them and the paths are
//! unchanged. The rate is `ESP_PER_PSP` there: 10 PSP = 1 USD = 10^12 ESP.

pub use sp_wire::units::*;

/// The `code` in a refusal for an amount that is not a power of two.
pub const BAD_DENOMINATION: &str = "bad_denomination";

/// Whether `units` is an ESP note size: a power of two. Zero is not one. Every
/// route that signs ESP, and every ESP note it accepts, is held to this, so that
/// notes of one size look alike (the same rule as PSP and FSP).
pub fn is_denomination(units: u64) -> bool {
    units.is_power_of_two()
}
