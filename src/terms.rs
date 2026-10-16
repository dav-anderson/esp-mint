use secp256k1::XOnlyPublicKey;

pub const SECONDS_PER_DAY: u64 = 86_400;
/// The default for how many days after issue a note becomes redeemable
/// (`terms.maturity_days`).
pub const REDEEM_WINDOW_DAYS: u64 = 365;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Terms {
    pub service: XOnlyPublicKey,
    pub redeemable_after_day: u64,
}

impl Terms {
    /// Terms for a note issued at `now_unix`, redeemable after the default window.
    pub fn new_at(service: XOnlyPublicKey, now_unix: u64) -> Self {
        Self::new_at_days(service, now_unix, REDEEM_WINDOW_DAYS)
    }

    /// Terms for a note issued at `now_unix`, redeemable after `maturity_days`
    /// (the mint's `terms.maturity_days`).
    pub fn new_at_days(service: XOnlyPublicKey, now_unix: u64, maturity_days: u64) -> Self {
        Self {
            service,
            redeemable_after_day: (now_unix / SECONDS_PER_DAY).saturating_add(maturity_days),
        }
    }

    pub fn is_redeemable_at(&self, now_unix: u64) -> bool {
        now_unix / SECONDS_PER_DAY >= self.redeemable_after_day
    }

    pub fn to_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.service.serialize());
        out[32..].copy_from_slice(&self.redeemable_after_day.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn service() -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(&hex::decode(G_X).unwrap()).unwrap()
    }

    #[test]
    fn window_is_365_days_from_the_day_of_issue() {
        let terms = Terms::new_at(service(), 1_791_571_184);
        assert_eq!(terms.redeemable_after_day, 20_735 + 365);
        assert_eq!(terms.redeemable_after_day, 21_100);
    }

    #[test]
    fn the_window_can_be_set() {
        let terms = Terms::new_at_days(service(), 1_791_571_184, 30);
        assert_eq!(terms.redeemable_after_day, 20_735 + 30);
        let now = Terms::new_at_days(service(), 1_791_571_184, 0);
        assert_eq!(now.redeemable_after_day, 20_735);
        assert!(now.is_redeemable_at(1_791_571_184));
        assert_eq!(
            Terms::new_at_days(service(), 1_791_571_184, REDEEM_WINDOW_DAYS),
            Terms::new_at(service(), 1_791_571_184)
        );
    }

    #[test]
    fn time_of_day_does_not_change_the_terms() {
        let midnight = 20_735 * SECONDS_PER_DAY;
        let a = Terms::new_at(service(), midnight);
        let b = Terms::new_at(service(), midnight + SECONDS_PER_DAY - 1);
        assert_eq!(a, b);
        assert_ne!(a, Terms::new_at(service(), midnight + SECONDS_PER_DAY));
    }

    #[test]
    fn redeemable_from_the_start_of_the_day() {
        let terms = Terms::new_at(service(), 1_791_571_184);
        let start = terms.redeemable_after_day * SECONDS_PER_DAY;
        assert!(!terms.is_redeemable_at(0));
        assert!(!terms.is_redeemable_at(1_791_571_184));
        assert!(!terms.is_redeemable_at(start - 1));
        assert!(terms.is_redeemable_at(start));
        assert!(terms.is_redeemable_at(start + 10 * SECONDS_PER_DAY));
    }

    #[test]
    fn bytes_are_service_then_big_endian_day() {
        let bytes = Terms::new_at(service(), 1_791_571_184).to_bytes();
        assert_eq!(hex::encode(&bytes[..32]), G_X);
        assert_eq!(&bytes[32..], &21_100u64.to_be_bytes());
    }
}
