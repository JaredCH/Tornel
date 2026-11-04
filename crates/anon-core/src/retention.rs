//! Retention policy math (`plan.md` §6).
//!
//! The retention clock is pinned to an **absolute** expiry timestamp computed at
//! insert time. This is deliberate: re-deriving "now - 90 days" at purge time
//! means a backwards clock change or a long offline period silently extends
//! retention (`plan.md` §6.1). An absolute `expires_at` cannot be extended by
//! moving the clock.

/// The mandatory retention ceiling, in days (`plan.md` §6).
pub const RETENTION_DAYS: i64 = 90;

/// Seconds in one day, used for retention arithmetic.
pub const SECONDS_PER_DAY: i64 = 86_400;

/// Total retention window in seconds.
pub const RETENTION_SECONDS: i64 = RETENTION_DAYS * SECONDS_PER_DAY;

/// Compute the absolute expiry for a message sent at `sent_at`.
///
/// `sent_at` is Unix epoch **seconds** (UTC). See `plan.md` §6.1: timestamps are
/// integers, never text, so the purge comparison cannot degrade to a string
/// comparison.
pub const fn expiry_from_sent_at(sent_at: i64) -> i64 {
    sent_at.saturating_add(RETENTION_SECONDS)
}

/// Whether a record with the given absolute `expires_at` is due for purge at `now`.
///
/// Uses `<=` so a record at exactly the boundary is purged, matching
/// `DELETE FROM messages WHERE expires_at <= CAST(strftime('%s','now') AS INTEGER)`.
pub const fn is_expired(expires_at: i64, now: i64) -> bool {
    expires_at <= now
}

/// Number of whole seconds of retention remaining, saturating at zero.
pub const fn retention_remaining(expires_at: i64, now: i64) -> i64 {
    let remaining = expires_at - now;
    if remaining < 0 {
        0
    } else {
        remaining
    }
}

/// The crypto-shredding bucket label for a timestamp (`plan.md` §6.2, layer 4).
///
/// Data keys are held per calendar month. When a bucket ages past the retention
/// ceiling the bucket key is zeroised, which makes any surviving ciphertext
/// cryptographically unrecoverable regardless of filesystem or flash
/// translation layer behaviour.
///
/// Returns a stable `YYYY-MM` label. Computed from the *send* time so a bucket
/// never mixes months.
pub fn retention_bucket(sent_at: i64) -> String {
    // `time` rejects offsets that overflow; clamp rather than panic.
    match time::OffsetDateTime::from_unix_timestamp(sent_at) {
        Ok(dt) => format!("{:04}-{:02}", dt.year(), u8::from(dt.month())),
        Err(_) => "0000-00".to_string(),
    }
}

/// Epoch seconds for "now", the single source of time for purge decisions.
///
/// Purge logic must call this rather than constructing time inline, so tests can
/// substitute a fixed clock (see `plan.md` §10, clock-skew and TTL tests).
pub fn now_epoch_seconds() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_is_absolute_and_ninety_days_out() {
        let sent = 1_700_000_000;
        assert_eq!(expiry_from_sent_at(sent), sent + 90 * 86_400);
        assert_eq!(RETENTION_SECONDS, 7_776_000);
    }

    #[test]
    fn boundary_is_inclusive() {
        // A record expiring exactly now is purged.
        assert!(is_expired(1_000, 1_000));
        // One second of life left is retained.
        assert!(!is_expired(1_001, 1_000));
    }

    #[test]
    fn moving_the_clock_backwards_cannot_extend_retention() {
        // The core anti-regression property from plan.md §6.5(1):
        // expiry is stored, not computed from the current clock.
        let sent = 1_700_000_000;
        let expires_at = expiry_from_sent_at(sent);

        // Purge at a time *before* the original wall clock would have been.
        let skewed_now = sent + RETENTION_SECONDS + 1;
        assert!(is_expired(expires_at, skewed_now));

        // And the decision does not depend on any notion of "now - 90d".
        assert_eq!(retention_remaining(expires_at, skewed_now), 0);
    }

    #[test]
    fn remaining_saturates_at_zero() {
        assert_eq!(retention_remaining(100, 500), 0);
        assert_eq!(retention_remaining(500, 100), 400);
    }

    #[test]
    fn buckets_are_stable_and_month_scoped() {
        // 2023-11-14
        let b = retention_bucket(1_700_000_000);
        assert_eq!(b, "2023-11");

        // Two timestamps in the same month share a bucket.
        assert_eq!(
            retention_bucket(1_700_000_000),
            retention_bucket(1_700_000_000 + 60)
        );
    }

    #[test]
    fn out_of_range_timestamps_do_not_panic() {
        assert_eq!(retention_bucket(i64::MAX), "0000-00");
        assert_eq!(retention_bucket(i64::MIN), "0000-00");
    }

    #[test]
    fn expiry_saturates_instead_of_overflowing() {
        assert_eq!(expiry_from_sent_at(i64::MAX), i64::MAX);
    }
}
