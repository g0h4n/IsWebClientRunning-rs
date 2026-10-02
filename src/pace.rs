//! Scan pacing: a tiny dependency-free PRNG for jitter sleeps and opsec target
//! shuffling.
//!
//! The probe is network-bound, so cryptographic randomness is pointless here —
//! all we want is an unpredictable, evenly-spread delay between connections and
//! a shuffled target order so a sweep does not march predictably up a subnet.
//! A `SplitMix64` generator seeded from the wall clock (plus a per-worker salt)
//! is plenty and keeps the crate free of a `rand` dependency in every build.

use std::time::{SystemTime, UNIX_EPOCH};

/// SplitMix64 — minimal, fast, good enough for pacing decisions.
pub struct Rng(u64);

impl Rng {
    /// Seed from an explicit value (mix it so nearby seeds diverge).
    pub fn seeded(seed: u64) -> Self {
        Rng(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    /// Seed from the current time plus a caller salt (e.g. a worker index), so
    /// each worker's jitter stream differs.
    pub fn from_time(salt: u64) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Rng::seeded(nanos ^ salt.wrapping_mul(0xD1B5_4A32_D192_ED03))
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[lo, hi]` (inclusive). `hi <= lo` yields `lo`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            lo
        } else {
            lo + self.next_u64() % (hi - lo + 1)
        }
    }
}

/// In-place Fisher–Yates shuffle, used by `--opsec` / `--shuffle` so the scan
/// order does not reveal a linear sweep.
pub fn shuffle<T>(items: &mut [T], rng: &mut Rng) {
    let n = items.len();
    for i in (1..n).rev() {
        let j = rng.range(0, i as u64) as usize;
        items.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_is_inclusive_and_bounded() {
        let mut r = Rng::seeded(42);
        for _ in 0..10_000 {
            let v = r.range(100, 200);
            assert!((100..=200).contains(&v));
        }
    }

    #[test]
    fn range_degenerate_returns_lo() {
        let mut r = Rng::seeded(1);
        assert_eq!(r.range(500, 500), 500);
        assert_eq!(r.range(900, 100), 900);
    }

    #[test]
    fn shuffle_preserves_multiset() {
        let mut r = Rng::seeded(7);
        let mut v: Vec<u32> = (0..100).collect();
        shuffle(&mut v, &mut r);
        let mut sorted = v.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..100).collect::<Vec<_>>());
        // Extremely unlikely to be identity after shuffling 100 items.
        assert_ne!(v, (0..100).collect::<Vec<_>>());
    }
}
