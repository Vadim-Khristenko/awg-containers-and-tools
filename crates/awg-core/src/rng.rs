//! Randomness behind a trait.
//!
//! Two reasons it is not just `rand::rng()` everywhere: the generator has
//! to be reproducible in tests (the timer invariants are checked across hundreds
//! of seeds), and the WASM build needs to plug in the browser's CSPRNG.

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;

/// Inclusive integer range plus raw byte fill.
pub trait Rng {
    /// Uniform in `[lo, hi]`. `hi < lo` yields `lo`.
    fn range(&mut self, lo: u32, hi: u32) -> u32;
    fn fill(&mut self, dst: &mut [u8]);
}

/// Cryptographically secure source — the only one used for real key material.
///
/// The source is the operating system's CSPRNG directly ([`SysRng`], which is
/// what rand called `OsRng` before 0.10), not the thread-local generator: a
/// 3.0 `HeaderProtectionKey` is key material, and key material has no business
/// coming out of a userspace ChaCha state that lives for the whole process.
pub struct SecureRng;

impl Rng for SecureRng {
    fn range(&mut self, lo: u32, hi: u32) -> u32 {
        if hi <= lo {
            return lo;
        }
        use rand::RngExt as _;
        // SysRng is fallible; UnwrapErr adapts it to the infallible trait the
        // range sampler wants. A host that cannot produce entropy must not
        // quietly get weak obfuscation parameters instead.
        UnwrapErr(SysRng).random_range(lo..=hi)
    }

    fn fill(&mut self, dst: &mut [u8]) {
        use rand::TryRng as _;
        SysRng
            .try_fill_bytes(dst)
            .expect("the operating system refused to provide entropy");
    }
}

/// Deterministic source for tests only.
///
/// Never use this for keys: it is a plain xorshift, chosen so the invariant
/// tests can sweep seeds without pulling in a seeded CSPRNG.
pub struct SeededRng(u64);

impl SeededRng {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(6364136223846793005).wrapping_add(1))
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

impl Rng for SeededRng {
    fn range(&mut self, lo: u32, hi: u32) -> u32 {
        if hi <= lo {
            return lo;
        }
        lo + (self.next() % ((hi - lo + 1) as u64)) as u32
    }

    fn fill(&mut self, dst: &mut [u8]) {
        for b in dst.iter_mut() {
            *b = (self.next() & 0xff) as u8;
        }
    }
}
