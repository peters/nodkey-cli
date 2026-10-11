//! Deterministic random sources for test vectors. Never use these to seal real messages.

use hpke::rand_core::{TryCryptoRng, TryRng};
use sha2::{Digest, Sha256};

/// A reproducible stream: block `i` = SHA-256("nodkey/v1/vectors/rng" ‖ seed ‖ u64be(i)).
#[derive(Clone)]
pub struct DetRng {
    seed: Vec<u8>,
    counter: u64,
    block: [u8; 32],
    used: usize,
}

impl DetRng {
    /// A stream for `seed`.
    pub fn new(seed: &[u8]) -> Self {
        DetRng {
            seed: seed.to_vec(),
            counter: 0,
            block: [0; 32],
            used: 32,
        }
    }

    fn refill(&mut self) {
        let mut h = Sha256::new();
        h.update(b"nodkey/v1/vectors/rng");
        h.update(&self.seed);
        h.update(self.counter.to_be_bytes());
        self.block.copy_from_slice(&h.finalize());
        self.counter += 1;
        self.used = 0;
    }

    /// The next `N` bytes of the stream.
    pub fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.fill(&mut out);
        out
    }

    fn fill(&mut self, dst: &mut [u8]) {
        for b in dst {
            if self.used == 32 {
                self.refill();
            }
            *b = self.block[self.used];
            self.used += 1;
        }
    }
}

impl TryRng for DetRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_le_bytes(self.take()))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_le_bytes(self.take()))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(dst);
        Ok(())
    }
}

impl TryCryptoRng for DetRng {}

/// Replays fixed bytes (for example an RFC 9180 `ikmE`) and panics when they run out.
pub struct FixedRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl FixedRng {
    /// A source that yields exactly `bytes`.
    pub fn new(bytes: &[u8]) -> Self {
        FixedRng {
            bytes: bytes.to_vec(),
            pos: 0,
        }
    }
}

impl TryRng for FixedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.pos + dst.len();
        dst.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn det_rng_is_reproducible_and_seed_dependent() {
        let mut a = DetRng::new(b"x");
        let mut b = DetRng::new(b"x");
        let mut c = DetRng::new(b"y");
        let a1: [u8; 50] = a.take();
        assert_eq!(a1, b.take::<50>());
        assert_ne!(a1, c.take::<50>());
        // Reading in pieces gives the same stream.
        let mut d = DetRng::new(b"x");
        let d1: [u8; 7] = d.take();
        let d2: [u8; 43] = d.take();
        assert_eq!(&a1[..7], &d1);
        assert_eq!(&a1[7..], &d2);
    }
}
