//! A password as the phone makes it (docs/agent-protocol.md, "What the phone makes"). The app has
//! its own generator; this one plays the phone in tests and keeps to the same rules.

use zeroize::Zeroizing;

use super::{CharSet, Reading, SYMBOLS};
use crate::Secret;

/// How often [`Reading::make`] starts again when a forced character would break
/// `max-consecutive`.
const TRIES: u32 = 100;

/// A random number below `n` (`n` > 0), without bias.
fn below(n: usize) -> usize {
    let n = n as u32;
    let zone = u32::MAX - u32::MAX % n;
    loop {
        let mut b = [0u8; 4];
        crate::random_bytes(&mut b);
        let v = u32::from_le_bytes(b);
        if v < zone {
            return (v % n) as usize;
        }
    }
}

fn pick(set: CharSet) -> char {
    set.chars().nth(below(set.len())).expect("a character")
}

impl Reading {
    /// A password that fits this reading, from the preferred characters (letters, digits and
    /// [`SYMBOLS`]) where the rules allow them, never with a space. `None` when the reading has a
    /// [`Reading::problem`], or no try kept to `max-consecutive`.
    pub fn make(&self) -> Option<Secret> {
        if self.problem().is_some() {
            return None;
        }
        let usable = self.allowed.usable();
        let preferred = match usable.intersect(
            CharSet::UPPER
                .union(CharSet::LOWER)
                .union(CharSet::DIGIT)
                .union(CharSet::of(SYMBOLS)),
        ) {
            p if p.is_empty() => usable,
            p => p,
        };
        let fill = if preferred.len() < 2 {
            usable
        } else {
            preferred
        };
        let length = self.length() as usize;
        let mut picks: Vec<CharSet> = if self.required.is_empty() {
            [
                CharSet::LOWER,
                CharSet::UPPER,
                CharSet::DIGIT,
                CharSet::of(SYMBOLS),
            ]
            .into_iter()
            .map(|class| class.intersect(preferred))
            .filter(|set| !set.is_empty())
            .collect()
        } else {
            self.required
                .iter()
                .map(|r| match r.intersect(preferred) {
                    p if p.is_empty() => r.usable(),
                    p => p,
                })
                .collect()
        };
        picks.truncate(length);
        (0..TRIES).find_map(|_| self.attempt(&picks, fill, length))
    }

    /// One try: each pick at a random place, the rest from `fill`, no run above
    /// `max-consecutive` where a choice is left.
    fn attempt(&self, picks: &[CharSet], fill: CharSet, length: usize) -> Option<Secret> {
        let mut places: Vec<Option<CharSet>> = vec![None; length];
        for &set in picks {
            let free: Vec<usize> = (0..length).filter(|&i| places[i].is_none()).collect();
            places[free[below(free.len())]] = Some(set);
        }
        let mut out = Zeroizing::new(String::with_capacity(length));
        let (mut run, mut last) = (0u32, None);
        for place in places {
            let mut set = place.unwrap_or(fill);
            if let (Some(max), Some(c)) = (self.max_consecutive, last)
                && run >= max
            {
                let without = set.without(c);
                if without.is_empty() {
                    return None;
                }
                set = without;
            }
            let c = pick(set);
            run = if Some(c) == last { run + 1 } else { 1 };
            last = Some(c);
            out.push(c);
        }
        let password = Secret::new(out.as_str());
        self.fits(password.expose()).then_some(password)
    }
}
