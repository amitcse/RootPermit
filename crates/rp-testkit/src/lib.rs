//! Test-only deterministic helpers for M1/M2/M3 conformance tests.
//!
//! Nothing in this crate is suitable for production identifiers, clocks, or
//! transport authorization. Its purpose is to make race and hostile-delivery
//! tests reproducible without wall-clock sleeps or randomness.

#![forbid(unsafe_code)]

/// Monotonic test clock measured in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeMonotonicClock {
    now_ns: u64,
}

impl FakeMonotonicClock {
    #[must_use]
    pub const fn at(now_ns: u64) -> Self {
        Self { now_ns }
    }

    #[must_use]
    pub const fn now_ns(self) -> u64 {
        self.now_ns
    }

    pub fn advance(&mut self, duration_ns: u64) {
        self.now_ns = self.now_ns.saturating_add(duration_ns);
    }

    pub fn set(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
    }
}

/// Deterministic non-cryptographic bytes for fixtures only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixtureBytes {
    state: u64,
}

impl FixtureBytes {
    #[must_use]
    pub const fn seeded(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_array<const N: usize>(&mut self) -> [u8; N] {
        let mut result = [0; N];
        for byte in &mut result {
            // xorshift64*; deterministic and explicitly not an entropy source.
            self.state ^= self.state >> 12;
            self.state ^= self.state << 25;
            self.state ^= self.state >> 27;
            self.state = self.state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            *byte = self.state as u8;
        }
        result
    }
}

/// Repeatable relay delivery mutations. Tests can apply this sequence to a
/// verified event stream to cover at-least-once duplication, drops, and reorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMutation {
    Deliver(usize),
    Duplicate(usize),
    Drop(usize),
}

/// Applies a hostile delivery script without ever changing the input values.
/// Invalid indices are ignored deliberately, allowing fuzz-style generated
/// scripts to remain total and deterministic.
#[must_use]
pub fn mutate_delivery<T: Clone>(input: &[T], script: &[DeliveryMutation]) -> Vec<T> {
    let mut output = Vec::new();
    for mutation in script {
        match *mutation {
            DeliveryMutation::Deliver(index) | DeliveryMutation::Duplicate(index) => {
                if let Some(value) = input.get(index) {
                    output.push(value.clone());
                    if matches!(*mutation, DeliveryMutation::Duplicate(_)) {
                        output.push(value.clone());
                    }
                }
            }
            DeliveryMutation::Drop(_) => {}
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_and_fixture_bytes_are_reproducible() {
        let mut clock = FakeMonotonicClock::at(4);
        clock.advance(6);
        assert_eq!(clock.now_ns(), 10);
        let mut first = FixtureBytes::seeded(42);
        let mut second = FixtureBytes::seeded(42);
        assert_eq!(first.next_array::<32>(), second.next_array::<32>());
    }

    #[test]
    fn hostile_delivery_can_duplicate_drop_and_reorder_without_mutation() {
        let values = ["first", "second", "third"];
        let output = mutate_delivery(
            &values,
            &[
                DeliveryMutation::Deliver(1),
                DeliveryMutation::Duplicate(0),
                DeliveryMutation::Drop(2),
                DeliveryMutation::Deliver(2),
            ],
        );
        assert_eq!(output, ["second", "first", "first", "third"]);
    }
}
