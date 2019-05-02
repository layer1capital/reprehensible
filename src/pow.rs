use crate::network_byte_order::Ne;
use crate::DatagramHead;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::mem::size_of;

#[derive(Clone)]
pub struct ProofOfWork {
    /// The time in nanoseconds when this proof of work was intended to be received.
    rx_time_nanos: u128,
    proof_of_work: u128,
}

impl ProofOfWork {
    /// Solve puzzle for prefix. Timstamp puzzle solution with current time.
    pub fn prove_work(difficulty: u32, prefix: &[u8]) -> ProofOfWork {
        debug_assert!(
            difficulty <= 64,
            "That's going a bit overboard. Don't you think?"
        );
        debug_assert_eq!(
            prefix.len(),
            size_of::<DatagramHead>(),
            "ProofOfWork is certainly cabable of tagging arbitrary length data, but you probably\
             meant to tag a datagram head."
        );

        let now = now_nanos();
        let pre = Sha256::new().chain(prefix).chain(now.to_ne());

        for proof_of_work in 0..std::u128::MAX {
            let puzzle_solution = proof_of_work.to_ne();
            if leading_zeros(
                &pre.clone()
                    .chain(puzzle_solution)
                    .result()
                    .as_slice()
                    .try_into()
                    .unwrap(),
            ) >= difficulty
            {
                return ProofOfWork {
                    rx_time_nanos: now,
                    proof_of_work,
                };
            }
        }
        panic!(
            "I've been at this for around 10^14 years. Humanity is probably long gone, time to rest."
        )
    }

    /// Create an empty proof of work tagged for now.
    pub fn no_work() -> ProofOfWork {
        ProofOfWork {
            rx_time_nanos: now_nanos(),
            proof_of_work: 0,
        }
    }
}

impl Ne for ProofOfWork {
    type B = [u8; 32];

    fn to_ne(self) -> Self::B {
        let mut ret: Self::B = [0u8; 32];
        {
            let (a, b) = ret.split_at_mut(16);
            a.copy_from_slice(&self.rx_time_nanos.to_ne());
            b.copy_from_slice(&self.proof_of_work.to_ne());
        }
        ret
    }

    fn from_ne_unchecked(src: &[u8]) -> Self {
        let (rx_time_nanos, rest) = u128::pick(src).unwrap();
        let (proof_of_work, rest) = u128::pick(rest).unwrap();
        debug_assert_eq!(rest.len(), 0);
        ProofOfWork {
            rx_time_nanos,
            proof_of_work,
        }
    }
}

pub fn score(inp: &[u8]) -> u32 {
    leading_zeros(
        &Sha256::new()
            .chain(inp)
            .result()
            .as_slice()
            .try_into()
            .unwrap(),
    )
}

fn leading_zeros(inp: &[u8; 32]) -> u32 {
    let mut ret = 0;
    for n in inp {
        if n == &0 {
            ret += 8;
        } else {
            ret += n.leading_zeros();
            break;
        }
    }
    return ret;
}

/// get current time in nanoseconds
fn now_nanos() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    (elapsed.as_secs() as u128) * 1_000_000 + (elapsed.subsec_nanos() as u128)
}
