use crate::network_byte_order::Ne;
use rust_sodium::crypto::box_::PublicKey;
use sha2::{Digest, Sha256};
use std::convert::TryInto;

/// Order of public keys does not matter.
pub fn prove_work(
    pk_a: &PublicKey,
    pk_b: &PublicKey,
    pow_time_nanos: u128,
    difficulty: u32,
) -> u128 {
    debug_assert!(
        difficulty <= 64,
        "That's going a bit overboard. Don't you think?"
    );
    let pre = prefix_sha(pk_a, pk_b, pow_time_nanos);
    for n in (0..std::u128::MAX).map(Ne::to_ne) {
        if leading_zeros(&pre.clone().chain(n).result().as_slice().try_into().unwrap())
            >= difficulty
        {
            return u128::from_ne_unchecked(&n);
        }
    }
    panic!(
        "I've been at this for around 10^14 years. Humanity is probably long gone, time to rest."
    )
}

pub fn score(pk_a: &PublicKey, pk_b: &PublicKey, pow_time_nanos: u128, proof_of_work: u128) -> u32 {
    leading_zeros(
        prefix_sha(pk_a, pk_b, pow_time_nanos)
            .chain(proof_of_work.to_ne())
            .result()
            .as_slice()
            .try_into()
            .unwrap(),
    )
}

fn prefix_sha(pk_a: &PublicKey, pk_b: &PublicKey, pow_time_nanos: u128) -> Sha256 {
    let a_ne = pk_a.to_ne();
    let b_ne = pk_b.to_ne();
    let (pk0, pk1) = if a_ne > b_ne {
        (a_ne, b_ne)
    } else {
        (b_ne, a_ne)
    };
    Sha256::new()
        .chain(pk0)
        .chain(pk1)
        .chain(pow_time_nanos.to_ne())
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

#[cfg(test)]
mod tests {
    use super::*;
    use rust_sodium::crypto::box_::gen_keypair;

    const DIFFICULTY: u32 = 1;

    #[test]
    fn pow_associative() {
        let source_pk = gen_keypair().0;
        let destination_pk = gen_keypair().0;

        /// Proof of work is a pure function
        assert_eq!(
            prove_work(&source_pk, &destination_pk, 0, DIFFICULTY),
            prove_work(&source_pk, &destination_pk, 0, DIFFICULTY)
        );

        /// Proof of work is associative
        assert_eq!(
            prove_work(&source_pk, &destination_pk, 0, DIFFICULTY),
            prove_work(&destination_pk, &source_pk, 0, DIFFICULTY)
        );
    }
}
