use byteorder::{ByteOrder, NetworkEndian};
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
    for n in 0..std::u128::MAX {
        let nbs = to_ne(n);
        if leading_zeros(
            &pre.clone()
                .chain(nbs)
                .result()
                .as_slice()
                .try_into()
                .unwrap(),
        ) >= difficulty
        {
            return n;
        }
    }
    panic!(
        "I've been at this for around 10^14 years. Humanity is probably long gone, time to rest."
    )
}

pub fn score(pk_a: &PublicKey, pk_b: &PublicKey, pow_time_nanos: u128, proof_of_work: u128) -> u32 {
    leading_zeros(
        prefix_sha(pk_a, pk_b, pow_time_nanos)
            .chain(to_ne(proof_of_work))
            .result()
            .as_slice()
            .try_into()
            .unwrap(),
    )
}

fn prefix_sha(pk_a: &PublicKey, pk_b: &PublicKey, pow_time_nanos: u128) -> Sha256 {
    let a_ne = pk_to_ne(pk_a.clone());
    let b_ne = pk_to_ne(pk_b.clone());
    if a_ne > b_ne {
        Sha256::new().chain(a_ne).chain(b_ne)
    } else {
        Sha256::new().chain(b_ne).chain(a_ne)
    }
    .chain(to_ne(pow_time_nanos))
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

fn to_ne(n: u128) -> [u8; 16] {
    let mut ret = [0u8; 16];
    NetworkEndian::write_u128(&mut ret, n);
    ret
}

fn pk_to_ne(n: PublicKey) -> [u8; 32] {
    let mut bytes = n.0;
    if cfg!(target_endian = "little") {
        bytes.reverse();
    }
    bytes
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

        for t in 0..16 {
            /// Proof of work is associative
            assert_eq!(
                prove_work(&source_pk, &destination_pk, t, DIFFICULTY),
                prove_work(&destination_pk, &source_pk, t, DIFFICULTY)
            );
        }
    }

    #[test]
    fn pow_pure() {
        let source_pk = gen_keypair().0;
        let destination_pk = gen_keypair().0;

        for t in 0..16 {
            /// Proof of work is a pure function
            assert_eq!(
                prove_work(&source_pk, &destination_pk, t, DIFFICULTY),
                prove_work(&source_pk, &destination_pk, t, DIFFICULTY)
            );
        }
    }
}
