use crate::pow;
use rust_sodium::crypto::box_::PublicKey;

/// Some bytes prepended to a datagram. Tags a source public key and a destination public key
/// with a timestamp.

#[derive(Clone, Debug)]
pub struct PowHeader {
    /// Time when proof of work was computed
    pub pow_time_nanos: u128,
    /// applied to destination_pk, source_pk, and pow_time_nanos; not the rest of the datagram
    /// can be reused in future packets
    pub proof_of_work: u128,
}

impl PowHeader {
    /// set the proof of work fields for this datagram.
    /// proof_of_work should mark (source_pk, destination_pk) and (destination_pk, source_pk).
    pub fn prove_work(
        source_pk: &PublicKey,
        destination_pk: &PublicKey,
        pow_time_nanos: u128,
        difficulty: u32,
    ) -> Self {
        let proof_of_work = pow::prove_work(source_pk, destination_pk, pow_time_nanos, difficulty);
        PowHeader {
            pow_time_nanos,
            proof_of_work,
        }
    }

    pub fn pow_score(&self, source_pk: &PublicKey, destination_pk: &PublicKey) -> u32 {
        pow::score(
            destination_pk,
            source_pk,
            self.pow_time_nanos,
            self.proof_of_work,
        )
    }
}
