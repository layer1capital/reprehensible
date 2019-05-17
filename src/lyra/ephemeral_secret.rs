use crate::common::xor;
use core::ops::BitXor;
use rust_sodium::crypto::secretbox::Key;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct EphemeralSecret([u8; 32]);

impl EphemeralSecret {
    pub fn random() -> EphemeralSecret {
        EphemeralSecret(rand::random())
    }
}

impl AsRef<[u8]> for EphemeralSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl BitXor for &EphemeralSecret {
    type Output = Key;
    fn bitxor(self, other: &EphemeralSecret) -> Self::Output {
        Key(xor(&self.0, &other.0))
    }
}
