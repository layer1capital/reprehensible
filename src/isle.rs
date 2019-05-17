//! isle (randomly named)

use crate::common::SerializeFailed;
use crate::invalid::Invalid;
use crate::sealed::Sealed;
use rust_sodium::crypto::box_::{gen_keypair, PublicKey, SecretKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Isle provides:
/// |                      |         |
/// | -                    | -       |
/// | Encryption           | yes     |
/// | Authentication       | yes     |
/// | DOS Resistance       | no      |
/// | Forward Secrecy      | partial |
/// | Stateless Datagrams  | yes     |
/// | Ordering             | no      |
/// | Reliability          | no      |
/// | Multiplexing         | no      |
/// | Replay Protection    | no      |
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Isle<T>(Sealed<Sealed<T>>);

impl<T: Serialize + DeserializeOwned> Isle<T> {
    /// decrypt and verify mesage is from public key of inner layer
    /// return None if message is invalid or serialization fails
    /// The returned public key is the verified static public key of the source.
    pub fn open(self, destination_sk: &SecretKey) -> Result<(PublicKey, T), Invalid> {
        let inner_layer = self.0.open(destination_sk)?;
        let source_static_pk = inner_layer.source_pk().clone();
        let plaintext = inner_layer.open(destination_sk)?;
        Ok((source_static_pk, plaintext))
    }

    pub fn seal(
        destination_pk: &PublicKey,
        source_sk: &SecretKey,
        plaintext: &T, // It would be nice if this could take a reference somehow
    ) -> Result<Isle<T>, SerializeFailed> {
        let inner_layer = Sealed::seal(&destination_pk, &source_sk, plaintext)?;
        let outer_layer_result = Sealed::seal(&destination_pk, &gen_keypair().1, &inner_layer);
        debug_assert!(outer_layer_result.is_ok());
        Ok(Isle(outer_layer_result?))
    }
}
