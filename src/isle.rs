//! isle (randomly named)

use crate::common::SerializeFailed;
use crate::invalid::Invalid;
use crate::sealed::Sealed;
use rust_sodium::crypto::box_::{gen_keypair, PublicKey, SecretKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Isle provides:
/// |                      |     |
/// | -                    | -   |
/// | Encryption           | yes |
/// | Authentication       | yes |
/// | DOS Resistance       | no  |
/// | Half Forward Secrecy | yes |
/// | Forward Secrecy      | no  |
/// | Stateless Datagrams  | yes |
/// | Ordering             | no  |
/// | Reliability          | no  |
/// | Multiplexing         | no  |
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Isle<T>(Sealed<Sealed<(PublicKey, T)>>);

impl<T: Serialize + DeserializeOwned> Isle<T> {
    /// decrypt and verify mesage is from public key of inner layer
    /// return None if message is invalid or serialization fails
    /// The returned public key is the verified static public key of the source.
    pub fn open(self, destination_sk: &SecretKey) -> Result<(PublicKey, T), Invalid> {
        let source_ephemeral_pk = self.0.source_pk().clone();
        let inner_layer = self.0.open(destination_sk)?;
        let source_static_pk = inner_layer.source_pk().clone();
        let (claimed_source_ephemeral_pk, plaintext) = inner_layer.open(destination_sk)?;
        if source_ephemeral_pk != claimed_source_ephemeral_pk {
            Err(Invalid::Decryption)
        } else {
            Ok((source_static_pk, plaintext))
        }
    }

    pub fn seal(
        destination_pk: &PublicKey,
        source_sk: &SecretKey,
        plaintext: T, // It would be nice if this could take a reference somehow
    ) -> Result<Isle<T>, SerializeFailed> {
        let (source_ephmeral_pk, source_ephmeral_sk) = gen_keypair();
        let inner_layer = Sealed::seal(
            &destination_pk,
            &source_sk,
            &(source_ephmeral_pk, plaintext),
        )?;
        let outer_layer_result = Sealed::seal(&destination_pk, &source_ephmeral_sk, &inner_layer);
        debug_assert!(outer_layer_result.is_ok());
        Ok(Isle(outer_layer_result?))
    }
}
