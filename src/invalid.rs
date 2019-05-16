use crate::common::DeserializeFailed;

/// Reason for failure
///
/// A deserialization error does not indicate that decryption would have succeeded.
/// It's possible to get a deserialization error on unverified data.
#[derive(PartialEq, Clone, Debug)]
pub enum Invalid {
    Decryption,
    Deserialization,
}

impl From<DeserializeFailed> for Invalid {
    fn from(df: DeserializeFailed) -> Self {
        let DeserializeFailed {} = df;
        Invalid::Decryption
    }
}
