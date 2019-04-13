use rust_sodium::crypto::box_::{
    gen_keypair, gen_nonce, open_precomputed, precompute, seal_precomputed, Nonce, PrecomputedKey,
    PublicKey, SecretKey,
};
use std::collections::BTreeMap;

#[derive(PartialEq, Eq, Ord, PartialOrd)]
struct U256(pub [u8; 32]);
#[derive(PartialEq, Eq, Ord, PartialOrd)]
struct PrivateKey(pub U256);

struct Datagram {
    peer_pk: PublicKey,
    nonce: Nonce,
    encrypted_payload: Vec<u8>,
}

/// A verified plaintext message from peer_pk
pub struct DatagramDecrypted {
    peer_pk: PublicKey,
    payload: Vec<u8>,
}

/// A reprehensible encrypted datagram sender/reciever with a cache of secret shared keys
pub struct Reprehensible {
    sk: SecretKey,
    shared_secret_cache: BTreeMap<PublicKey, PrecomputedKey>,
}

impl Reprehensible {
    /// Initialize reprehensible. sk is the secret key on which to listen
    pub fn create(sk: [u8; 32]) -> Reprehensible {
        Reprehensible {
            sk: as_sk(U256(sk)),
            shared_secret_cache: BTreeMap::new(),
        }
    }

    /// Recive a raw datagram, attempt to decrypt it.
    /// None will be returned if:
    /// - Datagram was not long enough to be valid.
    /// - Ciphertext failed verification.
    pub fn receive(&mut self, datagram: &[u8]) -> Option<DatagramDecrypted> {
        let dg = parse_datagram(datagram)?;
        let shared_secret = self.dh(&dg.peer_pk);
        let payload = open_precomputed(&dg.encrypted_payload, &dg.nonce, &shared_secret).ok()?;
        Some(DatagramDecrypted {
            peer_pk: dg.peer_pk,
            payload,
        })
    }

    /// Create a new datagram with self as sender and peer_pk as recipient.
    pub fn send(&mut self, peer_pk: PublicKey, message: &[u8]) -> Vec<u8> {
        let shared_secret = self.dh(&peer_pk);
        let nonce = gen_nonce();
        let encrypted_payload = seal_precomputed(message, &nonce, &shared_secret);
        Datagram {
            peer_pk: self.sk.public_key(),
            nonce,
            encrypted_payload,
        }
        .serialize()
    }

    fn dh(&mut self, peer_pk: &PublicKey) -> &PrecomputedKey {
        let sk = self.sk.clone();
        self.shared_secret_cache
            .entry(*peer_pk)
            .or_insert_with(|| precompute(&peer_pk, &sk))
    }
}

impl Datagram {
    fn serialize(self) -> Vec<u8> {
        let Datagram {
            peer_pk,
            nonce,
            mut encrypted_payload,
        } = self;
        let retlen = 32 + 24 + encrypted_payload.len();
        let mut ret = Vec::with_capacity(retlen);
        for b in peer_pk.as_ref() {
            ret.push(*b);
        }
        for b in nonce.as_ref() {
            ret.push(*b);
        }
        ret.append(&mut encrypted_payload);
        debug_assert_eq!(ret.len(), retlen);
        ret
    }
}

fn cat_u8_32s(a: &[u8; 32], b: &[u8; 32]) -> [u8; 64] {
    let mut ret = [0u8; 64];
    (&mut ret)[..32].copy_from_slice(a);
    (&mut ret)[32..].copy_from_slice(b);
    ret
}

fn parse_datagram(datagram: &[u8]) -> Option<Datagram> {
    let (peer_pk, rest) = take_u256(datagram)?;
    let (nonce, encrypted_payload) = take_nonce(rest)?;
    let peer_pk = as_pk(peer_pk);
    let encrypted_payload = encrypted_payload.to_vec();
    Some(Datagram {
        peer_pk,
        nonce,
        encrypted_payload,
    })
}

fn take_u256(slice: &[u8]) -> Option<(U256, &[u8])> {
    if slice.len() < 32 {
        None
    } else {
        let (head, rest) = slice.split_at(32);
        let mut ar: [u8; 32] = [0u8; 32];
        ar.copy_from_slice(head);
        Some((U256(ar), rest))
    }
}

fn take_nonce(slice: &[u8]) -> Option<(Nonce, &[u8])> {
    debug_assert_eq!(std::mem::size_of::<Nonce>(), 24);
    if slice.len() < 24 {
        None
    } else {
        let (head, rest) = slice.split_at(24);
        let nonce = Nonce::from_slice(head);
        debug_assert!(nonce.is_some());
        Some((nonce?, rest))
    }
}

fn as_pk(a: U256) -> PublicKey {
    debug_assert_eq!(std::mem::size_of::<PublicKey>(), 32);
    PublicKey::from_slice(&a.0).unwrap()
}

fn as_sk(a: U256) -> SecretKey {
    debug_assert_eq!(std::mem::size_of::<SecretKey>(), 32);
    SecretKey::from_slice(&a.0).unwrap()
}

fn as_u256(sk: SecretKey) -> U256 {
    debug_assert_eq!(std::mem::size_of::<SecretKey>(), 32);
    U256(sk.0)
}

/// Generate a random secret key on which to listen
pub fn random_sk() -> [u8; 32] {
    (gen_keypair().1).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_attack() {
        // problem:
        // since the server and the client both send and receive using the same shared key
        // a message redirected to self will be accepted
        unimplemented!()
    }

    #[test]
    fn retransmit_attack() {
        // problem:
        // since datagrams are unordered, retransmitted datagrams will be accepted
        unimplemented!()
    }

    #[test]
    fn client_server() {
        let mut server = Reprehensible::create(random_sk());
        let mut client = Reprehensible::create(random_sk());
        let server_pub = server.sk.public_key();
        let client_pub = client.sk.public_key();
        let datagram = client.send(server_pub, b"hello");
        let datagram_decrypted = server.receive(&datagram).unwrap();
        assert_eq!(datagram_decrypted.peer_pk, client_pub);
        assert_eq!(&datagram_decrypted.payload, b"hello");
    }

    #[test]
    fn cat() {
        assert_eq!(
            cat_u8_32s(
                &[
                    0x04, 0x16, 0xdf, 0x97, 0xc1, 0xee, 0x2c, 0xa8, 0xa1, 0x98, 0xf5, 0x0a, 0x86,
                    0x2e, 0x3b, 0x62, 0xea, 0x95, 0xa3, 0xb2, 0x30, 0x96, 0xcd, 0x44, 0x9f, 0x32,
                    0x02, 0xc9, 0x4c, 0x73, 0xbb, 0xb3
                ],
                &[
                    0x1f, 0xf7, 0x10, 0xe8, 0x0a, 0xd6, 0xc2, 0xdf, 0x06, 0x97, 0x61, 0x1e, 0x52,
                    0xe6, 0x43, 0x1c, 0xed, 0xe0, 0x68, 0xd4, 0x94, 0x49, 0xff, 0x93, 0x4c, 0x56,
                    0xf3, 0x1f, 0xd6, 0x61, 0x53, 0xa4
                ]
            )[..],
            [
                0x04, 0x16, 0xdf, 0x97, 0xc1, 0xee, 0x2c, 0xa8, 0xa1, 0x98, 0xf5, 0x0a, 0x86, 0x2e,
                0x3b, 0x62, 0xea, 0x95, 0xa3, 0xb2, 0x30, 0x96, 0xcd, 0x44, 0x9f, 0x32, 0x02, 0xc9,
                0x4c, 0x73, 0xbb, 0xb3, 0x1f, 0xf7, 0x10, 0xe8, 0x0a, 0xd6, 0xc2, 0xdf, 0x06, 0x97,
                0x61, 0x1e, 0x52, 0xe6, 0x43, 0x1c, 0xed, 0xe0, 0x68, 0xd4, 0x94, 0x49, 0xff, 0x93,
                0x4c, 0x56, 0xf3, 0x1f, 0xd6, 0x61, 0x53, 0xa4
            ][..]
        );
    }

    #[test]
    fn sk_to_pk_deterministic() {
        let rep = gen_keypair().1;
        assert_eq!(rep.public_key(), rep.public_key());
    }

    #[test]
    fn impersonate() {
        // send a message to self, using own public key
        let mut server = Reprehensible::create(random_sk());
        let server_pub = server.sk.public_key();
        let datagram = server.send(server_pub, b"hello");
        let datagram_decrypted = server.receive(&datagram).unwrap();
        assert_eq!(datagram_decrypted.peer_pk, server_pub);
        assert_eq!(&datagram_decrypted.payload, b"hello");
    }

    #[test]
    fn random_pk() {
        use rust_sodium::crypto::box_;

        let our_sk = [
            0x04, 0x16, 0xdf, 0x97, 0xc1, 0xee, 0x2c, 0xa8, 0xa1, 0x98, 0xf5, 0x0a, 0x86, 0x2e,
            0x3b, 0x62, 0xea, 0x95, 0xa3, 0xb2, 0x30, 0x96, 0xcd, 0x44, 0x9f, 0x32, 0x02, 0xc9,
            0x4c, 0x73, 0xbb, 0xb3,
        ];
        let their_sk = [
            0x1f, 0xf7, 0x10, 0xe8, 0x0a, 0xd6, 0xc2, 0xdf, 0x06, 0x97, 0x61, 0x1e, 0x52, 0xe6,
            0x43, 0x1c, 0xed, 0xe0, 0x68, 0xd4, 0x94, 0x49, 0xff, 0x93, 0x4c, 0x56, 0xf3, 0x1f,
            0xd6, 0x61, 0x53, 0xa4,
        ];

        let oursk = SecretKey(our_sk);
        let ourpk = oursk.public_key();
        let theirsk = SecretKey(their_sk);
        let theirpk = theirsk.public_key();
        let nonce = box_::gen_nonce();
        let plaintext = b"some data";
        let ciphertext = box_::seal(plaintext, &nonce, &theirpk, &oursk);
        let their_plaintext = box_::open(&ciphertext, &nonce, &ourpk, &theirsk).unwrap();
        assert!(plaintext == &their_plaintext[..]);
    }
}
