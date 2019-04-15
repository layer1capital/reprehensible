use rust_sodium::crypto::box_::{
    gen_keypair, gen_nonce, open_precomputed, precompute, seal_precomputed, Nonce, PrecomputedKey,
    PublicKey, SecretKey,
};
use std::collections::BTreeMap;

#[derive(PartialEq, Eq, Ord, PartialOrd)]
struct U256(pub [u8; 32]);

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
    session_cache: BTreeMap<PublicKey, SessionKeys>,
}

impl Reprehensible {
    /// Initialize reprehensible. sk is the secret key used for both sending and receiving
    pub fn create(sk: [u8; 32]) -> Reprehensible {
        Reprehensible {
            sk: as_sk(U256(sk)),
            session_cache: BTreeMap::new(),
        }
    }

    /// Recive a raw datagram, attempt to decrypt it.
    /// None will be returned if:
    /// - Datagram was not long enough to be valid.
    /// - Ciphertext failed verification.
    /// When None is returned, The datagram should be silently ignored and dropped.
    pub fn receive(&mut self, datagram: &[u8]) -> Option<DatagramDecrypted> {
        let dg = parse_datagram(datagram)?;
        let payload = open_precomputed(
            &dg.encrypted_payload,
            &dg.nonce,
            &self.session_keys(&dg.peer_pk).receive,
        )
        .ok()?;
        Some(DatagramDecrypted {
            peer_pk: dg.peer_pk,
            payload,
        })
    }

    /// Create a new datagram with self as sender and peer_pk as recipient.
    pub fn send(&mut self, peer_pk: PublicKey, message: &[u8]) -> Vec<u8> {
        let nonce = gen_nonce();
        let encrypted_payload =
            seal_precomputed(message, &nonce, &self.session_keys(&peer_pk).send);
        Datagram {
            peer_pk: self.sk.public_key(),
            nonce,
            encrypted_payload,
        }
        .serialize()
    }

    /// Get secret shared between self and peer.
    /// Secret is expensive to derive, so it is cached for performance.
    /// TODO: benchmark to see if caching is worthwhile
    fn session_keys(&mut self, peer_pk: &PublicKey) -> &SessionKeys {
        let sk = self.sk.clone();
        self.session_cache
            .entry(*peer_pk)
            .or_insert_with(|| SessionKeys::compute(&sk, peer_pk))
    }
}

struct SessionKeys {
    send: PrecomputedKey,
    receive: PrecomputedKey,
}

impl SessionKeys {
    fn compute(self_sk: &SecretKey, peer_pk: &PublicKey) -> SessionKeys {
        let shared_secret = precompute(peer_pk, self_sk);
        SessionKeys {
            send: xor(shared_secret.clone(), &self_sk.public_key()),
            receive: xor(shared_secret, peer_pk),
        }
    }
}

fn xor(shared: PrecomputedKey, publ: &PublicKey) -> PrecomputedKey {
    PrecomputedKey(xor_bytes(shared.0, &publ.0))
}

fn xor_bytes(mut a: [u8; 32], b: &[u8; 32]) -> [u8; 32] {
    for (s, p) in a.iter_mut().zip(b.iter()) {
        *s ^= p;
    }
    a
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
    use rand::Rng;
    rand::thread_rng().gen::<[u8; 32]>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_attack() {
        // problem:
        // since the server and the client both send and receive using the same shared key
        // a message redirected to self will be accepted if the public key field of the
        // datagram is modified to equal the recievers public key

        // fix:
        // Xor shared key with own public key to compute secret send key
        // Xor shared key with peer public key to compute secret receive key

        let mut server = Reprehensible::create(random_sk());
        let mut client = Reprehensible::create(random_sk());
        let datagram = client.send(server.sk.public_key(), b"hello");
        assert_eq!(&server.receive(&datagram).unwrap().payload, b"hello");
        assert!(client.receive(&datagram).is_none());

        let malicious_datagram = {
            // Attack mutates the datagram and sends it back to the client
            let mut malicious_datagram = parse_datagram(&datagram).unwrap();
            malicious_datagram.peer_pk = server.sk.public_key();
            malicious_datagram.serialize()
        };

        assert!(client.receive(&malicious_datagram).is_none());
    }

    #[test]
    fn retransmit_attack() {
        // problem:
        // since datagrams are unordered, retransmitted datagrams will be accepted

        let mut server = Reprehensible::create(random_sk());
        let mut client = Reprehensible::create(random_sk());
        let datagram = client.send(server.sk.public_key(), b"hello");
        assert_eq!(&server.receive(&datagram).unwrap().payload, b"hello");

        // Fails because server is vulnerable to retranmission attacks.
        assert!(&server.receive(&datagram).is_none());
    }

    #[test]
    fn client_server() {
        let mut server = Reprehensible::create(random_sk());
        let mut client = Reprehensible::create(random_sk());
        let datagram = client.send(server.sk.public_key(), b"hello");
        let datagram_decrypted = server.receive(&datagram).unwrap();
        assert_eq!(datagram_decrypted.peer_pk, client.sk.public_key());
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

    #[test]
    fn xor() {
        let a = [
            0x1e, 0x86, 0x95, 0x7e, 0xfd, 0xb3, 0x21, 0x9f, 0x97, 0x01, 0x56, 0x43, 0x94, 0x59,
            0x61, 0xcf, 0xa7, 0x1c, 0x2c, 0x73, 0xba, 0x59, 0x96, 0x66, 0xe7, 0xe3, 0xe0, 0x49,
            0x23, 0x17, 0x98, 0xb0,
        ];
        let b = [
            0x0d, 0x9c, 0xd8, 0x08, 0xef, 0xd6, 0x94, 0x1b, 0xff, 0xfb, 0xc1, 0x64, 0x1e, 0xb5,
            0xa9, 0x88, 0x32, 0x22, 0x77, 0xed, 0x91, 0xe5, 0xa4, 0xc7, 0x85, 0x3f, 0x6b, 0xda,
            0xe9, 0xb1, 0x22, 0x3d,
        ];
        let c = [
            0x13, 0x1a, 0x4d, 0x76, 0x12, 0x65, 0xb5, 0x84, 0x68, 0xfa, 0x97, 0x27, 0x8a, 0xec,
            0xc8, 0x47, 0x95, 0x3e, 0x5b, 0x9e, 0x2b, 0xbc, 0x32, 0xa1, 0x62, 0xdc, 0x8b, 0x93,
            0xca, 0xa6, 0xba, 0x8d,
        ];
        assert_eq!(xor_bytes(a, &b), c);
        assert_eq!(xor_bytes(a, &a), [0u8; 32]);
        assert_eq!(xor_bytes(xor_bytes(a, &b), &b), a);
    }
}
