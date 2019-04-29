pub use rust_sodium::crypto::box_::{gen_nonce, Nonce, PublicKey, SecretKey};
use rust_sodium::crypto::box_::{
    open_detached_precomputed, precompute, seal_detached_precomputed, PrecomputedKey, Tag,
};
use std::collections::BTreeMap;
use std::mem::size_of;

#[derive(PartialEq, Eq, Ord, PartialOrd)]
struct U256(pub [u8; 32]);

const DATAGRAM_HEADER_SIZE: usize = size_of::<PublicKey>() + size_of::<Nonce>() + size_of::<Tag>();

pub struct Datagram<'a> {
    pub peer_pk: PublicKey,
    pub nonce: Nonce,
    pub tag: Tag,
    pub encrypted_payload: &'a mut [u8],
}

/// A verified plaintext message from peer_pk
pub struct DatagramDecrypted<'a> {
    /// verified public key of the sender
    peer_pk: PublicKey,
    /// plaintext message
    payload: &'a mut [u8],
}

impl<'a> DatagramDecrypted<'a> {
    /// get the public key of the sender
    pub fn peer_pk(&self) -> &PublicKey {
        &self.peer_pk
    }

    /// get the plaintext message
    pub fn payload(&self) -> &[u8] {
        self.payload
    }
}

/// A reprehensible encrypted datagram sender/reciever with a cache of secret shared keys
pub struct Reprehensible {
    sk: SecretKey,
    // Keep in mind, the key to this map is taken as input. Using an non-self-balancing map type
    // exposes the implementation to tree unbalacing attacks.
    session_cache: BTreeMap<PublicKey, SessionKeys>,
}

impl Reprehensible {
    /// Initialize reprehensible. sk is the secret key used for both sending and receiving
    pub fn create(sk: SecretKey) -> Reprehensible {
        Reprehensible {
            sk,
            session_cache: BTreeMap::new(),
        }
    }

    /// Recive a raw datagram, attempt to decrypt it.
    /// None will be returned if ciphertext failed verification.
    /// When None is returned, The datagram should be silently ignored and dropped.
    pub fn receive<'a>(&mut self, datagram: Datagram<'a>) -> Option<DatagramDecrypted<'a>> {
        self.session_keys(&datagram.peer_pk).open(datagram)
    }

    /// Create a new datagram with self as sender and peer_pk as recipient.
    pub fn send<'a>(&mut self, peer_pk: &PublicKey, message: &'a mut [u8]) -> Datagram<'a> {
        let self_pk = self.sk.public_key();
        self.session_keys(peer_pk)
            .seal(self_pk, gen_nonce(), message)
    }

    /// Get the public key associated with this instance
    pub fn pk(&self) -> PublicKey {
        self.sk.public_key()
    }

    /// Get secret shared between self and peer.
    /// Secret is expensive to derive, so it is cached for performance.
    /// Early benchmarks indicate deriving a pair takes 3237 times as long as
    /// pulling it from the cache.
    /// Derivation on my machine takes around 84,171 nanoseconds.
    ///
    /// In the worst case senario, 100% cache misses, the cache adds relatively small overhead.
    fn session_keys(&mut self, peer_pk: &PublicKey) -> &SessionKeys {
        let sk = self.sk.clone();
        self.session_cache
            .entry(*peer_pk)
            .or_insert_with(|| SessionKeys::compute(&sk, peer_pk))
    }
}

#[derive(Clone)]
pub struct SessionKeys {
    shared_secret: PrecomputedKey,
}

impl SessionKeys {
    pub fn compute(self_sk: &SecretKey, peer_pk: &PublicKey) -> SessionKeys {
        SessionKeys {
            shared_secret: precompute(peer_pk, self_sk),
        }
    }

    pub fn seal<'a>(
        &self,
        self_pk: PublicKey,
        nonce: Nonce,
        message: &'a mut [u8],
    ) -> Datagram<'a> {
        let tag = seal_detached_precomputed(message, &nonce, &self.send_sk(&self_pk));
        Datagram {
            peer_pk: self_pk,
            nonce,
            tag,
            encrypted_payload: message,
        }
    }

    pub fn open<'a>(&self, datagram: Datagram<'a>) -> Option<DatagramDecrypted<'a>> {
        open_detached_precomputed(
            datagram.encrypted_payload,
            &datagram.tag,
            &datagram.nonce,
            &self.send_sk(&datagram.peer_pk),
        )
        .ok()?;
        Some(DatagramDecrypted {
            peer_pk: datagram.peer_pk,
            payload: datagram.encrypted_payload,
        })
    }

    // calulate the key to be used when sending from sender_pk
    fn send_sk(&self, sender_pk: &PublicKey) -> PrecomputedKey {
        xor(self.shared_secret.clone(), sender_pk)
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

impl<'a> Datagram<'a> {
    /// Attempt to interpret raw bytes as an encrypted datagram.
    /// None is returned if slice is not long enough to be a valid datagram.
    pub fn parse(raw: &mut [u8]) -> Option<Datagram> {
        let (head, encrypted_payload) = take_n_mut(raw, DATAGRAM_HEADER_SIZE)?;
        let (peer_pk, rest) = take_pk(head)?;
        let (nonce, rest) = take_nonce(rest)?;
        let (tag, rest) = take_tag(rest)?;
        debug_assert_eq!(rest.len(), 0);
        Some(Datagram {
            peer_pk,
            nonce,
            tag,
            encrypted_payload,
        })
    }

    pub fn serialize(self) -> Vec<u8> {
        let Datagram {
            peer_pk,
            nonce,
            tag,
            encrypted_payload,
        } = self;
        let retlen = DATAGRAM_HEADER_SIZE + encrypted_payload.len();
        let mut ret = Vec::with_capacity(retlen);
        for b in peer_pk.as_ref() {
            ret.push(*b);
        }
        for b in nonce.as_ref() {
            ret.push(*b);
        }
        for b in tag.as_ref() {
            ret.push(*b);
        }
        for b in encrypted_payload {
            ret.push(*b);
        }
        debug_assert_eq!(ret.len(), retlen);
        ret
    }
}

fn take_n_mut(slice: &mut [u8], mid: usize) -> Option<(&mut [u8], &mut [u8])> {
    if mid > slice.len() {
        None
    } else {
        Some(slice.split_at_mut(mid))
    }
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

fn take_pk(slice: &[u8]) -> Option<(PublicKey, &[u8])> {
    take_u256(slice).map(|(u256, rest)| (PublicKey(u256.0), rest))
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

fn take_tag(slice: &[u8]) -> Option<(Tag, &[u8])> {
    debug_assert_eq!(std::mem::size_of::<Tag>(), 16);
    if slice.len() < std::mem::size_of::<Tag>() {
        None
    } else {
        let (head, rest) = slice.split_at(std::mem::size_of::<Tag>());
        let tag = Tag::from_slice(head);
        debug_assert!(tag.is_some());
        Some((tag?, rest))
    }
}

fn as_sk(a: [u8; 32]) -> SecretKey {
    debug_assert_eq!(std::mem::size_of::<SecretKey>(), 32);
    SecretKey::from_slice(&a).unwrap()
}

/// Generate a random secret key on which to listen
pub fn random_sk() -> SecretKey {
    use rand::Rng;
    as_sk(rand::thread_rng().gen::<[u8; 32]>())
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

        let server = Reprehensible::create(random_sk());
        let mut client = Reprehensible::create(random_sk());
        let mut hello = b"hello".to_owned();
        let mut datagram = client.send(&server.sk.public_key(), &mut hello);

        // direct echo
        assert!(client
            .receive(copy_datagram(&datagram, &mut [0u8; 100]))
            .is_none());

        // modify sender public key and echo
        datagram.peer_pk = server.sk.public_key();
        assert!(client.receive(datagram).is_none());
    }

    fn copy_datagram<'a>(other: &Datagram, buf: &'a mut [u8]) -> Datagram<'a> {
        let buf = buf.split_at_mut(other.encrypted_payload.len()).0;
        buf.copy_from_slice(other.encrypted_payload);
        Datagram {
            peer_pk: other.peer_pk,
            nonce: other.nonce,
            tag: other.tag,
            encrypted_payload: buf,
        }
    }

    #[test]
    fn primitive_mitm_attack() {
        let mut server = Reprehensible::create(random_sk());
        let mut client = Reprehensible::create(random_sk());
        let mut hello = b"hello".to_owned();
        let datagram = client.send(&server.sk.public_key(), &mut hello);
        {
            datagram.encrypted_payload[0] += 1;
        }
        assert!(&server.receive(datagram).is_none());
    }

    #[test]
    fn client_server() {
        let mut server = Reprehensible::create(random_sk());
        let mut client = Reprehensible::create(random_sk());
        let mut hello = b"hello".to_owned();
        let datagram = client.send(&server.sk.public_key(), &mut hello);
        let datagram_decrypted = server.receive(datagram).unwrap();
        assert_eq!(datagram_decrypted.peer_pk, client.sk.public_key());
        assert_eq!(&datagram_decrypted.payload, &b"hello");
    }

    #[test]
    fn sk_to_pk_deterministic() {
        for _ in 0..100 {
            let sk = random_sk();
            assert_eq!(sk.public_key(), sk.public_key());
        }
    }

    #[test]
    fn impersonate() {
        // send a message to self, using own public key
        let mut server = Reprehensible::create(random_sk());
        let server_pub = server.sk.public_key();
        let mut hello = b"hello".to_owned();
        let datagram = server.send(&server_pub, &mut hello);
        let datagram_decrypted = server.receive(datagram).unwrap();
        assert_eq!(datagram_decrypted.peer_pk, server_pub);
        assert_eq!(&datagram_decrypted.payload, &b"hello");
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

    mod string_doubling_echo_server {
        use super::*;

        const SERVER_SK: SecretKey = SecretKey([
            0x33, 0x4f, 0x0e, 0xbf, 0x3a, 0x15, 0x9b, 0x7e, 0x70, 0x07, 0x30, 0x0b, 0x88, 0x6c,
            0x94, 0x78, 0x6a, 0x4c, 0xf8, 0x33, 0xd8, 0x95, 0xa1, 0x17, 0x45, 0x8b, 0xaa, 0x69,
            0x49, 0x33, 0x42, 0x6d,
        ]);

        pub fn get_pk() -> PublicKey {
            SERVER_SK.public_key()
        }

        pub fn echo(mut datagram: Vec<u8>) -> Option<Vec<u8>> {
            let mut server = Reprehensible::create(SERVER_SK);
            let dg = Datagram::parse(&mut datagram)?;
            let peer_pk = dg.peer_pk;
            let message: DatagramDecrypted = server.receive(dg)?;
            let mut reply = message.payload.to_vec();
            reply.append(&mut message.payload.to_vec());
            let reply_dg = server.send(&peer_pk, &mut reply);
            Some(reply_dg.serialize())
        }
    }

    #[test]
    fn echo_client() {
        let mut client = Reprehensible::create(random_sk());
        let mut message = b"redundancy".to_owned();
        let dg = client
            .send(&string_doubling_echo_server::get_pk(), &mut message)
            .serialize();
        let mut response_dg_raw = string_doubling_echo_server::echo(dg).unwrap();
        let response_dg = Datagram::parse(&mut response_dg_raw).unwrap();
        let response_plain = client.receive(response_dg).unwrap();
        assert_eq!(
            response_plain.peer_pk,
            string_doubling_echo_server::get_pk()
        );
        assert_eq!(response_plain.payload, b"redundancyredundancy");
    }

    #[test]
    /// ensure reprehensible composability
    fn double_encrypt() {
        let mut client = Reprehensible::create(random_sk());
        let mut server = Reprehensible::create(random_sk());
        let client_pk = client.sk.public_key();
        let server_pk = server.sk.public_key();

        let mut message = b"hello".to_owned();
        let mut message = client.send(&server_pk, &mut message).serialize();
        let message = client.send(&server_pk, &mut message);
        let mut rx = server.receive(message).unwrap();
        assert_eq!(rx.peer_pk, client_pk);
        let dg = Datagram::parse(&mut rx.payload).unwrap();
        assert_eq!(dg.peer_pk, client_pk);
        assert_ne!(dg.encrypted_payload, b"hello");
        let rx = server.receive(dg).unwrap();
        assert_eq!(rx.payload, b"hello");
    }

    fn decrypt(reciever: &mut Reprehensible, mut datagram: Vec<u8>) -> Option<Vec<u8>> {
        let dg = Datagram::parse(&mut datagram)?;
        let dgd = reciever.receive(dg)?;
        Some(dgd.payload.to_vec())
    }

    fn encrypt(sender: &mut Reprehensible, receiver: &PublicKey, mut message: Vec<u8>) -> Vec<u8> {
        sender.send(receiver, &mut message).serialize()
    }

    #[test]
    /// ensure reprehensible composability
    fn n_layer_encrypt() {
        let mut client = Reprehensible::create(random_sk());
        let mut server = Reprehensible::create(random_sk());
        let server_pk = server.sk.public_key();

        let n = 10;

        let mut iterations: Vec<Vec<u8>> = Vec::new();

        let mut message = b"hello".to_vec();
        for _ in 0..n {
            message = encrypt(&mut client, &server_pk, message);
            assert!(!iterations.contains(&message));
            iterations.push(message.clone());
        }

        for _ in 0..n {
            assert_eq!(iterations.pop().unwrap(), message);
            message = decrypt(&mut server, message).unwrap();
        }

        assert_eq!(message, b"hello");
    }

    #[test]
    fn no_nonce_reuse() {
        let mut client = Reprehensible::create(random_sk());
        let server = Reprehensible::create(random_sk());
        let server_pk = server.sk.public_key();

        for _ in 0..100 {
            assert_ne!(
                client.send(&server_pk, &mut b"hello".to_vec()).serialize(),
                client.send(&server_pk, &mut b"hello".to_vec()).serialize()
            );
        }
    }
}
