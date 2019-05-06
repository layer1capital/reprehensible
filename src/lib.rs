mod network_byte_order;
mod pow;
use crate::network_byte_order::Ne;
pub use pow::prove_work;
use rust_sodium::crypto::box_::{
    gen_nonce, open_detached_precomputed, precompute, seal_detached_precomputed, Nonce,
    PrecomputedKey, PublicKey, SecretKey, Tag,
};
use std::mem::size_of;

#[derive(Clone, Debug)]
struct DatagramHead {
    /// Public key of receiver, potentially used for routing.
    destination_pk: PublicKey,
    /// Public key of sender.
    source_pk: PublicKey,
    /// Time when proof of work was computed
    pow_time_nanos: u128,
    /// applied to destination_pk, source_pk, and pow_time_nanos; not the rest of the datagram
    /// can be reused in future packets
    proof_of_work: u128,
    nonce: Nonce,
    /// Message authentication code.
    mac: Tag,
}

#[derive(Clone, Debug)]
pub struct Datagram {
    head: DatagramHead,
    cyphertext: Vec<u8>,
}

impl Datagram {
    /// Attempt to interpret raw bytes as an encrypted datagram.
    /// None is returned only if slice is not long enough to be a valid datagram.
    pub fn parse(raw: &[u8]) -> Option<Datagram> {
        let (destination_pk, rest) = PublicKey::pick(raw)?;
        let (source_pk, rest) = PublicKey::pick(rest)?;
        let (pow_time_nanos, rest) = u128::pick(rest)?;
        let (proof_of_work, rest) = u128::pick(rest)?;
        let (nonce, rest) = Nonce::pick(rest)?;
        let (mac, rest) = Tag::pick(rest)?;
        let cyphertext = rest.to_vec();
        Some(Datagram {
            head: DatagramHead {
                destination_pk,
                source_pk,
                pow_time_nanos,
                proof_of_work,
                nonce,
                mac,
            },
            cyphertext,
        })
    }

    pub fn serialize(self) -> Vec<u8> {
        let Datagram {
            head:
                DatagramHead {
                    destination_pk,
                    source_pk,
                    pow_time_nanos,
                    proof_of_work,
                    nonce,
                    mac,
                },
            mut cyphertext,
        } = self;
        let retlen = size_of::<DatagramHead>() + cyphertext.len();
        let mut ret = Vec::with_capacity(retlen);
        ret.extend_from_slice(&destination_pk.to_ne());
        ret.extend_from_slice(&source_pk.to_ne());
        ret.extend_from_slice(&pow_time_nanos.to_ne());
        ret.extend_from_slice(&proof_of_work.to_ne());
        ret.extend_from_slice(&nonce.to_ne());
        ret.extend_from_slice(&mac.to_ne());
        ret.append(&mut cyphertext);
        debug_assert_eq!(ret.len(), retlen);
        ret
    }

    /// set the proof of work fields for this datagram.
    /// proof_of_work should mark (source_pk, destination_pk) and (destination_pk, source_pk).
    pub fn with_pow(mut self, pow_time_nanos: u128, proof_of_work: u128) -> Self {
        self.head.pow_time_nanos = pow_time_nanos;
        self.head.proof_of_work = proof_of_work;
        self
    }

    pub fn pow_score(&self) -> u32 {
        pow::score(
            &self.head.destination_pk,
            &self.head.source_pk,
            self.head.pow_time_nanos,
            self.head.proof_of_work,
        )
    }

    /// Calculate the proof of work score from the first few bytes of the datagram before the
    /// datagram is parsed. Return None if datagram is not long enough to have a score.
    pub fn pow_score_raw(raw: &[u8]) -> Option<u32> {
        let (destination_pk, rest) = PublicKey::pick(raw)?;
        let (source_pk, rest) = PublicKey::pick(rest)?;
        let (pow_time_nanos, rest) = u128::pick(rest)?;
        let (proof_of_work, _rest) = u128::pick(rest)?;
        Some(pow::score(
            &destination_pk,
            &source_pk,
            pow_time_nanos,
            proof_of_work,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct DatagramPlaintext {
    /// Public key of sender.
    pub source_pk: PublicKey,
    pub plaintext: Vec<u8>,
}

/// {De,En}cryptor
pub struct Cryptor {
    sk: SecretKey,
    pk: PublicKey,
}

impl Cryptor {
    pub fn new(sk: SecretKey) -> Self {
        let pk = sk.public_key();
        Cryptor { sk, pk }
    }

    pub fn encrypt(&self, destination_pk: PublicKey, plaintext: Vec<u8>) -> Datagram {
        SessionKey::compute(&self.sk, &destination_pk).seal(destination_pk, self.pk, plaintext)
    }

    /// If destination_pk does not match own pk, None is returned.
    pub fn decrypt(&self, datagram: Datagram) -> Option<DatagramPlaintext> {
        let Datagram {
            head:
                DatagramHead {
                    destination_pk,
                    source_pk,
                    pow_time_nanos: _,
                    proof_of_work: _,
                    nonce,
                    mac,
                },
            cyphertext,
        } = datagram;
        if destination_pk != self.pk {
            None
        } else {
            SessionKey::compute(&self.sk, &source_pk).open(source_pk, nonce, mac, cyphertext)
        }
    }
}

struct SessionKey {
    shared_secret: PrecomputedKey,
}

impl SessionKey {
    pub fn compute(self_sk: &SecretKey, peer_pk: &PublicKey) -> SessionKey {
        SessionKey {
            shared_secret: precompute(peer_pk, self_sk),
        }
    }

    pub fn seal(
        &self,
        destination_pk: PublicKey,
        source_pk: PublicKey,
        mut plaintext: Vec<u8>,
    ) -> Datagram {
        let nonce = gen_nonce();
        let mac = seal_detached_precomputed(&mut plaintext, &nonce, &self.send_sk(&source_pk));
        let cyphertext = plaintext;
        let head = DatagramHead {
            destination_pk,
            source_pk,
            pow_time_nanos: 0,
            proof_of_work: 0,
            nonce,
            mac,
        };
        Datagram { head, cyphertext }
    }

    pub fn open(
        &self,
        source_pk: PublicKey,
        nonce: Nonce,
        mac: Tag,
        mut cyphertext: Vec<u8>,
    ) -> Option<DatagramPlaintext> {
        open_detached_precomputed(&mut cyphertext, &mac, &nonce, &self.send_sk(&source_pk)).ok()?;
        let plaintext = cyphertext;
        Some(DatagramPlaintext {
            source_pk,
            plaintext,
        })
    }

    // calulate the key to be used when sending from source_pk
    fn send_sk(&self, source_pk: &PublicKey) -> PrecomputedKey {
        xor(self.shared_secret.clone(), source_pk)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rust_sodium::crypto::box_::gen_keypair;

    const DIFFICULTY: u32 = 1;

    #[test]
    fn echo_attack() {
        // problem:
        // since the server and the client both send and receive using the same shared key
        // a message redirected to self will be accepted if the public key field of the
        // datagram is modified to equal the recievers public key

        // fix:
        // Xor shared key with own public key to compute secret send key
        // Xor shared key with peer public key to compute secret receive key

        let server = Cryptor::new(gen_keypair().1);
        let client = Cryptor::new(gen_keypair().1);
        let mut datagram = client.encrypt(server.pk.clone(), b"hello".to_vec());

        // direct echo
        assert!(client.decrypt(datagram.clone()).is_none());

        // modify sender public key and echo
        datagram.head.source_pk = server.pk;
        assert!(client.decrypt(datagram).is_none());
    }

    #[test]
    fn primitive_mitm_attack() {
        let server = Cryptor::new(gen_keypair().1);
        let client = Cryptor::new(gen_keypair().1);
        let mut datagram = client.encrypt(server.pk, b"hello".to_vec());
        assert_eq!(
            &server.decrypt(datagram.clone()).unwrap().plaintext,
            b"hello"
        );
        datagram.cyphertext[0] += 1;
        assert!(&server.decrypt(datagram).is_none());
    }

    #[test]
    fn client_server() {
        let server = Cryptor::new(gen_keypair().1);
        let client = Cryptor::new(gen_keypair().1);
        let datagram = client.encrypt(server.pk, b"hello".to_vec());
        let datagram_decrypted = server.decrypt(datagram).unwrap();
        assert_eq!(datagram_decrypted.source_pk, client.pk);
        assert_eq!(&datagram_decrypted.plaintext, &b"hello");
    }

    #[test]
    fn sk_to_pk_deterministic() {
        for _ in 0..100 {
            let sk = gen_keypair().1;
            assert_eq!(sk.public_key(), sk.public_key());
        }
    }

    #[test]
    fn impersonate() {
        // send a message to self, using own public key
        let server = Cryptor::new(gen_keypair().1);
        let datagram = server.encrypt(server.pk, b"hello".to_vec());
        let datagram_decrypted = server.decrypt(datagram).unwrap();
        assert_eq!(datagram_decrypted.source_pk, server.pk);
        assert_eq!(&datagram_decrypted.plaintext, &b"hello");
    }

    #[test]
    fn pk_generated_from_random_bytes() {
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

        pub fn echo_server(mut datagram: Vec<u8>) -> Option<Vec<u8>> {
            let server = Cryptor::new(SERVER_SK);
            let dg = Datagram::parse(&mut datagram)?;
            let source_pk = dg.head.source_pk;
            let mut message = server.decrypt(dg)?;
            let mut reply = message.plaintext.clone();
            reply.append(&mut message.plaintext);
            let reply_dg = server.encrypt(source_pk, reply);
            Some(reply_dg.serialize())
        }

        #[test]
        fn echo_client() {
            let server_pk = SERVER_SK.public_key();

            let client = Cryptor::new(gen_keypair().1);
            let dg = client
                .encrypt(server_pk, b"redundancy".to_vec())
                .serialize();
            let mut response_dg_raw = echo_server(dg).unwrap();
            let response_dg = Datagram::parse(&mut response_dg_raw).unwrap();
            assert_eq!(response_dg.head.destination_pk, client.pk);
            assert_eq!(response_dg.head.source_pk, server_pk);
            let response_plain = client.decrypt(response_dg).unwrap();
            assert_eq!(response_plain.source_pk, server_pk);
            assert_eq!(response_plain.plaintext, b"redundancyredundancy");
        }

        #[test]
        fn echo_client_tamper() {
            let server_pk = SERVER_SK.public_key();
            let client = Cryptor::new(gen_keypair().1);
            let dg = client
                .encrypt(server_pk, b"redundancy".to_vec())
                .serialize();
            {
                // tamper destination pk
                let mut dg = dg.clone();
                dg[0] = dg[0].wrapping_add(1);
                assert!(echo_server(dg).is_none());
            }
            {
                // tamper source pk
                let mut dg = dg.clone();
                let sender_loc = size_of::<PublicKey>();
                dg[sender_loc] = dg[sender_loc].wrapping_add(1);
                assert!(echo_server(dg).is_none());
            }
            {
                // tamper body
                let mut dg = dg.clone();
                let end = dg.len() - 1;
                dg[end] = dg[end].wrapping_add(1);
                assert!(echo_server(dg).is_none());
            }
            {
                // tamper timestamp has no effect because echo server is not checking POW
                let mut dg = dg.clone();
                let timstamp_loc = size_of::<PublicKey>() + size_of::<PublicKey>();
                dg[timstamp_loc] = dg[timstamp_loc].wrapping_add(1);
                assert!(echo_server(dg).is_some());
            }
            {
                // tamper decrease length
                let mut dg = dg.clone();
                while let Some(_) = dg.pop() {
                    assert!(echo_server(dg.clone()).is_none());
                }
            }
            {
                // tamper increase length
                let mut dg = dg.clone();
                dg.push(0);
                assert!(echo_server(dg).is_none());
            }
            {
                // no tamper
                assert!(echo_server(dg.clone()).is_some());
            }
        }

        fn typed_tamper<F: FnOnce(&mut Datagram)>(tamper: F) -> Option<DatagramPlaintext> {
            let client = Cryptor::new(gen_keypair().1);
            let server = Cryptor::new(gen_keypair().1);
            let mut dg =
                Datagram::parse(&client.encrypt(server.pk, b"hello".to_vec()).serialize()).unwrap();
            tamper(&mut dg);
            server.decrypt(Datagram::parse(&dg.serialize()).unwrap())
        }

        #[test]
        fn echo_client_typed_tamper() {
            assert!(typed_tamper(|dg| {
                dg.head.destination_pk.0[0] = dg.head.destination_pk.0[0].wrapping_add(1);
            })
            .is_none());
            assert!(typed_tamper(|dg| {
                dg.head.source_pk.0[0] = dg.head.source_pk.0[0].wrapping_add(1);
            })
            .is_none());
            assert!(typed_tamper(|dg| {
                dg.cyphertext[0] = dg.cyphertext[0].wrapping_add(1);
            })
            .is_none());
            assert!(typed_tamper(|dg| {
                dg.head.pow_time_nanos = dg.head.pow_time_nanos.wrapping_add(1);
            })
            .is_some());
            assert!(typed_tamper(|dg| {
                dg.head.proof_of_work = dg.head.proof_of_work.wrapping_add(1);
            })
            .is_some());
            assert!(typed_tamper(|dg| {
                dg.cyphertext.pop();
            })
            .is_none());
            assert!(typed_tamper(|dg| {
                dg.cyphertext.push(0);
            })
            .is_none());
            assert!(typed_tamper(|_dg| {}).is_some());
        }

        #[test]
        /// tweak random bytes in transit and ensure Cryptor rejects messages
        fn random_tampering() {
            let client = Cryptor::new(gen_keypair().1);
            let datagram_raw = client
                .encrypt(SERVER_SK.public_key(), b"hello".to_vec())
                .serialize();

            assert!(echo_server(datagram_raw.clone()).is_some());

            for _ in 0..(datagram_raw.len()) {
                let mut dgr = datagram_raw.clone();
                let index: usize = rand::random::<usize>() % dgr.len();
                dgr[index] = dgr[index].wrapping_add(random_nonzero());
                let response = {
                    // It is possible to modify the proof of work fields (timestamp, and pow).
                    // Changing the field to something with a low score has a similar effect to
                    // simply dropping the packet.
                    echo_server(dgr)
                };
                let powstart = size_of::<PublicKey>() + size_of::<PublicKey>();
                let powend = powstart + size_of::<u128>() + size_of::<u128>();
                if index >= powstart && index < powend {
                    // we modified the proof of work, datagrams may still be accepted when pow is modified
                    assert!(response.is_some());
                } else {
                    assert!(response.is_none());
                }
            }

            fn random_nonzero() -> u8 {
                loop {
                    let ret = rand::random();
                    if ret != 0 {
                        return ret;
                    }
                }
            }
        }
    }

    #[test]
    /// ensure reprehensible composability
    fn double_encrypt() {
        let client = Cryptor::new(gen_keypair().1);
        let server = Cryptor::new(gen_keypair().1);
        let client_pk = client.pk;

        let message = client.encrypt(server.pk, b"hello".to_vec()).serialize();
        let message = client.encrypt(server.pk, message);
        let rx = server.decrypt(message).unwrap();
        assert_eq!(rx.source_pk, client_pk);
        let dg = Datagram::parse(&rx.plaintext).unwrap();
        assert_eq!(dg.head.source_pk, client_pk);
        assert_ne!(dg.cyphertext, b"hello");
        let rx = server.decrypt(dg).unwrap();
        assert_eq!(rx.plaintext, b"hello");
    }

    fn decrypt(reciever: &Cryptor, datagram: Vec<u8>) -> Option<Vec<u8>> {
        let dg = Datagram::parse(&datagram)?;
        let dgd = reciever.decrypt(dg)?;
        Some(dgd.plaintext.to_vec())
    }

    fn encrypt(sender: &Cryptor, receiver: PublicKey, message: Vec<u8>) -> Vec<u8> {
        sender.encrypt(receiver, message).serialize()
    }

    #[test]
    /// ensure reprehensible composability
    fn n_layer_encrypt() {
        let client = Cryptor::new(gen_keypair().1);
        let server = Cryptor::new(gen_keypair().1);
        let server_pk = server.pk;

        let n = 10;

        let mut iterations: Vec<Vec<u8>> = Vec::new();

        let mut message = b"hello".to_vec();
        for _ in 0..n {
            message = encrypt(&client, server_pk, message);
            assert!(!iterations.contains(&message));
            iterations.push(message.clone());
        }

        for _ in 0..n {
            assert_eq!(iterations.pop().unwrap(), message);
            message = decrypt(&server, message).unwrap();
        }

        assert_eq!(message, b"hello");
    }

    #[test]
    fn no_nonce_reuse() {
        let client = Cryptor::new(gen_keypair().1);
        let server = Cryptor::new(gen_keypair().1);
        for _ in 0..100 {
            assert_ne!(
                client.encrypt(server.pk, b"hello".to_vec()).head.nonce,
                client.encrypt(server.pk, b"hello".to_vec()).head.nonce
            );
        }
    }

    #[test]
    fn send_to_self() {
        let client = Cryptor::new(gen_keypair().1);
        let dg = client.encrypt(client.pk, b"hello".to_vec());
        assert_eq!(&client.decrypt(dg).unwrap().plaintext, b"hello"); // is this desired behaviour?
    }

    #[test]
    fn no_tag_dupes() {
        let client = Cryptor::new(gen_keypair().1);
        let server = Cryptor::new(gen_keypair().1);
        for _ in 0..100 {
            assert_ne!(
                client.encrypt(server.pk, b"hello".to_vec()).head.mac,
                client.encrypt(server.pk, b"hello".to_vec()).head.mac
            );
        }
    }

    mod proof_of_work {
        // Problem:
        // Generating session keys is expensive. It is relatively cheap for a remote peer to
        // make a server generate tons of session keys just by sending garbage udp packets.

        // Solution, demonstrated here:
        // Require a puzzle to be solved before deriving a shared key.

        use super::*;

        const SERVER_SK: SecretKey = SecretKey([
            0x33, 0x4f, 0x0e, 0xbf, 0x3a, 0x15, 0x9b, 0x7e, 0x70, 0x07, 0x30, 0x0b, 0x88, 0x6c,
            0x94, 0x78, 0x6a, 0x4c, 0xf8, 0x33, 0xd8, 0x95, 0xa1, 0x17, 0x45, 0x8b, 0xaa, 0x69,
            0x49, 0x33, 0x42, 0x6d,
        ]);

        /// Only returns None if proof of work is not satisfied. In this context other failures
        /// indicate a bug.
        pub fn echo_server_pow(mut datagram: Vec<u8>) -> Option<Vec<u8>> {
            let server = Cryptor::new(SERVER_SK);
            let dg = Datagram::parse(&mut datagram).unwrap();
            if dg.pow_score() < DIFFICULTY {
                return None;
            }
            let source_pk = dg.head.source_pk;
            let pow_time_nanos = dg.head.pow_time_nanos;
            let proof_of_work = dg.head.proof_of_work;
            let message = server.decrypt(dg).unwrap();
            let reply_dg = server
                .encrypt(source_pk, message.plaintext)
                .with_pow(pow_time_nanos, proof_of_work); // proof of work is resused for responce
            Some(reply_dg.serialize())
        }

        #[test]
        fn echo_client_pow() {
            let server_pk = SERVER_SK.public_key();
            let client = Cryptor::new(gen_keypair().1);
            let dg = client.encrypt(server_pk, b"hello".to_vec());

            let work = dg
                .clone()
                .with_pow(0, prove_work(&client.pk, &server_pk, 0, DIFFICULTY))
                .serialize();

            let lazy = {
                assert_ne!(DIFFICULTY, 0);
                // make sure score is less than DIFFICULTY
                let mut dg = dg.clone();
                while dg.pow_score() >= DIFFICULTY {
                    dg.head.proof_of_work += 1;
                }
                dg
            }
            .serialize();

            assert!(echo_server_pow(work).is_some());
            assert!(echo_server_pow(lazy).is_none());
        }

        #[test]
        fn echo_client_pow_reuse() {
            let server_pk = SERVER_SK.public_key();
            let client = Cryptor::new(gen_keypair().1);
            let work_proof = prove_work(&client.pk, &server_pk, 0, DIFFICULTY);
            let dg = client
                .encrypt(server_pk, b"hello".to_vec())
                .with_pow(0, work_proof)
                .serialize();
            let response = Datagram::parse(&echo_server_pow(dg).unwrap()).unwrap();
            assert!(response.pow_score() >= DIFFICULTY);
            assert_eq!(response.head.proof_of_work, work_proof);
            assert_eq!(&client.decrypt(response).unwrap().plaintext, b"hello");
        }
    }

    #[test]
    fn peer_spoof_sender() {
        let client = Cryptor::new(gen_keypair().1);
        let server = Cryptor::new(gen_keypair().1);

        {
            // client spoofs a datagram from server to client
            let spoof = SessionKey::compute(&client.sk, &server.pk).seal(
                client.pk, // <---\___ Sender and reciever are swapped.
                server.pk, // <---/
                b"spoof".to_vec(),
            );

            // client sends spoofed datagram to server
            let response = server.decrypt(spoof);

            // server should reject datagram
            assert!(response.is_none());
        }

        {
            // same test, but without spoofing
            let not_spoof = SessionKey::compute(&client.sk, &server.pk).seal(
                server.pk,
                client.pk,
                b"spoof".to_vec(),
            );
            let response = server.decrypt(not_spoof);
            assert!(response.is_some());
        }
    }

    #[test]
    fn send_empty() {
        let client = Cryptor::new(gen_keypair().1);
        let server = Cryptor::new(gen_keypair().1);
        let dg = client.encrypt(server.pk, b"".to_vec());
        assert_eq!(&server.decrypt(dg).unwrap().plaintext, b"");
    }

    #[test]
    fn send_large() {
        let client = Cryptor::new(gen_keypair().1);
        let server = Cryptor::new(gen_keypair().1);
        let plaintext: Vec<u8> = (0..1_000_000).map(|i| i as u8).collect();
        let dg = client.encrypt(server.pk, plaintext.clone());
        assert_eq!(server.decrypt(dg).unwrap().plaintext, plaintext);
    }

    #[test]
    fn pow() {
        let client = Cryptor::new(gen_keypair().1);
        let server = Cryptor::new(gen_keypair().1);
        let proof_of_work = prove_work(&client.pk, &server.pk, 0, DIFFICULTY);
        let dg = client
            .encrypt(server.pk, b"".to_vec())
            .with_pow(0, proof_of_work);
        let score = dg.pow_score();
        assert!(score >= DIFFICULTY);
    }

    #[test]
    fn pow_reuse() {
        let client = Cryptor::new(gen_keypair().1);
        let server = Cryptor::new(gen_keypair().1);

        for t in 0..16 {
            let proof_of_work = prove_work(&client.pk, &server.pk, t, DIFFICULTY);

            let c_to_s = client
                .encrypt(server.pk, b"hello, server".to_vec())
                .with_pow(t, proof_of_work);

            let s_to_c = server
                .encrypt(client.pk, b"hello, client".to_vec())
                .with_pow(t, proof_of_work);

            assert!(c_to_s.pow_score() >= DIFFICULTY);
            assert!(s_to_c.pow_score() >= DIFFICULTY);

            assert_eq!(&server.decrypt(c_to_s).unwrap().plaintext, b"hello, server");
            assert_eq!(&client.decrypt(s_to_c).unwrap().plaintext, b"hello, client");
        }
    }

    #[test]
    /// Datagram::pow_score yeilds the same result as Datagram::pow_score_raw.
    fn pow_raw_parsed() {
        let client = Cryptor::new(gen_keypair().1);
        let server = Cryptor::new(gen_keypair().1);

        for t in 0..16 {
            let proof_of_work = prove_work(&client.pk, &server.pk, t, DIFFICULTY);

            let dg = client
                .encrypt(server.pk, b"hello, server".to_vec())
                .with_pow(t, proof_of_work);

            assert_eq!(
                Datagram::pow_score(&dg),
                Datagram::pow_score_raw(&dg.serialize()).unwrap()
            );
        }
    }
}
