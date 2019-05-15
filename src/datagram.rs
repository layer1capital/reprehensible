use pow::Pow;
mod nanoseconds;
use nanoseconds::Nanoseconds;
use rust_sodium::crypto::box_::{PublicKey, SecretKey};
use sealed::Sealed;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Datagram {
    pow: Pow<(PublicKey, PublicKey, Nanoseconds)>,
    timestamp: Nanoseconds,
    message: Sealed<Vec<u8>>,
}

impl Datagram {
    pub fn pow_score(&self) -> u128 {
        let dest_pk = self.message.destination_pk().clone();
        let source_pk = self.message.source_pk().clone();
        let (pka, pkb) = if dest_pk > source_pk {
            (source_pk, dest_pk)
        } else {
            (dest_pk, source_pk)
        };
        self.pow
            .score(&(pka, pkb, self.timestamp))
            .expect("an error was reported during in memory serialization")
    }
}

// /// {De,En}cryptor
// pub struct Cryptor {
//     sk: SecretKey,
//     pk: PublicKey,
// }

// impl Cryptor {
//     pub fn new(sk: SecretKey) -> Self {
//         let pk = sk.public_key();
//         Cryptor { sk, pk }
//     }

//     pub fn encrypt(&self, destination_pk: PublicKey, plaintext: Vec<u8>) -> Datagram {
//         SessionKey::compute(&self.sk, &destination_pk).seal(destination_pk, self.pk, plaintext)
//     }

//     /// If destination_pk does not match own pk, None is returned.
//     pub fn decrypt<T: Deserialize>(&self, datagram: Datagram) -> Option<T> {
//         let Datagram { pow, message } = datagram;
//         if message != self.pk {
//             return None;
//         } else {
//             SessionKey::compute(&self.sk, &source_pk).open(source_pk, nonce, mac, cyphertext)
//         }
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use rust_sodium::crypto::box_::gen_keypair;
//     use std::mem::size_of;

//     #[test]
//     fn echo_attack() {
//         // problem:
//         // since the server and the client both send and receive using the same shared key
//         // a message redirected to self will be accepted if the public key field of the
//         // datagram is modified to equal the recievers public key

//         // fix:
//         // Xor shared key with own public key to compute secret send key
//         // Xor shared key with peer public key to compute secret receive key

//         let server = Cryptor::new(gen_keypair().1);
//         let client = Cryptor::new(gen_keypair().1);
//         let mut datagram = client.encrypt(server.pk.clone(), b"hello".to_vec());

//         // direct echo
//         assert!(client.decrypt(datagram.clone()).is_none());

//         // modify sender public key and echo
//         datagram.head.source_pk = server.pk;
//         assert!(client.decrypt(datagram).is_none());
//     }

//     #[test]
//     fn primitive_mitm_attack() {
//         let server = Cryptor::new(gen_keypair().1);
//         let client = Cryptor::new(gen_keypair().1);
//         let mut datagram = client.encrypt(server.pk, b"hello".to_vec());
//         assert_eq!(
//             &server.decrypt(datagram.clone()).unwrap().plaintext,
//             b"hello"
//         );
//         datagram.cyphertext[0] += 1;
//         assert!(&server.decrypt(datagram).is_none());
//     }

//     #[test]
//     fn client_server() {
//         let server = Cryptor::new(gen_keypair().1);
//         let client = Cryptor::new(gen_keypair().1);
//         let datagram = client.encrypt(server.pk, b"hello".to_vec());
//         let datagram_decrypted = server.decrypt(datagram).unwrap();
//         assert_eq!(datagram_decrypted.source_pk, client.pk);
//         assert_eq!(&datagram_decrypted.plaintext, &b"hello");
//     }

//     #[test]
//     fn sk_to_pk_deterministic() {
//         for _ in 0..100 {
//             let sk = gen_keypair().1;
//             assert_eq!(sk.public_key(), sk.public_key());
//         }
//     }

//     #[test]
//     fn impersonate() {
//         // send a message to self, using own public key
//         let server = Cryptor::new(gen_keypair().1);
//         let datagram = server.encrypt(server.pk, b"hello".to_vec());
//         let datagram_decrypted = server.decrypt(datagram).unwrap();
//         assert_eq!(datagram_decrypted.source_pk, server.pk);
//         assert_eq!(&datagram_decrypted.plaintext, &b"hello");
//     }

//     #[test]
//     fn pk_generated_from_random_bytes() {
//         use rust_sodium::crypto::box_;

//         let our_sk = [
//             0x04, 0x16, 0xdf, 0x97, 0xc1, 0xee, 0x2c, 0xa8, 0xa1, 0x98, 0xf5, 0x0a, 0x86, 0x2e,
//             0x3b, 0x62, 0xea, 0x95, 0xa3, 0xb2, 0x30, 0x96, 0xcd, 0x44, 0x9f, 0x32, 0x02, 0xc9,
//             0x4c, 0x73, 0xbb, 0xb3,
//         ];
//         let their_sk = [
//             0x1f, 0xf7, 0x10, 0xe8, 0x0a, 0xd6, 0xc2, 0xdf, 0x06, 0x97, 0x61, 0x1e, 0x52, 0xe6,
//             0x43, 0x1c, 0xed, 0xe0, 0x68, 0xd4, 0x94, 0x49, 0xff, 0x93, 0x4c, 0x56, 0xf3, 0x1f,
//             0xd6, 0x61, 0x53, 0xa4,
//         ];

//         let oursk = SecretKey(our_sk);
//         let ourpk = oursk.public_key();
//         let theirsk = SecretKey(their_sk);
//         let theirpk = theirsk.public_key();
//         let nonce = box_::gen_nonce();
//         let plaintext = b"some data";
//         let ciphertext = box_::seal(plaintext, &nonce, &theirpk, &oursk);
//         let their_plaintext = box_::open(&ciphertext, &nonce, &ourpk, &theirsk).unwrap();
//         assert!(plaintext == &their_plaintext[..]);
//     }

//     mod string_doubling_echo_server {
//         use super::*;

//         const SERVER_SK: SecretKey = SecretKey([
//             0x33, 0x4f, 0x0e, 0xbf, 0x3a, 0x15, 0x9b, 0x7e, 0x70, 0x07, 0x30, 0x0b, 0x88, 0x6c,
//             0x94, 0x78, 0x6a, 0x4c, 0xf8, 0x33, 0xd8, 0x95, 0xa1, 0x17, 0x45, 0x8b, 0xaa, 0x69,
//             0x49, 0x33, 0x42, 0x6d,
//         ]);

//         pub fn echo_server(mut datagram: Vec<u8>) -> Option<Vec<u8>> {
//             let server = Cryptor::new(SERVER_SK);
//             let dg = Datagram::parse(&mut datagram)?;
//             let source_pk = dg.head.source_pk;
//             let mut message = server.decrypt(dg)?;
//             let mut reply = message.plaintext.clone();
//             reply.append(&mut message.plaintext);
//             let reply_dg = server.encrypt(source_pk, reply);
//             Some(reply_dg.serialize())
//         }

//         #[test]
//         fn echo_client() {
//             let server_pk = SERVER_SK.public_key();

//             let client = Cryptor::new(gen_keypair().1);
//             let dg = client
//                 .encrypt(server_pk, b"redundancy".to_vec())
//                 .serialize();
//             let mut response_dg_raw = echo_server(dg).unwrap();
//             let response_dg = Datagram::parse(&mut response_dg_raw).unwrap();
//             assert_eq!(response_dg.head.destination_pk, client.pk);
//             assert_eq!(response_dg.head.source_pk, server_pk);
//             let response_plain = client.decrypt(response_dg).unwrap();
//             assert_eq!(response_plain.source_pk, server_pk);
//             assert_eq!(response_plain.plaintext, b"redundancyredundancy");
//         }

//         #[test]
//         fn echo_client_tamper() {
//             let server_pk = SERVER_SK.public_key();
//             let client = Cryptor::new(gen_keypair().1);
//             let dg = client
//                 .encrypt(server_pk, b"redundancy".to_vec())
//                 .serialize();
//             {
//                 // tamper destination pk
//                 let mut dg = dg.clone();
//                 dg[0] = dg[0].wrapping_add(1);
//                 assert!(echo_server(dg).is_none());
//             }
//             {
//                 // tamper source pk
//                 let mut dg = dg.clone();
//                 let sender_loc = size_of::<PublicKey>();
//                 dg[sender_loc] = dg[sender_loc].wrapping_add(1);
//                 assert!(echo_server(dg).is_none());
//             }
//             {
//                 // tamper body
//                 let mut dg = dg.clone();
//                 let end = dg.len() - 1;
//                 dg[end] = dg[end].wrapping_add(1);
//                 assert!(echo_server(dg).is_none());
//             }
//             {
//                 // tamper decrease length
//                 let mut dg = dg.clone();
//                 while let Some(_) = dg.pop() {
//                     assert!(echo_server(dg.clone()).is_none());
//                 }
//             }
//             {
//                 // tamper increase length
//                 let mut dg = dg.clone();
//                 dg.push(0);
//                 assert!(echo_server(dg).is_none());
//             }
//             {
//                 // no tamper
//                 assert!(echo_server(dg.clone()).is_some());
//             }
//         }

//         fn typed_tamper<F: FnOnce(&mut Datagram)>(tamper: F) -> Option<DatagramPlaintext> {
//             let client = Cryptor::new(gen_keypair().1);
//             let server = Cryptor::new(gen_keypair().1);
//             let mut dg =
//                 Datagram::parse(&client.encrypt(server.pk, b"hello".to_vec()).serialize()).unwrap();
//             tamper(&mut dg);
//             server.decrypt(Datagram::parse(&dg.serialize()).unwrap())
//         }

//         #[test]
//         fn echo_client_typed_tamper() {
//             assert!(typed_tamper(|dg| {
//                 dg.head.destination_pk.0[0] = dg.head.destination_pk.0[0].wrapping_add(1);
//             })
//             .is_none());
//             assert!(typed_tamper(|dg| {
//                 dg.head.source_pk.0[0] = dg.head.source_pk.0[0].wrapping_add(1);
//             })
//             .is_none());
//             assert!(typed_tamper(|dg| {
//                 dg.cyphertext[0] = dg.cyphertext[0].wrapping_add(1);
//             })
//             .is_none());
//             assert!(typed_tamper(|dg| {
//                 dg.cyphertext.pop();
//             })
//             .is_none());
//             assert!(typed_tamper(|dg| {
//                 dg.cyphertext.push(0);
//             })
//             .is_none());
//             assert!(typed_tamper(|_dg| {}).is_some());
//         }

//         #[test]
//         /// tweak random bytes in transit and ensure Cryptor rejects messages
//         fn random_tampering() {
//             let client = Cryptor::new(gen_keypair().1);
//             let datagram_raw = client
//                 .encrypt(SERVER_SK.public_key(), b"hello".to_vec())
//                 .serialize();

//             assert!(echo_server(datagram_raw.clone()).is_some());

//             for _ in 0..(datagram_raw.len()) {
//                 let mut dgr = datagram_raw.clone();
//                 let index: usize = rand::random::<usize>() % dgr.len();
//                 dgr[index] = dgr[index].wrapping_add(random_nonzero());
//                 let response = {
//                     // It is possible to modify the proof of work fields (timestamp, and pow).
//                     // Changing the field to something with a low score has a similar effect to
//                     // simply dropping the packet.
//                     echo_server(dgr)
//                 };
//                 assert!(response.is_none());
//             }

//             fn random_nonzero() -> u8 {
//                 loop {
//                     let ret = rand::random();
//                     if ret != 0 {
//                         return ret;
//                     }
//                 }
//             }
//         }
//     }

//     #[test]
//     /// ensure reprehensible composability
//     fn double_encrypt() {
//         let client = Cryptor::new(gen_keypair().1);
//         let server = Cryptor::new(gen_keypair().1);
//         let client_pk = client.pk;

//         let message = client.encrypt(server.pk, b"hello".to_vec()).serialize();
//         let message = client.encrypt(server.pk, message);
//         let rx = server.decrypt(message).unwrap();
//         assert_eq!(rx.source_pk, client_pk);
//         let dg = Datagram::parse(&rx.plaintext).unwrap();
//         assert_eq!(dg.head.source_pk, client_pk);
//         assert_ne!(dg.cyphertext, b"hello");
//         let rx = server.decrypt(dg).unwrap();
//         assert_eq!(rx.plaintext, b"hello");
//     }

//     fn decrypt(reciever: &Cryptor, datagram: Vec<u8>) -> Option<Vec<u8>> {
//         let dg = Datagram::parse(&datagram)?;
//         let dgd = reciever.decrypt(dg)?;
//         Some(dgd.plaintext.to_vec())
//     }

//     fn encrypt(sender: &Cryptor, receiver: PublicKey, message: Vec<u8>) -> Vec<u8> {
//         sender.encrypt(receiver, message).serialize()
//     }

//     #[test]
//     /// ensure reprehensible composability
//     fn n_layer_encrypt() {
//         let client = Cryptor::new(gen_keypair().1);
//         let server = Cryptor::new(gen_keypair().1);
//         let server_pk = server.pk;

//         let n = 10;

//         let mut iterations: Vec<Vec<u8>> = Vec::new();

//         let mut message = b"hello".to_vec();
//         for _ in 0..n {
//             message = encrypt(&client, server_pk, message);
//             assert!(!iterations.contains(&message));
//             iterations.push(message.clone());
//         }

//         for _ in 0..n {
//             assert_eq!(iterations.pop().unwrap(), message);
//             message = decrypt(&server, message).unwrap();
//         }

//         assert_eq!(message, b"hello");
//     }

//     #[test]
//     fn no_nonce_reuse() {
//         let client = Cryptor::new(gen_keypair().1);
//         let server = Cryptor::new(gen_keypair().1);
//         for _ in 0..100 {
//             assert_ne!(
//                 client.encrypt(server.pk, b"hello".to_vec()).head.nonce,
//                 client.encrypt(server.pk, b"hello".to_vec()).head.nonce
//             );
//         }
//     }

//     #[test]
//     fn send_to_self() {
//         let client = Cryptor::new(gen_keypair().1);
//         let dg = client.encrypt(client.pk, b"hello".to_vec());
//         assert_eq!(&client.decrypt(dg).unwrap().plaintext, b"hello"); // is this desired behaviour?
//     }

//     #[test]
//     fn no_tag_dupes() {
//         let client = Cryptor::new(gen_keypair().1);
//         let server = Cryptor::new(gen_keypair().1);
//         for _ in 0..100 {
//             assert_ne!(
//                 client.encrypt(server.pk, b"hello".to_vec()).head.mac,
//                 client.encrypt(server.pk, b"hello".to_vec()).head.mac
//             );
//         }
//     }

//     #[test]
//     fn peer_spoof_sender() {
//         let client = Cryptor::new(gen_keypair().1);
//         let server = Cryptor::new(gen_keypair().1);

//         {
//             // client spoofs a datagram from server to client
//             let spoof = SessionKey::compute(&client.sk, &server.pk).seal(
//                 client.pk, // <---\___ Sender and reciever are swapped.
//                 server.pk, // <---/
//                 b"spoof".to_vec(),
//             );

//             // client sends spoofed datagram to server
//             let response = server.decrypt(spoof);

//             // server should reject datagram
//             assert!(response.is_none());
//         }

//         {
//             // same test, but without spoofing
//             let not_spoof = SessionKey::compute(&client.sk, &server.pk).seal(
//                 server.pk,
//                 client.pk,
//                 b"spoof".to_vec(),
//             );
//             let response = server.decrypt(not_spoof);
//             assert!(response.is_some());
//         }
//     }

//     #[test]
//     fn send_empty() {
//         let client = Cryptor::new(gen_keypair().1);
//         let server = Cryptor::new(gen_keypair().1);
//         let dg = client.encrypt(server.pk, b"".to_vec());
//         assert_eq!(&server.decrypt(dg).unwrap().plaintext, b"");
//     }

//     #[test]
//     fn send_large() {
//         let client = Cryptor::new(gen_keypair().1);
//         let server = Cryptor::new(gen_keypair().1);
//         let plaintext: Vec<u8> = (0..1_000_000).map(|i| i as u8).collect();
//         let dg = client.encrypt(server.pk, plaintext.clone());
//         assert_eq!(server.decrypt(dg).unwrap().plaintext, plaintext);
//     }
// }
