use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

#[derive(PartialEq, Eq, Ord, PartialOrd)]
struct U256(pub [u8; 32]);
#[derive(PartialEq, Eq, Ord, PartialOrd)]
struct PrivateKey(pub U256);

struct Datagram {
    peer_pk: PublicKey,
    nonce: U256,
    encrypted_payload: Vec<u8>,
}

struct DatagramDecrypted {
    peer_pk: PublicKey,
    payload: Vec<u8>,
}

struct Reprehensible {
    private_key: StaticSecret,
}

impl Reprehensible {
    fn new() -> Reprehensible {
        Reprehensible {
            private_key: StaticSecret::new(&mut rand_os::OsRng::new().unwrap()),
        }
    }

    fn receive(&mut self, datagram: &[u8]) -> Option<DatagramDecrypted> {
        let datagram = parse_datagram(datagram)?;
        let shared_secret = self.private_key.diffie_hellman(&datagram.peer_pk);
        datagram.decrypt(&shared_secret)
    }

    fn send(&mut self, peer_pk: PublicKey, message: &[u8]) -> Vec<u8> {
        let shared_secret = self.private_key.diffie_hellman(&peer_pk);
        Datagram::encrypt(&shared_secret, peer_pk, message)
    }
}

impl Datagram {
    fn decrypt(self, shared_secret: &SharedSecret) -> Option<DatagramDecrypted> {
        unimplemented!()
    }

    fn encrypt(shared_secret: &SharedSecret, peer_pk: PublicKey, message: &[u8]) -> Vec<u8> {
        let nonce = rando_nonce();
        unimplemented!()
    }
}

fn cat_u8_32s(a: &[u8; 32], b: &[u8; 32]) -> [u8; 64] {
    let mut ret = [0u8; 64];
    (&mut ret)[..32].copy_from_slice(a);
    (&mut ret)[32..].copy_from_slice(a);
    ret
}

fn parse_datagram(datagram: &[u8]) -> Option<Datagram> {
    let (peer_pk, rest) = take_u256(datagram)?;
    let (nonce, encrypted_payload) = take_u256(rest)?;
    let peer_pk = PublicKey::from(peer_pk.0);
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

fn rando_nonce() -> U256 {
    use rand_os::rand_core::RngCore;
    let mut os_rng = rand_os::OsRng::new().unwrap();
    let mut nonce = [0u8; 32];
    os_rng.fill_bytes(&mut nonce);
    U256(nonce)
}

#[cfg(test)]
mod tests {
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
        let mut server = super::Reprehensible::new();
        let mut client = super::Reprehensible::new();
        let server_pub = x25519_dalek::PublicKey::from(&server.private_key);
        let client_pub = x25519_dalek::PublicKey::from(&client.private_key);
        let message = client.private_key.diffie_hellman(&server_pub);
        let datagram = client.send(server_pub, b"hello");
        let datagram_decrypted = server.receive(&datagram).unwrap();
        assert_eq!(datagram_decrypted.peer_pk.as_bytes(), client_pub.as_bytes());
        assert_eq!(&datagram_decrypted.payload, b"hello");
    }

    #[test]
    fn cat() {
        assert_eq!(
            super::cat_u8_32s(
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
        let rep = super::Reprehensible::new();
        assert_eq!(
            x25519_dalek::PublicKey::from(&rep.private_key).as_bytes(),
            x25519_dalek::PublicKey::from(&rep.private_key).as_bytes()
        );
    }
}
