use std::collections::BTreeMap;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

#[derive(PartialEq, Eq, Ord, PartialOrd)]
struct U256(pub [u8; 32]);
#[derive(PartialEq, Eq, Ord, PartialOrd)]
struct SessionID(pub U256);
struct PrivateKey(pub U256);

enum Datagram {
    DH(PublicKey),
    Data(MessageEncrypted),
}

struct MessageEncrypted {
    session_id: SessionID,
    nonce: U256,
    encrypted_payload: Vec<u8>,
}

struct MessageDecrypted {
    session_id: SessionID,
    payload: Vec<u8>,
}

struct Reprehensible {
    private_key: StaticSecret,
    connections: BTreeMap<SessionID, SharedSecret>,
}

impl Reprehensible {
    fn receive(&mut self, datagram: &[u8]) -> Receive {
        match self._receive(datagram) {
            Some(rx) => rx,
            None => Receive::Drop,
        }
    }

    fn _receive(&mut self, datagram: &[u8]) -> Option<Receive> {
        let datagram = parse_datagram(datagram)?;
        match datagram {
            Datagram::DH(peer_pub) => {
                self.dh(&peer_pub);
                None
            }
            Datagram::Data(message_enc) => self.receive_message(message_enc).map(Receive::Message),
        }
    }

    fn receive_message(&self, message: MessageEncrypted) -> Option<MessageDecrypted> {
        let shared_key = self.connections.get(&message.session_id)?;
        message.decrypt(shared_key)
    }

    fn dh(&mut self, peer_pk: &PublicKey) {
        let shared_secret = self.private_key.diffie_hellman(peer_pk);
        self.connections
            .insert(hash_sk(&shared_secret), shared_secret);
        unimplemented!()
    }

    fn connect(&mut self, peer_pk: &PublicKey) -> [u8; 64] {
        let shared_secret = self.private_key.diffie_hellman(peer_pk);
        self.connections
            .insert(hash_sk(&shared_secret), shared_secret);
        let pk = PublicKey::from(&self.private_key);
        cat_u8_32s(&[0u8; 32], pk.as_bytes())
    }
}

impl MessageEncrypted {
    fn decrypt(self, shared_key: &SharedSecret) -> Option<MessageDecrypted> {
        unimplemented!()
    }
}

enum Receive {
    Message(MessageDecrypted),
    /// Either an Invalid datagram or a connection being initiated, ignore
    Drop,
}

fn cat_u8_32s(a: &[u8; 32], b: &[u8; 32]) -> [u8; 64] {
    let mut ret = [0u8; 64];
    (&mut ret)[..32].copy_from_slice(a);
    (&mut ret)[32..].copy_from_slice(a);
    ret
}

fn hash_sk(sk: &SharedSecret) -> SessionID {
    unimplemented!()
}

fn parse_datagram(datagram: &[u8]) -> Option<Datagram> {
    let (session_id, rest) = take_u256(datagram)?;
    if session_id == U256([0; 32]) {
        // parse as DHEncrypted
        try_into_dh_pk(rest).map(Datagram::DH)
    } else {
        // parse as MessageEncrypted
        try_into_message_encrypted(datagram).map(Datagram::Data)
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

fn try_into_message_encrypted(datagram: &[u8]) -> Option<MessageEncrypted> {
    let (session_id, rest) = take_u256(datagram)?;
    let (nonce, encrypted_payload) = take_u256(rest)?;
    let encrypted_payload = encrypted_payload.to_vec();
    let session_id = SessionID(session_id);
    Some(MessageEncrypted {
        session_id,
        nonce,
        encrypted_payload,
    })
}

fn try_into_dh_pk(datagram_tail: &[u8]) -> Option<PublicKey> {
    let (head, tail) = take_u256(datagram_tail)?;
    if tail.len() != 0 {
        None
    } else {
        Some(PublicKey::from(head.0))
    }
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
        let server = super::Reprehensible {
            private_key: x25519_dalek::StaticSecret::new(&mut rand_os::OsRng::new().unwrap()),
            connections: std::collections::BTreeMap::new(),
        };
        let client = super::Reprehensible {
            private_key: x25519_dalek::StaticSecret::new(&mut rand_os::OsRng::new().unwrap()),
            connections: std::collections::BTreeMap::new(),
        };

        let server_pub = x25519_dalek::PublicKey::from(&server.private_key);
        let client_pub = x25519_dalek::PublicKey::from(&client.private_key);
        let message = client.private_key.diffie_hellman(&server_pub);
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
}
