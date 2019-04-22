use reprehensible::*;

// Problem:
// Generating session keys is expensive. It is relatively cheap for a remote peer to
// make a server generate tons of session keys just by sending garbage udp packets.

// Solution, demonstrated here:
// In a higher layer, require a puzzle to be solved before accepting datagrams for derivation.

#[test]
fn puzzle_client_server() {
    let server = ReprehensiblePuzzle::create();
    let client = ReprehensiblePuzzle::create();
    let mut hello = b"hello".to_owned();
    let datagram = client.send(&server.pk(), &mut hello);
    let datagram_decrypted = server.recv(datagram).unwrap();
    assert_eq!(datagram_decrypted.peer_pk().0, client.pk().0);
    assert_eq!(&datagram_decrypted.payload(), &b"hello");
}

#[test]
fn puzzle_lazy_client() {
    let server = ReprehensiblePuzzle::create();
    let mut client = ReprehensiblePuzzle::create();
    let mut hello = b"hello".to_owned();
    client.difficulty = 0;
    let datagram = client.send(&server.pk(), &mut hello);
    assert!(server.recv(datagram).is_none());
}

struct ReprehensiblePuzzle {
    pub sk: SecretKey,
    /// Number of bits that must be zero in order for the server to accept a connection.
    pub difficulty: u32,
}

impl ReprehensiblePuzzle {
    fn create() -> Self {
        ReprehensiblePuzzle {
            sk: random_sk(),
            difficulty: 13,
        }
    }

    fn send<'a>(&self, dest_pk: &PublicKey, plaintext: &'a mut [u8]) -> Datagram<'a> {
        // generate a nonce such that self.difficulty significant bits are 0
        let mut nonce = gen_nonce();
        let self_pk = self.pk();
        while score(&self_pk, &dest_pk, &nonce) < self.difficulty {
            inc(&mut nonce);
        }
        SessionKeys::compute(&self.sk, &dest_pk).seal(self_pk, nonce, plaintext)
    }

    fn recv<'a>(&self, dg: Datagram<'a>) -> Option<DatagramDecrypted<'a>> {
        if score(&dg.peer_pk, &self.pk(), &dg.nonce) < self.difficulty {
            None
        } else {
            SessionKeys::compute(&self.sk, &dg.peer_pk).open(dg)
        }
    }

    fn pk(&self) -> PublicKey {
        self.sk.public_key()
    }
}

fn score(tx_pk: &PublicKey, rx_pk: &PublicKey, nonce: &Nonce) -> u32 {
    use sha2::Digest;
    use std::convert::TryInto;
    let mut hasher = sha2::Sha256::new();
    hasher.input(&nonce.0);
    hasher.input(&rx_pk.0);
    hasher.input(&tx_pk.0);
    let r: [u8; 32] = hasher.result().as_slice().try_into().unwrap();
    leading_zeros(&r)
}

fn leading_zeros(inp: &[u8; 32]) -> u32 {
    let mut ret = 0;
    for n in inp {
        let lz = n.leading_zeros();
        ret += lz;
        if lz != 8 {
            break;
        }
    }
    return ret;
}

fn inc(n: &mut Nonce) {
    if n.0 == [u8::max_value(); 24] {
        n.0 = [0u8; 24];
    } else {
        n.increment_le_inplace();
    }
}
