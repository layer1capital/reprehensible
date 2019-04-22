use reprehensible::*;
mod util;

#[test]
#[ignore]
fn retransmit_attack() {
    // problem:
    // since datagrams are unordered, retransmitted datagrams will be accepted

    let server = AntiRetransmit::create();
    let client = AntiRetransmit::create();
    let mut hello = b"hello".to_owned();
    let datagram = client.send(&server.pk(), &mut hello);

    assert_eq!(
        &server
            .recv(util::copy_datagram(&datagram, &mut [0u8; 100]))
            .unwrap()
            .payload(),
        &b"hello"
    );

    // Fails because server is vulnerable to retransmission attacks.
    assert!(&server.recv(datagram).is_none());
}

struct AntiRetransmit {
    pub sk: SecretKey,
}

impl AntiRetransmit {
    fn create() -> AntiRetransmit {
        AntiRetransmit { sk: random_sk() }
    }

    fn send<'a>(&self, _dest_pk: &PublicKey, _plaintext: &'a mut [u8]) -> Datagram<'a> {
        unimplemented!()
    }

    fn recv<'a>(&self, _dg: Datagram<'a>) -> Option<DatagramDecrypted<'a>> {
        unimplemented!()
    }

    fn pk(&self) -> PublicKey {
        self.sk.public_key()
    }
}
