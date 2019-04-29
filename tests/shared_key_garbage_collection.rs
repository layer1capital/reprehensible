use lru::LruCache;
use reprehensible::*;

// Problem:
// session_cache only grows. An attack may fill it, causing the server to run out of memory.
// The cache may also fill over time in the absence of attacks.

// Solution:
// Use an Least Recently Used cache to toss old entries.

// To protect against a denile of service attack, it's recomended you combine this method
// with the one outlined in 'puzzle.rs'

#[test]
fn shared_key_one_call() {
    let mut server = ReprehensibleCache::create();
    let mut client = ReprehensibleCache::create();
    let mut hello = b"hello".to_owned();
    let datagram = client.send(&server.pk(), &mut hello);
    let datagram_decrypted = server.recv(datagram).unwrap();
    assert_eq!(datagram_decrypted.peer_pk().0, client.pk().0);
    assert_eq!(&datagram_decrypted.payload(), &b"hello");
}

#[test]
fn shared_key_garbage_collection() {
    let mut server = ReprehensibleCache::create();
    for i in 0..20 {
        let mut client = Reprehensible::create(random_sk());
        let mut hello = b"hello".to_owned();
        let datagram = client.send(&server.pk(), &mut hello);
        let datagram_decrypted = server.recv(datagram).unwrap();
        assert_eq!(datagram_decrypted.peer_pk().0, client.pk().0);
        assert_eq!(&datagram_decrypted.payload(), &b"hello");

        assert_eq!(server.session_cache.len(), (i + 1).min(10));
        assert_eq!(
            server.session_cache.len(),
            server.session_cache.iter().map(|_| 1).sum()
        );
    }
}

struct ReprehensibleCache {
    pub sk: SecretKey,
    pub session_cache: LruCache<PublicKey, SessionKeys>,
}

impl ReprehensibleCache {
    fn create() -> Self {
        ReprehensibleCache {
            sk: random_sk(),
            session_cache: LruCache::new(10),
        }
    }

    fn send<'a>(&mut self, dest_pk: &PublicKey, plaintext: &'a mut [u8]) -> Datagram<'a> {
        let self_pk = self.pk();
        self.session_keys(dest_pk)
            .seal(self_pk, gen_nonce(), plaintext)
    }

    fn recv<'a>(&mut self, dg: Datagram<'a>) -> Option<DatagramDecrypted<'a>> {
        self.session_keys(&dg.peer_pk).open(dg)
    }

    fn pk(&self) -> PublicKey {
        self.sk.public_key()
    }

    fn session_keys(&mut self, peer_pk: &PublicKey) -> SessionKeys {
        // check cache, if present, return item
        let sk = self.session_cache.get(peer_pk);
        if sk.is_some() {
            return sk.unwrap().clone();
        }

        // session keys were not cached, we must generate new ones
        let sks = SessionKeys::compute(&self.sk, peer_pk);
        self.session_cache.put(*peer_pk, sks.clone());
        sks
    }
}
