use keybob::Key;
use miscreant::stream::{Encryptor, Decryptor, NONCE_SIZE};
use miscreant::Aes128SivAead;
use std::io::Result;

const NONCE_PREFIX: &[u8; NONCE_SIZE] = &[0u8; NONCE_SIZE];

pub struct En(Encryptor<Aes128SivAead>);

impl En {
    pub fn new(key: &Key) -> Self {
        En(Encryptor::new(key.as_slice(), NONCE_PREFIX))
    }
}

impl FnOnce<(Vec<u8>,)> for En {
    type Output = Vec<u8>;

    extern "rust-call" fn call_once(mut self, args: (Vec<u8>,)) -> Self::Output {
        self.0.seal_next(&[], args.0.as_slice())
    }
}

impl FnMut<(Vec<u8>,)> for En {
    extern "rust-call" fn call_mut(&mut self, args: (Vec<u8>,)) -> Self::Output {
        self.0.seal_next(&[], args.0.as_slice())
    }
}

pub struct De(Decryptor<Aes128SivAead>);

impl De {
    pub fn new(key: &Key) -> Self {
        De(Decryptor::new(key.as_slice(), NONCE_PREFIX))
    }
}

impl FnOnce<(Vec<u8>,)> for De {
    type Output = Result<Vec<u8>>;

    extern "rust-call" fn call_once(mut self, args: (Vec<u8>,)) -> Self::Output {
        let opened = self.0.open_next(&[], args.0.as_slice()).unwrap();
        Ok(opened)
    }
}

impl FnMut<(Vec<u8>,)> for De {
    extern "rust-call" fn call_mut(&mut self, args: (Vec<u8>,)) -> Self::Output {
        let opened = self.0.open_next(&[], args.0.as_slice()).unwrap();
        Ok(opened)
    }
}
