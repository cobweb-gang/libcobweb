#![feature(trivial_bounds)]
#![feature(unboxed_closures)]
#![feature(fn_traits)]

use crate::en::{En, De};
use std::io::Result;
use keybob::Key;
use tun_tap::{Iface, Mode};
use tun_tap::r#async::Async;
use tun_tap_mac::{Iface as MacIface, Mode as MacMode};
use tun_tap_mac::r#async::Async as MacAsync;
use std::process::Command;
use tokio_core::reactor::Handle;
use futures::prelude::*;
use futures::stream::{SplitSink, SplitStream};
use futures::sink::With;
use futures::stream::Map;
use std::result::Result as DualResult;

fn cmd(cmd: &str, args: &[&str]) {
    let ecode = Command::new("ip")
        .args(args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(ecode.success(), "Failed to execute {}", cmd);
}

pub struct EncryptedTun<T: Sink, U: Stream> {
    sink: T,
    stream: U,
}

impl<T, U> EncryptedTun<T, U>
where T: Sink<SinkItem=Vec<u8>>,
      U: Stream<Item=Vec<u8>>,
      U::Error: std::fmt::Debug,
{
    pub fn new(handle: &Handle) -> Result<
        EncryptedTun<
            SplitSink<Async>,
            SplitStream<Async>
            >>
        {
        
        let tun = Iface::new("vpn%d", Mode::Tun);

        if tun.is_err() {
            eprintln!("ERROR: Permission denied. Try running as superuser");
            ::std::process::exit(1);
        }
       
        let tun_ok = tun.unwrap();
        cmd("ip", &["addr", "add", "dev", tun_ok.name(), "10.107.1.3/24"]);
        cmd("ip", &["link", "set", "up", "dev", tun_ok.name()]);
        let (sink, stream) = Async::new(tun_ok, handle)
            .unwrap()
            .split();
        
        Ok(EncryptedTun {
            sink: sink,
            stream: stream,
        })
    }

    #[cfg(target_os = "macos")]
    pub fn new(handle: &Handle) -> Result<
        EncryptedTun<
            SplitSink<MacAsync>,
            SplitStream<MacAsync>
            >>
        {
        
        let tun = MacIface::new("vpn%d", Mode::Tun);

        if tun.is_err() {
            eprintln!("ERROR: Permission denied. Try running as superuser");
            ::std::process::exit(1);
        }
       
        let tun_ok = tun.unwrap();
        cmd("ip", &["addr", "add", "dev", tun_ok.name(), "10.107.1.3/24"]);
        cmd("ip", &["link", "set", "up", "dev", tun_ok.name()]);
        let (sink, stream) = MacAsync::new(tun_ok, handle)
            .unwrap()
            .split();
        
        Ok(EncryptedTun {
            sink: sink,
            stream: stream,
        })
    }
    
    pub fn encrypt(self, key: &Key) -> Result<
        EncryptedTun<
            With<T, Vec<u8>, De, Result<Vec<u8>>>,
            Map<U, En>
            >>
            where std::io::Error: std::convert::From<<T as futures::Sink>::SinkError>
            {
        let encryptor = En::new(&key);
        let decryptor = De::new(&key);
        
        let decrypted_sink = self.sink.with(decryptor);
        let encrypted_stream = self.stream.map(encryptor);
        
        Ok(EncryptedTun {
            sink: decrypted_sink,
            stream: encrypted_stream,
        })
    }

    pub fn send(self, msg: Vec<u8>) -> DualResult<T, <T as futures::sink::Sink>::SinkError> {
        self.sink.send(msg).wait()
    }

    pub fn recv(self) -> Result<U> {
        Ok(self.stream.take(1).into_inner())
    }

    pub fn split(self) -> (T, U) {
        (self.sink, self.stream)
    }
}

mod en {
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
}
