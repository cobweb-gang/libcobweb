#![feature(trivial_bounds)]
#![feature(unboxed_closures)]
#![feature(fn_traits)]

use crate::en::{En, De};
use std::io::Result;
use keybob::Key;
use tun_tap::{Iface, Mode};
use tun_tap::r#async::Async;
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

pub struct Tun {
    // A simple TUN interface.
    //
    // # Examples
    // ```let tun = Tun::new(&handle).unwrap();
    // tun.send(vec![1, 3, 3, 7]).unwrap();
    // ```
    
    sink: SplitSink<Async>,
    stream: SplitStream<Async>,
}

pub struct EncryptedTun {
    // An interface to an encrypted TUN device.
    //
    // # Examples
    // ```let tun = Tun::new(&handle).unwrap()
    //              .encrypt(&Key::new(KeyType::Aes256))
    //              .unwrap();
    // tun.send(vec![1, 3, 3, 7]).unwrap();
    // ```
    
    sink: With<SplitSink<Async>, Vec<u8>, en::De, DualResult<Vec<u8>, std::io::Error>>,
    stream: Map<SplitStream<Async>, en::En>,
}

impl Tun {
    pub fn new(handle: &Handle) -> Result<Tun>
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
        
        Ok(Tun {
            sink: sink,
            stream: stream,
        })
    }
    
    pub fn encrypt(self, key: &Key) -> Result<EncryptedTun> {
        // Consumes the Tun and create an EncryptedTun.
        // You can use all the same methods on an EncryptedTun as you can with a regular Tun.
        
        let encryptor = En::new(&key);
        let decryptor = De::new(&key);
       
        Ok(EncryptedTun {
            sink: self.sink.with(decryptor),
            stream: self.stream.map(encryptor),
        })
    }

    pub fn send(self, msg: Vec<u8>) -> Result<()> {
        // Sends some bytes through the TUN device to whatever you have connected on the other end
        
        match self.sink.send(msg).wait() {
            Ok(_res) => Ok(()),
            Err(err) => Err(err)
        }
    }

    pub fn recv(self, buf: &mut Vec<u8>) -> Result<()> {
        // Receives bytes from the TUN device

        match self.stream.take(1).wait().last() {
            Some(res) => {
                buf.extend(res.unwrap().as_slice());
                Ok(())
                },
            None => Err(std::io::Error::new(std::io::ErrorKind::Other, "Sending failed"))
        }
    }

    pub fn split(self) -> (SplitSink<Async>, SplitStream<Async>) {
        (self.sink, self.stream)
    }
}

impl EncryptedTun {
    pub fn send(self, msg: Vec<u8>) -> Result<()> {
        // Sends some bytes through the TUN device to whatever you have connected on the other end
        
        match self.sink.send(msg).wait() {
            Ok(_res) => Ok(()),
            Err(err) => Err(err)
        }
    }

    pub fn recv(self, buf: &mut Vec<u8>) -> Result<()> {
        // Receives bytes from the TUN device
        
        match self.stream.take(1).wait().last() {
            Some(res) => {
                buf.extend(res.unwrap().as_slice());
                Ok(())
                },
            None => Err(std::io::Error::new(std::io::ErrorKind::Other, "Sending failed"))
        }
    }

    pub fn split(self) -> (With<SplitSink<Async>, Vec<u8>, en::De, DualResult<Vec<u8>, std::io::Error>>, Map<SplitStream<Async>, en::En>) {
        // Split the interface into its Sink and Stream components.
        // This is useful if you want to send and receive bytes from
        // another interface (like a UDP socket for example) and send them to
        // your TUN device.

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
