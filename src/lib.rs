#![feature(trivial_bounds)]
#![feature(unboxed_closures)]
#![feature(fn_traits)]

//!# Cobweb
//!Cobweb is a Rust library for creating fully asynchronous, encrypted VPNs, focused on simplicity and security. It supports both Mac and Linux - Windows support is a long-term goal but not planned.

//!Check out the documentation and examples for more info on how to use the library.

//!Cobweb is licensed under AGPLv3 to make sure that is free software and stays as free software. If you want a relicensed version for your project, email me and we (the contributers) will talk with you.

//!## Examples
//!Check the `examples` directory in the repository for example VPN client and server implementations.

//!## Next Release
//!Cobweb is currently in its `0.2.0` release - it provides enough features and documentation to be used powerfully, but lacks planned features, could use some better error handling and is not thoroughly tested. Use at your own risk.

//!`0.2.1` will see the first release of the optional `async-await-preview` feature to the crate. This flag will give access to code based on the upcoming `std::Future` and async/await APIs. Once those APIs become stable, the code based on the `futures` crate will be deprecated and moved under an optional `old-futures` flag, and Cobweb will see its `0.3.0` release.

mod en;

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
    /// A simple TUN interface.
    ///
    /// # Examples
    /// ```let tun = Tun::new(&handle).unwrap();
    /// tun.send(vec![1, 3, 3, 7]).unwrap();
    /// ```
    
    sink: SplitSink<Async>,
    stream: SplitStream<Async>,
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
        /// Consumes the Tun and create an EncryptedTun.
        /// You can use all the same methods on an EncryptedTun as you can with a regular Tun.
        
        let encryptor = En::new(&key);
        let decryptor = De::new(&key);
       
        Ok(EncryptedTun {
            sink: self.sink.with(decryptor),
            stream: self.stream.map(encryptor),
        })
    }

    pub fn send(self, msg: Vec<u8>) -> Result<()> {
        /// Sends some bytes through the TUN device to whatever you have connected on the other end
        
        match self.sink.send(msg).wait() {
            Ok(_res) => Ok(()),
            Err(err) => Err(err)
        }
    }

    pub fn recv(self, buf: &mut Vec<u8>) -> Result<()> {
        /// Receives bytes from the TUN device

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

impl Sink for Tun {
    type SinkItem = Vec<u8>;
    type SinkError = std::io::Error;

    fn start_send(&mut self, item: Vec<u8>) -> DualResult<futures::AsyncSink<Vec<u8>>, std::io::Error> {
        self.sink.start_send(item)
    }

    fn poll_complete(&mut self) -> DualResult<futures::Async<()>, std::io::Error> {
        self.sink.poll_complete()
    }
}

impl Stream for Tun {
    type Item = Vec<u8>;
    type Error = std::io::Error;

    fn poll(&mut self) -> DualResult<futures::Async<Option<Vec<u8>>>, std::io::Error> {
        self.stream.poll()
    }
}

pub struct EncryptedTun {
    /// An interface to an encrypted TUN device.
    ///
    /// # Examples
    /// ```let tun = Tun::new(&handle).unwrap()
    ///              .encrypt(&Key::new(KeyType::Aes256))
    ///              .unwrap();
    /// tun.send(vec![1, 3, 3, 7]).unwrap();
    /// ```
    
    sink: With<SplitSink<Async>, Vec<u8>, en::De, DualResult<Vec<u8>, std::io::Error>>,
    stream: Map<SplitStream<Async>, en::En>,
}

impl EncryptedTun {
    pub fn send(self, msg: Vec<u8>) -> Result<()> {
        /// Sends some bytes through the TUN device to whatever you have connected on the other end
        
        match self.sink.send(msg).wait() {
            Ok(_res) => Ok(()),
            Err(err) => Err(err)
        }
    }

    pub fn recv(self, buf: &mut Vec<u8>) -> Result<()> {
        /// Receives bytes from the TUN device
        
        match self.stream.take(1).wait().last() {
            Some(res) => {
                buf.extend(res.unwrap().as_slice());
                Ok(())
                },
            None => Err(std::io::Error::new(std::io::ErrorKind::Other, "Sending failed"))
        }
    }

    pub fn split(self) -> (With<SplitSink<Async>, Vec<u8>, en::De, DualResult<Vec<u8>, std::io::Error>>, Map<SplitStream<Async>, en::En>) {
        /// Split the interface into its Sink and Stream components.
        /// This is useful if you want to send and receive bytes from
        /// another interface (like a UDP socket for example) and send them to
        /// your TUN device.

        (self.sink, self.stream)
    }
}

impl Sink for EncryptedTun {
    type SinkItem = Vec<u8>;
    type SinkError = std::io::Error;

    fn start_send(&mut self, item: Vec<u8>) -> DualResult<futures::AsyncSink<Vec<u8>>, std::io::Error> {
        self.sink.start_send(item)
    }

    fn poll_complete(&mut self) -> DualResult<futures::Async<()>, std::io::Error> {
        self.sink.poll_complete()
    }
}

impl Stream for EncryptedTun {
    type Item = Vec<u8>;
    type Error = std::io::Error;

    fn poll(&mut self) -> DualResult<futures::Async<Option<Vec<u8>>>, std::io::Error> {
        self.stream.poll()
    }
}
