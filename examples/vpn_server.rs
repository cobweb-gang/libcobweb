// This is a simple VPN server implementation written with the EncryptedTun interface
// Please note that these examples have not been tested, and even if they did work you probably
// wouldn't want to use them primarily because of a lack of error handling and handshake security

extern crate futures;
extern crate tokio_core;
extern crate cobweb;
extern crate keybob;

use futures::prelude::*;
use tokio_core::net::{UdpSocket, UdpCodec};
use tokio_core::reactor::Core;
use cobweb::EncryptedTun;
use keybob::{Key, KeyType};


// This is a custom codec we've wrote for our UDP socket. It doesn't really do anything special,
// just makes sure to get the bytes back from the receiving end and encode the bytes sent, while
// pointing them to the correct address

struct VecCodec(SocketAddr);

impl UdpCodec for VecCodec {
    type In = Vec<u8>;
    type Out = Vec<u8>;
    fn decode(&mut self, _src: &SocketAddr, buf: &[u8]) -> Result<Self::In> {
        Ok(buf.to_owned())
    }
    fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) -> SocketAddr {
        buf.extend(&msg);
        self.0
    }
}

fn main() {
    let loc_addr = env::args()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let core = Core::new().unwrap();
    let handle = core.handle();
  
    // First we'll want to create a UDP socket, and then receive the key sent to us by the client
    let sock = UdpSocket::bind(&loc_addr, &handle).unwrap();
    let key: &mut [u8] = &mut [0u8];
    let (_num, rem_addr) = sock.recv_from(key).unwrap();

    // Here we initialize the EncryptedTun interface by first calling new(), and then encrypting it
    // with the encrypt() function

    // For now, we will have to initialize the interface using these unwieldly type definitions
    // This is planned to be fixed in later versions
    let tun = Tun::new(&handle)
        .unwrap()
        .encrypt(&key)
        .unwrap();

    // We'll want to split our tun interface into its sink and stream components
    let (tun_sink, tun_stream) = tun.split();

    // We'll split the UDP socket into its sink and stream as well
    let (udp_sink, udp_stream) = sock.framed(VecCodec(rem_addr))
        .split();
       
    // Finally, we are going to forward the streams of the tun and UDP socket into the sinks of the
    // other component. This is essentially what ties all of the components into a VPN; any bytes
    // received by the TUN device are automatically sent to the VPN server via the UDP sink, and
    // any bytes received from the server via the UDP stream are automatically written back to the
    // TUN device.
    let sender = tun_stream.forward(udp_sink);
    let receiver = udp_stream.forward(tun_sink);

    // Use the core to run these futures to completion
    core.run(sender.join(receiver))
        .unwrap();
}
