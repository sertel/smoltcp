mod ohua_util;

use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::str;

use log::debug;
use ohua_util::store_ycsb::Store;
use smoltcp::iface::{FragmentsCache, InterfaceBuilder, NeighborCache, SocketSet};
use smoltcp::phy::{Device, Medium, Loopback, wait as phy_wait};
use smoltcp::socket::{tcp};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

mod mock {
    use smoltcp::time::{Duration, Instant};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // should be AtomicU64 but that's unstable
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Clock(Arc<AtomicUsize>);

    impl Clock {
        pub fn new() -> Clock {
            Clock(Arc::new(AtomicUsize::new(0)))
        }

        pub fn advance(&self, duration: Duration) {
            self.0.fetch_add(duration.total_millis() as usize, Ordering::SeqCst);
        }

        pub fn elapsed(&self) -> Instant {
            Instant::from_millis(self.0.load(Ordering::SeqCst) as i64)
        }
    }
}


fn process_octets(octets: &mut [u8]) -> (usize, Vec<u8>) {
    let recvd_len = octets.len();
    let data = octets.to_owned();
    if !data.is_empty() {
        debug!(
            "tcp:6970 recv data: {:?}",
            str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)")
        );
    }
    (recvd_len, data)
}

fn main() {
    println!(
        r#"
      ___           ___           ___           ___                    ___           ___
     /\  \         /\__\         /\__\         /\  \                  /\__\         /\__\
    /::\  \       /:/  /        /:/  /        /::\  \                /:/  /        /:/  /
   /:/\:\  \     /:/__/        /:/  /        /:/\:\  \              /:/__/        /:/  /
  /:/  \:\  \   /::\  \ ___   /:/  /  ___   /::\_\:\  \            /::\__\____   /:/__/  ___
 /:/__/ \:\__\ /:/\:\  /\__\ /:/__/  /\__\ /:/\:\ \:\__\          /:/\:::::\__\  |:|  | /\__\
 \:\  \ /:/  / \/__\:\/:/  / \:\  \ /:/  / \/__\:\/:/  /          \/_|:|~~|~     |:|  |/:/  /
  \:\  /:/  /       \::/  /   \:\  /:/  /       \::/  /              |:|  |      |:|__/:/  /
   \:\/:/  /        /:/  /     \:\/:/  /        /:/  /               |:|  |       \::::/__/
    \::/  /        /:/  /       \::/  /        /:/  /                |:|  |        ~~~~
     \/__/         \/__/         \/__/         \/__/                  \|__|
"#
    );
    let mut store = Store::default();


    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 64]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 128]);
    let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);


    let mut device = Loopback::new(Medium::Ethernet);
    let clock = mock::Clock::new();

    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [
        IpCidr::new(IpAddress::v4(127, 0, 0, 1), 24)
    ];

    let medium = device.capabilities().medium;
    let mut builder = InterfaceBuilder::new(vec![]).ip_addrs(ip_addrs);

    let ipv4_frag_cache = FragmentsCache::new(vec![], BTreeMap::new());
    builder = builder.ipv4_fragments_cache(ipv4_frag_cache);


    let mut out_packet_buffer = [0u8; 1280];

    let sixlowpan_frag_cache = FragmentsCache::new(vec![], BTreeMap::new());
    builder = builder.sixlowpan_fragments_cache(sixlowpan_frag_cache).sixlowpan_out_packet_cache(&mut out_packet_buffer[..]);


    if medium == Medium::Ethernet {
        builder = builder.hardware_addr(ethernet_addr.into()).neighbor_cache(neighbor_cache);
    }
    let mut iface = builder.finalize(&mut device);

    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);

    loop {
        match iface.poll(clock.elapsed(), &mut device, &mut sockets) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
        if !socket.is_open() {
            socket.listen(6969).unwrap();
        }

        if socket.may_recv() {
            let input = socket.recv(process_octets).unwrap();
            if socket.can_send() && !input.is_empty() {
                debug!(
                    "tcp:6969 send data: {:?}",
                    str::from_utf8(input.as_ref()).unwrap_or("(invalid utf8)")
                );
                let outbytes = store.handle_message(&input);
                socket.send_slice(&outbytes[..]).unwrap();
            }
        } else if socket.may_send() {
            debug!("tcp:6969 close");
            socket.close();
        }

        match iface.poll_delay(clock.elapsed(), &sockets) {
            Some(Duration::ZERO) => debug!("resuming"),
            Some(delay) => {
                debug!("sleeping for {} ms", delay);
                clock.advance(delay)
            }
            None => clock.advance(Duration::from_millis(1)),
        }
    }
}
