mod utils;

use std::collections::{BTreeMap};
use std::os::unix::io::AsRawFd;
use std::str;

use log::debug;
use smoltcp::ohua_util::store::Store;
use smoltcp::iface::{InterfaceBuilder, NeighborCache};
use smoltcp::phy::{wait as phy_wait, Medium, Device, TunTapInterface};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

fn process_octets(octets:&mut [u8]) -> (usize, Vec<u8>) {
    let recvd_len = octets.len();
    let data = octets.to_owned();
    if !data.is_empty(){
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


    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; 64]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; 128]);
    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);


    let device = TunTapInterface::new("tap0", Medium::Ethernet).unwrap();
    let fd = device.as_raw_fd();
    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [
        IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24)
    ];

    let medium = device.capabilities().medium;
    let mut builder = InterfaceBuilder::new(device, vec![]).ip_addrs(ip_addrs);
    if medium == Medium::Ethernet {
        builder = builder
            .hardware_addr(ethernet_addr.into())
            .neighbor_cache(neighbor_cache);
    }
    let mut iface = builder.finalize();

    let tcp_handle = iface.add_socket(tcp_socket);

    loop {
        let timestamp = Instant::now();
        match iface.poll(timestamp) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        let socket = iface.get_socket::<TcpSocket>(tcp_handle);
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

        phy_wait(fd, iface.poll_delay(timestamp)).expect("wait error");
    }
}