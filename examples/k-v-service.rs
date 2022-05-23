mod utils;
use std::collections::{BTreeMap, HashMap};
use std::os::unix::io::AsRawFd;
use std::fmt::Write;

use log::debug;
use smoltcp::ohua_util::store::{Store, Message, RequestMsg};
use smoltcp::iface::{InterfaceBuilder, NeighborCache};
use smoltcp::phy::{wait as phy_wait, Medium, Device, TunTapInterface, Loopback};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

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
    // 1. Do something with Store
    //let mut some_table = HashMap::new();
    //some_table.insert("k1", "v1");
    let mut store = Store::default();
    let test_msg = Message::Read(RequestMsg {table: "sometable".to_string(), key: "somekey".to_string() });

    // 2. Get the simple hello world server running
    // 3. simplify as far as possible i.e. use as few smolTCP structs 'n helpers
    /* Leave out command line configuration for now


    let (mut opts, mut free) = utils::create_options();
    utils::add_tuntap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tuntap_options(&mut matches);
    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);
      */
    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; 64]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; 128]);
    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

    /*For now I use loopback as interface*/
    let device = TunTapInterface::new("tap0", Medium::Ethernet).unwrap();
    let fd = device.as_raw_fd();
    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let ip_addrs = [
        IpCidr::new(IpAddress::v4(192, 168, 211, 117), 8)
    ];

    let medium = device.capabilities().medium;
    let mut builder = InterfaceBuilder::new(device, vec![]).ip_addrs(ip_addrs);
    if medium == Medium::Ethernet {
        builder = builder
            .hardware_addr(EthernetAddress::default().into())
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
        println!("Made it through polling");
        // tcp: respond "hello"
        let socket = iface.get_socket::<TcpSocket>(tcp_handle);
        if !socket.is_open() {
            socket.listen(6969).unwrap();
        }
        if socket.is_open(){
            println!("socket 6969 is listening");
        }

        if socket.can_send() {
            println!("tcp:6969 send greeting");
            writeln!(socket, "hello").unwrap();
            println!("tcp:6969 close");
            socket.close();
        }
        phy_wait(fd, iface.poll_delay(timestamp)).expect("wait error");
    }

    // 4. Connect hello world server with Store

}