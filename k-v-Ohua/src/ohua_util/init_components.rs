use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;

use crate::ohua_util::store::Store;
use smoltcp::iface::{FragmentsCache, OInterface, OInterfaceBuilder, NeighborCache, SocketHandle, SocketSet};
use smoltcp::phy::{Device, Medium, TunTapInterface};
use smoltcp::socket::{tcp_ohua};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};



pub fn init_device() -> (TunTapInterface, RawFd) {
    let device = TunTapInterface::new("tap0", Medium::Ethernet).unwrap();
    let file_descriptor = device.as_raw_fd();
    (device, file_descriptor)
}

// TODO: For now I only have one Socket. In general I'll have to consider multiple sockets.
//   In that scenario I'll need send_data and receive_data structures, that link the sockets to the
//   app data to send or received via them
pub fn init_tcp_ip_stack<'a>(mut device: TunTapInterface, out_packet_buffer: &'a mut [u8])
                             ->  (OInterface<'a>,SocketSet, SocketHandle, TunTapInterface) {

    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [
        IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24)
    ];

    let medium = device.capabilities().medium;
    let mut builder = OInterfaceBuilder::new().ip_addrs(ip_addrs);

    //ToDo: fragments, outpacket and 6loWPAN are guarded by compiler flags.
    //      However, without them I get a panic from the Builder
    //      -> clarify why/is there is no default and if there should be one.
    let ipv4_frag_cache = FragmentsCache::new(vec![], BTreeMap::new());
    builder = builder.ipv4_fragments_cache(ipv4_frag_cache);

    let sixlowpan_frag_cache = FragmentsCache::new(vec![], BTreeMap::new());
    builder = builder
            .sixlowpan_fragments_cache(sixlowpan_frag_cache)
            .sixlowpan_out_packet_cache( out_packet_buffer);
    if medium == Medium::Ethernet {
        builder = builder
            .hardware_addr(ethernet_addr.into())
            .neighbor_cache(neighbor_cache);
    }
    let iface = builder.finalize(&mut device);
    let mut sockets = SocketSet::new(vec![]);

    let tcp_rx_buffer = tcp_ohua::SocketBuffer::new(vec![0; 64]);
    let tcp_tx_buffer = tcp_ohua::SocketBuffer::new(vec![0; 128]);
    let tcp_socket = tcp_ohua::OhuaTcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

    let tcp_handle = sockets.add::<tcp_ohua::OhuaTcpSocket>(tcp_socket);
    (iface, sockets, tcp_handle, device)
}

pub fn init_app()-> App{
    let store = Store::default();
    App{ store: store , testnum:3}
}

pub struct App {
    store: Store,
    pub testnum:i16,
}


impl App {
    pub fn do_app_stuff(self){
        println!("Doing app stuff")
    }
    pub fn handle_message(&mut self, input:Vec<u8>)-> Vec<u8> {
        self.store.handle_message(&input)
    }
}