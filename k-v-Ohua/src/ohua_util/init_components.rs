use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;

use crate::ohua_util::store::Store;
use smoltcp::iface::{Interface, InterfaceBuilder, NeighborCache, SocketHandle};
use smoltcp::phy::{Device, Medium, TunTapInterface};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};



//Question: What lifetime and tpye do I actually need to return here? Is it ok to heve the
// Device by default living for the whole application lifetime?
pub fn init_device() -> (TunTapInterface, RawFd) {
    let device = TunTapInterface::new("tap0", Medium::Ethernet).unwrap();
    let file_descriptor = device.as_raw_fd();
    (device, file_descriptor)
}

// TODO: For now I only have one Socket. In general I'll have to consider multiple sockets.
//   In that scenario I'll need send_data and receive_data structures, that link the sockets to the
//   app data to send or received via them
pub fn init_tcp_ip_stack<'a>(device: TunTapInterface) ->  (Interface<'a, TunTapInterface>, SocketHandle) {

    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; 64]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; 128]);
    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

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
    (iface, tcp_handle)
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