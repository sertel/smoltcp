use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;
use log::debug;

//use crate::ohua_util::store::Store;
//use crate::ohua_util::store_ycsb::Store;
use smoltcp::iface::{FragmentsCache, NeighborCache, SocketHandle, SocketSet, Interface, InterfaceBuilder, Messages};
use smoltcp::phy::{Device, Medium, TunTapInterface};
use smoltcp::socket::{tcp};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};
use smoltcp::{Result};
use std::str;

pub fn init_stack_and_device() -> (Interface<'static>,Vec<SocketHandle>, TunTapInterface)
{
    let mut out_packet_buffer = vec![];// [0u8; 1280];
    // First init the device
    let mut device = TunTapInterface::new("tap0", Medium::Ethernet).unwrap();

    // Second: assemble the interface components
    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [
        IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24)
    ];

    let medium = device.capabilities().medium;

    // Third assemble the sockets and the interface
    let mut sockets = vec![];

    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);

    let mut builder = InterfaceBuilder::new(sockets).ip_addrs(ip_addrs);

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
    let mut iface = builder.finalize(&mut device);
    let tcp_socket_handle = iface.add_socket(tcp_socket);
    (iface, vec![tcp_socket_handle],  device)
}


pub fn init_app(handles:Vec<SocketHandle>) -> App {
    //let store = Store::default();
    App{ /*store,*/ tcp_socket_handles: handles}
}


pub struct App {
    //store: Store,
    tcp_socket_handles: Vec<SocketHandle>,
}


impl App {
    pub fn do_app_stuff(
        &mut self,
        poll_res: Result<bool>,
        mut messages:Messages
    ) -> Messages
    {
    match poll_res {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

    // We don't do anything with the messages here and return what we received,
    // just like in the original benchmark.rs
    messages
    }
    /*
    fn handle_message(&mut self, input: &mut Vec<u8>) -> Vec<u8> {
        self.store.handle_message(&input)
    }*/

}
