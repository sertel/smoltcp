use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;
use log::debug;

use crate::ohua_util::store::Store;
use smoltcp::iface::{FragmentsCache, OInterface, OInterfaceBuilder, NeighborCache, SocketHandle, SocketSet};
use smoltcp::phy::{Device, Medium, TunTapInterface};
use smoltcp::socket::{tcp_ohua};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};
// use smoltcp::{Result}; can't import bcs it's private
use std::str;




pub fn init_device() -> (TunTapInterface, RawFd) {
    let device = TunTapInterface::new("tap0", Medium::Ethernet).unwrap();
    let file_descriptor = device.as_raw_fd();
    (device, file_descriptor)
}


pub fn init_stack_and_device() -> (OInterface<'static>, TunTapInterface, RawFd)
{
    let mut out_packet_buffer = vec![];// [0u8; 1280];
    // First init the device
    let mut device = TunTapInterface::new("tap0", Medium::Ethernet).unwrap();
    let file_descriptor = device.as_raw_fd();

    // Second: assemble the interface components
    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [
        IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24)
    ];

    let medium = device.capabilities().medium;
    let mut builder = OInterfaceBuilder::new().ip_addrs(ip_addrs);

    //ToDo: fragments, outpacket and 6loWPAN are guarded by compiler flags.
    //      However, if I don't init them I get a panic from the Builder
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

    (iface, device, file_descriptor)
}

// ToDo: The SocketSet contains a 'ManagedSlice' of sockets and this seems to borrow
//       Sockets/Buffers so I need a lifetime annotation here
//       What does it mean to make it static, in particular considering that we will
//       send it between stack and app?
pub fn init_app_and_sockets() -> (App, SocketSet<'static>){
    let store = Store::default();
    let mut sockets = SocketSet::new(vec![]);

    let tcp_rx_buffer = tcp_ohua::SocketBuffer::new(vec![0; 64]);
    let tcp_tx_buffer = tcp_ohua::SocketBuffer::new(vec![0; 128]);
    let tcp_socket = tcp_ohua::OhuaTcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

    let tcp_socket_handle = sockets.add::<tcp_ohua::OhuaTcpSocket>(tcp_socket);
    (App{ store, tcp_socket_handle}, sockets)
}

// ToDo: For now the App has just one socket but I'll need a more sophisticated way
//       to store/identify handles for different sockets
pub struct App {
    store: Store,
    tcp_socket_handle: SocketHandle,
}


impl App {

    pub fn do_app_stuff<'s, E: std::fmt::Display>(
        &mut self,
        mut sockets_obj: SocketSet<'s>,
        poll_res: Result<bool, E>)
        -> (bool, SocketSet<'s>) {
            match poll_res {
                Ok(_) => {}
                Err(e) => {
                debug!("poll error: {}", e);
            }
        }
        let sockets = &mut sockets_obj;
        let socket = sockets.get_mut::<tcp_ohua::OhuaTcpSocket>(self.tcp_socket_handle);
        if !socket.is_open() {
            socket.listen(6969).unwrap();
        }

        if socket.may_recv() {
            // ToDo: Check how we will handle function references i.e. can we "tell"
            //       Socket.recv to use this/any partcular function?
            //       Simple way out would be to cleanly separate and have the socket return the pure buffer
            let input = socket.recv(App::process_octets).unwrap();
            if socket.can_send() && !input.is_empty() {
                debug!(
                    "tcp:6969 send data: {:?}",
                    str::from_utf8(input.as_ref()).unwrap_or("(invalid utf8)")
                );
                let outbytes = self.handle_message(input);
                socket.send_slice(&outbytes[..]).unwrap();
            }
        } else if socket.may_send() {
            debug!("tcp:6969 close");
            socket.close();
        }
        // Just make it clear -> this turns the outer recursion into an endless loop:
        let should_continue = true;
        (should_continue, sockets_obj)
    }

    fn handle_message(&mut self, input:Vec<u8>)-> Vec<u8> {
        self.store.handle_message(&input)
    }

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
}
