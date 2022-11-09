mod ohua_util;


use std::os::unix::io::RawFd;
use defmt::debug;
use ohua_util::init_components::{init_app_and_sockets, init_stack_and_device};
use smoltcp::{Error,Result};
use smoltcp::iface::{OInterface, Interface, SocketSet, poll_6_egress_ask};
use smoltcp::phy::{Device, TunTapInterface, wait as phy_wait};
use smoltcp::time::Instant;
use crate::ohua_util::init_components::App;



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
    let (mut app, mut sockets):(App, SocketSet<'static>) = init_app_and_sockets();
    let (mut ip_stack, mut device, fd):(Interface, TunTapInterface, RawFd) = init_stack_and_device();

// ToDo: Currently we send around the actual SocketSet
//       -> this will not work out of the box, as SocketSet and the Sockets do
//          not implement serialization
//       -> we either need to implement serialization for the sockets OR
//          implement a serial format to identify sockets and operations on sockets
//          as well as a "replay" function to apply the changes/functions either side
//          made on their SocketSet on the other side of the channel stack <-> app

    loop_as_rec(app, ip_stack, device, sockets, fd)
}


fn loop_as_rec(
    mut app:App, mut ip_stack: Interface,
    mut device:TunTapInterface, mut sockets: SocketSet<'static>,
    fd:RawFd)  -> ()
    {
    let timestamp = Instant::now();
    let (poll_res, mut ip_stack_poll, device_poll, sockets_poll):
        (Result<bool>, Interface, TunTapInterface, SocketSet) =
        poll_6_egress_ask(timestamp, ip_stack, device, sockets);

    let (should_continue, sockets_do_app_stuff): (bool, SocketSet) = app.do_app_stuff(sockets_poll, poll_res);
        
    phy_wait(fd, ip_stack_poll.poll_delay(timestamp, &sockets_do_app_stuff)).expect("wait error");


    if should_continue {
        loop_as_rec(app, ip_stack_poll, device_poll, sockets_do_app_stuff, fd)
    } else { () }
}

