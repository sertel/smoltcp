mod ohua_util;


use std::os::unix::io::RawFd;
use defmt::debug;
use ohua_util::init_components::{init_app_and_sockets, init_stack_and_device};
use smoltcp::{Either, Error, Result};
use smoltcp::iface::{OInterface, Interface, SocketSet, poll_7_egress_ask, InterfaceCall};
use smoltcp::phy::{Device, TunTapInterface, wait as phy_wait};
use smoltcp::time::Instant;
use crate::ohua_util::init_components::App;

// This is just a wrapper as Ohua might not like literals
fn should_continue() -> bool {true}

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


/* Target:
--> App --> IP_Stack --> Device

fn loop_as_rec(app, ip_stack, device, sockets, call) {
     let app_or_dev_call = ip_stack.process(call);
     let iface_call = {
        if Either::is_left(app_or_dev_call) {
            app.process_call(app_or_dev_call.left_or_panic())
        } else {
            device.process_call(app_or_dev_call.right_or_panic())
        }
     }
     if should_continue() {
        loop_as_rec(app, ip_stack, device, sockets, iface_call)
     } else {
        ()
     }
}


*/

/*
current structure
outer_loop {
    timestamp = Instant::now();
    poll_result = inner_loop(timestamp, iface, device, sockets)
    app_result = app.do_stuff(poll_result)
    outer_loop()
}

*/

fn loop_as_rec(
    mut app:App, mut ip_stack: Interface,
    mut device:TunTapInterface, mut sockets: SocketSet<'static>,
    fd:RawFd)  -> ()
    {
    let timestamp = Instant::now();
    let (poll_res, mut ip_stack_poll, device_poll, sockets_poll):
        (Result<bool>, Interface, TunTapInterface, SocketSet) =
        egress_poll(timestamp, ip_stack, device, sockets);

    let sockets_do_app_stuff: SocketSet = app.do_app_stuff(sockets_poll, poll_res);
        
    phy_wait(fd, ip_stack_poll.poll_delay(timestamp, &sockets_do_app_stuff)).expect("wait error");


    if should_continue() {
        loop_as_rec(app, ip_stack_poll, device_poll, sockets_do_app_stuff, fd)
    } else { () }
}

pub fn egress_poll<D>(
    timestamp: Instant,
    mut ip_stack: Interface,
    device: D,
    sockets: SocketSet,
    ) -> (Result<bool>,Interface, D, SocketSet)
    where
        D: for<'d> Device<'d>,
    {
        ip_stack.inner.now = timestamp;
        let readiness_changed = false;

        let (readiness_has_changed,ip_stack_used, device_used, sockets_used) =
            simpl_poll_inner(timestamp, ip_stack, device, sockets,readiness_changed);

        (Ok(readiness_has_changed), ip_stack_used, device_used, sockets_used)
    }

pub fn simpl_poll_inner<D>(
    timestamp: Instant,
    mut ip_stack: Interface,
    device: D,
    mut sockets: SocketSet,
    readiness_may_have_changed: bool
    ) -> (bool, Interface, D, SocketSet)
    where D: for<'d> Device<'d>,
{

    let processed_any = false; //self.socket_ingress(device, &mut sockets);
    let ((emitted_any, sockets_after_loop), ip_stack_used, device_used) = egress_recursion_on_call(ip_stack, InterfaceCall::InitEgress(sockets), device);

    // Also leave this out for now
    //#[cfg(feature = "proto-igmp")]
    //self.igmp_egress(device)?;

    if processed_any || emitted_any {
        simpl_poll_inner(timestamp, ip_stack_used, device_used, sockets_after_loop, true)
    } else {
        (readiness_may_have_changed, ip_stack_used, device_used, sockets_after_loop)
    }

}

fn egress_recursion_on_call<D>(
    mut ip_stack: Interface,
    iface_call: InterfaceCall,
    mut device: D
    ) -> ((bool, SocketSet), Interface, D,)
    where D: for<'d> Device<'d>,
    {
        let device_call_or_return = ip_stack.process_call::<D>(iface_call);
        if Either::is_left(&device_call_or_return){
            let next_iface_call = device.process_call(device_call_or_return.left_or_panic());
            egress_recursion_on_call(ip_stack, next_iface_call, device)
        } else {
            // This should return (sockets, emitted__any)
            (device_call_or_return.right_or_panic(), ip_stack, device)
        }
    }
