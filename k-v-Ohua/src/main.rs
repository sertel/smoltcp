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
    let (mut app, mut sockets):(App, SocketSet) = init_app_and_sockets();
    let (mut ip_stack, mut device, fd):(Interface<'static>, TunTapInterface, RawFd) = init_stack_and_device();

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

// The timestamp is taken every time before we call poll, and then
// set in the inner interface
// The same timestamp is used in each round to call poll_delay
// which again sets the inner.now value to that same timestamp
// The problem is, that poll_delay takes thi sockets after they have
// been altered by the app
// so poll_delay is called with sockets from the 'next call' and timestamp from
// the current call (or current and last respectively)
// This means we can call poll_delay before we process the sockets. But we
/// can not 'wait' inside the interface because `phy_wait()` uses a
/// file descriptor to check when the device is available. I don't know how
/// we can realize this in M3.

fn loop_as_rec(
    mut app:App, mut ip_stack: Interface<'static>,
    mut device:TunTapInterface, mut sockets: SocketSet<'_>,
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
    mut ip_stack: Interface<'static>,
    device: D,
    sockets: SocketSet,
    ) -> (Result<bool>,Interface, D, SocketSet)
    where
        D: for<'d> Device<'d>,
    {
       let ((readiness_has_changed, sockets_used), ip_stack_used, device_used) = poll_recursion_on_call(ip_stack, InterfaceCall::InitPoll(sockets, timestamp), device);

        (Ok(readiness_has_changed), ip_stack_used, device_used, sockets_used)
    }

// this is currently just the outer poll loop + the egress loop
// Todo: The inner workings of interface.process_call need to be changeed to also include
//       poll loop + (ingress loop + egress loop). However this function will not change
//       as it merely distinguishes whether or not to keep looping between
//       interface and device.
fn poll_recursion_on_call<D>(
    mut ip_stack: Interface,
    iface_call: InterfaceCall,
    mut device: D
    ) -> ((bool, SocketSet), Interface, D)
    where D: for<'d> Device<'d>,
    {
        let device_call_or_return = ip_stack.process_call::<D>(iface_call);
        if Either::is_left(&device_call_or_return){
            let next_iface_call = device.process_call(device_call_or_return.left_or_panic());
            poll_recursion_on_call(ip_stack, next_iface_call, device)
        } else {
            // return = (processed_any, sockets)
            (device_call_or_return.right_or_panic(), ip_stack, device)
        }
    }
