mod ohua_util;


use std::os::unix::io::RawFd;
use ohua_util::init_components::{init_app_and_sockets, init_stack_and_device};
use smoltcp::{Either, Result};
use smoltcp::iface::{Interface, SocketSet, InterfaceCall, Messages, SocketHandle};
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
    let (mut ip_stack, handels, mut device, fd):(Interface, Vec<SocketHandle>, TunTapInterface, RawFd) = init_stack_and_device();
    let (app, messages):(App,  Messages) = init_app_and_sockets(handels);
// ToDo: Currently we send around the actual SocketSet
//       -> this will not work out of the box, as SocketSet and the Sockets do
//          not implement serialization
//       -> we either need to implement serialization for the sockets OR
//          implement a serial format to identify sockets and operations on sockets
//          as well as a "replay" function to apply the changes/functions either side
//          made on their SocketSet on the other side of the channel stack <-> app

    loop_as_rec(app, ip_stack, device, messages, fd)
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
    mut app:App, mut ip_stack: Interface,
    mut device:TunTapInterface, messages:Messages,
    fd:RawFd) -> ()
    {
    let timestamp = Instant::now();
    let (poll_res, mut ip_stack_poll, device_poll, messages_poll):
        (Result<bool>, Interface, TunTapInterface, Messages) =
        poll_recursion_on_call(ip_stack, InterfaceCall::InitPoll(messages, timestamp), device);

    let messages_do_app_stuff: Messages = app.do_app_stuff(poll_res, messages_poll);
        
    phy_wait(fd, ip_stack_poll.poll_delay(timestamp)).expect("wait error");


    if should_continue() {
        loop_as_rec(app, ip_stack_poll, device_poll, messages_do_app_stuff, fd)
    } else { () }
}

// this is currently just the outer poll loop + the egress loop
fn poll_recursion_on_call<'a, D>(
    mut ip_stack: Interface<'a>,
    iface_call: InterfaceCall,
    mut device: D
    ) -> (Result<bool>, Interface<'a>, D, Messages)
    where D: for<'d> Device<'d>,
    {
        let device_call_or_return = ip_stack.process_call::<D>(iface_call);
        if Either::is_left(&device_call_or_return){
            let next_iface_call = device.process_call(device_call_or_return.left_or_panic());
            poll_recursion_on_call(ip_stack, next_iface_call, device)
        } else {
            let (readiness_has_changed, messages_new) = device_call_or_return.right_or_panic();
            (Ok(readiness_has_changed), ip_stack, device, messages_new)
        }
    }
