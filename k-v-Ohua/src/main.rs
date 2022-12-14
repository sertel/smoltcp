mod ohua_util;


use ohua_util::init_components::{init_app, init_stack_and_device};
use smoltcp::{Either, Result};
use smoltcp::iface::{Interface, SocketSet, InterfaceCall, Messages, SocketHandle};
use smoltcp::phy::{Device, Loopback, TunTapInterface};
use smoltcp::time::Instant;
use std::{thread};
use std::time::Duration;
use crate::ohua_util::init_components::App;

fn should_continue()-> bool {true}

fn maybe_wait(call: InterfaceCall) -> InterfaceCall {
    match call {
        InterfaceCall::ProcessWait(duration, dev_sgn) =>
            {
                if let Some(smoltcp_duration) = duration {
                thread::sleep(Duration::from_micros(smoltcp_duration.micros()))
                }
                return  InterfaceCall::InitPoll
            },
        other_call => other_call
    }
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
    let (mut ip_stack, handels, mut device):(Interface, Vec<SocketHandle>, TunTapInterface) = init_stack_and_device();
    let mut app: App = init_app(handels);
    let mut iface_call = InterfaceCall::InitPoll;

    loop_as_rec_limited(app, ip_stack, device, iface_call, 0)
    /*
    loop {
        let device_or_app_call = ip_stack.process_call::<TunTapInterface>(iface_call);
        if Either::is_left(&device_or_app_call){
            let call = device.process_call(device_or_app_call.left_or_panic());
            iface_call = maybe_wait(call)
        } else {
            let (readiness_has_changed, messages_new) = device_or_app_call.right_or_panic();
            let answers = app.do_app_stuff(Ok(readiness_has_changed), messages_new);
            iface_call = InterfaceCall::AnswerToSocket(answers);
        }
    }*/
}


fn loop_as_rec_limited(
    mut app: App,
    mut ip_stack: Interface,
    mut device: TunTapInterface,
    mut if_call: InterfaceCall,
    count: i32) -> () {
    // Without tailcall elimination, we can only test this recursive
    // Version via limiting it to few recursions, otherwise we get an
    // instant stack overflow
    if count > 10 {return}
    let device_or_app_call = ip_stack.process_call::<TunTapInterface>(if_call);
    let if_call_new =
            if Either::is_left(&device_or_app_call){
                let call = device.process_call(device_or_app_call.left_or_panic());
                maybe_wait(call)
            } else {
                let (readiness_has_changed, messages_new) = device_or_app_call.right_or_panic();
                let answers = app.do_app_stuff(Ok(readiness_has_changed), messages_new);
                InterfaceCall::AnswerToSocket(answers)
            };
    if should_continue() {
        loop_as_rec_limited(app, ip_stack, device, if_call_new, count+1)
    } else {
        ()
    }
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
