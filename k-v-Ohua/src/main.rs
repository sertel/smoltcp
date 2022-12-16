mod ohua_util;


use ohua_util::init_components::{init_app, init_stack_and_device};
use smoltcp::{Either, Result};
use smoltcp::iface::{Interface, SocketSet, InterfaceCall, Messages, SocketHandle};
use smoltcp::phy::{Device, DeviceCall, Loopback, TunTapInterface};
use smoltcp::time::{Instant, Duration as smolDuration};
use std::{thread};
use std::time::Duration;
use crate::ohua_util::init_components::{App, AppCall};


///Helper function to please Ohua
fn should_continue()-> bool {true}

///Helper function to a) please Ohua and b) enable simple replacement in M3
fn maybe_wait(call: Either<InterfaceCall, (Option<smolDuration>, bool)>) -> InterfaceCall {
   if Either::is_left(&call) {
       return call.left_or_panic()
   } else {
       let (duration, sign) = call.right_or_panic();
       if let Some(smoltcp_duration) = duration {
                thread::sleep(Duration::from_micros(smoltcp_duration.micros()))
        }
        return  InterfaceCall::InitPoll
   }
}

///Helper function to please Ohua
fn unwrap_call(call: Either<DeviceCall, (bool, Messages)>) -> (bool, Option<DeviceCall>, Option<AppCall>) {
    match call {
        Either::Left(device_call) => (true, Some(device_call), None),
        Either::Right((sign, messages)) => {
            let call: AppCall = (Ok(sign), messages);
            (false, None, Some(call))
         },
    }
}
///Helper function to please Ohua
fn as_some_call(call:Either<DeviceCall, (bool, Messages)>)
    -> Option<DeviceCall> {
    Some(call.left_or_panic())
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

    /*
    loop_as_rec_limited(app, ip_stack, device, iface_call, 0)

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
    app_iface_rec(app, ip_stack, device, iface_call)

}

fn app_iface_rec(
    mut app: App,
    mut ip_stack: Interface,
    mut device: TunTapInterface,
    mut if_call: InterfaceCall,
    ) -> () {

    let device_or_app_call: Either<DeviceCall, (bool, Messages)> = ip_stack.process_call::<TunTapInterface>(if_call);
    // actually at this point we know it's a device_call
    let dev_call: Option<DeviceCall> = as_some_call(device_or_app_call);
    let (app_call, ip_stack_n, device_n): (Option<AppCall>, Interface, TunTapInterface)
        = iface_device_rec(ip_stack, device, dev_call);
    let nothing: () = dummy();
    let answers: Messages = app.do_app_stuff(app_call);
    let if_call_new: InterfaceCall = InterfaceCall::AnswerToSocket(answers);
    if should_continue() {
        app_iface_rec(app, ip_stack_n, device_n, if_call_new)
    } else {
        nothing
    }
}

fn iface_device_rec(
    mut ip_stack:Interface,
    mut device: TunTapInterface,
    mut dev_call:Option<DeviceCall>
) -> (Option<AppCall>, Interface, TunTapInterface) {
    let call: Either<InterfaceCall, (Option<smolDuration>, bool)> = device.process_call(dev_call);
    let iface_call: InterfaceCall = maybe_wait(call);
    let device_or_app_call: Either<DeviceCall, (bool, Messages)> = ip_stack.process_call::<TunTapInterface>(iface_call);
    let (sign, optn_dev_call, optn_app_call): (bool, Option<DeviceCall>, Option<AppCall>) = unwrap_call(device_or_app_call);
    if sign{
        iface_device_rec(ip_stack, device, optn_dev_call)
    } else {
        (optn_app_call, ip_stack, device)
    }
}


fn loop_as_rec_limited(
    mut app: App,
    mut ip_stack: Interface,
    mut device: TunTapInterface,
    mut if_call: InterfaceCall,
    count: i32) -> () {
    // Without tail call elimination, we can only test this recursive
    // Version via limiting it to few recursions, otherwise we get an
    // instant stack overflow
    if count > 10 {return}
    let device_or_app_call = ip_stack.process_call::<TunTapInterface>(if_call);
    let if_call_new =
            if Either::is_left(&device_or_app_call){
                let call_or_wait = device.process_call(Some(device_or_app_call.left_or_panic()));
                maybe_wait(call_or_wait)
            } else {
                let (readiness_has_changed, messages_new) = device_or_app_call.right_or_panic();
                let answers = app.do_app_stuff(AppCall(Ok(readiness_has_changed), messages_new));
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
