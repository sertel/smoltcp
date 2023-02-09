#![allow(clippy::collapsible_if)]

mod utils;
mod ohua_util;

use log::debug;
use std::cmp;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use smoltcp::Either;

use smoltcp::iface::{FragmentsCache, Interface, InterfaceBuilder, InterfaceCall, NeighborCache, SocketHandle, SocketSet};
use smoltcp::phy::{wait as phy_wait, Device, Medium, TunTapInterface};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};
use crate::ohua_util::init_components::{App, init_app, init_stack_and_device};


const AMOUNT: usize = 1_000_000_000;

enum Client {
    Reader,
    Writer,
    FullCircle,
}

fn client(kind: Client) {
    let (port, direction) = match kind {
        Client::Reader => (1234, "sending"),
        Client::Writer => (1235, "receiving"),
        Client::FullCircle => (6969, "sending"),
    };
    let mut stream = TcpStream::connect(("192.168.69.1", port)).unwrap();
    let mut buffer = vec![0; 1_000_000];
    let mut buffer_inp = vec![0; 1_000_000];

    let start = Instant::now();

    let mut processed = 0;
    let mut received_back = 0;
    while processed < AMOUNT {
        let length = cmp::min(buffer.len(), AMOUNT - processed);
        let result = match kind {
            Client::Reader => stream.read(&mut buffer[..length]).and_then(|s| Ok((s,0))),
            Client::Writer => stream.write(&buffer[..length]).and_then(|s| Ok((s,0))),
            Client::FullCircle => {
                let sent_and_recvd = stream
                    .write(&buffer[..length])
                    .and_then(|sent_bytes|{
                        //println!("send {:?}", sent_bytes);
                        let recvd = stream.read(&mut buffer_inp[..length])?;
                        //println!("recvd {:?}", recvd);
                        Ok((sent_bytes, recvd))});
                sent_and_recvd
            }
        };
        match result {
            Ok((0,0)) => break,
            Ok((s, r)) => {
                processed += s;
                received_back += r
            }
            Err(err) => panic!("cannot process: {}", err),
        }
    }

    let end = Instant::now();

    let elapsed = (end - start).total_millis() as f64 / 1000.0;
    let other_dir = match kind {
      Client::FullCircle => format!(" and {:.3} Gbps for receiving", received_back as f64 / elapsed / 0.125e9),
      _ => "".to_owned(),
    };
    println!("throughput: {:.3} Gbps for {}{}", processed as f64 / elapsed / 0.125e9, direction, other_dir);

    CLIENT_DONE.store(true, Ordering::SeqCst);
}

static CLIENT_DONE: AtomicBool = AtomicBool::new(false);
fn maybe_wait(call: Either<InterfaceCall, (Option<Duration>, bool)>) -> InterfaceCall {
   if Either::is_left(&call) {
       return call.left_or_panic()
   } else {
       return InterfaceCall::InitPoll
   }
}
fn main() {
    #[cfg(feature = "log")]
    utils::setup_logging("info");

    let (mut ip_stack, handels, mut device):(Interface, Vec<SocketHandle>, TunTapInterface) = init_stack_and_device();
    let mut app: App = init_app(handels);
    let mut iface_call = InterfaceCall::InitPoll;

    thread::spawn(move || client(Client::FullCircle));
    while !CLIENT_DONE.load(Ordering::SeqCst) {
        let device_or_app_call = ip_stack.process_call::<TunTapInterface>(iface_call);
        if Either::is_left(&device_or_app_call){
            let call = device.process_call(device_or_app_call.left_or_panic());
            iface_call = maybe_wait(call)
        } else {
            let (readiness_has_changed, messages_new) = device_or_app_call.right_or_panic();
            let answers = app.do_app_stuff(Ok(readiness_has_changed), messages_new);
            iface_call = InterfaceCall::AnswerToSocket(answers);
        }
    }
}
