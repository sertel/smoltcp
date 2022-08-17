mod ohua_util;

use std::str;

use log::debug;
use ohua_util::init_components::{init_app,init_device,init_tcp_ip_stack};
use smoltcp::phy::{Device, Medium, wait as phy_wait};
use smoltcp::socket::{TcpSocket};
use smoltcp::time::Instant;

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
    let mut app = init_app();
    let (device_n, fd) = init_device();
    let (mut tcp_ip_stack, socket_handle) = init_tcp_ip_stack(device_n);
    assert_eq!(app.testnum, 3);
    assert_eq!(tcp_ip_stack.device().capabilities().medium, Medium::Ethernet);

    loop {
        let timestamp = Instant::now();
        match tcp_ip_stack.poll(timestamp) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        let socket = tcp_ip_stack.get_socket::<TcpSocket>(socket_handle);
        if !socket.is_open() {
            socket.listen(6969).unwrap();
        }

        if socket.may_recv() {
            // ToDo: Check how we will handle function references i.e. can we "tell"
            //       Socket.recv to use this/any partcular function?
            //       Simple way out would be to cleanly separate and have the socket return the pure buffer
            let input = socket.recv(process_octets).unwrap();
            if socket.can_send() && !input.is_empty() {
                debug!(
                    "tcp:6969 send data: {:?}",
                    str::from_utf8(input.as_ref()).unwrap_or("(invalid utf8)")
                );
                let outbytes = app.handle_message(input);
                socket.send_slice(&outbytes[..]).unwrap();
            }
        } else if socket.may_send() {
            debug!("tcp:6969 close");
            socket.close();
        }

        phy_wait(fd, tcp_ip_stack.poll_delay(timestamp)).expect("wait error");
    }
}
