#![allow(clippy::collapsible_if)]

mod utils;

use log::debug;
use std::cmp;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use smoltcp::iface::{FragmentsCache, InterfaceBuilder, NeighborCache, SocketSet};
use smoltcp::phy::{wait as phy_wait, Device, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

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
        Client::FullCircle => (1337, "sending"),
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

fn main() {
    #[cfg(feature = "log")]
    utils::setup_logging("info");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tuntap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);
    free.push("MODE");

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tuntap_options(&mut matches);
    let fd = device.as_raw_fd();
    let mut device =
        utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);
    let mode = match matches.free[0].as_ref() {
        "reader" => Client::Reader,
        "writer" => Client::Writer,
        "full" => Client::FullCircle,
        _ => panic!("invalid mode"),
    };

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let tcp1_rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp1_tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp1_socket = tcp::Socket::new(tcp1_rx_buffer, tcp1_tx_buffer);

    let tcp2_rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp2_tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp2_socket = tcp::Socket::new(tcp2_rx_buffer, tcp2_tx_buffer);

    let tcp3_rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp3_tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp3_socket = tcp::Socket::new(tcp3_rx_buffer, tcp3_tx_buffer);

    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24)];
    let medium = device.capabilities().medium;
    // The modified interface holds it's own sockets, but poll can still
    // be used with normal 'passed in' sockets reference so the builder just
    // gets an empty socket set here
    let mut builder = InterfaceBuilder::new(vec![]).ip_addrs(ip_addrs);

    let ipv4_frag_cache = FragmentsCache::new(vec![], BTreeMap::new());
    builder = builder.ipv4_fragments_cache(ipv4_frag_cache);

    let mut out_packet_buffer = [0u8; 2048];

    let sixlowpan_frag_cache = FragmentsCache::new(vec![], BTreeMap::new());
    builder = builder
        .sixlowpan_fragments_cache(sixlowpan_frag_cache)
        .sixlowpan_out_packet_cache(&mut out_packet_buffer[..]);

    if medium == Medium::Ethernet {
        builder = builder
            .hardware_addr(ethernet_addr.into())
            .neighbor_cache(neighbor_cache);
    }
    let mut iface = builder.finalize(&mut device);

    let mut sockets = SocketSet::new(vec![]);
    let tcp1_handle = sockets.add(tcp1_socket);
    let tcp2_handle = sockets.add(tcp2_socket);
    let tcp3_handle = sockets.add(tcp3_socket);
    let default_timeout = Some(Duration::from_millis(1000));

    thread::spawn(move || client(mode));
    let mut processed_server = 0;
    while !CLIENT_DONE.load(Ordering::SeqCst) {
        let timestamp = Instant::now();
        match iface.poll(timestamp, &mut device, &mut sockets) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        // tcp:1234: emit data
        let socket = sockets.get_mut::<tcp::Socket>(tcp1_handle);
        if !socket.is_open() {
            socket.listen(1234).unwrap();
        }

        if socket.can_send() {
            if processed_server < AMOUNT {
                let length = socket
                    .send(|buffer| {
                        let length = cmp::min(buffer.len(), AMOUNT - processed_server);
                        (length, length)
                    })
                    .unwrap();
                processed_server += length;
            }
        }

        // tcp:1235: sink data
        let socket = sockets.get_mut::<tcp::Socket>(tcp2_handle);
        if !socket.is_open() {
            socket.listen(1235).unwrap();
        }

        if socket.can_recv() {
            if processed_server < AMOUNT {
                let length = socket
                    .recv(|buffer| {
                        let length = cmp::min(buffer.len(), AMOUNT - processed_server);
                        (length, length)
                    })
                    .unwrap();
                processed_server += length;
            }
        }
        // tcp:1337: receive and respond
        let socket = sockets.get_mut::<tcp::Socket>(tcp3_handle);
        if !socket.is_open() {
            socket.listen(1337).unwrap()
        }

        if socket.may_recv() {
            let data = socket
                .recv(|buffer| {
                    let recvd_len = buffer.len();
                    let mut data = buffer.to_owned();
                    (recvd_len, data)
                })
                .unwrap();
            if socket.can_send() && !data.is_empty() {
                debug!("tcp:1337 send data: ");
                socket.send_slice(&data[..]).unwrap();
            }
        } else if socket.may_send() {
            socket.close();
        }

        // Same matching is done by directly calling poll_delay now
        match iface.poll_at(timestamp, &sockets) {
            Some(poll_at) if timestamp < poll_at => {
                phy_wait(fd, Some(poll_at - timestamp)).expect("wait error");
            }
            //Adapt waiting in normal vs. Ohua version
            Some(_) => {phy_wait(fd, Some(Duration::from_millis(0))).expect("wait error");}
            None => {
                phy_wait(fd, default_timeout).expect("wait error");
            }
        }
    }
}
