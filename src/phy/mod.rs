/*! Access to networking hardware.

The `phy` module deals with the *network devices*. It provides a trait
for transmitting and receiving frames, [Device](trait.Device.html)
and implementations of it:

  * the [_loopback_](struct.Loopback.html), for zero dependency testing;
  * _middleware_ [Tracer](struct.Tracer.html) and
    [FaultInjector](struct.FaultInjector.html), to facilitate debugging;
  * _adapters_ [RawSocket](struct.RawSocket.html) and
    [TunTapInterface](struct.TunTapInterface.html), to transmit and receive frames
    on the host OS.
*/
#![cfg_attr(
    feature = "medium-ethernet",
    doc = r##"
# Examples

An implementation of the [Device](trait.Device.html) trait for a simple hardware
Ethernet controller could look as follows:

```rust
use smoltcp::Result;
use smoltcp::phy::{self, DeviceCapabilities, Device, Medium};
use smoltcp::time::Instant;

struct StmPhy {
    rx_buffer: [u8; 1536],
    tx_buffer: [u8; 1536],
}

impl<'a> StmPhy {
    fn new() -> StmPhy {
        StmPhy {
            rx_buffer: [0; 1536],
            tx_buffer: [0; 1536],
        }
    }
}

impl<'a> phy::Device<'a> for StmPhy {
    type RxToken = StmPhyRxToken<'a>;
    type TxToken = StmPhyTxToken<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        Some((StmPhyRxToken(&mut self.rx_buffer[..]),
              StmPhyTxToken(&mut self.tx_buffer[..])))
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(StmPhyTxToken(&mut self.tx_buffer[..]))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1536;
        caps.max_burst_size = Some(1);
        caps.medium = Medium::Ethernet;
        caps
    }
}

struct StmPhyRxToken<'a>(&'a mut [u8]);

impl<'a> phy::RxToken for StmPhyRxToken<'a> {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        // TODO: receive packet into buffer
        let result = f(&mut self.0);
        println!("rx called");
        result
    }
}

struct StmPhyTxToken<'a>(&'a mut [u8]);

impl<'a> phy::TxToken for StmPhyTxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        let result = f(&mut self.0[..len]);
        println!("tx called {}", len);
        // TODO: send packet out
        result
    }
}
```
"##
)]

use crate::iface::{InterfaceCall, InterfaceState};
use crate::time::{Duration, Instant};
use crate::{Either, Error, Result};
use core::fmt::Debug;

#[cfg(all(
    any(feature = "phy-raw_socket", feature = "phy-tuntap_interface"),
    unix
))]
mod sys;

mod fault_injector;
mod fuzz_injector;
#[cfg(any(feature = "std", feature = "alloc"))]
mod loopback;
mod pcap_writer;
#[cfg(all(feature = "phy-raw_socket", unix))]
mod raw_socket;
mod tracer;
#[cfg(all(
    feature = "phy-tuntap_interface",
    any(target_os = "linux", target_os = "android")
))]
mod tuntap_interface;

#[cfg(all(
    any(feature = "phy-raw_socket", feature = "phy-tuntap_interface"),
    unix
))]
pub use self::sys::wait;

pub use self::fault_injector::FaultInjector;
pub use self::fuzz_injector::{FuzzInjector, Fuzzer};
#[cfg(any(feature = "std", feature = "alloc"))]
pub use self::loopback::{BrokenLoopback, Loopback};
pub use self::pcap_writer::{PcapLinkType, PcapMode, PcapSink, PcapWriter};
#[cfg(all(feature = "phy-raw_socket", unix))]
pub use self::raw_socket::RawSocket;
pub use self::tracer::Tracer;
#[cfg(all(
    feature = "phy-tuntap_interface",
    any(target_os = "linux", target_os = "android")
))]
pub use self::tuntap_interface::TunTapInterface;

/// A description of checksum behavior for a particular protocol.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Checksum {
    /// Verify checksum when receiving and compute checksum when sending.
    Both,
    /// Verify checksum when receiving.
    Rx,
    /// Compute checksum before sending.
    Tx,
    /// Ignore checksum completely.
    None,
}

impl Default for Checksum {
    fn default() -> Checksum {
        Checksum::Both
    }
}

impl Checksum {
    /// Returns whether checksum should be verified when receiving.
    pub fn rx(&self) -> bool {
        match *self {
            Checksum::Both | Checksum::Rx => true,
            _ => false,
        }
    }

    /// Returns whether checksum should be verified when sending.
    pub fn tx(&self) -> bool {
        match *self {
            Checksum::Both | Checksum::Tx => true,
            _ => false,
        }
    }
}

/// A description of checksum behavior for every supported protocol.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub struct ChecksumCapabilities {
    pub ipv4: Checksum,
    pub udp: Checksum,
    pub tcp: Checksum,
    #[cfg(feature = "proto-ipv4")]
    pub icmpv4: Checksum,
    #[cfg(feature = "proto-ipv6")]
    pub icmpv6: Checksum,
}

impl ChecksumCapabilities {
    /// Checksum behavior that results in not computing or verifying checksums
    /// for any of the supported protocols.
    pub fn ignored() -> Self {
        ChecksumCapabilities {
            ipv4: Checksum::None,
            udp: Checksum::None,
            tcp: Checksum::None,
            #[cfg(feature = "proto-ipv4")]
            icmpv4: Checksum::None,
            #[cfg(feature = "proto-ipv6")]
            icmpv6: Checksum::None,
        }
    }
}

/// A description of device capabilities.
///
/// Higher-level protocols may achieve higher throughput or lower latency if they consider
/// the bandwidth or packet size limitations.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub struct DeviceCapabilities {
    /// Medium of the device.
    ///
    /// This indicates what kind of packet the sent/received bytes are, and determines
    /// some behaviors of Interface. For example, ARP/NDISC address resolution is only done
    /// for Ethernet mediums.
    pub medium: Medium,

    /// Maximum transmission unit.
    ///
    /// The network device is unable to send or receive frames larger than the value returned
    /// by this function.
    ///
    /// For Ethernet devices, this is the maximum Ethernet frame size, including the Ethernet header (14 octets), but
    /// *not* including the Ethernet FCS (4 octets). Therefore, Ethernet MTU = IP MTU + 14.
    ///
    /// Note that in Linux and other OSes, "MTU" is the IP MTU, not the Ethernet MTU, even for Ethernet
    /// devices. This is a common source of confusion.
    ///
    /// Most common IP MTU is 1500. Minimum is 576 (for IPv4) or 1280 (for IPv6). Maximum is 9216 octets.
    pub max_transmission_unit: usize,

    /// Maximum burst size, in terms of MTU.
    ///
    /// The network device is unable to send or receive bursts large than the value returned
    /// by this function.
    ///
    /// If `None`, there is no fixed limit on burst size, e.g. if network buffers are
    /// dynamically allocated.
    pub max_burst_size: Option<usize>,

    /// Checksum behavior.
    ///
    /// If the network device is capable of verifying or computing checksums for some protocols,
    /// it can request that the stack not do so in software to improve performance.
    pub checksum: ChecksumCapabilities,
}

impl DeviceCapabilities {
    pub fn ip_mtu(&self) -> usize {
        match self.medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => {
                self.max_transmission_unit - crate::wire::EthernetFrame::<&[u8]>::header_len()
            }
            #[cfg(feature = "medium-ip")]
            Medium::Ip => self.max_transmission_unit,
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => self.max_transmission_unit, // TODO(thvdveld): what is the MTU for Medium::IEEE802
        }
    }
}

/// Type of medium of a device.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Medium {
    /// Ethernet medium. Devices of this type send and receive Ethernet frames,
    /// and interfaces using it must do neighbor discovery via ARP or NDISC.
    ///
    /// Examples of devices of this type are Ethernet, WiFi (802.11), Linux `tap`, and VPNs in tap (layer 2) mode.
    #[cfg(feature = "medium-ethernet")]
    Ethernet,

    /// IP medium. Devices of this type send and receive IP frames, without an
    /// Ethernet header. MAC addresses are not used, and no neighbor discovery (ARP, NDISC) is done.
    ///
    /// Examples of devices of this type are the Linux `tun`, PPP interfaces, VPNs in tun (layer 3) mode.
    #[cfg(feature = "medium-ip")]
    Ip,

    #[cfg(feature = "medium-ieee802154")]
    Ieee802154,
}

impl Default for Medium {
    fn default() -> Medium {
        #[cfg(feature = "medium-ethernet")]
        return Medium::Ethernet;
        #[cfg(all(feature = "medium-ip", not(feature = "medium-ethernet")))]
        return Medium::Ip;
        #[cfg(all(
            feature = "medium-ieee802154",
            not(feature = "medium-ip"),
            not(feature = "medium-ethernet")
        ))]
        return Medium::Ieee802154;
        #[cfg(all(
            not(feature = "medium-ip"),
            not(feature = "medium-ethernet"),
            not(feature = "medium-ieee802154")
        ))]
        return panic!("No medium enabled");
    }
}

/// An interface for sending and receiving raw network frames.
///
/// The interface is based on _tokens_, which are types that allow to receive/transmit a
/// single packet. The `receive` and `transmit` functions only construct such tokens, the
/// real sending/receiving operation are performed when the tokens are consumed.
pub trait Device<'a> {
    type RxToken: RxToken + 'a;
    type TxToken: TxToken + 'a;

    /// Construct a token pair consisting of one receive token and one transmit token.
    ///
    /// The additional transmit token makes it possible to generate a reply packet based
    /// on the contents of the received packet. For example, this makes it possible to
    /// handle arbitrarily large ICMP echo ("ping") requests, where the all received bytes
    /// need to be sent back, without heap allocation.
    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)>;

    /// Construct a transmit token.
    fn transmit(&'a mut self) -> Option<Self::TxToken>;

    /// Get a description of device capabilities.
    fn capabilities(&self) -> DeviceCapabilities;

    fn send_tokenfree(&'a mut self, timestamp: Instant, packet: Vec<u8>) -> Result<()> {
        let sending_result = self
            .transmit()
            .ok_or_else(|| {
                net_debug!("failed to transmit IP: {}", Error::Exhausted);
                Error::Exhausted
            })
            .and_then(|token| {
                token.consume(timestamp, packet.len(), |buffer| {
                    Ok(buffer.copy_from_slice(packet.as_slice()))
                })
            });
        sending_result
    }

    /// To simplify things a bit we do not send tokens but merely the info
    fn receive_tokenfree(
        &'a mut self,
        timestamp: Instant,
    ) -> Option<(Vec<u8>, Result<()>, Option<()>)> {
        if let Some((rx, _tx)) = self.receive() {
            let mut received_frame = vec![];
            let receiving_result = rx.consume(timestamp, |frame| {
                received_frame.extend_from_slice(frame);
                Ok(())
            });
            return Some((received_frame, receiving_result, Some(())));
        } else {
            None
        }
    }

    fn transmit_tokenfree(&'a mut self) -> Option<()> {
        if self.transmit().is_some() {
            Some(())
        } else {
            None
        }
    }

    /// Thi function returns true when the device is ready to be used
    /// in poll again. It resembles the implementation in M3
    fn needs_poll(&self, max_duration: Option<Duration>) -> bool;

    // ToDo: To keep it simple we currently just send around a simple Ok
    //       instead of a token. Can this lead to requesting from one device,
    //       while sending with another? (Not in pur code but in general)
    fn process_call(
        &'a mut self,
        dev_call_state: DeviceCall,
    ) -> Either<InterfaceCall, (Option<Duration>, bool)> {
        match dev_call_state {
            DeviceCall::Transmit
                => Either::Left(InterfaceCall::InnerDispatchLocal(self.transmit_tokenfree())),
            DeviceCall::Consume(timestamp,packet, InterfaceState::Egress)
                => Either::Left(InterfaceCall::MatchSocketDispatchAfter(self.send_tokenfree(timestamp, packet))),
            DeviceCall::Consume(timestamp,packet, InterfaceState::Ingress)
                => Either::Left(InterfaceCall::LoopIngress(self.send_tokenfree(timestamp, packet))),
            DeviceCall::Receive(timestamp)
                => Either::Left(InterfaceCall::ProcessIngress(self.receive_tokenfree(timestamp))),
            DeviceCall::NeedsPoll(socket_wait_duration)
            // This is actually pretty clumsy, we do not want the interface to
            // process the waiting but we need to return an interface call here
                => Either::Right((socket_wait_duration, self.needs_poll(socket_wait_duration))),
        }
    }
}

/// A token to receive a single network packet.
pub trait RxToken {
    /// Consumes the token to receive a single network packet.
    ///
    /// This method receives a packet and then calls the given closure `f` with the raw
    /// packet bytes as argument.
    ///
    /// The timestamp must be a number of milliseconds, monotonically increasing since an
    /// arbitrary moment in time, such as system startup.
    fn consume<R, F>(self, timestamp: Instant, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>;
}

/// A token to transmit a single network packet.
pub trait TxToken {
    /// Consumes the token to send a single network packet.
    ///
    /// This method constructs a transmit buffer of size `len` and calls the passed
    /// closure `f` with a mutable reference to that buffer. The closure should construct
    /// a valid network packet (e.g. an ethernet packet) in the buffer. When the closure
    /// returns, the transmit buffer is sent out.
    ///
    /// The timestamp must be a number of milliseconds, monotonically increasing since an
    /// arbitrary moment in time, such as system startup.
    fn consume<R, F>(self, timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>;
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum DeviceCall {
    Transmit,
    Consume(Instant, Vec<u8>, InterfaceState),
    Receive(Instant),
    NeedsPoll(Option<Duration>),
}
