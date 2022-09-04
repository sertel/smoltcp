// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP for any IPv4 work
// and RFCs 8200 and 4861 for any IPv6 and NDISC work.

use core::cmp;
use managed::{ManagedMap, ManagedSlice};

use crate::iface::interface::{IgmpReportState, EthernetPacket,
                              FragmentsBuffer, OutPackets, SixlowpanOutPacket};
use crate::iface::Context;
#[cfg(any(feature = "proto-ipv4", feature = "proto-sixlowpan"))]
use super::fragmentation::PacketAssemblerSet;
use super::socket_set::SocketSet;
use crate::iface::{Routes};
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
use crate::iface::{NeighborAnswer, NeighborCache};
use crate::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use crate::rand::Rand;
#[cfg(feature = "socket-dhcpv4")]
use crate::socket::dhcpv4;
#[cfg(feature = "socket-dns")]
use crate::socket::dns;
use crate::socket::*;
use crate::time::{Duration, Instant};
use crate::wire::*;
use crate::{Error, Result};
#[cfg(feature = "ohua")]
use crate::socket::tcp_ohua::{DispatchCall, DispatchResult, OhuaTcpSocket};
#[cfg(feature = "ohua")]
use super::socket_meta::Meta;
#[cfg(feature = "ohua")]
use super::socket_set::Item;
#[cfg(feature = "ohua")]
use crate::phy::OhuaRawSocket;

use crate::iface::interface::{IpPacket};

/*
/// We start with transformation relevant Code because I go nuts otherwise with this
/// biblical-proportion modules

// Reminder: I need to pass a lifetime here because the original poll derived it from the &self
fn poll<'a, D>(timestamp:Instant, ip_stack: &'a mut OInterface,
               device: &mut D, sockets: &mut SocketSet<'a>)-> Result<bool>
  where D: for<'d> Device<'d>
{
    ip_stack.inner_mut().now = timestamp;
    // .. we leave out the optional fragments stuff for now

    let mut readiness_may_have_changed = false;
    let mut stack_opnt = Some(ip_stack);
    loop {
        let mut ip_stack_local = stack_opnt.take().unwrap();
        let processed_any = ip_stack_local.socket_ingress(device, sockets);
        let emitted_any = ip_stack_local.socket_egress_ohua(device, sockets);

        //#[cfg(feature = "proto-igmp")]
        //self.igmp_egress()?;

        if processed_any || emitted_any {
            readiness_may_have_changed = true;
        } else {
            break;
        }
        stack_opnt.replace(ip_stack_local);
    }

    Ok(readiness_may_have_changed)
}
*/


macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => {
                // concat!/stringify! doesn't work with defmt macros
                #[cfg(not(feature = "defmt"))]
                net_trace!(concat!("iface: malformed ", stringify!($e)));
                #[cfg(feature = "defmt")]
                net_trace!("iface: malformed");
                return Default::default();
            }
        }
    };
}

// We use these macros to temporarily take the 'field' i.e. the inner interface 
// from its owner (the interface) during function execution and put it back afterwards


macro_rules! let_field {
    ($self:ident.$field:ident, $($t:expr);+) => {
        match $self.$field.as_ref() {
            Some($field) => {
                $($t);+
            },
            None => panic!("Invariant broken! Option was None."),
        }
    };
    ($self:ident.$field:ident, $($t:stmt);+) => {
        match $self.$field.as_ref() {
            Some($field) => {
                $($t);+
            },
            None => panic!("Invariant broken! Option was None."),
        }
    };
}

macro_rules! let_mut_field {
    ($self:ident.$field:ident, $t:expr) => {
        match $self.$field.as_mut() {
            Some($field) => {
                $t
            },
            None => panic!("Invariant broken! Option was None."),
        }
    };
    ($self:ident.$field:ident, $($t:stmt);+) => {
        match $self.$field.as_mut() {
            Some($field) => {
                $($t)+
            },
            None => panic!("Invariant broken! Option was None."),
        }
    };
}

#[cfg(feature = "ohua")]
macro_rules! assert_none {
    ($e:expr) => {
        match $e {
            None => (),
            _ => panic!("Expected None value for stolen field but found value!")
        }
    };
}

/// A  network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct OInterface<'a> {
    inner: Option<Context<'a>>,
    fragments: FragmentsBuffer<'a>,
    out_packets: OutPackets<'a>,
}


/// A builder structure used for creating a network interface.
pub struct OInterfaceBuilder<'a> {
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    hardware_addr: Option<HardwareAddress>,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_cache: Option<NeighborCache<'a>>,
    #[cfg(feature = "medium-ieee802154")]
    pan_id: Option<Ieee802154Pan>,
    ip_addrs: ManagedSlice<'a, IpCidr>,
    #[cfg(feature = "proto-ipv4")]
    any_ip: bool,
    routes: Routes<'a>,
    /// Does not share storage with `ipv6_multicast_groups` to avoid IPv6 size overhead.
    #[cfg(feature = "proto-igmp")]
    ipv4_multicast_groups: ManagedMap<'a, Ipv4Address, ()>,
    random_seed: u64,

    #[cfg(feature = "proto-ipv4-fragmentation")]
    ipv4_fragments: Option<PacketAssemblerSet<'a, Ipv4FragKey>>,

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    sixlowpan_fragments: Option<PacketAssemblerSet<'a, SixlowpanFragKey>>,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    sixlowpan_fragments_cache_timeout: Duration,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    sixlowpan_out_buffer: Option<ManagedSlice<'a, u8>>,
}

impl<'a> OInterfaceBuilder<'a> {
    /// Create a builder used for creating a network interface using the
    /// given device and address.
    #[cfg_attr(
        all(feature = "medium-ethernet", not(feature = "proto-sixlowpan")),
        doc = r##"
# Examples

```
# use std::collections::BTreeMap;
#[cfg(feature = "proto-ipv4-fragmentation")]
use smoltcp::iface::FragmentsCache;
use smoltcp::iface::{InterfaceBuilder, NeighborCache};
# use smoltcp::phy::{Loopback, Medium};
use smoltcp::wire::{EthernetAddress, IpCidr, IpAddress};

let mut device = // ...
# Loopback::new(Medium::Ethernet);
let hw_addr = // ...
# EthernetAddress::default();
let neighbor_cache = // ...
# NeighborCache::new(BTreeMap::new());
# #[cfg(feature = "proto-ipv4-fragmentation")]
# let ipv4_frag_cache = // ...
# FragmentsCache::new(vec![], BTreeMap::new());
let ip_addrs = // ...
# [];
let builder = InterfaceBuilder::new()
        .hardware_addr(hw_addr.into())
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs);

# #[cfg(feature = "proto-ipv4-fragmentation")]
let builder = builder.ipv4_fragments_cache(ipv4_frag_cache);

let iface = builder.finalize(&mut device);
```
    "##
    )]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        OInterfaceBuilder {
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            hardware_addr: None,
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            neighbor_cache: None,

            #[cfg(feature = "medium-ieee802154")]
            pan_id: None,

            ip_addrs: ManagedSlice::Borrowed(&mut []),
            #[cfg(feature = "proto-ipv4")]
            any_ip: false,
            routes: Routes::new(ManagedMap::Borrowed(&mut [])),
            #[cfg(feature = "proto-igmp")]
            ipv4_multicast_groups: ManagedMap::Borrowed(&mut []),
            random_seed: 0,

            #[cfg(feature = "proto-ipv4-fragmentation")]
            ipv4_fragments: None,

            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            sixlowpan_fragments: None,
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            sixlowpan_fragments_cache_timeout: Duration::from_secs(60),
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            sixlowpan_out_buffer: None,
        }
    }

    /// Set the random seed for this interface.
    ///
    /// It is strongly recommended that the random seed is different on each boot,
    /// to avoid problems with TCP port/sequence collisions.
    ///
    /// The seed doesn't have to be cryptographically secure.
    pub fn random_seed(mut self, random_seed: u64) -> Self {
        self.random_seed = random_seed;
        self
    }

    /// Set the Hardware address the interface will use. See also
    /// [hardware_addr].
    ///
    /// # Panics
    /// This function panics if the address is not unicast.
    ///
    /// [hardware_addr]: struct.Interface.html#method.hardware_addr
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn hardware_addr(mut self, addr: HardwareAddress) -> Self {
        Context::check_hardware_addr(&addr);
        self.hardware_addr = Some(addr);
        self
    }

    /// Set the IEEE802.15.4 PAN ID the interface will use.
    ///
    /// **NOTE**: we use the same PAN ID for destination and source.
    #[cfg(feature = "medium-ieee802154")]
    pub fn pan_id(mut self, pan_id: Ieee802154Pan) -> Self {
        self.pan_id = Some(pan_id);
        self
    }

    /// Set the IP addresses the interface will use. See also
    /// [ip_addrs].
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    ///
    /// [ip_addrs]: struct.OInterface.html#method.ip_addrs
    pub fn ip_addrs<T>(mut self, ip_addrs: T) -> Self
    where
        T: Into<ManagedSlice<'a, IpCidr>>,
    {
        let ip_addrs = ip_addrs.into();
        Context::check_ip_addrs(&ip_addrs);
        self.ip_addrs = ip_addrs;
        self
    }

    /// Enable or disable the AnyIP capability, allowing packets to be received
    /// locally on IPv4 addresses other than the interface's configured [ip_addrs].
    /// When AnyIP is enabled and a route prefix in [routes] specifies one of
    /// the interface's [ip_addrs] as its gateway, the interface will accept
    /// packets addressed to that prefix.
    ///
    /// # IPv6
    ///
    /// This option is not available or required for IPv6 as packets sent to
    /// the interface are not filtered by IPv6 address.
    ///
    /// [routes]: struct.OInterface.html#method.routes
    /// [ip_addrs]: struct.OInterface.html#method.ip_addrs
    #[cfg(feature = "proto-ipv4")]
    pub fn any_ip(mut self, enabled: bool) -> Self {
        self.any_ip = enabled;
        self
    }

    /// Set the IP routes the interface will use. See also
    /// [routes].
    ///
    /// [routes]: struct.OInterface.html#method.routes
    pub fn routes<T>(mut self, routes: T) -> OInterfaceBuilder<'a>
    where
        T: Into<Routes<'a>>,
    {
        self.routes = routes.into();
        self
    }

    /// Provide storage for multicast groups.
    ///
    /// Join multicast groups by calling [`join_multicast_group()`] on an `OInterface`.
    /// Using [`join_multicast_group()`] will send initial membership reports.
    ///
    /// A previously destroyed interface can be recreated by reusing the multicast group
    /// storage, i.e. providing a non-empty storage to `ipv4_multicast_groups()`.
    /// Note that this way initial membership reports are **not** sent.
    ///
    /// [`join_multicast_group()`]: struct.OInterface.html#method.join_multicast_group
    #[cfg(feature = "proto-igmp")]
    pub fn ipv4_multicast_groups<T>(mut self, ipv4_multicast_groups: T) -> Self
    where
        T: Into<ManagedMap<'a, Ipv4Address, ()>>,
    {
        self.ipv4_multicast_groups = ipv4_multicast_groups.into();
        self
    }

    /// Set the Neighbor Cache the interface will use.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn neighbor_cache(mut self, neighbor_cache: NeighborCache<'a>) -> Self {
        self.neighbor_cache = Some(neighbor_cache);
        self
    }

    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub fn ipv4_fragments_cache(mut self, storage: PacketAssemblerSet<'a, Ipv4FragKey>) -> Self {
        self.ipv4_fragments = Some(storage);
        self
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub fn sixlowpan_fragments_cache(
        mut self,
        storage: PacketAssemblerSet<'a, SixlowpanFragKey>,
    ) -> Self {
        self.sixlowpan_fragments = Some(storage);
        self
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub fn sixlowpan_fragments_cache_timeout(mut self, timeout: Duration) -> Self {
        if timeout > Duration::from_secs(60) {
            net_debug!("RFC 4944 specifies that the reassembly timeout MUST be set to a maximum of 60 seconds");
        }
        self.sixlowpan_fragments_cache_timeout = timeout;
        self
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub fn sixlowpan_out_packet_cache<T>(mut self, storage: T) -> Self
    where
        T: Into<ManagedSlice<'a, u8>>,
    {
        self.sixlowpan_out_buffer = Some(storage.into());
        self
    }

    /// Create a network interface using the previously provided configuration.
    ///
    /// # Panics
    /// If a required option is not provided, this function will panic. Required
    /// options are:
    ///
    /// - [ethernet_addr]
    /// - [neighbor_cache]
    ///
    /// [ethernet_addr]: #method.ethernet_addr
    /// [neighbor_cache]: #method.neighbor_cache
    pub fn finalize<D>(self, device: &mut D) -> OInterface<'a>
    where
        D: for<'d> Device<'d>,
    {
        let caps = device.capabilities();

        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        let (hardware_addr, neighbor_cache) = match caps.medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => (
                Some(
                    self.hardware_addr
                        .expect("hardware_addr required option was not set"),
                ),
                Some(
                    self.neighbor_cache
                        .expect("neighbor_cache required option was not set"),
                ),
            ),
            #[cfg(feature = "medium-ip")]
            Medium::Ip => {
                assert!(
                    self.hardware_addr.is_none(),
                    "hardware_addr is set, but device medium is IP"
                );
                assert!(
                    self.neighbor_cache.is_none(),
                    "neighbor_cache is set, but device medium is IP"
                );
                (None, None)
            }
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => (
                Some(
                    self.hardware_addr
                        .expect("hardware_addr required option was not set"),
                ),
                Some(
                    self.neighbor_cache
                        .expect("neighbor_cache required option was not set"),
                ),
            ),
        };

        #[cfg(feature = "medium-ieee802154")]
        let mut rand = Rand::new(self.random_seed);
        #[cfg(not(feature = "medium-ieee802154"))]
        let rand = Rand::new(self.random_seed);

        #[cfg(feature = "medium-ieee802154")]
        let mut sequence_no;
        #[cfg(feature = "medium-ieee802154")]
        loop {
            sequence_no = (rand.rand_u32() & 0xff) as u8;
            if sequence_no != 0 {
                break;
            }
        }

        #[cfg(feature = "proto-sixlowpan")]
        let mut tag;

        #[cfg(feature = "proto-sixlowpan")]
        loop {
            tag = (rand.rand_u32() & 0xffff) as u16;
            if tag != 0 {
                break;
            }
        }

        OInterface {
            fragments: FragmentsBuffer {
                #[cfg(feature = "proto-ipv4-fragmentation")]
                ipv4_fragments: self
                    .ipv4_fragments
                    .expect("Cache for incoming IPv4 fragments is required"),
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                sixlowpan_fragments: self
                    .sixlowpan_fragments
                    .expect("Cache for incoming 6LoWPAN fragments is required"),
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                sixlowpan_fragments_cache_timeout: self.sixlowpan_fragments_cache_timeout,

                #[cfg(not(any(
                    feature = "proto-ipv4-fragmentation",
                    feature = "proto-sixlowpan-fragmentation"
                )))]
                _lifetime: core::marker::PhantomData,
            },
            out_packets: OutPackets {
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                sixlowpan_out_packet: SixlowpanOutPacket::new(
                    self.sixlowpan_out_buffer
                        .expect("Cache for outgoing 6LoWPAN fragments is required"),
                ),

                #[cfg(not(feature = "proto-sixlowpan-fragmentation"))]
                _lifetime: core::marker::PhantomData,
            },
            inner: Some(Context {
                now: Instant::from_secs(0),
                caps,
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                hardware_addr,
                ip_addrs: self.ip_addrs,
                #[cfg(feature = "proto-ipv4")]
                any_ip: self.any_ip,
                routes: self.routes,
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                neighbor_cache,
                #[cfg(feature = "proto-igmp")]
                ipv4_multicast_groups: self.ipv4_multicast_groups,
                #[cfg(feature = "proto-igmp")]
                igmp_report_state: IgmpReportState::Inactive,
                #[cfg(feature = "medium-ieee802154")]
                sequence_no,
                #[cfg(feature = "medium-ieee802154")]
                pan_id: self.pan_id,
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                tag,
                rand,
            }),
        }
    }
}


#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
fn icmp_reply_payload_len(len: usize, mtu: usize, header_len: usize) -> usize {
    // Send back as much of the original payload as will fit within
    // the minimum MTU required by IPv4. See RFC 1812 § 4.3.2.3 for
    // more details.
    //
    // Since the entire network layer packet must fit within the minimum
    // MTU supported, the payload must not exceed the following:
    //
    // <min mtu> - IP Header Size * 2 - ICMPv4 DstUnreachable hdr size
    cmp::min(len, mtu - header_len * 2 - 8)
}


impl<'a> OInterface<'a> {
    /// Get the socket context.
    ///
    /// The context is needed for some socket methods.
    pub fn context(&mut self) -> &mut Context<'a> {
        self.inner_mut()
    }


    /// Get the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the medium is not Ethernet or Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn hardware_addr(&self) -> HardwareAddress {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.inner.caps.medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.inner.caps.medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.inner().caps.medium == Medium::Ethernet
                || self.inner().caps.medium == Medium::Ieee802154
        );

        self.inner().hardware_addr.unwrap()
    }

    /// Set the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast, and if the medium is not Ethernet or
    /// Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn set_hardware_addr(&mut self, addr: HardwareAddress) {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.inner.caps.medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.inner.caps.medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.inner().caps.medium == Medium::Ethernet
                || self.inner().caps.medium == Medium::Ieee802154
        );

        Context::check_hardware_addr(&addr);
        self.inner_mut().hardware_addr = Some(addr);
    }

/* ToDo: Remove after refactoring
    /// Get a mutable reference to the inner device.
    ///
    /// There are no invariants imposed on the device by the interface itself. Furthermore the
    /// trait implementations, required for references of all lifetimes, guarantees that the
    /// mutable reference can not invalidate the device as such. For some devices, such access may
    /// still allow modifications with adverse effects on the usability as a `phy` device. You
    /// should not use them this way.
    pub fn device_mut(&mut self) -> &mut DeviceT {
        let_mut_field!(self.device,
            device
        )
    }
*/
    /// Add an address to a list of subscribed multicast IP addresses.
    ///
    /// Returns `Ok(announce_sent)` if the address was added successfully, where `announce_sent`
    /// indicates whether an initial immediate announcement has been sent.
    pub fn join_multicast_group<D, T: Into<IpAddress>>(
        &mut self,
        device: &mut D,
        addr: T,
        timestamp: Instant,
    ) -> Result<bool>
    where
        D: for<'d> Device<'d>,
    {
        self.inner_mut().now = timestamp;

        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(addr) => {
                let is_not_new = self
                    .inner_mut()
                    .ipv4_multicast_groups
                    .insert(addr, ())
                    .map_err(|_| Error::Exhausted)?
                    .is_some();
                if is_not_new {
                    Ok(false)
                } else if let Some(pkt) = self.inner().igmp_report_packet(IgmpVersion::Version2, addr)
                {
                    // Send initial membership report
                    let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                    self.inner_mut().dispatch_ip(tx_token, pkt, None)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            // Multicast is not yet implemented for other address families
            #[allow(unreachable_patterns)]
            _ => Err(Error::Unaddressable),
        }
    }

    /// Remove an address from the subscribed multicast IP addresses.
    ///
    /// Returns `Ok(leave_sent)` if the address was removed successfully, where `leave_sent`
    /// indicates whether an immediate leave packet has been sent.
    pub fn leave_multicast_group<D, T: Into<IpAddress>>(
        &mut self,
        device: &mut D,
        addr: T,
        timestamp: Instant,
    ) -> Result<bool>
    where
        D: for<'d> Device<'d>,
    {
        self.inner_mut().now = timestamp;

        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(addr) => {
                let was_not_present = self.inner_mut().ipv4_multicast_groups.remove(&addr).is_none();
                if was_not_present {
                    Ok(false)
                } else if let Some(pkt) = self.inner().igmp_leave_packet(addr) {
                    // Send group leave packet
                    let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                    self.inner_mut().dispatch_ip(tx_token, pkt, None)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            // Multicast is not yet implemented for other address families
            #[allow(unreachable_patterns)]
            _ => Err(Error::Unaddressable),
        }
    }

    /// Check whether the interface listens to given destination multicast IP address.
    pub fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner().has_multicast_group(addr)
    }
    //ToDo: Do we really need the inner interface to be passed somewhere?.
    //      After all it should be part of the TCP/IP component only and not
    //      be passed anywhere. Remove after refactoring
    fn inner(&self) -> &Context {
        let_field!(self.inner,
            inner
        )
    }

    fn inner_mut(&mut self) -> &mut Context<'a> {
        let_mut_field!(self.inner,
            inner
        )
    }



    /// Get the IP addresses of the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        self.inner().ip_addrs.as_ref()
    }

    /// Get the first IPv4 address if present.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.ip_addrs()
            .iter()
            .find_map(|cidr| match cidr.address() {
                IpAddress::Ipv4(addr) => Some(addr),
                #[allow(unreachable_patterns)]
                _ => None,
            })
    }

    /// Update the IP addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut ManagedSlice<'a, IpCidr>)>(&mut self, f: F) {
            f(&mut self.inner_mut().ip_addrs);
            Context::flush_cache(self.inner_mut());
            Context::check_ip_addrs(&self.inner().ip_addrs)
    }

    /// Check whether the interface has the given IP address assigned.
    pub fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner().has_ip_addr(addr)
    }

    /// Get the first IPv4 address of the interface.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_address(&self) -> Option<Ipv4Address> {
        self.inner().ipv4_address()
    }

    pub fn routes(&self) -> &Routes<'a> {
        let_field!(self.inner,
            &inner.routes
        )
    }

    pub fn routes_mut(&mut self) -> &mut Routes<'a> {
        &mut self.inner_mut().routes
    }


    pub fn poll_wrapper<'s, D>(
        &mut self,
        timestamp: Instant,
        mut device_obj: D,
        mut sockets_obj: SocketSet<'s>,
    ) -> (Result<bool>, D, SocketSet<'s>)
    where
        D: for<'d> Device<'d>,
    {
        let device = &mut device_obj;
        let sockets = &mut sockets_obj;
        let result = self.poll(timestamp, device, sockets);
        (result, device_obj, sockets_obj)
    }

    /// Transmit packets queued in the given sockets, and receive packets queued
    /// in the device.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
    ///
    /// # Errors
    /// This method will routinely return errors in response to normal network
    /// activity as well as certain boundary conditions such as buffer exhaustion.
    /// These errors are provided as an aid for troubleshooting, and are meant
    /// to be logged and ignored.
    ///
    /// As a special case, `Err(Error::Unrecognized)` is returned in response to
    /// packets containing any unsupported protocol, option, or form, which is
    /// a very common occurrence and on a production system it should not even
    /// be logged.
    pub fn poll<D>(
        &mut self,
        timestamp: Instant,
        device: &mut D,
        sockets: &mut SocketSet<'_>,
    ) -> Result<bool>
    where
        D: for<'d> Device<'d>,
    {
        self.inner_mut().now = timestamp;

        #[cfg(feature = "proto-ipv4-fragmentation")]
        if let Err(e) = self
            .fragments
            .ipv4_fragments
            .remove_when(|frag| Ok(timestamp >= frag.expires_at()?))
        {
            return Err(e);
        }

        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        if let Err(e) = self
            .fragments
            .sixlowpan_fragments
            .remove_when(|frag| Ok(timestamp >= frag.expires_at()?))
        {
            return Err(e);
        }

        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        match self.sixlowpan_egress(device) {
            Ok(true) => return Ok(true),
            Err(e) => return Err(e),
            _ => (),
        }

        let mut readiness_may_have_changed = false;

        loop {
            let processed_any = self.socket_ingress(device, sockets);
            let emitted_any = self.socket_egress(device, sockets);

            //#[cfg(feature = "proto-igmp")]
            //self.igmp_egress()?;

            if processed_any || emitted_any {
                readiness_may_have_changed = true;
            } else {
                break;
            }
        }

        Ok(readiness_may_have_changed)
    }

    /// Return a _soft deadline_ for calling [poll] the next time.
    /// The [Instant] returned is the time at which you should call [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Instant], and
    /// potentially harmful (impacting quality of service) to call it after the
    /// [Instant]
    ///
    /// [poll]: #method.poll
    /// [Instant]: struct.Instant.html
    pub fn poll_at(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Instant> {
       self.inner_mut().now = timestamp;
	
	// ToDo: If they ever leave the interface, outpackets need to be wrapped like inner
        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        if !self.out_packets.all_transmitted() {
            return Some(Instant::from_millis(0));
        }

        let inner = self.inner_mut();

        sockets
            .items()
            .filter_map(move |item| {
                let socket_poll_at = item.socket.poll_at(inner);
                match item
                    .meta
                    .poll_at(socket_poll_at, |ip_addr| inner.has_neighbor(&ip_addr))
                {
                    PollAt::Ingress => None,
                    PollAt::Time(instant) => Some(instant),
                    PollAt::Now => Some(Instant::from_millis(0)),
                }
            })
            .min()
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    /// The [Duration] returned is the time left to wait before calling [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Duration] has passed,
    /// and potentially harmful (impacting quality of service) to call it after the
    /// [Duration] has passed.
    ///
    /// [poll]: #method.poll
    /// [Duration]: struct.Duration.html
    pub fn poll_delay(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Duration> {
        match self.poll_at(timestamp, sockets) {
            Some(poll_at) if timestamp < poll_at => Some(poll_at - timestamp),
            Some(_) => Some(Duration::from_millis(0)),
            _ => None,
        }
    }

    fn socket_ingress<D>(&mut self, device: &mut D, sockets: &mut SocketSet<'_>) -> bool
    where
        D: for<'d> Device<'d>,
    {
        let mut processed_any = false;
        let mut inner = self.inner.take().unwrap();
        let Self {
            // inner,
          fragments: ref mut _fragments,
          out_packets: _out_packets,
          ..
        } = self;

        while let Some((rx_token, tx_token)) = device.receive() {
            let res = rx_token.consume(inner.now, |frame| {
                match inner.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        if let Some(packet) = inner.process_ethernet(sockets, &frame, _fragments) {
                            if let Err(err) = inner.dispatch(tx_token, packet) {
                                net_debug!("Failed to send response: {}", err);
                            }
                        }
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => {
                        if let Some(packet) = inner.process_ip(sockets, &frame, _fragments) {
                            if let Err(err) = inner.dispatch_ip(tx_token, packet, None) {
                                net_debug!("Failed to send response: {}", err);
                            }
                        }
                    }
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => {
                        if let Some(packet) = inner.process_ieee802154(sockets, &frame, _fragments)
                        {
                            if let Err(err) =
                                inner.dispatch_ip(tx_token, packet, Some(_out_packets))
                            {
                                net_debug!("Failed to send response: {}", err);
                            }
                        }
                    }
                }
                processed_any = true;
                Ok(())
            });

            if let Err(err) = res {
                net_debug!("Failed to consume RX token: {}", err);
            }
        }

        //Put inner back in place.
        let replaced = self.inner.replace(inner);
        assert!(replaced.is_none());
        processed_any
    }

    // ToDo: This is actually replaced by the socket_egress_tcp, remove when sure.
    fn socket_egress<D>(&mut self, device: &mut D, sockets: &mut SocketSet<'_>) -> bool
    where
        D: for<'d> Device<'d>,
    {
        let Self {
            inner: inner_option,
            out_packets: _out_packets,
            ..
        } = self;
        let _caps = device.capabilities();
	    let mut inner = inner_option.take().unwrap();
        let mut emitted_any = false;

        for item in sockets.items_mut() {
                if !item
                    .meta
                    .egress_permitted(inner.now, |ip_addr| inner.has_neighbor(&ip_addr))
                {
                    continue;
                }

              let mut neighbor_addr = None;
                

              let mut respond = |inner: &mut Context, response: IpPacket| {
                neighbor_addr = Some(response.ip_repr().dst_addr());
                match device.transmit().ok_or(Error::Exhausted) {
                    Ok(_t) => {
                        #[cfg(feature = "proto-sixlowpan-fragmentation")]
                        if let Err(_e) = inner.dispatch_ip(_t, response, Some(_out_packets)) {
                            net_debug!("failed to dispatch IP: {}", _e);
                        }

                        #[cfg(not(feature = "proto-sixlowpan-fragmentation"))]
                        if let Err(_e) = inner.dispatch_ip(_t, response, None) {
                            net_debug!("failed to dispatch IP: {}", _e);
                        }
                        emitted_any = true;
                    }
                    Err(e) => {
                        net_debug!("failed to transmit IP: {}", e);
                    }
                }

                Ok(())
              };

              let result = match &mut item.socket {
                #[cfg(feature = "ohua")]
                Socket::OhuaTcp(socket) => socket.dispatch(&mut inner, |inner, response| {
                    respond(inner, IpPacket::Tcp(response))
                }),

                #[cfg(feature = "socket-raw")]
                Socket::Raw(socket) => socket.dispatch(&mut inner, |inner, response| {
                    respond(inner, IpPacket::Raw(response))
                }),
                #[cfg(feature = "socket-icmp")]
                Socket::Icmp(socket) => socket.dispatch(&mut inner, |inner, response| match response {
                    #[cfg(feature = "proto-ipv4")]
                    (IpRepr::Ipv4(ipv4_repr), IcmpRepr::Ipv4(icmpv4_repr)) => {
                        respond(inner, IpPacket::Icmpv4((ipv4_repr, icmpv4_repr)))
                    }
                    #[cfg(feature = "proto-ipv6")]
                    (IpRepr::Ipv6(ipv6_repr), IcmpRepr::Ipv6(icmpv6_repr)) => {
                        respond(inner, IpPacket::Icmpv6((ipv6_repr, icmpv6_repr)))
                    }
                    #[allow(unreachable_patterns)]
                    _ => unreachable!(),
                }),
                #[cfg(feature = "socket-udp")]
                Socket::Udp(socket) => socket.dispatch(&mut inner, |inner, response| {
                    respond(inner, IpPacket::Udp(response))
                }),
                #[cfg(feature = "socket-tcp")]
                Socket::Tcp(socket) => socket.dispatch(&mut inner, |inner, response| {
                    respond(inner, IpPacket::Tcp(response))
                }),
                 #[cfg(feature = "socket-dhcpv4")]
                Socket::Dhcpv4(socket) => socket.dispatch(&mut inner, |inner, response| {
                    respond(inner, IpPacket::Dhcpv4(response))
                }),
                #[cfg(feature = "socket-dns")]
                Socket::Dns(ref mut socket) => socket.dispatch(&mut inner, |inner, response| {
                    respond(inner, IpPacket::Udp(response))
                }),
                  _other_socket => {
                      net_debug!("Sorry, only Ohua Tcp sockets supported for now"); Ok(())}
              };

           match result {
                Err(Error::Exhausted) => break, // Device buffer full.
                Err(Error::Unaddressable) => {
                    // `NeighborCache` already takes care of rate limiting the neighbor discovery
                    // requests from the socket. However, without an additional rate limiting
                    // mechanism, we would spin on every socket that has yet to discover its
                    // neighbor.
                    item.meta.neighbor_missing(
                        inner.now,
                        neighbor_addr.expect("non-IP response packet"),
                    );
                    break;
                }
                Err(err) => {
                    net_debug!(
                        "{}: cannot dispatch egress packet: {}",
                        item.meta.handle,
                        err
                    );
                }
                Ok(()) => {}
            }
        };
        //Put inner back in place.
        let replaced = self.inner.replace(inner);
        assert!(replaced.is_none());
        emitted_any
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    fn sixlowpan_egress<D>(&mut self, device: &mut D) -> Result<bool>
    where
        D: for<'d> Device<'d>,
    {
        let SixlowpanOutPacket {
            packet_len,
            sent_bytes,
            ..
        } = &self.out_packets.sixlowpan_out_packet;
        //let mut inner = self.inner.take().unwrap();
        if *packet_len == 0 {

            return Ok(false);
        }

        if *packet_len > *sent_bytes {
            match device.transmit().ok_or(Error::Exhausted) {
                Ok(tx_token) => {
                    if let Err(e) =
                    let_mut_field!(self.inner,
                        inner.dispatch_ieee802154_out_packet(
                        tx_token,
                        &mut self.out_packets.sixlowpan_out_packet,
                    )) {
                        net_debug!("failed to transmit: {}", e);
                    }

                    // Reset the buffer when we transmitted everything.
                    if self.out_packets.sixlowpan_out_packet.finished() {
                        self.out_packets.sixlowpan_out_packet.reset();
                    }
                }
                Err(e) => {
                    net_debug!("failed to transmit: {}", e);
                }
            }
            // Put the inner interface back in place and assert
            // the field was None before
            //assert_none!(self.inner.replace(inner));
            Ok(true)
        } else {
            //assert_none!(self.inner.replace(inner));
            Ok(false)
        }
    }

    #[cfg(feature = "ohua")]
    #[allow(dead_code)]
    // ToDo: Sockets wont live as long as the interface.
    fn socket_egress_ohua<DeviceT>(&'a mut self, device: &mut DeviceT, sockets: &mut SocketSet<'a>) -> bool
    where
        DeviceT: for<'d> Device<'d>,
    {
        //let Self {
        //    out_packets: _out_packets,
        //    ..
        // } = self;
        //let _caps = device.capabilities();

        let mut emitted_any = false;

        // Todo: currently sockets are an extra thing, but we need to make sockets and
        //       interface one component. Once that's done, adapt iteration here

        for handle in 0..sockets.size() {
            if let Some(mut socket_item) = sockets.remove_item(handle)// Panics if it fails
            {
                if socket_item
                    .meta
                    .egress_permitted(self.inner().now,
                                      |ip_addr| self.inner().has_neighbor(&ip_addr))
                {
                    let inner = self.inner.take().unwrap();
                    match socket_item.socket {
                        #[cfg(feature = "socket-tcp")]
                        Socket::OhuaTcp(tcp_socket) => {
                            let (innerp, metap, socketp, res) =
                                enter_sending_recursion(inner, device,
                                                        socket_item.meta,
                                                        DispatchCall::Pre(device_independent_emit), tcp_socket);
                            // put the socket back in it's place
                            sockets.re_add_stolen_socket(socketp, metap, handle);
                            // Put the inner interface back in place and assert
                            // the field was None before, inside the match it's 'innerp'
                            assert_none!(self.inner.replace(innerp));
                            match res {
                                // We also get here, when dispatch_before returns early without
                                // having send something
                                Ok((emitted, true)) => {
                                    emitted_any = emitted_any || emitted;
                                }
                                Ok((_, false)) => {
                                    break;
                                }
                                Err(err) => {
                                    // FIXME what about the state changes?!
                                    // New error handling doesn't return here any more
                                    // return Err(err);
                                    net_debug!("{}: cannot dispatch egress packet: {}", handle, err);
                                }
                            }
                        }
                        _ => panic!("Only TCP sockets supported!"),
                    }
                    //Reminder: currently it can not happen, that we leave the match
                    //          without putting back the innerInterface and socket.
                    //          Make sure it remains this way.

                }

                else { // egress was not permitted for that socket
                    //So inner was not taken but we still have to give back the socket
                    // Re-add will check if the socket_set is empty at the given handle, if so
                    // it put the socket back in place. If not it appends it to the set which
                    // would be a problem so we rather check it
                    //TODO: How can I satisfy the AnySocket trait bound without matching again
                    match socket_item.socket {
                        Socket::OhuaTcp(socket) =>
                            assert!(SocketSet::<'a>::same(
                                sockets.re_add_stolen_socket(socket, socket_item.meta, handle), handle)
                            ),
                        _ => panic!("Only TCP sockets supported!")
                    }

                };
            }
        }
       emitted_any
    }
}


#[cfg(feature = "ohua")]
fn enter_sending_recursion<'a, DeviceT>(
    mut inner: Context<'a>,
    device: &mut DeviceT,
    mut meta: Meta, // meta data external to the socket impl.(neighbor_cache)
    disp_call: DispatchCall,
    mut socket: OhuaTcpSocket<'a>,
) -> ( Context<'a>, Meta, OhuaTcpSocket<'a>, Result<(bool, bool)>)
where
    DeviceT: for<'d> Device<'d>,
{
    // What we do here
    // 1. call res = socket.dispatch_before()
    // 2. call dev_result = send_to_device() which is just the 'respond' closure
    // 3. call socket.dispatch_after()
    // We do this in this brain wrenching way, because we can only call the socket
    // once if we want it to be a single stateful node later on.
    // ToDo: Thread out_packets here when we support 6loWPAN
    let res = socket.dispatch_by_call(&mut inner, disp_call);
    match res {
        DispatchResult::Pre(pre_result) =>
            match pre_result {
            Ok(None) => (inner, meta, socket,
                        // we didn't emit anything because dispatch_before returned early
                        // but that's ok in the new version of smoltcp
                        Ok((false, true))),
            Ok(Some((data, (tcp_repr_p, ip_repr, is_keep_alive)))) => {
                let neighbor_addr = Some(ip_repr.dst_addr());
                match send_to_device(&inner, device, data) {
                    Ok(()) => enter_sending_recursion(
                        inner,
                        device,
                        meta,
                        DispatchCall::Post(tcp_repr_p, is_keep_alive),
                        socket,
                    ),
                    Err(Error::Exhausted) => (inner, meta, socket,
                        Ok((false, false))), // nowhere to transmit
                    Err(Error::Unaddressable) => {
                        // `NeighborCache` already takes care of rate limiting the neighbor discovery
                        // requests from the socket. However, without an additional rate limiting
                        // mechanism, we would spin on every socket that has yet to discover its
                        // neighbor.
                        meta.neighbor_missing(
                            inner.now,
                            neighbor_addr.expect("non-IP response packet"),
                        );
                        (inner, meta, socket, Ok((false, false)))
                    },
                    Err(err) => {
                        (inner, meta, socket,
                         Err(err))
                    },
                }
            }
            Err(Error::Exhausted) => (inner, meta, socket,
                 Ok((false, true))), // nothing to transmit
            Err(err) => {
                (inner,  meta, socket,
                 Err(err))
            }
        },
        DispatchResult::Post =>
                (inner, meta, socket,
            Ok((true, true))), // emitted_any = true
    }
}



/// This is in the end not at all a function on the socket but
/// only on the device and the IP layer.
#[cfg(feature = "ohua")]
fn send_to_device<'a, DeviceT: for<'d> Device<'d>>(
    inner: &'a Context<'a>,
    device_ref: &mut DeviceT,
    data: Vec<u8>
) -> Result<()>
{
    // get the token which holds the reference to the device
    let tx_token = device_ref.transmit().ok_or(Error::Exhausted)?;
    let tx_len = data.len();
    tx_token.consume(
        // FIXME this is really a bit annoying because the timestamp is not even used
        // but it is the only reason for sharing `inner`
        inner.now, // the timestamp is actually not used
        tx_len,
        |tx_buffer| { // sadly: instead of just taking this buffer, the RawSocket will create its own.
            debug_assert!(tx_buffer.as_ref().len() == tx_len);
            // all we need to do is copy over the data
            // FIXME don't copy. just move
            tx_buffer.copy_from_slice(data.as_slice());
            Ok(())
        })
}

/*
/// This sets the state of the socket when no error occurred.
#[cfg(feature = "ohua")]
fn socket_egress_tcp_post<'a>(
    inner: &'a Context<'a>,
    tcp_socket: &'a mut OhuaTcpSocket<'a>,
    result: (TcpRepr<'a>, bool),
) -> () {
    tcp_socket.dispatch_after(inner, result)
}
*/

#[cfg(feature = "ohua")]
fn device_independent_emit(
    inner: &mut Context,
    reprs: (IpRepr, TcpRepr),
) -> Result<Vec<u8>>
{
    let as_packet = IpPacket::Tcp(reprs);

    let mut device = OhuaRawSocket::new();

    // error handling in the original code seems broken here:
    // this is part of socked_result
    let tx_token = device.transmit().ok_or(Error::Exhausted)?;

    // TODO dispatch_ip just returns the result of the consume call.
    // need to make sure that we do not swallow this here..
    // Reminder: Dont forget to thread actual _out_packets through here instead of None
    inner.dispatch_ip(tx_token, as_packet, None)?;


    let d = device.data.borrow_mut().take();
    match d {
        Some(d) => Ok(d),
        None => panic!("We did not get any data packet to send from the IP layer.")
    }
}

/*
// TODO all of this could go back into the TCP socket.
#[cfg(feature = "ohua")]
fn socket_egress_tcp_pre<'a>(
    inner: &'a Context<'a>,
    tcp_socket: &'a mut OhuaTcpSocket<'a>,
) -> Result<(Vec<u8>, bool)> {
    let (ip_repr, tcp_repr, b) = tcp_socket.dispatch_before(
        inner)?;

    let response = IpPacket::Tcp((ip_repr, tcp_repr));

    let device = OhuaRawSocket::new();

    // error handling in the original code seems broken here:
    // this is part of socked_result
    let tx_token = device.transmit().ok_or(Error::Exhausted)?;
    // TODO dispatch_ip just returns the result of the consume call.
    // need to make sure that we do not swallow this here..
    inner.dispatch_ip(tx_token, response)?;

    match tx_token.data.take() {
        Some(d) => Ok((d,b)),
        None => panic!("We did not get any data packet to send from the IP layer.")
    }
}
*/


#[cfg(test)]
mod test {
    use std::collections::BTreeMap;
    #[cfg(feature = "proto-igmp")]
    use std::vec::Vec;

    use super::*;

    use crate::iface::OInterface;
    #[cfg(feature = "medium-ethernet")]
    use crate::iface::NeighborCache;
    use crate::phy::{ChecksumCapabilities, Loopback};
    #[cfg(feature = "proto-igmp")]
    use crate::time::Instant;
    use crate::{Error, Result};
    use crate::socket::tcp::test::socket_established_with_endpoints;

    #[allow(unused)]
    fn fill_slice(s: &mut [u8], val: u8) {
        for x in s.iter_mut() {
            *x = val
        }
    }

    fn create<'a>() -> (OInterface<'a>, SocketSet<'a>, Loopback) {
        #[cfg(feature = "medium-ethernet")]
        return create_ethernet();
        #[cfg(not(feature = "medium-ethernet"))]
        return create_ip();
    }

    #[cfg(all(feature = "medium-ip"))]
    #[allow(unused)]
    fn create_ip<'a>() -> (OInterface<'a>, SocketSet<'a>, Loopback) {
        // Create a basic device
        let mut device = Loopback::new(Medium::Ip);
        let ip_addrs = [
            #[cfg(feature = "proto-ipv4")]
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64),
        ];

        let iface_builder = OInterfaceBuilder::new().ip_addrs(ip_addrs);

        #[cfg(feature = "proto-ipv4-fragmentation")]
        let iface_builder =
            iface_builder.ipv4_fragments_cache(PacketAssemblerSet::new(vec![], BTreeMap::new()));

        #[cfg(feature = "proto-igmp")]
        let iface_builder = iface_builder.ipv4_multicast_groups(BTreeMap::new());
        let iface = iface_builder.finalize(&mut device);

        (iface, SocketSet::new(vec![]), device)
    }

    #[cfg(all(feature = "medium-ethernet"))]
    fn create_ethernet<'a>() -> (OInterface<'a>, SocketSet<'a>, Loopback) {
        // Create a basic device
        let mut device = Loopback::new(Medium::Ethernet);
        let ip_addrs = [
            #[cfg(feature = "proto-ipv4")]
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64),
        ];

        let iface_builder = OInterfaceBuilder::new()
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(NeighborCache::new(BTreeMap::new()))
            .ip_addrs(ip_addrs);

        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        let iface_builder = iface_builder
            .sixlowpan_fragments_cache(PacketAssemblerSet::new(vec![], BTreeMap::new()))
            .sixlowpan_out_packet_cache(vec![]);

        #[cfg(feature = "proto-ipv4-fragmentation")]
        let iface_builder =
            iface_builder.ipv4_fragments_cache(PacketAssemblerSet::new(vec![], BTreeMap::new()));

        #[cfg(feature = "proto-igmp")]
        let iface_builder = iface_builder.ipv4_multicast_groups(BTreeMap::new());
        let iface = iface_builder.finalize(&mut device);

        (iface, SocketSet::new(vec![]), device)
    }

    #[cfg(feature = "proto-igmp")]
    fn recv_all(device: &mut Loopback, timestamp: Instant) -> Vec<Vec<u8>> {
        let mut pkts = Vec::new();
        while let Some((rx, _tx)) = device.receive() {
            rx.consume(timestamp, |pkt| {
                pkts.push(pkt.to_vec());
                Ok(())
            })
            .unwrap();
        }
        pkts
    }

    #[derive(Debug, PartialEq)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    struct MockTxToken;

    impl TxToken for MockTxToken {
        fn consume<R, F>(self, _: Instant, _: usize, _: F) -> Result<R>
        where
            F: FnOnce(&mut [u8]) -> Result<R>,
        {
            Err(Error::Unaddressable)
        }
    }

    #[test]
    #[should_panic(expected = "hardware_addr required option was not set")]
    #[cfg(all(feature = "medium-ethernet"))]
    fn test_builder_initialization_panic() {
        let mut device = Loopback::new(Medium::Ethernet);
        OInterfaceBuilder::new().finalize(&mut device);
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_no_icmp_no_unicast_ipv4() {
        let (mut iface, mut sockets, _device) = create();

        // Unknown Ipv4 Protocol
        //
        // Because the destination is the broadcast address
        // this should not trigger and Destination Unreachable
        // response. See RFC 1122 § 3.2.2.
        let repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            dst_addr: Ipv4Address::BROADCAST,
            next_header: IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit: 0x40,
        });

        let mut bytes = vec![0u8; 54];
        repr.emit(&mut bytes, &ChecksumCapabilities::default());
        let frame = Ipv4Packet::new_unchecked(&bytes);

        // Ensure that the unknown protocol frame does not trigger an
        // ICMP error response when the destination address is a
        // broadcast address

        #[cfg(not(feature = "proto-ipv4-fragmentation"))]
        assert_eq!(iface.inner.process_ipv4(&mut sockets, &frame, None), None);
        #[cfg(feature = "proto-ipv4-fragmentation")]
        let_mut_field!(iface.inner,
            assert_eq!(
                inner.process_ipv4(
                    &mut sockets,
                    &frame,
                    Some(&mut iface.fragments.ipv4_fragments)
                ),
                None
            )
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_no_icmp_no_unicast_ipv6() {
        let (mut iface, mut sockets, _device) = create();

        // Unknown Ipv6 Protocol
        //
        // Because the destination is the broadcast address
        // this should not trigger and Destination Unreachable
        // response. See RFC 1122 § 3.2.2.
        let repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: Ipv6Address::LINK_LOCAL_ALL_NODES,
            next_header: IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit: 0x40,
        });

        let mut bytes = vec![0u8; 54];
        repr.emit(&mut bytes, &ChecksumCapabilities::default());
        let frame = Ipv6Packet::new_unchecked(&bytes);

        // Ensure that the unknown protocol frame does not trigger an
        // ICMP error response when the destination address is a
        // broadcast address
        assert_eq!(iface.inner_mut().process_ipv6(&mut sockets, &frame), None);
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_icmp_error_no_payload() {
        static NO_BYTES: [u8; 0] = [];
        let (mut iface, mut sockets, _device) = create();

        // Unknown Ipv4 Protocol with no payload
        let repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            next_header: IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit: 0x40,
        });

        let mut bytes = vec![0u8; 34];
        repr.emit(&mut bytes, &ChecksumCapabilities::default());
        let frame = Ipv4Packet::new_unchecked(&bytes);

        // The expected Destination Unreachable response due to the
        // unknown protocol
        let icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::ProtoUnreachable,
            header: Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                next_header: IpProtocol::Unknown(12),
                payload_len: 0,
                hop_limit: 64,
            },
            data: &NO_BYTES,
        };

        let expected_repr = IpPacket::Icmpv4((
            Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                next_header: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            },
            icmp_repr,
        ));

        // Ensure that the unknown protocol triggers an error response.
        // And we correctly handle no payload.

        #[cfg(not(feature = "proto-ipv4-fragmentation"))]
        assert_eq!(
            iface.inner_mut().process_ipv4(&mut sockets, &frame, None),
            Some(expected_repr)
        );

        #[cfg(feature = "proto-ipv4-fragmentation")]
        let_mut_field!(iface.inner,
            assert_eq!(
                inner.process_ipv4(
                    &mut sockets,
                    &frame,
                    Some(&mut iface.fragments.ipv4_fragments)
                ),
                Some(expected_repr)
            )
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_local_subnet_broadcasts() {
        let (mut iface, _, _device) = create();
        iface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 1, 23]), 24));
            });
        });

        assert!(iface
            .inner_mut()
            .is_subnet_broadcast(Ipv4Address([192, 168, 1, 255])),);
        assert!(!iface
            .inner_mut()
            .is_subnet_broadcast(Ipv4Address([192, 168, 1, 254])),);

        iface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 23, 24]), 16));
            });
        });
        assert!(!iface
            .inner_mut()
            .is_subnet_broadcast(Ipv4Address([192, 168, 23, 255])),);
        assert!(!iface
            .inner_mut()
            .is_subnet_broadcast(Ipv4Address([192, 168, 23, 254])),);
        assert!(!iface
            .inner_mut()
            .is_subnet_broadcast(Ipv4Address([192, 168, 255, 254])),);
        assert!(iface
            .inner_mut()
            .is_subnet_broadcast(Ipv4Address([192, 168, 255, 255])),);

        iface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 23, 24]), 8));
            });
        });
        assert!(!iface
            .inner_mut()
            .is_subnet_broadcast(Ipv4Address([192, 23, 1, 255])),);
        assert!(!iface
            .inner_mut()
            .is_subnet_broadcast(Ipv4Address([192, 23, 1, 254])),);
        assert!(!iface
            .inner_mut()
            .is_subnet_broadcast(Ipv4Address([192, 255, 255, 254])),);
        assert!(iface
            .inner_mut()
            .is_subnet_broadcast(Ipv4Address([192, 255, 255, 255])),);
    }

    #[test]
    #[cfg(all(feature = "socket-udp", feature = "proto-ipv4"))]
    fn test_icmp_error_port_unreachable() {
        static UDP_PAYLOAD: [u8; 12] = [
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x6c, 0x64, 0x21,
        ];
        let (mut iface, mut sockets, _device) = create();

        let mut udp_bytes_unicast = vec![0u8; 20];
        let mut udp_bytes_broadcast = vec![0u8; 20];
        let mut packet_unicast = UdpPacket::new_unchecked(&mut udp_bytes_unicast);
        let mut packet_broadcast = UdpPacket::new_unchecked(&mut udp_bytes_broadcast);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
        };

        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            next_header: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
            hop_limit: 64,
        });

        // Emit the representations to a packet
        udp_repr.emit(
            &mut packet_unicast,
            &ip_repr.src_addr(),
            &ip_repr.dst_addr(),
            UDP_PAYLOAD.len(),
            |buf| buf.copy_from_slice(&UDP_PAYLOAD),
            &ChecksumCapabilities::default(),
        );

        let data = packet_unicast.into_inner();

        // The expected Destination Unreachable ICMPv4 error response due
        // to no sockets listening on the destination port.
        let icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::PortUnreachable,
            header: Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                next_header: IpProtocol::Udp,
                payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
                hop_limit: 64,
            },
            data,
        };
        let expected_repr = IpPacket::Icmpv4((
            Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                next_header: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            },
            icmp_repr,
        ));

        // Ensure that the unknown protocol triggers an error response.
        // And we correctly handle no payload.
        assert_eq!(
            iface.inner_mut().process_udp(&mut sockets, ip_repr, false, data),
            Some(expected_repr)
        );

        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr: Ipv4Address::BROADCAST,
            next_header: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
            hop_limit: 64,
        });

        // Emit the representations to a packet
        udp_repr.emit(
            &mut packet_broadcast,
            &ip_repr.src_addr(),
            &IpAddress::Ipv4(Ipv4Address::BROADCAST),
            UDP_PAYLOAD.len(),
            |buf| buf.copy_from_slice(&UDP_PAYLOAD),
            &ChecksumCapabilities::default(),
        );

        // Ensure that the port unreachable error does not trigger an
        // ICMP error response when the destination address is a
        // broadcast address and no socket is bound to the port.
        assert_eq!(
            iface
                .inner_mut()
                .process_udp(&mut sockets, ip_repr, false, packet_broadcast.into_inner()),
            None
        );
    }

    #[test]
    #[cfg(feature = "socket-udp")]
    fn test_handle_udp_broadcast() {
        use crate::wire::IpEndpoint;

        static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

        let (mut iface, mut sockets, _device) = create();

        let rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);
        let tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);

        let udp_socket = udp::Socket::new(rx_buffer, tx_buffer);

        let mut udp_bytes = vec![0u8; 13];
        let mut packet = UdpPacket::new_unchecked(&mut udp_bytes);

        let socket_handle = sockets.add(udp_socket);

        #[cfg(feature = "proto-ipv6")]
        let src_ip = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
        let src_ip = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
        };

        #[cfg(feature = "proto-ipv6")]
        let ip_repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: src_ip,
            dst_addr: Ipv6Address::LINK_LOCAL_ALL_NODES,
            next_header: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
            hop_limit: 0x40,
        });
        #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: src_ip,
            dst_addr: Ipv4Address::BROADCAST,
            next_header: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
            hop_limit: 0x40,
        });

        // Bind the socket to port 68
        let socket = sockets.get_mut::<udp::Socket>(socket_handle);
        assert_eq!(socket.bind(68), Ok(()));
        assert!(!socket.can_recv());
        assert!(socket.can_send());

        udp_repr.emit(
            &mut packet,
            &ip_repr.src_addr(),
            &ip_repr.dst_addr(),
            UDP_PAYLOAD.len(),
            |buf| buf.copy_from_slice(&UDP_PAYLOAD),
            &ChecksumCapabilities::default(),
        );

        // Packet should be handled by bound UDP socket
        assert_eq!(
            iface
                .inner_mut()
                .process_udp(&mut sockets, ip_repr, false, packet.into_inner()),
            None
        );

        // Make sure the payload to the UDP packet processed by process_udp is
        // appended to the bound sockets rx_buffer
        let socket = sockets.get_mut::<udp::Socket>(socket_handle);
        assert!(socket.can_recv());
        assert_eq!(
            socket.recv(),
            Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_ip.into(), 67)))
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_handle_ipv4_broadcast() {
        use crate::wire::{Icmpv4Packet, Icmpv4Repr, Ipv4Packet};

        let (mut iface, mut sockets, _device) = create();

        let our_ipv4_addr = iface.ipv4_address().unwrap();
        let src_ipv4_addr = Ipv4Address([127, 0, 0, 2]);

        // ICMPv4 echo request
        let icmpv4_data: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];
        let icmpv4_repr = Icmpv4Repr::EchoRequest {
            ident: 0x1234,
            seq_no: 0xabcd,
            data: &icmpv4_data,
        };

        // Send to IPv4 broadcast address
        let ipv4_repr = Ipv4Repr {
            src_addr: src_ipv4_addr,
            dst_addr: Ipv4Address::BROADCAST,
            next_header: IpProtocol::Icmp,
            hop_limit: 64,
            payload_len: icmpv4_repr.buffer_len(),
        };

        // Emit to ip frame
        let mut bytes = vec![0u8; ipv4_repr.buffer_len() + icmpv4_repr.buffer_len()];
        let frame = {
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(&mut bytes),
                &ChecksumCapabilities::default(),
            );
            icmpv4_repr.emit(
                &mut Icmpv4Packet::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
                &ChecksumCapabilities::default(),
            );
            Ipv4Packet::new_unchecked(&bytes)
        };

        // Expected ICMPv4 echo reply
        let expected_icmpv4_repr = Icmpv4Repr::EchoReply {
            ident: 0x1234,
            seq_no: 0xabcd,
            data: &icmpv4_data,
        };
        let expected_ipv4_repr = Ipv4Repr {
            src_addr: our_ipv4_addr,
            dst_addr: src_ipv4_addr,
            next_header: IpProtocol::Icmp,
            hop_limit: 64,
            payload_len: expected_icmpv4_repr.buffer_len(),
        };
        let expected_packet = IpPacket::Icmpv4((expected_ipv4_repr, expected_icmpv4_repr));

        #[cfg(not(feature = "proto-ipv4-fragmentation"))]
        assert_eq!(
            iface.inner.process_ipv4(&mut sockets, &frame, None),
            Some(expected_packet)
        );

        #[cfg(feature = "proto-ipv4-fragmentation")]
        let_mut_field!(iface.inner,
            assert_eq!(
                inner.process_ipv4(
                    &mut sockets,
                    &frame,
                    Some(&mut iface.fragments.ipv4_fragments)
                ),
                Some(expected_packet)
            )
        );
    }

    #[test]
    #[cfg(feature = "socket-udp")]
    fn test_icmp_reply_size() {

        #[cfg(feature = "proto-ipv6")]
        use crate::wire::Icmpv6DstUnreachable;
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        use crate::wire::IPV4_MIN_MTU as MIN_MTU;
        #[cfg(feature = "proto-ipv6")]
        use crate::wire::IPV6_MIN_MTU as MIN_MTU;

        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        const MAX_PAYLOAD_LEN: usize = 528;
        #[cfg(feature = "proto-ipv6")]
        const MAX_PAYLOAD_LEN: usize = 1192;

        let (mut iface, mut sockets, _device) = create();

        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let src_addr = Ipv4Address([192, 168, 1, 1]);
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let dst_addr = Ipv4Address([192, 168, 1, 2]);
        #[cfg(feature = "proto-ipv6")]
        let src_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        #[cfg(feature = "proto-ipv6")]
        let dst_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

        // UDP packet that if not truncated will cause a icmp port unreachable reply
        // to exceed the minimum mtu bytes in length.
        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
        };
        let mut bytes = vec![0xff; udp_repr.header_len() + MAX_PAYLOAD_LEN];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(
            &mut packet,
            &src_addr.into(),
            &dst_addr.into(),
            MAX_PAYLOAD_LEN,
            |buf| fill_slice(buf, 0x2a),
            &ChecksumCapabilities::default(),
        );
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let ip_repr = Ipv4Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.header_len() + MAX_PAYLOAD_LEN,
        };
        #[cfg(feature = "proto-ipv6")]
        let ip_repr = Ipv6Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.header_len() + MAX_PAYLOAD_LEN,
        };
        let payload = packet.into_inner();

        // Expected packets
        #[cfg(feature = "proto-ipv6")]
        let expected_icmp_repr = Icmpv6Repr::DstUnreachable {
            reason: Icmpv6DstUnreachable::PortUnreachable,
            header: ip_repr,
            data: &payload[..MAX_PAYLOAD_LEN],
        };
        #[cfg(feature = "proto-ipv6")]
        let expected_ip_repr = Ipv6Repr {
            src_addr: dst_addr,
            dst_addr: src_addr,
            next_header: IpProtocol::Icmpv6,
            hop_limit: 64,
            payload_len: expected_icmp_repr.buffer_len(),
        };
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let expected_icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::PortUnreachable,
            header: ip_repr,
            data: &payload[..MAX_PAYLOAD_LEN],
        };
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let expected_ip_repr = Ipv4Repr {
            src_addr: dst_addr,
            dst_addr: src_addr,
            next_header: IpProtocol::Icmp,
            hop_limit: 64,
            payload_len: expected_icmp_repr.buffer_len(),
        };

        // The expected packet does not exceed the IPV4_MIN_MTU
        #[cfg(feature = "proto-ipv6")]
        assert_eq!(
            expected_ip_repr.buffer_len() + expected_icmp_repr.buffer_len(),
            MIN_MTU
        );
        // The expected packet does not exceed the IPV4_MIN_MTU
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        assert_eq!(
            expected_ip_repr.buffer_len() + expected_icmp_repr.buffer_len(),
            MIN_MTU
        );
        // The expected packet and the generated packet are equal
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        assert_eq!(
            iface
                .inner
                .process_udp(&mut sockets, ip_repr.into(), false, payload),
            Some(IpPacket::Icmpv4((expected_ip_repr, expected_icmp_repr)))
        );
        #[cfg(feature = "proto-ipv6")]
        assert_eq!(
            iface
                .inner_mut()
                .process_udp(&mut sockets, ip_repr.into(), false, payload),
            Some(IpPacket::Icmpv6((expected_ip_repr, expected_icmp_repr)))
        );
    }

    #[test]
    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
    fn test_handle_valid_arp_request() {
        let (mut iface, mut sockets, _device) = create_ethernet();

        let mut eth_bytes = vec![0u8; 42];

        let local_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x01]);
        let remote_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x02]);
        let local_hw_addr = EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

        let repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: remote_hw_addr,
            source_protocol_addr: remote_ip_addr,
            target_hardware_addr: EthernetAddress::default(),
            target_protocol_addr: local_ip_addr,
        };

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress::BROADCAST);
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Arp);
        let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
        repr.emit(&mut packet);

        // Ensure an ARP Request for us triggers an ARP Reply
        let_mut_field!(iface.inner,
            assert_eq!(
                inner.process_ethernet(&mut sockets, frame.into_inner(), &mut iface.fragments),
                Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Reply,
                    source_hardware_addr: local_hw_addr,
                    source_protocol_addr: local_ip_addr,
                    target_hardware_addr: remote_hw_addr,
                    target_protocol_addr: remote_ip_addr
                }))
            )
        );

        // Ensure the address of the requester was entered in the cache
        assert_eq!(
            iface.inner_mut().lookup_hardware_addr(
                MockTxToken,
                &IpAddress::Ipv4(local_ip_addr),
                &IpAddress::Ipv4(remote_ip_addr)
            ),
            Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
        );
    }

    #[test]
    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
    fn test_handle_valid_ndisc_request() {
        let (mut iface, mut sockets, _device) = create_ethernet();

        let mut eth_bytes = vec![0u8; 86];

        let local_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1);
        let remote_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2);
        let local_hw_addr = EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

        let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
            target_addr: local_ip_addr,
            lladdr: Some(remote_hw_addr.into()),
        });
        let ip_repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: remote_ip_addr,
            dst_addr: local_ip_addr.solicited_node(),
            next_header: IpProtocol::Icmpv6,
            hop_limit: 0xff,
            payload_len: solicit.buffer_len(),
        });

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x00]));
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Ipv6);
        ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
        solicit.emit(
            &remote_ip_addr.into(),
            &local_ip_addr.solicited_node().into(),
            &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.buffer_len()..]),
            &ChecksumCapabilities::default(),
        );

        let icmpv6_expected = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
            flags: NdiscNeighborFlags::SOLICITED,
            target_addr: local_ip_addr,
            lladdr: Some(local_hw_addr.into()),
        });

        let ipv6_expected = Ipv6Repr {
            src_addr: local_ip_addr,
            dst_addr: remote_ip_addr,
            next_header: IpProtocol::Icmpv6,
            hop_limit: 0xff,
            payload_len: icmpv6_expected.buffer_len(),
        };

        // Ensure an Neighbor Solicitation triggers a Neighbor Advertisement
        let_mut_field!(iface.inner,
            assert_eq!(
                inner.process_ethernet(&mut sockets, frame.into_inner(), &mut iface.fragments),
                Some(EthernetPacket::Ip(IpPacket::Icmpv6((
                    ipv6_expected,
                    icmpv6_expected
                ))))
            )
        );

        // Ensure the address of the requester was entered in the cache
        assert_eq!(
            iface.inner_mut().lookup_hardware_addr(
                MockTxToken,
                &IpAddress::Ipv6(local_ip_addr),
                &IpAddress::Ipv6(remote_ip_addr)
            ),
            Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
        );
    }

    #[test]
    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
    fn test_handle_other_arp_request() {
        let (mut iface, mut sockets, _device) = create_ethernet();

        let mut eth_bytes = vec![0u8; 42];

        let remote_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x02]);
        let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

        let repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: remote_hw_addr,
            source_protocol_addr: remote_ip_addr,
            target_hardware_addr: EthernetAddress::default(),
            target_protocol_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x03]),
        };

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress::BROADCAST);
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Arp);
        let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
        repr.emit(&mut packet);

        // Ensure an ARP Request for someone else does not trigger an ARP Reply
        let_mut_field!(iface.inner,
            assert_eq!(
                inner.process_ethernet(&mut sockets, frame.into_inner(), &mut iface.fragments),
                None
            )
        );

        // Ensure the address of the requester was NOT entered in the cache
        assert_eq!(
            iface.inner_mut().lookup_hardware_addr(
                MockTxToken,
                &IpAddress::Ipv4(Ipv4Address([0x7f, 0x00, 0x00, 0x01])),
                &IpAddress::Ipv4(remote_ip_addr)
            ),
            Err(Error::Unaddressable)
        );
    }

    #[test]
    #[cfg(all(
        feature = "medium-ethernet",
        feature = "proto-ipv4",
        not(feature = "medium-ieee802154")
    ))]
    fn test_arp_flush_after_update_ip() {
        let (mut iface, mut sockets, _device) = create_ethernet();

        let mut eth_bytes = vec![0u8; 42];

        let local_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x01]);
        let remote_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x02]);
        let local_hw_addr = EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

        let repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: remote_hw_addr,
            source_protocol_addr: remote_ip_addr,
            target_hardware_addr: EthernetAddress::default(),
            target_protocol_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
        };

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress::BROADCAST);
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Arp);
        {
            let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
            repr.emit(&mut packet);
        }

        // Ensure an ARP Request for us triggers an ARP Reply
        assert_eq!(
            iface
                .inner
                .process_ethernet(&mut sockets, frame.into_inner(), &mut iface.fragments),
            Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: local_hw_addr,
                source_protocol_addr: local_ip_addr,
                target_hardware_addr: remote_hw_addr,
                target_protocol_addr: remote_ip_addr
            }))
        );

        // Ensure the address of the requester was entered in the cache
        assert_eq!(
            iface.inner.lookup_hardware_addr(
                MockTxToken,
                &IpAddress::Ipv4(local_ip_addr),
                &IpAddress::Ipv4(remote_ip_addr)
            ),
            Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
        );

        // Update IP addrs to trigger ARP cache flush
        let local_ip_addr_new = Ipv4Address([0x7f, 0x00, 0x00, 0x01]);
        iface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(local_ip_addr_new, 24));
            });
        });

        // ARP cache flush after address change
        assert!(!iface.inner.has_neighbor(&IpAddress::Ipv4(remote_ip_addr)));
    }

    #[test]
    #[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
    fn test_icmpv4_socket() {
        use crate::wire::Icmpv4Packet;

        let (mut iface, mut sockets, _device) = create();

        let rx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 24]);
        let tx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 24]);

        let icmpv4_socket = icmp::Socket::new(rx_buffer, tx_buffer);

        let socket_handle = sockets.add(icmpv4_socket);

        let ident = 0x1234;
        let seq_no = 0x5432;
        let echo_data = &[0xff; 16];

        let socket = sockets.get_mut::<icmp::Socket>(socket_handle);
        // Bind to the ID 0x1234
        assert_eq!(socket.bind(icmp::Endpoint::Ident(ident)), Ok(()));

        // Ensure the ident we bound to and the ident of the packet are the same.
        let mut bytes = [0xff; 24];
        let mut packet = Icmpv4Packet::new_unchecked(&mut bytes[..]);
        let echo_repr = Icmpv4Repr::EchoRequest {
            ident,
            seq_no,
            data: echo_data,
        };
        echo_repr.emit(&mut packet, &ChecksumCapabilities::default());
        let icmp_data = &*packet.into_inner();

        let ipv4_repr = Ipv4Repr {
            src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
            dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
            next_header: IpProtocol::Icmp,
            payload_len: 24,
            hop_limit: 64,
        };
        let ip_repr = IpRepr::Ipv4(ipv4_repr);

        // Open a socket and ensure the packet is handled due to the listening
        // socket.
        assert!(!sockets.get_mut::<icmp::Socket>(socket_handle).can_recv());

        // Confirm we still get EchoReply from `smoltcp` even with the ICMP socket listening
        let echo_reply = Icmpv4Repr::EchoReply {
            ident,
            seq_no,
            data: echo_data,
        };
        let ipv4_reply = Ipv4Repr {
            src_addr: ipv4_repr.dst_addr,
            dst_addr: ipv4_repr.src_addr,
            ..ipv4_repr
        };
        assert_eq!(
            iface.inner_mut().process_icmpv4(&mut sockets, ip_repr, icmp_data),
            Some(IpPacket::Icmpv4((ipv4_reply, echo_reply)))
        );

        let socket = sockets.get_mut::<icmp::Socket>(socket_handle);
        assert!(socket.can_recv());
        assert_eq!(
            socket.recv(),
            Ok((
                icmp_data,
                IpAddress::Ipv4(Ipv4Address::new(0x7f, 0x00, 0x00, 0x02))
            ))
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_solicited_node_addrs() {
        let (mut iface, _, _device) = create();
        let mut new_addrs = vec![
            IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 1, 2, 0, 2), 64),
            IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 3, 4, 0, 0xffff), 64),
        ];
        iface.update_ip_addrs(|addrs| {
            new_addrs.extend(addrs.to_vec());
            *addrs = From::from(new_addrs);
        });
        assert!(iface
            .inner_mut()
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0002)));
        assert!(iface
            .inner_mut()
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0xffff)));
        assert!(!iface
            .inner_mut()
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0003)));
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_icmpv6_nxthdr_unknown() {
        let (mut iface, mut sockets, _device) = create();

        let remote_ip_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

        let payload = [0x12, 0x34, 0x56, 0x78];

        let ipv6_repr = Ipv6Repr {
            src_addr: remote_ip_addr,
            dst_addr: Ipv6Address::LOOPBACK,
            next_header: IpProtocol::HopByHop,
            payload_len: 12,
            hop_limit: 0x40,
        };

        let mut bytes = vec![0; 52];
        let frame = {
            let ip_repr = IpRepr::Ipv6(ipv6_repr);
            ip_repr.emit(&mut bytes, &ChecksumCapabilities::default());
            let mut offset = ipv6_repr.buffer_len();
            {
                let mut hbh_pkt = Ipv6HopByHopHeader::new_unchecked(&mut bytes[offset..]);
                hbh_pkt.set_next_header(IpProtocol::Unknown(0x0c));
                hbh_pkt.set_header_len(0);
                offset += 8;
                {
                    let mut pad_pkt = Ipv6Option::new_unchecked(&mut *hbh_pkt.options_mut());
                    Ipv6OptionRepr::PadN(3).emit(&mut pad_pkt);
                }
                {
                    let mut pad_pkt = Ipv6Option::new_unchecked(&mut hbh_pkt.options_mut()[5..]);
                    Ipv6OptionRepr::Pad1.emit(&mut pad_pkt);
                }
            }
            bytes[offset..].copy_from_slice(&payload);
            Ipv6Packet::new_unchecked(&bytes)
        };

        let reply_icmp_repr = Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
            pointer: 40,
            header: ipv6_repr,
            data: &payload[..],
        };

        let reply_ipv6_repr = Ipv6Repr {
            src_addr: Ipv6Address::LOOPBACK,
            dst_addr: remote_ip_addr,
            next_header: IpProtocol::Icmpv6,
            payload_len: reply_icmp_repr.buffer_len(),
            hop_limit: 0x40,
        };

        // Ensure the unknown next header causes a ICMPv6 Parameter Problem
        // error message to be sent to the sender.
        assert_eq!(
            iface.inner_mut().process_ipv6(&mut sockets, &frame),
            Some(IpPacket::Icmpv6((reply_ipv6_repr, reply_icmp_repr)))
        );
    }

    #[test]
    #[cfg(feature = "proto-igmp")]
    fn test_handle_igmp() {
        fn recv_igmp(device: &mut Loopback, timestamp: Instant) -> Vec<(Ipv4Repr, IgmpRepr)> {
            let caps = device.capabilities();
            let checksum_caps = &caps.checksum;
            recv_all(device, timestamp)
                .iter()
                .filter_map(|frame| {
                    let ipv4_packet = match caps.medium {
                        #[cfg(feature = "medium-ethernet")]
                        Medium::Ethernet => {
                            let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                            Ipv4Packet::new_checked(eth_frame.payload()).ok()?
                        }
                        #[cfg(feature = "medium-ip")]
                        Medium::Ip => Ipv4Packet::new_checked(&frame[..]).ok()?,
                        #[cfg(feature = "medium-ieee802154")]
                        Medium::Ieee802154 => todo!(),
                    };
                    let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, checksum_caps).ok()?;
                    let ip_payload = ipv4_packet.payload();
                    let igmp_packet = IgmpPacket::new_checked(ip_payload).ok()?;
                    let igmp_repr = IgmpRepr::parse(&igmp_packet).ok()?;
                    Some((ipv4_repr, igmp_repr))
                })
                .collect::<Vec<_>>()
        }

        let groups = [
            Ipv4Address::new(224, 0, 0, 22),
            Ipv4Address::new(224, 0, 0, 56),
        ];

        let (mut iface, mut sockets, mut device) = create();

        // Join multicast groups
        let timestamp = Instant::now();
        for group in &groups {
            iface
                .join_multicast_group(&mut device, *group, timestamp)
                .unwrap();
        }

        let reports = recv_igmp(&mut device, timestamp);
        assert_eq!(reports.len(), 2);
        for (i, group_addr) in groups.iter().enumerate() {
            assert_eq!(reports[i].0.next_header, IpProtocol::Igmp);
            assert_eq!(reports[i].0.dst_addr, *group_addr);
            assert_eq!(
                reports[i].1,
                IgmpRepr::MembershipReport {
                    group_addr: *group_addr,
                    version: IgmpVersion::Version2,
                }
            );
        }

        // General query
        let timestamp = Instant::now();
        const GENERAL_QUERY_BYTES: &[u8] = &[
            0x46, 0xc0, 0x00, 0x24, 0xed, 0xb4, 0x00, 0x00, 0x01, 0x02, 0x47, 0x43, 0xac, 0x16,
            0x63, 0x04, 0xe0, 0x00, 0x00, 0x01, 0x94, 0x04, 0x00, 0x00, 0x11, 0x64, 0xec, 0x8f,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        {
            // Transmit GENERAL_QUERY_BYTES into loopback
            let tx_token = device.transmit().unwrap();
            tx_token
                .consume(timestamp, GENERAL_QUERY_BYTES.len(), |buffer| {
                    buffer.copy_from_slice(GENERAL_QUERY_BYTES);
                    Ok(())
                })
                .unwrap();
        }
        // Trigger processing until all packets received through the
        // loopback have been processed, including responses to
        // GENERAL_QUERY_BYTES. Therefore `recv_all()` would return 0
        // pkts that could be checked.
        iface.socket_ingress(&mut device, &mut sockets);

        // Leave multicast groups
        let timestamp = Instant::now();
        for group in &groups {
            iface
                .leave_multicast_group(&mut device, *group, timestamp)
                .unwrap();
        }

        let leaves = recv_igmp(&mut device, timestamp);
        assert_eq!(leaves.len(), 2);
        for (i, group_addr) in groups.iter().cloned().enumerate() {
            assert_eq!(leaves[i].0.next_header, IpProtocol::Igmp);
            assert_eq!(leaves[i].0.dst_addr, Ipv4Address::MULTICAST_ALL_ROUTERS);
            assert_eq!(leaves[i].1, IgmpRepr::LeaveGroup { group_addr });
        }
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-raw"))]
    fn test_raw_socket_no_reply() {
        use crate::wire::{IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

        let (mut iface, mut sockets, _device) = create();

        let packets = 1;
        let rx_buffer =
            raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let tx_buffer = raw::PacketBuffer::new(
            vec![raw::PacketMetadata::EMPTY; packets],
            vec![0; 48 * packets],
        );
        let raw_socket = raw::Socket::new(IpVersion::Ipv4, IpProtocol::Udp, rx_buffer, tx_buffer);
        sockets.add(raw_socket);

        let src_addr = Ipv4Address([127, 0, 0, 2]);
        let dst_addr = Ipv4Address([127, 0, 0, 1]);

        const PAYLOAD_LEN: usize = 10;

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
        };
        let mut bytes = vec![0xff; udp_repr.header_len() + PAYLOAD_LEN];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(
            &mut packet,
            &src_addr.into(),
            &dst_addr.into(),
            PAYLOAD_LEN,
            |buf| fill_slice(buf, 0x2a),
            &ChecksumCapabilities::default(),
        );
        let ipv4_repr = Ipv4Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.header_len() + PAYLOAD_LEN,
        };

        // Emit to frame
        let mut bytes = vec![0u8; ipv4_repr.buffer_len() + udp_repr.header_len() + PAYLOAD_LEN];
        let frame = {
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(&mut bytes),
                &ChecksumCapabilities::default(),
            );
            udp_repr.emit(
                &mut UdpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
                &src_addr.into(),
                &dst_addr.into(),
                PAYLOAD_LEN,
                |buf| fill_slice(buf, 0x2a),
                &ChecksumCapabilities::default(),
            );
            Ipv4Packet::new_unchecked(&bytes)
        };

        #[cfg(not(feature = "proto-ipv4-fragmentation"))]
        assert_eq!(iface.inner.process_ipv4(&mut sockets, &frame, None), None);
        #[cfg(feature = "proto-ipv4-fragmentation")]
        let_mut_field!(iface.inner,
            assert_eq!(
                inner.process_ipv4(
                    &mut sockets,
                    &frame,
                    Some(&mut iface.fragments.ipv4_fragments)
                ),
                None
            )
        );
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-raw", feature = "socket-udp"))]
    fn test_raw_socket_with_udp_socket() {
        use crate::wire::{IpEndpoint, IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

        static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

        let (mut iface, mut sockets, _device) = create();

        let udp_rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);
        let udp_tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);
        let udp_socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);
        let udp_socket_handle = sockets.add(udp_socket);

        // Bind the socket to port 68
        let socket = sockets.get_mut::<udp::Socket>(udp_socket_handle);
        assert_eq!(socket.bind(68), Ok(()));
        assert!(!socket.can_recv());
        assert!(socket.can_send());

        let packets = 1;
        let raw_rx_buffer =
            raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let raw_tx_buffer = raw::PacketBuffer::new(
            vec![raw::PacketMetadata::EMPTY; packets],
            vec![0; 48 * packets],
        );
        let raw_socket = raw::Socket::new(
            IpVersion::Ipv4,
            IpProtocol::Udp,
            raw_rx_buffer,
            raw_tx_buffer,
        );
        sockets.add(raw_socket);

        let src_addr = Ipv4Address([127, 0, 0, 2]);
        let dst_addr = Ipv4Address([127, 0, 0, 1]);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
        };
        let mut bytes = vec![0xff; udp_repr.header_len() + UDP_PAYLOAD.len()];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(
            &mut packet,
            &src_addr.into(),
            &dst_addr.into(),
            UDP_PAYLOAD.len(),
            |buf| buf.copy_from_slice(&UDP_PAYLOAD),
            &ChecksumCapabilities::default(),
        );
        let ipv4_repr = Ipv4Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        };

        // Emit to frame
        let mut bytes =
            vec![0u8; ipv4_repr.buffer_len() + udp_repr.header_len() + UDP_PAYLOAD.len()];
        let frame = {
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(&mut bytes),
                &ChecksumCapabilities::default(),
            );
            udp_repr.emit(
                &mut UdpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
                &src_addr.into(),
                &dst_addr.into(),
                UDP_PAYLOAD.len(),
                |buf| buf.copy_from_slice(&UDP_PAYLOAD),
                &ChecksumCapabilities::default(),
            );
            Ipv4Packet::new_unchecked(&bytes)
        };

	#[cfg(not(feature = "proto-ipv4-fragmentation"))]
        let_mut_field!(iface.inner,
		assert_eq!(
		    inner.process_ipv4(&mut sockets, &frame, None), None
		)
        );

	#[cfg(feature = "proto-ipv4-fragmentation")]
	let_mut_field!(iface.inner,
		assert_eq!(
		    inner.process_ipv4(
		        &mut sockets,
		        &frame,
		        Some(&mut iface.fragments.ipv4_fragments)
		    ),
		    None
		)
	);
        // Make sure the UDP socket can still receive in presence of a Raw socket that handles UDP
        let socket = sockets.get_mut::<udp::Socket>(udp_socket_handle);
        assert!(socket.can_recv());
        assert_eq!(
            socket.recv(),
            Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_addr.into(), 67)))
        );
    }

   #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-tcp", feature = "ohua"))]
    fn test_tcp_socket_egress() {
        use crate::socket::tcp_ohua::OhuaTcpSocket;
        use crate::socket::tcp_ohua::test::{
            socket_established_with_endpoints, TestSocket};
        use crate::wire::{IpEndpoint, Ipv4Address, IpAddress};

        //smoltcp: egress_tcp
        let (mut iface1, mut sockets1, mut device1) = create();

        let TestSocket{socket, cx} = socket_established_with_endpoints(
                // I could not enforce proto-ipv4
                IpEndpoint{
                    addr: IpAddress::Ipv4(Ipv4Address([192, 168, 1, 1])),
                    port: 80
                },
                IpEndpoint {
                    addr: IpAddress::Ipv4(Ipv4Address::BROADCAST),
                    port: 49500} );

        //iface1.inner = Some(cx);
        // Devices sending buffer should be empty
        assert!(device1.empty_tx());

        let tcp_socket_handle1 = sockets1.add(socket);

        let socket1 = sockets1.get_mut::<tcp_ohua::OhuaTcpSocket>(tcp_socket_handle1);
        assert!(!socket1.can_recv());
        assert!(socket1.may_send());
        assert!(socket1.can_send());
        // Sockets sending buffer should be empty before sending
        assert!(socket1.send_queue()==0);


        let msg = "hello".as_bytes();
        let msg_len = msg.len();
        // Enqueue the message in the sockets sending buffer
        let result_len = socket1.send_slice(msg);
        assert_eq!(result_len, Ok(msg_len));
        net_debug!("running egress");
        assert_eq!(iface1.socket_egress(&mut device1, &mut sockets1), true);
       // Make sure the data arrived at the device level:
        /* socket_egress gets a sending token from the device, passes is through
         socket.dispatch() and (in this case) device.transmi() -> inner_interface.dispatch()->
         inner_interface.dispatch_ip() -> inner_interface.dispatch_ethernet() ->  token.consume()
         The consume function for Loopback interfaces causes the assembled packet representation
         to be pushed to the devices Tx queue. So that's where we'd expect to see the packet afterwards
         */
        // TODO: I need a function to build the comparison packet (btw. mock packets seem to be needed quite often so ...
        // Devices sending buffer should contain our packet
       assert_eq!(1, device1.num_tx_packets());
       net_debug!("one packet in the buffer :-)");


        // OHUA: socket_egress_tcp
        net_debug!("Now the same procedure for Ohua");
        let (mut iface2, mut sockets2, mut device2) = create();
        let TestSocket{socket, cx} = socket_established_with_endpoints(
                // I could not enforce proto-ipv4
                IpEndpoint{
                    addr: IpAddress::Ipv4(Ipv4Address([192, 168, 1, 1])),
                    port: 80
                },
                IpEndpoint {
                    addr: IpAddress::Ipv4(Ipv4Address::BROADCAST),
                    port: 49500} );

        //iface2.inner = Some(cx);
        // Devices sending buffer should again be empty
        assert!(device2.empty_tx());

        let tcp_socket_handle2 = sockets2.add(socket);

        let socket2 = sockets2.get_mut::<tcp_ohua::OhuaTcpSocket>(tcp_socket_handle2);
        assert!(!socket2.can_recv());
        assert!(socket2.may_send());
        assert!(socket2.can_send());
        // Sockets sending buffer should be empty before sending
        assert!(socket2.send_queue()==0);

        // Enqueue the message in the sockets sending buffer
        let result_len = socket2.send_slice(msg);
        assert_eq!(result_len, Ok(msg_len));
        net_debug!("running egress with ohua version");
        assert_eq!(iface2.socket_egress_ohua(&mut device2, &mut sockets2 ), true);

        // Again make sure the data arrived at the device level:
        // Devices sending buffer should contain our packet
        assert_eq!(1, device2.num_tx_packets());

        // TODO compare the states of both sockets
       let s1 = sockets1.get_mut::<tcp_ohua::OhuaTcpSocket>(tcp_socket_handle1).state();
       let s2 = sockets2.get_mut::<tcp_ohua::OhuaTcpSocket>(tcp_socket_handle2).state();
       assert_eq!(s1, s2);


        // As it is a loopback we should also be able to receive from it
        iface1.socket_ingress(&mut device2, &mut sockets2);
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-tcp", feature = "ohua"))]
    fn test_tcp_socket_ingress() {
        /*let TestSocket{socket, cx} = socket_established_with_endpoints(
                // local
                IpEndpoint{
                    addr: IpAddress::Ipv4(Ipv4Address([192, 168, 1, 1])),
                    port: 80
                },
                // remote
                IpEndpoint {
                    addr: IpAddress::Ipv4(Ipv4Address::BROADCAST),
                    port: 49500} );
        let mock_context = Context::mock();
        // assert_eq!(mock_context, mock_context);
        // TODO: The igmp test uses ingress and puts the packet directly into the device before
        // do this.*/
        assert!(true);
    }
    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-tcp", feature = "ohua"))]
    fn test_tcp_loop() {
        // TODO: Rebuild the loopback example, just in case we're not testing examples all the
        // time and mess something up
    }



}
