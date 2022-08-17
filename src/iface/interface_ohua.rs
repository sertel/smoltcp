// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP for any IPv4 work
// and RFCs 8200 and 4861 for any IPv6 and NDISC work.

//use core::cmp;
use managed::{ManagedMap, ManagedSlice};

#[cfg(feature = "ohua")]
use super::socket_meta::Meta;
#[cfg(feature = "ohua")]
use super::socket_set::Item;
#[cfg(feature = "ohua")]
use crate::phy::OhuaSocket;

use super::socket_set::SocketSet;
use super::{SocketHandle, SocketStorage};
use crate::iface::Routes;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
use crate::iface::{NeighborAnswer, NeighborCache};
use crate::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use crate::rand::Rand;
use crate::socket::*;
use crate::time::{Duration, Instant};
use crate::wire::*;
use crate::{Error, Result};
use crate::iface::interface::IpPacket;
use crate::socket::tcp_ohua::{Call,Results, OhuaTcpSocket};

/// A  network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct OInterface<'a, DeviceT: for<'d> Device<'d>> {
    device: Option<DeviceT>,
    sockets: SocketSet<'a>,
    inner: Option<OInterfaceInner<'a>>,
}

// We use those macros to temporarily take the 'field' i.e. sockets, inner or device
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

/// The device independent part of an Ethernet network interface.
///
/// Separating the device from the data required for prorcessing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `OInterface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on its `inner` field.
pub struct OInterfaceInner<'a> {
    caps: DeviceCapabilities,
    now: Instant,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_cache: Option<NeighborCache<'a>>,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    hardware_addr: Option<HardwareAddress>,
    #[cfg(feature = "medium-ieee802154")]
    sequence_no: u8,
    #[cfg(feature = "medium-ieee802154")]
    pan_id: Option<Ieee802154Pan>,
    ip_addrs: ManagedSlice<'a, IpCidr>,
    #[cfg(feature = "proto-ipv4")]
    any_ip: bool,
    routes: Routes<'a>,
    #[cfg(feature = "proto-igmp")]
    ipv4_multicast_groups: ManagedMap<'a, Ipv4Address, ()>,
    /// When to report for (all or) the next multicast group membership via IGMP
    #[cfg(feature = "proto-igmp")]
    igmp_report_state: IgmpReportState,
    rand: Rand,
}

/// A builder structure used for creating a network interface.
pub struct OInterfaceBuilder<'a, DeviceT: for<'d> Device<'d>> {
    device: DeviceT,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    hardware_addr: Option<HardwareAddress>,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_cache: Option<NeighborCache<'a>>,
    #[cfg(feature = "medium-ieee802154")]
    pan_id: Option<Ieee802154Pan>,
    ip_addrs: ManagedSlice<'a, IpCidr>,
    sockets: SocketSet<'a>,
    #[cfg(feature = "proto-ipv4")]
    any_ip: bool,
    routes: Routes<'a>,
    /// Does not share storage with `ipv6_multicast_groups` to avoid IPv6 size overhead.
    #[cfg(feature = "proto-igmp")]
    ipv4_multicast_groups: ManagedMap<'a, Ipv4Address, ()>,
    random_seed: u64,
}

impl<'a, DeviceT> OInterfaceBuilder<'a, DeviceT>
where
    DeviceT: for<'d> Device<'d>,
{
    /// Create a builder used for creating a network interface using the
    /// given device and address.
    #[cfg_attr(
        feature = "medium-ethernet",
        doc = r##"
# Examples

```
# use std::collections::BTreeMap;
use smoltcp::iface::{OInterfaceBuilder, NeighborCache};
# use smoltcp::phy::{Loopback, Medium};
use smoltcp::wire::{EthernetAddress, IpCidr, IpAddress};

let device = // ...
# Loopback::new(Medium::Ethernet);
let hw_addr = // ...
# EthernetAddress::default();
let neighbor_cache = // ...
# NeighborCache::new(BTreeMap::new());
let ip_addrs = // ...
# [];
let iface = OInterfaceBuilder::new(device, vec![])
        .hardware_addr(hw_addr.into())
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs)
        .finalize();
```
    "##
    )]
    pub fn new<SocketsT>(device: DeviceT, sockets: SocketsT) -> Self
    where
        SocketsT: Into<ManagedSlice<'a, SocketStorage<'a>>>,
    {
        OInterfaceBuilder {
            device: device,
            sockets: SocketSet::new(sockets),

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
    /// [hardware_addr]: struct.OInterface.html#method.hardware_addr
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn hardware_addr(mut self, addr: HardwareAddress) -> Self {
        OInterfaceInner::check_hardware_addr(&addr);
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
        OInterfaceInner::check_ip_addrs(&ip_addrs);
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
    pub fn routes<T>(mut self, routes: T) -> OInterfaceBuilder<'a, DeviceT>
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
    pub fn finalize(self) -> OInterface<'a, DeviceT> {
        let device_capabilities = self.device.capabilities();

        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        let (hardware_addr, neighbor_cache) = match device_capabilities.medium {
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

        let caps = self.device.capabilities();

        #[cfg(feature = "medium-ieee802154")]
        let mut rand :Rand = Rand::new(self.random_seed);
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

        OInterface {
            device: Some(self.device),
            sockets: self.sockets,
            inner: Some(OInterfaceInner {
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
                igmp_report_state:IgmpReportState::Inactive,
                #[cfg(feature = "medium-ieee802154")]
                sequence_no,
                #[cfg(feature = "medium-ieee802154")]
                pan_id: self.pan_id,
                rand,
            }),
        }
    }
}


impl<'a, DeviceT> OInterface<'a, DeviceT>
where
    DeviceT: for<'d> Device<'d>,
{
    /// Add a socket to the interface, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add_socket<T: AnySocket<'a>>(&mut self, socket: T) -> SocketHandle {
        self.sockets.add(socket)
    }

    /// Get a socket from the interface by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get_socket<T: AnySocket<'a>>(&mut self, handle: SocketHandle) -> &mut T {
        self.sockets.get(handle)
    }

    /// Get a socket by handle, and the socket context.
    ///
    /// The context is needed for some socket methods.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get_socket_and_context<T: AnySocket<'a>>(
        &mut self,
        handle: SocketHandle,
    ) -> (&mut T, &mut OInterfaceInner<'a>) {
        let_mut_field!(self.inner,
            (self.sockets.get(handle), inner)
        )
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove_socket(&mut self, handle: SocketHandle) -> Socket<'a> {
        self.sockets.remove(handle)
    }

    /// Get the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the medium is not Ethernet or Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn hardware_addr(&self) -> HardwareAddress {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.device().capabilities().medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.device().capabilities().medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.device().capabilities().medium == Medium::Ethernet
                || self.device().capabilities().medium == Medium::Ieee802154
        );

        let_field!(self.inner,
            inner.hardware_addr.unwrap()
        )
    }

    /// Set the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast, and if the medium is not Ethernet or
    /// Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn set_hardware_addr(&mut self, addr: HardwareAddress) {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.device().capabilities().medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.device().capabilities().medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.device().capabilities().medium == Medium::Ethernet
                || self.device().capabilities().medium == Medium::Ieee802154
        );

        OInterfaceInner::check_hardware_addr(&addr);
        self.inner_mut().hardware_addr = Some(addr);
    }

    /// Get a reference to the inner device.
    pub fn device(&self) -> &DeviceT {
        let_field!(self.device,
            device
        )
    }

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

    fn inner(&self) -> &OInterfaceInner {
        let_field!(self.inner,
            inner
        )
    }

    fn inner_mut(&mut self) -> &mut OInterfaceInner<'a> {
        let_mut_field!(self.inner,
            inner
        )
    }

    /// Get an iterator to the inner sockets.
    pub fn sockets(&self) -> impl Iterator<Item = (SocketHandle, &Socket<'a>)> {
        self.sockets.iter().map(|i| (i.meta.handle, &i.socket))
    }

    /// Get a mutable iterator to the inner sockets.
    pub fn sockets_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut Socket<'a>)> {
        self.sockets
            .iter_mut()
            .map(|i| (i.meta.handle, &mut i.socket))
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
            .filter_map(|cidr| match cidr.address() {
                IpAddress::Ipv4(addr) => Some(addr),
                _ => None,
            })
            .next()
    }

    /// Update the IP addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut ManagedSlice<'a, IpCidr>)>(&mut self, f: F) {
        let_mut_field!(self.inner,
            f(&mut inner.ip_addrs);
            OInterfaceInner::flush_cache(inner);
            OInterfaceInner::check_ip_addrs(&inner.ip_addrs)
        )
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
        let_mut_field!(self.inner,
            &mut inner.routes
        )
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
    pub fn poll(&mut self, timestamp: Instant) -> Result<bool> {
        let_mut_field!(self.inner,
            inner.now = timestamp
        );

        let mut readiness_may_have_changed = false;
        loop {
            let processed_any = self.socket_ingress();
            let emitted_any = self.socket_egress()?;

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
    pub fn poll_at(&mut self, timestamp: Instant) -> Option<Instant> {
        let_mut_field!(self.inner,
            inner.now = timestamp;

            //let inner = &mut inner;

            self.sockets
                .iter()
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
        )
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    /// The [Duration] returned is the time left to wait before calling [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Duration] has passed,
    /// and potentially harmful (impacting quality of service) to call it after the
    /// [Duration] has passed.
    ///
    /// [poll]: #method.poll
    /// [Duration]: struct.Duration.html
    pub fn poll_delay(&mut self, timestamp: Instant) -> Option<Duration> {
        match self.poll_at(timestamp) {
            Some(poll_at) if timestamp < poll_at => Some(poll_at - timestamp),
            Some(_) => Some(Duration::from_millis(0)),
            _ => None,
        }
    }

    fn socket_ingress(&mut self) -> bool {
        let mut processed_any = false;
//        let Self {
//            device,
//            inner,
//            sockets,
//            ..
//        } = self;
        let sockets = &mut self.sockets;
        let_mut_field!(self.inner,
        let_mut_field!(self.device,
            while let Some((rx_token, tx_token)) = device.receive() {
                if let Err(err) = rx_token.consume(inner.now, |frame| match inner.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => match inner.process_ethernet(sockets, &frame) {
                        Ok(response) => {
                            processed_any = true;
                            if let Some(packet) = response {
                                if let Err(err) = inner.dispatch(tx_token, packet) {
                                    net_debug!("Failed to send response: {}", err);
                                }
                            }
                            Ok(())
                        }
                        Err(err) => {
                            net_debug!("cannot process ingress packet: {}", err);
                            #[cfg(not(feature = "defmt"))]
                            net_debug!(
                                "packet dump follows:\n{}",
                                PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &frame)
                            );
                            Err(err)
                        }
                    },
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => match inner.process_ip(sockets, &frame) {
                        Ok(response) => {
                            processed_any = true;
                            if let Some(packet) = response {
                                if let Err(err) = inner.dispatch_ip(tx_token, packet) {
                                    net_debug!("Failed to send response: {}", err);
                                }
                            }
                            Ok(())
                        }
                        Err(err) => {
                            net_debug!("cannot process ingress packet: {}", err);
                            Err(err)
                        }
                    },
                    _ => panic!("No ieee format stuff for now")
                }) {
                    net_debug!("Failed to consume RX token: {}", err);
                }
            }
        ));
        processed_any
    }

    // ToDo: This is actually replaced by the socket_egress_tcp, remove when sure.
    fn socket_egress(&mut self) -> Result<bool> {
//        let Self {
//            device,
//            inner,
//            sockets,
//            ..
//        } = self;
        let sockets = &mut self.sockets;
        let_mut_field!(self.device,
        let_mut_field!(self.inner,
            let _caps = device.capabilities();

            let mut emitted_any = false;
            for item in sockets.iter_mut() {
                if !item
                    .meta
                    .egress_permitted(inner.now, |ip_addr| inner.has_neighbor(&ip_addr))
                {
                    continue;
                }

                let mut neighbor_addr = None;
                let mut device_result = Ok(());

               macro_rules! respond {
                   ($inner:expr, $response:expr) => {{
                       let response = $response;
                       neighbor_addr = Some(response.ip_repr().dst_addr());
                       let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                       device_result = $inner.dispatch_ip(tx_token, response);
                       device_result
                   }};
               }

               let socket_result = match &mut item.socket {
                   #[cfg(feature = "socket-raw")]
                   Socket::Raw(socket) => socket.dispatch(inner, |inner, response| {
                       respond!(inner, IpPacket::Raw(response))
                   }),
                   #[cfg(feature = "socket-icmp")]
                   Socket::Icmp(socket) => socket.dispatch(inner, |inner, response| match response {
                       #[cfg(feature = "proto-ipv4")]
                       (IpRepr::Ipv4(ipv4_repr), IcmpRepr::Ipv4(icmpv4_repr)) => {
                           respond!(inner, IpPacket::Icmpv4((ipv4_repr, icmpv4_repr)))
                       }
                       #[cfg(feature = "proto-ipv6")]
                       (IpRepr::Ipv6(ipv6_repr), IcmpRepr::Ipv6(icmpv6_repr)) => {
                           respond!(inner, IpPacket::Icmpv6((ipv6_repr, icmpv6_repr)))
                       }
                       _ => Err(Error::Unaddressable),
                   }),
                   #[cfg(feature = "socket-udp")]
                   Socket::Udp(socket) => socket.dispatch(inner, |inner, response| {
                       respond!(inner, IpPacket::Udp(response))
                   }),
                   #[cfg(feature = "socket-tcp")]
                   Socket::Tcp(socket) => socket.dispatch(inner, |inner, response| {
                       respond!(inner, IpPacket::Tcp(response))
                   }),

                   #[cfg(feature = "ohua")]
                   Socket::OhuaTcp(socket) => socket.dispatch(inner, |inner, response| {
                       respond!(inner, IpPacket::Tcp(response))
                   }),
                   #[cfg(feature = "socket-dhcpv4")]
                   Socket::Dhcpv4(socket) => socket.dispatch(inner, |inner, response| {
                       respond!(inner, IpPacket::Dhcpv4(response))
                   }),
               };

               match (device_result, socket_result) {
                   (Err(Error::Exhausted), _) => break,   // nowhere to transmit
                   (Ok(()), Err(Error::Exhausted)) => (), // nothing to transmit
                   (Err(Error::Unaddressable), _) => {
                       // `NeighborCache` already takes care of rate limiting the neighbor discovery
                       // requests from the socket. However, without an additional rate limiting
                       // mechanism, we would spin on every socket that has yet to discover its
                       // neighboor.
                       item.meta.neighbor_missing(
                           inner.now,
                           neighbor_addr.expect("non-IP response packet"),
                       );
                       break;
                   }
                   (Err(err), _) | (_, Err(err)) => {
                       net_debug!(
                           "{}: cannot dispatch egress packet: {}",
                           item.meta.handle,
                           err
                       );
                       return Err(err);
                   }
                   (Ok(()), Ok(())) => emitted_any = true,
               }
            };
            Ok(emitted_any)
        )
        )
    }

    #[cfg(feature = "ohua")]
    #[allow(dead_code)]
    fn socket_egress_tcp(& mut self) -> Result<bool> {
       let sockets = &mut self.sockets;

        let mut emitted_any = false;
        for handle in 0..sockets.size() {
           match sockets.remove_item(handle) {

                None => (), // Can't take out a none.
                Some(mut socket_item) => {
                    // steal/borrow
                    let inner = self.inner.take().unwrap();
                    let device = self.device.take().unwrap();

                    if socket_item
                        .meta
                        .egress_permitted(inner.now, |ip_addr| inner.has_neighbor(&ip_addr))
                    {
                        match socket_item.socket {
                            #[cfg(feature = "socket-tcp")]
                            Socket::OhuaTcp(tcp_socket) => {

                                let (innerp, devicep, metap, socketp, res) =
                                    pre_send_post_recursion(inner, device, socket_item.meta, Call::Pre(device_independent_emit), tcp_socket);

                                // return what we have stolen/borrowed
                                sockets.insert(
                                    handle,
                                    Item {
                                        meta: metap,
                                        socket: Socket::OhuaTcp(socketp),
                                    });
                                let x = self.device.replace(devicep);
                                assert_none!(x);
                                let y = self.inner.replace(innerp);
                                assert_none!(y);
                                match res {
                                    Ok((emitted, true)) => {
                                        emitted_any = emitted_any || emitted;
                                    }
                                    Ok((_, false)) => {
                                        break;
                                    }
                                    Err(err) => {
                                        // FIXME what about the state changes?!
                                        return Err(err);
                                    }
                                }
                            }
                            _ => panic!("Only TCP sockets supported!"),
                        }
                    }
                    else {
                        // return what we have stolen/borrowed
                        let x = self.device.replace(device);
                        assert_none!(x);
                        let y = self.inner.replace(inner);
                        assert_none!(y);
                    }
                }
            }
        }
       Ok(emitted_any)
    }
}

#[cfg(feature = "ohua")]
fn pre_send_post_recursion<'a, DeviceT>(
    mut inner: OInterfaceInner<'a>,
    mut device: DeviceT,
    mut meta: Meta, // meta data external to the socket impl.(neighbor_cache)
    d: Call,
    mut socket: OhuaTcpSocket,
) -> (OInterfaceInner<'a>, DeviceT, Meta, OhuaTcpSocket<'a>, Result<(bool, bool)>)
where
    DeviceT: for<'d> Device<'d>,
{
    let res = socket.dispatch_c(&mut inner, d);
    match res {
        Results::Pre(pre_result) => match pre_result {
            Ok((data, (tcp_repr_p, ip_repr, is_keep_alive))) => {
                let neighbor_addr = Some(ip_repr.dst_addr());
                match send_to_device(&inner, &mut device, data) {
                    Ok(()) => pre_send_post_recursion(
                        inner,
                        device,
                        meta,
                        Call::Post(tcp_repr_p, is_keep_alive),
                        socket,
                    ),
                    Err(Error::Exhausted) => (inner, device, meta, socket,
                        Ok((false, false))), // nowhere to transmit
                    Err(Error::Unaddressable) => {
                        // `NeighborCache` already takes care of rate limiting the neighbor discovery
                        // requests from the socket. However, without an additional rate limiting
                        // mechanism, we would spin on every socket that has yet to discover its
                        // neighboor.
                        meta.neighbor_missing(
                            inner.now,
                            neighbor_addr.expect("non-IP response packet"),
                        );
                        (inner, device, meta, socket, Ok((false, false)))
                    }
                    Err(err) => {
                        net_debug!("{}: cannot dispatch egress packet: {}", meta.handle, err);
                        (inner, device, meta, socket,
                         Err(err))
                    }
                }
            }
            Err(Error::Exhausted) => (inner, device, meta, socket,
                 Ok((false, true))), // nothing to transmit
            Err(err) => {
                net_debug!("{}: cannot dispatch egress packet: {}", meta.handle, err);
                (inner, device, meta, socket,
                 Err(err))
            }
        },
        Results::Post =>
                (inner, device, meta, socket,
            Ok((true, true))), // emitted_any = true
    }
}

#[cfg(feature = "ohua")]
fn device_independent_emit<'a,'b,'c>(
    inner: &'a mut  OInterfaceInner<'b>,
    reprs: (IpRepr, TcpRepr<'c>),
) -> Result<Vec<u8>>
{
    let as_packet = IpPacket::Tcp(reprs);

    let mut device = OhuaSocket::new();

    // error handling in the original code seems broken here:
    // this is part of socked_result
    let tx_token = device.transmit().ok_or(Error::Exhausted)?;

    // TODO dispatch_ip just returns the result of the consume call.
    // need to make sure that we do not swallow this here..
    // REMINDER: So actually it would be let
    inner.dispatch_ip(tx_token, as_packet)?;


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
    inner: &'a OInterfaceInner<'a>,
    tcp_socket: &'a mut OhuaTcpSocket<'a>,
) -> Result<(Vec<u8>, bool)> {
    let (ip_repr, tcp_repr, b) = tcp_socket.dispatch_before(
        inner)?;

    let response = IpPacket::Tcp((ip_repr, tcp_repr));

    let device = OhuaSocket::new();

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

/// This is in the end not at all a function on the socket but
/// only on the device and the IP layer.
#[cfg(feature = "ohua")]
fn send_to_device<'a, DeviceT: for<'d> Device<'d>>(
    inner: &'a OInterfaceInner<'a>,
    device: &mut DeviceT,
    data: Vec<u8>
) -> Result<()>
{
    // get the token which holds the reference to the device
    let tx_token = device.transmit().ok_or(Error::Exhausted)?;
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
    inner: &'a OInterfaceInner<'a>,
    tcp_socket: &'a mut OhuaTcpSocket<'a>,
    result: (TcpRepr<'a>, bool),
) -> () {
    tcp_socket.dispatch_after(inner, result)
}
*/

impl<'a> OInterfaceInner<'a> {
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn now(&self) -> Instant {
        self.now
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn hardware_addr(&self) -> Option<HardwareAddress> {
        self.hardware_addr
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn checksum_caps(&self) -> ChecksumCapabilities {
        self.caps.checksum.clone()
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn ip_mtu(&self) -> usize {
        self.caps.ip_mtu()
    }

    #[allow(unused)] // unused depending on which sockets are enabled, and in tests
    pub(crate) fn rand(&mut self) -> &mut Rand {
        &mut self.rand
    }

    #[cfg(test)]
    pub(crate) fn mock() -> Self {
        Self {
            caps: DeviceCapabilities {
                #[cfg(feature = "medium-ethernet")]
                medium: crate::phy::Medium::Ethernet,
                #[cfg(not(feature = "medium-ethernet"))]
                medium: crate::phy::Medium::Ip,
                checksum: crate::phy::ChecksumCapabilities {
                    #[cfg(feature = "proto-ipv4")]
                    icmpv4: crate::phy::Checksum::Both,
                    #[cfg(feature = "proto-ipv6")]
                    icmpv6: crate::phy::Checksum::Both,
                    ipv4: crate::phy::Checksum::Both,
                    tcp: crate::phy::Checksum::Both,
                    udp: crate::phy::Checksum::Both,
                },
                max_burst_size: None,
                #[cfg(feature = "medium-ethernet")]
                max_transmission_unit: 1514,
                #[cfg(not(feature = "medium-ethernet"))]
                max_transmission_unit: 1500,
            },
            now: Instant::from_millis_const(0),

            ip_addrs: ManagedSlice::Owned(vec![]),
            rand: Rand::new(1234),
            routes: Routes::new(&mut [][..]),

            #[cfg(feature = "proto-ipv4")]
            any_ip: false,

            #[cfg(feature = "medium-ieee802154")]
            pan_id: Some(crate::wire::Ieee802154Pan(0xabcd)),
            #[cfg(feature = "medium-ieee802154")]
            sequence_no: 0,

            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            hardware_addr: Some(crate::wire::HardwareAddress::Ethernet(
                crate::wire::EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]),
            )),
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            neighbor_cache: None,

            #[cfg(feature = "proto-igmp")]
            igmp_report_state: IgmpReportState::Inactive,
            #[cfg(feature = "proto-igmp")]
            ipv4_multicast_groups: ManagedMap::Borrowed(&mut []),
        }
    }

    #[cfg(test)]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn set_now(&mut self, now: Instant) {
        self.now = now
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn check_hardware_addr(addr: &HardwareAddress) {
        if !addr.is_unicast() {
            panic!("Ethernet address {} is not unicast", addr)
        }
    }

    fn check_ip_addrs(addrs: &[IpCidr]) {
        for cidr in addrs {
            if !cidr.address().is_unicast() && !cidr.address().is_unspecified() {
                panic!("IP address {} is not unicast", cidr.address())
            }
        }
    }

    #[cfg(feature = "medium-ieee802154")]
    fn get_sequence_number(&mut self) -> u8 {
        let no = self.sequence_no;
        self.sequence_no = self.sequence_no.wrapping_add(1);
        no
    }

    /// Determine if the given `Ipv6Address` is the solicited node
    /// multicast address for a IPv6 addresses assigned to the interface.
    /// See [RFC 4291 § 2.7.1] for more details.
    ///
    /// [RFC 4291 § 2.7.1]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    #[cfg(feature = "proto-ipv6")]
    pub fn has_solicited_node(&self, addr: Ipv6Address) -> bool {
        self.ip_addrs.iter().any(|cidr| {
            match *cidr {
                IpCidr::Ipv6(cidr) if cidr.address() != Ipv6Address::LOOPBACK => {
                    // Take the lower order 24 bits of the IPv6 address and
                    // append those bits to FF02:0:0:0:0:1:FF00::/104.
                    addr.as_bytes()[14..] == cidr.address().as_bytes()[14..]
                }
                _ => false,
            }
        })
    }

    /// Check whether the interface has the given IP address assigned.
    fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    /// Get the first IPv4 address of the interface.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_address(&self) -> Option<Ipv4Address> {
        self.ip_addrs
            .iter()
            .filter_map(|addr| match *addr {
                IpCidr::Ipv4(cidr) => Some(cidr.address()),
                #[cfg(feature = "proto-ipv6")]
                IpCidr::Ipv6(_) => None,
            })
            .next()
    }

    /// Check whether the interface listens to given destination multicast IP address.
    ///
    /// If built without feature `proto-igmp` this function will
    /// always return `false`.
    pub fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(key) => {
                key == Ipv4Address::MULTICAST_ALL_SYSTEMS
                    || self.ipv4_multicast_groups.get(&key).is_some()
            }
            _ => false,
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn process_ethernet<'frame, T: AsRef<[u8]>>(
        &mut self,
        sockets: &mut SocketSet,
        frame: &'frame T,
    ) -> Result<Option<EthernetPacket<'frame>>> {
        let eth_frame = EthernetFrame::new_checked(frame)?;

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && HardwareAddress::Ethernet(eth_frame.dst_addr()) != self.hardware_addr.unwrap()
        {
            return Ok(None);
        }

        match eth_frame.ethertype() {
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Arp => self.process_arp(self.now, &eth_frame),
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;
                self.process_ipv4(sockets, &ipv4_packet)
                    .map(|o| o.map(EthernetPacket::Ip))
            }
            #[cfg(feature = "proto-ipv6")]
            EthernetProtocol::Ipv6 => {
                let ipv6_packet = Ipv6Packet::new_checked(eth_frame.payload())?;
                self.process_ipv6(sockets, &ipv6_packet)
                    .map(|o| o.map(EthernetPacket::Ip))
            }
            // Drop all other traffic.
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(feature = "medium-ip")]
    fn process_ip<'frame, T: AsRef<[u8]>>(
        &mut self,
        sockets: &mut SocketSet,
        ip_payload: &'frame T,
    ) -> Result<Option<IpPacket<'frame>>> {
        match IpVersion::of_packet(ip_payload.as_ref()) {
            #[cfg(feature = "proto-ipv4")]
            Ok(IpVersion::Ipv4) => {
                let ipv4_packet = Ipv4Packet::new_checked(ip_payload)?;
                self.process_ipv4(sockets, &ipv4_packet)
            }
            #[cfg(feature = "proto-ipv6")]
            Ok(IpVersion::Ipv6) => {
                let ipv6_packet = Ipv6Packet::new_checked(ip_payload)?;
                self.process_ipv6(sockets, &ipv6_packet)
            }
            // Drop all other traffic.
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(feature = "medium-ieee802154")]
    fn process_ieee802154<'frame, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        sixlowpan_payload: &'frame T,
    ) -> Result<Option<IpPacket<'frame>>> {
        let ieee802154_frame = Ieee802154Frame::new_checked(sixlowpan_payload)?;
        let ieee802154_repr = Ieee802154Repr::parse(&ieee802154_frame)?;

        if ieee802154_repr.frame_type != Ieee802154FrameType::Data {
            return Ok(None);
        }

        // Drop frames when the user has set a PAN id and the PAN id from frame is not equal to this
        // When the user didn't set a PAN id (so it is None), then we accept all PAN id's.
        // We always accept the broadcast PAN id.
        if self.pan_id.is_some()
            && ieee802154_repr.dst_pan_id != self.pan_id
            && ieee802154_repr.dst_pan_id != Some(Ieee802154Pan::BROADCAST)
        {
            net_debug!(
                "dropping {:?} because not our PAN id (or not broadcast)",
                ieee802154_repr
            );
            return Ok(None);
        }

        match ieee802154_frame.payload() {
            Some(payload) => self.process_sixlowpan(sockets, &ieee802154_repr, payload),
            None => Ok(None),
        }
    }

    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
    fn process_arp<'frame, T: AsRef<[u8]>>(
        &mut self,
        timestamp: Instant,
        eth_frame: &EthernetFrame<&'frame T>,
    ) -> Result<Option<EthernetPacket<'frame>>> {
        let arp_packet = ArpPacket::new_checked(eth_frame.payload())?;
        let arp_repr = ArpRepr::parse(&arp_packet)?;

        match arp_repr {
            ArpRepr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_protocol_addr,
                ..
            } => {
                // Only process ARP packets for us.
                if !self.has_ip_addr(target_protocol_addr) {
                    return Ok(None);
                }

                // Only process REQUEST and RESPONSE.
                if let ArpOperation::Unknown(_) = operation {
                    net_debug!("arp: unknown operation code");
                    return Err(Error::Malformed);
                }

                // Discard packets with non-unicast source addresses.
                if !source_protocol_addr.is_unicast() || !source_hardware_addr.is_unicast() {
                    net_debug!("arp: non-unicast source address");
                    return Err(Error::Malformed);
                }

                if !self.in_same_network(&IpAddress::Ipv4(source_protocol_addr)) {
                    net_debug!("arp: source IP address not in same network as us");
                    return Err(Error::Malformed);
                }

                // Fill the ARP cache from any ARP packet aimed at us (both request or response).
                // We fill from requests too because if someone is requesting our address they
                // are probably going to talk to us, so we avoid having to request their address
                // when we later reply to them.
                self.neighbor_cache.as_mut().unwrap().fill(
                    source_protocol_addr.into(),
                    source_hardware_addr.into(),
                    timestamp,
                );

                if operation == ArpOperation::Request {
                    let src_hardware_addr = match self.hardware_addr {
                        Some(HardwareAddress::Ethernet(addr)) => addr,
                        _ => unreachable!(),
                    };

                    Ok(Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Reply,
                        source_hardware_addr: src_hardware_addr,
                        source_protocol_addr: target_protocol_addr,
                        target_hardware_addr: source_hardware_addr,
                        target_protocol_addr: source_protocol_addr,
                    })))
                } else {
                    Ok(None)
                }
            }
        }
    }

    #[cfg(feature = "socket-raw")]
    fn raw_socket_filter<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: &IpRepr,
        ip_payload: &'frame [u8],
    ) -> bool {
        let mut handled_by_raw_socket = false;

        // Pass every IP packet to all raw sockets we have registered.
        for raw_socket in sockets
            .iter_mut()
            .filter_map(|i| OhuaRawSocket::downcast(&mut i.socket))
        {
            if !raw_socket.accepts(ip_repr) {
                continue;
            }

            match raw_socket.process(self, ip_repr, ip_payload) {
                // The packet is valid and handled by socket.
                Ok(()) => handled_by_raw_socket = true,
                // The socket buffer is full or the packet was truncated
                Err(Error::Exhausted) | Err(Error::Truncated) => (),
                // Raw sockets don't validate the packets in any way.
                Err(_) => unreachable!(),
            }
        }
        handled_by_raw_socket
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_ipv6<'frame, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        ipv6_packet: &Ipv6Packet<&'frame T>,
    ) -> Result<Option<IpPacket<'frame>>> {
        let ipv6_repr = Ipv6Repr::parse(ipv6_packet)?;

        if !ipv6_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return Err(Error::Malformed);
        }

        let ip_payload = ipv6_packet.payload();

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket = self.raw_socket_filter(sockets, &ipv6_repr.into(), ip_payload);
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        self.process_nxt_hdr(
            sockets,
            ipv6_repr,
            ipv6_repr.next_header,
            handled_by_raw_socket,
            ip_payload,
        )
    }

    /// Given the next header value forward the payload onto the correct process
    /// function.
    #[cfg(feature = "proto-ipv6")]
    fn process_nxt_hdr<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ipv6_repr: Ipv6Repr,
        nxt_hdr: IpProtocol,
        handled_by_raw_socket: bool,
        ip_payload: &'frame [u8],
    ) -> Result<Option<IpPacket<'frame>>> {
        match nxt_hdr {
            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp => self.process_tcp(sockets, ipv6_repr.into(), ip_payload),
            _ => panic!("process_nxt_hdr: Only tcp for now ")
        }
    }

    #[cfg(feature = "proto-ipv4")]
    fn process_ipv4<'frame, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        ipv4_packet: &Ipv4Packet<&'frame T>,
    ) -> Result<Option<IpPacket<'frame>>> {
        let ipv4_repr = Ipv4Repr::parse(ipv4_packet, &self.caps.checksum)?;

        if !self.is_unicast_v4(ipv4_repr.src_addr) {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return Err(Error::Malformed);
        }

        let ip_repr = IpRepr::Ipv4(ipv4_repr);
        let ip_payload = ipv4_packet.payload();

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket = self.raw_socket_filter(sockets, &ip_repr, ip_payload);
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        #[cfg(feature = "socket-dhcpv4")]
        {
            if ipv4_repr.protocol == IpProtocol::Udp  {
                panic!("process_ipv4: We currently only support TCP")
            }
        }

        if !self.has_ip_addr(ipv4_repr.dst_addr)
            && !self.has_multicast_group(ipv4_repr.dst_addr)
            && !self.is_broadcast_v4(ipv4_repr.dst_addr)
        {
            // Ignore IP packets not directed at us, or broadcast, or any of the multicast groups.
            // If AnyIP is enabled, also check if the packet is routed locally.
            if !self.any_ip
                || !ipv4_repr.dst_addr.is_unicast()
                || self
                    .routes
                    .lookup(&IpAddress::Ipv4(ipv4_repr.dst_addr), self.now)
                    .map_or(true, |router_addr| !self.has_ip_addr(router_addr))
            {
                return Ok(None);
            }
        }

        match ipv4_repr.protocol {
            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp => self.process_tcp(sockets, ip_repr, ip_payload),
            _ => panic!("process_ipv4: We currently only support TCP")
        }
    }

    /// Checks if an incoming packet has a broadcast address for the interfaces
    /// associated ipv4 addresses.
    #[cfg(feature = "proto-ipv4")]
    fn is_subnet_broadcast(&self, address: Ipv4Address) -> bool {
        self.ip_addrs
            .iter()
            .filter_map(|own_cidr| match own_cidr {
                IpCidr::Ipv4(own_ip) => Some(own_ip.broadcast()?),
                #[cfg(feature = "proto-ipv6")]
                IpCidr::Ipv6(_) => None,
            })
            .any(|broadcast_address| address == broadcast_address)
    }

    /// Checks if an ipv4 address is broadcast, taking into account subnet broadcast addresses
    #[cfg(feature = "proto-ipv4")]
    fn is_broadcast_v4(&self, address: Ipv4Address) -> bool {
        address.is_broadcast() || self.is_subnet_broadcast(address)
    }

    /// Checks if an ipv4 address is unicast, taking into account subnet broadcast addresses
    #[cfg(feature = "proto-ipv4")]
    fn is_unicast_v4(&self, address: Ipv4Address) -> bool {
        address.is_unicast() && !self.is_subnet_broadcast(address)
    }

    /// Host duties of the **IGMPv2** protocol.
    ///
    /// Sets up `igmp_report_state` for responding to IGMP general/specific membership queries.
    /// Membership must not be reported immediately in order to avoid flooding the network
    /// after a query is broadcasted by a router; this is not currently done.


    #[cfg(all(
        any(feature = "medium-ethernet", feature = "medium-ieee802154"),
        feature = "proto-ipv6"
    ))]
    fn process_ndisc<'frame>(
        &mut self,
        ip_repr: Ipv6Repr,
        repr: NdiscRepr<'frame>,
    ) -> Result<Option<IpPacket<'frame>>> {
        match repr {
            NdiscRepr::NeighborAdvert {
                lladdr,
                target_addr,
                flags,
            } => {
                let ip_addr = ip_repr.src_addr.into();
                if let Some(lladdr) = lladdr {
                    let lladdr = lladdr.parse(self.caps.medium)?;
                    if !lladdr.is_unicast() || !target_addr.is_unicast() {
                        return Err(Error::Malformed);
                    }
                    if flags.contains(NdiscNeighborFlags::OVERRIDE)
                        || !self
                            .neighbor_cache
                            .as_mut()
                            .unwrap()
                            .lookup(&ip_addr, self.now)
                            .found()
                    {
                        self.neighbor_cache
                            .as_mut()
                            .unwrap()
                            .fill(ip_addr, lladdr, self.now)
                    }
                }
                Ok(None)
            }
            NdiscRepr::NeighborSolicit {
                target_addr,
                lladdr,
                ..
            } => {
                if let Some(lladdr) = lladdr {
                    let lladdr = lladdr.parse(self.caps.medium)?;
                    if !lladdr.is_unicast() || !target_addr.is_unicast() {
                        return Err(Error::Malformed);
                    }
                    self.neighbor_cache.as_mut().unwrap().fill(
                        ip_repr.src_addr.into(),
                        lladdr,
                        self.now,
                    );
                }

                if self.has_solicited_node(ip_repr.dst_addr) && self.has_ip_addr(target_addr) {
                    let advert = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                        flags: NdiscNeighborFlags::SOLICITED,
                        target_addr,
                        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                        lladdr: Some(self.hardware_addr.unwrap().into()),
                    });
                    let ip_repr = Ipv6Repr {
                        src_addr: target_addr,
                        dst_addr: ip_repr.src_addr,
                        next_header: IpProtocol::Icmpv6,
                        hop_limit: 0xff,
                        payload_len: advert.buffer_len(),
                    };
                    Ok(Some(IpPacket::Icmpv6((ip_repr, advert))))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_hopbyhop<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ipv6_repr: Ipv6Repr,
        handled_by_raw_socket: bool,
        ip_payload: &'frame [u8],
    ) -> Result<Option<IpPacket<'frame>>> {
        let hbh_pkt = Ipv6HopByHopHeader::new_checked(ip_payload)?;
        let hbh_repr = Ipv6HopByHopRepr::parse(&hbh_pkt)?;
        for result in hbh_repr.options() {
            let opt_repr = result?;
            match opt_repr {
                Ipv6OptionRepr::Pad1 | Ipv6OptionRepr::PadN(_) => (),
                Ipv6OptionRepr::Unknown { type_, .. } => {
                    match Ipv6OptionFailureType::from(type_) {
                        Ipv6OptionFailureType::Skip => (),
                        Ipv6OptionFailureType::Discard => {
                            return Ok(None);
                        }
                        _ => {
                            // FIXME(dlrobertson): Send an ICMPv6 parameter problem message
                            // here.
                            return Err(Error::Unrecognized);
                        }
                    }
                }
            }
        }
        self.process_nxt_hdr(
            sockets,
            ipv6_repr,
            hbh_repr.next_header,
            handled_by_raw_socket,
            &ip_payload[hbh_repr.buffer_len()..],
        )
    }


    #[cfg(feature = "socket-tcp")]
    fn process_tcp<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Result<Option<IpPacket<'frame>>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = TcpPacket::new_checked(ip_payload)?;
        let tcp_repr = TcpRepr::parse(&tcp_packet, &src_addr, &dst_addr, &self.caps.checksum)?;

        for tcp_socket in sockets
            .iter_mut()
            .filter_map(|i| OhuaTcpSocket::downcast(&mut i.socket))
        {
            if !tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                continue;
            }

            match tcp_socket.process(self, &ip_repr, &tcp_repr) {
                // The packet is valid and handled by socket.
                Ok(reply) => return Ok(reply.map(IpPacket::Tcp)),
                // The packet is malformed, or doesn't match the socket state,
                // or the socket buffer is full.
                Err(e) => return Err(e),
            }
        }

        if tcp_repr.control == TcpControl::Rst {
            // Never reply to a TCP RST packet with another TCP RST packet.
            Ok(None)
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            Ok(Some(IpPacket::Tcp(TcpSocket::rst_reply(
                &ip_repr, &tcp_repr,
            ))))
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn dispatch<Tx>(&mut self, tx_token: Tx, packet: EthernetPacket) -> Result<()>
    where
        Tx: TxToken,
    {
        match packet {
            #[cfg(feature = "proto-ipv4")]
            EthernetPacket::Arp(arp_repr) => {
                let dst_hardware_addr = match arp_repr {
                    ArpRepr::EthernetIpv4 {
                        target_hardware_addr,
                        ..
                    } => target_hardware_addr,
                };

                self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                })
            }
            EthernetPacket::Ip(packet) => self.dispatch_ip(tx_token, packet),
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn dispatch_ethernet<Tx, F>(&self, tx_token: Tx, buffer_len: usize, f: F) -> Result<()>
    where
        Tx: TxToken,
        F: FnOnce(EthernetFrame<&mut [u8]>),
    {
        let tx_len = EthernetFrame::<&[u8]>::buffer_len(buffer_len);
        tx_token.consume(self.now, tx_len, |tx_buffer| {
            debug_assert!(tx_buffer.as_ref().len() == tx_len);
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = if let Some(HardwareAddress::Ethernet(addr)) = self.hardware_addr {
                addr
            } else {
                return Err(Error::Malformed);
            };

            frame.set_src_addr(src_addr);

            f(frame);

            Ok(())
        })
    }

    fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.ip_addrs.iter().any(|cidr| cidr.contains_addr(addr))
    }

    fn route(&self, addr: &IpAddress, timestamp: Instant) -> Result<IpAddress> {
        // Send directly.
        if self.in_same_network(addr) || addr.is_broadcast() {
            return Ok(*addr);
        }

        // Route via a router.
        match self.routes.lookup(addr, timestamp) {
            Some(router_addr) => Ok(router_addr),
            None => Err(Error::Unaddressable),
        }
    }

    fn has_neighbor(&self, addr: &IpAddress) -> bool {
        match self.route(addr, self.now) {
            Ok(_routed_addr) => match self.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => self
                    .neighbor_cache
                    .as_ref()
                    .unwrap()
                    .lookup(&_routed_addr, self.now)
                    .found(),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => self
                    .neighbor_cache
                    .as_ref()
                    .unwrap()
                    .lookup(&_routed_addr, self.now)
                    .found(),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => true,
            },
            Err(_) => false,
        }
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn lookup_hardware_addr<Tx>(
        &mut self,
        tx_token: Tx,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
    ) -> Result<(HardwareAddress, Tx)>
    where
        Tx: TxToken,
    {
        net_debug!("lookup");
        if dst_addr.is_broadcast() {
            net_debug!("found broadcast");
            let hardware_addr = match self.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::BROADCAST),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => unreachable!(),
            };

            return Ok((hardware_addr, tx_token));
        }

        if dst_addr.is_multicast() {
            let b = dst_addr.as_bytes();
            let hardware_addr = match *dst_addr {
                IpAddress::Unspecified => unreachable!(),
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(_addr) => {
                    HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
                        0x01,
                        0x00,
                        0x5e,
                        b[1] & 0x7F,
                        b[2],
                        b[3],
                    ]))
                }
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(_addr) => match self.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
                        0x33, 0x33, b[12], b[13], b[14], b[15],
                    ])),
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => {
                        // Not sure if this is correct
                        HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST)
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => unreachable!(),
                },
            };

            return Ok((hardware_addr, tx_token));
        }

        let dst_addr = self.route(dst_addr, self.now)?;

        match self
            .neighbor_cache
            .as_mut()
            .unwrap()
            .lookup(&dst_addr, self.now)
        {
            NeighborAnswer::Found(hardware_addr) => return Ok((hardware_addr, tx_token)),
            NeighborAnswer::RateLimited => return Err(Error::Unaddressable),
            _ => (), // XXX
        }

        match (src_addr, dst_addr) {
            #[cfg(feature = "proto-ipv4")]
            (&IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr)) => {
                net_debug!(
                    "address {} not in neighbor cache, sending ARP request",
                    dst_addr
                );
                let src_hardware_addr =
                    if let Some(HardwareAddress::Ethernet(addr)) = self.hardware_addr {
                        addr
                    } else {
                        return Err(Error::Malformed);
                    };

                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    source_hardware_addr: src_hardware_addr,
                    source_protocol_addr: src_addr,
                    target_hardware_addr: EthernetAddress::BROADCAST,
                    target_protocol_addr: dst_addr,
                };

                self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(EthernetAddress::BROADCAST);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    arp_repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()))
                })?;
            }

            #[cfg(feature = "proto-ipv6")]
            (&IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => {
                net_debug!(
                    "address {} not in neighbor cache, sending Neighbor Solicitation",
                    dst_addr
                );

                let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
                    target_addr: dst_addr,
                    lladdr: Some(self.hardware_addr.unwrap().into()),
                });

                let packet = IpPacket::Icmpv6((
                    Ipv6Repr {
                        src_addr,
                        dst_addr: dst_addr.solicited_node(),
                        next_header: IpProtocol::Icmpv6,
                        payload_len: solicit.buffer_len(),
                        hop_limit: 0xff,
                    },
                    solicit,
                ));

                self.dispatch_ip(tx_token, packet)?;
            }

            _ => (),
        }
        // The request got dispatched, limit the rate on the cache.
        self.neighbor_cache.as_mut().unwrap().limit_rate(self.now);
        Err(Error::Unaddressable)
    }

    fn flush_cache(&mut self) {
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        if let Some(cache) = self.neighbor_cache.as_mut() {
            cache.flush()
        }
    }

    fn dispatch_ip<Tx: TxToken>(&mut self, tx_token: Tx, packet: IpPacket) -> Result<()> {
        let ip_repr = packet.ip_repr().lower(&self.ip_addrs)?;

        match self.caps.medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => {
                net_debug!("looking up HW addr ...");
                let (dst_hardware_addr, tx_token) = match self.lookup_hardware_addr(
                    tx_token,
                    &ip_repr.src_addr(),
                    &ip_repr.dst_addr(),
                )? {
                    (HardwareAddress::Ethernet(addr), tx_token) => (addr, tx_token),
                    #[cfg(feature = "medium-ieee802154")]
                    (HardwareAddress::Ieee802154(_), _) => unreachable!(),
                };

                net_debug!("Got HW address.");
                let caps = self.caps.clone();
                self.dispatch_ethernet(tx_token, ip_repr.total_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    match ip_repr {
                        #[cfg(feature = "proto-ipv4")]
                        IpRepr::Ipv4(_) => frame.set_ethertype(EthernetProtocol::Ipv4),
                        #[cfg(feature = "proto-ipv6")]
                        IpRepr::Ipv6(_) => frame.set_ethertype(EthernetProtocol::Ipv6),
                        _ => return,
                    }

                    ip_repr.emit(frame.payload_mut(), &caps.checksum);

                    let payload = &mut frame.payload_mut()[ip_repr.buffer_len()..];
                    packet.emit_payload(ip_repr, payload, &caps);
                })
            }
            #[cfg(feature = "medium-ip")]
            Medium::Ip => {
                let tx_len = ip_repr.total_len();
                tx_token.consume(self.now, tx_len, |mut tx_buffer| {
                    debug_assert!(tx_buffer.as_ref().len() == tx_len);
                    
                    ip_repr.emit(&mut tx_buffer, &self.caps.checksum);

                    let payload = &mut tx_buffer[ip_repr.buffer_len()..];
                    packet.emit_payload(ip_repr, payload, &self.caps);

                    Ok(())
                })
            }
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => self.dispatch_ieee802154(tx_token, packet),
        }
    }



}

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

    #[allow(unused)]
    fn fill_slice(s: &mut [u8], val: u8) {
        for x in s.iter_mut() {
            *x = val
        }
    }

    fn create_loopback<'a>() -> OInterface<'a, Loopback> {
        #[cfg(feature = "medium-ethernet")]
        return create_loopback_ethernet();
        #[cfg(not(feature = "medium-ethernet"))]
        return create_loopback_ip();
    }

    #[cfg(all(feature = "medium-ip"))]
    #[allow(unused)]
    fn create_loopback_ip<'a>() -> OInterface<'a, Loopback> {
        // Create a basic device
        let device = Loopback::new(Medium::Ip);
        let ip_addrs = [
            #[cfg(feature = "proto-ipv4")]
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64),
        ];

        let iface_builder = OInterfaceBuilder::new(device, vec![]).ip_addrs(ip_addrs);
        #[cfg(feature = "proto-igmp")]
        let iface_builder = iface_builder.ipv4_multicast_groups(BTreeMap::new());
        iface_builder.finalize()
    }

    #[cfg(all(feature = "medium-ethernet"))]
    fn create_loopback_ethernet<'a>() -> OInterface<'a, Loopback> {
        // Create a basic device
        let device = Loopback::new(Medium::Ethernet);
        let ip_addrs = [
            #[cfg(feature = "proto-ipv4")]
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64),
        ];

        let iface_builder = OInterfaceBuilder::new(device, vec![])
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(NeighborCache::new(BTreeMap::new()))
            .ip_addrs(ip_addrs);
        #[cfg(feature = "proto-igmp")]
        let iface_builder = iface_builder.ipv4_multicast_groups(BTreeMap::new());
        iface_builder.finalize()
    }

    #[cfg(feature = "proto-igmp")]
    fn recv_all(iface: &mut OInterface<'_, Loopback>, timestamp: Instant) -> Vec<Vec<u8>> {
        let mut pkts = Vec::new();
        while let Some((rx, _tx)) = iface.device_mut().receive() {
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
        OInterfaceBuilder::new(Loopback::new(Medium::Ethernet), vec![]).finalize();
    }


    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_solicited_node_addrs() {
        let mut iface = create_loopback();
        let mut new_addrs = vec![
            IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 1, 2, 0, 2), 64),
            IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 3, 4, 0, 0xffff), 64),
        ];
        iface.update_ip_addrs(|addrs| {
            new_addrs.extend(addrs.to_vec());
            *addrs = From::from(new_addrs);
        });
        assert!(iface
            .inner()
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0002)));
        assert!(iface
            .inner()
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0xffff)));
        assert!(!iface
            .inner()
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0003)));
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-raw"))]
    fn test_raw_socket_no_reply() {
        use crate::socket::{RawPacketMetadata, RawSocket, RawSocketBuffer};
        use crate::wire::{IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

        let mut iface = create_loopback();

        let packets = 1;
        let rx_buffer =
            RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let tx_buffer = RawSocketBuffer::new(
            vec![RawPacketMetadata::EMPTY; packets],
            vec![0; 48 * packets],
        );
        let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Udp, rx_buffer, tx_buffer);
        iface.add_socket(raw_socket);

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
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
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

        let_mut_field!(iface.inner,
        assert_eq!(
            inner.process_ipv4(&mut iface.sockets, &frame),
            Ok(None)
        )
        );
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-raw"))]
    fn test_raw_socket_truncated_packet() {
        use crate::socket::{RawPacketMetadata, RawSocket, RawSocketBuffer};
        use crate::wire::{IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

        let mut iface = create_loopback();

        let packets = 1;
        let rx_buffer =
            RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let tx_buffer = RawSocketBuffer::new(
            vec![RawPacketMetadata::EMPTY; packets],
            vec![0; 48 * packets],
        );
        let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Udp, rx_buffer, tx_buffer);
        iface.add_socket(raw_socket);

        let src_addr = Ipv4Address([127, 0, 0, 2]);
        let dst_addr = Ipv4Address([127, 0, 0, 1]);

        const PAYLOAD_LEN: usize = 49; // 49 > 48, hence packet will be truncated

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
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
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
        
        let frame = let_mut_field!(iface.inner,
            inner.process_ipv4(&mut iface.sockets, &frame)
        );

        // because the packet could not be handled we should send an Icmp message
        assert!(match frame {
            Ok(Some(IpPacket::Icmpv4(_))) => true,
            _ => false,
        });
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-raw", feature = "socket-udp"))]
    fn test_raw_socket_with_udp_socket() {
        use crate::socket::{
            RawPacketMetadata, RawSocket, RawSocketBuffer, UdpPacketMetadata, UdpSocket,
            UdpSocketBuffer,
        };
        use crate::wire::{IpEndpoint, IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

        static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

        let mut iface = create_loopback();

        let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);
        let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);
        let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);
        let udp_socket_handle = iface.add_socket(udp_socket);

        // Bind the socket to port 68
        let socket = iface.get_socket::<UdpSocket>(udp_socket_handle);
        assert_eq!(socket.bind(68), Ok(()));
        assert!(!socket.can_recv());
        assert!(socket.can_send());

        let packets = 1;
        let raw_rx_buffer =
            RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let raw_tx_buffer = RawSocketBuffer::new(
            vec![RawPacketMetadata::EMPTY; packets],
            vec![0; 48 * packets],
        );
        let raw_socket = RawSocket::new(
            IpVersion::Ipv4,
            IpProtocol::Udp,
            raw_rx_buffer,
            raw_tx_buffer,
        );
        iface.add_socket(raw_socket);

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
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
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

        let_mut_field!(iface.inner,
        assert_eq!(
            inner.process_ipv4(&mut iface.sockets, &frame),
            Ok(None)
        )
        );

        // Make sure the UDP socket can still receive in presence of a Raw socket that handles UDP
        let socket = iface.get_socket::<UdpSocket>(udp_socket_handle);
        assert!(socket.can_recv());
        assert_eq!(
            socket.recv(),
            Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_addr.into(), 67)))
        );
    }

   #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-tcp", feature = "ohua"))]
    fn test_tcp_socket_egress() {
        use crate::socket::Socket;
        use crate::socket::tcp_ohua::test::{
            socket_established_with_endpoints, TestSocket};
        use crate::wire::{IpEndpoint, Ipv4Address, IpAddress};

        //SmolTCP
        let mut iface1 = create_loopback_ip();

        let TestSocket{socket, cx} =
            socket_established_with_endpoints(
                // I could not enforce proto-ipv4
                IpEndpoint{
                    addr: IpAddress::Ipv4(Ipv4Address([192, 168, 1, 1])),
                    port: 80
                },
                IpEndpoint {
                    addr: IpAddress::Ipv4(Ipv4Address::BROADCAST),
                    port: 49500} );

        iface1.inner = Some(cx);
        // Devices sending buffer should be empty
        if let Some(ref device_ref) = iface1.device {
            assert!(device_ref.empty_tx());
        }
        let tcp_socket_handle1 = iface1.add_socket(socket);

        let socket1 = iface1.get_socket::<TcpSocket>(tcp_socket_handle1);
        assert!(!socket1.can_recv());
        assert!(socket1.may_send());
        assert!(socket1.can_send());
        // Sockets sending buffer should be empty before sending
        assert!(socket1.send_queue()==0);


        let msg = "hello".as_bytes();
        let msg_len = msg.len();
        // Enque the message in the sockets sending buffer
        let result_len = socket1.send_slice(msg);
        assert_eq!(result_len, Ok(msg_len));
        net_debug!("running egress");
        assert_eq!(iface1.socket_egress(), Ok(true));
       // Make sure the data arrived at the device level:
        /* socket_egress gets a sending token from the device, passes is through
         socket.dispatch() and (in this case) device.transmi() -> inner_interface.dispatch()->
         innner_interface.dispatch_ip() -> inner_interface.dispatch_ethernet() ->  token.cosume()
         The consume function for Loopback interfaces causes the assembled packet representation
         to be pushed to the devices Tx queue. So that's where we'd expect to see the packet afterwards
         */
        // TODO: I need a function to build the comparison packet (btw. mock packets seem to be needed quite often so ...
        // Devices sending buffer should contain our packet
        if let Some(ref device_ref) = iface1.device {
            assert_eq!(1, device_ref.num_tx_packets());
            net_debug!("one packet in the buffer :-)");
        }


        // OHUA:
        net_debug!("Now the same procedure for Ohua");
        let mut iface2 = create_loopback_ip();
        let TestSocket{socket, cx} =
            socket_established_with_endpoints(
                // I could not enforce proto-ipv4
                IpEndpoint{
                    addr: IpAddress::Ipv4(Ipv4Address([192, 168, 1, 1])),
                    port: 80
                },
                IpEndpoint {
                    addr: IpAddress::Ipv4(Ipv4Address::BROADCAST),
                    port: 49500} );

        iface2.inner = Some(cx);
        // Devices sending buffer should again be empty
        if let Some(ref device_ref) = iface2.device {
            assert!(device_ref.empty_tx());
        }
        let tcp_socket_handle2 = iface2.add_socket(socket);

        let socket2 = iface2.get_socket::<TcpSocket>(tcp_socket_handle2);
        assert!(!socket2.can_recv());
        assert!(socket2.may_send());
        assert!(socket2.can_send());
        // Sockets sending buffer should be empty before sending
        assert!(socket2.send_queue()==0);

        // Enque the message in the sockets sending buffer
        let result_len = socket2.send_slice(msg);
        assert_eq!(result_len, Ok(msg_len));
        net_debug!("running egress with ohua version");
        assert_eq!(iface2.socket_egress_tcp(), Ok(true));

        // Again make sure the data arrived at the device level:
        // Devices sending buffer should contain our packet
        if let Some(ref device_ref) = iface2.device {
            assert_eq!(1, device_ref.num_tx_packets());
            net_debug!("one packet in the buffer :-)");
        }

        // TODO compare the states of both sockets
       let s1 = iface1.get_socket::<TcpSocket>(tcp_socket_handle1).state();
       let s2 = iface2.get_socket::<TcpSocket>(tcp_socket_handle2).state();
       assert_eq!(s1, s2);
        // As it is a loopback we should also be able to receive from it
       iface1.socket_ingress();
    }

}
