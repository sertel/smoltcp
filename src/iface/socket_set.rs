use core::fmt;
use managed::ManagedSlice;

use super::socket_meta::Meta;
use crate::socket::{AnySocket, Socket};

/// Opaque struct with space for storing one socket.
///
/// This is public so you can use it to allocate space for storing
/// sockets when creating an Interface.
#[derive(Debug, Default)]
pub struct SocketStorage<'s> {
    inner: Option<Item<'s>>,
}

impl<'s> SocketStorage<'s> {
    pub const EMPTY: Self = Self { inner: None };
}

// REMINDER: Make Item and Meta pub(crate) again when possible
/// An item of a socket set.
#[derive(Debug)]
pub struct Item<'s> {
    pub meta: Meta,
    pub(crate) socket: Socket<'s>,
}

/// A handle, identifying a socket in an Interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SocketHandle(usize);
impl SocketHandle {
    pub(crate) fn as_index(&self) -> usize {
        self.0
    }
    pub(crate) fn from_index(i:usize) -> Self {
        SocketHandle(i)
    }
}
impl fmt::Display for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// An extensible set of sockets.
///
/// The lifetime `'s` is used when storing a `Socket<'s>`.
#[derive(Debug)]
pub struct SocketSet<'s> {
    sockets: ManagedSlice<'s, SocketStorage<'s>>,
}

impl<'s> SocketSet<'s> {
    /// Create a socket set using the provided storage.
    pub fn new<SocketsT>(sockets: SocketsT) -> SocketSet<'s>
    where
        SocketsT: Into<ManagedSlice<'s, SocketStorage<'s>>>,
    {
        let sockets = sockets.into();
        SocketSet { sockets }
    }

    /// Add a socket to the set, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add<T: AnySocket<'s>>(&mut self, socket: T) -> SocketHandle {
        fn put<'s>(index: usize, slot: &mut SocketStorage<'s>, socket: Socket<'s>) -> SocketHandle {
            net_trace!("[{}]: adding", index);
            let handle = SocketHandle(index);
            let mut meta = Meta::default();
            meta.handle = handle;
            *slot = SocketStorage {
                inner: Some(Item { meta, socket }),
            };
            handle
        }

        let socket = socket.upcast();

        for (index, slot) in self.sockets.iter_mut().enumerate() {
            if slot.inner.is_none() {
                return put(index, slot, socket);
            }
        }

        match self.sockets {
            ManagedSlice::Borrowed(_) => panic!("adding a socket to a full SocketSet"),
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(ref mut sockets) => {
                sockets.push(SocketStorage { inner: None });
                let index = sockets.len() - 1;
                put(index, &mut sockets[index], socket)
            }
        }
    }

    //Reminder: Remove this method when we don't pass around sockets any more
    pub fn re_add_stolen_socket<T: AnySocket<'s>>(&mut self, socket: T, meta:Meta, handle: usize) -> SocketHandle {
        let put = |index: usize, slot: &mut SocketStorage<'s>, socket: Socket<'s>| {
            net_trace!("[{}]: adding", index);
            *slot = SocketStorage {
                inner: Some(Item { meta, socket }),
            };
            SocketHandle(handle)
        };

        let socket = socket.upcast();

        for (index, slot) in self.sockets.iter_mut().enumerate() {
            if index == handle && slot.inner.is_none() {
                return put(index, slot, socket);
            }
        }

        match self.sockets {
            ManagedSlice::Borrowed(_) => panic!("adding a socket to a full SocketSet"),
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(ref mut sockets) => {
                sockets.push(SocketStorage { inner: None });
                let index = sockets.len() - 1;
                put(index, &mut sockets[index], socket)
            }
        }
    }
    //Reminder : Just like the function above, remove when possible
    pub fn remove_item(&mut self, handle: usize) -> Option<Item<'s>> {
        net_trace!("[{}]: removing item", handle);
        self.sockets[handle].inner.take()
   }

   pub fn get_mut_item(&mut self, handle: usize) -> Option<&mut Item<'s>> {
        self.sockets[handle].inner.as_mut()
   }

    // Reminder: See the last two reminders
    pub fn same(handle:SocketHandle, other:usize) -> bool {
        handle.0 == other
    }
    /// Get a socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get<T: AnySocket<'s>>(&self, handle: SocketHandle) -> &T {
        match self.sockets[handle.0].inner.as_ref() {
            Some(item) => {
                T::downcast(&item.socket).expect("handle refers to a socket of a wrong type")
            }
            None => panic!("handle does not refer to a valid socket"),
        }
    }
    /// Given some item, returns a reference to the next item in the socket set.
    /// If no item is given, the first item  in the set will be referenced
    /// After the last item, the function returns None
    pub fn get_next_item(&mut self, item: Option<Item>) -> Option<Item> {
        match item {
            None => self.sockets[0].inner.take(),
            Some(socket_item) => {
                let index = socket_item.meta.handle.0;
                if index+1 < self.size() {
                    self.sockets[index+1].inner.take()
                } else {
                    return None
                }
            }
        }
    }

    /// Get a mutable socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get_mut<T: AnySocket<'s>>(&mut self, handle: SocketHandle) -> &mut T {
        match self.sockets[handle.0].inner.as_mut() {
            Some(item) => T::downcast_mut(&mut item.socket)
                .expect("handle refers to a socket of a wrong type"),
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove(&mut self, handle: SocketHandle) -> Socket<'s> {
        net_trace!("[{}]: removing", handle.0);
        match self.sockets[handle.0].inner.take() {
            Some(item) => item.socket,
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get an iterator to the inner sockets.
    pub fn iter(&self) -> impl Iterator<Item = (SocketHandle, &Socket<'s>)> {
        self.items().map(|i| (i.meta.handle, &i.socket))
    }

    /// Get a mutable iterator to the inner sockets.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut Socket<'s>)> {
        self.items_mut().map(|i| (i.meta.handle, &mut i.socket))
    }

    /// Iterate every socket in this set.
    pub(crate) fn items(&self) -> impl Iterator<Item = &Item<'s>> + '_ {
        self.sockets.iter().filter_map(|x| x.inner.as_ref())
    }

    /// Iterate every socket in this set.
    pub(crate) fn items_mut(&mut self) -> impl Iterator<Item = &mut Item<'s>> + '_ {
        self.sockets.iter_mut().filter_map(|x| x.inner.as_mut())
    }

    pub(crate) fn size(& self) -> usize {
        self.sockets.len()
    }
}
