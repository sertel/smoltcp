#[cfg(not(feature = "rust-1_28"))]
use alloc::collections::VecDeque;
use alloc::vec::Vec;
#[cfg(feature = "rust-1_28")]
use alloc::VecDeque;

use crate::phy::{self, Device, DeviceCapabilities, Medium};
use crate::time::{Duration, Instant};
use crate::Result;

/// A loopback device.
#[derive(Debug)]
pub struct Loopback {
    queue: VecDeque<Vec<u8>>,
    medium: Medium,
}

#[allow(clippy::new_without_default)]
impl Loopback {
    /// Creates a loopback device.
    ///
    /// Every packet transmitted through this device will be received through it
    /// in FIFO order.
    pub fn new(medium: Medium) -> Loopback {
        Loopback {
            queue: VecDeque::new(),
            medium,
        }
    }
}

impl<'a> Device<'a> for Loopback {
    type RxToken = RxToken;
    type TxToken = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: 65535,
            medium: self.medium,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        self.queue.pop_front().map(move |buffer| {
            let rx = RxToken { buffer };
            let tx = TxToken {
                queue: &mut self.queue,
            };
            (rx, tx)
        })
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            queue: &mut self.queue,
        })
    }

    fn needs_poll(&self, _duration:Option<Duration>) -> bool {
        true
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        f(&mut self.buffer)
    }
}

#[doc(hidden)]
pub struct TxToken<'a> {
    pub(crate) queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let mut buffer = Vec::new();
        buffer.resize(len, 0);
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}



#[cfg(test)]
impl Loopback{
    pub(crate) fn empty_tx(&self) -> bool {
            self.queue.is_empty()
        }
    pub(crate) fn num_tx_packets(&self) -> usize {
        self.queue.len()
    }
    /*
    pub(crate) fn compare_tx(&self, other_txtoken:VecDeque<Vec<u8>>) -> bool {
            self.queue == other_txtoken
        }

     */
}
// A constantly "exhausted" loopback device for testing.
#[derive(Debug)]
pub struct BrokenLoopback {
    queue: VecDeque<Vec<u8>>,
    medium: Medium,
}

#[allow(clippy::new_without_default)]
impl BrokenLoopback {
    pub fn new(medium: Medium) -> BrokenLoopback {
        BrokenLoopback {
            queue: VecDeque::new(),
            medium,
        }
    }
    pub(crate) fn empty_tx(&self) -> bool {
            self.queue.is_empty()
        }
    pub(crate) fn num_tx_packets(&self) -> usize {
        self.queue.len()
    }
}

impl<'a> Device<'a> for BrokenLoopback {
    type RxToken = RxToken;
    type TxToken = TxToken<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        None
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        None
    }

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: 65535,
            medium: self.medium,
            ..DeviceCapabilities::default()
        }
    }
    ///Dummy function to resemble m3 device interface
    fn needs_poll(&self, duration:Option<Duration>) -> bool {
        true
    }

}

