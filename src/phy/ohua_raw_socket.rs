use crate::time::Instant; 
use crate::phy::{self, Device, DeviceCapabilities};
use crate::Result;
use std::rc::Rc;
use std::cell::RefCell;

pub struct OhuaSocket{
  pub data : Rc<RefCell<Option<Vec<u8>>>>
}

pub struct RxToken{}
pub struct TxToken{
  pub data : Rc<RefCell<Option<Vec<u8>>>>
}


impl OhuaSocket {
    pub fn new() -> Self {
        OhuaSocket{ data: Rc::new(RefCell::new(None)) }
    }
}

impl<'a> Device<'a> for OhuaSocket {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        unimplemented!()
    }

    // Receive is happening immediately.
    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        // TODO it is not clear to me whether that is actually needed.
        unimplemented!()
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken{ data: self.data.clone() })
    }
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, _timestamp: Instant, _f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        // unclear whether we actually need this side!
        unimplemented!()
    }
}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        // TODO just reuse the buffer.
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        match self.data.borrow_mut().replace(buffer) {
            None => (),
            _ => panic!("There was another value in the buffer.")
        }
        result // we need to return the result here already. the code around needs to take care of it.
    }
}
