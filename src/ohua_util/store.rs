use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct Store {
    data: Arc<HashMap<String, HashMap<String, String>>>,
    // modified_keys: Vec<String>,
}

impl Store {
    //pub fn default() -> Store {
      //  unimplemented!()
    //}

    pub fn update(&mut self, items: Vec<Option<(Message, TcpStream)>>) {
        // -> Vec<(Message, TcpStream)> {
        let elems = Arc::get_mut(&mut self.data).unwrap();

        for item in items {
            match item {
                Some((Message::Read(_), _)) => unreachable!(),
                Some((Message::Write(write_msg), mut stream)) => {
                    elems.insert(write_msg.key, write_msg.value);

                    stream.write_all("OK".as_bytes()).unwrap();
                    // if self.modified_keys.contains(&write_msg.key) {
                    //     Some((Message::Write(write_msg), stream))
                    // } else {
                    //     self.modified_keys.push(write_msg.key.clone());
                    //     self.data.insert(write_msg.key, write_msg.value);
                    //     None
                    // }
                }
                Some((Message::Delete(del_msg), mut stream)) => {
                    elems.remove(&del_msg.key);

                    stream.write_all("OK".as_bytes()).unwrap();
                    // if self.modified_keys.contains(&del_msg.key) {
                    //     Some((Message::Delete(del_msg), stream))
                    // } else {
                    //     self.modified_keys.push(del_msg.key.clone());
                    //     self.data.remove(&del_msg.key);
                    //     None
                    // }
                }
                Some((Message::Update(write_msg), mut stream)) => {
                    elems.insert(write_msg.key, write_msg.value);

                    stream.write_all("OK".as_bytes()).unwrap();
                    // if self.modified_keys.contains(&write_msg.key) {
                    //     Some((Message::Write(write_msg), stream))
                    // } else {
                    //     self.modified_keys.push(write_msg.key.clone());
                    //     self.data.insert(write_msg.key, write_msg.value);
                    //     None
                    // }
                }
                None => (), // None,
            }
        }
    }

    // pub fn done(&mut self) {
    //     self.modified_keys.clear();
    // }

    pub fn get(&self, key: &str) -> Option<&HashMap<String, String>> {
        self.data.get(key)
    }

    pub fn behappy(&self, msg:Option<Message>) -> () {
        match msg {
            Some(Message::Read(RequestMsg{table:_t, key:k})) => println!("Yippi {}", k),
            _ => {}
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Message {
    /// Read a value from the key-value store
    Read(RequestMsg),
    /// Write a value.
    Write(Record),
    /// Delete a value
    Delete(RequestMsg),
    /// Update a given key with the new value
    Update(Record),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RequestMsg {
    pub table: String,
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Record {
    pub table: String,
    pub key: String,
    pub value: HashMap<String, String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ResultRec<'a> {
    pub table: String,
    pub key: String,
    pub value: &'a HashMap<String, String>,
}

impl<'a> ResultRec<'a> {
    pub fn from_request(req: RequestMsg, val: &'a HashMap<String, String>) -> Self {
        Self {
            table: req.table,
            key: req.key,
            value: val,
        }
    }
}