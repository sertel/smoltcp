use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str;
use log::debug;

#[derive(Clone, Default)]
pub struct Store {
    data: HashMap<String, String>,
}

impl Store {
    //pub fn default() -> Store {
      //  unimplemented!()
    //}

    pub fn handle_message(&mut self, input_bytes:&[u8]) -> Vec<u8>{

        let mut message_bytes = input_bytes.to_vec();
        if input_bytes.ends_with(&[b'\n']) {
            debug!("ends with linefeed");
            message_bytes.pop();
        }

        match serde_json::from_slice(&message_bytes) {
            Ok(message) => {
                let answer = self.update_state(message);
                serde_json::to_vec(&answer).unwrap()
            },
            _ => {
                let fail_msg = Answer{
                    code:400,
                    data: ResponseData::FailInfo("Mal formed request".to_string()) };
                serde_json::to_vec(&fail_msg).unwrap()
            }
        }
    }

    fn update_state(&mut self, message:Message) -> Answer {
            match message {
                Message::Read(read_msg) => {
                    if let Some(val) =
                        self.data.get(&read_msg.key) {
                        let rec = Record{key:read_msg.key, value: val.to_string() };
                        Answer{code:200, data:ResponseData::Record(rec)}
                    } else {
                        Answer{code:400, data:ResponseData::FailInfo("No such record".to_string()) }
                    }
                },
                Message::Insert(write_msg) => {
                    if let None = self.data.get(&write_msg.key) {
                        self.data.insert(write_msg.key, write_msg.value);
                        Answer{code:201, data:ResponseData::Success }
                    } else {
                        Answer{code:400, data:ResponseData::FailInfo("Record already present".to_string()) }
                    }
                }
                Message::Delete(del_msg) => {
                    if let Some(val) = self.data.remove(&del_msg.key) {
                        let rec = Record {key: del_msg.key, value: val};
                        Answer { code: 200, data: ResponseData::Record(rec) };
                    }
                    Answer{code:400, data:ResponseData::FailInfo("Record was not present".to_string())}
                }
                Message::Update(write_msg) => {
                    self.data.insert(write_msg.key, write_msg.value);
                    Answer{code:200, data:ResponseData::Success}
                }
            }
        }

}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Message {
    /// Read a value from the key-value store
    Read(RequestMsg),
    /// Write a value.
    Insert(Record),
    /// Delete a value
    Delete(RequestMsg),
    /// Update a given key with the new value
    Update(Record),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RequestMsg {
    //pub table: String,
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Record {
    //pub table: String,
    pub key: String,
    pub value: String,
}


#[derive(Serialize, Clone, Debug)]
pub struct Answer {
    pub code: i32,
    pub data: ResponseData,
}


#[derive(Serialize, Clone, Debug)]
pub enum ResponseData {
    Success,
    FailInfo(String),
    Record(Record),
}

