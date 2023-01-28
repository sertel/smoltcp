use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str;
use log::debug;


#[derive(Clone)]
pub struct Store {
    data: HashMap<String, HashMap<String, String>>,
    defaultAnswer: Record,
}

impl Store {
    pub fn default() -> Store {
        Store {
            data: HashMap::new(),
            defaultAnswer: Record{
                table:"defaultTable".to_owned(),
                key:"defaultKey".to_owned(),
                value: HashMap::from([
                    ("field1".to_owned(), "spring".to_owned()), 
                    ("field2".to_owned(), "summer".to_owned()), 
                    ("field3".to_owned(), "autumn".to_owned()), 
                    ("field4".to_owned(), "summer again, because why not".to_owned())]),
            }            
        }
    }

    pub fn handle_message(&mut self, input_bytes:&[u8]) -> Vec<u8>{
        //println!("Handling message");
        let mut message_bytes = input_bytes.to_vec();
        if input_bytes.ends_with(&[b'\n']) {
            debug!("ends with linefeed");
            message_bytes.pop();
        }

        match serde_json::from_slice(&message_bytes) {
            
            Ok(message) => {
                let answer = self.update_state(message);
                //serde_json::to_vec(&answer).unwrap()
                answer
            },
            _ => {
                /*
                let fail_msg = Answer{
                    code:400,
                    data: ResponseData::FailInfo("Mal formed request".to_string()) };
                serde_json::to_vec(&fail_msg).unwrap()*/
                "OK".as_bytes().to_vec()
            }
        }
    }

    fn update_state(&mut self, message:Message) -> Vec<u8> {
            //println!("Updating state");
            match message {
                Message::Read(_) => "OK".as_bytes().to_vec(),//serde_json::to_vec(&self.defaultAnswer).unwrap(),
                Message::Write(write_msg) => {
                    self.data.insert(write_msg.table, write_msg.value);
                    "OK".as_bytes().to_vec()
                },
                Message::Delete(del_msg) => {
                    self.data.remove(&del_msg.key);
                    "OK".as_bytes().to_vec()
                }
                Message::Update(write_msg) => {
                    self.data.insert(write_msg.table, write_msg.value);
                    "OK".as_bytes().to_vec()
                }
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

#[derive(Serialize,Deserialize, Clone, Debug)]
pub enum ResponseData {
    Success,
    FailInfo(String),
    Record(Record),
}



