use crate::error::Error;
use serde::Deserialize;
use std::io;

pub mod acceptor;
mod header;

fn new_error<T: ToString>(message: T) -> io::Error {
    return Error::new(format!("socks: {}", message.to_string())).into();
}
