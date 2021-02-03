use crate::error::Error;
use std::io;

pub mod acceptor;
mod header;

fn new_error<T: ToString>(message: T) -> io::Error {
    Error::new(format!("socks: {}", message.to_string())).into()
}
