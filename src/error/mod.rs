use std::error;
use std::fmt::{self, Debug, Formatter};
use std::io;

#[derive(Clone)]
pub struct Error {
    pub message: String,
}

impl Error {
    pub fn new<S>(message: S) -> Error
    where
        S: Into<String>,
    {
        Error {
            message: message.into(),
        }
    }
}

impl Debug for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::new(err.to_string())
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        io::Error::new(io::ErrorKind::Other, err.message)
    }
}
