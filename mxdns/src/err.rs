use std::fmt;
use trust_dns::error::ClientError;

#[derive(Debug)]
pub struct Error {
    original: Option<Box<dyn std::error::Error>>,
    msg: String,
}

impl std::error::Error for Error {}

impl From<ClientError> for Error {
    fn from(c: ClientError) -> Self {
        let msg = format!("{}", c);
        Self {
            original: None,
            msg,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}
