use resolv_conf::ParseError;
use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0} - bad dns query {1}")]
    DnsQuery(String, #[source] dnssector::Error),
    #[error("{0} - response packet has no answer")]
    EmptyResponse(&'static str),
    #[error("{0} - extract ips")]
    ExtractIps(String, #[source] dnssector::Error),
    #[error("query - udp bind")]
    Bind(#[source] io::Error),
    #[error("query - udp connect to {0}")]
    Connect(String, #[source] io::Error),
    #[error("query - udp send to {0}")]
    Send(String, #[source] io::Error),
    #[error("query - receive dns response from {0}")]
    Recv(String, #[source] io::Error),
    #[error("{0} - cannot parse dns response")]
    ParseResponse(String, #[source] dnssector::Error),
    #[error("{0} - {1} requires TCP which is unsupported")]
    TcpUnsupported(String, String),
}

/*
// TODO: thiserror
#[derive(Debug)]
pub struct Error {
    original: Option<Box<dyn std::error::Error>>,
    msg: String,
}

impl Error {
    pub(crate) fn new<S>(msg: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            original: None,
            msg: msg.into(),
        }
    }
}

impl std::error::Error for Error {}

impl From<ClientError> for Error {
    fn from(c: ClientError) -> Self {
        let msg = format!("{}", c);
        Self {
            original: None, // Uses Failure and does not implement Error trait
            msg,
        }
    }
}

impl From<io::Error> for Error {
    fn from(i: io::Error) -> Self {
        let msg = format!("{}", i);
        Self {
            original: Some(Box::new(i)),
            msg,
        }
    }
}

impl From<ParseError> for Error {
    fn from(p: ParseError) -> Self {
        let msg = format!("{}", p);
        Self {
            original: Some(Box::new(p)),
            msg,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}
*/
