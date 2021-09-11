use std::error::Error;
use std::fmt;
use std::num::ParseIntError;

use ipnet::AddrParseError;

pub type ParseResult<T> = Result<T, ParseError>;

#[derive(Debug)]
pub struct ParseError {
    msg: String,
    inner: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl ParseError {
    pub fn new<S, E>(msg: S, err: Option<E>) -> Self
    where
        S: AsRef<str>,
        E: Error + Send + Sync + 'static,
    {
        let inner = err.map(|err| err.into());
        Self {
            msg: msg.as_ref().to_string(),
            inner,
        }
    }

    pub fn from_msg<S>(msg: S) -> Self
    where
        S: AsRef<str>,
    {
        Self {
            msg: msg.as_ref().to_string(),
            inner: None,
        }
    }
}

macro_rules! err {
    ( $msg:literal $(,)? ) => {
        $crate::error::ParseError::from_msg($msg)
    };
    ( $fmt:expr, $( $arg:tt )* ) => {
        $crate::error::ParseError::from_msg(format!($fmt, $($arg)*))
    };
}

impl Error for ParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.inner
            .as_ref()
            .map(|boxed_err| boxed_err.as_ref() as &(dyn Error))
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(inner_err) = self.source() {
            write!(f, "{}: {}", self.msg, inner_err)
        } else {
            write!(f, "{}", self.msg)
        }
    }
}

impl<R> From<pest::error::Error<R>> for ParseError
where
    R: pest::RuleType + Send + Sync + 'static,
{
    fn from(err: pest::error::Error<R>) -> Self {
        Self::new("failed to parse expression", Some(err))
    }
}

impl From<ParseIntError> for ParseError {
    fn from(err: ParseIntError) -> Self {
        Self::new("failed to parse integer value", Some(err))
    }
}

impl From<AddrParseError> for ParseError {
    fn from(err: AddrParseError) -> Self {
        Self::new("failed to parse IP prefix", Some(err))
    }
}

impl From<nom::error::Error<String>> for ParseError {
    fn from(err: nom::error::Error<String>) -> Self {
        Self::new("nom parse error", Some(err))
    }
}

pub type SubstitutionResult<T> = Result<T, SubstitutionError>;

#[derive(Debug)]
pub enum SubstitutionError {
    PeerAs,
}

impl Error for SubstitutionError {}

impl fmt::Display for SubstitutionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::PeerAs => write!(f, "failed to substitute 'PeerAs' token"),
        }
    }
}
