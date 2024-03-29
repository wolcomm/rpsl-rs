use std::error::Error;
use std::fmt;
use std::num::ParseIntError;

/// Custom [`Result<T, E>`] containing a possible [`ParseError`].
pub type ParseResult<T> = Result<T, ParseError>;

/// Error returned during RPSL text to AST parsing failures.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct ParseError {
    msg: String,
    inner: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl ParseError {
    pub(crate) fn new<S, E>(msg: S, err: Option<E>) -> Self
    where
        S: AsRef<str>,
        E: Error + Send + Sync + 'static,
    {
        let inner = err.map(Into::into);
        Self {
            msg: msg.as_ref().to_string(),
            inner,
        }
    }

    pub(crate) fn from_msg<S>(msg: S) -> Self
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
pub(crate) use err;

impl Error for ParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.as_ref().map(|boxed_err| {
            let err: &(dyn Error) = boxed_err.as_ref();
            err
        })
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl From<ip::Error> for ParseError {
    fn from(err: ip::Error) -> Self {
        Self::new("failed to parse IP address or prefix", Some(err))
    }
}

impl From<time::error::Parse> for ParseError {
    fn from(err: time::error::Parse) -> Self {
        Self::new("failed to parse date string", Some(err))
    }
}

impl From<ValidationError> for ParseError {
    fn from(err: ValidationError) -> Self {
        Self::new("failed to validate object attributes", Some(err))
    }
}

/// Custom [`Result<T, E>`] containing a possible [`ValidationError`].
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Error returned during RPSL object attribute validation failure.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct ValidationError(String);

impl From<String> for ValidationError {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl Error for ValidationError {}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
