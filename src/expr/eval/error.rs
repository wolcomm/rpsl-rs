use std::error::Error;
use std::fmt;

// use super::resolver::ResolverError;

/// Custom [`Result<T, E>`] containing a possible [`EvaluationError`].
pub type EvaluationResult<T> = Result<T, EvaluationError>;

#[derive(Debug)]
pub struct EvaluationError {
    kind: EvaluationErrorKind,
    msg: String,
    inner: Option<Box<dyn Error + Send + Sync + 'static>>,
}

#[derive(Debug, strum::Display)]
#[strum(serialize_all = "kebab-case")]
pub enum EvaluationErrorKind {
    Substitution,
    Resolution,
    RangeOperatorApplication,
    PrefixLengthValidation,
    PrefixRangeConstruction,
    PrefixLengthRangeConstruction,
}

impl Error for EvaluationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.inner
            .as_ref()
            .map(|boxed_err| boxed_err.as_ref() as &(dyn Error))
    }
}

impl fmt::Display for EvaluationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(inner_err) = self.source() {
            write!(
                f,
                "{} during expression {}: {}",
                self.msg, self.kind, inner_err
            )
        } else {
            write!(f, "{}", self.msg)
        }
    }
}

impl EvaluationError {
    pub(crate) fn new<S>(kind: EvaluationErrorKind, msg: S) -> Self
    where
        S: AsRef<str>,
    {
        Self::new_from(kind, msg, None::<&(dyn Error + Send + Sync + 'static)>)
    }

    pub(crate) fn new_from<S, E>(kind: EvaluationErrorKind, msg: S, err: Option<E>) -> Self
    where
        S: AsRef<str>,
        E: Error + Send + Sync + 'static,
    {
        let inner = err.map(|err| err.into());
        Self {
            kind,
            msg: msg.as_ref().to_string(),
            inner,
        }
    }
}

impl From<ip::Error> for EvaluationError {
    fn from(err: ip::Error) -> Self {
        Self::new_from(
            EvaluationErrorKind::RangeOperatorApplication,
            "failed to apply range operator",
            Some(err),
        )
    }
}

#[derive(Debug, Default)]
pub struct EvaluationErrors {
    inner: Vec<EvaluationError>,
}

impl EvaluationErrors {
    pub fn iter(&self) -> impl Iterator<Item = &EvaluationError> {
        self.inner.iter()
    }
}

pub struct IntoIter {
    inner: <Vec<EvaluationError> as IntoIterator>::IntoIter,
}

impl Iterator for IntoIter {
    type Item = EvaluationError;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl IntoIterator for EvaluationErrors {
    type IntoIter = IntoIter;
    type Item = EvaluationError;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter {
            inner: self.inner.into_iter(),
        }
    }
}

impl Extend<EvaluationError> for EvaluationErrors {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = EvaluationError>,
    {
        self.inner.extend(iter)
    }
}

impl FromIterator<EvaluationError> for EvaluationErrors {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = EvaluationError>,
    {
        let mut this = Self::default();
        this.extend(iter);
        this
    }
}

macro_rules! err {
    ( $kind:expr, $msg:literal $(,)? ) => {
        EvaluationError::new($kind, $msg)
    };
    ( $kind:expr, $fmt:expr, $( $arg:tt )* ) => {
        EvaluationError::new($kind, format!($fmt, $($arg)*))
    };
}
pub(crate) use err;
