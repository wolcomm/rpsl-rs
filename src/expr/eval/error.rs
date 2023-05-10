use std::error::Error;
use std::fmt;

use crate::primitive::RangeOperator;

/// The error type produced by a failed attempt to evaluate an RPSL expression.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, thiserror::Error)]
pub enum EvaluationError {
    /// Applying a [`RangeOperator`] to an IP prefix range failed.
    #[error("failed to apply range operator '{operator}' to IP prefix range '{range}'")]
    RangeOperator {
        /// The string representation of the IP prefix range.
        range: String,
        /// The [`RangeOperator`] that failed to apply.
        operator: RangeOperator,
        /// The underlying error that resulted in this failure.
        source: ip::Error,
    },

    /// An attempt to resolve an RPSL name or primitive failed.
    #[error("error while resolving {item:?}")]
    Resolution {
        /// The item that was being resolved when this failure occurred.
        item: Box<dyn fmt::Debug + Send + Sync + 'static>,
        /// The underlying source error.
        source: Box<dyn Error + Send + Sync + 'static>,
    },
}
