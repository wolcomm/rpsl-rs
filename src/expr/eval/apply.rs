use ip::{self, traits::PrefixRange as _};

use crate::primitive::RangeOperator;

use super::EvaluationResult;

pub(crate) trait Apply {
    fn apply<A, P>(&self, input: P) -> EvaluationResult<Option<A::PrefixRange>>
    where
        A: ip::AfiClass,
        P: Into<ip::PrefixRange<A>>;
}

impl Apply for RangeOperator {
    fn apply<A, P>(&self, input: P) -> EvaluationResult<Option<A::PrefixRange>>
    where
        A: ip::AfiClass,
        P: Into<A::PrefixRange>,
    {
        let range = input.into();
        match self {
            Self::None => Ok(Some(range)),
            Self::LessIncl => Ok(Some(range.or_longer())),
            Self::LessExcl => Ok(range.or_longer_excl()),
            Self::Exact(l) => {
                let length = range.new_prefix_length(*l)?;
                Ok(range.with_length(length))
            }
            Self::Range(l, u) => {
                let lower = range.new_prefix_length(*l)?;
                let upper = range.new_prefix_length(*u)?;
                Ok(range.with_length_range(lower..=upper))
            }
        }
    }
}
