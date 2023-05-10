use ip::{
    self,
    traits::{AfiClass, PrefixRange as _},
};

use crate::primitive::RangeOperator;

use super::EvaluationError;

pub(crate) trait Apply<A>: Sized {
    type Output;
    fn apply(self, operator: RangeOperator) -> Result<Self::Output, EvaluationError>;
}

impl<A: AfiClass, T> Apply<A> for T
where
    T: Into<A::PrefixRange>,
{
    type Output = Option<A::PrefixRange>;

    fn apply(self, operator: RangeOperator) -> Result<Self::Output, EvaluationError> {
        let range: A::PrefixRange = self.into();
        match operator {
            RangeOperator::None => Ok(Some(range)),
            RangeOperator::LessIncl => Ok(Some(range.or_longer())),
            RangeOperator::LessExcl => Ok(range.or_longer_excl()),
            RangeOperator::Exact(l) => range
                .new_prefix_length(l)
                .map_err(|source| EvaluationError::RangeOperator {
                    range: range.to_string(),
                    operator,
                    source,
                })
                .map(|length| range.with_length(length)),
            RangeOperator::Range(l, u) => range
                .new_prefix_length(l)
                .and_then(|lower| Ok(lower..=range.new_prefix_length(u)?))
                .map_err(|source| EvaluationError::RangeOperator {
                    range: range.to_string(),
                    operator,
                    source,
                })
                .map(|len_range| range.with_length_range(len_range)),
        }
    }
}
