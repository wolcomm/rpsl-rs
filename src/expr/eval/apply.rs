use ip::{self, traits::PrefixRange as _};

use crate::primitive::RangeOperator;

use super::EvaluationResult;

pub(crate) trait Apply<A> {
    type Output;
    fn apply(self, operator: RangeOperator) -> EvaluationResult<Self::Output>;
}

impl<A: ip::AfiClass, T> Apply<A> for T
where
    T: Into<A::PrefixRange>,
{
    type Output = Option<A::PrefixRange>;

    fn apply(self, operator: RangeOperator) -> EvaluationResult<Self::Output> {
        let range: A::PrefixRange = self.into();
        match operator {
            RangeOperator::None => Ok(Some(range)),
            RangeOperator::LessIncl => Ok(Some(range.or_longer())),
            RangeOperator::LessExcl => Ok(range.or_longer_excl()),
            RangeOperator::Exact(l) => {
                let length = range.new_prefix_length(l)?;
                Ok(range.with_length(length))
            }
            RangeOperator::Range(l, u) => {
                let lower = range.new_prefix_length(l)?;
                let upper = range.new_prefix_length(u)?;
                Ok(range.with_length_range(lower..=upper))
            }
        }
    }
}
