use std::convert::TryInto;

use crate::{
    addr_family::Afi,
    primitive::{IpPrefix, RangeOperator},
};

use super::{
    data::{IpPrefixRange, PrefixLengthRange},
    error::{EvaluationError, EvaluationResult},
};

macro_rules! err {
    ( $( $arg:tt )* ) => {
        super::error::err!(
            super::error::EvaluationErrorKind::RangeOperatorApplication,
            $($arg)*
        )
    };
}

pub trait Apply<O> {
    type Output;

    fn apply(&self, operand: O) -> EvaluationResult<Self::Output>;
}

impl<A: Afi> Apply<IpPrefix<A>> for RangeOperator {
    type Output = IpPrefixRange<A>;

    fn apply(&self, prefix: IpPrefix<A>) -> EvaluationResult<Self::Output> {
        let prefix_len = A::prefix_len(prefix.as_ref()).try_into()?;
        let len_range = match *self {
            Self::None => Some(PrefixLengthRange::exact(prefix_len)),
            Self::LessIncl => Some(PrefixLengthRange::ge(prefix_len)),
            Self::LessExcl => PrefixLengthRange::gt(prefix_len),
            Self::Exact(len) => {
                PrefixLengthRange::ge(prefix_len) & PrefixLengthRange::exact(len.try_into()?)
            }
            Self::Range(lower, upper) => {
                PrefixLengthRange::ge(prefix_len) & (lower..=upper).try_into()?
            }
        }
        .ok_or_else(|| {
            err!(
                "empty IP prefix range produced from expression {}{}",
                prefix,
                self
            )
        })?;
        IpPrefixRange::new(prefix, len_range)
    }
}

impl<A: Afi> Apply<IpPrefixRange<A>> for RangeOperator {
    type Output = IpPrefixRange<A>;

    fn apply(&self, prefix_range: IpPrefixRange<A>) -> EvaluationResult<Self::Output> {
        let prefix = prefix_range.prefix().to_owned();
        let range_start = prefix_range
            .len_range()
            .start()
            .ok_or_else(|| err!("invalid prefix length-range start bound: {}", prefix_range))?;
        let len_range = match *self {
            Self::None => Some(*prefix_range.len_range()),
            Self::LessIncl => Some(PrefixLengthRange::ge(range_start)),
            Self::LessExcl => PrefixLengthRange::gt(range_start),
            Self::Exact(len) => prefix_range.len_range().merge(&(len..=len).try_into()?),
            Self::Range(lower, upper) => {
                prefix_range.len_range().merge(&(lower..=upper).try_into()?)
            }
        }
        .ok_or_else(|| {
            err!(
                "empty IP prefix range produced after applying {} to {}",
                self,
                prefix_range
            )
        })?;
        IpPrefixRange::new(prefix, len_range)
    }
}

impl<I, O> Apply<I> for RangeOperator
where
    I: IntoIterator,
    RangeOperator: Apply<I::Item, Output = O>,
{
    // TODO: use `impl Iterator` once the feature has stabilised
    type Output = ApplyMap<O>;

    fn apply(&self, iter: I) -> EvaluationResult<Self::Output> {
        Ok(ApplyMap(
            iter.into_iter()
                .filter_map(|item| {
                    self.apply(item)
                        .map_err(|err| {
                            log::warn!("failed to apply range operator to prefix-range: {}", err)
                        })
                        .ok()
                })
                .collect::<Vec<_>>()
                .into_iter(),
        ))
    }
}

pub struct ApplyMap<O>(std::vec::IntoIter<O>);

impl<O> Iterator for ApplyMap<O> {
    type Item = O;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}
