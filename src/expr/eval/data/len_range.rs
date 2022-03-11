use std::cmp::max;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::ops::{BitAnd, Bound, RangeBounds, RangeInclusive};

use ranges::{Domain, GenericRange, OperationResult};

use crate::addr_family::Afi;

use super::{
    error::{EvaluationError, EvaluationResult},
    len::PrefixLength,
};

macro_rules! err {
    ( $( $arg:tt )* ) => {
        super::error::err!(
            super::error::EvaluationErrorKind::PrefixLengthRangeConstruction,
            $($arg)*
        )
    };
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct PrefixLengthRange<A: Afi>(GenericRange<PrefixLength<A>>);

impl<A: Afi> PrefixLengthRange<A> {
    pub fn exact(len: PrefixLength<A>) -> Self {
        // unwrap is safe because we can guarantee start <= end
        (len..=len).try_into().unwrap()
    }

    pub fn ge(len: PrefixLength<A>) -> Self {
        Self(GenericRange::new_at_least(len))
    }

    pub fn gt(len: PrefixLength<A>) -> Option<Self> {
        let range = GenericRange::new_greater_than(len);
        if range.is_empty() {
            None
        } else {
            Some(Self(range))
        }
    }

    pub fn full() -> Self {
        Self(GenericRange::full())
    }

    /// Merge with another [`PrefixLengthRange<A>`] following the logic
    /// defined in [RFC2622] for the repeated application of range operands.
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-2
    pub fn merge(&self, other: &Self) -> Option<Self> {
        let start = max(self.start()?, other.start()?);
        let end = other.end()?;
        (start..=end).try_into().ok()
    }

    pub fn start(&self) -> Option<PrefixLength<A>> {
        PrefixLength::from_bound(self.0.start_bound(), |len| len.successor())
    }

    pub fn end(&self) -> Option<PrefixLength<A>> {
        PrefixLength::from_bound(self.0.end_bound(), |len| len.predecessor())
    }
}

impl<A: Afi> TryFrom<RangeInclusive<PrefixLength<A>>> for PrefixLengthRange<A> {
    type Error = EvaluationError;

    fn try_from(range: RangeInclusive<PrefixLength<A>>) -> EvaluationResult<Self> {
        if range.start() > range.end() {
            Err(err!(
                "range start ({}) greater than range end ({})",
                range.start(),
                range.end()
            ))
        } else {
            Ok(Self(range.into()))
        }
    }
}

impl<A: Afi> TryFrom<RangeInclusive<u8>> for PrefixLengthRange<A> {
    type Error = EvaluationError;

    fn try_from(range: RangeInclusive<u8>) -> EvaluationResult<Self> {
        let lower: PrefixLength<A> = range.start().to_owned().try_into()?;
        let upper = range.end().to_owned().try_into()?;
        (lower..=upper).try_into()
    }
}

impl<A: Afi> BitAnd for PrefixLengthRange<A> {
    type Output = Option<Self>;

    fn bitand(self, rhs: Self) -> Self::Output {
        match self.0.bitand(rhs.0) {
            OperationResult::Empty => None,
            OperationResult::Single(range) => Some(Self(range)),
            OperationResult::Double(_, _) => unreachable!(),
        }
    }
}

impl<A: Afi> fmt::Display for PrefixLengthRange<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<A: Afi> IntoIterator for PrefixLengthRange<A> {
    type Item = PrefixLength<A>;
    type IntoIter = PrefixLengthRangeIter<A>;
    fn into_iter(self) -> Self::IntoIter {
        let end = self
            .end()
            .expect("attempted to create an iterator without a valid end bound");
        let current = self.start();
        Self::IntoIter { current, end }
    }
}

pub struct PrefixLengthRangeIter<A: Afi> {
    current: Option<PrefixLength<A>>,
    end: PrefixLength<A>,
}

impl<A: Afi> Iterator for PrefixLengthRangeIter<A> {
    type Item = PrefixLength<A>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current) = self.current.take() {
            self.current = current.successor().filter(|next| next <= &self.end);
            Some(current)
        } else {
            None
        }
    }
}
