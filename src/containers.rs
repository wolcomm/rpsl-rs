use std::fmt;

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

use crate::{
    error::{ParseError, ParseResult},
    parser::TokenPair,
};

/// Ordered list of RPSL expressions or names. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-2
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ListOf<T>(Vec<T>);

impl<T> FromIterator<T> for ListOf<T> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        Self(iter.into_iter().collect())
    }
}

impl<'a, T> TryFrom<TokenPair<'a>> for ListOf<T>
where
    T: TryFrom<TokenPair<'a>, Error = ParseError>,
{
    type Error = ParseError;

    fn try_from(pair: TokenPair<'a>) -> ParseResult<Self> {
        pair.into_inner().map(T::try_from).collect()
    }
}

impl<T> fmt::Display for ListOf<T>
where
    T: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .map(T::to_string)
            .collect::<Vec<String>>()
            .join(", ")
            .fmt(f)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<T> Arbitrary for ListOf<T>
where
    T: Arbitrary,
    T::Strategy: 'static,
{
    type Parameters = ParamsFor<T>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        proptest::collection::vec(any_with::<T>(params), 1..8)
            .prop_map(|v| v.into_iter().collect())
            .boxed()
    }
}
