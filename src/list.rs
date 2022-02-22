use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::iter::FromIterator;

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
        pair.into_inner()
            .map(|inner_pair| inner_pair.try_into())
            .collect()
    }
}

impl<T> fmt::Display for ListOf<T>
where
    T: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0
            .iter()
            .map(|item| item.to_string())
            .collect::<Vec<String>>()
            .join(", ")
            .fmt(f)
    }
}
