use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::iter::FromIterator;

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, collection::size_range, prelude::*};
#[cfg(any(test, feature = "arbitrary"))]
use regex::Regex;

use crate::{
    error::{ParseError, ParseResult},
    parser::{ParserRule, TokenPair},
    primitive::SetNameComp,
};

/// Enumerated RPSL object namees.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum RpslObjectKey {
    Mntner(Mntner),
}

/// RPSL `mntner` name. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.1
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Mntner(String);

impl TryFrom<TokenPair<'_>> for Mntner {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Mntner);
        match pair.as_rule() {
            ParserRule::mntner_name => Ok(Self(pair.as_str().to_owned())),
            // TODO: factor out into a macro
            _ => Err(err!(
                "expected a mntner name, got {:?}: {}",
                pair.as_rule(),
                pair.as_str()
            )),
        }
    }
}

impl_from_str!(ParserRule::mntner_name => Mntner);

impl fmt::Display for Mntner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Mntner {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        let reserved = Regex::new(r"^(?i)AS\d|AS-|RS-|FLTR-|RTRS-|PRNG-").unwrap();
        "[A-Za-z][A-Za-z0-9_-]+"
            .prop_filter_map("names cannot begin with a reserved sequence", move |s| {
                if reserved.is_match(&s) {
                    None
                } else {
                    Some(Self(s))
                }
            })
            .boxed()
    }
}

/// RPSL `aut-num` name: a representation of an autonomous system number. See
/// [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-6
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct AutNum(u32);

impl TryFrom<TokenPair<'_>> for AutNum {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => AutNum);
        match pair.as_rule() {
            ParserRule::aut_num => Ok(Self(
                next_parse_or!(pair.into_inner() => "failed to parse aut-num"),
            )),
            _ => Err(err!(
                "expected an aut-num expression, got {:?}: {}",
                pair.as_rule(),
                pair.as_str()
            )),
        }
    }
}

impl_from_str!(ParserRule::aut_num => AutNum);

impl fmt::Display for AutNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for AutNum {
    type Parameters = ParamsFor<u32>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        any_with::<u32>(args).prop_map(Self).boxed()
    }
}

macro_rules! impl_set_try_from {
    ( $rule:pat => $t:ty ) => {
        impl TryFrom<TokenPair<'_>> for $t {
            type Error = ParseError;
            fn try_from(pair: TokenPair) -> ParseResult<Self> {
                debug_construction!(pair => $t);
                match pair.as_rule() {
                    $rule => Ok(Self(
                        pair.into_inner()
                            .map(|inner| inner.try_into())
                            .collect::<ParseResult<_>>()?,
                    )),
                    _   => Err(err!(
                            concat!("expected a '", stringify!($rule), "' expression, got {:?}: {}"),
                            pair.as_rule(),
                            pair.as_str(),
                    ))
                }
            }
        }
    }
}

macro_rules! impl_from_iter_set_comps {
    ( $item:ty => $t:ty ) => {
        impl FromIterator<$item> for $t {
            fn from_iter<I>(iter: I) -> Self
            where
                I: IntoIterator<Item = $item>,
            {
                Self(iter.into_iter().collect())
            }
        }
    };
}

macro_rules! impl_into_iter_set_comps {
    ( $t:ty => $item:ty ) => {
        impl IntoIterator for $t {
            type IntoIter = std::vec::IntoIter<$item>;
            type Item = $item;
            fn into_iter(self) -> Self::IntoIter {
                self.0.into_iter()
            }
        }

        impl<'a> IntoIterator for &'a $t {
            type IntoIter = std::slice::Iter<'a, $item>;
            type Item = &'a $item;
            fn into_iter(self) -> Self::IntoIter {
                self.0.iter()
            }
        }
    };
}

macro_rules! impl_set_display {
    ( $t:ty ) => {
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.into_iter()
                    .map(|component| component.to_string())
                    .collect::<Vec<_>>()
                    .join(":")
                    .fmt(f)
            }
        }
    };
}

#[cfg(any(test, feature = "arbitrary"))]
macro_rules! impl_set_arbitrary {
    ( $pattern:literal => $t:ty) => {
        impl Arbitrary for $t {
            type Parameters = ();
            type Strategy = BoxedStrategy<Self>;
            fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
                const SET_NAME: &str = $pattern;
                (
                    SET_NAME.prop_map(SetNameComp::Name),
                    any_with::<Vec<SetNameComp>>((size_range(0..5), (SET_NAME,))),
                )
                    .prop_map(|(named, mut components)| {
                        components.push(named);
                        components
                    })
                    .prop_shuffle()
                    .prop_map(Self)
                    .boxed()
            }
        }
    };
}

/// RPSL `as-set` name. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.1
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AsSet(Vec<SetNameComp>);

impl_set_try_from!(ParserRule::as_set => AsSet);
impl_from_str!(ParserRule::as_set => AsSet);
impl_from_iter_set_comps!(SetNameComp => AsSet);
impl_into_iter_set_comps!(AsSet => SetNameComp);
impl_set_display!(AsSet);
#[cfg(any(test, feature = "arbitrary"))]
impl_set_arbitrary!("[Aa][Ss]-[A-Za-z0-9_-]+" => AsSet);

/// RPSL `route-set` name. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.2
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RouteSet(Vec<SetNameComp>);

impl_set_try_from!(ParserRule::route_set => RouteSet);
impl_from_str!(ParserRule::route_set => RouteSet);
impl_from_iter_set_comps!(SetNameComp => RouteSet);
impl_into_iter_set_comps!(RouteSet => SetNameComp);
impl_set_display!(RouteSet);
#[cfg(any(test, feature = "arbitrary"))]
impl_set_arbitrary!("[Rr][Ss]-[A-Za-z0-9_-]+" => RouteSet);

/// RPSL `filter-set` name. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.4
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct FilterSet(Vec<SetNameComp>);

impl_set_try_from!(ParserRule::filter_set => FilterSet);
impl_from_str!(ParserRule::filter_set => FilterSet);
impl_from_iter_set_comps!(SetNameComp => FilterSet);
impl_into_iter_set_comps!(FilterSet => SetNameComp);
impl_set_display!(FilterSet);
#[cfg(any(test, feature = "arbitrary"))]
impl_set_arbitrary!("[Ff][Ll][Tt][Rr]-[A-Za-z0-9_-]+" => FilterSet);

/// RPSL `rtr-set` name. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.5
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RtrSet(Vec<SetNameComp>);

impl_set_try_from!(ParserRule::rtr_set => RtrSet);
impl_from_str!(ParserRule::rtr_set => RtrSet);
impl_from_iter_set_comps!(SetNameComp => RtrSet);
impl_into_iter_set_comps!(RtrSet => SetNameComp);
impl_set_display!(RtrSet);
#[cfg(any(test, feature = "arbitrary"))]
impl_set_arbitrary!("[Rr][Tt][Rr][Ss]-[A-Za-z0-9_-]+" => RtrSet);

/// RPSL `peering-set` name. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.6
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct PeeringSet(Vec<SetNameComp>);

impl_set_try_from!(ParserRule::peering_set => PeeringSet);
impl_from_str!(ParserRule::peering_set => PeeringSet);
impl_from_iter_set_comps!(SetNameComp => PeeringSet);
impl_into_iter_set_comps!(PeeringSet => SetNameComp);
impl_set_display!(PeeringSet);
#[cfg(any(test, feature = "arbitrary"))]
impl_set_arbitrary!("[Pp][Rr][Nn][Gg]-[A-Za-z0-9_-]+" => PeeringSet);

#[cfg(test)]
mod tests {
    use super::*;
    use paste::paste;

    display_fmt_parses! {
        AutNum,
        Mntner,
        AsSet,
        RouteSet,
        FilterSet,
        RtrSet,
        PeeringSet,
    }
}
