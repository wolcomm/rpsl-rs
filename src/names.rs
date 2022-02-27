use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::iter::FromIterator;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, collection::size_range, prelude::*};

use crate::{
    error::{ParseError, ParseResult},
    parser::{
        debug_construction, impl_from_str, impl_str_primitive, next_into_or, next_parse_or,
        rule_mismatch, ParserRule, TokenPair,
    },
    primitive::SetNameComp,
};

#[cfg(any(test, feature = "arbitrary"))]
use crate::primitive::arbitrary::impl_rpsl_name_arbitrary;

/// RPSL `mntner` name. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.1
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Mntner(String);
impl_str_primitive!(ParserRule::mntner_name => Mntner);
impl_from_str!(ParserRule::mntner_name => Mntner);
#[cfg(any(test, feature = "arbitrary"))]
impl_rpsl_name_arbitrary!(Mntner);

/// RPSL `person` name. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.2
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Person(String);
impl_str_primitive!(ParserRule::person => Person);

/// RPSL `role` name. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.3
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Role(String);
impl_str_primitive!(ParserRule::role => Role);

/// RPSL `key-cert` name. See [RFC2726].
///
/// [RFC2726]: https://datatracker.ietf.org/doc/html/rfc2726
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum KeyCert {
    /// A `PGP` `key-cert` name.
    Pgp(String),
    /// A `X509` `key-cert` name.
    X509(String),
}

impl TryFrom<TokenPair<'_>> for KeyCert {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => KeyCert);
        match pair.as_rule() {
            ParserRule::key_cert_pgp => Ok(Self::Pgp(pair.as_str().to_string())),
            ParserRule::key_cert_x509 => Ok(Self::X509(pair.as_str().to_string())),
            _ => Err(rule_mismatch!(pair => "key-cert name")),
        }
    }
}

impl_from_str!(ParserRule::key_cert => KeyCert);

impl fmt::Display for KeyCert {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Pgp(name) | Self::X509(name) => name.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for KeyCert {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            "PGPKEY-[0-9A-Fa-f]+".prop_map(Self::Pgp),
            "X509-[0-9]+".prop_map(Self::X509),
        ]
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
                next_parse_or!(pair.into_inner() => "failed to parse aut-num")?,
            )),
            _ => Err(rule_mismatch!(pair => "aut-num name")),
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

/// RPSL `as-block` name. See [RFC2725].
///
/// [RFC2725]: https://datatracker.ietf.org/doc/html/rfc2725#section-10.1
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct AsBlock {
    lower: AutNum,
    upper: AutNum,
}

impl TryFrom<TokenPair<'_>> for AsBlock {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => AsBlock);
        match pair.as_rule() {
            ParserRule::as_block => {
                let mut pairs = pair.into_inner();
                let lower = next_into_or!(pairs => "failed to parse lower AS number")?;
                let upper = next_into_or!(pairs => "failed to parse upper AS number")?;
                Ok(Self { lower, upper })
            }
            _ => Err(rule_mismatch!(pair => "as-block name")),
        }
    }
}

impl_from_str!(ParserRule::as_block => AsBlock);

impl fmt::Display for AsBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} - {}", self.lower, self.upper)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for AsBlock {
    type Parameters = ParamsFor<u32>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        any_with::<u32>(args)
            .prop_flat_map(|lower| (lower..).prop_map(move |upper| (AutNum(lower), AutNum(upper))))
            .prop_map(|(lower, upper)| Self { lower, upper })
            .boxed()
    }
}

/// RPSL `inetnum` name.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct InetNum {
    lower: Ipv4Addr,
    upper: Ipv4Addr,
}

impl TryFrom<TokenPair<'_>> for InetNum {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => InetNum);
        match pair.as_rule() {
            ParserRule::inetnum => {
                let mut pairs = pair.into_inner();
                let lower = next_parse_or!(pairs => "failed to parse lower IPv4 address")?;
                let upper = next_parse_or!(pairs => "failed to parse lower IPv4 address")?;
                Ok(Self { lower, upper })
            }
            _ => Err(rule_mismatch!(pair => "inetnum name")),
        }
    }
}

impl_from_str!(ParserRule::inetnum => InetNum);

impl fmt::Display for InetNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} - {}", self.lower, self.upper)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for InetNum {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<Ipv4Addr>()
            .prop_flat_map(|lower| {
                let upper = (<Ipv4Addr as Into<u32>>::into(lower)..).prop_map(Ipv4Addr::from);
                (Just(lower), upper)
            })
            .prop_map(|(lower, upper)| Self { lower, upper })
            .boxed()
    }
}

/// RPSL `inet6num` name. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-5
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Inet6Num {
    lower: Ipv6Addr,
    upper: Ipv6Addr,
}

impl TryFrom<TokenPair<'_>> for Inet6Num {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Inet6Num);
        match pair.as_rule() {
            ParserRule::inet6num => {
                let mut pairs = pair.into_inner();
                let lower = next_parse_or!(pairs => "failed to parse lower IPv6 address")?;
                let upper = next_parse_or!(pairs => "failed to parse lower IPv6 address")?;
                Ok(Self { lower, upper })
            }
            _ => Err(rule_mismatch!(pair => "inet6num name")),
        }
    }
}

impl_from_str!(ParserRule::inet6num => Inet6Num);

impl fmt::Display for Inet6Num {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} - {}", self.lower, self.upper)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Inet6Num {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<Ipv6Addr>()
            .prop_flat_map(|lower| {
                let upper = (<Ipv6Addr as Into<u128>>::into(lower)..).prop_map(Ipv6Addr::from);
                (Just(lower), upper)
            })
            .prop_map(|(lower, upper)| Self { lower, upper })
            .boxed()
    }
}

/// RPSL `route` name. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-6
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Route(Ipv4Net);

impl TryFrom<TokenPair<'_>> for Route {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Route);
        match pair.as_rule() {
            ParserRule::ipv4_prefix => Ok(Self(pair.as_str().parse()?)),
            _ => Err(rule_mismatch!(pair => "route name")),
        }
    }
}

impl_from_str!(ParserRule::ipv4_prefix => Route);

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Route {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (any::<Ipv4Addr>(), (0u8..32))
            .prop_map(|(addr, len)| Ipv4Net::new(addr, len).unwrap().trunc())
            .prop_map(Self)
            .boxed()
    }
}

/// RPSL `route6` name. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-3
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Route6(Ipv6Net);

impl TryFrom<TokenPair<'_>> for Route6 {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Route);
        match pair.as_rule() {
            ParserRule::ipv6_prefix => Ok(Self(pair.as_str().parse()?)),
            _ => Err(rule_mismatch!(pair => "route name")),
        }
    }
}

impl_from_str!(ParserRule::ipv6_prefix => Route6);

impl fmt::Display for Route6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Route6 {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (any::<Ipv6Addr>(), (0u8..128))
            .prop_map(|(addr, len)| Ipv6Net::new(addr, len).unwrap().trunc())
            .prop_map(Self)
            .boxed()
    }
}

/// RPSL `inet-rtr` name. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-9
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct InetRtr(String);
impl_str_primitive!(ParserRule::inet_rtr => InetRtr);
impl_from_str!(ParserRule::inet_rtr => InetRtr);

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for InetRtr {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        r"[A-Za-z][0-9A-Za-z_-]*(\.[A-Za-z][0-9A-Za-z_-]*)*"
            .prop_map(Self)
            .boxed()
    }
}

/// RPSL `dictionary` name. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-10
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Dictionary(String);
impl_str_primitive!(ParserRule::dictionary => Dictionary);

macro_rules! impl_set_try_from {
    ( $rule:pat => $t:ty ) => {
        impl TryFrom<TokenPair<'_>> for $t {
            type Error = ParseError;
            fn try_from(pair: TokenPair) -> ParseResult<Self> {
                $crate::parser::debug_construction!(pair => $t);
                match pair.as_rule() {
                    $rule => Ok(Self(
                        pair.into_inner()
                            .map(|inner| inner.try_into())
                            .collect::<ParseResult<_>>()?,
                    )),
                    // TODO: try to use `rule_mismatch!` here
                    _   => Err($crate::error::err!(
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
                    SET_NAME.prop_map(|name| SetNameComp::Name(name.as_str().into())),
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
    use crate::tests::display_fmt_parses;

    display_fmt_parses! {
        Mntner,
        KeyCert,
        AutNum,
        AsBlock,
        InetNum,
        Inet6Num,
        Route,
        Route6,
        InetRtr,
        AsSet,
        RouteSet,
        FilterSet,
        RtrSet,
        PeeringSet,
    }
}
