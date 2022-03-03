use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    addr_family::LiteralPrefixSetAfi,
    error::{ParseError, ParseResult},
    names::{AsSet, AutNum, InetRtr, RouteSet, RtrSet},
    parser::{debug_construction, next_into_or, rule_mismatch, ParserRule, TokenPair},
    primitive::{IpAddress, IpPrefix, RangeOperator},
};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

/// Names that can appear in the `members` attribute of an `as-set` object.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.1
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum AsSetMember {
    /// An `as-set` member wrapping an `aut-num` name.
    AutNum(AutNum),
    /// An `as-set` member wrapping an `as-set` name.
    AsSet(AsSet),
}

impl TryFrom<TokenPair<'_>> for AsSetMember {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => AsSetMember);
        match pair.as_rule() {
            ParserRule::aut_num => Ok(Self::AutNum(pair.try_into()?)),
            ParserRule::as_set => Ok(Self::AsSet(pair.try_into()?)),
            _ => Err(rule_mismatch!(pair => "as-set member")),
        }
    }
}

impl fmt::Display for AsSetMember {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::AutNum(aut_num) => aut_num.fmt(f),
            Self::AsSet(as_set) => as_set.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for AsSetMember {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<AutNum>().prop_map(Self::AutNum),
            any::<AsSet>().prop_map(Self::AsSet),
        ]
        .boxed()
    }
}

/// Elements that can appear in the `members` or `mp-members` attribute of a
/// `route-set` object.
/// See [RFC2622] and [RFC4012].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.2
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-4.2
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RouteSetMember<A: LiteralPrefixSetAfi> {
    base: RouteSetMemberElem<A>,
    op: RangeOperator,
}

impl<A: LiteralPrefixSetAfi> RouteSetMember<A> {
    /// Construct a new [`RouteSetMember`].
    pub fn new(base: RouteSetMemberElem<A>, op: RangeOperator) -> Self {
        Self { base, op }
    }
}

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for RouteSetMember<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => RouteSetMember);
        match pair.as_rule() {
            rule if rule == A::ROUTE_SET_MEMBER_RULE => {
                let mut pairs = pair.into_inner();
                let base = next_into_or!(pairs => "failed to get route-set member element")?;
                let op = match pairs.next() {
                    Some(inner) => inner.try_into()?,
                    None => RangeOperator::None,
                };
                Ok(Self { base, op })
            }
            _ => Err(rule_mismatch!(pair => "route-set member")),
        }
    }
}

impl<A: LiteralPrefixSetAfi> fmt::Display for RouteSetMember<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}", self.base, self.op)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A: LiteralPrefixSetAfi> Arbitrary for RouteSetMember<A>
where
    A: fmt::Debug + Clone + 'static,
    A::Addr: Arbitrary,
{
    type Parameters = ParamsFor<RangeOperator>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            any::<RouteSetMemberElem<A>>(),
            any_with::<RangeOperator>(params),
        )
            .prop_map(|(base, op)| Self { base, op })
            .boxed()
    }
}

/// RPSL names that can appear as the base of a member element in the `members`
/// or `mp-members` attribute of a `route-set` object.
/// See [RFC2622] and [RFC4012].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.2
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-4.2
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum RouteSetMemberElem<A: LiteralPrefixSetAfi> {
    /// A `route-set` member wrapping literal IP prefix.
    Prefix(IpPrefix<A>),
    /// A `route-set` member wrapping the `RS-ANY` token.
    RsAny,
    /// A `route-set` member wrapping the `AS-ANY` token.
    AsAny,
    /// A `route-set` member wrapping a `route-set` name.
    RouteSet(RouteSet),
    /// A `route-set` member wrapping a `as-set` name.
    AsSet(AsSet),
    /// A `route-set` member wrapping an `aut-num` name.
    AutNum(AutNum),
}

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for RouteSetMemberElem<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => RouteSetMemberElem);
        match pair.as_rule() {
            rule if rule == A::LITERAL_PREFIX_RULE => Ok(Self::Prefix(pair.try_into()?)),
            ParserRule::any_rs => Ok(Self::RsAny),
            ParserRule::any_as => Ok(Self::AsAny),
            ParserRule::route_set => Ok(Self::RouteSet(pair.try_into()?)),
            ParserRule::as_set => Ok(Self::AsSet(pair.try_into()?)),
            ParserRule::aut_num => Ok(Self::AutNum(pair.try_into()?)),
            _ => Err(rule_mismatch!(pair => "route-set member element")),
        }
    }
}

impl<A: LiteralPrefixSetAfi> fmt::Display for RouteSetMemberElem<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Prefix(prefix) => prefix.fmt(f),
            Self::RsAny => write!(f, "RS-ANY"),
            Self::AsAny => write!(f, "AS-ANY"),
            Self::RouteSet(route_set) => route_set.fmt(f),
            Self::AsSet(as_set) => as_set.fmt(f),
            Self::AutNum(aut_num) => aut_num.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A: LiteralPrefixSetAfi> Arbitrary for RouteSetMemberElem<A>
where
    A: fmt::Debug + Clone + 'static,
    A::Addr: Arbitrary,
{
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<IpPrefix<A>>().prop_map(Self::Prefix),
            Just(Self::RsAny),
            Just(Self::AsAny),
            any::<RouteSet>().prop_map(Self::RouteSet),
            any::<AsSet>().prop_map(Self::AsSet),
            any::<AutNum>().prop_map(Self::AutNum),
        ]
        .boxed()
    }
}

/// RPSL names that can appear in the `members` or `mp-members` attribute of an
/// `rtr-set` object.
/// See [RFC2622] and [RFC4012].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.5
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-4.6
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum RtrSetMember<A: LiteralPrefixSetAfi> {
    /// An `rtr-set` member wrapping a literal IP address.
    Addr(IpAddress<A>),
    /// An `rtr-set` member wrapping an `inet-rtr` name.
    InetRtr(InetRtr),
    /// An `rtr-set` member wrapping an `rtr-set` name.
    RtrSet(RtrSet),
}

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for RtrSetMember<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => RtrSetMember);
        match pair.as_rule() {
            rule if rule == A::LITERAL_ADDR_RULE => Ok(Self::Addr(pair.try_into()?)),
            ParserRule::inet_rtr => Ok(Self::InetRtr(pair.try_into()?)),
            ParserRule::rtr_set => Ok(Self::RtrSet(pair.try_into()?)),
            _ => Err(rule_mismatch!(pair => "rtr-set member")),
        }
    }
}

impl<A: LiteralPrefixSetAfi> fmt::Display for RtrSetMember<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Addr(addr) => addr.fmt(f),
            Self::InetRtr(inet_rtr) => inet_rtr.fmt(f),
            Self::RtrSet(rtr_set) => rtr_set.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A: LiteralPrefixSetAfi> Arbitrary for RtrSetMember<A>
where
    A: fmt::Debug + Clone + 'static,
    A::Addr: Arbitrary,
{
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<IpAddress<A>>().prop_map(Self::Addr),
            any::<InetRtr>().prop_map(Self::InetRtr),
            any::<RtrSet>().prop_map(Self::RtrSet),
        ]
        .boxed()
    }
}
