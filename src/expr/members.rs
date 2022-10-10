use std::convert::{TryFrom, TryInto};
use std::fmt;

use ip::{Any, Ipv4};

use crate::{
    error::{ParseError, ParseResult},
    names::{AsSet, AutNum, InetRtr, RouteSet, RtrSet},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::{IpAddress, IpPrefix, ParserAfi, RangeOperator},
};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

/// Names that can appear in the `members` attribute of an `as-set` object.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.1
pub type AsSetMember = self::as_set::Member;
impl_from_str!(ParserRule::as_set_member_choice => AsSetMember);

mod as_set {
    use super::*;

    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    pub enum Member {
        /// An `as-set` member wrapping an `aut-num` name.
        AutNum(AutNum),
        /// An `as-set` member wrapping an `as-set` name.
        AsSet(AsSet),
    }

    impl TryFrom<TokenPair<'_>> for Member {
        type Error = ParseError;

        fn try_from(pair: TokenPair) -> ParseResult<Self> {
            debug_construction!(pair => Member);
            match pair.as_rule() {
                ParserRule::aut_num => Ok(Self::AutNum(pair.try_into()?)),
                ParserRule::as_set => Ok(Self::AsSet(pair.try_into()?)),
                _ => Err(rule_mismatch!(pair => "as-set member")),
            }
        }
    }

    impl fmt::Display for Member {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::AutNum(aut_num) => aut_num.fmt(f),
                Self::AsSet(as_set) => as_set.fmt(f),
            }
        }
    }

    #[cfg(any(test, feature = "arbitrary"))]
    impl Arbitrary for Member {
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
}

/// Elements that can appear in the `members` attribute of a `route-set` object.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.2
pub type RouteSetMember = self::route_set::Member<Ipv4>;

/// Elements that can appear in the `mp-members` attribute of a `route-set` object.
/// See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-4.2
pub type RouteSetMpMember = self::route_set::Member<Any>;

mod route_set {
    use super::*;

    pub trait MemberAfi: ParserAfi {
        /// Address family specific [`ParserRule`] for `route-set` member items.
        const ROUTE_SET_MEMBER_RULE: ParserRule;
    }

    impl MemberAfi for Ipv4 {
        const ROUTE_SET_MEMBER_RULE: ParserRule = ParserRule::route_set_member_choice;
    }

    impl MemberAfi for Any {
        const ROUTE_SET_MEMBER_RULE: ParserRule = ParserRule::route_set_mp_member_choice;
    }

    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    pub struct Member<A: MemberAfi> {
        base: MemberElem<A>,
        op: RangeOperator,
    }

    impl<A: MemberAfi> Member<A> {
        /// Construct a new [`RouteSetMember`].
        pub fn new(base: MemberElem<A>, op: RangeOperator) -> Self {
            Self { base, op }
        }
    }

    impl_from_str! {
        forall A: MemberAfi {
            A::ROUTE_SET_MEMBER_RULE => Member<A>
        }
    }

    impl<A: MemberAfi> TryFrom<TokenPair<'_>> for Member<A> {
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

    impl<A: MemberAfi> fmt::Display for Member<A> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}{}", self.base, self.op)
        }
    }

    #[cfg(any(test, feature = "arbitrary"))]
    impl<A: MemberAfi> Arbitrary for Member<A>
    where
        A: fmt::Debug + Clone + 'static,
        A::Prefix: Arbitrary,
    {
        type Parameters = ParamsFor<RangeOperator>;
        type Strategy = BoxedStrategy<Self>;
        fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
            (any::<MemberElem<A>>(), any_with::<RangeOperator>(params))
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
    pub enum MemberElem<A: MemberAfi> {
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

    impl<A: MemberAfi> TryFrom<TokenPair<'_>> for MemberElem<A> {
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

    impl<A: MemberAfi> fmt::Display for MemberElem<A> {
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
    impl<A: MemberAfi> Arbitrary for MemberElem<A>
    where
        A: fmt::Debug + Clone + 'static,
        A::Prefix: Arbitrary,
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
}

/// RPSL names that can appear in the `members` attribute of an `rtr-set`
/// object.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.5
pub type RtrSetMember = self::rtr_set::Member<Ipv4>;

/// RPSL names that can appear in the `mp-members` attribute of an `rtr-set`
/// object.
/// See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-4.6
pub type RtrSetMpMember = self::rtr_set::Member<Any>;

mod rtr_set {
    use super::*;

    pub trait MemberAfi: ParserAfi {
        /// Address family specific [`ParserRule`] for `rtr-set` member items.
        const RTR_SET_MEMBER_RULE: ParserRule;
    }

    impl MemberAfi for Ipv4 {
        const RTR_SET_MEMBER_RULE: ParserRule = ParserRule::rtr_set_member_choice;
    }

    impl MemberAfi for Any {
        const RTR_SET_MEMBER_RULE: ParserRule = ParserRule::rtr_set_mp_member_choice;
    }

    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    pub enum Member<A: MemberAfi> {
        /// An `rtr-set` member wrapping a literal IP address.
        Addr(IpAddress<A>),
        /// An `rtr-set` member wrapping an `inet-rtr` name.
        InetRtr(InetRtr),
        /// An `rtr-set` member wrapping an `rtr-set` name.
        RtrSet(RtrSet),
    }

    impl_from_str! {
        forall A: MemberAfi {
            A::RTR_SET_MEMBER_RULE => Member<A>
        }
    }

    impl<A: MemberAfi> TryFrom<TokenPair<'_>> for Member<A> {
        type Error = ParseError;

        fn try_from(pair: TokenPair) -> ParseResult<Self> {
            debug_construction!(pair => Member);
            match pair.as_rule() {
                rule if rule == A::LITERAL_ADDR_RULE => Ok(Self::Addr(pair.try_into()?)),
                ParserRule::inet_rtr => Ok(Self::InetRtr(pair.try_into()?)),
                ParserRule::rtr_set => Ok(Self::RtrSet(pair.try_into()?)),
                _ => Err(rule_mismatch!(pair => "rtr-set member")),
            }
        }
    }

    impl<A: MemberAfi> fmt::Display for Member<A> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::Addr(addr) => addr.fmt(f),
                Self::InetRtr(inet_rtr) => inet_rtr.fmt(f),
                Self::RtrSet(rtr_set) => rtr_set.fmt(f),
            }
        }
    }

    #[cfg(any(test, feature = "arbitrary"))]
    impl<A: MemberAfi> Arbitrary for Member<A>
    where
        A: fmt::Debug + Clone + 'static,
        A::Address: Arbitrary,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{compare_ast, display_fmt_parses};

    display_fmt_parses! {
        AsSetMember,
        RouteSetMember,
        RouteSetMpMember,
        RtrSetMember,
        RtrSetMpMember,
    }

    compare_ast! {
        RouteSetMember {
            rfc2622_fig13_route_set_example1: "128.9.0.0/16" => {
                RouteSetMember::new (
                    route_set::MemberElem::Prefix("128.9.0.0/16".parse().unwrap()),
                    RangeOperator::None,
                )
            }
            rfc2622_fig13_route_set_example2: "rs-foo" => {
                RouteSetMember::new(
                    route_set::MemberElem::RouteSet("rs-foo".parse().unwrap()),
                    RangeOperator::None,
                )
            }
            rfc2622_fig13_route_set_example3_1: "5.0.0.0/8^+" => {
                RouteSetMember::new(
                    route_set::MemberElem::Prefix("5.0.0.0/8".parse().unwrap()),
                    RangeOperator::LessIncl,
                )
            }
            rfc2622_fig13_route_set_example3_2: "30.0.0.0/8^24-32" => {
                RouteSetMember::new(
                    route_set::MemberElem::Prefix("30.0.0.0/8".parse().unwrap()),
                    RangeOperator::Range(24, 32),
                )
            }
            rfc2622_fig13_route_set_example3_3: "rs-foo^+" => {
                RouteSetMember::new(
                    route_set::MemberElem::RouteSet("rs-foo".parse().unwrap()),
                    RangeOperator::LessIncl,
                )
            }
            rfc2622_fig15_route_set_example_1: "AS1" => {
                RouteSetMember::new(
                    route_set::MemberElem::AutNum("AS1".parse().unwrap()),
                    RangeOperator::None,
                )
            }
            rfc2622_fig15_route_set_example_2: "AS-FOO" => {
                RouteSetMember::new(
                    route_set::MemberElem::AsSet("AS-FOO".parse().unwrap()),
                    RangeOperator::None,
                )
            }
        }
        RouteSetMpMember {
            rfc4012_sect4_2_route_set_example_1: "rs-bar" => {
                RouteSetMpMember::new(
                    route_set::MemberElem::RouteSet("rs-bar".parse().unwrap()),
                    RangeOperator::None,
                )
            }
            rfc4012_sect4_2_route_set_example_2: "2001:0DB8::/32" => {
                RouteSetMpMember::new(
                    route_set::MemberElem::Prefix("2001:0DB8::/32".parse().unwrap()),
                    RangeOperator::None,
                )
            }
            rfc4012_sect4_2_route_set_example_3: "192.0.2.0/24" => {
                RouteSetMpMember::new(
                    route_set::MemberElem::Prefix("192.0.2.0/24".parse().unwrap()),
                    RangeOperator::None,
                )
            }
        }
    }
}
