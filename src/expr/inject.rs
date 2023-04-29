use std::fmt;

use ip::{Any, Ipv4, Ipv6};

use crate::{
    containers::ListOf,
    error::{ParseError, ParseResult},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::{IpPrefixRange, ParserAfi},
};

use super::{
    action,
    rtr::{self, ExprAfi as _},
};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

/// RPSL `inject` expression for `route` objects. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-8.1
#[allow(clippy::module_name_repetitions)]
pub type InjectExpr = Expr<Ipv4>;
impl_from_str!(ParserRule::just_inject_expr => InjectExpr);

/// RPSL `inject` expression for `route6` objects. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-3
#[allow(clippy::module_name_repetitions)]
pub type Inject6Expr = Expr<Ipv6>;
impl_from_str!(ParserRule::just_inject6_expr => Inject6Expr);

pub trait ExprAfi: ParserAfi {
    /// Address family of contained `rtr-expression`.
    type RtrExprAfi: rtr::ExprAfi;
    /// Address family specific [`ParserRule`] for inject expressions.
    const INJECT_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for unit inject expressions.
    const INJECT_COND_UNIT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for conjunctive inject expressions.
    const INJECT_COND_AND_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for disjunctive inject expressions.
    const INJECT_COND_OR_RULE: ParserRule;
    /// Array of address family specific [`ParserRule`] for inject expressions.
    const INJECT_COND_RULES: [ParserRule; 3] = [
        Self::INJECT_COND_UNIT_RULE,
        Self::INJECT_COND_AND_RULE,
        Self::INJECT_COND_OR_RULE,
    ];
    /// Check whether a [`ParserRule`] variant is an `inject` expression for
    /// this address family.
    fn match_inject_condition_rule(rule: ParserRule) -> bool {
        Self::INJECT_COND_RULES
            .iter()
            .any(|inject_cond_rule| &rule == inject_cond_rule)
    }
    /// Address family specific [`ParserRule`] for inject `have-components`
    /// condition term.
    const INJECT_COND_TERM_HAVE_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for inject `exclude` condition
    /// term.
    const INJECT_COND_TERM_EXCLUDE_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for inject `static` condition
    /// term.
    const INJECT_COND_TERM_STATIC_RULE: ParserRule;
}

impl ExprAfi for Ipv4 {
    type RtrExprAfi = Self;
    const INJECT_EXPR_RULE: ParserRule = ParserRule::inject_expr;
    const INJECT_COND_UNIT_RULE: ParserRule = ParserRule::inject_cond_unit;
    const INJECT_COND_AND_RULE: ParserRule = ParserRule::inject_cond_and;
    const INJECT_COND_OR_RULE: ParserRule = ParserRule::inject_cond_or;
    const INJECT_COND_TERM_HAVE_RULE: ParserRule = ParserRule::inject_cond_term_have;
    const INJECT_COND_TERM_EXCLUDE_RULE: ParserRule = ParserRule::inject_cond_term_excl;
    const INJECT_COND_TERM_STATIC_RULE: ParserRule = ParserRule::inject_cond_term_stat;
}

impl ExprAfi for Ipv6 {
    // TODO: impl rtr::ExprAfi for Ipv6 and remove this type
    type RtrExprAfi = Any;
    const INJECT_EXPR_RULE: ParserRule = ParserRule::inject6_expr;
    const INJECT_COND_UNIT_RULE: ParserRule = ParserRule::inject6_cond_unit;
    const INJECT_COND_AND_RULE: ParserRule = ParserRule::inject6_cond_and;
    const INJECT_COND_OR_RULE: ParserRule = ParserRule::inject6_cond_or;
    const INJECT_COND_TERM_HAVE_RULE: ParserRule = ParserRule::inject6_cond_term_have;
    const INJECT_COND_TERM_EXCLUDE_RULE: ParserRule = ParserRule::inject6_cond_term_excl;
    const INJECT_COND_TERM_STATIC_RULE: ParserRule = ParserRule::inject6_cond_term_stat;
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Expr<A: ExprAfi> {
    at: Option<rtr::Expr<A::RtrExprAfi>>,
    action: Option<action::Expr>,
    condition: Option<Condition<A>>,
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for Expr<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            rule if rule == A::INJECT_EXPR_RULE => {
                let (mut at, mut action, mut condition) = (None, None, None);
                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        rule if A::RtrExprAfi::match_rtr_expr_rule(rule) => {
                            at = Some(inner_pair.try_into()?);
                        }
                        ParserRule::action_expr => {
                            action = Some(inner_pair.try_into()?);
                        }
                        rule if A::match_inject_condition_rule(rule) => {
                            condition = Some(inner_pair.try_into()?);
                        }
                        _ => return Err(rule_mismatch!(inner_pair => "inject expression element")),
                    }
                }
                Ok(Self {
                    at,
                    action,
                    condition,
                })
            }
            _ => Err(rule_mismatch!(pair => "inject expression")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for Expr<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut statements = Vec::new();
        if let Some(rtr_expr) = &self.at {
            statements.push(format!("at {rtr_expr}"));
        }
        if let Some(action_expr) = &self.action {
            statements.push(format!("action {action_expr}"));
        }
        if let Some(condition) = &self.condition {
            statements.push(format!("upon {condition}"));
        }
        statements.join(" ").fmt(f)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for Expr<A>
where
    A: ExprAfi + 'static,
    A::RtrExprAfi: 'static,
    A::Prefix: Arbitrary,
    <A::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
    A::PrefixLength: AsRef<u8>,
    <A::RtrExprAfi as ip::AfiClass>::Address: Arbitrary,
    <<A::RtrExprAfi as ip::AfiClass>::Address as Arbitrary>::Parameters: Clone,
    <<A::RtrExprAfi as ip::AfiClass>::Address as Arbitrary>::Strategy: 'static,
    <<A::RtrExprAfi as ip::AfiClass>::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
    <A::RtrExprAfi as ip::AfiClass>::PrefixLength: AsRef<u8>,
{
    type Parameters = (
        ParamsFor<Option<rtr::Expr<A::RtrExprAfi>>>,
        ParamsFor<Option<action::Expr>>,
        ParamsFor<Option<Condition<A>>>,
    );
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            any_with::<Option<rtr::Expr<A::RtrExprAfi>>>(params.0),
            any_with::<Option<action::Expr>>(params.1),
            any_with::<Option<Condition<A>>>(params.2),
        )
            .prop_map(|(at, action, condition)| Self {
                at,
                action,
                condition,
            })
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Condition<A: ExprAfi> {
    Unit(Term<A>),
    And(Term<A>, Term<A>),
    Or(Term<A>, Term<A>),
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for Condition<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => Condition);
        match pair.as_rule() {
            rule if rule == A::INJECT_COND_UNIT_RULE => Ok(Self::Unit(
                next_into_or!(pair.into_inner() => "failed to get inject condition term")?,
            )),
            rule if rule == A::INJECT_COND_AND_RULE => {
                let mut pairs = pair.into_inner();
                Ok(Self::And(
                    next_into_or!(pairs => "failed to get left inject condition term")?,
                    next_into_or!(pairs => "failed to get right inject condition term")?,
                ))
            }
            rule if rule == A::INJECT_COND_OR_RULE => {
                let mut pairs = pair.into_inner();
                Ok(Self::Or(
                    next_into_or!(pairs => "failed to get left inject condition term")?,
                    next_into_or!(pairs => "failed to get right inject condition term")?,
                ))
            }
            _ => Err(rule_mismatch!(pair => "inject condition")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for Condition<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unit(term) => term.fmt(f),
            Self::And(lhs, rhs) => write!(f, "{lhs} AND {rhs}"),
            Self::Or(lhs, rhs) => write!(f, "{lhs} OR {rhs}"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for Condition<A>
where
    A: ExprAfi + 'static,
    A::Prefix: Arbitrary,
    <A::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
    A::PrefixLength: AsRef<u8>,
{
    type Parameters = ParamsFor<Term<A>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        let term = any_with::<Term<A>>(params);
        prop_oneof![
            term.clone().prop_map(Self::Unit),
            (term.clone(), term.clone()).prop_map(|(lhs, rhs)| Self::And(lhs, rhs)),
            (term.clone(), term).prop_map(|(lhs, rhs)| Self::Or(lhs, rhs)),
        ]
        .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Term<A: ExprAfi> {
    HaveComps(ListOf<IpPrefixRange<A>>),
    Exclude(ListOf<IpPrefixRange<A>>),
    Static,
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for Term<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => Term);
        match pair.as_rule() {
            rule if rule == A::INJECT_COND_TERM_HAVE_RULE => Ok(Self::HaveComps(
                next_into_or!(pair.into_inner() => "failed to get inject have-components condition prefix ranges")?,
            )),
            rule if rule == A::INJECT_COND_TERM_EXCLUDE_RULE => Ok(Self::Exclude(
                next_into_or!(pair.into_inner() => "failed to get inject exclude condition prefix ranges")?,
            )),
            rule if rule == A::INJECT_COND_TERM_STATIC_RULE => Ok(Self::Static),
            _ => Err(rule_mismatch!(pair => "inject condition term")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for Term<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HaveComps(prefixes) => write!(f, "have-components {{{prefixes}}}"),
            Self::Exclude(prefixes) => write!(f, "exclude {{{prefixes}}}"),
            Self::Static => write!(f, "static"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for Term<A>
where
    A: ExprAfi + 'static,
    A::Prefix: Arbitrary,
    <A::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
    A::PrefixLength: AsRef<u8>,
{
    type Parameters = ParamsFor<ListOf<IpPrefixRange<A>>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        let prefix_range_list = any_with::<ListOf<IpPrefixRange<A>>>(params);
        prop_oneof![
            prefix_range_list.clone().prop_map(Self::HaveComps),
            prefix_range_list.prop_map(Self::Exclude),
            Just(Self::Static),
        ]
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        primitive::RangeOperator,
        tests::{compare_ast, display_fmt_parses},
    };

    display_fmt_parses! {
        InjectExpr,
        Inject6Expr,
    }

    compare_ast! {
        InjectExpr {
            rfc2622_fig32_route_example1_1: "at 1.1.1.1 action dpa = 100;" => {
                InjectExpr {
                    at: Some("1.1.1.1".parse().unwrap()),
                    action: Some("dpa = 100;".parse().unwrap()),
                    condition: None,
                }
            }
            rfc2622_fig32_route_example1_2: "at 1.1.1.2 action dpa = 110;" => {
                InjectExpr {
                    at: Some("1.1.1.2".parse().unwrap()),
                    action: Some("dpa = 110;".parse().unwrap()),
                    condition: None,
                }
            }
            rfc2622_fig32_route_example2: "upon HAVE-COMPONENTS {128.8.0.0/16, 128.9.0.0/16}" => {
                InjectExpr {
                    at: None,
                    action: None,
                    condition: Some(Condition::Unit(Term::HaveComps(vec![
                        IpPrefixRange::new("128.8.0.0/16".parse().unwrap(), RangeOperator::None),
                        IpPrefixRange::new("128.9.0.0/16".parse().unwrap(), RangeOperator::None),
                    ].into_iter().collect())))
                }
            }
            rfc2622_sect8_2_route_example1: "at 7.7.7.1 action next-hop = 7.7.7.2; cost = 10; upon static" => {
                InjectExpr {
                    at: Some("7.7.7.1".parse().unwrap()),
                    action: Some("next-hop = 7.7.7.2; cost = 10;".parse().unwrap()),
                    condition: Some(Condition::Unit(Term::Static)),
                }
            }
            rfc2622_sect8_2_route_example2: "at 7.7.7.1 action next-hop = 7.7.7.3; cost = 20; upon static" => {
                InjectExpr {
                    at: Some("7.7.7.1".parse().unwrap()),
                    action: Some("next-hop = 7.7.7.3; cost = 20;".parse().unwrap()),
                    condition: Some(Condition::Unit(Term::Static)),
                }
            }
        }
    }
}
