use std::convert::{TryFrom, TryInto};
use std::fmt;

use ip::{Any, Ipv4};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

use crate::{
    error::{ParseError, ParseResult},
    names::{InetRtr, RtrSet},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::{IpAddress, ParserAfi},
};

pub trait ExprAfi: ParserAfi {
    /// Address family specific [`ParserRule`] for unit router expressions.
    const RTR_EXPR_UNIT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for unit router expressions.
    const RTR_EXPR_AND_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for conjunctive router expressions.
    const RTR_EXPR_OR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for exclusive router expressions.
    const RTR_EXPR_EXCEPT_RULE: ParserRule;
    /// Array of address family specific [`ParserRule`] for router expressions.
    const RTR_EXPR_RULES: [ParserRule; 4] = [
        Self::RTR_EXPR_UNIT_RULE,
        Self::RTR_EXPR_AND_RULE,
        Self::RTR_EXPR_OR_RULE,
        Self::RTR_EXPR_EXCEPT_RULE,
    ];
    /// Check whether a [`ParserRule`] variant is a `router` expression for
    /// this address family.
    fn match_rtr_expr_rule(rule: ParserRule) -> bool {
        Self::RTR_EXPR_RULES
            .iter()
            .any(|rtr_expr_rule| &rule == rtr_expr_rule)
    }
}

impl ExprAfi for Ipv4 {
    const RTR_EXPR_UNIT_RULE: ParserRule = ParserRule::rtr_expr_unit;
    const RTR_EXPR_AND_RULE: ParserRule = ParserRule::rtr_expr_and;
    const RTR_EXPR_OR_RULE: ParserRule = ParserRule::rtr_expr_or;
    const RTR_EXPR_EXCEPT_RULE: ParserRule = ParserRule::rtr_expr_except;
}

impl ExprAfi for Any {
    const RTR_EXPR_UNIT_RULE: ParserRule = ParserRule::mp_rtr_expr_unit;
    const RTR_EXPR_AND_RULE: ParserRule = ParserRule::mp_rtr_expr_and;
    const RTR_EXPR_OR_RULE: ParserRule = ParserRule::mp_rtr_expr_or;
    const RTR_EXPR_EXCEPT_RULE: ParserRule = ParserRule::mp_rtr_expr_except;
}

/// RPSL `router-expression`. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.6
pub type RtrExpr = Expr<Ipv4>;
impl_from_str!(ParserRule::just_rtr_expr => RtrExpr);

/// RPSL `mp-router-expression`. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.5.1
pub type MpRtrExpr = Expr<Any>;
impl_from_str!(ParserRule::just_mp_rtr_expr => MpRtrExpr);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Expr<A: ExprAfi> {
    Unit(Term<A>),
    And(Term<A>, Box<Expr<A>>),
    Or(Term<A>, Box<Expr<A>>),
    Except(Term<A>, Box<Expr<A>>),
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for Expr<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            rule if rule == A::RTR_EXPR_UNIT_RULE => Ok(Self::Unit(
                next_into_or!(pair.into_inner() => "failed to get inet-rtr expression term")?,
            )),
            rule if rule == A::RTR_EXPR_AND_RULE => {
                let mut pairs = pair.into_inner();
                Ok(Self::And(
                    next_into_or!(pairs => "failed to get left hand inet-rtr expression term")?,
                    Box::new(
                        next_into_or!(pairs => "failed to get right hand inet-rtr expression")?,
                    ),
                ))
            }
            rule if rule == A::RTR_EXPR_OR_RULE => {
                let mut pairs = pair.into_inner();
                Ok(Self::Or(
                    next_into_or!(pairs => "failed to get left hand inet-rtr expression term")?,
                    Box::new(
                        next_into_or!(pairs => "failed to get right hand inet-rtr expression")?,
                    ),
                ))
            }
            rule if rule == A::RTR_EXPR_EXCEPT_RULE => {
                let mut pairs = pair.into_inner();
                Ok(Self::Except(
                    next_into_or!(pairs => "failed to get left hand inet-rtr expression term")?,
                    Box::new(
                        next_into_or!(pairs => "failed to get right hand inet-rtr expression")?,
                    ),
                ))
            }
            _ => Err(rule_mismatch!(pair => "inet-rtr expression")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for Expr<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Unit(term) => term.fmt(f),
            Self::And(lhs, rhs) => write!(f, "{} AND {}", lhs, rhs),
            Self::Or(lhs, rhs) => write!(f, "{} OR {}", lhs, rhs),
            Self::Except(lhs, rhs) => write!(f, "{} EXCEPT {}", lhs, rhs),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A: ExprAfi> Arbitrary for Expr<A>
where
    A: fmt::Debug + Clone + 'static,
    Term<A>: Arbitrary,
    <Term<A> as Arbitrary>::Parameters: Clone,
    <Term<A> as Arbitrary>::Strategy: Clone,
{
    type Parameters = ParamsFor<Term<A>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        let term = any_with::<Term<A>>(params.clone());
        any_with::<Term<A>>(params)
            .prop_map(Self::Unit)
            .prop_recursive(2, 4, 4, move |unit| {
                prop_oneof![
                    (term.clone(), unit.clone())
                        .prop_map(|(term, unit)| Self::And(term, Box::new(unit))),
                    (term.clone(), unit.clone())
                        .prop_map(|(term, unit)| Self::Or(term, Box::new(unit))),
                    (term.clone(), unit.clone())
                        .prop_map(|(term, unit)| Self::Except(term, Box::new(unit))),
                ]
            })
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Term<A: ExprAfi> {
    RtrSet(RtrSet),
    InetRtr(InetRtr),
    Literal(IpAddress<A>),
    Expr(Box<Expr<A>>),
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for Term<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Term);
        match pair.as_rule() {
            ParserRule::rtr_set => Ok(Self::RtrSet(pair.try_into()?)),
            ParserRule::inet_rtr => Ok(Self::InetRtr(pair.try_into()?)),
            rule if rule == A::LITERAL_ADDR_RULE => Ok(Self::Literal(pair.try_into()?)),
            rule if A::match_rtr_expr_rule(rule) => Ok(Self::Expr(Box::new(pair.try_into()?))),
            _ => Err(rule_mismatch!(pair => "inet-rtr expression term")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for Term<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::RtrSet(rtr_set) => rtr_set.fmt(f),
            Self::InetRtr(inet_rtr) => inet_rtr.fmt(f),
            Self::Literal(addr) => addr.fmt(f),
            Self::Expr(expr) => write!(f, "({})", expr),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A: ExprAfi> Arbitrary for Term<A>
where
    A: fmt::Debug + 'static,
    A::Address: Arbitrary,
{
    type Parameters = ParamsFor<IpAddress<A>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<RtrSet>().prop_map(Self::RtrSet),
            any::<InetRtr>().prop_map(Self::InetRtr),
            any_with::<IpAddress<A>>(params).prop_map(Self::Literal),
        ]
        .prop_recursive(2, 4, 4, |inner| {
            prop_oneof![
                inner.clone().prop_map(Expr::Unit),
                (inner.clone(), inner.clone())
                    .prop_map(|(lhs, rhs)| Expr::And(lhs, Box::new(Expr::Unit(rhs)))),
                (inner.clone(), inner.clone())
                    .prop_map(|(lhs, rhs)| Expr::Or(lhs, Box::new(Expr::Unit(rhs)))),
                (inner.clone(), inner.clone())
                    .prop_map(|(lhs, rhs)| Expr::Except(lhs, Box::new(Expr::Unit(rhs)))),
            ]
            .prop_map(|expr| Self::Expr(Box::new(expr)))
        })
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{compare_ast, display_fmt_parses};

    display_fmt_parses! {
        RtrExpr,
        MpRtrExpr,
    }

    compare_ast! {
        RtrExpr {
            rfc2622_sect5_6_autnum_example1: "7.7.7.2" => {
                RtrExpr::Unit(Term::Literal("7.7.7.2".parse().unwrap()))
            }
            rfc2622_sect5_6_autnum_example2: "7.7.7.1" => {
                RtrExpr::Unit(Term::Literal("7.7.7.1".parse().unwrap()))
            }
            // the 'NOT' operator is invalid for rtr expressions.
            // accordingly, the following example taken from rfc2622
            // section 5.6 is invalid:
            //
            // rfc2622_sect5_6_autnum_example6: "not 7.7.7.1" => {
            //     RtrExpr::Unit(Term::Expr)
            // }
        }
    }

    compare_ast! {
        MpRtrExpr {
            mp_rtr_addr_literal_ipv4: "192.0.2.10" => {
                MpRtrExpr::Unit(Term::Literal("192.0.2.10".parse().unwrap()))
            }
            mp_rtr_addr_literal_ipv6: "a000::" => {
                MpRtrExpr::Unit(Term::Literal("a000::".parse().unwrap()))
            }
        }
    }
}
