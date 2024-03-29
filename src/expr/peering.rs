use std::fmt;

use ip::{Any, Ipv4};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

use crate::{
    error::{ParseError, ParseResult},
    names::PeeringSet,
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
};

use super::{rtr, AsExpr};

pub trait ExprAfi: rtr::ExprAfi {
    /// Address family specific [`ParserRule`] for remote router expressions.
    const REMOTE_RTR_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for local router expressions.
    const LOCAL_RTR_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for literal peering expressions.
    const PEERING_EXPR_LITERAL_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for named peering expressions.
    const PEERING_EXPR_NAMED_RULE: ParserRule;
    /// Array of address family specific [`ParserRule`] for peering expressions.
    const PEERING_EXPR_RULES: [ParserRule; 2] = [
        Self::PEERING_EXPR_NAMED_RULE,
        Self::PEERING_EXPR_LITERAL_RULE,
    ];
    /// Check whether a [`ParserRule`] variant is a `peering` expression for
    /// this address family.
    fn match_peering_expr_rule(rule: ParserRule) -> bool {
        Self::PEERING_EXPR_RULES
            .iter()
            .any(|peering_expr_rule| &rule == peering_expr_rule)
    }
}

impl ExprAfi for Ipv4 {
    const REMOTE_RTR_EXPR_RULE: ParserRule = ParserRule::remote_rtr_expr;
    const LOCAL_RTR_EXPR_RULE: ParserRule = ParserRule::local_rtr_expr;
    const PEERING_EXPR_LITERAL_RULE: ParserRule = ParserRule::peering_expr_literal;
    const PEERING_EXPR_NAMED_RULE: ParserRule = ParserRule::peering_expr_named;
}

impl ExprAfi for Any {
    const REMOTE_RTR_EXPR_RULE: ParserRule = ParserRule::remote_mp_rtr_expr;
    const LOCAL_RTR_EXPR_RULE: ParserRule = ParserRule::local_mp_rtr_expr;
    const PEERING_EXPR_LITERAL_RULE: ParserRule = ParserRule::mp_peering_expr_literal;
    const PEERING_EXPR_NAMED_RULE: ParserRule = ParserRule::mp_peering_expr_named;
}

/// RPSL `peering` expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.6
#[allow(clippy::module_name_repetitions)]
pub type PeeringExpr = Expr<Ipv4>;
impl_from_str!(ParserRule::just_peering_expr => Expr<Ipv4>);

/// RPSL `mp-peering` expression. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.5.1
pub type MpPeeringExpr = Expr<Any>;
impl_from_str!(ParserRule::just_mp_peering_expr => Expr<Any>);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Expr<A: ExprAfi> {
    Named(PeeringSet),
    Literal(LiteralPeering<A>),
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for Expr<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            rule if rule == A::PEERING_EXPR_NAMED_RULE => Ok(Self::Named(
                next_into_or!(pair.into_inner() => "failed to get peering-set name")?,
            )),
            rule if rule == A::PEERING_EXPR_LITERAL_RULE => Ok(Self::Literal(pair.try_into()?)),
            _ => Err(rule_mismatch!(pair => "peering expression")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for Expr<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(peering_set) => peering_set.fmt(f),
            Self::Literal(literal) => literal.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for Expr<A>
where
    A: ExprAfi + Clone + fmt::Debug + 'static,
    A::Address: Arbitrary,
    <A::Address as Arbitrary>::Parameters: Clone,
{
    type Parameters = ParamsFor<LiteralPeering<A>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<PeeringSet>().prop_map(Self::Named),
            any_with::<LiteralPeering<A>>(params).prop_map(Self::Literal),
        ]
        .boxed()
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct LiteralPeering<A: ExprAfi> {
    as_expr: AsExpr,
    remote_rtr: Option<rtr::Expr<A>>,
    local_rtr: Option<rtr::Expr<A>>,
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for LiteralPeering<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => LiteralPeering);
        match pair.as_rule() {
            rule if rule == A::PEERING_EXPR_LITERAL_RULE => {
                let mut pairs = pair.into_inner();
                let (mut remote_rtr, mut local_rtr) = (None, None);
                let as_expr = next_into_or!(pairs => "failed to get AS expression")?;
                for inner_pair in pairs {
                    match inner_pair.as_rule() {
                        rule if rule == A::REMOTE_RTR_EXPR_RULE => {
                            remote_rtr = Some(
                                next_into_or!(inner_pair.into_inner() => "failed to get remote inet-rtr expression")?,
                            );
                        }
                        rule if rule == A::LOCAL_RTR_EXPR_RULE => {
                            local_rtr = Some(
                                next_into_or!(inner_pair.into_inner() => "failed to get local inet-rtr expression")?,
                            );
                        }
                        _ => return Err(rule_mismatch!(inner_pair => "inet-rtr expression")),
                    }
                }
                Ok(Self {
                    as_expr,
                    remote_rtr,
                    local_rtr,
                })
            }
            _ => Err(rule_mismatch!(pair => "literal peering expression")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for LiteralPeering<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_expr)?;
        if let Some(rtr_expr) = &self.remote_rtr {
            write!(f, " {rtr_expr}")?;
        }
        if let Some(rtr_expr) = &self.local_rtr {
            write!(f, " AT {rtr_expr}")?;
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for LiteralPeering<A>
where
    A: ExprAfi + Clone + fmt::Debug + 'static,
    A::Address: Arbitrary,
    <A::Address as Arbitrary>::Parameters: Clone,
{
    type Parameters = ParamsFor<Option<rtr::Expr<A>>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            any::<AsExpr>(),
            any_with::<Option<rtr::Expr<A>>>(params.clone()),
            any_with::<Option<rtr::Expr<A>>>(params),
        )
            .prop_map(|(as_expr, remote_rtr, local_rtr)| Self {
                as_expr,
                remote_rtr,
                local_rtr,
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{compare_ast, display_fmt_parses};

    display_fmt_parses! {
        PeeringExpr,
        MpPeeringExpr,
    }

    compare_ast! {
        PeeringExpr {
            rfc2622_sect5_6_autnum_example1: "AS2 7.7.7.2 at 7.7.7.1" => {
                PeeringExpr::Literal(LiteralPeering {
                    as_expr: "AS2".parse().unwrap(),
                    remote_rtr: Some("7.7.7.2".parse().unwrap()),
                    local_rtr: Some("7.7.7.1".parse().unwrap()),
                })
            }
            rfc2622_sect5_6_autnum_example2: "AS2 at 7.7.7.1" => {
                PeeringExpr::Literal(LiteralPeering {
                    as_expr: "AS2".parse().unwrap(),
                    remote_rtr: None,
                    local_rtr: Some("7.7.7.1".parse().unwrap()),
                })
            }
            rfc2622_sect5_6_autnum_example3: "AS2" => {
                PeeringExpr::Literal(LiteralPeering {
                    as_expr: "AS2".parse().unwrap(),
                    remote_rtr: None,
                    local_rtr: None,
                })
            }
            rfc2622_sect5_6_autnum_example4: "AS-FOO at 9.9.9.1" => {
                PeeringExpr::Literal(LiteralPeering {
                    as_expr: "AS-FOO".parse().unwrap(),
                    remote_rtr: None,
                    local_rtr: Some("9.9.9.1".parse().unwrap()),
                })
            }
            rfc2622_sect5_6_autnum_example5: "AS-FOO" => {
                PeeringExpr::Literal(LiteralPeering {
                    as_expr: "AS-FOO".parse().unwrap(),
                    remote_rtr: None,
                    local_rtr: None,
                })
            }
            // the 'NOT' operator is invalid for rtr expressions.
            // accordingly, the following example taken from rfc2622
            // section 5.6 is invalid:
            //
            // rfc2622_sect5_6_autnum_example6: "AS-FOO and not AS2 at not 7.7.7.1" => {
            //     PeeringExpr::Literal(LiteralPeering {
            //         as_expr: "AS-FOO and not AS2".parse().unwrap(),
            //         remote_rtr: None,
            //         local_rtr: None,
            //     })
            // }
            rfc2622_sect5_6_autnum_example7: "prng-foo" => {
                PeeringExpr::Named("prng-foo".parse().unwrap())
            }
            rfc2622_sect5_6_peering_set_example7_1: "AS1 at 9.9.9.1" => {
                PeeringExpr::Literal(LiteralPeering {
                    as_expr: "AS1".parse().unwrap(),
                    remote_rtr: None,
                    local_rtr: Some(rtr::Expr::Unit(rtr::Term::Literal(
                        "9.9.9.1".parse().unwrap(),
                    ))),
                })
            }
            rfc2622_sect5_6_peering_set_example7_2: "prng-bar" => {
                PeeringExpr::Named("prng-bar".parse().unwrap())
            }
            rfc2622_sect6_autnum_example1: "AS2" => {
                PeeringExpr::Literal(LiteralPeering {
                    as_expr: "AS2".parse().unwrap(),
                    remote_rtr: None,
                    local_rtr: None,
                })
            }
            rfc2622_sect6_autnum_example3: "AS2 7.7.7.2 at 7.7.7.1" => {
                PeeringExpr::Literal(LiteralPeering {
                    as_expr: "AS2".parse().unwrap(),
                    remote_rtr: Some(rtr::Expr::Unit(rtr::Term::Literal(
                        "7.7.7.2".parse().unwrap()
                    ))),
                    local_rtr: Some(rtr::Expr::Unit(rtr::Term::Literal(
                        "7.7.7.1".parse().unwrap()
                    ))),
                })
            }
            rfc2622_fig37_peering_set_example: "AS3334 192.87.45.195" => {
                PeeringExpr::Literal(LiteralPeering {
                    as_expr: "AS3334".parse().unwrap(),
                    remote_rtr: Some(rtr::Expr::Unit(rtr::Term::Literal(
                        "192.87.45.195".parse().unwrap(),
                    ))),
                    local_rtr: None,
                })
            }
        }
    }

    compare_ast! {
        MpPeeringExpr {
            rfc4012_sect4_4_peering_set_example: "AS65002 2001:0DB8::1 at 2001:0DB8::2" => {
                MpPeeringExpr::Literal(LiteralPeering {
                    as_expr: "AS65002".parse().unwrap(),
                    remote_rtr: Some("2001:0DB8::1".parse().unwrap()),
                    local_rtr: Some("2001:0DB8::2".parse().unwrap()),
                })
            }
        }
    }
}
