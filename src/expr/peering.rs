use std::convert::{TryFrom, TryInto};
use std::fmt;

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

use crate::{
    addr_family::{afi, LiteralPrefixSetAfi},
    error::{ParseError, ParseResult},
    names::PeeringSet,
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
};

use super::{rtr, AsExpr};

/// RPSL `peering` expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.6
pub type PeeringExpr = Expr<afi::Ipv4>;
impl_from_str!(ParserRule::just_peering_expr => Expr<afi::Ipv4>);

/// RPSL `mp-peering` expression. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.5.1
pub type MpPeeringExpr = Expr<afi::Any>;
impl_from_str!(ParserRule::just_mp_peering_expr => Expr<afi::Any>);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Expr<A: LiteralPrefixSetAfi> {
    Named(PeeringSet),
    Literal(LiteralPeering<A>),
}

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for Expr<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
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

impl<A: LiteralPrefixSetAfi> fmt::Display for Expr<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Named(peering_set) => peering_set.fmt(f),
            Self::Literal(literal) => literal.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A: LiteralPrefixSetAfi> Arbitrary for Expr<A>
where
    A: Clone + fmt::Debug + 'static,
    A::Addr: Arbitrary,
    <A::Addr as Arbitrary>::Strategy: 'static,
    <A::Addr as Arbitrary>::Parameters: Clone,
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

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct LiteralPeering<A: LiteralPrefixSetAfi> {
    as_expr: AsExpr,
    remote_rtr: Option<rtr::Expr<A>>,
    local_rtr: Option<rtr::Expr<A>>,
}

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for LiteralPeering<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
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
                            )
                        }
                        rule if rule == A::LOCAL_RTR_EXPR_RULE => {
                            local_rtr = Some(
                                next_into_or!(inner_pair.into_inner() => "failed to get local inet-rtr expression")?,
                            )
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

impl<A: LiteralPrefixSetAfi> fmt::Display for LiteralPeering<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_expr)?;
        if let Some(rtr_expr) = &self.remote_rtr {
            write!(f, " {}", rtr_expr)?;
        }
        if let Some(rtr_expr) = &self.local_rtr {
            write!(f, " AT {}", rtr_expr)?;
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A: LiteralPrefixSetAfi> Arbitrary for LiteralPeering<A>
where
    A: Clone + fmt::Debug + 'static,
    A::Addr: Arbitrary,
    <A::Addr as Arbitrary>::Strategy: 'static,
    <A::Addr as Arbitrary>::Parameters: Clone,
{
    type Parameters = (ParamsFor<AsExpr>, ParamsFor<Option<rtr::Expr<A>>>);
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            any_with::<AsExpr>(params.0),
            any_with::<Option<rtr::Expr<A>>>(params.1.clone()),
            any_with::<Option<rtr::Expr<A>>>(params.1.clone()),
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
