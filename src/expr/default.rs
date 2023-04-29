use std::fmt;

use ip::{Any, Ipv4};

use crate::{
    containers::ListOf,
    error::{ParseError, ParseResult},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::AfiSafi,
};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

use super::{filter, peering, ActionExpr};

#[cfg(any(test, feature = "arbitrary"))]
use super::arbitrary::AfiSafiList;

pub trait ExprAfi: filter::ExprAfi + peering::ExprAfi {
    /// Address family specific [`ParserRule`] for `default` expressions.
    const DEFAULT_EXPR_RULE: ParserRule;
}

impl ExprAfi for Ipv4 {
    const DEFAULT_EXPR_RULE: ParserRule = ParserRule::default_expr;
}

impl ExprAfi for Any {
    const DEFAULT_EXPR_RULE: ParserRule = ParserRule::mp_default_expr;
}

/// RPSL `default` expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-6.5
#[allow(clippy::module_name_repetitions)]
pub type DefaultExpr = Expr<Ipv4>;
impl_from_str!(ParserRule::just_default_expr => DefaultExpr);

/// RPSL `mp-default` expression. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.5
pub type MpDefaultExpr = Expr<Any>;
impl_from_str!(ParserRule::just_mp_default_expr => MpDefaultExpr);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Expr<A: ExprAfi> {
    afis: Option<ListOf<AfiSafi>>,
    peering: peering::Expr<A>,
    action: Option<ActionExpr>,
    networks: Option<filter::Expr<A>>,
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for Expr<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            rule if rule == A::DEFAULT_EXPR_RULE => {
                let mut pairs = pair.into_inner().peekable();
                let afis =
                    if pairs.peek().map(TokenPair::as_rule) == Some(ParserRule::afi_safi_list) {
                        Some(next_into_or!(pairs => "failed to get afi list")?)
                    } else {
                        None
                    };
                let peering = next_into_or!(pairs => "failed to get peering expression")?;
                let (mut action, mut networks) = (None, None);
                for pair in pairs {
                    match pair.as_rule() {
                        ParserRule::action_expr => {
                            action = Some(pair.try_into()?);
                        }
                        rule if A::match_filter_expr_rule(rule) => {
                            networks = Some(pair.try_into()?);
                        }
                        _ => return Err(rule_mismatch!(pair => "default expression element")),
                    }
                }
                Ok(Self {
                    afis,
                    peering,
                    action,
                    networks,
                })
            }
            _ => Err(rule_mismatch!(pair => "default expression")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for Expr<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(afis) = &self.afis {
            write!(f, "afi {afis} ")?;
        }
        write!(f, "to {}", self.peering)?;
        if let Some(action) = &self.action {
            write!(f, " action {action}")?;
        }
        if let Some(networks) = &self.networks {
            write!(f, " networks {networks}")?;
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for Expr<A>
where
    A: AfiSafiList + 'static,
    A::Address: Arbitrary,
    <A::Address as Arbitrary>::Parameters: Clone,
    <A::Address as Arbitrary>::Strategy: 'static,
    A::Prefix: Arbitrary,
    <A::Prefix as Arbitrary>::Parameters: Clone,
    <A::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
    A::PrefixLength: AsRef<u8>,
{
    type Parameters = (
        ParamsFor<Option<ListOf<AfiSafi>>>,
        ParamsFor<peering::Expr<A>>,
        ParamsFor<Option<ActionExpr>>,
        ParamsFor<Option<filter::Expr<A>>>,
    );
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            A::any_afis(params.0),
            any_with::<peering::Expr<A>>(params.1),
            any_with::<Option<ActionExpr>>(params.2),
            any_with::<Option<filter::Expr<A>>>(params.3),
        )
            .prop_map(|(afis, peering, action, networks)| Self {
                afis,
                peering,
                action,
                networks,
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{compare_ast, display_fmt_parses};

    display_fmt_parses! {
        DefaultExpr,
        MpDefaultExpr,
    }

    compare_ast! {
        DefaultExpr {
            rfc2622_sect6_example1: "to AS2" => {
                DefaultExpr {
                    afis: None,
                    peering: "AS2".parse().unwrap(),
                    action: None,
                    networks: None,
                }
            }
            rfc2622_sect6_example2: "to AS2 7.7.7.2 at 7.7.7.1" => {
                DefaultExpr {
                    afis: None,
                    peering: "AS2 7.7.7.2 at 7.7.7.1".parse().unwrap(),
                    action: None,
                    networks: None,
                }
            }
            rfc2622_sect6_example3: "to AS2 action pref = 1;" => {
                DefaultExpr {
                    afis: None,
                    peering: "AS2".parse().unwrap(),
                    action: Some("pref = 1;".parse().unwrap()),
                    networks: None,
                }
            }
            rfc2622_sect6_example4: "to AS2 networks { 128.9.0.0/16 }" => {
                DefaultExpr {
                    afis: None,
                    peering: "AS2".parse().unwrap(),
                    action: None,
                    networks: Some("{ 128.9.0.0/16 }".parse().unwrap()),
                }
            }
        }
    }
}
