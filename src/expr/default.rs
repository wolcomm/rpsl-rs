use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    addr_family::{afi, LiteralPrefixSetAfi},
    error::{ParseError, ParseResult},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
};

use super::{filter, peering, ActionExpr};

/// RPSL `default` expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-6.5
pub type DefaultExpr = Expr<afi::Ipv4>;
impl_from_str!(ParserRule::just_default_expr => DefaultExpr);

/// RPSL `mp-default` expression. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.5
pub type MpDefaultExpr = Expr<afi::Any>;
impl_from_str!(ParserRule::just_mp_default_expr => MpDefaultExpr);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Expr<A: LiteralPrefixSetAfi> {
    peering: peering::Expr<A>,
    action: Option<ActionExpr>,
    networks: Option<filter::Expr<A>>,
}

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for Expr<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            rule if rule == A::DEFAULT_EXPR_RULE => {
                let mut pairs = pair.into_inner();
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
                    peering,
                    action,
                    networks,
                })
            }
            _ => Err(rule_mismatch!(pair => "default expression")),
        }
    }
}

impl<A: LiteralPrefixSetAfi> fmt::Display for Expr<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "to {}", self.peering)?;
        if let Some(action) = &self.action {
            write!(f, " action {}", action)?;
        }
        if let Some(networks) = &self.networks {
            write!(f, " networks {}", networks)?;
        }
        Ok(())
    }
}

// TODO: impl Arbitrary for Expr

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::compare_ast;

    compare_ast! {
        DefaultExpr {
            rfc2622_sect6_example1: "to AS2" => {
                DefaultExpr {
                    peering: "AS2".parse().unwrap(),
                    action: None,
                    networks: None,
                }
            }
            rfc2622_sect6_example2: "to AS2 7.7.7.2 at 7.7.7.1" => {
                DefaultExpr {
                    peering: "AS2 7.7.7.2 at 7.7.7.1".parse().unwrap(),
                    action: None,
                    networks: None,
                }
            }
            rfc2622_sect6_example3: "to AS2 action pref = 1;" => {
                DefaultExpr {
                    peering: "AS2".parse().unwrap(),
                    action: Some("pref = 1;".parse().unwrap()),
                    networks: None,
                }
            }
            rfc2622_sect6_example4: "to AS2 networks { 128.9.0.0/16 }" => {
                DefaultExpr {
                    peering: "AS2".parse().unwrap(),
                    action: None,
                    networks: Some("{ 128.9.0.0/16 }".parse().unwrap()),
                }
            }
        }
    }
}
