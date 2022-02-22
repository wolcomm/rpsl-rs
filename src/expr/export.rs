use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    addr_family::{afi, LiteralPrefixSetAfi},
    error::{ParseError, ParseResult},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
};

use super::{filter, peering, ActionExpr, ProtocolDistribution};

/// RPSL `export` expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-6.2
pub type ExportExpr = Statement<afi::Ipv4>;
impl_from_str!(ParserRule::just_export_stmt => Statement<afi::Ipv4>);

/// RPSL `mp-export` expression. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.5
pub type MpExportExpr = Statement<afi::Any>;
impl_from_str!(ParserRule::just_mp_export_stmt => Statement<afi::Any>);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Statement<A: LiteralPrefixSetAfi> {
    protocol_dist: Option<ProtocolDistribution>,
    expr: Expr<A>,
}

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for Statement<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Statement);
        match pair.as_rule() {
            rule if rule == A::EXPORT_STMT_SIMPLE_RULE => Ok(Self {
                protocol_dist: None,
                expr: next_into_or!(pair.into_inner() => "failed to get export expression")?,
            }),
            rule if rule == A::EXPORT_STMT_PROTOCOL_RULE => {
                let mut pairs = pair.into_inner();
                let protocol_dist = Some(
                    next_into_or!(pairs => "failed to get protocol redistribution expression")?,
                );
                let expr = next_into_or!(pairs => "failed to get export expression")?;
                Ok(Self {
                    protocol_dist,
                    expr,
                })
            }
            _ => Err(rule_mismatch!(pair => "export statement")),
        }
    }
}

impl<A: LiteralPrefixSetAfi> fmt::Display for Statement<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(protocol_dist_expr) = &self.protocol_dist {
            write!(f, "{} ", protocol_dist_expr)?;
        }
        write!(f, "{}", self.expr)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Expr<A: LiteralPrefixSetAfi> {
    Unit(Term<A>),
    Except(Term<A>, Box<Expr<A>>),
    Refine(Term<A>, Box<Expr<A>>),
}

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for Expr<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            rule if rule == A::EXPORT_EXPR_UNIT_RULE => Ok(Self::Unit(
                next_into_or!(pair.into_inner() => "failed to get export term")?,
            )),
            rule if rule == A::EXPORT_EXPR_EXCEPT_RULE => {
                let mut pairs = pair.into_inner();
                let term = next_into_or!(pairs => "failed to get export term")?;
                let expr =
                    Box::new(next_into_or!(pairs => "failed to get inner export expression")?);
                Ok(Self::Except(term, expr))
            }
            rule if rule == A::EXPORT_EXPR_REFINE_RULE => {
                let mut pairs = pair.into_inner();
                let term = next_into_or!(pairs => "failed to get export term")?;
                let expr =
                    Box::new(next_into_or!(pairs => "failed to get inner export expression")?);
                Ok(Self::Refine(term, expr))
            }
            _ => Err(rule_mismatch!(pair => "export expression")),
        }
    }
}

impl<A: LiteralPrefixSetAfi> fmt::Display for Expr<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Unit(term) => term.fmt(f),
            Self::Except(term, expr) => write!(f, "{} EXCEPT {}", term, expr),
            Self::Refine(term, expr) => write!(f, "{} REFINE {}", term, expr),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Term<A: LiteralPrefixSetAfi>(Vec<Factor<A>>);

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for Term<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Term);
        match pair.as_rule() {
            rule if rule == A::EXPORT_TERM_RULE => Ok(Self(
                pair.into_inner()
                    .map(|inner_pair| inner_pair.try_into())
                    .collect::<ParseResult<_>>()?,
            )),
            _ => Err(rule_mismatch!(pair => "export expression term")),
        }
    }
}

impl<A: LiteralPrefixSetAfi> fmt::Display for Term<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0.len() <= 1 {
            self.0[0].fmt(f)
        } else {
            writeln!(f, "{{")?;
            self.0
                .iter()
                .try_for_each(|factor| writeln!(f, "{};", factor))?;
            writeln!(f, "}}")
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Factor<A: LiteralPrefixSetAfi> {
    peerings: Vec<(peering::Expr<A>, Option<ActionExpr>)>,
    filter: filter::Expr<A>,
}

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for Factor<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Factor);
        match pair.as_rule() {
            rule if rule == A::EXPORT_FACTOR_RULE => {
                let mut pairs = pair.into_inner().peekable();
                let mut peerings = Vec::new();
                while let Some(rule) = pairs.peek().map(|pair| pair.as_rule()) {
                    if !A::match_peering_expr_rule(rule) {
                        break;
                    }
                    let peering_expr = next_into_or!(pairs => "failed to get peering expression")?;
                    let action_expr = if let Some(ParserRule::action_expr) =
                        pairs.peek().map(|pair| pair.as_rule())
                    {
                        Some(next_into_or!(pairs => "failed to get action expression")?)
                    } else {
                        None
                    };
                    peerings.push((peering_expr, action_expr));
                }
                let filter = next_into_or!(pairs => "failed to get filter expression")?;
                Ok(Self { peerings, filter })
            }
            _ => Err(rule_mismatch!(pair => "export expression factor")),
        }
    }
}

impl<A: LiteralPrefixSetAfi> fmt::Display for Factor<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.peerings
            .iter()
            .try_for_each(|(peering_expr, action_expr)| {
                write!(f, "TO {}", peering_expr)?;
                if let Some(action_expr) = action_expr {
                    write!(f, " ACTION {}", action_expr)?;
                }
                Ok(())
            })?;
        write!(f, " ANNOUNCE {}", self.filter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::compare_ast;

    compare_ast! {
        ExportExpr {
            rfc2622_sect6_autnum_example1: "\
            to AS2 \
            action med = 5; community .= { 70 }; \
            announce AS4" => {
                ExportExpr {
                    protocol_dist: None,
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![("AS2".parse().unwrap(), Some("med = 5; community .= { 70 };".parse().unwrap()))],
                        filter: "AS4".parse().unwrap(),
                    }]))
                }
            }
            rfc2622_sect6_autnum_example2: "to AS-FOO announce ANY" => {
                ExportExpr {
                    protocol_dist: None,
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![("AS-FOO".parse().unwrap(), None)],
                        filter: "ANY".parse().unwrap(),
                    }]))
                }
            }
            rfc2622_sect6_autnum_example3: "protocol BGP4 into RIP to AS1 announce ANY" => {
                ExportExpr {
                    protocol_dist: Some("protocol BGP4 into RIP".parse().unwrap()),
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![("AS1".parse().unwrap(), None)],
                        filter: "ANY".parse().unwrap(),
                    }]))
                }
            }
            rfc2622_sect6_autnum_example4: "protocol BGP4 into OSPF to AS1 announce AS2" => {
                ExportExpr {
                    protocol_dist: Some("protocol BGP4 into OSPF".parse().unwrap()),
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![("AS1".parse().unwrap(), None)],
                        filter: "AS2".parse().unwrap(),
                    }]))
                }
            }
        }
    }
}
