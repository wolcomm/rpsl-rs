use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    error::{ParseError, ParseResult},
    names::{AsSet, AutNum},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
};

/// RPSL `as-expression`. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.6
pub type AsExpr = Expr;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Expr {
    Unit(Term),
    And(Term, Term),
    Or(Term, Term),
    Except(Term, Term),
}

impl_from_str!(ParserRule::just_as_expr => Expr);

impl TryFrom<TokenPair<'_>> for Expr {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            ParserRule::as_expr_unit => Ok(Self::Unit(
                next_into_or!(pair.into_inner() => "failed to get AS expression term")?,
            )),
            ParserRule::as_expr_and => {
                let mut pairs = pair.into_inner();
                Ok(Self::And(
                    next_into_or!(pairs => "failed to get left hand AS expression term")?,
                    next_into_or!(pairs => "failed to get right hand AS expression term")?,
                ))
            }
            ParserRule::as_expr_or => {
                let mut pairs = pair.into_inner();
                Ok(Self::Or(
                    next_into_or!(pairs => "failed to get left hand AS expression term")?,
                    next_into_or!(pairs => "failed to get right hand AS expression term")?,
                ))
            }
            ParserRule::as_expr_except => {
                let mut pairs = pair.into_inner();
                Ok(Self::Except(
                    next_into_or!(pairs => "failed to get left hand AS expression term")?,
                    next_into_or!(pairs => "failed to get right hand AS expression term")?,
                ))
            }
            _ => Err(rule_mismatch!(pair => "AS expression")),
        }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Unit(term) => term.fmt(f),
            Self::And(lhs, rhs) => write!(f, "{} AND {}", lhs, rhs),
            Self::Or(lhs, rhs) => write!(f, "{} OR {}", lhs, rhs),
            Self::Except(lhs, rhs) => write!(f, "{} EXCEPT {}", lhs, rhs),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Term {
    Any,
    AsSet(AsSet),
    AutNum(AutNum),
    Expr(Box<Expr>),
}

impl TryFrom<TokenPair<'_>> for Term {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Term);
        match pair.as_rule() {
            ParserRule::any_as => Ok(Self::Any),
            ParserRule::as_set => Ok(Self::AsSet(pair.try_into()?)),
            ParserRule::aut_num => Ok(Self::AutNum(pair.try_into()?)),
            ParserRule::as_expr_unit
            | ParserRule::as_expr_and
            | ParserRule::as_expr_or
            | ParserRule::as_expr_except => Ok(Self::Expr(Box::new(pair.try_into()?))),
            _ => Err(rule_mismatch!(pair => "AS expression term")),
        }
    }
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Any => write!(f, "AS-ANY"),
            Self::AsSet(as_set) => as_set.fmt(f),
            Self::AutNum(aut_num) => aut_num.fmt(f),
            Self::Expr(expr) => write!(f, "({})", expr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::compare_ast;

    compare_ast! {
        AsExpr {
            rfc2622_sect6_autnum_example1: "AS2" => {
                AsExpr::Unit(Term::AutNum("AS2".parse().unwrap()))
            }
        }
    }
}
