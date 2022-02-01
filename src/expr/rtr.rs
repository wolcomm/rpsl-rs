use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    addr_family::{afi, LiteralPrefixSetAfi},
    error::{ParseError, ParseResult},
    names::{InetRtr, RtrSet},
    parser::{ParserRule, TokenPair},
};

pub type RtrExpr = Expr<afi::Ipv4>;
pub type MpRtrExpr = Expr<afi::Any>;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Expr<A: LiteralPrefixSetAfi> {
    Unit(Term<A>),
    And(Term<A>, Term<A>),
    Or(Term<A>, Term<A>),
    Except(Term<A>, Term<A>),
}

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for Expr<A> {
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
                    next_into_or!(pairs => "failed to get right hand inet-rtr expression term")?,
                ))
            }
            rule if rule == A::RTR_EXPR_OR_RULE => {
                let mut pairs = pair.into_inner();
                Ok(Self::Or(
                    next_into_or!(pairs => "failed to get left hand inet-rtr expression term")?,
                    next_into_or!(pairs => "failed to get right hand inet-rtr expression term")?,
                ))
            }
            rule if rule == A::RTR_EXPR_EXCEPT_RULE => {
                let mut pairs = pair.into_inner();
                Ok(Self::Except(
                    next_into_or!(pairs => "failed to get left hand inet-rtr expression term")?,
                    next_into_or!(pairs => "failed to get right hand inet-rtr expression term")?,
                ))
            }
            _ => Err(rule_mismatch!(pair => "inet-rtr expression")),
        }
    }
}

impl<A: LiteralPrefixSetAfi> fmt::Display for Expr<A> {
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
pub enum Term<A: LiteralPrefixSetAfi> {
    RtrSet(RtrSet),
    InetRtr(InetRtr),
    Literal(A::Addr),
    Expr(Box<Expr<A>>),
}

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for Term<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Term);
        match pair.as_rule() {
            ParserRule::rtr_set => Ok(Self::RtrSet(pair.try_into()?)),
            ParserRule::inet_rtr => Ok(Self::InetRtr(pair.try_into()?)),
            rule if rule == A::RTR_ADDR_LITERAL_RULE => Ok(Self::Literal(pair.as_str().parse()?)),
            rule if A::match_rtr_expr_rule(rule) => Ok(Self::Expr(Box::new(pair.try_into()?))),
            _ => Err(rule_mismatch!(pair => "inet-rtr expression term")),
        }
    }
}

impl<A: LiteralPrefixSetAfi> fmt::Display for Term<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::RtrSet(rtr_set) => rtr_set.fmt(f),
            Self::InetRtr(inet_rtr) => inet_rtr.fmt(f),
            Self::Literal(addr) => addr.fmt(f),
            Self::Expr(expr) => write!(f, "({})", expr),
        }
    }
}
