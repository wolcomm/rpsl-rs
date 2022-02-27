use std::convert::{TryFrom, TryInto};
use std::fmt;

#[cfg(any(test, feature = "arbitrary"))]
use proptest::prelude::*;

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
    And(Term, Box<Expr>),
    Or(Term, Box<Expr>),
    Except(Term, Box<Expr>),
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
                    Box::new(
                        next_into_or!(pairs => "failed to get right hand AS expression term")?,
                    ),
                ))
            }
            ParserRule::as_expr_or => {
                let mut pairs = pair.into_inner();
                Ok(Self::Or(
                    next_into_or!(pairs => "failed to get left hand AS expression term")?,
                    Box::new(
                        next_into_or!(pairs => "failed to get right hand AS expression term")?,
                    ),
                ))
            }
            ParserRule::as_expr_except => {
                let mut pairs = pair.into_inner();
                Ok(Self::Except(
                    next_into_or!(pairs => "failed to get left hand AS expression term")?,
                    Box::new(
                        next_into_or!(pairs => "failed to get right hand AS expression term")?,
                    ),
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

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Expr {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        let term = any::<Term>();
        any::<Term>()
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

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Term {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        let leaf = prop_oneof![
            Just(Self::Any),
            any::<AsSet>().prop_map(Self::AsSet),
            any::<AutNum>().prop_map(Self::AutNum),
        ];
        leaf.prop_recursive(2, 4, 4, |inner| {
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
        AsExpr,
    }

    compare_ast! {
        AsExpr {
            rfc2622_sect6_autnum_example1: "AS2" => {
                AsExpr::Unit(Term::AutNum("AS2".parse().unwrap()))
            }
            rfc2622_fig30_route_example1: "AS1 OR AS2" => {
                AsExpr::Or(
                    Term::AutNum("AS1".parse().unwrap()),
                    Box::new(Expr::Unit(Term::AutNum("AS2".parse().unwrap()))),
                )
            }
            rfc2622_fig33_route_example: "AS1 or AS2 or AS3" => {
                AsExpr::Or(
                    Term::AutNum("AS1".parse().unwrap()),
                    Box::new(Expr::Or(
                        Term::AutNum("AS2".parse().unwrap()),
                        Box::new(Expr::Unit(Term::AutNum("AS3".parse().unwrap()))),
                    )),
                )
            }
        }
    }
}
