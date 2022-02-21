use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    addr_family::{afi, LiteralPrefixSetAfi},
    error::{ParseError, ParseResult},
    parser::{ParserRule, TokenPair},
};

use super::{filter, peering, ActionExpr, ProtocolDistribution};

pub type ImportExpr = Statement<afi::Ipv4>;
pub type MpImportExpr = Statement<afi::Any>;

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
            rule if rule == A::IMPORT_STMT_SIMPLE_RULE => Ok(Self {
                protocol_dist: None,
                expr: next_into_or!(pair.into_inner() => "failed to get import expression")?,
            }),
            rule if rule == A::IMPORT_STMT_PROTOCOL_RULE => {
                let mut pairs = pair.into_inner();
                let protocol_dist = Some(
                    next_into_or!(pairs => "failed to get protocol redistribution expression")?,
                );
                let expr = next_into_or!(pairs => "failed to get import expression")?;
                Ok(Self {
                    protocol_dist,
                    expr,
                })
            }
            _ => Err(rule_mismatch!(pair => "import statement")),
        }
    }
}

impl_from_str!(ParserRule::just_import_stmt => Statement<afi::Ipv4>);
impl_from_str!(ParserRule::just_mp_import_stmt => Statement<afi::Any>);

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
            rule if rule == A::IMPORT_EXPR_UNIT_RULE => Ok(Self::Unit(
                next_into_or!(pair.into_inner() => "failed to get import term")?,
            )),
            rule if rule == A::IMPORT_EXPR_EXCEPT_RULE => {
                let mut pairs = pair.into_inner();
                let term = next_into_or!(pairs => "failed to get import term")?;
                let expr =
                    Box::new(next_into_or!(pairs => "failed to get inner import expression")?);
                Ok(Self::Except(term, expr))
            }
            rule if rule == A::IMPORT_EXPR_REFINE_RULE => {
                let mut pairs = pair.into_inner();
                let term = next_into_or!(pairs => "failed to get import term")?;
                let expr =
                    Box::new(next_into_or!(pairs => "failed to get inner import expression")?);
                Ok(Self::Refine(term, expr))
            }
            _ => Err(rule_mismatch!(pair => "import expression")),
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
            rule if rule == A::IMPORT_TERM_RULE => Ok(Self(
                pair.into_inner()
                    .map(|inner_pair| inner_pair.try_into())
                    .collect::<ParseResult<_>>()?,
            )),
            _ => Err(rule_mismatch!(pair => "import expression term")),
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
            rule if rule == A::IMPORT_FACTOR_RULE => {
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
            _ => Err(rule_mismatch!(pair => "import expression factor")),
        }
    }
}

impl<A: LiteralPrefixSetAfi> fmt::Display for Factor<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.peerings
            .iter()
            .try_for_each(|(peering_expr, action_expr)| {
                write!(f, "FROM {}", peering_expr)?;
                if let Some(action_expr) = action_expr {
                    write!(f, " ACTION {}", action_expr)?;
                }
                Ok(())
            })?;
        write!(f, " ACCEPT {}", self.filter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    compare_ast! {
        ImportExpr {
            rfc2622_sect5_6_autnum_example1: "from AS2 7.7.7.2 at 7.7.7.1 accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_dist: None,
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![("AS2 7.7.7.2 at 7.7.7.1".parse().unwrap(), None)],
                        filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                    }]))
                }
            }
            rfc2622_sect5_6_autnum_example2: "from AS2 at 7.7.7.1 accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_dist: None,
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![("AS2 at 7.7.7.1".parse().unwrap(), None)],
                        filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                    }]))
                }
            }
            rfc2622_sect5_6_autnum_example3: "from AS2 accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_dist: None,
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![("AS2".parse().unwrap(), None)],
                        filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                    }]))
                }
            }
            rfc2622_sect5_6_autnum_example4: "from AS-FOO at 9.9.9.1 accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_dist: None,
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![("AS-FOO at 9.9.9.1".parse().unwrap(), None)],
                        filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                    }]))
                }
            }
            rfc2622_sect5_6_autnum_example5: "from AS-FOO accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_dist: None,
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![("AS-FOO".parse().unwrap(), None)],
                        filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                    }]))
                }
            }
            // the 'NOT' operator is invalid for rtr expressions.
            // accordingly, the following example taken from rfc2622
            // section 5.6 is invalid:
            //
            // rfc2622_sect5_6_autnum_example6: "from AS-FOO and not AS2 at not 7.7.7.1 accept { 128.9.0.0/16 }" => {
            //     ImportExpr {
            //         protocol_dist: None,
            //         expr: Expr::Unit(Term(vec![Factor {
            //             peerings: vec![("AS-FOO and not AS2 at not 7.7.7.1".parse().unwrap(), None)],
            //             filter: "{ 128.9.0.0/16 }".parse().unwrap(),
            //         }]))
            //     }
            // }
            rfc2622_sect5_6_autnum_example7: "from prng-foo accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_dist: None,
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![("prng-foo".parse().unwrap(), None)],
                        filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                    }]))
                }
            }
            rfc2622_sect6_autnum_example0: "from AS2 accept AS2" => {
                ImportExpr {
                    protocol_dist: None,
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![("AS2".parse().unwrap(), None)],
                        filter: "AS2".parse().unwrap(),
                    }]))
                }
            }
            rfc2622_sect6_autnum_example1: "from AS2 action pref = 1; accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_dist: None,
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![("AS2".parse().unwrap(), Some("pref = 1;".parse().unwrap()))],
                        filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                    }]))
                }
            }
            rfc2622_sect6_autnum_example2: "\
            from AS2 \
            action pref = 10; med = 0; community.append(10250, 3561:10); \
            accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_dist: None,
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![(
                            "AS2".parse().unwrap(),
                            Some("pref = 10; med = 0; community.append(10250, 3561:10);".parse().unwrap())
                        )],
                        filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                    }]))
                }
            }
            rfc2622_sect6_autnum_example3: "\
            from AS2 7.7.7.2 at 7.7.7.1 action pref = 1;
            from AS2 action pref = 2;
            accept AS4" => {
                ImportExpr {
                    protocol_dist: None,
                    expr: Expr::Unit(Term(vec![Factor {
                        peerings: vec![
                            (
                                "AS2 7.7.7.2 at 7.7.7.1".parse().unwrap(),
                                Some("pref = 1;".parse().unwrap())
                            ),
                            (
                                "AS2".parse().unwrap(),
                                Some("pref = 2;".parse().unwrap())
                            ),
                        ],
                        filter: "AS4".parse().unwrap(),
                    }]))
                }
            }
            // The original version in RFC2622 Section 6.6 (with braces around
            // nested import-expressions) doesn't conform to the grammar!
            rfc2622_sect6_autnum_example4: "\
            from AS1 action pref = 1; accept as-foo;
                except from AS2 action pref = 2; accept AS226;
                    except from AS3 action pref = 3; accept {128.9.0.0/16};" => {
                ImportExpr {
                    protocol_dist: None,
                    expr: Expr::Except(
                        Term(vec![Factor {
                            peerings: vec![(
                                "AS1".parse().unwrap(),
                                Some("pref = 1;".parse().unwrap()),
                            )],
                            filter: "AS-FOO".parse().unwrap(),
                        }]),
                        Box::new(Expr::Except(
                            Term(vec![Factor {
                                peerings: vec![(
                                    "AS2".parse().unwrap(),
                                    Some("pref = 2;".parse().unwrap()),
                                )],
                                filter: "AS226".parse().unwrap(),
                            }]),
                            Box::new(Expr::Unit(Term(vec![Factor {
                                peerings: vec![(
                                    "AS3".parse().unwrap(),
                                    Some("pref = 3;".parse().unwrap()),
                                )],
                                filter: "{128.9.0.0/16}".parse().unwrap(),
                            }])))
                        ))
                    )
                }
            }
            rfc2622_sect6_autnum_example5: "\
            {  from AS-ANY action pref = 1; accept community(3560:10);
               from AS-ANY action pref = 2; accept community(3560:20);
            } refine {
                from AS1 accept AS1;
                from AS2 accept AS2;
                from AS3 accept AS3;
            }" => {
                ImportExpr {
                    protocol_dist: None,
                    expr: Expr::Refine(
                        Term(vec![
                            Factor {
                                peerings: vec![(
                                    "AS-ANY".parse().unwrap(),
                                    Some("pref = 1;".parse().unwrap()),
                                )],
                                filter: "community(3560:10)".parse().unwrap(),
                            },
                            Factor {
                                peerings: vec![(
                                    "AS-ANY".parse().unwrap(),
                                    Some("pref = 2;".parse().unwrap()),
                                )],
                                filter: "community(3560:20)".parse().unwrap(),
                            },
                        ]),
                        Box::new(Expr::Unit(Term(vec![
                            Factor {
                                peerings: vec![("AS1".parse().unwrap(), None)],
                                filter: "AS1".parse().unwrap(),
                            },
                            Factor {
                                peerings: vec![("AS2".parse().unwrap(), None)],
                                filter: "AS2".parse().unwrap(),
                            },
                            Factor {
                                peerings: vec![("AS3".parse().unwrap(), None)],
                                filter: "AS3".parse().unwrap(),
                            },
                        ])))
                    )
                }
            }
        }
    }
}
