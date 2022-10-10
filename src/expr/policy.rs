use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::marker::PhantomData;

use ip::{Any, Ipv4};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

use crate::{
    error::{ParseError, ParseResult},
    list::ListOf,
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::{AfiSafi, Protocol},
};

use super::{filter, peering, ActionExpr};

#[cfg(any(test, feature = "arbitrary"))]
use super::arbitrary::AfiSafiList;

pub trait StmtAfi: filter::ExprAfi + peering::ExprAfi {
    /// Address family specific [`ParserRule`] for `import` factors.
    const IMPORT_FACTOR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `import` terms.
    const IMPORT_TERM_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for unit `import` expressions.
    const IMPORT_EXPR_UNIT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `EXCEPT` `import` expressions.
    const IMPORT_EXPR_EXCEPT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `REFINE` `import` expressions.
    const IMPORT_EXPR_REFINE_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `import` afi-expressions.
    const IMPORT_AFI_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `import` statements.
    const IMPORT_STMT_RULE: ParserRule;

    /// Address family specific [`ParserRule`] for `export` factors.
    const EXPORT_FACTOR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `export` terms.
    const EXPORT_TERM_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for unit `export` expressions.
    const EXPORT_EXPR_UNIT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `EXCEPT` `export` expressions.
    const EXPORT_EXPR_EXCEPT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `REFINE` `export` expressions.
    const EXPORT_EXPR_REFINE_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `export` afi-expressions.
    const EXPORT_AFI_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `export` statements.
    const EXPORT_STMT_RULE: ParserRule;
}

impl StmtAfi for Ipv4 {
    const IMPORT_FACTOR_RULE: ParserRule = ParserRule::import_factor;
    const IMPORT_TERM_RULE: ParserRule = ParserRule::import_term;
    const IMPORT_EXPR_UNIT_RULE: ParserRule = ParserRule::import_expr_unit;
    const IMPORT_EXPR_EXCEPT_RULE: ParserRule = ParserRule::import_expr_except;
    const IMPORT_EXPR_REFINE_RULE: ParserRule = ParserRule::import_expr_refine;
    const IMPORT_AFI_EXPR_RULE: ParserRule = ParserRule::import_afi_expr;
    const IMPORT_STMT_RULE: ParserRule = ParserRule::import_stmt;

    const EXPORT_FACTOR_RULE: ParserRule = ParserRule::export_factor;
    const EXPORT_TERM_RULE: ParserRule = ParserRule::export_term;
    const EXPORT_EXPR_UNIT_RULE: ParserRule = ParserRule::export_expr_unit;
    const EXPORT_EXPR_EXCEPT_RULE: ParserRule = ParserRule::export_expr_except;
    const EXPORT_EXPR_REFINE_RULE: ParserRule = ParserRule::export_expr_refine;
    const EXPORT_AFI_EXPR_RULE: ParserRule = ParserRule::export_afi_expr;
    const EXPORT_STMT_RULE: ParserRule = ParserRule::export_stmt;
}

impl StmtAfi for Any {
    const IMPORT_FACTOR_RULE: ParserRule = ParserRule::mp_import_factor;
    const IMPORT_TERM_RULE: ParserRule = ParserRule::mp_import_term;
    const IMPORT_EXPR_UNIT_RULE: ParserRule = ParserRule::mp_import_expr_unit;
    const IMPORT_EXPR_EXCEPT_RULE: ParserRule = ParserRule::mp_import_expr_except;
    const IMPORT_EXPR_REFINE_RULE: ParserRule = ParserRule::mp_import_expr_refine;
    const IMPORT_AFI_EXPR_RULE: ParserRule = ParserRule::mp_import_afi_expr;
    const IMPORT_STMT_RULE: ParserRule = ParserRule::mp_import_stmt;

    const EXPORT_FACTOR_RULE: ParserRule = ParserRule::mp_export_factor;
    const EXPORT_TERM_RULE: ParserRule = ParserRule::mp_export_term;
    const EXPORT_EXPR_UNIT_RULE: ParserRule = ParserRule::mp_export_expr_unit;
    const EXPORT_EXPR_EXCEPT_RULE: ParserRule = ParserRule::mp_export_expr_except;
    const EXPORT_EXPR_REFINE_RULE: ParserRule = ParserRule::mp_export_expr_refine;
    const EXPORT_AFI_EXPR_RULE: ParserRule = ParserRule::mp_export_afi_expr;
    const EXPORT_STMT_RULE: ParserRule = ParserRule::mp_export_stmt;
}

/// RPSL `import` expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-6.1
pub type ImportExpr = Statement<Ipv4, Import<Ipv4>>;
impl_from_str!(ParserRule::just_import_stmt => Statement<Ipv4, Import<Ipv4>>);

/// RPSL `mp-import` expression. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.5
pub type MpImportExpr = Statement<Any, Import<Any>>;
impl_from_str!(ParserRule::just_mp_import_stmt => Statement<Any, Import<Any>>);

/// RPSL `export` expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-6.2
pub type ExportExpr = Statement<Ipv4, Export<Ipv4>>;
impl_from_str!(ParserRule::just_export_stmt => Statement<Ipv4, Export<Ipv4>>);

/// RPSL `mp-export` expression. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.5
pub type MpExportExpr = Statement<Any, Export<Any>>;
impl_from_str!(ParserRule::just_mp_export_stmt => Statement<Any, Export<Any>>);

pub trait Policy<A: StmtAfi> {
    const PEER_DIRECTION: &'static str;
    const ACTION_VERB: &'static str;

    const STMT_RULE: ParserRule;
    const AFI_EXPR_RULE: ParserRule;
    const EXPR_UNIT_RULE: ParserRule;
    const EXPR_EXCEPT_RULE: ParserRule;
    const EXPR_REFINE_RULE: ParserRule;
    const TERM_RULE: ParserRule;
    const FACTOR_RULE: ParserRule;
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Import<A>(PhantomData<A>);

impl<A: StmtAfi> Policy<A> for Import<A> {
    const PEER_DIRECTION: &'static str = "from";
    const ACTION_VERB: &'static str = "accept";

    const STMT_RULE: ParserRule = A::IMPORT_STMT_RULE;
    const AFI_EXPR_RULE: ParserRule = A::IMPORT_AFI_EXPR_RULE;
    const EXPR_UNIT_RULE: ParserRule = A::IMPORT_EXPR_UNIT_RULE;
    const EXPR_EXCEPT_RULE: ParserRule = A::IMPORT_EXPR_EXCEPT_RULE;
    const EXPR_REFINE_RULE: ParserRule = A::IMPORT_EXPR_REFINE_RULE;
    const TERM_RULE: ParserRule = A::IMPORT_TERM_RULE;
    const FACTOR_RULE: ParserRule = A::IMPORT_FACTOR_RULE;
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Export<A>(PhantomData<A>);

impl<A: StmtAfi> Policy<A> for Export<A> {
    const PEER_DIRECTION: &'static str = "to";
    const ACTION_VERB: &'static str = "announce";

    const STMT_RULE: ParserRule = A::EXPORT_STMT_RULE;
    const AFI_EXPR_RULE: ParserRule = A::EXPORT_AFI_EXPR_RULE;
    const EXPR_UNIT_RULE: ParserRule = A::EXPORT_EXPR_UNIT_RULE;
    const EXPR_EXCEPT_RULE: ParserRule = A::EXPORT_EXPR_EXCEPT_RULE;
    const EXPR_REFINE_RULE: ParserRule = A::EXPORT_EXPR_REFINE_RULE;
    const TERM_RULE: ParserRule = A::EXPORT_TERM_RULE;
    const FACTOR_RULE: ParserRule = A::EXPORT_FACTOR_RULE;
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Statement<A: StmtAfi, P: Policy<A>> {
    protocol_from: Option<Protocol>,
    protocol_into: Option<Protocol>,
    afi_expr: AfiExpr<A, P>,
}

impl<A: StmtAfi, P: Policy<A>> TryFrom<TokenPair<'_>> for Statement<A, P> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Statement);
        match pair.as_rule() {
            rule if rule == P::STMT_RULE => {
                let mut pairs = pair.into_inner().peekable();
                let protocol_from = if let Some(ParserRule::from_protocol) =
                    pairs.peek().map(|inner_pair| inner_pair.as_rule())
                {
                    let inner_pair = pairs.next().unwrap();
                    Some(
                        next_into_or!(inner_pair.into_inner() => "failed to get redistribution source protocol")?,
                    )
                } else {
                    None
                };
                let protocol_into = if let Some(ParserRule::into_protocol) =
                    pairs.peek().map(|inner_pair| inner_pair.as_rule())
                {
                    let inner_pair = pairs.next().unwrap();
                    Some(
                        next_into_or!(inner_pair.into_inner() => "failed to get redistribution source protocol")?,
                    )
                } else {
                    None
                };
                let afi_expr = next_into_or!(pairs => "failed to get policy afi expression")?;
                Ok(Self {
                    protocol_from,
                    protocol_into,
                    afi_expr,
                })
            }
            _ => Err(rule_mismatch!(pair => "policy statement")),
        }
    }
}

impl<A: StmtAfi, P: Policy<A>> fmt::Display for Statement<A, P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(protocol) = &self.protocol_from {
            write!(f, "protocol {} ", protocol)?;
        }
        if let Some(protocol) = &self.protocol_into {
            write!(f, "into {} ", protocol)?;
        }
        write!(f, "{}", self.afi_expr)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A, P> Arbitrary for Statement<A, P>
where
    A: AfiSafiList + 'static,
    P: Policy<A> + fmt::Debug + 'static,
    A::Address: Arbitrary,
    <A::Address as Arbitrary>::Parameters: Clone,
    <A::Address as Arbitrary>::Strategy: 'static,
    A::Prefix: Arbitrary,
    <A::Prefix as Arbitrary>::Parameters: Clone,
    <A::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
    A::PrefixLength: AsRef<u8>,
{
    type Parameters = (
        ParamsFor<Option<Protocol>>,
        ParamsFor<Option<Protocol>>,
        ParamsFor<AfiExpr<A, P>>,
    );
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            any_with::<Option<Protocol>>(params.0),
            any_with::<Option<Protocol>>(params.1),
            any_with::<AfiExpr<A, P>>(params.2),
        )
            .prop_map(|(protocol_from, protocol_into, afi_expr)| Self {
                protocol_from,
                protocol_into,
                afi_expr,
            })
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AfiExpr<A: StmtAfi, P: Policy<A>> {
    afis: Option<ListOf<AfiSafi>>,
    expr: Expr<A, P>,
}

impl<A: StmtAfi, P: Policy<A>> TryFrom<TokenPair<'_>> for AfiExpr<A, P> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => AfiExpr);
        match pair.as_rule() {
            rule if rule == P::AFI_EXPR_RULE => {
                let mut pairs = pair.into_inner().peekable();
                let afis = if let Some(ParserRule::afi_safi_list) =
                    pairs.peek().map(|inner_pair| inner_pair.as_rule())
                {
                    Some(next_into_or!(pairs => "failed to get afi list")?)
                } else {
                    None
                };
                let expr = next_into_or!(pairs => "failed to get policy expression")?;
                Ok(Self { afis, expr })
            }
            _ => Err(rule_mismatch!(pair => "policy afi expression")),
        }
    }
}

impl<A: StmtAfi, P: Policy<A>> fmt::Display for AfiExpr<A, P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(afis) = &self.afis {
            write!(f, "afi {} ", afis)?;
        }
        write!(f, "{}", self.expr)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A, P> Arbitrary for AfiExpr<A, P>
where
    A: AfiSafiList + 'static,
    P: Policy<A> + fmt::Debug + 'static,
    A::Address: Arbitrary,
    <A::Address as Arbitrary>::Parameters: Clone,
    <A::Address as Arbitrary>::Strategy: 'static,
    A::Prefix: Arbitrary,
    <A::Prefix as Arbitrary>::Parameters: Clone,
    <A::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
    A::PrefixLength: AsRef<u8>,
{
    type Parameters = (ParamsFor<Option<ListOf<AfiSafi>>>, ParamsFor<Expr<A, P>>);
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (A::any_afis(params.0), any_with::<Expr<A, P>>(params.1))
            .prop_map(|(afis, expr)| Self { afis, expr })
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Expr<A: StmtAfi, P: Policy<A>> {
    Unit(Term<A, P>),
    Except(Term<A, P>, Box<AfiExpr<A, P>>),
    Refine(Term<A, P>, Box<AfiExpr<A, P>>),
}

impl<A: StmtAfi, P: Policy<A>> TryFrom<TokenPair<'_>> for Expr<A, P> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            rule if rule == P::EXPR_UNIT_RULE => Ok(Self::Unit(
                next_into_or!(pair.into_inner() => "failed to get policy term")?,
            )),
            rule if rule == P::EXPR_EXCEPT_RULE => {
                let mut pairs = pair.into_inner();
                let term = next_into_or!(pairs => "failed to get policy term")?;
                let expr =
                    Box::new(next_into_or!(pairs => "failed to get inner policy afi expression")?);
                Ok(Self::Except(term, expr))
            }
            rule if rule == P::EXPR_REFINE_RULE => {
                let mut pairs = pair.into_inner();
                let term = next_into_or!(pairs => "failed to get policy term")?;
                let expr =
                    Box::new(next_into_or!(pairs => "failed to get inner policy afi expression")?);
                Ok(Self::Refine(term, expr))
            }
            _ => Err(rule_mismatch!(pair => "policy expression")),
        }
    }
}

impl<A: StmtAfi, P: Policy<A>> fmt::Display for Expr<A, P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Unit(term) => term.fmt(f),
            Self::Except(term, expr) => write!(f, "{} EXCEPT {}", term, expr),
            Self::Refine(term, expr) => write!(f, "{} REFINE {}", term, expr),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A, P> Arbitrary for Expr<A, P>
where
    A: AfiSafiList + 'static,
    P: Policy<A> + fmt::Debug + 'static,
    A::Address: Arbitrary,
    <A::Address as Arbitrary>::Parameters: Clone,
    <A::Address as Arbitrary>::Strategy: 'static,
    A::Prefix: Arbitrary,
    <A::Prefix as Arbitrary>::Parameters: Clone,
    <A::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
    A::PrefixLength: AsRef<u8>,
{
    type Parameters = (ParamsFor<Term<A, P>>, ParamsFor<Option<AfiSafi>>);
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        let term = any_with::<Term<A, P>>(params.0.clone()).boxed();
        let afis = A::any_afis(params.1);
        any_with::<Term<A, P>>(params.0)
            .prop_map(Self::Unit)
            .prop_recursive(2, 4, 4, move |unit| {
                prop_oneof![
                    (term.clone(), afis.clone(), unit.clone()).prop_map(|(term, afis, unit)| {
                        Self::Except(term, Box::new(AfiExpr { afis, expr: unit }))
                    }),
                    (term.clone(), afis.clone(), unit.clone()).prop_map(|(term, afis, unit)| {
                        Self::Refine(term, Box::new(AfiExpr { afis, expr: unit }))
                    }),
                ]
            })
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Term<A: StmtAfi, P: Policy<A>>(Vec<Factor<A, P>>);

impl<A: StmtAfi, P: Policy<A>> TryFrom<TokenPair<'_>> for Term<A, P> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Term);
        match pair.as_rule() {
            rule if rule == P::TERM_RULE => Ok(Self(
                pair.into_inner()
                    .map(|inner_pair| inner_pair.try_into())
                    .collect::<ParseResult<_>>()?,
            )),
            _ => Err(rule_mismatch!(pair => "policy expression term")),
        }
    }
}

impl<A: StmtAfi, P: Policy<A>> fmt::Display for Term<A, P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0.len() <= 1 {
            self.0[0].fmt(f)
        } else {
            write!(f, "{{")?;
            self.0
                .iter()
                .try_for_each(|factor| write!(f, " {};", factor))?;
            write!(f, " }}")
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A, P> Arbitrary for Term<A, P>
where
    A: AfiSafiList + 'static,
    P: Policy<A> + fmt::Debug + 'static,
    A::Address: Arbitrary,
    <A::Address as Arbitrary>::Parameters: Clone,
    <A::Address as Arbitrary>::Strategy: 'static,
    A::Prefix: Arbitrary,
    <A::Prefix as Arbitrary>::Parameters: Clone,
    <A::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
    A::PrefixLength: AsRef<u8>,
{
    type Parameters = ParamsFor<Factor<A, P>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        proptest::collection::vec(any_with::<Factor<A, P>>(params), 1..8)
            .prop_map(Self)
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Factor<A: StmtAfi, P: Policy<A>> {
    peerings: Vec<(peering::Expr<A>, Option<ActionExpr>)>,
    filter: filter::Expr<A>,
    direction: PhantomData<P>,
}

impl<A: StmtAfi, P: Policy<A>> TryFrom<TokenPair<'_>> for Factor<A, P> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Factor);
        match pair.as_rule() {
            rule if rule == P::FACTOR_RULE => {
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
                Ok(Self {
                    peerings,
                    filter,
                    direction: PhantomData,
                })
            }
            _ => Err(rule_mismatch!(pair => "policy expression factor")),
        }
    }
}

impl<A: StmtAfi, P: Policy<A>> fmt::Display for Factor<A, P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.peerings
            .iter()
            .try_for_each(|(peering_expr, action_expr)| {
                write!(f, "{} {} ", P::PEER_DIRECTION, peering_expr)?;
                if let Some(action_expr) = action_expr {
                    write!(f, "ACTION {} ", action_expr)?;
                }
                Ok(())
            })?;
        write!(f, "{} {}", P::ACTION_VERB, self.filter)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A, P> Arbitrary for Factor<A, P>
where
    A: AfiSafiList + 'static,
    P: Policy<A> + fmt::Debug,
    A::Address: Arbitrary,
    <A::Address as Arbitrary>::Parameters: Clone,
    <A::Address as Arbitrary>::Strategy: 'static,
    A::Prefix: Arbitrary,
    <A::Prefix as Arbitrary>::Parameters: Clone,
    <A::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
    A::PrefixLength: AsRef<u8>,
{
    type Parameters = (
        ParamsFor<peering::Expr<A>>,
        ParamsFor<Option<ActionExpr>>,
        ParamsFor<filter::Expr<A>>,
    );
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            proptest::collection::vec(
                (
                    any_with::<peering::Expr<A>>(params.0),
                    any_with::<Option<ActionExpr>>(params.1),
                ),
                1..8,
            ),
            any_with::<filter::Expr<A>>(params.2),
        )
            .prop_map(|(peerings, filter)| Self {
                peerings,
                filter,
                direction: PhantomData,
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{compare_ast, display_fmt_parses};

    #[test]
    fn display_export_expr() {
        let expr = MpExportExpr {
            protocol_from: None,
            protocol_into: None,
            afi_expr: AfiExpr {
                afis: None,
                expr: Expr::Unit(Term(vec![Factor {
                    peerings: vec![
                        ("AS1".parse().unwrap(), None),
                        ("AS2".parse().unwrap(), None),
                    ],
                    filter: "AS-ANY".parse().unwrap(),
                    direction: PhantomData,
                }])),
            },
        };
        let repr = "to AS1 to AS2 announce AS-ANY";
        assert_eq!(expr.to_string(), repr)
    }

    display_fmt_parses! {
        ImportExpr,
        ExportExpr,
        MpImportExpr,
        MpExportExpr,
    }

    compare_ast! {
        ImportExpr {
            rfc2622_sect5_6_autnum_example1: "from AS2 7.7.7.2 at 7.7.7.1 accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Unit(Term(vec![Factor {
                            peerings: vec![("AS2 7.7.7.2 at 7.7.7.1".parse().unwrap(), None)],
                            filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                            direction: PhantomData,
                        }]))
                    },
                }
            }
            rfc2622_sect5_6_autnum_example2: "from AS2 at 7.7.7.1 accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Unit(Term(vec![Factor {
                            peerings: vec![("AS2 at 7.7.7.1".parse().unwrap(), None)],
                            filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                            direction: PhantomData,
                        }]))
                    },
                }
            }
            rfc2622_sect5_6_autnum_example3: "from AS2 accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Unit(Term(vec![Factor {
                            peerings: vec![("AS2".parse().unwrap(), None)],
                            filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                            direction: PhantomData,
                        }]))
                    },
                }
            }
            rfc2622_sect5_6_autnum_example4: "from AS-FOO at 9.9.9.1 accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Unit(Term(vec![Factor {
                            peerings: vec![("AS-FOO at 9.9.9.1".parse().unwrap(), None)],
                            filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                            direction: PhantomData,
                        }]))
                    },
                }
            }
            rfc2622_sect5_6_autnum_example5: "from AS-FOO accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Unit(Term(vec![Factor {
                            peerings: vec![("AS-FOO".parse().unwrap(), None)],
                            filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                            direction: PhantomData,
                        }]))
                    },
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
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Unit(Term(vec![Factor {
                            peerings: vec![("prng-foo".parse().unwrap(), None)],
                            filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                            direction: PhantomData,
                        }]))
                    },
                }
            }
            rfc2622_sect6_autnum_example0: "from AS2 accept AS2" => {
                ImportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Unit(Term(vec![Factor {
                            peerings: vec![("AS2".parse().unwrap(), None)],
                            filter: "AS2".parse().unwrap(),
                            direction: PhantomData,
                        }]))
                    },
                }
            }
            rfc2622_sect6_autnum_example1: "from AS2 action pref = 1; accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Unit(Term(vec![Factor {
                            peerings: vec![("AS2".parse().unwrap(), Some("pref = 1;".parse().unwrap()))],
                            filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                            direction: PhantomData,
                        }]))
                    },
                }
            }
            rfc2622_sect6_autnum_example2: "\
            from AS2 \
            action pref = 10; med = 0; community.append(10250, 3561:10); \
            accept { 128.9.0.0/16 }" => {
                ImportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Unit(Term(vec![Factor {
                            peerings: vec![(
                                "AS2".parse().unwrap(),
                                Some("pref = 10; med = 0; community.append(10250, 3561:10);".parse().unwrap())
                            )],
                            filter: "{ 128.9.0.0/16 }".parse().unwrap(),
                            direction: PhantomData,
                        }]))
                    },
                }
            }
            rfc2622_sect6_autnum_example3: "\
            from AS2 7.7.7.2 at 7.7.7.1 action pref = 1;
            from AS2 action pref = 2;
            accept AS4" => {
                ImportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
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
                            direction: PhantomData,
                        }]))
                    },
                }
            }
            // The original version in RFC2622 Section 6.6 (with braces around
            // nested import-expressions) doesn't conform to the grammar!
            rfc2622_sect6_autnum_example4: "\
            from AS1 action pref = 1; accept as-foo;
                except from AS2 action pref = 2; accept AS226;
                    except from AS3 action pref = 3; accept {128.9.0.0/16};" => {
                ImportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Except(
                            Term(vec![Factor {
                                peerings: vec![(
                                    "AS1".parse().unwrap(),
                                    Some("pref = 1;".parse().unwrap()),
                                )],
                                filter: "AS-FOO".parse().unwrap(),
                                direction: PhantomData,
                            }]),
                            Box::new(AfiExpr {
                                afis: None,
                                expr: Expr::Except(
                                    Term(vec![Factor {
                                        peerings: vec![(
                                            "AS2".parse().unwrap(),
                                            Some("pref = 2;".parse().unwrap()),
                                        )],
                                        filter: "AS226".parse().unwrap(),
                                        direction: PhantomData,
                                    }]),
                                    Box::new(AfiExpr {
                                        afis: None,
                                        expr: Expr::Unit(Term(vec![Factor {
                                            peerings: vec![(
                                                "AS3".parse().unwrap(),
                                                Some("pref = 3;".parse().unwrap()),
                                            )],
                                            filter: "{128.9.0.0/16}".parse().unwrap(),
                                            direction: PhantomData,
                                        }])),
                                    })
                                ),
                            })
                        )
                    },
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
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Refine(
                            Term(vec![
                                Factor {
                                    peerings: vec![(
                                        "AS-ANY".parse().unwrap(),
                                        Some("pref = 1;".parse().unwrap()),
                                    )],
                                    filter: "community(3560:10)".parse().unwrap(),
                                    direction: PhantomData,
                                },
                                Factor {
                                    peerings: vec![(
                                        "AS-ANY".parse().unwrap(),
                                        Some("pref = 2;".parse().unwrap()),
                                    )],
                                    filter: "community(3560:20)".parse().unwrap(),
                                    direction: PhantomData,
                                },
                            ]),
                            Box::new(AfiExpr {
                                afis: None,
                                expr: Expr::Unit(Term(vec![
                                    Factor {
                                        peerings: vec![("AS1".parse().unwrap(), None)],
                                        filter: "AS1".parse().unwrap(),
                                        direction: PhantomData,
                                    },
                                    Factor {
                                        peerings: vec![("AS2".parse().unwrap(), None)],
                                        filter: "AS2".parse().unwrap(),
                                        direction: PhantomData,
                                    },
                                    Factor {
                                        peerings: vec![("AS3".parse().unwrap(), None)],
                                        filter: "AS3".parse().unwrap(),
                                        direction: PhantomData,
                                    },
                                ])),
                            })
                        )
                    },
                }
            }
        }
    }

    compare_ast! {
        MpImportExpr {
            rfc4012_sect2_5_3_aut_num_example1: "\
            afi any.unicast from AS65001 accept as-foo;
            except afi any.unicast {
                from AS65002 accept AS65226;
            }
            except afi ipv6.unicast {
                from AS65003 accept {2001:0DB8::/32};
            }" => {
                MpImportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: Some(vec!["any.unicast".parse().unwrap()].into_iter().collect()),
                        expr: Expr::Except(
                            Term(vec![
                                Factor {
                                    peerings: vec![("AS65001".parse().unwrap(), None)],
                                    filter: "as-foo".parse().unwrap(),
                                    direction: PhantomData,
                                }
                            ]),
                            Box::new(AfiExpr {
                                afis: Some(vec!["any.unicast".parse().unwrap()].into_iter().collect()),
                                expr: Expr::Except(
                                    Term(vec![
                                        Factor {
                                            peerings: vec![("AS65002".parse().unwrap(), None)],
                                            filter: "AS65226".parse().unwrap(),
                                            direction: PhantomData,
                                        }
                                    ]),
                                    Box::new(AfiExpr {
                                        afis: Some(vec!["ipv6.unicast".parse().unwrap()].into_iter().collect()),
                                        expr: Expr::Unit(
                                            Term(vec![
                                                Factor {
                                                    peerings: vec![("AS65003".parse().unwrap(), None)],
                                                    filter: "{2001:0DB8::/32}".parse().unwrap(),
                                                    direction: PhantomData,
                                                }
                                            ])
                                        )
                                    })
                                )
                            }),
                        )
                    },
                }
            }
            rfc4012_sect2_5_3_aut_num_example2: "afi ipv6.unicast from AS65001 accept {192.0.2.0/24}" => {
                MpImportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: Some(vec!["ipv6.unicast".parse().unwrap()].into_iter().collect()),
                        expr: Expr::Unit(
                            Term(vec![
                                Factor {
                                    peerings: vec![("AS65001".parse().unwrap(), None)],
                                    filter: "{192.0.2.0/24}".parse().unwrap(),
                                    direction: PhantomData,
                                }
                            ])
                        )
                    },
                }
            }
        }
    }

    compare_ast! {
        ExportExpr {
            rfc2622_sect6_autnum_example1: "\
            to AS2 \
            action med = 5; community .= { 70 }; \
            announce AS4" => {
                ExportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Unit(Term(vec![Factor {
                            peerings: vec![("AS2".parse().unwrap(), Some("med = 5; community .= { 70 };".parse().unwrap()))],
                            filter: "AS4".parse().unwrap(),
                            direction: PhantomData,
                        }]))
                    },
                }
            }
            rfc2622_sect6_autnum_example2: "to AS-FOO announce ANY" => {
                ExportExpr {
                    protocol_from: None,
                    protocol_into: None,
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Unit(Term(vec![Factor {
                            peerings: vec![("AS-FOO".parse().unwrap(), None)],
                            filter: "ANY".parse().unwrap(),
                            direction: PhantomData,
                        }]))
                    },
                }
            }
            rfc2622_sect6_autnum_example3: "protocol BGP4 into RIP to AS1 announce ANY" => {
                ExportExpr {
                    protocol_from: Some(Protocol::Bgp4),
                    protocol_into: Some(Protocol::Rip),
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Unit(Term(vec![Factor {
                            peerings: vec![("AS1".parse().unwrap(), None)],
                            filter: "ANY".parse().unwrap(),
                            direction: PhantomData,
                        }]))
                    },
                }
            }
            rfc2622_sect6_autnum_example4: "protocol BGP4 into OSPF to AS1 announce AS2" => {
                ExportExpr {
                    protocol_from: Some(Protocol::Bgp4),
                    protocol_into: Some(Protocol::Ospf),
                    afi_expr: AfiExpr {
                        afis: None,
                        expr: Expr::Unit(Term(vec![Factor {
                            peerings: vec![("AS1".parse().unwrap(), None)],
                            filter: "AS2".parse().unwrap(),
                            direction: PhantomData,
                        }]))
                    },
                }
            }
        }
    }
}
