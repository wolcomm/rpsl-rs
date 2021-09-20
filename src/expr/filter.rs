use std::convert::{TryFrom, TryInto};
use std::fmt;

use ipnet::{IpNet, Ipv4Net};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

use crate::{
    error::{ParseError, ParseResult},
    names::{AsSet, AutNum, FilterSet, RouteSet},
    parser::{ParserRule, TokenPair},
    primitive::{LiteralPrefixSetEntry, RangeOperator},
};

pub type FilterExpr = Expr<Ipv4Net>;
pub type MpFilterExpr = Expr<IpNet>;

// TODO: seperate filter and mp-filter expressions.
/// RSPL `mp-filter` expression. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.5.2
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Expr<T> {
    /// An expression containing a single [`Term`].
    Unit(Term<T>),
    /// An expression containing the negation (`NOT ...`) of a [`Term`].
    Not(Term<T>),
    /// An expression containing the logical intersection (`... AND ...`) of a
    /// pair of [`Term`]s.
    And(Term<T>, Term<T>),
    /// An expression containing the logical union (`... OR ...`) of a
    /// pair of [`Term`]s.
    Or(Term<T>, Term<T>),
}

impl TryFrom<TokenPair<'_>> for Expr<Ipv4Net> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            ParserRule::filter_expr_unit => Ok(Self::Unit(
                next_into_or!(pair.into_inner() => "failed to get inner filter term"),
            )),
            ParserRule::filter_expr_not => Ok(Self::Not(
                next_into_or!(pair.into_inner() => "failed to get inner filter term"),
            )),
            ParserRule::filter_expr_and => {
                let mut pairs = pair.into_inner();
                let (left_term, right_term) = (
                    next_into_or!(pairs => "failed to get left inner filter term"),
                    next_into_or!(pairs => "failed to get right inner filter term"),
                );
                Ok(Self::And(left_term, right_term))
            }
            ParserRule::filter_expr_or => {
                let mut pairs = pair.into_inner();
                let (left_term, right_term) = (
                    next_into_or!(pairs => "failed to get left inner filter term"),
                    next_into_or!(pairs => "failed to get right inner filter term"),
                );
                Ok(Self::Or(left_term, right_term))
            }
            _ => Err(err!(
                "expected a filter expression, got {:?}: '{}'",
                pair.as_rule(),
                pair.as_str()
            )),
        }
    }
}

impl_from_str!(ParserRule::just_filter => Expr<Ipv4Net>);

impl TryFrom<TokenPair<'_>> for Expr<IpNet> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            ParserRule::mp_filter_expr_unit => Ok(Self::Unit(
                next_into_or!(pair.into_inner() => "failed to get inner mp-filter term"),
            )),
            ParserRule::mp_filter_expr_not => Ok(Self::Not(
                next_into_or!(pair.into_inner() => "failed to get inner mp-filter term"),
            )),
            ParserRule::mp_filter_expr_and => {
                let mut pairs = pair.into_inner();
                let (left_term, right_term) = (
                    next_into_or!(pairs => "failed to get left inner mp-filter term"),
                    next_into_or!(pairs => "failed to get right inner mp-filter term"),
                );
                Ok(Self::And(left_term, right_term))
            }
            ParserRule::mp_filter_expr_or => {
                let mut pairs = pair.into_inner();
                let (left_term, right_term) = (
                    next_into_or!(pairs => "failed to get left inner mp-filter term"),
                    next_into_or!(pairs => "failed to get right inner mp-filter term"),
                );
                Ok(Self::Or(left_term, right_term))
            }
            _ => Err(err!(
                "expected an mp-filter expression, got {:?}: '{}'",
                pair.as_rule(),
                pair.as_str()
            )),
        }
    }
}

impl_from_str!(ParserRule::just_mp_filter => Expr<IpNet>);

impl<T: fmt::Display> fmt::Display for Expr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Unit(term) => term.fmt(f),
            Self::Not(term) => write!(f, "NOT {}", term),
            Self::And(lhs, rhs) => write!(f, "{} AND {}", lhs, rhs),
            Self::Or(lhs, rhs) => write!(f, "{} OR {}", lhs, rhs),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<T> Arbitrary for Expr<T>
where
    T: fmt::Debug + Clone + 'static,
    LiteralPrefixSetEntry<T>: Arbitrary,
    <LiteralPrefixSetEntry<T> as Arbitrary>::Parameters: Clone,
    <LiteralPrefixSetEntry<T> as Arbitrary>::Strategy: 'static,
{
    type Parameters = (ParamsFor<Term<T>>, ParamsFor<Term<T>>);
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any_with::<Term<T>>(args.0.clone()).prop_map(Self::Unit),
            any_with::<Term<T>>(args.0.clone()).prop_map(Self::Not),
            any_with::<(Term<T>, Term<T>)>(args.clone()).prop_map(|(lhs, rhs)| Self::And(lhs, rhs)),
            any_with::<(Term<T>, Term<T>)>(args.clone()).prop_map(|(lhs, rhs)| Self::Or(lhs, rhs)),
        ]
        .boxed()
    }
}

/// A term in an RPSL `mp-filter` expression.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Term<T> {
    /// The `ANY` token.
    Any,
    /// A literal prefix set expression.
    Literal(PrefixSetExpr<T>, RangeOperator),
    /// A named `filter-set`.
    Named(FilterSet),
    /// A parenthesised sub-expression.
    Expr(Box<Expr<T>>),
}

impl TryFrom<TokenPair<'_>> for Term<Ipv4Net> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Term);
        match pair.as_rule() {
            ParserRule::literal_filter => {
                let mut pairs = pair.into_inner();
                Ok(Self::Literal(
                    next_into_or!(pairs => "failed to get inner prefix set expression"),
                    match pairs.next() {
                        Some(inner) => inner.try_into()?,
                        None => RangeOperator::None,
                    },
                ))
            }
            ParserRule::named_filter => Ok(Self::Named(
                next_into_or!(pair.into_inner() => "failed to get inner filter-set name"),
            )),
            ParserRule::any_fltr => Ok(Self::Any),
            ParserRule::filter_expr_unit
            | ParserRule::filter_expr_not
            | ParserRule::filter_expr_and
            | ParserRule::filter_expr_or => Ok(Self::Expr(Box::new(pair.try_into()?))),
            _ => Err(err!(
                "expected filter term, got {:?}: {}",
                pair.as_rule(),
                pair.as_str()
            )),
        }
    }
}

impl TryFrom<TokenPair<'_>> for Term<IpNet> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Term);
        match pair.as_rule() {
            ParserRule::mp_literal_filter => {
                let mut pairs = pair.into_inner();
                Ok(Self::Literal(
                    next_into_or!(pairs => "failed to get inner prefix set expression"),
                    match pairs.next() {
                        Some(inner) => inner.try_into()?,
                        None => RangeOperator::None,
                    },
                ))
            }
            ParserRule::mp_named_filter => Ok(Self::Named(
                next_into_or!(pair.into_inner() => "failed to get inner filter-set name"),
            )),
            ParserRule::any_fltr => Ok(Self::Any),
            ParserRule::mp_filter_expr_unit
            | ParserRule::mp_filter_expr_not
            | ParserRule::mp_filter_expr_and
            | ParserRule::mp_filter_expr_or => Ok(Self::Expr(Box::new(pair.try_into()?))),
            _ => Err(err!(
                "expected mp-filter term, got {:?}: {}",
                pair.as_rule(),
                pair.as_str()
            )),
        }
    }
}

impl<T: fmt::Display> fmt::Display for Term<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Any => write!(f, "ANY"),
            Self::Literal(set_expr, op) => write!(f, "{}{}", set_expr, op),
            Self::Named(fltr_set_expr) => fltr_set_expr.fmt(f),
            Self::Expr(expr) => write!(f, "({})", expr),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<T> Arbitrary for Term<T>
where
    T: fmt::Debug + Clone + 'static,
    LiteralPrefixSetEntry<T>: Arbitrary,
    <LiteralPrefixSetEntry<T> as Arbitrary>::Parameters: Clone,
    <LiteralPrefixSetEntry<T> as Arbitrary>::Strategy: 'static,
{
    type Parameters = ParamsFor<(PrefixSetExpr<T>, RangeOperator)>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        let leaf = prop_oneof![
            any_with::<(PrefixSetExpr<T>, RangeOperator)>(args.clone())
                .prop_map(|(set, op)| Self::Literal(set, op)),
            any::<FilterSet>().prop_map(Self::Named),
            Just(Self::Any),
        ];
        leaf.prop_recursive(8, 16, 2, |inner| {
            prop_oneof![
                inner.clone().prop_map(Expr::Unit),
                inner.clone().prop_map(Expr::Not),
                (inner.clone(), inner.clone()).prop_map(|(lhs, rhs)| Expr::And(lhs, rhs)),
                (inner.clone(), inner.clone()).prop_map(|(lhs, rhs)| Expr::Or(lhs, rhs)),
            ]
            .prop_map(|expr| Self::Expr(Box::new(expr)))
        })
        .boxed()
    }
}

/// An RPSL sub-expression representing a set of IP prefixes.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum PrefixSetExpr<T> {
    /// A literal IP prefix list.
    Literal(Vec<LiteralPrefixSetEntry<T>>),
    /// A named RSPL object that can be evaluated as a `route-set`.
    Named(NamedPrefixSet),
}

impl TryFrom<TokenPair<'_>> for PrefixSetExpr<Ipv4Net> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => PrefixSetExpr);
        match pair.as_rule() {
            ParserRule::literal_prefix_set => Ok(Self::Literal(
                pair.into_inner()
                    .map(|inner| inner.try_into())
                    .collect::<ParseResult<_>>()?,
            )),
            ParserRule::named_prefix_set => Ok(Self::Named(
                next_into_or!(pair.into_inner() => "failed to get prefix set name"),
            )),
            _ => Err(err!(
                "expected prefix set expression, got {:?}: {}",
                pair.as_rule(),
                pair.as_str()
            )),
        }
    }
}

impl TryFrom<TokenPair<'_>> for PrefixSetExpr<IpNet> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => PrefixSetExpr);
        match pair.as_rule() {
            ParserRule::mp_literal_prefix_set => Ok(Self::Literal(
                pair.into_inner()
                    .map(|inner| inner.try_into())
                    .collect::<ParseResult<_>>()?,
            )),
            ParserRule::named_prefix_set => Ok(Self::Named(
                next_into_or!(pair.into_inner() => "failed to get prefix set name"),
            )),
            _ => Err(err!(
                "expected prefix set expression, got {:?}: {}",
                pair.as_rule(),
                pair.as_str()
            )),
        }
    }
}

impl<T: fmt::Display> fmt::Display for PrefixSetExpr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Literal(entries) => write!(
                f,
                "{{{}}}",
                entries
                    .iter()
                    .map(|entry| entry.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Named(set) => set.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<T> Arbitrary for PrefixSetExpr<T>
where
    T: fmt::Debug + 'static,
    LiteralPrefixSetEntry<T>: Arbitrary,
    <LiteralPrefixSetEntry<T> as Arbitrary>::Strategy: 'static,
{
    type Parameters = ParamsFor<Vec<LiteralPrefixSetEntry<T>>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any_with::<Vec<LiteralPrefixSetEntry<T>>>(args).prop_map(Self::Literal),
            any::<NamedPrefixSet>().prop_map(Self::Named),
        ]
        .boxed()
    }
}

/// Enumeration of RSPL objects that can be evaluated in a context where a
/// `route-set` is expected. See [RFC2622]
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.3
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum NamedPrefixSet {
    /// The `RS-ANY` token.
    RsAny,
    /// The `AS-ANY` token.
    AsAny,
    /// The `PeerAS` token.
    PeerAs,
    /// A `route-set` name.
    RouteSet(RouteSet),
    /// An `as-set` name.
    AsSet(AsSet),
    /// An `aut-num` name.
    AutNum(AutNum),
}

impl TryFrom<TokenPair<'_>> for NamedPrefixSet {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => NamedPrefixSet);
        match pair.as_rule() {
            ParserRule::any_rs => Ok(Self::RsAny),
            ParserRule::any_as => Ok(Self::AsAny),
            ParserRule::peeras => Ok(Self::PeerAs),
            ParserRule::route_set => Ok(Self::RouteSet(pair.try_into()?)),
            ParserRule::as_set => Ok(Self::AsSet(pair.try_into()?)),
            ParserRule::aut_num => Ok(Self::AutNum(pair.try_into()?)),
            _ => Err(err!(
                "expected a named prefix set variant, got {:?}: {}",
                pair.as_rule(),
                pair.as_str()
            )),
        }
    }
}

impl fmt::Display for NamedPrefixSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::RsAny => write!(f, "RS-ANY"),
            Self::AsAny => write!(f, "AS-ANY"),
            Self::PeerAs => write!(f, "PeerAS"),
            Self::RouteSet(set) => set.fmt(f),
            Self::AsSet(set) => set.fmt(f),
            Self::AutNum(autnum) => autnum.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for NamedPrefixSet {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(Self::RsAny),
            Just(Self::AsAny),
            Just(Self::PeerAs),
            any::<RouteSet>().prop_map(Self::RouteSet),
            any::<AsSet>().prop_map(Self::AsSet),
            any::<AutNum>().prop_map(Self::AutNum),
        ]
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use ipnet::IpNet;
    use paste::paste;

    use crate::primitive::SetNameComp;

    use super::*;

    display_fmt_parses! {
        FilterExpr,
        MpFilterExpr,
    }

    macro_rules! test_exprs {
        ( $( $name:ident: $query:literal => $expr_t:ty: $expr:expr ),* $(,)? ) => {
            paste! {
                $(
                    #[test]
                    fn [< $name _expr>]() {
                        let ast: $expr_t = dbg!($query.parse().unwrap());
                        assert_eq!(ast, $expr)
                    }
                )*
            }
        }
    }

    test_exprs! {
        single_autnum: "AS65000" => FilterExpr:
            FilterExpr::Unit(Term::Literal(
                PrefixSetExpr::Named(NamedPrefixSet::AutNum("AS65000".parse().unwrap())),
                RangeOperator::None
            )),
        simple_as_set: "AS-FOO" => FilterExpr:
            FilterExpr::Unit(Term::Literal(
                PrefixSetExpr::Named(NamedPrefixSet::AsSet(vec![
                    SetNameComp::Name("AS-FOO".to_string())
                ].into_iter().collect())),
                RangeOperator::None
            )),
        hierarchical_as_set: "AS65000:AS-FOO" => FilterExpr:
            FilterExpr::Unit(Term::Literal(
                PrefixSetExpr::Named(NamedPrefixSet::AsSet(vec![
                    SetNameComp::AutNum("AS65000".parse().unwrap()),
                    SetNameComp::Name("AS-FOO".to_string())
                ].into_iter().collect())),
                RangeOperator::None
            )),
        simple_route_set: "RS-FOO" => FilterExpr:
            FilterExpr::Unit(Term::Literal(
                PrefixSetExpr::Named(NamedPrefixSet::RouteSet(vec![
                    SetNameComp::Name("RS-FOO".to_string())
                ].into_iter().collect())),
                RangeOperator::None
            )),
        hierarchical_route_set: "AS65000:RS-FOO" => FilterExpr:
            FilterExpr::Unit(Term::Literal(
                PrefixSetExpr::Named(NamedPrefixSet::RouteSet(vec![
                    SetNameComp::AutNum("AS65000".parse().unwrap()),
                    SetNameComp::Name("RS-FOO".to_string())
                ].into_iter().collect())),
                RangeOperator::None
            )),
        peeras: "PeerAS" => FilterExpr:
            FilterExpr::Unit(Term::Literal(
                PrefixSetExpr::Named(NamedPrefixSet::PeerAs),
                RangeOperator::None
            )),
        any: "RS-ANY" => FilterExpr:
            FilterExpr::Unit(Term::Literal(
                PrefixSetExpr::Named(NamedPrefixSet::RsAny),
                RangeOperator::None
            )),
        named_filter_set: "FLTR-FOO" => FilterExpr:
            FilterExpr::Unit(Term::Named(vec![
                SetNameComp::Name("FLTR-FOO".to_string()),
            ].into_iter().collect())),
        hierarchical_named_filter_set: "AS65000:FLTR-FOO" => FilterExpr:
            FilterExpr::Unit(Term::Named(vec![
                SetNameComp::AutNum("AS65000".parse().unwrap()),
                SetNameComp::Name("FLTR-FOO".to_string()),
            ].into_iter().collect())),
        empty_literal_prefix_set: "{}" => FilterExpr:
            FilterExpr::Unit(Term::Literal(
                PrefixSetExpr::Literal(vec![]),
                RangeOperator::None,
            )),
        single_literal_prefix_set: "{ 192.0.2.0/24^- }" => FilterExpr:
            FilterExpr::Unit(Term::Literal(
                PrefixSetExpr::Literal(vec![
                    LiteralPrefixSetEntry::new(
                        "192.0.2.0/24".parse().unwrap(),
                        RangeOperator::LessExcl,
                    ),
                ]),
                RangeOperator::None,
            )),
        multi_literal_prefix_set: "{ 192.0.2.0/25^+, 192.0.2.128/26^27, 2001:db8::/32^48-56 }" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Literal(
                PrefixSetExpr::Literal(vec![
                    LiteralPrefixSetEntry::new(
                        IpNet::V4("192.0.2.0/25".parse().unwrap()),
                        RangeOperator::LessIncl,
                    ),
                    LiteralPrefixSetEntry::new(
                        IpNet::V4("192.0.2.128/26".parse().unwrap()),
                        RangeOperator::Exact(27),
                    ),
                    LiteralPrefixSetEntry::new(
                        IpNet::V6("2001:db8::/32".parse().unwrap()),
                        RangeOperator::Range(48, 56),
                    ),
                ]),
                RangeOperator::None,
            )),

        // Parenthesised
        parens_single_autnum: "(AS65000)" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(
                    PrefixSetExpr::Named(NamedPrefixSet::AutNum("AS65000".parse().unwrap())),
                    RangeOperator::None
                ))
            ))),
        parens_hierarchical_as_set: "(AS65000:AS-FOO:PeerAS)" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(
                    PrefixSetExpr::Named(NamedPrefixSet::AsSet(vec![
                        SetNameComp::AutNum("AS65000".parse().unwrap()),
                        SetNameComp::Name("AS-FOO".to_string()),
                        SetNameComp::PeerAs,
                    ].into_iter().collect())),
                    RangeOperator::None
                ))
            ))),
        parens_peeras: "(PeerAS)" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(
                    PrefixSetExpr::Named(NamedPrefixSet::PeerAs),
                    RangeOperator::None
                ))
            ))),
        parens_any: "(AS-ANY)" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(
                    PrefixSetExpr::Named(NamedPrefixSet::AsAny),
                    RangeOperator::None
                ))
            ))),
        parens_empty_literal_prefix_set: "({})" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(
                    PrefixSetExpr::Literal(vec![]),
                    RangeOperator::None,
                ))
            ))),
        parens_single_literal_prefix_set: "({ 192.0.2.0/24^- })" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(
                    PrefixSetExpr::Literal(vec![
                        LiteralPrefixSetEntry::new(
                            IpNet::V4("192.0.2.0/24".parse().unwrap()),
                            RangeOperator::LessExcl,
                        ),
                    ]),
                    RangeOperator::None,
                ))
            ))),
        parens_multi_literal_prefix_set: "({ 192.0.2.0/25^+, 192.0.2.128/26^27, 2001:db8::/32^48-56 })" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(
                    PrefixSetExpr::Literal(vec![
                        LiteralPrefixSetEntry::new(
                            IpNet::V4("192.0.2.0/25".parse().unwrap()),
                            RangeOperator::LessIncl,
                        ),
                        LiteralPrefixSetEntry::new(
                            IpNet::V4("192.0.2.128/26".parse().unwrap()),
                            RangeOperator::Exact(27),
                        ),
                        LiteralPrefixSetEntry::new(
                            IpNet::V6("2001:db8::/32".parse().unwrap()),
                            RangeOperator::Range(48, 56),
                        ),
                    ]),
                    RangeOperator::None,
                ))
            ))),
    }
}
