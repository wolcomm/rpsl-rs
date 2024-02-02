use std::fmt;
use std::marker::PhantomData;

use ip::{Any, Ipv4};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

use crate::{
    error::{ParseError, ParseResult},
    names::{AsSet, AutNum, FilterSet, RouteSet},
    parser::{
        debug_construction, impl_from_str, next_into_or, next_parse_or, rule_mismatch, ParserRule,
        TokenPair,
    },
    primitive::{IpPrefixRange, ParserAfi, PeerAs, RangeOperator},
};

use super::action;

pub trait ExprAfi: ParserAfi {
    /// Address family specific [`ParserRule`] for IP prefix set literals.
    const LITERAL_PREFIX_SET_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for ranged IP prefix set literals.
    const LITERAL_RANGED_PREFIX_SET_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for literal filter terms.
    const LITERAL_FILTER_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for named filter terms.
    const NAMED_FILTER_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for unit filter expressions.
    const FILTER_EXPR_UNIT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for negated filter expressions.
    const FILTER_EXPR_NOT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for conjunctive filter expressions.
    const FILTER_EXPR_AND_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for disjunctive filter expressions.
    const FILTER_EXPR_OR_RULE: ParserRule;
    /// Array of address family specific [`ParserRule`] for filter expressions.
    const FILTER_EXPR_RULES: [ParserRule; 4] = [
        Self::FILTER_EXPR_UNIT_RULE,
        Self::FILTER_EXPR_NOT_RULE,
        Self::FILTER_EXPR_AND_RULE,
        Self::FILTER_EXPR_OR_RULE,
    ];
    /// Check whether a [`ParserRule`] variant is a `filter` expression for
    /// this address family.
    fn match_filter_expr_rule(rule: ParserRule) -> bool {
        Self::FILTER_EXPR_RULES
            .iter()
            .any(|filter_expr_rule| &rule == filter_expr_rule)
    }
    /// Address family specific [`ParserRule`] for filter expressions.
    const FILTER_EXPR_ROOT_RULE: ParserRule;
}

impl ExprAfi for Ipv4 {
    const LITERAL_PREFIX_SET_RULE: ParserRule = ParserRule::literal_prefix_set;
    const LITERAL_RANGED_PREFIX_SET_RULE: ParserRule = ParserRule::ranged_prefix_set;
    const LITERAL_FILTER_RULE: ParserRule = ParserRule::literal_filter;
    const NAMED_FILTER_RULE: ParserRule = ParserRule::named_filter;
    const FILTER_EXPR_UNIT_RULE: ParserRule = ParserRule::filter_expr_unit;
    const FILTER_EXPR_NOT_RULE: ParserRule = ParserRule::filter_expr_not;
    const FILTER_EXPR_AND_RULE: ParserRule = ParserRule::filter_expr_and;
    const FILTER_EXPR_OR_RULE: ParserRule = ParserRule::filter_expr_or;
    const FILTER_EXPR_ROOT_RULE: ParserRule = ParserRule::just_filter_expr;
}

impl ExprAfi for Any {
    const LITERAL_PREFIX_SET_RULE: ParserRule = ParserRule::mp_literal_prefix_set;
    const LITERAL_RANGED_PREFIX_SET_RULE: ParserRule = ParserRule::mp_ranged_prefix_set;
    const LITERAL_FILTER_RULE: ParserRule = ParserRule::mp_literal_filter;
    const NAMED_FILTER_RULE: ParserRule = ParserRule::mp_named_filter;
    const FILTER_EXPR_UNIT_RULE: ParserRule = ParserRule::mp_filter_expr_unit;
    const FILTER_EXPR_NOT_RULE: ParserRule = ParserRule::mp_filter_expr_not;
    const FILTER_EXPR_AND_RULE: ParserRule = ParserRule::mp_filter_expr_and;
    const FILTER_EXPR_OR_RULE: ParserRule = ParserRule::mp_filter_expr_or;
    const FILTER_EXPR_ROOT_RULE: ParserRule = ParserRule::just_mp_filter_expr;
}

/// RPSL `filter` expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.4
#[allow(clippy::module_name_repetitions)]
pub type FilterExpr = Expr<Ipv4>;

/// RPSL `mp-filter` expression. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.5.2
pub type MpFilterExpr = Expr<Any>;

impl_from_str! {
    forall A: ExprAfi {
        A::FILTER_EXPR_ROOT_RULE => Expr<A>
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Expr<A: ExprAfi> {
    /// An expression containing a single [`Term`].
    Unit(Term<A>),
    /// An expression containing the negation (`NOT ...`) of a [`Term`].
    Not(Box<Expr<A>>),
    /// An expression containing the logical intersection (`... AND ...`) of a
    /// pair of [`Term`]s.
    And(Term<A>, Box<Expr<A>>),
    /// An expression containing the logical union (`... OR ...`) of a
    /// pair of [`Term`]s.
    Or(Term<A>, Box<Expr<A>>),
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for Expr<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            rule if rule == A::FILTER_EXPR_UNIT_RULE => Ok(Self::Unit(
                next_into_or!(pair.into_inner() => "failed to get inner filter term")?,
            )),
            rule if rule == A::FILTER_EXPR_NOT_RULE => Ok(Self::Not(Box::new(
                next_into_or!(pair.into_inner() => "failed to get inner filter term")?,
            ))),
            rule if rule == A::FILTER_EXPR_AND_RULE => {
                let mut pairs = pair.into_inner();
                let (left_term, right_expr) = (
                    next_into_or!(pairs => "failed to get left inner filter term")?,
                    Box::new(next_into_or!(pairs => "failed to get right inner filter term")?),
                );
                Ok(Self::And(left_term, right_expr))
            }
            rule if rule == A::FILTER_EXPR_OR_RULE => {
                let mut pairs = pair.into_inner();
                let (left_term, right_expr) = (
                    next_into_or!(pairs => "failed to get left inner filter term")?,
                    Box::new(next_into_or!(pairs => "failed to get right inner filter term")?),
                );
                Ok(Self::Or(left_term, right_expr))
            }
            _ => Err(rule_mismatch!(pair => "filter expression")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for Expr<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unit(term) => term.fmt(f),
            Self::Not(expr) => write!(f, "NOT {expr}"),
            Self::And(lhs, rhs) => write!(f, "{lhs} AND {rhs}"),
            Self::Or(lhs, rhs) => write!(f, "{lhs} OR {rhs}"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for Expr<A>
where
    A: ExprAfi + fmt::Debug + Clone + 'static,
    Term<A>: Arbitrary,
    <Term<A> as Arbitrary>::Parameters: Clone,
{
    type Parameters = ParamsFor<Term<A>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        let term = any_with::<Term<A>>(args.clone()).boxed();
        any_with::<Term<A>>(args)
            .prop_map(Self::Unit)
            .prop_recursive(2, 4, 4, move |unit| {
                prop_oneof![
                    unit.clone().prop_map(|unit| Self::Not(Box::new(unit))),
                    (term.clone(), unit.clone())
                        .prop_map(|(term, unit)| Self::And(term, Box::new(unit))),
                    (term.clone(), unit).prop_map(|(term, unit)| Self::Or(term, Box::new(unit))),
                ]
            })
            .boxed()
    }
}

/// A term in an RPSL `mp-filter` expression.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Term<A: ExprAfi> {
    /// The `ANY` token.
    Any,
    /// A literal prefix set expression.
    Literal(Literal<A>),
    /// A named `filter-set`.
    Named(FilterSet),
    /// A parenthesised sub-expression.
    Expr(Box<Expr<A>>),
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for Term<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => Term);
        match pair.as_rule() {
            rule if rule == A::LITERAL_FILTER_RULE => Ok(Self::Literal(
                next_into_or!(pair.into_inner() => "failed to get filter literal")?,
            )),
            rule if rule == A::NAMED_FILTER_RULE => Ok(Self::Named(
                next_into_or!(pair.into_inner() => "failed to get inner filter-set name")?,
            )),
            ParserRule::any_fltr => Ok(Self::Any),
            rule if A::match_filter_expr_rule(rule) => Ok(Self::Expr(Box::new(pair.try_into()?))),
            _ => Err(rule_mismatch!(pair => "filter term")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for Term<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => write!(f, "ANY"),
            Self::Literal(fltr_literal) => fltr_literal.fmt(f),
            Self::Named(fltr_set_expr) => fltr_set_expr.fmt(f),
            Self::Expr(expr) => write!(f, "({expr})"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for Term<A>
where
    A: ExprAfi + Clone + fmt::Debug + 'static,
    PrefixSetExpr<A>: Arbitrary,
    <PrefixSetExpr<A> as Arbitrary>::Parameters: Clone,
{
    type Parameters = ParamsFor<Literal<A>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        let leaf = prop_oneof![
            any_with::<Literal<A>>(args).prop_map(Self::Literal),
            any::<FilterSet>().prop_map(Self::Named),
            Just(Self::Any),
        ];
        leaf.prop_recursive(2, 4, 4, |inner| {
            prop_oneof![
                inner.clone().prop_map(Expr::Unit),
                inner
                    .clone()
                    .prop_map(|inner| Expr::Not(Box::new(Expr::Unit(inner)))),
                (inner.clone(), inner.clone())
                    .prop_map(|(lhs, rhs)| Expr::And(lhs, Box::new(Expr::Unit(rhs)))),
                (inner.clone(), inner)
                    .prop_map(|(lhs, rhs)| Expr::Or(lhs, Box::new(Expr::Unit(rhs)))),
            ]
            .prop_map(|expr| Self::Expr(Box::new(expr)))
        })
        .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Literal<A: ExprAfi> {
    PrefixSet(PrefixSetExpr<A>, RangeOperator),
    AsPath(AsPathRegexp),
    AttrMatch(action::Stmt),
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for Literal<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => Literal);
        match pair.as_rule() {
            rule if rule == A::LITERAL_RANGED_PREFIX_SET_RULE => {
                let mut pairs = pair.into_inner();
                Ok(Self::PrefixSet(
                    next_into_or!(pairs => "failed to get inner prefix set expression")?,
                    match pairs.next() {
                        Some(inner) => inner.try_into()?,
                        None => RangeOperator::None,
                    },
                ))
            }
            ParserRule::as_path_regexpr => Ok(Self::AsPath(pair.try_into()?)),
            ParserRule::action_stmt_oper | ParserRule::action_stmt_meth => {
                Ok(Self::AttrMatch(pair.try_into()?))
            }
            _ => Err(rule_mismatch!(pair => "filter literal")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for Literal<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrefixSet(set_expr, op) => write!(f, "{set_expr}{op}"),
            Self::AsPath(as_path_regexp) => as_path_regexp.fmt(f),
            Self::AttrMatch(stmt) => stmt.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for Literal<A>
where
    A: ExprAfi + Clone + fmt::Debug + 'static,
    PrefixSetExpr<A>: Arbitrary,
    <PrefixSetExpr<A> as Arbitrary>::Parameters: Clone,
{
    type Parameters = (
        ParamsFor<(PrefixSetExpr<A>, RangeOperator)>,
        ParamsFor<AsPathRegexp>,
        ParamsFor<action::Stmt>,
    );
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any_with::<(PrefixSetExpr<A>, RangeOperator)>(args.0)
                .prop_map(|(set, op)| Self::PrefixSet(set, op)),
            any_with::<AsPathRegexp>(args.1).prop_map(Self::AsPath),
            any_with::<action::Stmt>(args.2).prop_map(Self::AttrMatch),
        ]
        .boxed()
    }
}

/// An RPSL sub-expression representing a set of IP prefixes.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum PrefixSetExpr<A: ExprAfi> {
    /// A literal IP prefix list.
    Literal(Vec<IpPrefixRange<A>>),
    /// A named RSPL object that can be evaluated as a `route-set`.
    Named(NamedPrefixSet<A>),
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for PrefixSetExpr<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => PrefixSetExpr);
        match pair.as_rule() {
            rule if rule == A::LITERAL_PREFIX_SET_RULE => Ok(Self::Literal(
                pair.into_inner()
                    .map(IpPrefixRange::try_from)
                    .collect::<ParseResult<_>>()?,
            )),
            ParserRule::named_prefix_set => Ok(Self::Named(
                next_into_or!(pair.into_inner() => "failed to get prefix set name")?,
            )),
            _ => Err(rule_mismatch!(pair => "prefix-set expression")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for PrefixSetExpr<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(entries) => write!(
                f,
                "{{{}}}",
                entries
                    .iter()
                    .map(IpPrefixRange::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Named(set) => set.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for PrefixSetExpr<A>
where
    A: ExprAfi + fmt::Debug + 'static,
    IpPrefixRange<A>: Arbitrary,
    <IpPrefixRange<A> as Arbitrary>::Strategy: 'static,
{
    type Parameters = ParamsFor<Vec<IpPrefixRange<A>>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any_with::<Vec<IpPrefixRange<A>>>(args).prop_map(Self::Literal),
            any::<NamedPrefixSet<A>>().prop_map(Self::Named),
        ]
        .boxed()
    }
}

/// Enumeration of RSPL objects that can be evaluated in a context where a
/// `route-set` is expected. See [RFC2622]
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.3
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum NamedPrefixSet<A: ExprAfi> {
    /// The `RS-ANY` token.
    RsAny,
    /// The `AS-ANY` token.
    AsAny,
    /// The `PeerAS` token.
    PeerAs(PeerAs),
    /// A `route-set` name.
    RouteSet(RouteSet, PhantomData<A>),
    /// An `as-set` name.
    AsSet(AsSet, PhantomData<A>),
    /// An `aut-num` name.
    AutNum(AutNum, PhantomData<A>),
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for NamedPrefixSet<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => NamedPrefixSet);
        match pair.as_rule() {
            ParserRule::any_rs => Ok(Self::RsAny),
            ParserRule::any_as => Ok(Self::AsAny),
            ParserRule::peeras => Ok(Self::PeerAs(PeerAs)),
            ParserRule::route_set => Ok(Self::RouteSet(pair.try_into()?, PhantomData)),
            ParserRule::as_set => Ok(Self::AsSet(pair.try_into()?, PhantomData)),
            ParserRule::aut_num => Ok(Self::AutNum(pair.try_into()?, PhantomData)),
            _ => Err(rule_mismatch!(pair => "named prefix-set variant")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for NamedPrefixSet<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RsAny => write!(f, "RS-ANY"),
            Self::AsAny => write!(f, "AS-ANY"),
            Self::PeerAs(_) => write!(f, "PeerAS"),
            Self::RouteSet(set, _) => set.fmt(f),
            Self::AsSet(set, _) => set.fmt(f),
            Self::AutNum(autnum, _) => autnum.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for NamedPrefixSet<A>
where
    A: ExprAfi + 'static,
{
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(Self::RsAny),
            Just(Self::AsAny),
            Just(Self::PeerAs(PeerAs)),
            any::<RouteSet>().prop_map(|set| Self::RouteSet(set, PhantomData)),
            any::<AsSet>().prop_map(|set| Self::AsSet(set, PhantomData)),
            any::<AutNum>().prop_map(|autnum| Self::AutNum(autnum, PhantomData)),
        ]
        .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AsPathRegexp {
    match_start: bool,
    elements: Vec<AsPathRegexpElem>,
    match_end: bool,
}

impl AsPathRegexp {
    fn new(match_start: bool, elements: Vec<AsPathRegexpElem>, match_end: bool) -> Self {
        Self {
            match_start,
            elements,
            match_end,
        }
    }
}

impl TryFrom<TokenPair<'_>> for AsPathRegexp {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => AsPathRegexp);
        match pair.as_rule() {
            ParserRule::as_path_regexpr => {
                let mut pairs = pair.into_inner().peekable();
                let mut elements = vec![];
                let match_start = if pairs.peek().map(TokenPair::as_rule)
                    == Some(ParserRule::as_path_regexpr_soi)
                {
                    _ = pairs.next();
                    true
                } else {
                    false
                };
                while pairs.peek().map(TokenPair::as_rule) == Some(ParserRule::as_path_regexpr_elem)
                {
                    elements.push(pairs.next().unwrap().try_into()?);
                }
                let match_end = if pairs.peek().map(TokenPair::as_rule)
                    == Some(ParserRule::as_path_regexpr_eoi)
                {
                    _ = pairs.next();
                    true
                } else {
                    false
                };
                Ok(Self::new(match_start, elements, match_end))
            }
            _ => Err(rule_mismatch!(pair => "AS path regexp")),
        }
    }
}

impl fmt::Display for AsPathRegexp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<")?;
        if self.match_start {
            write!(f, "^")?;
        };
        write!(
            f,
            "{}",
            self.elements
                .iter()
                .map(AsPathRegexpElem::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        )?;
        if self.match_end {
            write!(f, "$")?;
        };
        write!(f, ">")
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for AsPathRegexp {
    type Parameters = ParamsFor<Vec<AsPathRegexpElem>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            any::<bool>(),
            any_with::<Vec<AsPathRegexpElem>>(params),
            any::<bool>(),
        )
            .prop_map(|(match_start, elements, match_end)| {
                Self::new(match_start, elements, match_end)
            })
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AsPathRegexpElem {
    component: AsPathRegexpComponent,
    op: Option<AsPathRegexpOp>,
}

impl AsPathRegexpElem {
    const fn new(component: AsPathRegexpComponent, op: Option<AsPathRegexpOp>) -> Self {
        Self { component, op }
    }
}

impl TryFrom<TokenPair<'_>> for AsPathRegexpElem {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => AsPathRegexpElem);
        match pair.as_rule() {
            ParserRule::as_path_regexpr_elem => {
                let mut pairs = pair.into_inner();
                Ok(Self::new(
                    next_into_or!(pairs => "failed to get inner AS path regexp component")?,
                    match pairs.next() {
                        Some(inner) => Some(inner.try_into()?),
                        None => None,
                    },
                ))
            }
            _ => Err(rule_mismatch!(pair => "AS path regexp element")),
        }
    }
}

impl fmt::Display for AsPathRegexpElem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.component.fmt(f)?;
        if let Some(op) = &self.op {
            op.fmt(f)?;
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for AsPathRegexpElem {
    type Parameters = ParamsFor<Option<AsPathRegexpOp>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            any::<AsPathRegexpComponent>(),
            any_with::<Option<AsPathRegexpOp>>(params),
        )
            .prop_map(|(component, op)| Self::new(component, op))
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) enum AsPathRegexpComponent {
    AutNum(AutNum),
    AsSet(AsSet),
    Any,
    ComponentSet(Vec<AsPathRegexpComponentSetMember>),
    ComplComponentSet(Vec<AsPathRegexpComponentSetMember>),
    Alternates(Box<AsPathRegexpElem>, Box<AsPathRegexpElem>),
}

impl TryFrom<TokenPair<'_>> for AsPathRegexpComponent {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => AsPathRegexpComponent);
        match pair.as_rule() {
            ParserRule::as_set => Ok(Self::AsSet(pair.try_into()?)),
            ParserRule::aut_num => Ok(Self::AutNum(pair.try_into()?)),
            ParserRule::as_path_any => Ok(Self::Any),
            ParserRule::as_path_set => Ok(Self::ComponentSet(
                pair.into_inner()
                    .map(AsPathRegexpComponentSetMember::try_from)
                    .collect::<ParseResult<_>>()?,
            )),
            ParserRule::as_path_set_compl => Ok(Self::ComplComponentSet(
                pair.into_inner()
                    .map(AsPathRegexpComponentSetMember::try_from)
                    .collect::<ParseResult<_>>()?,
            )),
            ParserRule::as_path_regexpr_alt => {
                let mut pairs = pair.into_inner();
                Ok(Self::Alternates(
                    Box::new(
                        next_into_or!(pairs => "failed to get alternate AS path regexp element")?,
                    ),
                    Box::new(
                        next_into_or!(pairs => "failed to get alternate AS path regexp element")?,
                    ),
                ))
            }
            _ => Err(rule_mismatch!(pair => "AS path regexp component")),
        }
    }
}

impl fmt::Display for AsPathRegexpComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AutNum(aut_num) => aut_num.fmt(f),
            Self::AsSet(as_set) => as_set.fmt(f),
            Self::Any => write!(f, "."),
            Self::ComponentSet(components) => {
                write!(
                    f,
                    "[{}]",
                    components
                        .iter()
                        .map(AsPathRegexpComponentSetMember::to_string)
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
            Self::ComplComponentSet(components) => {
                write!(
                    f,
                    "[^{}]",
                    components
                        .iter()
                        .map(AsPathRegexpComponentSetMember::to_string)
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
            Self::Alternates(left, right) => write!(f, "({left}|{right})"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for AsPathRegexpComponent {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<AutNum>().prop_map(Self::AutNum),
            any::<AsSet>().prop_map(Self::AsSet),
            Just(Self::Any),
            proptest::collection::vec(any::<AsPathRegexpComponentSetMember>(), 1..10)
                .prop_map(Self::ComponentSet),
            proptest::collection::vec(any::<AsPathRegexpComponentSetMember>(), 1..10)
                .prop_map(Self::ComplComponentSet),
        ]
        .prop_recursive(2, 4, 4, |inner| {
            (
                (inner.clone(), any::<Option<AsPathRegexpOp>>()),
                (inner, any::<Option<AsPathRegexpOp>>()),
            )
                .prop_map(
                    |((left_component, left_op), (right_component, right_op))| {
                        Self::Alternates(
                            Box::new(AsPathRegexpElem::new(left_component, left_op)),
                            Box::new(AsPathRegexpElem::new(right_component, right_op)),
                        )
                    },
                )
        })
        .boxed()
    }
}

#[allow(variant_size_differences)]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) enum AsPathRegexpComponentSetMember {
    AutNum(AutNum),
    AsSet(AsSet),
    AsRange(AutNum, AutNum),
}

impl TryFrom<TokenPair<'_>> for AsPathRegexpComponentSetMember {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => AsPathRegexpComponentSetMember);
        match pair.as_rule() {
            ParserRule::as_set => Ok(Self::AsSet(pair.try_into()?)),
            ParserRule::aut_num => Ok(Self::AutNum(pair.try_into()?)),
            ParserRule::as_path_set_range => {
                let mut pairs = pair.into_inner();
                Ok(Self::AsRange(
                    next_into_or!(pairs => "failed to get AS range lower bound")?,
                    next_into_or!(pairs => "failed to get AS range upper bound")?,
                ))
            }
            _ => Err(rule_mismatch!(pair => "AS set member")),
        }
    }
}

impl fmt::Display for AsPathRegexpComponentSetMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AutNum(aut_num) => aut_num.fmt(f),
            Self::AsSet(as_set) => as_set.fmt(f),
            Self::AsRange(lower, upper) => write!(f, "{lower}-{upper}"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for AsPathRegexpComponentSetMember {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<AutNum>().prop_map(Self::AutNum),
            any::<AsSet>().prop_map(Self::AsSet),
            (any::<AutNum>(), any::<AutNum>())
                .prop_map(|(lower, upper)| Self::AsRange(lower, upper)),
        ]
        .boxed()
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum AsPathRegexpOp {
    Optional,
    Any,
    Multi,
    AtLeast(usize),
    AtMost(usize),
    Range(usize, usize),
    AnySame,
    MultiSame,
    AtLeastSame(usize),
    AtMostSame(usize),
    RangeSame(usize, usize),
}

impl TryFrom<TokenPair<'_>> for AsPathRegexpOp {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => AsPathRegexpOp);
        match pair.as_rule() {
            ParserRule::as_path_regexpr_opt => Ok(Self::Optional),
            ParserRule::as_path_regexpr_any => Ok(Self::Any),
            ParserRule::as_path_regexpr_multi => Ok(Self::Multi),
            ParserRule::as_path_regexpr_atleast => Ok(Self::AtLeast(
                next_parse_or!(pair.into_inner() => "failed to get repitition lower bound")?,
            )),
            ParserRule::as_path_regexpr_atmost => Ok(Self::AtMost(
                next_parse_or!(pair.into_inner() => "failed to get repitition upper bound")?,
            )),
            ParserRule::as_path_regexpr_range => {
                let mut pairs = pair.into_inner();
                Ok(Self::Range(
                    next_parse_or!(pairs => "failed to get repitition lower bound")?,
                    next_parse_or!(pairs => "failed to get repitition upper bound")?,
                ))
            }
            ParserRule::as_path_regexpr_any_same => Ok(Self::AnySame),
            ParserRule::as_path_regexpr_multi_same => Ok(Self::MultiSame),
            ParserRule::as_path_regexpr_atleast_same => Ok(Self::AtLeastSame(
                next_parse_or!(pair.into_inner() => "failed to get repitition lower bound")?,
            )),
            ParserRule::as_path_regexpr_atmost_same => Ok(Self::AtMostSame(
                next_parse_or!(pair.into_inner() => "failed to get repitition upper bound")?,
            )),
            ParserRule::as_path_regexpr_range_same => {
                let mut pairs = pair.into_inner();
                Ok(Self::RangeSame(
                    next_parse_or!(pairs => "failed to get repitition lower bound")?,
                    next_parse_or!(pairs => "failed to get repitition upper bound")?,
                ))
            }
            _ => Err(rule_mismatch!(pair => "AS path regexp repitition operator")),
        }
    }
}

impl fmt::Display for AsPathRegexpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Optional => write!(f, "?"),
            Self::Any => write!(f, "*"),
            Self::Multi => write!(f, "+"),
            Self::AtLeast(lower) => write!(f, "{{{lower},}}"),
            Self::AtMost(upper) => write!(f, "{{,{upper}}}"),
            Self::Range(lower, upper) => write!(f, "{{{lower},{upper}}}"),
            Self::AnySame => write!(f, "~*"),
            Self::MultiSame => write!(f, "~+"),
            Self::AtLeastSame(lower) => write!(f, "~{{{lower},}}"),
            Self::AtMostSame(upper) => write!(f, "~{{,{upper}}}"),
            Self::RangeSame(lower, upper) => write!(f, "~{{{lower},{upper}}}"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for AsPathRegexpOp {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(Self::Optional),
            Just(Self::Any),
            Just(Self::Multi),
            any::<usize>().prop_map(Self::AtLeast),
            any::<usize>().prop_map(Self::AtMost),
            (any::<usize>(), any::<usize>()).prop_map(|(lower, upper)| Self::Range(lower, upper)),
            Just(Self::AnySame),
            Just(Self::MultiSame),
            any::<usize>().prop_map(Self::AtLeastSame),
            any::<usize>().prop_map(Self::AtMostSame),
            (any::<usize>(), any::<usize>())
                .prop_map(|(lower, upper)| Self::RangeSame(lower, upper)),
        ]
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use paste::paste;

    use crate::{
        primitive::SetNameComp,
        tests::{compare_ast, display_fmt_parses},
    };

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
            FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                PrefixSetExpr::Named(NamedPrefixSet::AutNum("AS65000".parse().unwrap(), PhantomData)),
                RangeOperator::None
            ))),
        simple_as_set: "AS-FOO" => FilterExpr:
            FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                PrefixSetExpr::Named(NamedPrefixSet::AsSet(vec![
                    SetNameComp::Name("AS-FOO".into())
                ].into_iter().collect(), PhantomData)),
                RangeOperator::None
            ))),
        hierarchical_as_set: "AS65000:AS-FOO" => FilterExpr:
            FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                PrefixSetExpr::Named(NamedPrefixSet::AsSet(vec![
                    SetNameComp::AutNum("AS65000".parse().unwrap()),
                    SetNameComp::Name("AS-FOO".into())
                ].into_iter().collect(), PhantomData)),
                RangeOperator::None
            ))),
        simple_route_set: "RS-FOO" => FilterExpr:
            FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                PrefixSetExpr::Named(NamedPrefixSet::RouteSet(vec![
                    SetNameComp::Name("RS-FOO".into())
                ].into_iter().collect(), PhantomData)),
                RangeOperator::None
            ))),
        hierarchical_route_set: "AS65000:RS-FOO" => FilterExpr:
            FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                PrefixSetExpr::Named(NamedPrefixSet::RouteSet(vec![
                    SetNameComp::AutNum("AS65000".parse().unwrap()),
                    SetNameComp::Name("RS-FOO".into())
                ].into_iter().collect(), PhantomData)),
                RangeOperator::None
            ))),
        peeras: "PeerAS" => FilterExpr:
            FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                PrefixSetExpr::Named(NamedPrefixSet::PeerAs(PeerAs)),
                RangeOperator::None
            ))),
        any: "RS-ANY" => FilterExpr:
            FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                PrefixSetExpr::Named(NamedPrefixSet::RsAny),
                RangeOperator::None
            ))),
        named_filter_set: "FLTR-FOO" => FilterExpr:
            FilterExpr::Unit(Term::Named(vec![
                SetNameComp::Name("FLTR-FOO".into()),
            ].into_iter().collect())),
        hierarchical_named_filter_set: "AS65000:FLTR-FOO" => FilterExpr:
            FilterExpr::Unit(Term::Named(vec![
                SetNameComp::AutNum("AS65000".parse().unwrap()),
                SetNameComp::Name("FLTR-FOO".into()),
            ].into_iter().collect())),
        empty_literal_prefix_set: "{}" => FilterExpr:
            FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                PrefixSetExpr::Literal(vec![]),
                RangeOperator::None,
            ))),
        single_literal_prefix_set: "{ 192.0.2.0/24^- }" => FilterExpr:
            FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                PrefixSetExpr::Literal(vec![
                    IpPrefixRange::new(
                        "192.0.2.0/24".parse().unwrap(),
                        RangeOperator::LessExcl,
                    ),
                ]),
                RangeOperator::None,
            ))),
        multi_literal_prefix_set: "{ 192.0.2.0/25^+, 192.0.2.128/26^27, 2001:db8::/32^48-56 }" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                PrefixSetExpr::Literal(vec![
                    IpPrefixRange::new(
                        "192.0.2.0/25".parse().unwrap(),
                        RangeOperator::LessIncl,
                    ),
                    IpPrefixRange::new(
                        "192.0.2.128/26".parse().unwrap(),
                        RangeOperator::Exact(27),
                    ),
                    IpPrefixRange::new(
                        "2001:db8::/32".parse().unwrap(),
                        RangeOperator::Range(48, 56),
                    ),
                ]),
                RangeOperator::None,
            ))),

        // Parenthesised
        parens_single_autnum: "(AS65000)" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Named(NamedPrefixSet::AutNum("AS65000".parse().unwrap(), PhantomData)),
                    RangeOperator::None
                )))
            ))),
        parens_hierarchical_as_set: "(AS65000:AS-FOO:PeerAS)" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Named(NamedPrefixSet::AsSet(vec![
                        SetNameComp::AutNum("AS65000".parse().unwrap()),
                        SetNameComp::Name("AS-FOO".into()),
                        SetNameComp::PeerAs(PeerAs),
                    ].into_iter().collect(), PhantomData)),
                    RangeOperator::None
                )))
            ))),
        parens_peeras: "(PeerAS)" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Named(NamedPrefixSet::PeerAs(PeerAs)),
                    RangeOperator::None
                )))
            ))),
        parens_any: "(AS-ANY)" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Named(NamedPrefixSet::AsAny),
                    RangeOperator::None
                )))
            ))),
        parens_empty_literal_prefix_set: "({})" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Literal(vec![]),
                    RangeOperator::None,
                )))
            ))),
        parens_single_literal_prefix_set: "({ 192.0.2.0/24^- })" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Literal(vec![
                        IpPrefixRange::new(
                            "192.0.2.0/24".parse().unwrap(),
                            RangeOperator::LessExcl,
                        ),
                    ]),
                    RangeOperator::None,
                )))
            ))),
        parens_multi_literal_prefix_set: "({ 192.0.2.0/25^+, 192.0.2.128/26^27, 2001:db8::/32^48-56 })" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Expr(Box::new(
                Expr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Literal(vec![
                        IpPrefixRange::new(
                            "192.0.2.0/25".parse().unwrap(),
                            RangeOperator::LessIncl,
                        ),
                        IpPrefixRange::new(
                            "192.0.2.128/26".parse().unwrap(),
                            RangeOperator::Exact(27),
                        ),
                        IpPrefixRange::new(
                            "2001:db8::/32".parse().unwrap(),
                            RangeOperator::Range(48, 56),
                        ),
                    ]),
                    RangeOperator::None,
                )))
            ))),
        as_path_empty: "<>" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Literal(Literal::AsPath(AsPathRegexp::new(
                false,
                vec![],
                false,
            )))),
        as_path_strict_empty: "<^$>" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Literal(Literal::AsPath(AsPathRegexp::new(
                true,
                vec![],
                true,
            )))),
        as_path_autnum: "<^AS65000 AS65001>" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Literal(Literal::AsPath(AsPathRegexp::new(
                true,
                vec![
                    AsPathRegexpElem::new(
                        AsPathRegexpComponent::AutNum("AS65000".parse().unwrap()),
                        None,
                    ),
                    AsPathRegexpElem::new(
                        AsPathRegexpComponent::AutNum("AS65001".parse().unwrap()),
                        None,
                    ),
                ],
                false,
            )))),
        as_path_as_set: "<^AS-FOO? AS65001$>" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Literal(Literal::AsPath(AsPathRegexp::new(
                true,
                vec![
                    AsPathRegexpElem::new(
                        AsPathRegexpComponent::AsSet("AS-FOO".parse().unwrap()),
                        Some(AsPathRegexpOp::Optional),
                    ),
                    AsPathRegexpElem::new(
                        AsPathRegexpComponent::AutNum("AS65001".parse().unwrap()),
                        None,
                    ),
                ],
                true,
            )))),
        as_path_alternates: "<(AS-FOO+ | AS65000) AS65001* $>" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Literal(Literal::AsPath(AsPathRegexp::new(
                false,
                vec![
                    AsPathRegexpElem::new(
                        AsPathRegexpComponent::Alternates(
                            Box::new(AsPathRegexpElem::new(
                                AsPathRegexpComponent::AsSet("AS-FOO".parse().unwrap()),
                                Some(AsPathRegexpOp::Multi),
                            )),
                            Box::new(AsPathRegexpElem::new(
                                AsPathRegexpComponent::AutNum("AS65000".parse().unwrap()),
                                None,
                            )),
                        ),
                        None,
                    ),
                    AsPathRegexpElem::new(
                        AsPathRegexpComponent::AutNum("AS65001".parse().unwrap()),
                        Some(AsPathRegexpOp::Any),
                    ),
                ],
                true,
            )))),
        as_path_sets: "<[AS-FOO AS65000-AS65003]+ AS65001 $>" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Literal(Literal::AsPath(AsPathRegexp::new(
                false,
                vec![
                    AsPathRegexpElem::new(
                        AsPathRegexpComponent::ComponentSet(vec![
                            AsPathRegexpComponentSetMember::AsSet("AS-FOO".parse().unwrap()),
                            AsPathRegexpComponentSetMember::AsRange(
                                "AS65000".parse().unwrap(),
                                "AS65003".parse().unwrap(),
                            )
                        ]),
                        Some(AsPathRegexpOp::Multi),
                    ),
                    AsPathRegexpElem::new(
                        AsPathRegexpComponent::AutNum("AS65001".parse().unwrap()),
                        None,
                    ),
                ],
                true,
            )))),
        as_path_set_compl: "<^ [^AS-FOO AS-BAR]~{1,3} AS65001{2,} $>" => MpFilterExpr:
            MpFilterExpr::Unit(Term::Literal(Literal::AsPath(AsPathRegexp::new(
                true,
                vec![
                    AsPathRegexpElem::new(
                        AsPathRegexpComponent::ComplComponentSet(vec![
                            AsPathRegexpComponentSetMember::AsSet("AS-FOO".parse().unwrap()),
                            AsPathRegexpComponentSetMember::AsSet("AS-BAR".parse().unwrap()),
                        ]),
                        Some(AsPathRegexpOp::RangeSame(1, 3)),
                    ),
                    AsPathRegexpElem::new(
                        AsPathRegexpComponent::AutNum("AS65001".parse().unwrap()),
                        Some(AsPathRegexpOp::AtLeast(2)),
                    ),
                ],
                true,
            )))),
    }

    compare_ast! {
        FilterExpr {
            rfc2622_sect6_autnum_example1: "{ 128.9.0.0/16 }" => {
                FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Literal(vec![
                        IpPrefixRange::new("128.9.0.0/16".parse().unwrap(), RangeOperator::None)
                    ]),
                    RangeOperator::None,
                )))
            }
            rfc2622_sect5_example1: "{ 5.0.0.0/8, 6.0.0.0/8 }" => {
                FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Literal(vec![
                        IpPrefixRange::new("5.0.0.0/8".parse().unwrap(), RangeOperator::None),
                        IpPrefixRange::new("6.0.0.0/8".parse().unwrap(), RangeOperator::None),
                    ]),
                    RangeOperator::None,
                )))
            }
            rfc2622_sect5_example2: "(AS1 or fltr-foo) and <AS2>" => {
                FilterExpr::And(
                    Term::Expr(Box::new(FilterExpr::Or(
                        Term::Literal(Literal::PrefixSet(
                            PrefixSetExpr::Named(NamedPrefixSet::AutNum("AS1".parse().unwrap(), PhantomData)),
                            RangeOperator::None,
                        )),
                        Box::new(Expr::Unit(Term::Named("fltr-foo".parse().unwrap()))),
                    ))),
                    Box::new(Expr::Unit(Term::Literal(Literal::AsPath(AsPathRegexp::new(
                        false,
                        vec![
                            AsPathRegexpElem::new(
                                AsPathRegexpComponent::AutNum("AS2".parse().unwrap()),
                                None,
                            ),
                        ],
                        false,
                    ))))),
                )
            }
            rfc2622_sect5_example3: "{ 0.0.0.0/0 }" => {
                FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Literal(vec![
                        IpPrefixRange::new("0.0.0.0/0".parse().unwrap(), RangeOperator::None),
                    ]),
                    RangeOperator::None,
                )))
            }
            rfc2622_sect5_example4: "{ 128.9.0.0/16, 128.8.0.0/16, 128.7.128.0/17, 5.0.0.0/8 }" => {
                FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Literal(vec![
                        IpPrefixRange::new("128.9.0.0/16".parse().unwrap(), RangeOperator::None),
                        IpPrefixRange::new("128.8.0.0/16".parse().unwrap(), RangeOperator::None),
                        IpPrefixRange::new("128.7.128.0/17".parse().unwrap(), RangeOperator::None),
                        IpPrefixRange::new("5.0.0.0/8".parse().unwrap(), RangeOperator::None),
                    ]),
                    RangeOperator::None,
                )))
            }
            rfc2622_sect5_example5: "{ }" => {
                FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Literal(vec![]),
                    RangeOperator::None,
                )))
            }
            rfc2622_sect5_example6: "{ 5.0.0.0/8^+, 128.9.0.0/16^-, 30.0.0.0/8^16, 30.0.0.0/8^24-32 }" => {
                FilterExpr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Literal(vec![
                        IpPrefixRange::new("5.0.0.0/8".parse().unwrap(), RangeOperator::LessIncl),
                        IpPrefixRange::new("128.9.0.0/16".parse().unwrap(), RangeOperator::LessExcl),
                        IpPrefixRange::new("30.0.0.0/8".parse().unwrap(), RangeOperator::Exact(16)),
                        IpPrefixRange::new("30.0.0.0/8".parse().unwrap(), RangeOperator::Range(24, 32)),
                    ]),
                    RangeOperator::None,
                )))
            }
            rfc2622_sect5_example7: "<AS3>" => {
                FilterExpr::Unit(Term::Literal(Literal::AsPath(AsPathRegexp::new(
                    false,
                    vec![
                        AsPathRegexpElem::new(
                            AsPathRegexpComponent::AutNum("AS3".parse().unwrap()),
                            None,
                        ),
                    ],
                    false,
                ))))
            }
            rfc2622_sect5_example8: "<^AS1>" => {
                FilterExpr::Unit(Term::Literal(Literal::AsPath(AsPathRegexp::new(
                    true,
                    vec![
                        AsPathRegexpElem::new(
                            AsPathRegexpComponent::AutNum("AS1".parse().unwrap()),
                            None,
                        ),
                    ],
                    false,
                ))))
            }
            rfc2622_sect5_example9: "<AS2$>" => {
                FilterExpr::Unit(Term::Literal(Literal::AsPath(AsPathRegexp::new(
                    false,
                    vec![
                        AsPathRegexpElem::new(
                            AsPathRegexpComponent::AutNum("AS2".parse().unwrap()),
                            None,
                        ),
                    ],
                    true,
                ))))
            }
            rfc2622_sect5_example10: "<^AS1 AS2 AS3$>" => {
                FilterExpr::Unit(Term::Literal(Literal::AsPath(AsPathRegexp::new(
                    true,
                    vec![
                        AsPathRegexpElem::new(
                            AsPathRegexpComponent::AutNum("AS1".parse().unwrap()),
                            None,
                        ),
                        AsPathRegexpElem::new(
                            AsPathRegexpComponent::AutNum("AS2".parse().unwrap()),
                            None,
                        ),
                        AsPathRegexpElem::new(
                            AsPathRegexpComponent::AutNum("AS3".parse().unwrap()),
                            None,
                        ),
                    ],
                    true,
                ))))
            }
            rfc2622_sect5_example11: "<^AS1 .* AS2$>" => {
                FilterExpr::Unit(Term::Literal(Literal::AsPath(AsPathRegexp::new(
                    true,
                    vec![
                        AsPathRegexpElem::new(
                            AsPathRegexpComponent::AutNum("AS1".parse().unwrap()),
                            None,
                        ),
                        AsPathRegexpElem::new(
                            AsPathRegexpComponent::Any,
                            Some(AsPathRegexpOp::Any),
                        ),
                        AsPathRegexpElem::new(
                            AsPathRegexpComponent::AutNum("AS2".parse().unwrap()),
                            None,
                        ),
                    ],
                    true,
                ))))
            }
            rfc2622_sect5_example12: "NOT {128.9.0.0/16, 128.8.0.0/16}" => {
                FilterExpr::Not(Box::new(Expr::Unit(Term::Literal(Literal::PrefixSet(
                    PrefixSetExpr::Literal(
                        vec![
                            IpPrefixRange::new(
                                "128.9.0.0/16".parse().unwrap(),
                                RangeOperator::None,
                            ),
                            IpPrefixRange::new(
                                "128.8.0.0/16".parse().unwrap(),
                                RangeOperator::None,
                            )
                        ],
                    ),
                    RangeOperator::None,
                )))))
            }
            rfc2622_sect5_example13: "AS226 AS227 OR AS228" => {
                FilterExpr::Or(
                    Term::Literal(Literal::PrefixSet(
                        PrefixSetExpr::Named(NamedPrefixSet::AutNum("AS226".parse().unwrap(), PhantomData)),
                        RangeOperator::None,
                    )),
                    Box::new(Expr::Or(
                        Term::Literal(Literal::PrefixSet(
                            PrefixSetExpr::Named(NamedPrefixSet::AutNum("AS227".parse().unwrap(), PhantomData)),
                            RangeOperator::None,
                        )),
                        Box::new(Expr::Unit(Term::Literal(Literal::PrefixSet(
                            PrefixSetExpr::Named(NamedPrefixSet::AutNum("AS228".parse().unwrap(), PhantomData)),
                            RangeOperator::None,
                        ))))
                    ))
                )
            }
            rfc2622_sect5_example14: "AS226 AND NOT {128.9.0.0/16}" => {
                FilterExpr::And(
                    Term::Literal(Literal::PrefixSet(
                        PrefixSetExpr::Named(NamedPrefixSet::AutNum("AS226".parse().unwrap(), PhantomData)),
                        RangeOperator::None,
                    )),
                    Box::new(Expr::Not(Box::new(Expr::Unit(
                        Term::Literal(Literal::PrefixSet(
                            PrefixSetExpr::Literal(
                                vec![
                                    IpPrefixRange::new(
                                        "128.9.0.0/16".parse().unwrap(),
                                        RangeOperator::None,
                                    )
                                ],
                            ),
                            RangeOperator::None,
                        ))
                    ))))
                )
            }
            rfc2622_sect5_example15: "AS226 AND {0.0.0.0/0^0-18}" => {
                FilterExpr::And(
                    Term::Literal(Literal::PrefixSet(
                        PrefixSetExpr::Named(NamedPrefixSet::AutNum("AS226".parse().unwrap(), PhantomData)),
                        RangeOperator::None,
                    )),
                    Box::new(Expr::Unit(Term::Literal(Literal::PrefixSet(
                        PrefixSetExpr::Literal(
                            vec![
                                IpPrefixRange::new(
                                    "0.0.0.0/0".parse().unwrap(),
                                    RangeOperator::Range(0, 18),
                                )
                            ]
                        ),
                        RangeOperator::None,
                    ))))
                )
            }
        }
    }
}
