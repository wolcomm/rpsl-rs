use core::ops::Not;

use ip::{self, traits::PrefixSet as _};

use crate::{names, primitive};

use super::filter;

mod apply;
use self::apply::Apply;

mod error;
pub use self::error::EvaluationError;

mod resolver;
pub use self::resolver::{Evaluator, Resolver};

mod sealed {
    pub trait Sealed {}
}
use sealed::Sealed;

/// An RPSL expression that is capable of being "evaluated".
///
/// The provided implementations define the AST traversal and roll-up logic for each expression
/// type.
///
/// When a name or primitive is encountered, the job of resolving that item to the necessary
/// intermediate data type is delegated to `resolver`.
///
/// The bounds on each implementation determine the resolver capabilities necessary for evaluating
/// the implementing expression type.
pub trait Evaluate<'a, R>: Sized + Sealed {
    /// The type output by evaluating `Self`.
    type Output: 'a;

    /// Evaluate `self`, performing name resolution using `resolver`.
    ///
    /// # Errors
    ///
    /// If an unhandled error is encountered during the evaluation, then an [`Err`] containing an
    /// [`EvaluationError`] will be returned.
    ///
    /// For details on handling recoverable errors, see the methods on [`Evaluator`].
    fn evaluate(self, resolver: &mut R) -> Result<Self::Output, EvaluationError>;
}

impl<A: filter::ExprAfi> Sealed for filter::Expr<A> {}
impl<'a, A, R> Evaluate<'a, R> for filter::Expr<A>
where
    A: filter::ExprAfi,
    R: Resolver<'a, names::FilterSet, Self>
        + Resolver<'a, names::AsSet, A::PrefixSet>
        + Resolver<'a, primitive::PeerAs, A::PrefixSet>
        + Resolver<'a, names::RouteSet, A::PrefixSet>
        + Resolver<'a, names::AutNum, A::PrefixSet>,
{
    type Output = A::PrefixSet;
    fn evaluate(self, resolver: &mut R) -> Result<Self::Output, EvaluationError> {
        match self {
            Self::Unit(term) => term.evaluate(resolver),
            Self::Not(term) => term.evaluate(resolver).map(Self::Output::not),
            Self::And(lhs, rhs) => Ok(lhs.evaluate(resolver)? & rhs.evaluate(resolver)?),
            Self::Or(lhs, rhs) => Ok(lhs.evaluate(resolver)? | rhs.evaluate(resolver)?),
        }
    }
}

impl<A: filter::ExprAfi> Sealed for filter::Term<A> {}
impl<'a, A, R> Evaluate<'a, R> for filter::Term<A>
where
    A: filter::ExprAfi,
    R: Resolver<'a, names::FilterSet, filter::Expr<A>>
        + Resolver<'a, names::AsSet, A::PrefixSet>
        + Resolver<'a, primitive::PeerAs, A::PrefixSet>
        + Resolver<'a, names::RouteSet, A::PrefixSet>
        + Resolver<'a, names::AutNum, A::PrefixSet>,
{
    type Output = A::PrefixSet;
    fn evaluate(self, resolver: &mut R) -> Result<Self::Output, EvaluationError> {
        match self {
            Self::Any => Ok(A::PrefixSet::any()),
            Self::Literal(literal) => literal.evaluate(resolver),
            Self::Named(filter_set) => {
                resolve_or_map_err!(resolver, filter_set)?.evaluate(resolver)
            }
            Self::Expr(expr) => expr.evaluate(resolver),
        }
    }
}

impl<A: filter::ExprAfi> Sealed for filter::Literal<A> {}
impl<'a, A, R> Evaluate<'a, R> for filter::Literal<A>
where
    A: filter::ExprAfi,
    R: Resolver<'a, names::AsSet, A::PrefixSet>
        + Resolver<'a, primitive::PeerAs, A::PrefixSet>
        + Resolver<'a, names::RouteSet, A::PrefixSet>
        + Resolver<'a, names::AutNum, A::PrefixSet>,
{
    type Output = A::PrefixSet;
    fn evaluate(self, resolver: &mut R) -> Result<Self::Output, EvaluationError> {
        match self {
            Self::PrefixSet(prefix_set_expr, operator) => {
                prefix_set_expr.evaluate(resolver).and_then(|output| {
                    resolver.collect_results(output.ranges().filter_map(|range| {
                        <A::PrefixRange as Apply<A>>::apply(range, operator).transpose()
                    }))
                })
            }
            Self::AsPath(_) => todo!("AS-path regexp expressions not yet implemented"),
            Self::AttrMatch(_) => todo!("action match expressions not yet implemented"),
        }
    }
}

impl<A: filter::ExprAfi> Sealed for filter::PrefixSetExpr<A> {}
impl<'a, A, R> Evaluate<'a, R> for filter::PrefixSetExpr<A>
where
    A: filter::ExprAfi,
    R: Resolver<'a, names::AsSet, A::PrefixSet>
        + Resolver<'a, primitive::PeerAs, A::PrefixSet>
        + Resolver<'a, names::RouteSet, A::PrefixSet>
        + Resolver<'a, names::AutNum, A::PrefixSet>,
{
    type Output = A::PrefixSet;
    fn evaluate(self, resolver: &mut R) -> Result<Self::Output, EvaluationError> {
        match self {
            Self::Literal(prefix_ranges) => {
                resolver.collect_results(prefix_ranges.into_iter().filter_map(|range| {
                    let prefix = range.prefix().into_inner();
                    <A::Prefix as Apply<A>>::apply(prefix, range.operator()).transpose()
                }))
            }
            Self::Named(named) => named.evaluate(resolver),
        }
    }
}

impl<A: filter::ExprAfi> Sealed for filter::NamedPrefixSet<A> {}
impl<'a, A, R> Evaluate<'a, R> for filter::NamedPrefixSet<A>
where
    A: filter::ExprAfi,
    R: Resolver<'a, names::AsSet, A::PrefixSet>
        + Resolver<'a, primitive::PeerAs, A::PrefixSet>
        + Resolver<'a, names::RouteSet, A::PrefixSet>
        + Resolver<'a, names::AutNum, A::PrefixSet>,
{
    type Output = A::PrefixSet;
    fn evaluate(self, resolver: &mut R) -> Result<Self::Output, EvaluationError> {
        match self {
            Self::RsAny | Self::AsAny => Ok(A::PrefixSet::any()),
            Self::PeerAs(peer_as) => resolve_or_map_err!(resolver, peer_as),
            Self::AsSet(as_set, _) => resolve_or_map_err!(resolver, as_set),
            Self::RouteSet(route_set, _) => resolve_or_map_err!(resolver, route_set),
            Self::AutNum(autnum, _) => resolve_or_map_err!(resolver, autnum),
        }
    }
}

macro_rules! resolve_or_map_err {
    ($resolver:expr, $item:expr) => {
        $resolver
            .resolve(&$item)
            .map_err(|err| EvaluationError::Resolution {
                item: Box::new($item),
                source: Box::new(err),
            })
    };
}
use resolve_or_map_err;
