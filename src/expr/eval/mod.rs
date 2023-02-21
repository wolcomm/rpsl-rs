use std::iter::FromIterator;
use std::ops::{BitAnd, BitOr, Not};

use ip;

use crate::names;

use super::filter;

mod any;
mod apply;
mod error;

use self::{
    any::AnyPrefixRange,
    apply::Apply as _,
    error::{EvaluationError, EvaluationErrorKind, EvaluationResult},
};

trait PrefixSet<A>:
    FromIterator<EvaluationResult<ip::PrefixRange<A>>>
    + IntoIterator<Item = EvaluationResult<ip::PrefixRange<A>>>
where
    A: filter::ExprAfi,
{
}

trait Evaluate<R> {
    type Output;
    fn evaluate(self, resolver: &mut R) -> EvaluationResult<Self::Output>;
}

impl<A, R, I, E> Evaluate<R> for filter::Expr<A>
where
    A: filter::ExprAfi,
    A::PrefixRange: AnyPrefixRange,
    R: Resolver<filter::NamedPrefixSet<A>, Output = I>
        + Resolver<names::FilterSet, Output = filter::Expr<A>>,
    I: IntoIterator<Item = Result<ip::PrefixRange<A>, E>>,
    I::IntoIter: 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    type Output = Box<dyn PrefixSet<A>>;
    fn evaluate(self, resolver: &mut R) -> EvaluationResult<Self::Output> {
        match self {
            Self::Unit(term) => term.evaluate(resolver)?.collect(),
            Self::Not(_) => todo!(),
            Self::And(_, _) => todo!(),
            Self::Or(_, _) => todo!(),
        }
    }
}

impl<A, R, I, E> Evaluate<R> for filter::Term<A>
where
    A: filter::ExprAfi,
    A::PrefixRange: AnyPrefixRange,
    R: Resolver<filter::NamedPrefixSet<A>, Output = I>
        + Resolver<names::FilterSet, Output = filter::Expr<A>>,
    I: IntoIterator<Item = Result<ip::PrefixRange<A>, E>>,
    I::IntoIter: 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    type Output = Box<dyn Iterator<Item = EvaluationResult<ip::PrefixRange<A>>>>;
    fn evaluate(self, resolver: &mut R) -> EvaluationResult<Self::Output> {
        match self {
            Self::Any => Ok(Box::new(A::PrefixRange::any().map(Ok)) as Self::Output),
            Self::Literal(literal) => literal.evaluate(resolver),
            Self::Named(filter_set) => resolver
                .resolve(&filter_set)
                .map_err(|err| {
                    EvaluationError::new_from(
                        EvaluationErrorKind::Resolution,
                        format!("failed to resolve {:?}", filter_set),
                        Some(err),
                    )
                })
                .and_then(|expr| expr.evaluate(resolver))
                .map(|prefix_set| Box::new(prefix_set.into_iter()) as Self::Output),
            Self::Expr(expr) => expr
                .evaluate(resolver)
                .map(|prefix_set| Box::new(prefix_set.into_iter()) as Self::Output),
        }
    }
}

impl<A, R, I, E> Evaluate<R> for filter::Literal<A>
where
    A: filter::ExprAfi,
    R: Resolver<filter::NamedPrefixSet<A>, Output = I>,
    I: IntoIterator<Item = Result<ip::PrefixRange<A>, E>>,
    I::IntoIter: 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    type Output = Box<dyn Iterator<Item = EvaluationResult<ip::PrefixRange<A>>>>;
    fn evaluate(self, resolver: &mut R) -> EvaluationResult<Self::Output> {
        match self {
            Self::PrefixSet(prefix_set_expr, operator) => {
                prefix_set_expr.evaluate(resolver).map(move |iter| {
                    Box::new(iter.filter_map(move |result| {
                        result
                            .and_then(|range| operator.apply::<A, _>(range))
                            .transpose()
                    })) as Self::Output
                })
            }
            Self::AsPath(_) => todo!("AS-path regexp expressions not yet implemented"),
            Self::AttrMatch(_) => todo!("action match expressions not yet implemented"),
        }
    }
}

impl<A, R, I, E> Evaluate<R> for filter::PrefixSetExpr<A>
where
    A: filter::ExprAfi,
    R: Resolver<filter::NamedPrefixSet<A>, Output = I>,
    I: IntoIterator<Item = Result<ip::PrefixRange<A>, E>>,
    I::IntoIter: 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    type Output = Box<dyn Iterator<Item = EvaluationResult<ip::PrefixRange<A>>>>;
    fn evaluate(self, resolver: &mut R) -> EvaluationResult<Self::Output> {
        match self {
            Self::Literal(prefix_ranges) => {
                Ok(Box::new(prefix_ranges.into_iter().filter_map(|range| {
                    range
                        .operator()
                        .apply::<A, _>(range.prefix().into_inner())
                        .transpose()
                })) as Self::Output)
            }
            Self::Named(named) => named.evaluate(resolver),
        }
    }
}

impl<A, R, I, E> Evaluate<R> for filter::NamedPrefixSet<A>
where
    A: filter::ExprAfi,
    R: Resolver<filter::NamedPrefixSet<A>, Output = I>,
    I: IntoIterator<Item = Result<ip::PrefixRange<A>, E>>,
    I::IntoIter: 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    type Output = Box<dyn Iterator<Item = EvaluationResult<ip::PrefixRange<A>>>>;
    fn evaluate(self, resolver: &mut R) -> EvaluationResult<Self::Output> {
        resolver
            .resolve(&self)
            .map_err(|err| {
                EvaluationError::new_from(
                    EvaluationErrorKind::Resolution,
                    format!("failed to resolve {:?}", self),
                    Some(err),
                )
            })
            .map(|iter| {
                Box::new(iter.into_iter().map(|result| {
                    result.map_err(|err| {
                        EvaluationError::new_from(
                            EvaluationErrorKind::Resolution,
                            "error while resolving named prefix set",
                            Some(err),
                        )
                    })
                })) as Self::Output
            })
    }
}

trait Resolver<T> {
    type Output;
    type Error: std::error::Error + Send + Sync + 'static;
    fn resolve(&mut self, expr: &T) -> Result<Self::Output, Self::Error>;
}
