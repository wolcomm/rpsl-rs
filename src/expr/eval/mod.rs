use core::iter::once;
use core::ops::{BitAnd, BitOr, Not};

use ip::{self, traits::PrefixSet as _};

use crate::names;

use super::filter;

mod apply;
use self::apply::Apply;

mod error;
use self::error::{EvaluationError, EvaluationErrorKind, EvaluationErrors, EvaluationResult};

mod resolver;
pub use self::resolver::Resolver;
use self::resolver::{map_errors, ResolverError};

/// An object capable of evaluating arbitrary RPSL expressions.
pub trait Evaluator: Sized {
    /// Evaluate an RPSL expression.
    fn evaluate<T: Evaluate<Self>>(&mut self, expr: T) -> Evaluated<Self, T> {
        expr.evaluate(self)
    }
}

/// The value produced by evaluating an RPSL expression `T`.
#[derive(Debug)]
pub struct Evaluated<R, T: Evaluate<R>> {
    output: T::Output,
    errors: EvaluationErrors,
}

impl<R, T> Evaluated<R, T>
where
    T: Evaluate<R> + std::fmt::Debug,
    T::Output: Default,
{
    fn from_resolver_err<E: ResolverError>(err: E, item: &T) -> Self {
        let errors = once(EvaluationError::new_from(
            EvaluationErrorKind::Resolution,
            format!("failed to resolve {item:?}"),
            Some(err),
        ))
        .collect();
        Self {
            errors,
            output: Default::default(),
        }
    }
}

#[allow(clippy::missing_const_for_fn)]
impl<R, T: Evaluate<R>> Evaluated<R, T> {
    fn new(output: T::Output, errors: Option<EvaluationErrors>) -> Self {
        Self {
            output,
            errors: errors.unwrap_or_default(),
        }
    }

    /// Get a reference to the output of the evaluation.
    pub const fn output(&self) -> &T::Output {
        &self.output
    }

    /// Extract the evaluation output, consuming `self`.
    pub fn into_output(self) -> T::Output {
        self.output
    }

    /// Get an iterator over the errors produced during the evaluation.
    pub const fn errors(&self) -> &EvaluationErrors {
        &self.errors
    }

    fn and_then<U, F>(self, mut f: F) -> Evaluated<R, U>
    where
        U: Evaluate<R>,
        F: FnMut(&T::Output, &mut EvaluationErrors) -> U::Output,
    {
        let previous = &self.output;
        let mut errors = self.errors;
        let output = f(previous, &mut errors);
        Evaluated { output, errors }
    }

    fn pass<U>(self) -> Evaluated<R, U>
    where
        U: Evaluate<R, Output = T::Output>,
    {
        Evaluated {
            output: self.output,
            errors: self.errors,
        }
    }

    fn combine<F>(self, other: Self, f: F) -> Self
    where
        F: FnOnce(T::Output, T::Output) -> T::Output,
    {
        let errors = self
            .errors
            .into_iter()
            .chain(other.errors.into_iter())
            .collect();
        let output = f(self.output, other.output);
        Self { output, errors }
    }
}

impl<R, T, U> Extend<Result<U, EvaluationError>> for Evaluated<R, T>
where
    T: Evaluate<R>,
    T::Output: Extend<U>,
{
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Result<U, EvaluationError>>,
    {
        iter.into_iter().for_each(|item| match item {
            Ok(val) => self.output.extend(Some(val)),
            Err(err) => self.errors.extend(Some(err)),
        });
    }
}

impl<R, T, U> FromIterator<Result<U, EvaluationError>> for Evaluated<R, T>
where
    T: Evaluate<R>,
    T::Output: Default + Extend<U>,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Result<U, EvaluationError>>,
    {
        // TODO: this calls `T::Output::extend` for each `Ok(value)`.
        //       When `T::Output` is an `ip::PrefixSet` this will cause
        //       re-aggregation for each iteration, making it very slow.
        let mut this = Self {
            output: T::Output::default(),
            errors: EvaluationErrors::default(),
        };
        this.extend(iter);
        this
    }
}

impl<R, T> BitAnd for Evaluated<R, T>
where
    T: Evaluate<R>,
    T::Output: BitAnd<Output = T::Output>,
{
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.combine(rhs, BitAnd::bitand)
    }
}

impl<R, T> BitOr for Evaluated<R, T>
where
    T: Evaluate<R>,
    T::Output: BitOr<Output = T::Output>,
{
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.combine(rhs, BitOr::bitor)
    }
}

impl<R, T> Not for Evaluated<R, T>
where
    T: Evaluate<R>,
    T::Output: Not<Output = T::Output>,
{
    type Output = Self;

    fn not(self) -> Self::Output {
        Self::Output::new(!self.output, Some(self.errors))
    }
}

pub trait Evaluate<R>: Sized {
    type Output;
    fn evaluate(self, resolver: &mut R) -> Evaluated<R, Self>;
}

impl<A, R, I, E> Evaluate<R> for filter::Expr<A>
where
    A: filter::ExprAfi,
    R: Resolver<filter::NamedPrefixSet<A>, Output = I> + Resolver<names::FilterSet, Output = Self>,
    I: IntoIterator<Item = Result<A::PrefixRange, E>>,
    E: ResolverError,
{
    type Output = A::PrefixSet;
    fn evaluate(self, resolver: &mut R) -> Evaluated<R, Self> {
        match self {
            Self::Unit(term) => term.evaluate(resolver).pass(),
            Self::Not(term) => !term.evaluate(resolver).pass(),
            Self::And(lhs, rhs) => lhs.evaluate(resolver).pass() & rhs.evaluate(resolver),
            Self::Or(lhs, rhs) => lhs.evaluate(resolver).pass() | rhs.evaluate(resolver),
        }
    }
}

impl<A, R, I, E> Evaluate<R> for filter::Term<A>
where
    A: filter::ExprAfi,
    R: Resolver<filter::NamedPrefixSet<A>, Output = I>
        + Resolver<names::FilterSet, Output = filter::Expr<A>>,
    I: IntoIterator<Item = Result<A::PrefixRange, E>>,
    E: ResolverError,
{
    type Output = A::PrefixSet;
    fn evaluate(self, resolver: &mut R) -> Evaluated<R, Self> {
        match self {
            Self::Any => Evaluated::new(A::PrefixSet::any(), None),
            Self::Literal(literal) => literal.evaluate(resolver).pass(),
            Self::Named(ref filter_set) => match resolver.resolve(filter_set) {
                Ok(expr) => expr.evaluate(resolver).pass(),
                Err(err) => Evaluated::from_resolver_err(err, &self),
            },
            Self::Expr(expr) => expr.evaluate(resolver).pass(),
        }
    }
}

impl<A, R, I, E> Evaluate<R> for filter::Literal<A>
where
    A: filter::ExprAfi,
    R: Resolver<filter::NamedPrefixSet<A>, Output = I>,
    I: IntoIterator<Item = Result<A::PrefixRange, E>>,
    E: ResolverError,
{
    type Output = A::PrefixSet;
    fn evaluate(self, resolver: &mut R) -> Evaluated<R, Self> {
        match self {
            Self::PrefixSet(prefix_set_expr, operator) => prefix_set_expr
                .evaluate(resolver)
                .and_then(|output, errors| {
                    let mut new = Self::Output::default();
                    output
                        .ranges()
                        .filter_map(|range| {
                            <A::PrefixRange as Apply<A>>::apply(range, operator).transpose()
                        })
                        .for_each(|result| match result {
                            Ok(val) => new.extend(Some(val)),
                            Err(err) => errors.extend(Some(err)),
                        });
                    new
                }),
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
    E: ResolverError,
{
    type Output = A::PrefixSet;
    fn evaluate(self, resolver: &mut R) -> Evaluated<R, Self> {
        match self {
            Self::Literal(prefix_ranges) => prefix_ranges
                .into_iter()
                .filter_map(|range| {
                    let prefix = range.prefix().into_inner();
                    <A::Prefix as Apply<A>>::apply(prefix, range.operator()).transpose()
                })
                .collect(),
            Self::Named(named) => named.evaluate(resolver).pass(),
        }
    }
}

impl<A, R, I, E> Evaluate<R> for filter::NamedPrefixSet<A>
where
    A: filter::ExprAfi,
    R: Resolver<Self, Output = I>,
    I: IntoIterator<Item = Result<A::PrefixRange, E>>,
    E: ResolverError,
{
    type Output = A::PrefixSet;
    fn evaluate(self, resolver: &mut R) -> Evaluated<R, Self> {
        match resolver.resolve(&self) {
            Ok(iter) => map_errors(iter, &self).collect(),
            Err(err) => Evaluated::from_resolver_err(err, &self),
        }
    }
}
