use std::marker::PhantomData;
use std::ops::Deref;

use super::filter;

mod apply;
mod data;
mod error;
mod resolve;
mod resolver;
/// traits for performing value substitution on RPSL expressions.
mod subst;
// Evaluation states
mod state;

use self::{
    error::EvaluationResult, resolve::Resolve, resolver::Resolver, state::State, subst::Substitute,
};

#[derive(Clone, Debug)]
pub struct Evaluation<T, S: State> {
    expr: T,
    state: PhantomData<S>,
}

impl<T, S: State> Deref for Evaluation<T, S> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.expr
    }
}

impl<T, S: State> AsRef<T> for Evaluation<T, S> {
    fn as_ref(&self) -> &T {
        self.deref()
    }
}

impl<T, S: State> Evaluation<T, S> {
    fn into_inner(self) -> T {
        self.expr
    }
}

// impl<T> From<T> for Evaluation<T, state::New> {
//     fn from(expr: T) -> Self {
//         Evaluation {
//             expr,
//             state: PhantomData,
//         }
//     }
// }
//
impl<A: filter::ExprAfi> From<filter::Expr<A>> for Evaluation<filter::Expr<A>, state::New> {
    fn from(expr: filter::Expr<A>) -> Self {
        Self {
            expr,
            state: PhantomData,
        }
    }
}

impl<A: filter::ExprAfi> From<Evaluation<filter::Expr<A>, state::Substituted>>
    for Evaluation<filter::Expr<A>, state::Ready>
{
    fn from(evaluation: Evaluation<filter::Expr<A>, state::Substituted>) -> Self {
        Evaluation {
            expr: evaluation.into_inner(),
            state: PhantomData,
        }
    }
}

trait PreEvaluate<I>: Into<Evaluation<Self, state::New>> {
    fn pre_evaluate(self, info: &mut I) -> EvaluationResult<Evaluation<Self, state::Ready>>;
}

impl<A: filter::ExprAfi, I: subst::PeerAs> PreEvaluate<I> for filter::Expr<A> {
    fn pre_evaluate(self, info: &mut I) -> EvaluationResult<Evaluation<Self, state::Ready>> {
        Ok(Evaluation::from(self).substitute(info)?.into())
    }
}

trait Evaluate<E: Resolver>: PreEvaluate<E>
where
    Evaluation<Self, state::Ready>: Resolve<E>,
{
    fn evaluate(
        self,
        evaluator: &mut E,
    ) -> EvaluationResult<<Evaluation<Self, state::Ready> as Resolve<E>>::Output> {
        self.pre_evaluate(evaluator)?.resolve(evaluator)
    }
}

impl<T, E> Evaluate<E> for T
where
    T: PreEvaluate<E>,
    E: Resolver,
    Evaluation<Self, state::Ready>: Resolve<E>,
{
}

#[cfg(test)]
mod tests;
