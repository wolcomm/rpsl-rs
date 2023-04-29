use super::error::{EvaluationError, EvaluationErrorKind};

pub trait Resolver<T> {
    type Output;
    type Error: std::error::Error + Send + Sync + 'static;
    fn resolve(&mut self, expr: &T) -> Result<Self::Output, Self::Error>;
}

pub(super) trait ResolverError: std::error::Error + Send + Sync + 'static {}

impl<E> ResolverError for E where E: std::error::Error + Send + Sync + 'static {}

pub(super) fn map_errors<I, U, T, E>(
    iter: I,
    item: U,
) -> impl Iterator<Item = Result<T, EvaluationError>>
where
    E: ResolverError,
    I: IntoIterator<Item = Result<T, E>>,
    U: std::fmt::Debug,
{
    iter.into_iter().map(move |result| {
        result.map_err(|err| {
            EvaluationError::new_from(
                EvaluationErrorKind::Resolution,
                format!("error while resolving named prefix set {item:?}"),
                Some(err),
            )
        })
    })
}
