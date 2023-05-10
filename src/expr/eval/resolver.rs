use super::{error::EvaluationError, Evaluate};

/// An object capable of evaluating arbitrary RPSL expressions.
///
/// The logic for traversing and evaluating specific RPSL filter expressions is implemented
/// in [`Evaluate<R>`].
///
/// This trait provides the generic [`evaluate()`][Self::evaluate] entry-point method, which is available
/// for every `T: Evaluate<Self>`.
///
/// In addition to an implementation of this trait, client code must also provide the necessary
/// implementations of [`Resolver<I, O>`] to meet the required trait bounds.
///
/// # Examples
///
/// A hypothetical implementation that resolves names via a local database look-up:
///
/// ``` no_run
/// use ip::{Any, PrefixSet};
/// use rpsl::{
///     names, primitive,
///     expr::{
///         eval::{Evaluate, Evaluator, EvaluationError, Resolver},
///         MpFilterExpr
///     }
/// };
///
/// // The type providing expression evaluation and name resolution
/// #[derive(Debug)]
/// struct Db {
///     // ..
/// }
///
/// // A custom error type that our client code will produce
/// #[derive(Debug)]
/// enum Error {
///     # Io
///     // ..
/// }
///
/// // impl std::error::Error + From<EvaluationError> for Error ..
/// # impl std::fmt::Display for Error {
/// #     fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { unimplemented!(); }
/// # }
/// # impl std::error::Error for Error {}
/// # impl From<EvaluationError> for Error {
/// #     fn from(_: EvaluationError) -> Self { unimplemented!(); }
/// # }
///
/// impl Db {
///     // open a connection to our database...
///     fn open() -> Self {
///         // ..
///         # unimplemented!();
///     }
///
///     // look up a name in the database and return the necessary output type for the context of
///     // the request...
///     fn fetch_as<I, O>(&mut self, item: &I) -> Result<O, Error> {
///         // ..
///         # unimplemented!();
///     }
///
///     // log an error via some implementation specific mechanism...
///     fn log(&mut self, err: &(dyn std::error::Error)) {
///         // ..
///         # unimplemented!()
///     }
/// }
///
/// impl<'a> Evaluator<'a> for Db {
///
///     // we could return another type here, but for simplicity, we just preserve the `Output`
///     type Output<T> = <T as Evaluate<'a, Self>>::Output
///     where
///         T: Evaluate<'a, Self>;
///
///     // our custom error type
///     type Error = Error;
///
///     // this is where we would construct our alternate `Output<T>`
///     fn finalise<T>(&mut self, output: T::Output) -> Result<Self::Output<T>, Self::Error>
///     where
///         T: Evaluate<'a, Self>,
///     {
///         Ok(output)
///     }
///
///     // log any errors that are returned during name resolution, except `Error::Io` which
///     // we consider fatal
///     fn sink_error(&mut self, err: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
///         if let Some(Error::Io) = err.downcast_ref::<Error>() {
///             println!("database IO error, aborting...");
///             return false;
///         }
///         self.log(err);
///         true
///     }
///
/// }
///
/// // we need to provide `Resolver` impls for the resolvable names that might appear in an
/// // `MpFilterExpr`
///
/// impl Resolver<'_, names::FilterSet, MpFilterExpr> for Db {
///     // we re-use the same error type for simplicity
///     type IError = Error;
///
///     // the actual look-up is delegated to the database
///     fn resolve(&mut self, expr: &names::FilterSet) -> Result<MpFilterExpr, Self::Error> {
///         self.fetch_as(expr)
///     }
/// }
///
/// impl Resolver<'_, names::AsSet, PrefixSet<Any>> for Db {
///     type IError = Error;
///     fn resolve(&mut self, expr: &names::AsSet) -> Result<PrefixSet<Any>, Self::Error> {
///         self.fetch_as(expr)
///     }
/// }
///
/// impl Resolver<'_, names::RouteSet, PrefixSet<Any>> for Db {
///     type IError = Error;
///     fn resolve(&mut self, expr: &names::RouteSet) -> Result<PrefixSet<Any>, Self::Error> {
///         self.fetch_as(expr)
///     }
/// }
///
/// impl Resolver<'_, names::AutNum, PrefixSet<Any>> for Db {
///     type IError = Error;
///     fn resolve(&mut self, expr: &names::AutNum) -> Result<PrefixSet<Any>, Self::Error> {
///         self.fetch_as(expr)
///     }
/// }
///
/// impl Resolver<'_, primitive::PeerAs, PrefixSet<Any>> for Db {
///     type IError = Error;
///     fn resolve(&mut self, expr: &primitive::PeerAs) -> Result<PrefixSet<Any>, Self::Error> {
///         self.fetch_as(expr)
///     }
/// }
///
/// // and now we can actually evaluate an mp-filter expression..
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let filter: MpFilterExpr = "AS-FOO".parse()?;
///     let output = Db::open().evaluate(filter)?;
///     println!("{:?}", output);
///     Ok(())
/// }
/// ```
pub trait Evaluator<'a>: Sized {
    /// The type returned by [`evaluate()`][Self::evaluate] for expression type `T`.
    ///
    /// Conversion to this type at the end of the evaluation process is provided by
    /// [`finalise()`][Self::finalise].
    ///
    /// # Examples
    ///
    /// To return the same type as [`T::Output`][Evaluate::Output]:
    ///
    /// ``` no_run
    /// # struct Foo;
    /// use rpsl::expr::eval::{Evaluate, Evaluator};
    ///
    /// impl<'a> Evaluator<'a> for Foo {
    ///
    ///     type Output<T> = <T as Evaluate<'a, Self>>::Output
    ///     where
    ///         T: Evaluate<'a, Self>;
    ///
    ///     fn finalise<T>(&mut self, output: T::Output) -> Result<Self::Output<T>, Self::Error>
    ///     where
    ///         T: Evaluate<'a, Self>,
    ///     {
    ///         Ok(output)
    ///     }
    ///
    ///     // ..
    ///     # type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
    ///     # fn sink_error(&mut self, _: &(dyn std::error::Error + Send + Sync + 'static)) -> bool { true }
    /// }
    /// ```
    type Output<T>
    where
        T: Evaluate<'a, Self>;

    /// The error type produced by failed evaluations.
    type Error: From<EvaluationError>;

    /// Evaluate an RPSL expression.
    ///
    /// This method delegates the evaluation logic to [`Evaluate::<Self>::evaluate`] which is
    /// available as long as the necessary implementations of [`Resolver`] for `Self` are present.
    ///
    /// # Errors
    ///
    /// Errors encountered during evaluation are passed to [`sink_error()`][Self::sink_error],
    /// where they can either be handled or propagated up and fail the evaluation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ip::{PrefixSet, Ipv4, traits::PrefixSet as _};
    /// # use rpsl::{
    /// #     names::{FilterSet, AsSet, RouteSet, AutNum},
    /// #     primitive::PeerAs,
    /// #     expr::{eval::{Evaluator, Resolver, Evaluate}, FilterExpr}
    /// # };
    /// struct Eval();
    ///
    /// impl<'a> Evaluator<'a> for Eval {
    ///     // ..
    ///     # type Output<T> = <T as Evaluate<'a, Self>>::Output where T: Evaluate<'a, Self>;
    ///     # type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
    ///     # fn finalise<T: Evaluate<'a, Self>>(&mut self, output: T::Output) -> Result<Self::Output<T>, Self::Error> { Ok(output) }
    ///     # fn sink_error(&mut self, _: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    ///     # true }
    /// }
    /// # macro_rules! impl_resolver {
    /// #     ( $( $input:ty => $output:ty );* $(;)? ) => { $(
    /// #         impl Resolver<'_, $input, $output> for Eval {
    /// #             type IError = std::convert::Infallible;
    /// #             fn resolve(&mut self, _: &$input) -> Result<$output, Self::IError> { unimplemented!(); }
    /// #         }
    /// #     )* }
    /// # }
    /// # impl_resolver! {
    /// #     FilterSet => FilterExpr;
    /// #     AsSet => PrefixSet<Ipv4>;
    /// #     RouteSet => PrefixSet<Ipv4>;
    /// #     AutNum => PrefixSet<Ipv4>;
    /// #     PeerAs => PrefixSet<Ipv4>;
    /// # }
    ///
    /// let filter: FilterExpr = "{10.0.0.0/8^24}^+ OR {10.0.0.0/8}".parse()?;
    /// let set = Eval().evaluate(filter)?;
    ///
    /// assert_eq!(set.ranges().count(), 2);
    ///
    /// let prefixes = (16..=24).map(|n| 2usize.pow(n)).sum::<usize>() + 1;
    /// assert_eq!(set.prefixes().count(), prefixes);
    /// # Ok::<_, Box<dyn std::error::Error + Send + Sync + 'static>>(())
    /// ```
    fn evaluate<T: Evaluate<'a, Self>>(&mut self, expr: T) -> Result<Self::Output<T>, Self::Error> {
        let output = expr.evaluate(self)?;
        self.finalise(output)
    }

    /// Perform the final conversion from the type returned by [`Evaluate::<Self>::evaluate`]
    /// (i.e. `T::Output`) into [`Self::Output<T>`].
    ///
    /// # Errors
    ///
    /// If any fatal errors are encountered during conversion then the implementation should return
    /// an [`Err`] containing a [`Self::Error`].
    /// For non-fatal errors, implementations are encouraged to make use of the error handling
    /// functionality from [`Self::collect_result`], [`Self::collect_results`] and [`Self::sink_error`].
    ///
    /// # Examples
    ///
    /// An implementation that produces a [`Vec<ip::Prefix<Any>>`]:
    ///
    /// ``` rust
    /// # use std::str::FromStr;
    /// # use ip::{PrefixSet, Prefix, Any, traits::PrefixSet as _};
    /// # use rpsl::{
    /// #     names::{FilterSet, AsSet, RouteSet, AutNum},
    /// #     primitive::PeerAs,
    /// #     expr::{eval::{Evaluator, Resolver, Evaluate}, MpFilterExpr}
    /// # };
    /// struct PrefixesEvalutor();
    ///
    /// enum MaybePrefixes {
    ///     Prefixes(Vec<Prefix<Any>>),
    ///     Other(Box<dyn std::any::Any>),
    /// }
    ///
    /// impl Evaluator<'static> for PrefixesEvalutor {
    ///
    ///     type Output<T> = MaybePrefixes
    ///     where
    ///         T: Evaluate<'static, Self>;
    ///
    ///     fn finalise<T>(&mut self, output: T::Output) -> Result<Self::Output<T>, Self::Error>
    ///     where
    ///         T: Evaluate<'static, Self>,
    ///     {
    ///         use MaybePrefixes::{Prefixes, Other};
    ///         let boxed = Box::new(output) as Box<dyn std::any::Any>;
    ///         if let Some(prefix_set) = boxed.downcast_ref::<PrefixSet<Any>>() {
    ///             Ok(Prefixes(prefix_set.prefixes().collect()))
    ///         } else {
    ///             Ok(Other(boxed))
    ///         }
    ///     }
    ///
    ///     // ..
    ///     # type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
    ///     # fn sink_error(&mut self, _: &(dyn std::error::Error + Send + Sync + 'static)) -> bool { true }
    /// }
    /// # macro_rules! impl_resolver {
    /// #     ( $( $input:ty => $output:ty );* $(;)? ) => { $(
    /// #         impl Resolver<'static, $input, $output> for PrefixesEvalutor {
    /// #             type IError = std::convert::Infallible;
    /// #             fn resolve(&mut self, _: &$input) -> Result<$output, Self::IError> { unimplemented!(); }
    /// #         }
    /// #     )* }
    /// # }
    /// # impl_resolver! {
    /// #     FilterSet => MpFilterExpr;
    /// #     AsSet => PrefixSet<Any>;
    /// #     RouteSet => PrefixSet<Any>;
    /// #     AutNum => PrefixSet<Any>;
    /// #     PeerAs => PrefixSet<Any>;
    /// # }
    ///
    /// let filter: MpFilterExpr = "{ 2001:db8::/32^+ } AND { ::/0^33 }".parse()?;
    ///
    /// let expected: Vec<Prefix<Any>> = ["2001:db8::/33", "2001:db8:8000::/33"].into_iter()
    ///     .map(Prefix::<Any>::from_str)
    ///     .collect::<Result<_, _>>()?;
    ///
    /// match PrefixesEvalutor().evaluate(filter)? {
    ///     MaybePrefixes::Prefixes(prefixes) => {
    ///         assert_eq!(prefixes, expected);
    ///     }
    ///     MaybePrefixes::Other(_) => {
    ///         return Err("expecting a list of prefixes!".into());
    ///     }
    /// }
    /// # Ok::<_, Box<dyn std::error::Error + Send + Sync + 'static>>(())
    /// ```
    fn finalise<T>(&mut self, output: T::Output) -> Result<Self::Output<T>, Self::Error>
    where
        T: Evaluate<'a, Self>;

    /// Handle an error condition or abort evaluation.
    ///
    /// Implementations should inspect `err` argument to determine whether evaluation should
    /// proceed (by returning [`true`]) or abort (by returning [`false`]).
    /// If the error condition is non-fatal, additional error handling (such as logging, etc)
    /// should be performed here.
    ///
    /// # Examples
    ///
    /// Error handling based on error type:
    ///
    /// ``` no_run
    /// # use rpsl::expr::eval::{Evaluator, Evaluate};
    /// # mod some {
    /// #     #[derive(Debug)]
    /// #     pub struct IoError;
    /// #     impl std::fmt::Display for IoError {
    /// #         fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { "io error".fmt(f) }
    /// #     }
    /// #     impl std::error::Error for IoError {}
    /// # }
    /// struct Eval;
    ///
    /// impl<'a> Evaluator<'a> for Eval {
    ///
    ///     fn sink_error(&mut self, err: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    ///         if err.is::<some::IoError>() {
    ///             println!("error: {err}");
    ///             return false;
    ///         }
    ///         println!("warning: {err}");
    ///         true
    ///     }
    ///
    ///     // ..
    ///     # type Output<T> = <T as Evaluate<'a, Self>>::Output where T: Evaluate<'a, Self>;
    ///     # type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
    ///     # fn finalise<T: Evaluate<'a, Self>>(&mut self, output: T::Output) -> Result<Self::Output<T>, Self::Error> { Ok(output) }
    /// }
    /// ```
    fn sink_error(&mut self, err: &(dyn std::error::Error + Send + Sync + 'static)) -> bool;

    /// Handle the [`Result`] returned by a fallible operation using the error handling provided by
    /// [`sink_error()`][Self::sink_error].
    ///
    /// # Errors
    ///
    /// - [`Ok(val)`] values are mapped to [`Ok(Some(val))`].
    /// - [`Err(err)`] values that are fully handled by [`Self::sink_error`] are mapped to
    ///   [`Ok(None)`].
    /// - [`Err(err)`] values that are un-handled by [`Self::sink_error`] are mapped (unchanged,
    ///   except for their type) to [`Err(val)`].
    fn collect_result<T, E1, E2>(&mut self, result: Result<T, E1>) -> Result<Option<T>, E2>
    where
        E1: Into<E2> + std::error::Error + Send + Sync + 'static,
        E2: std::error::Error + Send + Sync + 'static,
    {
        result.map(Some).or_else(|err| {
            if self.sink_error(&err) {
                Ok(None)
            } else {
                Err(err.into())
            }
        })
    }

    /// Collect an [`Iterator`] of [`Result`]s into a collection, handling and filtering out
    /// non-fatal errors in the process.
    ///
    /// # Errors
    ///
    /// [`Err`] items are handled and filtered out using [`Self::sink_error`]. Errors that cannot
    /// be fully handled in this way are propagated to the return value.
    ///
    /// # Examples
    ///
    /// ``` rust
    /// # use std::fmt;
    /// # use rpsl::expr::{eval::{Evaluator, Resolver, Evaluate}, FilterExpr};
    /// struct Eval {
    ///     errors: usize,
    /// }
    ///
    /// impl Default for Eval {
    ///     fn default() -> Self {
    ///         Self { errors: 0 }
    ///     }
    /// }
    ///
    /// #[derive(Debug)]
    /// enum Error {
    ///     Fatal(&'static str),
    ///     NonFatal(&'static str),
    /// }
    ///
    /// impl fmt::Display for Error {
    ///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    ///         match self {
    ///             Self::Fatal(msg) | Self::NonFatal(msg) => msg.fmt(f)
    ///         }
    ///     }
    /// }
    ///
    /// impl std::error::Error for Error {}
    ///
    /// impl<'a> Evaluator<'a> for Eval {
    ///
    ///     fn sink_error(&mut self, err: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    ///         if let Some(Error::Fatal(msg)) = err.downcast_ref::<Error>() {
    ///             println!("fatal error: {msg}");
    ///             return false;
    ///         }
    ///         println!("error: {err}");
    ///         self.errors += 1;
    ///         true
    ///     }
    ///
    ///     // ..
    ///     # type Output<T> = <T as Evaluate<'a, Self>>::Output where T: Evaluate<'a, Self>;
    ///     # type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
    ///     # fn finalise<T: Evaluate<'a, Self>>(&mut self, output: T::Output) -> Result<Self::Output<T>, Self::Error> { Ok(output) }
    /// }
    ///
    /// let results = [Ok(()), Err(Error::NonFatal("quite bad")), Err(Error::Fatal("very bad"))];
    ///
    /// let mut eval = Eval::default();
    ///
    /// let processed: Result<Vec<()>, Error> = eval.collect_results(results);
    ///
    /// assert!(matches!(processed, Err(Error::Fatal(_))));
    /// assert_eq!(eval.errors, 1);
    /// # Ok::<_, Box<dyn std::error::Error + Send + Sync + 'static>>(())
    /// ```
    fn collect_results<I, T, E1, E2, O>(&mut self, iter: I) -> Result<O, E2>
    where
        I: IntoIterator<Item = Result<T, E1>>,
        E1: Into<E2> + std::error::Error + Send + Sync + 'static,
        E2: std::error::Error + Send + Sync + 'static,
        O: FromIterator<T>,
    {
        iter.into_iter()
            .filter_map(|result| self.collect_result(result).transpose())
            .collect()
    }
}

/// An object capable of resolving an RPSL name or primitive `I` into a type `O` as part of the
/// evaluation of an RPSL expression in which it appears.
pub trait Resolver<'a, I, O>: Evaluator<'a> {
    /// The error type produced by failed resolution attempts.
    type IError: std::error::Error + Send + Sync + 'static;

    /// Attempt to resolve an RPSL name or primitive.
    ///
    /// Users of the library are not expected to call this method directly: it will be called
    /// during evaluation when an item of type `I` is encountered in that expression AST.
    ///
    /// # Errors
    ///
    /// Implementations should only return `Err(err)` variants in cases where the error should be
    /// considered fatal.
    ///
    /// The error handling methods on [`Evaluator`] can be used to process non-fatal errors.
    fn resolve(&mut self, expr: &I) -> Result<O, Self::IError>;
}
