use std::str::FromStr;

use ip::{traits::PrefixSet as _, Any, Prefix, PrefixRange, PrefixSet};

use rpsl::{
    error::ParseError,
    expr::{
        eval::{Evaluate, EvaluationError, Evaluator, Resolver},
        MpFilterExpr,
    },
    names, primitive,
};

test_evaluation! {
    evaluate_filter {
        "(AS-FOO^- OR RS-BAR^+) AND FLTR-BAZ AND NOT AS65000" => [
            "192.168.0.0/16,19,20",
            "192.168.128.0/17,18,18",
            "192.168.0.0/18,18,18",
            "2001:db8::/32,33,48",
        ]
    }
}

/// Our custom evaluator implementation
#[derive(Debug)]
struct Eval;

impl Eval {
    fn new() -> Self {
        Self
    }
}

impl<'a> Evaluator<'a> for Eval {
    /// Return `T::Output` unchanged
    type Output<T> = <T as Evaluate<'a, Self>>::Output
    where
        T: Evaluate<'a, Self>;

    /// The error type for failed evaluations.
    type Error = Error;

    fn finalise<T>(&mut self, output: T::Output) -> Result<Self::Output<T>, Self::Error>
    where
        T: Evaluate<'a, Self>,
    {
        Ok(output)
    }

    fn sink_error(&mut self, err: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
        // special handling for `ip::Error` errors.
        if err.is::<ip::Error>() {
            println!("special handling for {err:?}");
            // uncomment to bail on the evaluation in this case:
            // return false;
        }
        // in the general case, just log or whatever.
        println!("error: {err}");
        true
    }
}

impl Resolver<'_, names::FilterSet, MpFilterExpr> for Eval {
    type IError = Error;
    fn resolve(&mut self, expr: &names::FilterSet) -> Result<MpFilterExpr, Self::Error> {
        match expr.to_string().as_ref() {
            "FLTR-BAZ" => Ok("{0.0.0.0/0^18-20, ::/0^16-48}".parse()?),
            _ => Ok("ANY".parse()?),
        }
    }
}

impl Resolver<'_, primitive::PeerAs, PrefixSet<Any>> for Eval {
    type IError = Error;
    fn resolve(&mut self, _: &primitive::PeerAs) -> Result<PrefixSet<Any>, Self::IError> {
        unimplemented!()
    }
}

impl Resolver<'_, names::AsSet, PrefixSet<Any>> for Eval {
    type IError = Error;
    fn resolve(&mut self, expr: &names::AsSet) -> Result<PrefixSet<Any>, Self::IError> {
        match expr.to_string().as_ref() {
            "AS-FOO" => self.collect_results(
                ["2001:db8::/32", "2001:dj9::/32"]
                    .into_iter()
                    .map(Prefix::<Any>::from_str),
            ),
            _ => Ok(PrefixSet::<Any>::any()),
        }
    }
}

impl Resolver<'_, names::RouteSet, PrefixSet<Any>> for Eval {
    type IError = Error;
    fn resolve(&mut self, expr: &names::RouteSet) -> Result<PrefixSet<Any>, Self::IError> {
        match expr.to_string().as_ref() {
            "RS-BAR" => self.collect_results(
                ["192.168.0.0/17", "192.168.128.0/17"]
                    .into_iter()
                    .map(Prefix::<Any>::from_str),
            ),
            _ => Ok(PrefixSet::<Any>::any()),
        }
    }
}

impl Resolver<'_, names::AutNum, PrefixSet<Any>> for Eval {
    type IError = Error;
    fn resolve(&mut self, expr: &names::AutNum) -> Result<PrefixSet<Any>, Self::IError> {
        match expr.to_string().as_ref() {
            "AS65000" => {
                self.collect_results(["192.168.64.0/18"].into_iter().map(Prefix::<Any>::from_str))
            }
            _ => Ok(PrefixSet::<Any>::any()),
        }
    }
}

#[derive(Debug)]
struct Error {
    msg: String,
    inner: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl From<&str> for Error {
    fn from(msg: &str) -> Self {
        Self {
            msg: msg.to_string(),
            inner: None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)?;
        if let Some(err) = &self.inner {
            write!(f, ": {err}")?;
        }
        Ok(())
    }
}

impl From<EvaluationError> for Error {
    fn from(err: EvaluationError) -> Self {
        Self {
            msg: "expression evaluation failed".to_string(),
            inner: Some(Box::new(err)),
        }
    }
}

impl From<ip::Error> for Error {
    fn from(err: ip::Error) -> Self {
        Self {
            msg: "IP address parsing failed".to_string(),
            inner: Some(Box::new(err)),
        }
    }
}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Self {
        Self {
            msg: "RPSL expression parsing failed".to_string(),
            inner: Some(Box::new(err)),
        }
    }
}

impl std::error::Error for Error {}

macro_rules! test_evaluation {
    ( $(
        $case:ident { $filter:literal => $expect:expr }
    )* ) => { $(
        #[test]
        fn $case() -> Result<(), Box<dyn std::error::Error>> {
            let filter: MpFilterExpr = $filter.parse()?;
            let expect = $expect
                .into_iter()
                .map(PrefixRange::<Any>::from_str)
                .collect::<Result<Vec<_>, _>>()?;
            let ranges: Vec<_> = Eval::new().evaluate(filter)?.ranges().collect();
            assert_eq!(dbg!(ranges), expect);
            Ok(())
        }
    )* };
}
use test_evaluation;
