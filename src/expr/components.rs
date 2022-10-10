use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::iter::FromIterator;

use ip::{Any, Ipv4, Ipv6};

use crate::{
    error::{ParseError, ParseResult},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::{ParserAfi, Protocol},
};

use super::filter::{self, ExprAfi as FilterExprAfi};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

pub trait ExprAfi: ParserAfi {
    type FilterExprAfi: filter::ExprAfi;
    /// Address family specific [`ParserRule`] for components expressions.
    const COMPONENTS_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for components protocol terms.
    const COMPONENTS_PROTO_TERMS_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for components protocol term.
    const COMPONENTS_PROTO_TERM_RULE: ParserRule;
}

impl ExprAfi for Ipv4 {
    type FilterExprAfi = Ipv4;
    const COMPONENTS_EXPR_RULE: ParserRule = ParserRule::components_expr;
    const COMPONENTS_PROTO_TERMS_RULE: ParserRule = ParserRule::components_proto_terms;
    const COMPONENTS_PROTO_TERM_RULE: ParserRule = ParserRule::components_proto_term;
}

impl ExprAfi for Ipv6 {
    // TODO: impl filter::ExprAfi for Ipv6 and remove this type
    type FilterExprAfi = Any;
    const COMPONENTS_EXPR_RULE: ParserRule = ParserRule::components6_expr;
    const COMPONENTS_PROTO_TERMS_RULE: ParserRule = ParserRule::components6_proto_terms;
    const COMPONENTS_PROTO_TERM_RULE: ParserRule = ParserRule::components6_proto_term;
}

/// RPSL `components` expression for `route` objects. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-8.1
pub type ComponentsExpr = Expr<Ipv4>;
impl_from_str!(ParserRule::just_components_expr => ComponentsExpr);

/// RPSL `components` expression for `route6` objects. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-3
pub type Components6Expr = Expr<Ipv6>;
impl_from_str!(ParserRule::just_components6_expr => Components6Expr);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Expr<A: ExprAfi> {
    atomic: bool,
    filter: Option<filter::Expr<A::FilterExprAfi>>,
    proto_terms: ProtocolTerms<A>,
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for Expr<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            rule if rule == A::COMPONENTS_EXPR_RULE => {
                let (mut atomic, mut filter, mut proto_terms) =
                    (false, None, ProtocolTerms::default());
                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        ParserRule::atomic => {
                            atomic = true;
                        }
                        rule if A::FilterExprAfi::match_filter_expr_rule(rule) => {
                            filter = Some(inner_pair.try_into()?);
                        }
                        rule if rule == A::COMPONENTS_PROTO_TERMS_RULE => {
                            proto_terms = inner_pair.try_into()?;
                        }
                        _ => {
                            return Err(
                                rule_mismatch!(inner_pair => "components expression element"),
                            )
                        }
                    }
                }
                Ok(Self {
                    atomic,
                    filter,
                    proto_terms,
                })
            }
            _ => Err(rule_mismatch!(pair => "components expression")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for Expr<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut statements = Vec::new();
        if self.atomic {
            statements.push("ATOMIC".to_string());
        }
        if let Some(filter_expr) = &self.filter {
            statements.push(filter_expr.to_string());
        }
        statements.push(self.proto_terms.to_string());
        statements.join(" ").fmt(f)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for Expr<A>
where
    A: ExprAfi + 'static,
    A::Address: Arbitrary,
    A::FilterExprAfi: 'static,
    <A::FilterExprAfi as ip::AfiClass>::Prefix: Arbitrary,
    <<A::FilterExprAfi as ip::AfiClass>::Prefix as Arbitrary>::Parameters: Clone,
    <<A::FilterExprAfi as ip::AfiClass>::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
    <A::FilterExprAfi as ip::AfiClass>::PrefixLength: AsRef<u8>,
{
    type Parameters = (
        ParamsFor<Option<filter::Expr<A::FilterExprAfi>>>,
        ParamsFor<ProtocolTerms<A>>,
    );
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            any::<bool>(),
            any_with::<Option<filter::Expr<A::FilterExprAfi>>>(params.0),
            any_with::<ProtocolTerms<A>>(params.1),
        )
            .prop_map(|(atomic, filter, proto_terms)| Self {
                atomic,
                filter,
                proto_terms,
            })
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ProtocolTerms<A: ExprAfi>(Vec<ProtocolTerm<A>>);

impl<A: ExprAfi> Default for ProtocolTerms<A> {
    fn default() -> Self {
        Self(Vec::default())
    }
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for ProtocolTerms<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => ProtocolTerms);
        match pair.as_rule() {
            rule if rule == A::COMPONENTS_PROTO_TERMS_RULE => Ok(Self(
                pair.into_inner()
                    .map(|inner_pair| inner_pair.try_into())
                    .collect::<ParseResult<_>>()?,
            )),
            _ => Err(rule_mismatch!(pair => "components expression protocol terms")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for ProtocolTerms<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0
            .iter()
            .map(|term| term.to_string())
            .collect::<Vec<_>>()
            .join(" ")
            .fmt(f)
    }
}

impl<A: ExprAfi> FromIterator<ProtocolTerm<A>> for ProtocolTerms<A> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = ProtocolTerm<A>>,
    {
        Self(iter.into_iter().collect())
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for ProtocolTerms<A>
where
    A: ExprAfi + 'static,
    A::FilterExprAfi: 'static,
    <A::FilterExprAfi as ip::AfiClass>::Prefix: Arbitrary,
    <<A::FilterExprAfi as ip::AfiClass>::Prefix as Arbitrary>::Parameters: Clone,
    <<A::FilterExprAfi as ip::AfiClass>::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
    <A::FilterExprAfi as ip::AfiClass>::PrefixLength: AsRef<u8>,
{
    type Parameters = ParamsFor<ProtocolTerm<A>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        proptest::collection::vec(any_with::<ProtocolTerm<A>>(params), 0..4)
            .prop_map(Self)
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ProtocolTerm<A: ExprAfi> {
    protocol: Protocol,
    filter: filter::Expr<A::FilterExprAfi>,
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for ProtocolTerm<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => ProtocolTerm);
        match pair.as_rule() {
            rule if rule == A::COMPONENTS_PROTO_TERM_RULE => {
                let mut pairs = pair.into_inner();
                let protocol = next_into_or!(pairs => "failed to get protocol name")?;
                let filter = next_into_or!(pairs => "failed to get filter expression")?;
                Ok(Self { protocol, filter })
            }
            _ => Err(rule_mismatch!(pair => "components protocol term")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for ProtocolTerm<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "protocol {} {}", self.protocol, self.filter)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for ProtocolTerm<A>
where
    A: ExprAfi,
    A::FilterExprAfi: 'static,
    <A::FilterExprAfi as ip::AfiClass>::Prefix: Arbitrary,
    <<A::FilterExprAfi as ip::AfiClass>::Prefix as Arbitrary>::Parameters: Clone,
    <<A::FilterExprAfi as ip::AfiClass>::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
    <A::FilterExprAfi as ip::AfiClass>::PrefixLength: AsRef<u8>,
{
    type Parameters = ParamsFor<filter::Expr<A::FilterExprAfi>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            any::<Protocol>(),
            any_with::<filter::Expr<A::FilterExprAfi>>(params),
        )
            .prop_map(|(protocol, filter)| Self { protocol, filter })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{compare_ast, display_fmt_parses};

    display_fmt_parses! {
        ComponentsExpr,
        Components6Expr,
    }

    compare_ast! {
        ComponentsExpr {
            rfc2622_fig29_route_example1: "<^AS2>" => {
                ComponentsExpr {
                    atomic: false,
                    filter: Some("<^AS2>".parse().unwrap()),
                    proto_terms: Default::default(),
                }
            }
            rfc2622_fig29_route_example2: "\
                    protocol BGP4 {128.8.0.0/16^+}
                    protocol OSPF {128.9.0.0/16^+}" => {
                ComponentsExpr {
                    atomic: false,
                    filter: None,
                    proto_terms: vec![
                        ProtocolTerm {
                            protocol: Protocol::Bgp4,
                            filter: "{128.8.0.0/16^+}".parse().unwrap(),
                        },
                        ProtocolTerm {
                            protocol: Protocol::Ospf,
                            filter: "{128.9.0.0/16^+}".parse().unwrap(),
                        },
                    ].into_iter().collect(),
                }
            }
            rfc2622_fig30_route_example1: "{128.8.0.0/15^-}" => {
                ComponentsExpr {
                    atomic: false,
                    filter: Some("{128.8.0.0/15^-}".parse().unwrap()),
                    proto_terms: Default::default(),
                }
            }
            rfc2622_fig33_route_example: "{128.8.0.0/16, 128.9.0.0/16}" => {
                ComponentsExpr {
                    atomic: false,
                    filter: Some("{128.8.0.0/16, 128.9.0.0/16}".parse().unwrap()),
                    proto_terms: Default::default(),
                }
            }
            regression1: "" => {
                ComponentsExpr {
                    atomic: false,
                    filter: None,
                    proto_terms: Default::default(),
                }
            }
        }
    }

    compare_ast! {
        Components6Expr {
            regression1: "" => {
                Components6Expr {
                    atomic: false,
                    filter: None,
                    proto_terms: Default::default(),
                }
            }
        }
    }
}
