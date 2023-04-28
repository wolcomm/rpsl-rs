use std::fmt;

use crate::{
    error::{ParseError, ParseResult},
    parser::{debug_construction, impl_from_str, rule_mismatch, ParserRule, TokenPair},
};

use super::autnum;

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

/// RPSL `aggr-mtd` expression for `route` and `route6` objects. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-8.1
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum AggrMtdExpr {
    /// `INBOUND` variant.
    Inbound,
    /// `OUTBOUND` variant.
    Outbound(Option<autnum::Expr>),
}

impl_from_str!(ParserRule::just_aggr_mtd_expr => AggrMtdExpr);

impl TryFrom<TokenPair<'_>> for AggrMtdExpr {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => AggrMtdExpr);
        match pair.as_rule() {
            ParserRule::aggr_mtd_expr_inbound => Ok(Self::Inbound),
            ParserRule::aggr_mtd_expr_outbound => {
                let as_expr = if let Some(inner_pair) = pair.into_inner().next() {
                    Some(inner_pair.try_into()?)
                } else {
                    None
                };
                Ok(Self::Outbound(as_expr))
            }
            _ => Err(rule_mismatch!(pair => "aggr-mtd expression")),
        }
    }
}

impl fmt::Display for AggrMtdExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inbound => write!(f, "INBOUND"),
            Self::Outbound(None) => write!(f, "OUTBOUND"),
            Self::Outbound(Some(as_expr)) => write!(f, "OUTBOUND {as_expr}"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for AggrMtdExpr {
    type Parameters = ParamsFor<Option<autnum::Expr>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(Self::Inbound),
            any_with::<Option<autnum::Expr>>(params).prop_map(Self::Outbound),
        ]
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{compare_ast, display_fmt_parses};

    display_fmt_parses! {
        AggrMtdExpr,
    }

    compare_ast! {
        AggrMtdExpr {
            rfc2622_fig30_route_example1: "outbound AS-ANY" => {
                AggrMtdExpr::Outbound(Some("AS-ANY".parse().unwrap()))
            }
            rfc2622_fig33_route_example: "outbound AS1 or AS2 or AS5" => {
                AggrMtdExpr::Outbound(Some("AS1 or AS2 or AS5".parse().unwrap()))
            }
            rfc2622_fig34_route_example1: "outbound" => {
                AggrMtdExpr::Outbound(None)
            }
        }
    }
}
