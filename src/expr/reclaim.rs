use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    error::{ParseError, ParseResult},
    parser::{
        debug_construction, impl_case_insensitive_str_primitive, impl_from_str, rule_mismatch,
        ParserRule, TokenPair,
    },
};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// RPSL `reclaim` expression. See [RFC2725].
///
/// ## Implementation note
///
/// Only the `ALL` variant of the expression is properly implemented.
/// Other forms of the `reclaim` or `no-reclaim` attributes are stored as
/// free-form strings.
///
/// [RFC2725]: https://datatracker.ietf.org/doc/html/rfc2725#section-10
pub enum ReclaimExpr {
    /// The `ALL` form.
    All,
    // TODO
    /// Other, unimplemented, forms.
    Filter(ReclaimExprFilter),
}

impl_from_str!(ParserRule::just_reclaim_expr => ReclaimExpr);

impl TryFrom<TokenPair<'_>> for ReclaimExpr {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => ReclaimExpr);
        match pair.as_rule() {
            ParserRule::reclaim_expr_all => Ok(Self::All),
            ParserRule::reclaim_expr_free_form => Ok(Self::Filter(pair.as_str().into())),
            _ => Err(rule_mismatch!(pair => "reclaim expression")),
        }
    }
}

impl fmt::Display for ReclaimExpr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::All => write!(f, "ALL"),
            Self::Filter(s) => write!(f, "{}", s),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for ReclaimExpr {
    type Parameters = ParamsFor<ReclaimExprFilter>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(Self::All),
            any_with::<ReclaimExprFilter>(params).prop_map(Self::Filter),
        ]
        .boxed()
    }
}

#[derive(Clone, Debug)]
pub struct ReclaimExprFilter(String);
impl_case_insensitive_str_primitive!(ParserRule::reclaim_expr_free_form => ReclaimExprFilter);

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for ReclaimExprFilter {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        r"[\PC&&\S]\PC*".prop_map(Self).boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{compare_ast, display_fmt_parses};

    display_fmt_parses! {
        ReclaimExpr,
    }

    compare_ast! {
        ReclaimExpr {
            rfc2725_inetnum_example1: "ALL" => {
                ReclaimExpr::All
            }
            rfc2725_inetnum_example2: "192.168.146/23+" => {
                ReclaimExpr::Filter("192.168.146/23+".into())
            }
        }
    }
}
