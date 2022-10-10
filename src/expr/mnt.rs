use std::convert::{TryFrom, TryInto};
use std::fmt;

use ip::Any;

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

use crate::{
    error::{ParseError, ParseResult},
    list::ListOf,
    names::Mntner,
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::IpPrefixRange,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// RPSL `mnt-routes` expression. See [RFC2725].
///
/// [RFC2725]: https://datatracker.ietf.org/doc/html/rfc2725#section-10
pub struct MntRoutesExpr {
    mntners: ListOf<Mntner>,
    qualifier: Option<MntRoutesExprQualifier>,
}

impl_from_str!(ParserRule::just_mnt_routes_expr => MntRoutesExpr);

impl TryFrom<TokenPair<'_>> for MntRoutesExpr {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => MntRoutesExpr);
        match pair.as_rule() {
            ParserRule::mnt_routes_expr => {
                let mut pairs = pair.into_inner();
                let mntners = next_into_or!(pairs => "failed to get mntners list")?;
                let qualifier = if let Some(inner_pair) = pairs.next() {
                    Some(inner_pair.try_into()?)
                } else {
                    None
                };
                Ok(Self { mntners, qualifier })
            }
            _ => Err(rule_mismatch!(pair => "mnt-routes expression")),
        }
    }
}

impl fmt::Display for MntRoutesExpr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.mntners)?;
        if let Some(qualifier) = &self.qualifier {
            write!(f, " {}", qualifier)?;
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for MntRoutesExpr {
    type Parameters = ParamsFor<Option<MntRoutesExprQualifier>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            any::<ListOf<Mntner>>(),
            any_with::<Option<MntRoutesExprQualifier>>(params),
        )
            .prop_map(|(mntners, qualifier)| Self { mntners, qualifier })
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum MntRoutesExprQualifier {
    Prefixes(ListOf<IpPrefixRange<Any>>),
    Any,
}

impl TryFrom<TokenPair<'_>> for MntRoutesExprQualifier {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => MntRoutesExprQualifier);
        match pair.as_rule() {
            ParserRule::mnt_routes_expr_qual_list => Ok(Self::Prefixes(
                next_into_or!(pair.into_inner() => "failed to get prefix range list")?,
            )),
            ParserRule::mnt_routes_expr_qual_any => Ok(Self::Any),
            _ => Err(rule_mismatch!(pair => "mnt-routes expression qualifier")),
        }
    }
}

impl fmt::Display for MntRoutesExprQualifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Prefixes(prefixes) => write!(f, "{{{}}}", prefixes),
            Self::Any => write!(f, "ANY"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for MntRoutesExprQualifier {
    type Parameters = ParamsFor<ListOf<IpPrefixRange<Any>>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(Self::Any),
            any_with::<ListOf<IpPrefixRange<Any>>>(params).prop_map(Self::Prefixes),
        ]
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        primitive::RangeOperator,
        tests::{compare_ast, display_fmt_parses},
    };

    display_fmt_parses! {
        MntRoutesExpr,
    }

    compare_ast! {
        MntRoutesExpr {
            rfc2725_aut_num_example2: "EBG-COM {192.168.144.0/23}" => {
                MntRoutesExpr {
                    mntners: vec!["EBG-COM".parse().unwrap()].into_iter().collect(),
                    qualifier: Some(MntRoutesExprQualifier::Prefixes(vec![
                        IpPrefixRange::new(
                            "192.168.144.0/23".parse().unwrap(),
                            RangeOperator::None,
                        ),
                    ].into_iter().collect())),
                }
            }
            rfc4012_sect4_aut_num_example1: "MAINT-AS65001 {2001:0DB8::/32^+, 192.0.2.0/24^+}" => {
                MntRoutesExpr {
                    mntners: vec!["MAINT-AS65001".parse().unwrap()].into_iter().collect(),
                    qualifier: Some(MntRoutesExprQualifier::Prefixes(vec![
                        IpPrefixRange::new(
                            "2001:0DB8::/32".parse().unwrap(),
                            RangeOperator::LessIncl,
                        ),
                        IpPrefixRange::new(
                            "192.0.2.0/24".parse().unwrap(),
                            RangeOperator::LessIncl,
                        ),
                    ].into_iter().collect()))
                }
            }
        }
    }
}
