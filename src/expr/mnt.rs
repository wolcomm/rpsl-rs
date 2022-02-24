use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    addr_family::afi,
    error::{ParseError, ParseResult},
    list::ListOf,
    names::Mntner,
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::PrefixRange,
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

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum MntRoutesExprQualifier {
    Prefixes(ListOf<PrefixRange<afi::Any>>),
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
