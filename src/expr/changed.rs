use std::fmt;

use crate::{
    error::{ParseError, ParseResult},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::{Date, EmailAddress},
};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

/// RPSL `changed` expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.1
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ChangedExpr {
    by: EmailAddress,
    on: Date,
}

impl_from_str!(ParserRule::just_changed_expr => ChangedExpr);

impl ChangedExpr {
    /// Create a new [`ChangedExpr`].
    #[must_use]
    pub const fn new(by: EmailAddress, on: Date) -> Self {
        Self { by, on }
    }
}

impl TryFrom<TokenPair<'_>> for ChangedExpr {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => ChangedExpr);
        match pair.as_rule() {
            ParserRule::changed_expr => {
                let mut pairs = pair.into_inner();
                Ok(Self {
                    by: next_into_or!(pairs => "failed to get changed by address")?,
                    on: next_into_or!(pairs => "failed to get changed on date")?,
                })
            }
            _ => Err(rule_mismatch!(pair => "changed expression")),
        }
    }
}

impl fmt::Display for ChangedExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.by, self.on)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for ChangedExpr {
    type Parameters = ParamsFor<EmailAddress>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (any_with::<EmailAddress>(params), any::<Date>())
            .prop_map(|(by, on)| Self { by, on })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{compare_ast, display_fmt_parses};

    display_fmt_parses! {
        ChangedExpr,
    }

    compare_ast! {
        ChangedExpr {
            rfc2622_example: "johndoe@terabit-labs.nn 19900401" => {
                ChangedExpr::new(
                    "johndoe@terabit-labs.nn".into(),
                    "19900401".parse().unwrap(),
                )
            }
        }
    }
}
