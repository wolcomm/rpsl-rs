use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    error::{ParseError, ParseResult},
    parser::{ParserRule, TokenPair},
    primitive::{Date, EmailAddress},
};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ChangedExpr {
    by: EmailAddress,
    on: Date,
}

impl ChangedExpr {
    pub fn new(by: EmailAddress, on: Date) -> Self {
        Self { by, on }
    }
}

impl TryFrom<TokenPair<'_>> for ChangedExpr {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
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

impl_from_str!(ParserRule::just_changed_expr => ChangedExpr);

impl fmt::Display for ChangedExpr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.by, self.on)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
