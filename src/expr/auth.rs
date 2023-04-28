use std::fmt;

use crate::{
    error::{ParseError, ParseResult},
    names::{KeyCert, Person, Role},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::{CryptHash, EmailAddressRegex, PgpFromFingerprint},
};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::prelude::*;

/// RPSL `auth` expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.1
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum AuthExpr {
    /// `NONE` authentication scheme.
    None,
    /// `MAIL-FROM` authentication scheme.
    Mail(EmailAddressRegex),
    /// `PGP-FROM` authentication scheme.
    PgpFrom(PgpFromFingerprint),
    /// `CRYPT-PW` authentication scheme.
    Crypt(CryptHash),
    /// `key-cert` authentication schemes.
    KeyCert(KeyCert),
    /// `person` authentication scheme.
    Person(Person),
    /// `role` authentication scheme.
    Role(Role),
}

impl TryFrom<TokenPair<'_>> for AuthExpr {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => AuthExpr);
        match pair.as_rule() {
            ParserRule::auth_expr_none => Ok(Self::None),
            ParserRule::auth_expr_mail => Ok(Self::Mail(
                next_into_or!(pair.into_inner() => "failed to get email regex")?,
            )),
            ParserRule::auth_expr_pgp_from => Ok(Self::PgpFrom(
                next_into_or!(pair.into_inner() => "failed to get pgp key")?,
            )),
            ParserRule::auth_expr_crypt => Ok(Self::Crypt(
                next_into_or!(pair.into_inner() => "failed to get crypt hash")?,
            )),
            ParserRule::auth_expr_key_cert => Ok(Self::KeyCert(
                next_into_or!(pair.into_inner() => "failed to get key-cert name")?,
            )),
            ParserRule::auth_expr_person => Ok(Self::Person(
                next_into_or!(pair.into_inner() => "failed to get person name")?,
            )),
            ParserRule::auth_expr_role => Ok(Self::Role(
                next_into_or!(pair.into_inner() => "failed to get role name")?,
            )),
            _ => Err(rule_mismatch!(pair => "auth expression")),
        }
    }
}

impl_from_str!(ParserRule::just_auth_expr => AuthExpr);

impl fmt::Display for AuthExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "NONE"),
            Self::Mail(s) => write!(f, "MAIL-FROM {s}"),
            Self::PgpFrom(s) => write!(f, "PGP-FROM {s}"),
            Self::Crypt(s) => write!(f, "CRYPT-PW {s}"),
            Self::Person(s) => write!(f, "PERSON {s}"),
            Self::Role(s) => write!(f, "ROLE {s}"),
            Self::KeyCert(key_cert) => key_cert.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for AuthExpr {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(Self::None),
            any::<EmailAddressRegex>().prop_map(Self::Mail),
            any::<PgpFromFingerprint>().prop_map(Self::PgpFrom),
            any::<CryptHash>().prop_map(Self::Crypt),
            any::<KeyCert>().prop_map(Self::KeyCert),
            any::<Person>().prop_map(Self::Person),
            any::<Role>().prop_map(Self::Role),
        ]
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{compare_ast, display_fmt_parses};

    display_fmt_parses! {
        AuthExpr,
    }

    compare_ast! {
        AuthExpr {
            rfc2622_crypt_example: "CRYPT-PW dhjsdfhruewf" => {
                AuthExpr::Crypt("dhjsdfhruewf".into())
            }
            rfc2622_mail_example: r"MAIL-FROM .*@ripe\.net" => {
                AuthExpr::Mail(r".*@ripe\.net".into())
            }
        }
    }
}
