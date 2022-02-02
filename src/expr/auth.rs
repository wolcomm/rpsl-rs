use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    error::{ParseError, ParseResult},
    names::KeyCert,
    parser::{ParserRule, TokenPair},
    primitive::{CryptHash, EmailAddressRegex, PgpFromFingerprint},
};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum AuthExpr {
    None,
    Mail(EmailAddressRegex),
    PgpFrom(PgpFromFingerprint),
    Crypt(CryptHash),
    KeyCert(KeyCert),
}

impl TryFrom<TokenPair<'_>> for AuthExpr {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
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
            _ => Err(rule_mismatch!(pair => "auth expression")),
        }
    }
}

impl_from_str!(ParserRule::just_auth_expr => AuthExpr);

impl fmt::Display for AuthExpr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::None => write!(f, "NONE"),
            Self::Mail(s) => write!(f, "MAIL-FROM {}", s),
            Self::PgpFrom(s) => write!(f, "PGP-FROM {}", s),
            Self::Crypt(s) => write!(f, "CRYPT-PW {}", s),
            Self::KeyCert(key_cert) => key_cert.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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