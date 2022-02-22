use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    error::{ParseError, ParseResult},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::Protocol,
};

/// RPSL `protocol` redistribution expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-6.3
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ProtocolDistribution {
    from: Option<Protocol>,
    into: Option<Protocol>,
}

impl_from_str!(ParserRule::just_protocol_dist_expr => ProtocolDistribution);

impl TryFrom<TokenPair<'_>> for ProtocolDistribution {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => ProtocolDistribution);
        match pair.as_rule() {
            ParserRule::protocol_dist_expr => {
                let (mut from, mut into) = (None, None);
                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        ParserRule::from_protocol => {
                            from = Some(
                                next_into_or!(inner_pair.into_inner() => "failed to get source protocol")?,
                            );
                        }
                        ParserRule::into_protocol => {
                            into = Some(
                                next_into_or!(inner_pair.into_inner() => "failed to get destination protocol")?,
                            );
                        }
                        _ => return Err(rule_mismatch!(inner_pair => "protocol name")),
                    }
                }
                Ok(Self { from, into })
            }
            _ => Err(rule_mismatch!(pair => "protocol redistribution expression")),
        }
    }
}

impl fmt::Display for ProtocolDistribution {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(from) = &self.from {
            write!(f, "protocol {} ", from)?;
        }
        if let Some(into) = &self.into {
            write!(f, "into {}", into)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::compare_ast;

    compare_ast! {
        ProtocolDistribution {
            rfc2622_sect6_example1: "protocol BGP4 into RIP" => {
                ProtocolDistribution {
                    from: Some(Protocol::Bgp4),
                    into: Some(Protocol::Rip),
                }
            }
            rfc2622_sect6_example2: "protocol BGP4 into OSPF" => {
                ProtocolDistribution {
                    from: Some(Protocol::Bgp4),
                    into: Some(Protocol::Ospf),
                }
            }
            rfc2622_sect6_example3: "protocol STATIC into BGP4" => {
                ProtocolDistribution {
                    from: Some(Protocol::Static),
                    into: Some(Protocol::Bgp4),
                }
            }
            rfc2622_sect6_example4: "protocol IDMR" => {
                ProtocolDistribution {
                    from: Some(Protocol::Unknown("IDMR".into())),
                    into: None,
                }
            }
        }
    }
}
