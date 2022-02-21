use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    error::{ParseError, ParseResult},
    parser::{ParserRule, TokenPair},
    primitive::Protocol,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ProtocolDistribution {
    from: Option<Protocol>,
    into: Option<Protocol>,
}

impl TryFrom<TokenPair<'_>> for ProtocolDistribution {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => ProtocolDistribution);
        match pair.as_rule() {
            ParserRule::protocol_dist_expr => {
                let mut pairs = pair.into_inner();
                let (mut from, mut into) = (None, None);
                while let Some(inner_pair) = pairs.next() {
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
                        _ => Err(rule_mismatch!(inner_pair => "protocol name"))?,
                    }
                }
                Ok(Self { from, into })
            }
            _ => Err(rule_mismatch!(pair => "protocol redistribution expression")),
        }
    }
}

impl_from_str!(ParserRule::just_protocol_dist_expr => ProtocolDistribution);

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
