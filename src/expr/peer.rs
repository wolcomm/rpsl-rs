use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    addr_family::{afi, LiteralPrefixSetAfi},
    error::{ParseError, ParseResult},
    list::ListOf,
    names::{InetRtr, PeeringSet, RtrSet},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::{PeerOptKey, PeerOptVal, Protocol},
};

/// RPSL `peer` expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-9
pub type PeerExpr = Expr<afi::Ipv4>;
impl_from_str!(ParserRule::just_peer_expr => PeerExpr);

/// RPSL `mp-peer` expression. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-4.5
pub type MpPeerExpr = Expr<afi::Any>;
impl_from_str!(ParserRule::just_mp_peer_expr => MpPeerExpr);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Expr<A: LiteralPrefixSetAfi> {
    protocol: Protocol,
    peer: PeerSpec<A>,
    opts: Option<ListOf<PeerOpt>>,
}

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for Expr<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            rule if rule == A::PEER_EXPR_RULE => {
                let mut pairs = pair.into_inner();
                let protocol = next_into_or!(pairs => "failed to get protocol")?;
                let peer = next_into_or!(pairs => "failed to get peer specification")?;
                let opts = if let Some(pair) = pairs.next() {
                    Some(pair.try_into()?)
                } else {
                    None
                };
                Ok(Self {
                    protocol,
                    peer,
                    opts,
                })
            }
            _ => Err(rule_mismatch!(pair => "peer expression")),
        }
    }
}

impl<A: LiteralPrefixSetAfi> fmt::Display for Expr<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.protocol, self.peer)?;
        if let Some(opts) = &self.opts {
            write!(f, " {}", opts)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum PeerSpec<A: LiteralPrefixSetAfi> {
    Addr(A::Addr),
    InetRtr(InetRtr),
    RtrSet(RtrSet),
    PeeringSet(PeeringSet),
}

impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for PeerSpec<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => PeerSpec);
        match pair.as_rule() {
            rule if rule == A::LITERAL_ADDR_RULE => Ok(Self::Addr(pair.as_str().parse()?)),
            ParserRule::inet_rtr => Ok(Self::InetRtr(pair.try_into()?)),
            ParserRule::rtr_set => Ok(Self::RtrSet(pair.try_into()?)),
            ParserRule::peering_set => Ok(Self::PeeringSet(pair.try_into()?)),
            _ => Err(rule_mismatch!(pair => "peer specification")),
        }
    }
}

impl<A: LiteralPrefixSetAfi> fmt::Display for PeerSpec<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Addr(addr) => addr.fmt(f),
            Self::InetRtr(inet_rtr) => inet_rtr.fmt(f),
            Self::RtrSet(rtr_set) => rtr_set.fmt(f),
            Self::PeeringSet(peering_set) => peering_set.fmt(f),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct PeerOpt {
    key: PeerOptKey,
    val: Option<PeerOptVal>,
}

impl TryFrom<TokenPair<'_>> for PeerOpt {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => PeerOpt);
        match pair.as_rule() {
            ParserRule::peer_opt => {
                let mut pairs = pair.into_inner();
                let key = next_into_or!(pairs => "failed to get peer option key")?;
                let val = if let Some(inner_pair) = pairs.next() {
                    Some(inner_pair.try_into()?)
                } else {
                    None
                };
                Ok(Self { key, val })
            }
            _ => Err(rule_mismatch!(pair => "peer option")),
        }
    }
}

impl fmt::Display for PeerOpt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.key)?;
        if let Some(val) = &self.val {
            write!(f, "({})", val)
        } else {
            write!(f, "()")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::compare_ast;

    compare_ast! {
        PeerExpr {
            rfc2622_fig36_inet_rtr_example: "BGP4 192.87.45.195 asno(AS3334), flap_damp()" => {
                PeerExpr {
                    protocol: Protocol::Bgp4,
                    peer: PeerSpec::Addr("192.87.45.195".parse().unwrap()),
                    opts: Some(vec![
                        PeerOpt {
                            key: "asno".into(),
                            val: Some("AS3334".into()),
                        },
                        PeerOpt {
                            key: "flap_damp".into(),
                            val: None,
                        }
                    ].into_iter().collect()),
                }
            }
            rfc2622_fig37_inet_rtr_example1: "BGP4 rtrs-ibgp-peers asno(AS3333), flap_damp()" => {
                PeerExpr {
                    protocol: Protocol::Bgp4,
                    peer: PeerSpec::RtrSet("rtrs-ibgp-peers".parse().unwrap()),
                    opts: Some(vec![
                        PeerOpt {
                            key: "asno".into(),
                            val: Some("AS3333".into()),
                        },
                        PeerOpt {
                            key: "flap_damp".into(),
                            val: None,
                        }
                    ].into_iter().collect()),
                }
            }
            rfc2622_fig37_inet_rtr_example2: "BGP4 prng-ebgp-peers asno(PeerAS), flap_damp()" => {
                PeerExpr {
                    protocol: Protocol::Bgp4,
                    peer: PeerSpec::PeeringSet("prng-ebgp-peers".parse().unwrap()),
                    opts: Some(vec![
                        PeerOpt {
                            key: "asno".into(),
                            val: Some("PeerAS".into()),
                        },
                        PeerOpt {
                            key: "flap_damp".into(),
                            val: None,
                        }
                    ].into_iter().collect()),
                }
            }
        }
    }
}
