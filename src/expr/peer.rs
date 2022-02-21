use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    addr_family::{afi, LiteralPrefixSetAfi},
    error::{ParseError, ParseResult},
    list::ListOf,
    names::{InetRtr, PeeringSet, RtrSet},
    parser::{ParserRule, TokenPair},
    primitive::{PeerOptKey, PeerOptVal, Protocol},
};

pub type PeerExpr = Expr<afi::Ipv4>;
pub type MpPeerExpr = Expr<afi::Any>;

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
    val: PeerOptVal,
}

impl TryFrom<TokenPair<'_>> for PeerOpt {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => PeerOpt);
        match pair.as_rule() {
            ParserRule::peer_opt => {
                let mut pairs = pair.into_inner();
                let key = next_into_or!(pairs => "failed to get peer option key")?;
                let val = next_into_or!(pairs => "failed to get peer option value")?;
                Ok(Self { key, val })
            }
            _ => Err(rule_mismatch!(pair => "peer option")),
        }
    }
}

impl fmt::Display for PeerOpt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}({})", self.key, self.val)
    }
}
