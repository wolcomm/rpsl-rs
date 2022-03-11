use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    addr_family::{afi, AfiClass},
    error::{ParseError, ParseResult},
    list::ListOf,
    names::{InetRtr, PeeringSet, RtrSet},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::{IpAddress, PeerOptKey, PeerOptVal, Protocol},
};

pub trait ExprAfi: AfiClass {
    /// Address family specific [`ParserRule`] for peer expressions.
    const PEER_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for peer specifications.
    const PEER_SPEC_RULE: ParserRule;
}

impl ExprAfi for afi::Ipv4 {
    const PEER_EXPR_RULE: ParserRule = ParserRule::peer_expr;
    const PEER_SPEC_RULE: ParserRule = ParserRule::peer_spec;
}

impl ExprAfi for afi::Any {
    const PEER_EXPR_RULE: ParserRule = ParserRule::mp_peer_expr;
    const PEER_SPEC_RULE: ParserRule = ParserRule::mp_peer_spec;
}

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

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
pub struct Expr<A: ExprAfi> {
    protocol: Protocol,
    peer: PeerSpec<A>,
    opts: Option<ListOf<PeerOpt>>,
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for Expr<A> {
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

impl<A: ExprAfi> fmt::Display for Expr<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.protocol, self.peer)?;
        if let Some(opts) = &self.opts {
            write!(f, " {}", opts)?;
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A: ExprAfi> Arbitrary for Expr<A>
where
    A: fmt::Debug + 'static,
    A::Addr: Arbitrary,
    <A::Addr as Arbitrary>::Strategy: 'static,
{
    type Parameters = ParamsFor<Option<ListOf<PeerOpt>>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            any::<Protocol>(),
            any::<PeerSpec<A>>(),
            any_with::<Option<ListOf<PeerOpt>>>(params),
        )
            .prop_map(|(protocol, peer, opts)| Self {
                protocol,
                peer,
                opts,
            })
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum PeerSpec<A: ExprAfi> {
    Addr(IpAddress<A>),
    InetRtr(InetRtr),
    RtrSet(RtrSet),
    PeeringSet(PeeringSet),
}

impl<A: ExprAfi> TryFrom<TokenPair<'_>> for PeerSpec<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => PeerSpec);
        match pair.as_rule() {
            rule if rule == A::LITERAL_ADDR_RULE => Ok(Self::Addr(pair.try_into()?)),
            ParserRule::inet_rtr => Ok(Self::InetRtr(pair.try_into()?)),
            ParserRule::rtr_set => Ok(Self::RtrSet(pair.try_into()?)),
            ParserRule::peering_set => Ok(Self::PeeringSet(pair.try_into()?)),
            _ => Err(rule_mismatch!(pair => "peer specification")),
        }
    }
}

impl<A: ExprAfi> fmt::Display for PeerSpec<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Addr(addr) => addr.fmt(f),
            Self::InetRtr(inet_rtr) => inet_rtr.fmt(f),
            Self::RtrSet(rtr_set) => rtr_set.fmt(f),
            Self::PeeringSet(peering_set) => peering_set.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A: ExprAfi> Arbitrary for PeerSpec<A>
where
    A: fmt::Debug + 'static,
    A::Addr: Arbitrary,
    <A::Addr as Arbitrary>::Strategy: 'static,
{
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<IpAddress<A>>().prop_map(Self::Addr),
            any::<InetRtr>().prop_map(Self::InetRtr),
            any::<RtrSet>().prop_map(Self::RtrSet),
            any::<PeeringSet>().prop_map(Self::PeeringSet),
        ]
        .boxed()
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

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for PeerOpt {
    type Parameters = ParamsFor<Option<PeerOptVal>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (any::<PeerOptKey>(), any_with::<Option<PeerOptVal>>(params))
            .prop_map(|(key, val)| Self { key, val })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{compare_ast, display_fmt_parses};

    display_fmt_parses! {
        PeerExpr,
        MpPeerExpr,
    }

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
