use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    addr_family::{afi, Afi},
    error::{ParseError, ParseResult},
    parser::{ParserRule, TokenPair},
};

use super::ActionExpr;

pub type IfaddrExpr = Expr<afi::Ipv4>;
pub type InterfaceExpr = Expr<afi::Any>;

impl_from_str!(ParserRule::just_ifaddr_expr => IfaddrExpr);
impl_from_str!(ParserRule::just_interface_expr => InterfaceExpr);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Expr<A: TunnelEndpointAfi> {
    addr: A::Addr,
    masklen: u8,
    action: Option<ActionExpr>,
    tunnel: Option<A::Tunnel>,
}

impl<A: TunnelEndpointAfi> TryFrom<TokenPair<'_>> for Expr<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            ParserRule::ifaddr_expr => {
                let mut pairs = pair.into_inner().peekable();
                let addr = next_parse_or!(pairs => "failed to get interface address")?;
                let masklen = next_parse_or!(pairs => "failed to get mask legth")?;
                A::check_addr_len(addr, masklen)?;
                let action = if let Some(ParserRule::action_expr) =
                    pairs.peek().map(|pair| pair.as_rule())
                {
                    Some(next_into_or!(pairs => "failed to get action expression")?)
                } else {
                    None
                };
                let tunnel = if let Some(ParserRule::tunnel_spec) =
                    pairs.peek().map(|pair| pair.as_rule())
                {
                    Some(next_into_or!(pairs => "failed to get tunnel specification")?)
                } else {
                    None
                };
                Ok(Self {
                    addr,
                    masklen,
                    action,
                    tunnel,
                })
            }
            _ => Err(rule_mismatch!(pair => "ifaddr expression")),
        }
    }
}

impl<A: TunnelEndpointAfi> fmt::Display for Expr<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} masklen {}", &self.addr, &self.masklen)?;
        if let Some(action_expr) = &self.action {
            write!(f, " action {}", action_expr)?;
        }
        if let Some(tunnel_spec) = &self.tunnel {
            write!(f, " {}", tunnel_spec)?;
        }
        Ok(())
    }
}

pub trait TunnelEndpointAfi
where
    Self: Afi,
    Self::Tunnel: fmt::Display + for<'a> TryFrom<TokenPair<'a>, Error = ParseError>,
{
    type Tunnel;
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum NeverTunnel {}

impl TryFrom<TokenPair<'_>> for NeverTunnel {
    type Error = ParseError;

    fn try_from(_: TokenPair) -> ParseResult<Self> {
        Err(err!(
            "tried to construct a tunnel expression in an 'ifaddr' attribute"
        ))
    }
}

impl fmt::Display for NeverTunnel {
    fn fmt(&self, _: &mut fmt::Formatter) -> fmt::Result {
        Err(fmt::Error)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct TunnelInterface<A: Afi> {
    endpoint: A::Addr,
    encapsulation: TunnelEncaps,
}

impl<A: TunnelEndpointAfi> TryFrom<TokenPair<'_>> for TunnelInterface<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => TunnelInterface);
        match pair.as_rule() {
            ParserRule::tunnel_spec => {
                let mut pairs = pair.into_inner();
                let endpoint = next_parse_or!(pairs => "failed to get tunnel endpoint address")?;
                let encapsulation = next_into_or!(pairs => "failed to get tunnel encapsulation")?;
                Ok(Self {
                    endpoint,
                    encapsulation,
                })
            }
            _ => Err(rule_mismatch!(pair => "tunnel specification")),
        }
    }
}

impl<A: TunnelEndpointAfi> fmt::Display for TunnelInterface<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tunnel {}, {}", self.endpoint, self.encapsulation)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum TunnelEncaps {
    Gre,
    IpInIp,
}

impl TryFrom<TokenPair<'_>> for TunnelEncaps {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => TunnelEncaps);
        match pair.as_rule() {
            ParserRule::encapsulation_gre => Ok(Self::Gre),
            ParserRule::encapsulation_ipip => Ok(Self::IpInIp),
            _ => Err(rule_mismatch!(pair => "tunnel encapsulation")),
        }
    }
}

impl fmt::Display for TunnelEncaps {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Gre => write!(f, "GRE"),
            Self::IpInIp => write!(f, "IPinIP"),
        }
    }
}

impl TunnelEndpointAfi for afi::Ipv4 {
    type Tunnel = NeverTunnel;
}

impl TunnelEndpointAfi for afi::Any {
    type Tunnel = TunnelInterface<Self>;
}

#[cfg(test)]
mod tests {
    use super::*;

    compare_ast! {
        IfaddrExpr {
            rfc2622_fig20_inet_rtr_example: "1.1.1.1 masklen 30" => {
                IfaddrExpr {
                    addr: "1.1.1.1".parse().unwrap(),
                    masklen: 30,
                    action: None,
                    tunnel: None,
                }
            }
        }
    }
}
