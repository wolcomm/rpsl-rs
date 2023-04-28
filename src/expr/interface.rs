use std::fmt;
use std::hash;

use ip::{traits::Interface as _, Any, Ipv4};

use crate::{
    error::{err, ParseError, ParseResult},
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::{IpAddress, ParserAfi},
};

use super::ActionExpr;

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

/// RPSL `ifaddr` expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-9
pub type IfaddrExpr = Expr<Ipv4>;
impl_from_str!(ParserRule::just_ifaddr_expr => IfaddrExpr);

/// RPSL `interface` expression. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-4.5
#[allow(clippy::module_name_repetitions)]
pub type InterfaceExpr = Expr<Any>;
impl_from_str!(ParserRule::just_interface_expr => InterfaceExpr);

pub trait TunnelEndpointAfi: ParserAfi {
    type Tunnel: fmt::Display
        + for<'a> TryFrom<TokenPair<'a>, Error = ParseError>
        + Clone
        + fmt::Debug
        + hash::Hash
        + PartialEq
        + Eq;

    const INTERFACE_EXPR_RULE: ParserRule;

    #[cfg(any(test, feature = "arbitrary"))]
    fn arbitrary_tunnel(
        params: ParamsFor<Option<Self::Tunnel>>,
    ) -> BoxedStrategy<Option<Self::Tunnel>>
    where
        Self::Tunnel: Arbitrary;
}

impl TunnelEndpointAfi for Ipv4 {
    type Tunnel = NeverTunnel;

    const INTERFACE_EXPR_RULE: ParserRule = ParserRule::ifaddr_expr;

    #[cfg(any(test, feature = "arbitrary"))]
    fn arbitrary_tunnel(_: ParamsFor<Option<Self::Tunnel>>) -> BoxedStrategy<Option<Self::Tunnel>> {
        Just(None).boxed()
    }
}

impl TunnelEndpointAfi for Any {
    type Tunnel = TunnelInterface<Self>;

    const INTERFACE_EXPR_RULE: ParserRule = ParserRule::interface_expr;

    #[cfg(any(test, feature = "arbitrary"))]
    fn arbitrary_tunnel(
        params: ParamsFor<Option<Self::Tunnel>>,
    ) -> BoxedStrategy<Option<Self::Tunnel>> {
        any_with::<Option<Self::Tunnel>>(params).boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Expr<A: TunnelEndpointAfi> {
    interface: A::Interface,
    action: Option<ActionExpr>,
    tunnel: Option<A::Tunnel>,
}

impl<A: TunnelEndpointAfi> TryFrom<TokenPair<'_>> for Expr<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            rule if rule == A::INTERFACE_EXPR_RULE => {
                let mut pairs = pair.into_inner().peekable();
                let interface = format!(
                    "{}/{}",
                    pairs
                        .next()
                        .ok_or_else(|| err!("failed to get interface address"))?
                        .as_str(),
                    pairs
                        .next()
                        .ok_or_else(|| err!("failed to get interface masklen"))?
                        .as_str()
                )
                .parse()?;
                let action =
                    if pairs.peek().map(TokenPair::as_rule) == Some(ParserRule::action_expr) {
                        Some(next_into_or!(pairs => "failed to get action expression")?)
                    } else {
                        None
                    };
                let tunnel =
                    if pairs.peek().map(TokenPair::as_rule) == Some(ParserRule::tunnel_spec) {
                        Some(next_into_or!(pairs => "failed to get tunnel specification")?)
                    } else {
                        None
                    };
                Ok(Self {
                    interface,
                    action,
                    tunnel,
                })
            }
            _ => Err(rule_mismatch!(pair => "ifaddr or interface expression")),
        }
    }
}

impl<A: TunnelEndpointAfi> fmt::Display for Expr<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} masklen {}",
            &self.interface.addr(),
            &self.interface.prefix_len()
        )?;
        if let Some(action_expr) = &self.action {
            write!(f, " action {action_expr}")?;
        }
        if let Some(tunnel_spec) = &self.tunnel {
            write!(f, " {tunnel_spec}")?;
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for Expr<A>
where
    A: TunnelEndpointAfi + fmt::Debug,
    A::Interface: Arbitrary,
    <A::Interface as Arbitrary>::Strategy: 'static,
    A::Tunnel: Arbitrary + 'static,
    <A::Tunnel as Arbitrary>::Strategy: 'static,
{
    type Parameters = (
        ParamsFor<A::Interface>,
        ParamsFor<Option<ActionExpr>>,
        ParamsFor<Option<A::Tunnel>>,
    );
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            any_with::<A::Interface>(params.0),
            any_with::<Option<ActionExpr>>(params.1),
            A::arbitrary_tunnel(params.2),
        )
            .prop_map(|(interface, action, tunnel)| Self {
                interface,
                action,
                tunnel,
            })
            .boxed()
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum NeverTunnel {}

impl TryFrom<TokenPair<'_>> for NeverTunnel {
    type Error = ParseError;

    fn try_from(_: TokenPair<'_>) -> ParseResult<Self> {
        Err(err!(
            "tried to construct a tunnel expression in an 'ifaddr' attribute"
        ))
    }
}

impl fmt::Display for NeverTunnel {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Err(fmt::Error)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for NeverTunnel {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        panic!("Tried to construct a NeverTunnel")
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct TunnelInterface<A: TunnelEndpointAfi> {
    endpoint: IpAddress<A>,
    encapsulation: TunnelEncaps,
}

impl<A: TunnelEndpointAfi> TryFrom<TokenPair<'_>> for TunnelInterface<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => TunnelInterface);
        match pair.as_rule() {
            ParserRule::tunnel_spec => {
                let mut pairs = pair.into_inner();
                let endpoint = next_into_or!(pairs => "failed to get tunnel endpoint address")?;
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tunnel {}, {}", self.endpoint, self.encapsulation)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for TunnelInterface<A>
where
    A: TunnelEndpointAfi + fmt::Debug + 'static,
    A::Address: Arbitrary,
{
    type Parameters = ParamsFor<IpAddress<A>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (any_with::<IpAddress<A>>(params), any::<TunnelEncaps>())
            .prop_map(|(endpoint, encapsulation)| Self {
                endpoint,
                encapsulation,
            })
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum TunnelEncaps {
    Gre,
    IpInIp,
}

impl TryFrom<TokenPair<'_>> for TunnelEncaps {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => TunnelEncaps);
        match pair.as_rule() {
            ParserRule::encapsulation_gre => Ok(Self::Gre),
            ParserRule::encapsulation_ipip => Ok(Self::IpInIp),
            _ => Err(rule_mismatch!(pair => "tunnel encapsulation")),
        }
    }
}

impl fmt::Display for TunnelEncaps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gre => write!(f, "GRE"),
            Self::IpInIp => write!(f, "IPinIP"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for TunnelEncaps {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![Just(Self::Gre), Just(Self::IpInIp),].boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{compare_ast, display_fmt_parses};

    display_fmt_parses! {
        IfaddrExpr,
        InterfaceExpr,
    }

    compare_ast! {
        IfaddrExpr {
            rfc2622_fig20_inet_rtr_example: "1.1.1.1 masklen 30" => {
                IfaddrExpr {
                    interface: "1.1.1.1/30".parse().unwrap(),
                    action: None,
                    tunnel: None,
                }
            }
        }
    }
}
