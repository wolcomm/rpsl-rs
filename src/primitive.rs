use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::str::FromStr;

#[cfg(any(test, feature = "arbitrary"))]
use ipnet::{IpNet, Ipv4Net};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

use crate::{
    error::{ParseError, ParseResult},
    names::AutNum,
    parser::{ParserRule, TokenPair},
};

/// IP prefix appearing in a literal prefix set.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct LiteralPrefixSetEntry<T> {
    prefix: T,
    op: RangeOperator,
}

impl<T> LiteralPrefixSetEntry<T> {
    /// Construct a new [`LiteralPrefixSetEntry`].
    pub fn new(prefix: T, op: RangeOperator) -> Self {
        Self { prefix, op }
    }

    /// Get the IP prefix represented by this [`LiteralPrefixSetEntry`].
    pub fn prefix(&self) -> &T {
        &self.prefix
    }

    /// Get the [`RangeOperator`] for this [`LiteralPrefixSetEntry`].
    pub fn operator(&self) -> &RangeOperator {
        &self.op
    }
}

impl<T> TryFrom<TokenPair<'_>> for LiteralPrefixSetEntry<T>
where
    T: FromStr,
    T::Err: Into<ParseError>,
{
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => LiteralPrefixSetEntry);
        let mut pairs = pair.into_inner();
        // let prefix = next_parse_or!(pairs => "failed to get inner prefix");
        let prefix = pairs
            .next()
            .ok_or_else(|| err!("failed to get inner prefix"))?
            .as_str()
            .parse()
            .map_err(|err: T::Err| err.into())?;
        let op = match pairs.next() {
            Some(inner) => inner.try_into()?,
            None => RangeOperator::None,
        };
        Ok(Self { prefix, op })
    }
}

impl<T: fmt::Display> fmt::Display for LiteralPrefixSetEntry<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}", self.prefix, self.op)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for LiteralPrefixSetEntry<Ipv4Net> {
    type Parameters = ParamsFor<std::net::Ipv4Addr>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        use std::net::Ipv4Addr;
        any_with::<Ipv4Addr>(args)
            .prop_flat_map(|addr| {
                let max_len = 32u8;
                (Just(addr), 0..=max_len, Just(max_len))
            })
            .prop_flat_map(|(addr, len, max_len)| {
                (
                    Just(addr),
                    Just(len),
                    any_with::<RangeOperator>((len, max_len)),
                )
            })
            .prop_map(|(addr, len, op)| {
                let prefix = Ipv4Net::new(addr, len).unwrap().trunc();
                Self { prefix, op }
            })
            .boxed()
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for LiteralPrefixSetEntry<IpNet> {
    type Parameters = ParamsFor<std::net::IpAddr>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        use std::net::IpAddr;
        any_with::<IpAddr>(args)
            .prop_flat_map(|addr| {
                let max_len = match addr {
                    IpAddr::V4(_) => 32u8,
                    IpAddr::V6(_) => 128u8,
                };
                (Just(addr), 0..=max_len, Just(max_len))
            })
            .prop_flat_map(|(addr, len, max_len)| {
                (
                    Just(addr),
                    Just(len),
                    any_with::<RangeOperator>((len, max_len)),
                )
            })
            .prop_map(|(addr, len, op)| {
                let prefix = match addr {
                    IpAddr::V4(addr) => ipnet::Ipv4Net::new(addr, len).unwrap().trunc().into(),
                    IpAddr::V6(addr) => ipnet::Ipv6Net::new(addr, len).unwrap().trunc().into(),
                };
                Self { prefix, op }
            })
            .boxed()
    }
}

/// RSPL range operator. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-2
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum RangeOperator {
    /// No range operator.
    None,
    /// Exclusive more specific operator (`^-`).
    LessExcl,
    /// Inclusive more specific operator (`^+`).
    LessIncl,
    /// Exact length operator (`^n`).
    Exact(u8),
    /// Length range operator (`^m-n`).
    Range(u8, u8),
}

impl TryFrom<TokenPair<'_>> for RangeOperator {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => PrefixOp);
        match pair.as_rule() {
            ParserRule::less_excl => Ok(Self::LessExcl),
            ParserRule::less_incl => Ok(Self::LessIncl),
            ParserRule::exact => Ok(Self::Exact(
                next_parse_or!(pair.into_inner() => "failed to get operand for range operation"),
            )),
            ParserRule::range => {
                let mut pairs = pair.into_inner();
                Ok(Self::Range(
                    next_parse_or!(pairs => "failed to get lower operand for range operation"),
                    next_parse_or!(pairs => "failed to get upper operand for range operation"),
                ))
            }
            _ => Err(err!(
                "expected a prefix range operation, got {:?}: {}",
                pair.as_rule(),
                pair.as_str()
            )),
        }
    }
}

impl fmt::Display for RangeOperator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::None => write!(f, ""),
            Self::LessExcl => write!(f, "^-"),
            Self::LessIncl => write!(f, "^+"),
            Self::Exact(n) => write!(f, "^{}", n),
            Self::Range(m, n) => write!(f, "^{}-{}", m, n),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for RangeOperator {
    type Parameters = (u8, u8);
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(Self::None),
            Just(Self::LessExcl),
            Just(Self::LessIncl),
            (args.0..=args.1).prop_map(Self::Exact),
            (args.0..=args.1)
                .prop_flat_map(move |lower| (Just(lower), lower..=args.1))
                .prop_map(|(lower, upper)| Self::Range(lower, upper))
        ]
        .boxed()
    }
}

/// Components (seperated by `:`) in RPSL set names.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum SetNameComp {
    /// Component containing the name of an `aut-num`.
    AutNum(AutNum),
    /// Component containing the `PeerAS` token.
    PeerAs,
    /// Component containing a set name, according to the class of the set.
    Name(String),
}

impl TryFrom<TokenPair<'_>> for SetNameComp {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => SetNameComp);
        match pair.as_rule() {
            ParserRule::aut_num => Ok(Self::AutNum(pair.as_str().parse()?)),
            ParserRule::peeras => Ok(Self::PeerAs),
            ParserRule::filter_set_name
            | ParserRule::route_set_name
            | ParserRule::as_set_name
            | ParserRule::rtr_set_name
            | ParserRule::peering_set_name => Ok(Self::Name(pair.as_str().to_string())),
            _ => Err(err!(
                "expected a set name component, got {:?}: {}",
                pair.as_rule(),
                pair.as_str()
            )),
        }
    }
}

impl fmt::Display for SetNameComp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::AutNum(autnum) => autnum.fmt(f),
            Self::PeerAs => write!(f, "PeerAS"),
            Self::Name(name) => name.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for SetNameComp {
    type Parameters = (&'static str,);
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<AutNum>().prop_map(Self::AutNum),
            Just(Self::PeerAs),
            args.0.prop_map(Self::Name)
        ]
        .boxed()
    }
}
