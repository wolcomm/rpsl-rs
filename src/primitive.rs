use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::str::FromStr;

use chrono::NaiveDate;

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

use crate::{
    addr_family::Afi,
    error::{err, ParseError, ParseResult},
    names::AutNum,
    parser::{
        debug_construction, impl_case_insensitive_str_primitive, impl_str_primitive, next_parse_or,
        rule_mismatch, ParserRule, TokenPair,
    },
};

/// IP prefix literal.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Prefix<A: Afi>(A::Net);

impl<A: Afi> FromStr for Prefix<A> {
    type Err = <A::Net as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

impl<A: Afi> TryFrom<TokenPair<'_>> for Prefix<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Prefix);
        match pair.as_rule() {
            rule if rule == A::LITERAL_PREFIX_RULE => Ok(Self(pair.as_str().parse()?)),
            _ => Err(rule_mismatch!(pair => "IP prefix")),
        }
    }
}

impl<A: Afi> fmt::Display for Prefix<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

// TODO: impl Arbitrary for Prefix

/// IP prefix range literal.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct PrefixRange<A: Afi> {
    prefix: A::Net,
    op: RangeOperator,
}

impl<A: Afi> PrefixRange<A> {
    /// Construct a new [`PrefixRange<T>`].
    pub fn new(prefix: A::Net, op: RangeOperator) -> Self {
        Self { prefix, op }
    }

    /// Get the IP prefix represented by this [`PrefixRange<T>`].
    pub fn prefix(&self) -> &A::Net {
        &self.prefix
    }

    /// Get the [`RangeOperator`] for this [`PrefixRange<T>`].
    pub fn operator(&self) -> &RangeOperator {
        &self.op
    }
}

impl<A: Afi> TryFrom<TokenPair<'_>> for PrefixRange<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => PrefixRange);
        let mut pairs = pair.into_inner();
        let prefix = next_parse_or!(pairs => "failed to get inner prefix")?;
        // .map_err(|err| err.into())?;
        let op = match pairs.next() {
            Some(inner) => inner.try_into()?,
            None => RangeOperator::None,
        };
        Ok(Self { prefix, op })
    }
}

impl<A: Afi> fmt::Display for PrefixRange<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}", self.prefix, self.op)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A: Afi> Arbitrary for PrefixRange<A>
where
    A: fmt::Debug,
    A::Addr: Arbitrary + Clone,
    <A::Addr as Arbitrary>::Strategy: 'static,
    A::Net: fmt::Debug,
{
    type Parameters = ParamsFor<A::Addr>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        any_with::<A::Addr>(args)
            .prop_flat_map(|addr| {
                let max_len = A::max_len(&addr);
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
                let prefix = A::addr_to_net(addr, len);
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
                next_parse_or!(pair.into_inner() => "failed to get operand for range operation")?,
            )),
            ParserRule::range => {
                let mut pairs = pair.into_inner();
                Ok(Self::Range(
                    next_parse_or!(pairs => "failed to get lower operand for range operation")?,
                    next_parse_or!(pairs => "failed to get upper operand for range operation")?,
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
    Name(SetNameCompName),
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
            | ParserRule::peering_set_name => Ok(Self::Name(pair.try_into()?)),
            // TODO: use rule_mismatch!
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
            args.0.prop_map(|name| Self::Name(name.as_str().into()))
        ]
        .boxed()
    }
}

/// RPSL set class name component.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5
#[derive(Clone, Debug)]
pub struct SetNameCompName(String);
impl_case_insensitive_str_primitive!(
    ParserRule::filter_set_name
     | ParserRule::route_set_name
     | ParserRule::as_set_name
     | ParserRule::rtr_set_name
     | ParserRule::peering_set_name => SetNameCompName
);

/// RPSL `descr` attribute string.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.1
#[derive(Clone, Debug)]
pub struct ObjectDescr(String);
impl_case_insensitive_str_primitive!(ParserRule::object_descr => ObjectDescr);

/// RPSL `nic-hanndle`.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-2
#[derive(Clone, Debug)]
pub struct NicHdl(String);
impl_case_insensitive_str_primitive!(ParserRule::nic_hdl => NicHdl);

/// RPSL `remarks` attribute string.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.1
#[derive(Clone, Debug)]
pub struct Remarks(String);
impl_case_insensitive_str_primitive!(ParserRule::remarks => Remarks);

/// RPSL `registry-name`.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-2
#[derive(Clone, Debug)]
pub struct RegistryName(String);
impl_case_insensitive_str_primitive!(ParserRule::registry_name => RegistryName);

/// RPSL `address` attribute string.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.2
#[derive(Clone, Debug)]
pub struct Address(String);
impl_case_insensitive_str_primitive!(ParserRule::address => Address);

/// RPSL `email-address`.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-2
#[derive(Clone, Debug)]
pub struct EmailAddress(String);
impl_case_insensitive_str_primitive!(ParserRule::email_addr => EmailAddress);

/// RPSL `phone` or `fax-no` attribute string.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.2
#[derive(Clone, Debug)]
pub struct TelNumber(String);
impl_case_insensitive_str_primitive!(ParserRule::tel_number => TelNumber);

/// Email address regular expression used in the `MAIL-FROM` authentication
/// scheme.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.1
#[derive(Clone, Debug)]
pub struct EmailAddressRegex(String);
impl_case_insensitive_str_primitive!(ParserRule::email_addr_regexp => EmailAddressRegex);

/// PGP key fingerprint used in the `PGP-FROM` authentication scheme.
/// See [RFC2725].
///
/// [RFC2725]: https://datatracker.ietf.org/doc/html/rfc2725#section-8
#[derive(Clone, Debug)]
pub struct PgpFromFingerprint(String);
impl_case_insensitive_str_primitive!(ParserRule::pgp_from_fingerpr => PgpFromFingerprint);

/// UNIX crypt hash value used in the `CRYPT-PW` authentication scheme.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.1
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct CryptHash(String);
impl_str_primitive!(ParserRule::crypt_hash => CryptHash);

/// RPSL `trouble` attribute string.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.3
#[derive(Clone, Debug)]
pub struct Trouble(String);
impl_case_insensitive_str_primitive!(ParserRule::trouble => Trouble);

/// RPSL `key-cert` object owner.
/// See [RFC2726].
///
/// [RFC2726]: https://datatracker.ietf.org/doc/html/rfc2726#section-2.1
#[derive(Clone, Debug)]
pub struct KeyOwner(String);
impl_case_insensitive_str_primitive!(ParserRule::owner => KeyOwner);

/// Key fingerprint appearing in an RPSL `key-cert` object.
/// See [RFC2726].
///
/// [RFC2726]: https://datatracker.ietf.org/doc/html/rfc2726#section-2.1
#[derive(Clone, Debug)]
pub struct Fingerprint(String);
impl_case_insensitive_str_primitive!(ParserRule::key_fingerprint => Fingerprint);

/// ASCII armoured certificate appearing in an RPSL `key-cert` object.
/// See [RFC2726].
///
/// [RFC2726]: https://datatracker.ietf.org/doc/html/rfc2726#section-2.1
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Certificate(String);
impl_str_primitive!(ParserRule::key_certif => Certificate);

/// Autonomous system name, contained in the `as-name` RPSL attribute.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-6
#[derive(Clone, Debug)]
pub struct AsName(String);
impl_case_insensitive_str_primitive!(ParserRule::as_name => AsName);

/// IP network name, contained in the `netname` RIPE-81 attribute.
/// See [RFC1786].
///
/// [RFC1786]: https://datatracker.ietf.org/doc/html/rfc1786
#[derive(Clone, Debug)]
pub struct Netname(String);
impl_case_insensitive_str_primitive!(ParserRule::netname => Netname);

/// [ISO-3166] two letter country code.
///
/// [ISO-3166]: https://www.iso.org/obp/ui/#search
#[derive(Clone, Debug)]
pub struct CountryCode(String);
impl_case_insensitive_str_primitive!(ParserRule::country_code => CountryCode);

/// RPSL `dns-name`.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-2
#[derive(Clone, Debug)]
pub struct DnsName(String);
impl_case_insensitive_str_primitive!(ParserRule::dns_name => DnsName);

/// RPSL `date`.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-2
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Date(NaiveDate);

impl AsRef<NaiveDate> for Date {
    fn as_ref(&self) -> &NaiveDate {
        &self.0
    }
}

impl FromStr for Date {
    type Err = ParseError;
    fn from_str(s: &str) -> ParseResult<Self> {
        Ok(Self(NaiveDate::parse_from_str(s, "%Y%m%d")?))
    }
}

impl TryFrom<TokenPair<'_>> for Date {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Date);
        match pair.as_rule() {
            ParserRule::date => pair.as_str().parse(),
            _ => Err(rule_mismatch!(pair => "date")),
        }
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.format("%Y%m%d"))
    }
}

/// RPSL `key-cert` object signing method.
/// See [RFC2726].
///
/// [RFC2726]: https://datatracker.ietf.org/doc/html/rfc2726#section-2.1
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum SigningMethod {
    /// `PGP` signing method.
    Pgp,
    /// `X509` signing method.
    X509,
}

impl TryFrom<TokenPair<'_>> for SigningMethod {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => SigningMethod);
        match pair.as_rule() {
            ParserRule::signing_method_pgp => Ok(Self::Pgp),
            ParserRule::signing_method_x509 => Ok(Self::X509),
            _ => Err(rule_mismatch!(pair => "signing method")),
        }
    }
}

impl fmt::Display for SigningMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Pgp => write!(f, "PGP"),
            Self::X509 => write!(f, "X509"),
        }
    }
}

// TODO: impl Arbitrary for SigningMethod

/// RPSL `protocol` name.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-7
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Protocol {
    /// Border Gateway Protocol version 4.
    Bgp4,
    /// BGP version 4 with Multi-Protocol extensions.
    MpBgp,
    /// Open Shortest Path First.
    Ospf,
    /// Routing Information Protocol "next-gen".
    RipNg,
    /// Routing Information Protocol.
    Rip,
    /// Interior Gateway Routing Protocol.
    Igrp,
    /// ISO Intermediate System to Intermediate System protocol.
    IsIs,
    /// Static routing information.
    Static,
    /// Dynamic Vector Multicast Routing Protocol.
    Dvmrp,
    /// Protocol Independent Multicast - Dense Mode.
    PimDm,
    /// Protocol Independent Multicast - Sparse Mode.
    PimSm,
    /// Core Based Trees.
    Cbt,
    /// Multicast Open Shortest Path First.
    Mospf,
    /// Unknown routing protocol variant.
    Unknown(UnknownProtocol),
}

impl TryFrom<TokenPair<'_>> for Protocol {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Protocol);
        match pair.as_rule() {
            ParserRule::protocol_bgp4 => Ok(Self::Bgp4),
            ParserRule::protocol_mpbgp => Ok(Self::MpBgp),
            ParserRule::protocol_ospf => Ok(Self::Ospf),
            ParserRule::protocol_ripng => Ok(Self::RipNg),
            ParserRule::protocol_rip => Ok(Self::Rip),
            ParserRule::protocol_igrp => Ok(Self::Igrp),
            ParserRule::protocol_isis => Ok(Self::IsIs),
            ParserRule::protocol_static => Ok(Self::Static),
            ParserRule::protocol_dvmrp => Ok(Self::Dvmrp),
            ParserRule::protocol_pim_dm => Ok(Self::PimDm),
            ParserRule::protocol_pim_sm => Ok(Self::PimSm),
            ParserRule::protocol_cbt => Ok(Self::Cbt),
            ParserRule::protocol_mospf => Ok(Self::Mospf),
            ParserRule::protocol_unknown => Ok(Self::Unknown(pair.try_into()?)),
            _ => Err(rule_mismatch!(pair => "protocol name")),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Bgp4 => write!(f, "BGP4"),
            Self::MpBgp => write!(f, "MPBGP"),
            Self::Ospf => write!(f, "OSPF"),
            Self::RipNg => write!(f, "RIPng"),
            Self::Rip => write!(f, "RIP"),
            Self::Igrp => write!(f, "IGRP"),
            Self::IsIs => write!(f, "IS-IS"),
            Self::Static => write!(f, "STATIC"),
            Self::Dvmrp => write!(f, "DVMRP"),
            Self::PimDm => write!(f, "PIM-DM"),
            Self::PimSm => write!(f, "PIM-SM"),
            Self::Cbt => write!(f, "CBT"),
            Self::Mospf => write!(f, "MOSPF"),
            Self::Unknown(name) => write!(f, "{}", name),
        }
    }
}

// TODO: impl Arbitrary for Protocol

/// An unknown `protocol` name.
#[derive(Clone, Debug)]
pub struct UnknownProtocol(String);
impl_case_insensitive_str_primitive!(ParserRule::protocol_unknown => UnknownProtocol);

/// RPSL `protocol` option name.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-9
#[derive(Clone, Debug)]
pub struct PeerOptKey(String);
impl_case_insensitive_str_primitive!(ParserRule::peer_opt_key => PeerOptKey);

/// RPSL `protocol` option value.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-9
#[derive(Clone, Debug)]
pub struct PeerOptVal(String);
impl_case_insensitive_str_primitive!(ParserRule::peer_opt_val => PeerOptVal);
