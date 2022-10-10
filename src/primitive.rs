use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::str::FromStr;

use ip::{traits::Prefix as _, AfiClass, Any, Ipv4, Ipv6};

use time::{format_description::FormatItem, macros::format_description};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

use crate::{
    error::{err, ParseError, ParseResult},
    names::AutNum,
    parser::{
        debug_construction, impl_case_insensitive_str_primitive, impl_from_str, impl_str_primitive,
        next_into_or, next_parse_or, rule_mismatch, ParserRule, TokenPair,
    },
};

#[cfg(any(test, feature = "arbitrary"))]
use self::arbitrary::{impl_free_form_arbitrary, impl_rpsl_name_arbitrary, prop_filter_keywords};

pub trait ParserAfi: AfiClass {
    const LITERAL_ADDR_RULE: ParserRule;
    const LITERAL_PREFIX_RULE: ParserRule;
}
impl ParserAfi for Ipv4 {
    const LITERAL_ADDR_RULE: ParserRule = ParserRule::ipv4_addr;
    const LITERAL_PREFIX_RULE: ParserRule = ParserRule::ipv4_prefix;
}
impl ParserAfi for Ipv6 {
    const LITERAL_ADDR_RULE: ParserRule = ParserRule::ipv6_addr;
    const LITERAL_PREFIX_RULE: ParserRule = ParserRule::ipv6_prefix;
}
impl ParserAfi for Any {
    const LITERAL_ADDR_RULE: ParserRule = ParserRule::ip_addr_choice;
    const LITERAL_PREFIX_RULE: ParserRule = ParserRule::ip_prefix_choice;
}

/// IP address literal.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct IpAddress<A: ParserAfi> {
    inner: A::Address,
}

impl<A: ParserAfi> IpAddress<A> {
    pub fn new(address: A::Address) -> Self {
        Self { inner: address }
    }

    pub fn into_inner(self) -> A::Address {
        self.inner
    }
}

impl<A: ParserAfi> FromStr for IpAddress<A> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s.parse()?))
    }
}

impl<A: ParserAfi> TryFrom<TokenPair<'_>> for IpAddress<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => IpAddress);
        match pair.as_rule() {
            rule if rule == A::LITERAL_ADDR_RULE => Ok(pair.as_str().parse()?),
            _ => Err(rule_mismatch!(pair => "IP address")),
        }
    }
}

impl<A: ParserAfi> fmt::Display for IpAddress<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for IpAddress<A>
where
    A: ParserAfi + 'static,
    A::Address: Arbitrary,
    <A::Address as Arbitrary>::Strategy: 'static,
{
    type Parameters = ParamsFor<A::Address>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        any_with::<A::Address>(params).prop_map(Self::new).boxed()
    }
}

/// IP prefix literal.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct IpPrefix<A: ParserAfi> {
    inner: A::Prefix,
}

impl<A: ParserAfi> IpPrefix<A> {
    pub fn new(prefix: A::Prefix) -> Self {
        Self { inner: prefix }
    }

    pub fn into_inner(self) -> A::Prefix {
        self.inner
    }
}

impl<A: ParserAfi> FromStr for IpPrefix<A> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s.parse()?))
    }
}

impl<A: ParserAfi> TryFrom<TokenPair<'_>> for IpPrefix<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Prefix);
        match pair.as_rule() {
            rule if rule == A::LITERAL_PREFIX_RULE => Ok(pair.as_str().parse()?),
            _ => Err(rule_mismatch!(pair => "IP prefix")),
        }
    }
}

impl<A: ParserAfi> fmt::Display for IpPrefix<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for IpPrefix<A>
where
    A: ParserAfi + 'static,
    A::Prefix: Arbitrary,
{
    type Parameters = ParamsFor<A::Prefix>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        any_with::<A::Prefix>(params).prop_map(Self::new).boxed()
    }
}

/// IP prefix range literal.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct IpPrefixRange<A: ParserAfi> {
    prefix: IpPrefix<A>,
    op: RangeOperator,
}

impl<A: ParserAfi> IpPrefixRange<A> {
    /// Construct a new [`PrefixRange<T>`].
    pub fn new(prefix: IpPrefix<A>, op: RangeOperator) -> Self {
        Self { prefix, op }
    }

    /// Get the IP prefix represented by this [`PrefixRange<T>`].
    pub fn prefix(&self) -> &IpPrefix<A> {
        &self.prefix
    }

    /// Get the [`RangeOperator`] for this [`PrefixRange<T>`].
    pub fn operator(&self) -> &RangeOperator {
        &self.op
    }
}

impl<A: ParserAfi> TryFrom<TokenPair<'_>> for IpPrefixRange<A> {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => PrefixRange);
        let mut pairs = pair.into_inner();
        let prefix = next_parse_or!(pairs => "failed to get inner prefix")?;
        let op = match pairs.next() {
            Some(inner) => inner.try_into()?,
            None => RangeOperator::None,
        };
        Ok(Self { prefix, op })
    }
}

impl<A: ParserAfi> fmt::Display for IpPrefixRange<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}", self.prefix, self.op)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<A> Arbitrary for IpPrefixRange<A>
where
    A: ParserAfi + 'static,
    A::Prefix: Arbitrary,
    <A::Prefix as ip::traits::Prefix>::Length: AsRef<u8>,
{
    type Parameters = ParamsFor<IpPrefix<A>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        any_with::<IpPrefix<A>>(params)
            .prop_flat_map(|prefix| {
                let len = *prefix.into_inner().prefix_len().as_ref();
                let max_len = *prefix.into_inner().max_prefix_len().as_ref();
                (Just(prefix), any_with::<RangeOperator>((len, max_len)))
            })
            .prop_map(|(prefix, op)| Self::new(prefix, op))
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
            _ => Err(rule_mismatch!(pair => "set name component")),
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
    type Parameters = ParamsFor<SetNameCompName>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<AutNum>().prop_map(Self::AutNum),
            Just(Self::PeerAs),
            any_with::<SetNameCompName>(params).prop_map(Self::Name),
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

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for SetNameCompName {
    type Parameters = ParamsFor<String>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        prop_filter_keywords(any_with::<String>(params))
            .prop_map(Self)
            .boxed()
    }
}

/// RPSL `descr` attribute string.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.1
#[derive(Clone, Debug)]
pub struct ObjectDescr(String);
impl_case_insensitive_str_primitive!(ParserRule::object_descr => ObjectDescr);
#[cfg(any(test, feature = "arbitrary"))]
impl_free_form_arbitrary!(ObjectDescr);

/// RPSL `nic-hanndle`.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-2
#[derive(Clone, Debug)]
pub struct NicHdl(String);
impl_case_insensitive_str_primitive!(ParserRule::nic_hdl => NicHdl);
#[cfg(any(test, feature = "arbitrary"))]
impl_rpsl_name_arbitrary!(NicHdl);

/// RPSL `remarks` attribute string.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.1
#[derive(Clone, Debug)]
pub struct Remarks(String);
impl_case_insensitive_str_primitive!(ParserRule::remarks => Remarks);
#[cfg(any(test, feature = "arbitrary"))]
impl_free_form_arbitrary!(Remarks);

/// RPSL `registry-name`.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-2
#[derive(Clone, Debug)]
pub struct RegistryName(String);
impl_case_insensitive_str_primitive!(ParserRule::registry_name => RegistryName);
#[cfg(any(test, feature = "arbitrary"))]
impl_rpsl_name_arbitrary!(RegistryName);

/// RPSL `address` attribute string.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.2
#[derive(Clone, Debug)]
pub struct Address(String);
impl_case_insensitive_str_primitive!(ParserRule::address => Address);
#[cfg(any(test, feature = "arbitrary"))]
impl_free_form_arbitrary!(Address);

/// RPSL `email-address`.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-2
#[derive(Clone, Debug)]
pub struct EmailAddress(String);
impl_case_insensitive_str_primitive!(ParserRule::email_addr => EmailAddress);

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for EmailAddress {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (any::<DnsName>(), any::<DnsName>())
            .prop_map(|(user, host)| format!("{}@{}", user, host))
            .prop_map(Self)
            .boxed()
    }
}

/// RPSL `phone` or `fax-no` attribute string.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.2
#[derive(Clone, Debug)]
pub struct TelNumber(String);
impl_case_insensitive_str_primitive!(ParserRule::tel_number => TelNumber);

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for TelNumber {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        r"\+[0-9][0-9 ]*( ext\. [0-9]+)?".prop_map(Self).boxed()
    }
}

/// Email address regular expression used in the `MAIL-FROM` authentication
/// scheme.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.1
#[derive(Clone, Debug)]
pub struct EmailAddressRegex(String);
impl_case_insensitive_str_primitive!(ParserRule::email_addr_regexp => EmailAddressRegex);
#[cfg(any(test, feature = "arbitrary"))]
impl_free_form_arbitrary!(EmailAddressRegex);

/// PGP key fingerprint used in the `PGP-FROM` authentication scheme.
/// See [RFC2725].
///
/// [RFC2725]: https://datatracker.ietf.org/doc/html/rfc2725#section-8
#[derive(Clone, Debug)]
pub struct PgpFromFingerprint(String);
impl_case_insensitive_str_primitive!(ParserRule::pgp_from_fingerpr => PgpFromFingerprint);
#[cfg(any(test, feature = "arbitrary"))]
impl_free_form_arbitrary!(PgpFromFingerprint);

/// UNIX crypt hash value used in the `CRYPT-PW` authentication scheme.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.1
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct CryptHash(String);
impl_str_primitive!(ParserRule::crypt_hash => CryptHash);
#[cfg(any(test, feature = "arbitrary"))]
impl_free_form_arbitrary!(CryptHash);

/// RPSL `trouble` attribute string.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.3
#[derive(Clone, Debug)]
pub struct Trouble(String);
impl_case_insensitive_str_primitive!(ParserRule::trouble => Trouble);
#[cfg(any(test, feature = "arbitrary"))]
impl_free_form_arbitrary!(Trouble);

/// RPSL `key-cert` object owner.
/// See [RFC2726].
///
/// [RFC2726]: https://datatracker.ietf.org/doc/html/rfc2726#section-2.1
#[derive(Clone, Debug)]
pub struct KeyOwner(String);
impl_case_insensitive_str_primitive!(ParserRule::owner => KeyOwner);
#[cfg(any(test, feature = "arbitrary"))]
impl_free_form_arbitrary!(KeyOwner);

/// Key fingerprint appearing in an RPSL `key-cert` object.
/// See [RFC2726].
///
/// [RFC2726]: https://datatracker.ietf.org/doc/html/rfc2726#section-2.1
#[derive(Clone, Debug)]
pub struct Fingerprint(String);
impl_case_insensitive_str_primitive!(ParserRule::key_fingerprint => Fingerprint);

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Fingerprint {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        r"[0-9A-Fa-f]+".prop_map(Self).boxed()
    }
}

/// ASCII armoured certificate appearing in an RPSL `key-cert` object.
/// See [RFC2726].
///
/// [RFC2726]: https://datatracker.ietf.org/doc/html/rfc2726#section-2.1
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Certificate(String);
impl_str_primitive!(ParserRule::key_certif => Certificate);
#[cfg(any(test, feature = "arbitrary"))]
impl_free_form_arbitrary!(Certificate);

/// Autonomous system name, contained in the `as-name` RPSL attribute.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-6
#[derive(Clone, Debug)]
pub struct AsName(String);
impl_case_insensitive_str_primitive!(ParserRule::as_name => AsName);
#[cfg(any(test, feature = "arbitrary"))]
impl_rpsl_name_arbitrary!(AsName);

/// IP network name, contained in the `netname` RIPE-81 attribute.
/// See [RFC1786].
///
/// [RFC1786]: https://datatracker.ietf.org/doc/html/rfc1786
#[derive(Clone, Debug)]
pub struct Netname(String);
impl_case_insensitive_str_primitive!(ParserRule::netname => Netname);
#[cfg(any(test, feature = "arbitrary"))]
impl_rpsl_name_arbitrary!(Netname);

/// [ISO-3166] two letter country code.
///
/// [ISO-3166]: https://www.iso.org/obp/ui/#search
#[derive(Clone, Debug)]
pub struct CountryCode(String);
impl_case_insensitive_str_primitive!(ParserRule::country_code => CountryCode);

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for CountryCode {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        r"[A-Za-z]{2}".prop_map(Self).boxed()
    }
}

/// RPSL `dns-name`.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-2
#[derive(Clone, Debug)]
pub struct DnsName(String);
impl_case_insensitive_str_primitive!(ParserRule::dns_name => DnsName);

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for DnsName {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_filter_keywords(r"[A-Za-z][0-9A-Za-z_-]*(\.[A-Za-z][0-9A-Za-z_-]*)*")
            .prop_map(Self)
            .boxed()
    }
}

/// RPSL `date`.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-2
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Date(time::Date);

const DATE_FMT: &[FormatItem] = format_description!("[year][month][day]");

impl AsRef<time::Date> for Date {
    fn as_ref(&self) -> &time::Date {
        &self.0
    }
}

impl FromStr for Date {
    type Err = ParseError;
    fn from_str(s: &str) -> ParseResult<Self> {
        Ok(Self(time::Date::parse(s, DATE_FMT)?))
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
        write!(f, "{}", self.0.format(DATE_FMT).map_err(|_| fmt::Error)?)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Date {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (time::macros::date!(0000 - 01 - 01).to_julian_day()..time::Date::MAX.to_julian_day())
            .prop_map(|day| Self(time::Date::from_julian_day(day).unwrap()))
            .boxed()
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

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for SigningMethod {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![Just(Self::Pgp), Just(Self::X509)].boxed()
    }
}

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

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Protocol {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(Self::Bgp4),
            Just(Self::MpBgp),
            Just(Self::Ospf),
            Just(Self::RipNg),
            Just(Self::Rip),
            Just(Self::Igrp),
            Just(Self::IsIs),
            Just(Self::Static),
            Just(Self::Dvmrp),
            Just(Self::PimDm),
            Just(Self::PimSm),
            Just(Self::Cbt),
            Just(Self::Mospf),
            any::<UnknownProtocol>().prop_map(Self::Unknown)
        ]
        .boxed()
    }
}

/// An unknown `protocol` name.
#[derive(Clone, Debug)]
pub struct UnknownProtocol(String);
impl_case_insensitive_str_primitive!(ParserRule::protocol_unknown => UnknownProtocol);
#[cfg(any(test, feature = "arbitrary"))]
impl_rpsl_name_arbitrary!(UnknownProtocol);

/// RPSL `protocol` option name.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-9
#[derive(Clone, Debug)]
pub struct PeerOptKey(String);
impl_case_insensitive_str_primitive!(ParserRule::peer_opt_key => PeerOptKey);
#[cfg(any(test, feature = "arbitrary"))]
impl_rpsl_name_arbitrary!(PeerOptKey);

/// RPSL `protocol` option value.
/// See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-9
#[derive(Clone, Debug)]
pub struct PeerOptVal(String);
impl_case_insensitive_str_primitive!(ParserRule::peer_opt_val => PeerOptVal);

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for PeerOptVal {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        r"[^\);\pC]+".prop_map(Self).boxed()
    }
}

/// RPSL `afi` names.
/// See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.1
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AfiSafi {
    afi: Afi,
    safi: Option<Safi>,
}

impl_from_str!(ParserRule::afi_safi => AfiSafi);

impl TryFrom<TokenPair<'_>> for AfiSafi {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => AfiSafi);
        match pair.as_rule() {
            ParserRule::afi_safi => {
                let mut pairs = pair.into_inner();
                let afi = next_into_or!(pairs => "failed to get afi name")?;
                let safi = if let Some(inner_pair) = pairs.next() {
                    Some(inner_pair.try_into()?)
                } else {
                    None
                };
                Ok(Self { afi, safi })
            }
            _ => Err(rule_mismatch!(pair => "afi/safi identifier")),
        }
    }
}

impl fmt::Display for AfiSafi {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.afi)?;
        if let Some(safi) = &self.safi {
            write!(f, ".{}", safi)?;
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for AfiSafi {
    type Parameters = ParamsFor<Option<Safi>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (any::<Afi>(), any_with::<Option<Safi>>(params))
            .prop_map(|(afi, safi)| Self { afi, safi })
            .boxed()
    }
}

/// RPSL address family indicator.
/// See [RFC4012}].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.1
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Afi {
    /// `ipv4` address family.
    Ipv4,
    /// `ipv6` address family.
    Ipv6,
    /// `any` token.
    Any,
}

impl TryFrom<TokenPair<'_>> for Afi {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Afi);
        match pair.as_rule() {
            ParserRule::afi_ipv4 => Ok(Self::Ipv4),
            ParserRule::afi_ipv6 => Ok(Self::Ipv6),
            ParserRule::afi_any => Ok(Self::Any),
            _ => Err(rule_mismatch!(pair => "afi identifier")),
        }
    }
}

impl fmt::Display for Afi {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Ipv4 => write!(f, "ipv4"),
            Self::Ipv6 => write!(f, "ipv6"),
            Self::Any => write!(f, "any"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Afi {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![Just(Self::Ipv4), Just(Self::Ipv6), Just(Self::Any)].boxed()
    }
}

/// RPSL subsequent address family indicator.
/// See [RFC4012}].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.1
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Safi {
    /// `unicast` SAFI.
    Unicast,
    /// `multicast` SAFI.
    Multicast,
}

impl TryFrom<TokenPair<'_>> for Safi {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => SafiName);
        match pair.as_rule() {
            ParserRule::safi_unicast => Ok(Self::Unicast),
            ParserRule::safi_multicast => Ok(Self::Multicast),
            _ => Err(rule_mismatch!(pair => "safi identifier")),
        }
    }
}

impl fmt::Display for Safi {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Unicast => write!(f, "unicast"),
            Self::Multicast => write!(f, "multicast"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Safi {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![Just(Self::Unicast), Just(Self::Multicast)].boxed()
    }
}

/// Helpers for implementing [`Arbitrary`] for primitive types.
#[cfg(any(test, feature = "arbitrary"))]
pub mod arbitrary {
    use super::*;
    use regex::RegexSetBuilder;

    /// Filter the values yielded by a [`Strategy<Value = String>`] for
    /// reserved RPSL keywords.
    pub fn prop_filter_keywords<S>(strategy: S) -> impl Strategy<Value = String>
    where
        S: Strategy<Value = String>,
    {
        let keywords = RegexSetBuilder::new(&[
            "^ANY$",
            "^AS-ANY$",
            "^RS-ANY$",
            "^PeerAS$",
            "^AND$",
            "^OR$",
            "^NOT$",
            "^ATOMIC$",
            "^FROM$",
            "^TO$",
            "^AT$",
            "^ACTION$",
            "^ACCEPT$",
            "^ANNOUNCE$",
            "^EXCEPT$",
            "^REFINE$",
            "^NETWORKS$",
            "^INTO$",
            "^INBOUND$",
            "^OUTBOUND$",
        ])
        .case_insensitive(true)
        .build()
        .unwrap();
        strategy.prop_filter("names cannot collide with rpsl keywords", move |s| {
            !keywords.is_match(s)
        })
    }

    macro_rules! impl_rpsl_name_arbitrary {
        ( $t:ty ) => {
            impl proptest::arbitrary::Arbitrary for $t {
                type Parameters = ();
                type Strategy = proptest::strategy::BoxedStrategy<Self>;
                fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
                    let reserved =
                        regex::Regex::new(r"^(?i)AS\d|AS-|RS-|FLTR-|RTRS-|PRNG-").unwrap();
                    $crate::primitive::arbitrary::prop_filter_keywords("[A-Za-z][A-Za-z0-9_-]+")
                        .prop_filter_map("names cannot begin with a reserved sequence", move |s| {
                            if reserved.is_match(&s) {
                                None
                            } else {
                                Some(Self(s))
                            }
                        })
                        .boxed()
                }
            }
        };
    }
    pub(crate) use impl_rpsl_name_arbitrary;

    macro_rules! impl_free_form_arbitrary {
        ( $t:ty ) => {
            impl Arbitrary for $t {
                type Parameters = ();
                type Strategy = BoxedStrategy<Self>;
                fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
                    r"([^#\pC\s][^#\pC]*)?".prop_map(Self).boxed()
                }
            }
        };
    }
    pub(crate) use impl_free_form_arbitrary;
}
