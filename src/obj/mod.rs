use std::collections::HashMap;
use std::fmt;

use crate::{
    attr::{AttributeSeq, AttributeType, RpslAttribute},
    error::{ParseError, ParseResult, ValidationError, ValidationResult},
    names,
    parser::{debug_construction, impl_from_str, rule_mismatch, ParserRule, TokenPair},
};

mod macros;

use self::macros::rpsl_object_class;

/// Enumeration of RPSL object class types.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum RpslObject {
    /// RPSL `mntner` object. See [`Mntner`].
    Mntner(Mntner),
    /// RPSL `person` object. See [`Person`].
    Person(Person),
    /// RPSL `role` object. See [`Role`].
    Role(Role),
    /// RPSL `key-cert` object. See [`KeyCert`].
    KeyCert(KeyCert),
    /// RPSL `as-block` object. See [`AsBlock`].
    AsBlock(AsBlock),
    /// RPSL `aut-num` object. See [`AutNum`].
    AutNum(AutNum),
    /// RPSL `inetnum` object. See [`InetNum`].
    InetNum(InetNum),
    /// RPSL `inet6num` object. See [`Inet6Num`].
    Inet6Num(Inet6Num),
    /// RPSL `route` object. See [`Route`].
    Route(Route),
    /// RPSL `route6` object. See [`Route6`].
    Route6(Route6),
    /// RPSL `as-set` object. See [`AsSet`].
    AsSet(AsSet),
    /// RPSL `route-set` object. See [`RouteSet`].
    RouteSet(RouteSet),
    /// RPSL `filter-set` object. See [`FilterSet`].
    FilterSet(FilterSet),
    /// RPSL `rtr-set` object. See [`RtrSet`].
    RtrSet(RtrSet),
    /// RPSL `peering-set` object. See [`PeeringSet`].
    PeeringSet(PeeringSet),
    /// RPSL `inet-rtr` object. See [`InetRtr`].
    InetRtr(InetRtr),
    /// RPSL `dictionary` object. See [`Dictionary`].
    Dictionary(Dictionary),
}

impl TryFrom<TokenPair<'_>> for RpslObject {
    type Error = ParseError;

    fn try_from(pair: TokenPair<'_>) -> ParseResult<Self> {
        debug_construction!(pair => RpslObject);
        match pair.as_rule() {
            ParserRule::mntner_obj => Ok(Self::Mntner(pair.try_into()?)),
            ParserRule::person_obj => Ok(Self::Person(pair.try_into()?)),
            ParserRule::role_obj => Ok(Self::Role(pair.try_into()?)),
            ParserRule::key_cert_obj => Ok(Self::KeyCert(pair.try_into()?)),
            ParserRule::as_block_obj => Ok(Self::AsBlock(pair.try_into()?)),
            ParserRule::aut_num_obj => Ok(Self::AutNum(pair.try_into()?)),
            ParserRule::inetnum_obj => Ok(Self::InetNum(pair.try_into()?)),
            ParserRule::inet6num_obj => Ok(Self::Inet6Num(pair.try_into()?)),
            ParserRule::route_obj => Ok(Self::Route(pair.try_into()?)),
            ParserRule::route6_obj => Ok(Self::Route6(pair.try_into()?)),
            ParserRule::as_set_obj => Ok(Self::AsSet(pair.try_into()?)),
            ParserRule::route_set_obj => Ok(Self::RouteSet(pair.try_into()?)),
            ParserRule::filter_set_obj => Ok(Self::FilterSet(pair.try_into()?)),
            ParserRule::rtr_set_obj => Ok(Self::RtrSet(pair.try_into()?)),
            ParserRule::peering_set_obj => Ok(Self::PeeringSet(pair.try_into()?)),
            ParserRule::inet_rtr_obj => Ok(Self::InetRtr(pair.try_into()?)),
            ParserRule::dictionary_obj => Ok(Self::Dictionary(pair.try_into()?)),
            _ => Err(rule_mismatch!(pair => "rpsl object")),
        }
    }
}

impl_from_str!(ParserRule::just_rpsl_object => RpslObject);

impl fmt::Display for RpslObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mntner(obj) => obj.fmt(f),
            Self::Person(obj) => obj.fmt(f),
            Self::Role(obj) => obj.fmt(f),
            Self::KeyCert(obj) => obj.fmt(f),
            Self::AsBlock(obj) => obj.fmt(f),
            Self::AutNum(obj) => obj.fmt(f),
            Self::InetNum(obj) => obj.fmt(f),
            Self::Inet6Num(obj) => obj.fmt(f),
            Self::Route(obj) => obj.fmt(f),
            Self::Route6(obj) => obj.fmt(f),
            Self::AsSet(obj) => obj.fmt(f),
            Self::RouteSet(obj) => obj.fmt(f),
            Self::FilterSet(obj) => obj.fmt(f),
            Self::RtrSet(obj) => obj.fmt(f),
            Self::PeeringSet(obj) => obj.fmt(f),
            Self::InetRtr(obj) => obj.fmt(f),
            Self::Dictionary(obj) => obj.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod arbitrary {
    use proptest::{
        arbitrary::{any, Arbitrary},
        prop_oneof,
        strategy::{BoxedStrategy, Strategy as _},
    };

    use super::{
        AsBlock, AsSet, AutNum, Dictionary, FilterSet, Inet6Num, InetNum, InetRtr, KeyCert, Mntner,
        PeeringSet, Person, Role, Route, Route6, RouteSet, RpslObject, RtrSet,
    };

    impl Arbitrary for RpslObject {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;
        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            prop_oneof![
                any::<Mntner>().prop_map(Self::Mntner),
                any::<Person>().prop_map(Self::Person),
                any::<Role>().prop_map(Self::Role),
                any::<KeyCert>().prop_map(Self::KeyCert),
                any::<AsBlock>().prop_map(Self::AsBlock),
                any::<AutNum>().prop_map(Self::AutNum),
                any::<InetNum>().prop_map(Self::InetNum),
                any::<Inet6Num>().prop_map(Self::Inet6Num),
                any::<Route>().prop_map(Self::Route),
                any::<Route6>().prop_map(Self::Route6),
                any::<AsSet>().prop_map(Self::AsSet),
                any::<RouteSet>().prop_map(Self::RouteSet),
                any::<FilterSet>().prop_map(Self::FilterSet),
                any::<RtrSet>().prop_map(Self::RtrSet),
                any::<PeeringSet>().prop_map(Self::PeeringSet),
                any::<InetRtr>().prop_map(Self::InetRtr),
                any::<Dictionary>().prop_map(Self::Dictionary),
            ]
            .boxed()
        }
    }
}

/// Object validation rule indicating whether a given RPSL attribute type is
/// permitted in a given RSPL object, and if so whether it is mandatory
/// and/or multivalued.
#[derive(Debug, Copy, Clone)]
pub struct AttributeRule {
    attr: AttributeType,
    mandatory: bool,
    multivalued: bool,
}

impl AttributeRule {
    const fn new(attr: AttributeType, mandatory: bool, multivalued: bool) -> Self {
        Self {
            attr,
            mandatory,
            multivalued,
        }
    }
}

/// Interface for RSPL object types.
pub trait RpslObjectClass: Sized {
    /// The name of the RPSL class.
    const CLASS: &'static str;
    /// The set of rules governing the occurrence of attributes in this object
    /// class.
    const ATTRS: &'static [AttributeRule];
    /// The type of the eponymous attribute of the RPSL object class.
    type Name;

    /// Create a new instance of [`Self`], validating its attributes in the
    /// process.
    ///
    /// # Errors
    ///
    /// See [`RpslObjectClass::validate`].
    fn new<I>(name: Self::Name, iter: I) -> ValidationResult<Self>
    where
        I: IntoIterator<Item = RpslAttribute>;

    /// Get the attribute for which the class is named.
    fn name(&self) -> &Self::Name;

    /// Get the attributes of the object.
    fn attrs(&self) -> &AttributeSeq;

    /// Validate that an iterator of [`RpslAttribute`]s yields can be used to
    /// construct a valid instance of [`Self`].
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] if the construction rules for `Self` are
    /// violated:
    ///
    /// - All mandatory attributes are present in `attrs`;
    /// - No disallowed attributes are present in `attrs`; and
    /// - Non-multivalued attributes are present at most once in `attrs`.
    fn validate<I>(attrs: I) -> ValidationResult<AttributeSeq>
    where
        I: IntoIterator<Item = RpslAttribute>,
    {
        let mut seen: HashMap<AttributeType, usize> = HashMap::new();
        let allowed: HashMap<AttributeType, bool> = Self::ATTRS
            .iter()
            .map(|rule| (rule.attr, rule.multivalued))
            .collect();
        let seq = attrs
            .into_iter()
            .inspect(|attr| {
                let count = seen.entry(attr.into()).or_insert(0);
                *count += 1;
            })
            .collect();
        seen.iter().try_for_each(|(attr, count)| {
            allowed
                .get(attr)
                .ok_or_else::<ValidationError, _>(|| {
                    format!(
                        "attribute '{}' not allowed in '{}' object",
                        attr,
                        Self::CLASS
                    )
                    .into()
                })
                .and_then(|multivalued| {
                    if !multivalued && count > &1 {
                        Err(format!(
                            "multiple '{}' attributes not allowed in '{}' object",
                            attr,
                            Self::CLASS
                        )
                        .into())
                    } else {
                        Ok(())
                    }
                })
        })?;
        Self::ATTRS
            .iter()
            .filter(|rule| rule.mandatory)
            .try_for_each(|rule| {
                seen.contains_key(&rule.attr)
                    .then_some(())
                    .ok_or_else::<ValidationError, _>(|| {
                        format!(
                            "missing mandatory attribute {} in '{}' object",
                            rule.attr,
                            Self::CLASS
                        )
                        .into()
                    })
            })?;
        Ok(seq)
    }
}

// descr attribute is mandatory and single-valued for all objects in terms of
// rfc2622, but is optional and multi-valued in terms of the ripe object template.
//
// similarly, tech-c is mandatory for all objects in terms of rfc2622, but is
// optional in terms of both ripe and radb object templates.
//
// we use the less restrictive versions here.

rpsl_object_class! {
    /// RPSL `mntner` object.
    ///
    /// Defined in [RFC2622], updated by [RFC2725] and [RFC2726].
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.1
    /// [RFC2725]: https://datatracker.ietf.org/doc/html/rfc2725#section-8
    /// [RFC2726]: https://datatracker.ietf.org/doc/html/rfc2726#section-2.2
    Mntner {
        class: "mntner",
        name: names::Mntner,
        parser_rule: ParserRule::mntner_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            Auth (+),
            UpdTo (+),
            MntNfy (*),
            // `referral-by` is mandatory according to rfc2725, but that
            // breaks backwards compatibility with ~everything!
            ReferralBy (*),
            AuthOverride (?),
        ],
    }
}

rpsl_object_class! {
    /// RPSL `person` object.
    ///
    /// Defined in [RFC2622].
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.2
    Person {
        class: "person",
        name: names::Person,
        parser_rule: ParserRule::person_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            NicHdl,
            Address (+),
            Phone (+),
            FaxNo (*),
            EMail (+),
            Auth (*),
        ],
    }
}

rpsl_object_class! {
    /// RPSL `role` object.
    ///
    /// Defined in [RFC2622].
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-3.3
    Role {
        class: "role",
        name: names::Role,
        parser_rule: ParserRule::role_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            NicHdl,
            Trouble (*),
            Address (+),
            Phone (+),
            FaxNo (*),
            EMail (+),
            Auth (*),
        ],
    }
}

rpsl_object_class! {
    /// RPSL `key-cert` object.
    ///
    /// Defined in [RFC2726].
    ///
    /// [RFC2726]: https://datatracker.ietf.org/doc/html/rfc2726
    KeyCert {
        class: "key-cert",
        name: names::KeyCert,
        parser_rule: ParserRule::key_cert_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            Method,
            Owner (+),
            Fingerpr,
            Certif,
        ],
    }
}

rpsl_object_class! {
    /// RPSL `as-block` object.
    ///
    /// Defined in [RFC2725].
    ///
    /// [RFC2725]: https://datatracker.ietf.org/doc/html/rfc2725#section-10
    AsBlock {
        class: "as-block",
        name: names::AsBlock,
        parser_rule: ParserRule::as_block_obj,
        attributes: [
            Descr (*),
            AdminC (*),
            TechC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            MntLower (*),
            // rfc2725 doesn't say whether `reclaim` and `no-reclaim` are
            // multi-valued!
            Reclaim (?),
            NoReclaim (?),
        ],
    }
}

rpsl_object_class! {
    /// RPSL `aut-num` object.
    ///
    /// Defined in [RFC2622]. Updated by [RFC2725], and [RFC4012].
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-6
    /// [RFC2725]: https://datatracker.ietf.org/doc/html/rfc2725#section-10
    /// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-2.5
    AutNum {
        class: "aut-num",
        name: names::AutNum,
        parser_rule: ParserRule::aut_num_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            AsName,
            AutNumMemberOf (*),
            Import (*),
            MpImport (*),
            Export (*),
            MpExport (*),
            Default (*),
            MpDefault (*),
            MntRoutes (*),
            MntLower (*),
            // rfc2725 doesn't say whether `reclaim` and `no-reclaim` are
            // multi-valued!
            Reclaim (?),
            NoReclaim (?),
        ],
    }
}

// TODO: check whois.ripe.net template
rpsl_object_class! {
    /// RPSL `inetnum` object.
    ///
    /// The `inetnum` object is not defined in the RPSL RFCs.
    /// See [RIPE-81] and [RIPE-181] for details.
    InetNum {
        class: "inetnum",
        name: names::InetNum,
        parser_rule: ParserRule::inetnum_obj,
        attributes: [
            Netname,
            Descr (*),
            Country (+),
            AdminC (*),
            TechC (*),
            // TODO
            // Status,
            MntBy (+),
            Changed (+),
            Source,
            MntRoutes (*),
            MntLower (*),
            // rfc2725 doesn't say whether `reclaim` and `no-reclaim` are
            // multi-valued!
            Reclaim (?),
            NoReclaim (?),
        ],
    }
}

// TODO: check rfc4012
rpsl_object_class! {
    /// RPSL `inet6num` object.
    ///
    /// Defined in [RFC4012].
    ///
    /// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-5
    Inet6Num {
        class: "inet6num",
        name: names::Inet6Num,
        parser_rule: ParserRule::inet6num_obj,
        attributes: [
            Netname,
            Descr (*),
            Country (+),
            AdminC (*),
            TechC (*),
            // TODO
            // Status,
            MntBy (+),
            Changed (+),
            Source,
            MntRoutes (*),
            MntLower (*),
            // rfc2725 doesn't say whether `reclaim` and `no-reclaim` are
            // multi-valued!
            Reclaim (?),
            NoReclaim (?),
        ],
    }
}

rpsl_object_class! {
    /// RPSL `route` object.
    ///
    /// Defined in [RFC2622]. Updated by [RFC2725]
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-4
    /// [RFC2725]: https://datatracker.ietf.org/doc/html/rfc2725#section-10.1
    Route {
        class: "route",
        name: names::Route,
        parser_rule: ParserRule::route_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            Origin,
            RouteMemberOf (*),
            Inject (*),
            Components (?),
            AggrBndry (?),
            AggrMtd (?),
            ExportComps (?),
            Holes (*),
            MntRoutes (*),
            MntLower (*),
            Pingable4 (*),
            PingHdl (*),
            // rfc2725 doesn't say whether `reclaim` and `no-reclaim` are
            // multi-valued!
            Reclaim (?),
            NoReclaim (?),
        ],
    }
}

rpsl_object_class! {
    /// RPSL `route6` object.
    ///
    /// Defined in [RFC4012].
    ///
    /// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-3
    Route6 {
        class: "route6",
        name: names::Route6,
        parser_rule: ParserRule::route6_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            Origin,
            RouteMemberOf (*),
            Inject6 (*),
            Components6 (?),
            AggrBndry (?),
            AggrMtd (?),
            ExportComps6 (?),
            Holes6 (*),
            MntRoutes (*),
            MntLower (*),
            Pingable6 (*),
            PingHdl (*),
            // rfc2725 doesn't say whether `reclaim` and `no-reclaim` are
            // multi-valued!
            Reclaim (?),
            NoReclaim (?),
        ],
    }
}

rpsl_object_class! {
    /// RPSL `as-set` object.
    ///
    /// Defined in [RFC2622]. Updated by [RFC4012].
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.1
    /// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-4.1
    AsSet {
        class: "as-set",
        name: names::AsSet,
        parser_rule: ParserRule::as_set_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            AsSetMembers (*),
            MbrsByRef (*),
            // `mnt-lower` is not allowed to appear in set objects in terms
            // of the definition in rfc2725.
            // however, for it to work correctly this must be allowed.
            // Also, it appears in `route-set` examples in rfc2725! FFS!
            MntLower (*),
        ],
    }
}

rpsl_object_class! {
    /// RPSL `route-set` object.
    ///
    /// Defined in [RFC2622]. Updated by [RFC4012].
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.2
    /// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-4.2
    RouteSet {
        class: "route-set",
        name: names::RouteSet,
        parser_rule: ParserRule::route_set_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            RouteSetMembers (*),
            RouteSetMpMembers (*),
            MbrsByRef (*),
            // `mnt-lower` is not allowed to appear in set objects in terms
            // of the definition in rfc2725.
            // however, for it to work correctly this must be allowed.
            // Also, it appears in `route-set` examples in rfc2725! FFS!
            MntLower (*),
        ],
    }
}

rpsl_object_class! {
    /// RPSL `filter-set` object.
    ///
    /// Defined in [RFC2622]. Updated by [RFC4012].
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.4
    /// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-4.3
    FilterSet {
        class: "filter-set",
        name: names::FilterSet,
        parser_rule: ParserRule::filter_set_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            // TODO: one of `filter` or `mp-filter` should be required during
            // validation.
            Filter (?),
            MpFilter (?),
            // `mnt-lower` is not allowed to appear in set objects in terms
            // of the definition in rfc2725.
            // however, for it to work correctly this must be allowed.
            // Also, it appears in `route-set` examples in rfc2725! FFS!
            MntLower (*),
        ],
    }
}

rpsl_object_class! {
    /// RPSL `rtr-set` object.
    ///
    /// Defined in [RFC2622]. Updated by [RFC4012].
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.5
    /// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-4.6
    RtrSet {
        class: "rtr-set",
        name: names::RtrSet,
        parser_rule: ParserRule::rtr_set_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            RtrSetMembers (*),
            RtrSetMpMembers (*),
            MbrsByRef (*),
            // `mnt-lower` is not allowed to appear in set objects in terms
            // of the definition in rfc2725.
            // however, for it to work correctly this must be allowed.
            // Also, it appears in `route-set` examples in rfc2725! FFS!
            MntLower (*),
        ],
    }
}

rpsl_object_class! {
    /// RPSL `peering-set` object.
    ///
    /// Defined in [RFC2622]. Updated by [RFC4012].
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-5.6
    /// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-4.4
    PeeringSet {
        class: "peering-set",
        name: names::PeeringSet,
        parser_rule: ParserRule::peering_set_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            // TODO: one of `peering` or `mp-peering` should be required during
            // validation.
            Peering (*),
            MpPeering (*),
            // `mnt-lower` is not allowed to appear in set objects in terms
            // of the definition in rfc2725.
            // however, for it to work correctly this must be allowed.
            // Also, it appears in `route-set` examples in rfc2725! FFS!
            MntLower (*),
        ],
    }
}

rpsl_object_class! {
    /// RPSL `inet-rtr` object.
    ///
    /// Defined in [RFC2622]. Updated by [RFC4012].
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-9
    /// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-4.5
    InetRtr {
        class: "inet-rtr",
        name: names::InetRtr,
        parser_rule: ParserRule::inet_rtr_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            Alias (*),
            LocalAs,
            Ifaddr (+),
            Interface (*),
            Peer (*),
            MpPeer (*),
            InetRtrMemberOf (*),
        ],
    }
}

rpsl_object_class! {
    /// RPSL `dictionary` object.
    ///
    /// Defined in [RFC2622].
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-10
    Dictionary {
        class: "dictionary",
        name: names::Dictionary,
        parser_rule: ParserRule::dictionary_obj,
        attributes: [
            // universal
            Descr (*),
            TechC (*),
            AdminC (*),
            Remarks (*),
            Notify (*),
            MntBy (+),
            Changed (+),
            Source,
            //
            // TODO
        ],
    }
}

#[cfg(test)]
mod tests;
