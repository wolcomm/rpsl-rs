use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::{
    attr::{AttributeSeq, AttributeType, RpslAttribute},
    error::{ParseError, ParseResult, ValidationError, ValidationResult},
    names,
    parser::{ParserRule, TokenPair},
};

#[macro_use]
mod macros;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum RpslObject {
    Mntner(Mntner),
    Person(Person),
    Role(Role),
    KeyCert(KeyCert),
    AsBlock(AsBlock),
    AutNum(AutNum),
    InetNum(InetNum),
    Inet6Num(Inet6Num),
    Route(Route),
    Route6(Route6),
    AsSet(AsSet),
    RouteSet(RouteSet),
    FilterSet(FilterSet),
    RtrSet(RtrSet),
    PeeringSet(PeeringSet),
    InetRtr(InetRtr),
    Dictionary(Dictionary),
}

impl TryFrom<TokenPair<'_>> for RpslObject {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
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

struct AttributeRule {
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

trait RpslObjectClass: Sized {
    const CLASS: &'static str;
    const ATTRS: &'static [AttributeRule];
    type Name;

    fn new<I>(name: Self::Name, iter: I) -> ValidationResult<Self>
    where
        I: IntoIterator<Item = RpslAttribute>;

    fn name(&self) -> &Self::Name;

    fn attrs(&self) -> &AttributeSeq;

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
                    .then(|| ())
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
// we use the less restrictive version here.

rpsl_object_class! {
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
        ],
    }
}

rpsl_object_class! {
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
        ],
    }
}

rpsl_object_class! {
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
        ],
    }
}

rpsl_object_class! {
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
        ],
    }
}

rpsl_object_class! {
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
            Export (*),
            Default (*),
        ],
    }
}

// TODO: check whois.ripe.net template
rpsl_object_class! {
    InetNum {
        class: "inet-num",
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
        ],
    }
}

// TODO: check whois.ripe.net template
rpsl_object_class! {
    Inet6Num {
        class: "inet6-num",
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
        ],
    }
}

rpsl_object_class! {
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
            // TODO: rfc2622 section 8 "advanced attributes"
        ],
    }
}

rpsl_object_class! {
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
            // TODO
        ],
    }
}

rpsl_object_class! {
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
        ],
    }
}

rpsl_object_class! {
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
        ],
    }
}

rpsl_object_class! {
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
            Filter,
        ],
    }
}

rpsl_object_class! {
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
            MbrsByRef (*),
        ],
    }
}

rpsl_object_class! {
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
            Peering (+),
        ],
    }
}

rpsl_object_class! {
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
mod tests {
    use crate::{
        attr::RpslAttribute,
        expr::{AuthExpr, ChangedExpr},
        members::{AsSetMember, RouteSetMember, RouteSetMemberElem, RtrSetMember},
        primitive::{RangeOperator, SigningMethod},
    };

    use super::*;

    compare_ast! {
            RpslObject {
                rfc2622_fig2_mntner: "\
mntner:      RIPE-NCC-MNT
descr:       RIPE-NCC Maintainer
admin-c:     DK58
tech-c:      OPS4-RIPE
upd-to:      ops@ripe.net
mnt-nfy:     ops-fyi@ripe.net
auth:        CRYPT-PW lz1A7/JnfkTtI
mnt-by:      RIPE-NCC-MNT
changed:     ripe-dbm@ripe.net 19970820
source:      RIPE" => {
                    RpslObject::Mntner(Mntner::new(
                        "RIPE-NCC-MNT".parse().unwrap(),
                        vec![
                            RpslAttribute::Descr("RIPE-NCC Maintainer".into()),
                            RpslAttribute::AdminC("DK58".into()),
                            RpslAttribute::TechC("OPS4-RIPE".into()),
                            RpslAttribute::UpdTo("ops@ripe.net".into()),
                            RpslAttribute::MntNfy("ops-fyi@ripe.net".into()),
                            RpslAttribute::Auth(AuthExpr::Crypt("lz1A7/JnfkTtI".into())),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "ripe-dbm@ripe.net".into(),
                                "19970820".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                // The original in RFC2622 is missing `mnt-by`
                rfc2622_fig4_person: "\
person:      Daniel Karrenberg
address:     RIPE Network Coordination Centre (NCC)
address:     Singel 258
address:     NL-1016 AB  Amsterdam
address:     Netherlands
phone:       +31 20 535 4444
fax-no:      +31 20 535 4445
e-mail:      Daniel.Karrenberg@ripe.net
nic-hdl:     DK58
mnt-by:      RIPE-NCC-MNT
changed:     Daniel.Karrenberg@ripe.net 19970616
source:      RIPE" => {
                    RpslObject::Person(Person::new(
                        "Daniel Karrenberg".into(),
                        vec![
                            RpslAttribute::Address("RIPE Network Coordination Centre (NCC)".into()),
                            RpslAttribute::Address("Singel 258".into()),
                            RpslAttribute::Address("NL-1016 AB  Amsterdam".into()),
                            RpslAttribute::Address("Netherlands".into()),
                            RpslAttribute::Phone("+31 20 535 4444".into()),
                            RpslAttribute::FaxNo("+31 20 535 4445".into()),
                            RpslAttribute::EMail("Daniel.Karrenberg@ripe.net".into()),
                            RpslAttribute::NicHdl("DK58".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "Daniel.Karrenberg@ripe.net".into(),
                                "19970616".parse().unwrap()
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
                // The original in RFC2622 is missing `mnt-by`
                rfc2622_fig6_role: "\
role:        RIPE NCC Operations
trouble:
address:     Singel 258
address:     1016 AB Amsterdam
address:     The Netherlands
phone:       +31 20 535 4444
fax-no:      +31 20 545 4445
e-mail:      ops@ripe.net
admin-c:     CO19-RIPE
tech-c:      RW488-RIPE
tech-c:      JLSD1-RIPE
nic-hdl:     OPS4-RIPE
notify:      ops@ripe.net
mnt-by:      RIPE-NCC-MNT
changed:     roderik@ripe.net 19970926
source:      RIPE" => {
                    RpslObject::Role(Role::new(
                        "RIPE NCC Operations".into(),
                        vec![
                            RpslAttribute::Trouble("".into()),
                            RpslAttribute::Address("Singel 258".into()),
                            RpslAttribute::Address("1016 AB Amsterdam".into()),
                            RpslAttribute::Address("The Netherlands".into()),
                            RpslAttribute::Phone("+31 20 535 4444".into()),
                            RpslAttribute::FaxNo("+31 20 545 4445".into()),
                            RpslAttribute::EMail("ops@ripe.net".into()),
                            RpslAttribute::AdminC("CO19-RIPE".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::TechC("JLSD1-RIPE".into()),
                            RpslAttribute::NicHdl("OPS4-RIPE".into()),
                            RpslAttribute::Notify("ops@ripe.net".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
                rfc2622_fig8_route_example1: "\
route:      128.9.0.0/16
origin:     AS226
descr:      Example route object
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::Route(Route::new(
                        "128.9.0.0/16".parse().unwrap(),
                        vec![
                            RpslAttribute::Origin("AS226".parse().unwrap()),
                            RpslAttribute::Descr("Example route object".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
                rfc2622_fig8_route_example2: "\
route:      128.99.0.0/16
origin:     AS226
descr:      Example route object
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::Route(Route::new(
                        "128.99.0.0/16".parse().unwrap(),
                        vec![
                            RpslAttribute::Origin("AS226".parse().unwrap()),
                            RpslAttribute::Descr("Example route object".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
                rfc2622_fig8_route_example3: "\
route:      128.8.0.0/16
origin:     AS1
descr:      Example route object
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::Route(Route::new(
                        "128.8.0.0/16".parse().unwrap(),
                        vec![
                            RpslAttribute::Origin("AS1".parse().unwrap()),
                            RpslAttribute::Descr("Example route object".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
                rfc2622_fig8_route_example4: "\
route:      128.8.0.0/16
origin:     AS2
descr:      Example route object
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::Route(Route::new(
                        "128.8.0.0/16".parse().unwrap(),
                        vec![
                            RpslAttribute::Origin("AS2".parse().unwrap()),
                            RpslAttribute::Descr("Example route object".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
                rfc2622_fig10_as_set_example1: "\
as-set:     as-foo
members:    AS1, AS2
descr:      Example as-set
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::AsSet(AsSet::new(
                        "as-foo".parse().unwrap(),
                        vec![
                            RpslAttribute::AsSetMembers(vec![
                                AsSetMember::AutNum("AS1".parse().unwrap()),
                                AsSetMember::AutNum("AS2".parse().unwrap()),
                            ].into_iter().collect()),
                            RpslAttribute::Descr("Example as-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig10_as_set_example2: "\
as-set:     as-bar
members:    AS3, as-foo
descr:      Example as-set
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::AsSet(AsSet::new(
                        "as-bar".parse().unwrap(),
                        vec![
                            RpslAttribute::AsSetMembers(vec![
                                AsSetMember::AutNum("AS3".parse().unwrap()),
                                AsSetMember::AsSet("as-foo".parse().unwrap()),
                            ].into_iter().collect()),
                            RpslAttribute::Descr("Example as-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig10_as_set_example3: "\
as-set:     as-empty
descr:      Example as-set
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::AsSet(AsSet::new(
                        "as-empty".parse().unwrap(),
                        vec![
                            RpslAttribute::Descr("Example as-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig11_as_set_example: "\
as-set:         as-foo
members:        AS1, AS2
mbrs-by-ref:    MNTR-ME
descr:          Example as-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::AsSet(AsSet::new(
                        "as-foo".parse().unwrap(),
                        vec![
                            RpslAttribute::AsSetMembers(vec![
                                AsSetMember::AutNum("AS1".parse().unwrap()),
                                AsSetMember::AutNum("AS2".parse().unwrap()),
                            ].into_iter().collect()),
                            RpslAttribute::MbrsByRef(vec!["MNTR-ME".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Descr("Example as-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig13_route_set_example1: "\
route-set:      rs-foo
members:        128.9.0.0/16, 128.9.0.0/24
descr:          Example route-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::RouteSet(RouteSet::new(
                        "rs-foo".parse().unwrap(),
                        vec![
                            RpslAttribute::RouteSetMembers(vec![
                                RouteSetMember::new(
                                    RouteSetMemberElem::Prefix("128.9.0.0/16".parse().unwrap()),
                                    RangeOperator::None,
                                ),
                                RouteSetMember::new(
                                    RouteSetMemberElem::Prefix("128.9.0.0/24".parse().unwrap()),
                                    RangeOperator::None,
                                ),
                            ].into_iter().collect()),
                            RpslAttribute::Descr("Example route-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig13_route_set_example2: "\
route-set:      rs-bar
members:        128.7.0.0/16, rs-foo
descr:          Example route-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::RouteSet(RouteSet::new(
                        "rs-bar".parse().unwrap(),
                        vec![
                            RpslAttribute::RouteSetMembers(vec![
                                RouteSetMember::new(
                                    RouteSetMemberElem::Prefix("128.7.0.0/16".parse().unwrap()),
                                    RangeOperator::None,
                                ),
                                RouteSetMember::new(
                                    RouteSetMemberElem::RouteSet("rs-foo".parse().unwrap()),
                                    RangeOperator::None,
                                ),
                            ].into_iter().collect()),
                            RpslAttribute::Descr("Example route-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig13_route_set_example3: "\
route-set:      rs-bar
members:        5.0.0.0/8^+, 30.0.0.0/8^24-32, rs-foo^+
descr:          Example route-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::RouteSet(RouteSet::new(
                        "rs-bar".parse().unwrap(),
                        vec![
                            RpslAttribute::RouteSetMembers(vec![
                                RouteSetMember::new(
                                    RouteSetMemberElem::Prefix("5.0.0.0/8".parse().unwrap()),
                                    RangeOperator::LessIncl,
                                ),
                                RouteSetMember::new(
                                    RouteSetMemberElem::Prefix("30.0.0.0/8".parse().unwrap()),
                                    RangeOperator::Range(24, 32),
                                ),
                                RouteSetMember::new(
                                    RouteSetMemberElem::RouteSet("rs-foo".parse().unwrap()),
                                    RangeOperator::LessIncl,
                                ),
                            ].into_iter().collect()),
                            RpslAttribute::Descr("Example route-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig14_route_set_example1: "\
route-set:      rs-foo
mbrs-by-ref:    MNTR-ME, MNTR-YOU
descr:          Example route-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::RouteSet(RouteSet::new(
                        "rs-foo".parse().unwrap(),
                        vec![
                            RpslAttribute::MbrsByRef(vec![
                                "MNTR-ME".parse().unwrap(),
                                "MNTR-YOU".parse().unwrap(),
                            ].into_iter().collect()),
                            RpslAttribute::Descr("Example route-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig14_route_set_example2: "\
route-set:      rs-bar
members:        128.7.0.0/16
mbrs-by-ref:    MNTR-YOU
descr:          Example route-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::RouteSet(RouteSet::new(
                        "rs-bar".parse().unwrap(),
                        vec![
                            RpslAttribute::RouteSetMembers(vec![
                                RouteSetMember::new(
                                    RouteSetMemberElem::Prefix("128.7.0.0/16".parse().unwrap()),
                                    RangeOperator::None,
                                ),
                            ].into_iter().collect()),
                            RpslAttribute::MbrsByRef(vec![
                                "MNTR-YOU".parse().unwrap(),
                            ].into_iter().collect()),
                            RpslAttribute::Descr("Example route-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig14_route_example1: "\
route:      128.9.0.0/16
origin:     AS1
member-of:  rs-foo
descr:      Example route object
tech-c:     RW488-RIPE
mnt-by:     MNTR-ME
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::Route(Route::new(
                        "128.9.0.0/16".parse().unwrap(),
                        vec![
                            RpslAttribute::Origin("AS1".parse().unwrap()),
                            RpslAttribute::RouteMemberOf(vec!["rs-foo".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Descr("Example route object".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["MNTR-ME".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig14_route_example2: "\
route:      128.8.0.0/16
origin:     AS2
member-of:  rs-foo, rs-bar
descr:      Example route object
tech-c:     RW488-RIPE
mnt-by:     MNTR-YOU
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::Route(Route::new(
                        "128.8.0.0/16".parse().unwrap(),
                        vec![
                            RpslAttribute::Origin("AS2".parse().unwrap()),
                            RpslAttribute::RouteMemberOf(vec![
                                "rs-foo".parse().unwrap(),
                                "rs-bar".parse().unwrap(),
                            ].into_iter().collect()),
                            RpslAttribute::Descr("Example route object".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["MNTR-YOU".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig15_route_set_example: "\
route-set:      rs-special
members:        128.9.0.0/16, AS1, AS2, AS-FOO
descr:          Example route-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::RouteSet(RouteSet::new(
                        "rs-special".parse().unwrap(),
                        vec![
                            RpslAttribute::RouteSetMembers(vec![
                                RouteSetMember::new(
                                    RouteSetMemberElem::Prefix("128.9.0.0/16".parse().unwrap()),
                                    RangeOperator::None,
                                ),
                                RouteSetMember::new(
                                    RouteSetMemberElem::AutNum("AS1".parse().unwrap()),
                                    RangeOperator::None,
                                ),
                                RouteSetMember::new(
                                    RouteSetMemberElem::AutNum("AS2".parse().unwrap()),
                                    RangeOperator::None,
                                ),
                                RouteSetMember::new(
                                    RouteSetMemberElem::AsSet("AS-FOO".parse().unwrap()),
                                    RangeOperator::None,
                                ),
                            ].into_iter().collect()),
                            RpslAttribute::Descr("Example route-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig17_filter_set_example1: "\
filter-set:     fltr-foo
filter:         { 5.0.0.0/8, 6.0.0.0/8 }
descr:          Example filter-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::FilterSet(FilterSet::new(
                        "fltr-foo".parse().unwrap(),
                        vec![
                            RpslAttribute::Filter("{ 5.0.0.0/8, 6.0.0.0/8 }".parse().unwrap()),
                            RpslAttribute::Descr("Example filter-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig17_filter_set_example2: "\
filter-set:     fltr-bar
filter:         (AS1 or fltr-foo) and <AS2>
descr:          Example filter-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::FilterSet(FilterSet::new(
                        "fltr-bar".parse().unwrap(),
                        vec![
                            RpslAttribute::Filter("(AS1 or fltr-foo) and <AS2>".parse().unwrap()),
                            RpslAttribute::Descr("Example filter-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig19_rtr_set_example1: "\
rtr-set:        rtrs-foo
members:        rtr1.isp.net, rtr2.isp.net
descr:          Example rtr-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::RtrSet(RtrSet::new(
                        "rtrs-foo".parse().unwrap(),
                        vec![
                            RpslAttribute::RtrSetMembers(vec![
                                RtrSetMember::InetRtr("rtr1.isp.net".into()),
                                RtrSetMember::InetRtr("rtr2.isp.net".into()),
                            ].into_iter().collect()),
                            RpslAttribute::Descr("Example rtr-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig19_rtr_set_example2: "\
rtr-set:        rtrs-bar
members:        rtr3.isp.net, rtrs-foo
descr:          Example rtr-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::RtrSet(RtrSet::new(
                        "rtrs-bar".parse().unwrap(),
                        vec![
                            RpslAttribute::RtrSetMembers(vec![
                                RtrSetMember::InetRtr("rtr3.isp.net".into()),
                                RtrSetMember::RtrSet("rtrs-foo".parse().unwrap()),
                            ].into_iter().collect()),
                            RpslAttribute::Descr("Example rtr-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig20_rtr_set_example: "\
rtr-set:        rtrs-foo
members:        rtr1.isp.net, rtr2.isp.net
mbrs-by-ref:    MNTR-ME
descr:          Example rtr-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::RtrSet(RtrSet::new(
                        "rtrs-foo".parse().unwrap(),
                        vec![
                            RpslAttribute::RtrSetMembers(vec![
                                RtrSetMember::InetRtr("rtr1.isp.net".into()),
                                RtrSetMember::InetRtr("rtr2.isp.net".into()),
                            ].into_iter().collect()),
                            RpslAttribute::MbrsByRef(vec!["MNTR-ME".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Descr("Example rtr-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_fig20_inet_rtr_example: "\
inet-rtr:       rtr3.isp.net
local-as:       as1
ifaddr:         1.1.1.1 masklen 30
member-of:      rtrs-foo
mnt-by:         MNTR-ME
descr:          Example inet-rtr
tech-c:         RW488-RIPE
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::InetRtr(InetRtr::new(
                        "rtr3.isp.net".into(),
                        vec![
                            RpslAttribute::LocalAs("as1".parse().unwrap()),
                            RpslAttribute::Ifaddr("1.1.1.1 masklen 30".parse().unwrap()),
                            RpslAttribute::InetRtrMemberOf(vec!["rtrs-foo".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::MntBy(vec!["MNTR-ME".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Descr("Example inet-rtr".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_sect5_6_autnum_example1: "\
aut-num:    AS1
import:     from AS2 7.7.7.2 at 7.7.7.1 accept { 128.9.0.0/16 }
as-name:    Example-AS
descr:      Example aut-num
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::AutNum(AutNum::new(
                        "AS1".parse().unwrap(),
                        vec![
                            RpslAttribute::Import("from AS2 7.7.7.2 at 7.7.7.1 accept { 128.9.0.0/16 }".parse().unwrap()),
                            RpslAttribute::AsName("Example-AS".into()),
                            RpslAttribute::Descr("example aut-num".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_sect5_6_autnum_example2: "\
aut-num:    AS1
import:     from AS2 at 7.7.7.1 accept { 128.9.0.0/16 }
as-name:    Example-AS
descr:      Example aut-num
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::AutNum(AutNum::new(
                        "AS1".parse().unwrap(),
                        vec![
                            RpslAttribute::Import("from AS2 at 7.7.7.1 accept { 128.9.0.0/16 }".parse().unwrap()),
                            RpslAttribute::AsName("Example-AS".into()),
                            RpslAttribute::Descr("example aut-num".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_sect5_6_autnum_example3: "\
aut-num:    AS1
import:     from AS2 accept { 128.9.0.0/16 }
as-name:    Example-AS
descr:      Example aut-num
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::AutNum(AutNum::new(
                        "AS1".parse().unwrap(),
                        vec![
                            RpslAttribute::Import("from AS2 accept { 128.9.0.0/16 }".parse().unwrap()),
                            RpslAttribute::AsName("Example-AS".into()),
                            RpslAttribute::Descr("example aut-num".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_sect5_6_as_set_example4: "\
as-set:     AS-FOO
members:    AS2, AS3
descr:      Example as-set
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::AsSet(AsSet::new(
                        "AS-FOO".parse().unwrap(),
                        vec![
                            RpslAttribute::AsSetMembers(vec![
                                AsSetMember::AutNum("AS2".parse().unwrap()),
                                AsSetMember::AutNum("AS3".parse().unwrap()),
                            ].into_iter().collect()),
                            RpslAttribute::Descr("Example as-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_sect5_6_autnum_example4: "\
aut-num:    AS1
import:     from AS-FOO at 9.9.9.1 accept { 128.9.0.0/16 }
as-name:    Example-AS
descr:      Example aut-num
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::AutNum(AutNum::new(
                        "AS1".parse().unwrap(),
                        vec![
                            RpslAttribute::Import("from AS-FOO at 9.9.9.1 accept { 128.9.0.0/16 }".parse().unwrap()),
                            RpslAttribute::AsName("Example-AS".into()),
                            RpslAttribute::Descr("example aut-num".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_sect5_6_autnum_example5: "\
aut-num:    AS1
import:     from AS-FOO accept { 128.9.0.0/16 }
as-name:    Example-AS
descr:      Example aut-num
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::AutNum(AutNum::new(
                        "AS1".parse().unwrap(),
                        vec![
                            RpslAttribute::Import("from AS-FOO accept { 128.9.0.0/16 }".parse().unwrap()),
                            RpslAttribute::AsName("Example-AS".into()),
                            RpslAttribute::Descr("example aut-num".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                // the 'NOT' operator is invalid for rtr expressions.
                // accordingly, the following example taken from rfc2622
                // section 5.6 is invalid:
                //
                // rfc2622_sect5_6_autnum_example6: "\
    // aut-num:    AS1
    // import:     from AS-FOO and not AS2 at not 7.7.7.1
                // accept { 128.9.0.0/16 }
    // as-name:    Example-AS
    // descr:      Example aut-num
    // tech-c:     RW488-RIPE
    // mnt-by:     RIPE-NCC-MNT
    // changed:    roderik@ripe.net 19970926
    // source:     RIPE" => {
                //     RpslObject::AutNum(AutNum::new(
                //         "AS1".parse().unwrap(),
                //         vec![
                //             RpslAttribute::Import("from AS-FOO and not AS2 at not 7.7.7.1 accept { 128.9.0.0/16 }".parse().unwrap()),
                //             RpslAttribute::AsName("Example-AS".into()),
                //             RpslAttribute::Descr("example aut-num".into()),
                //             RpslAttribute::TechC("RW488-RIPE".into()),
                //             RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                //             RpslAttribute::Changed(ChangedExpr::new(
                //                 "roderik@ripe.net".into(),
                //                 "19970926".parse().unwrap(),
                //             )),
                //             RpslAttribute::Source("RIPE".into()),
                //         ],
                //     ).unwrap())
                // }
                rfc2622_sect5_6_peering_set_example7_1: "\
peering-set:    prng-bar
peering:        AS1 at 9.9.9.1
descr:          Example peering-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::PeeringSet(PeeringSet::new(
                        "prng-bar".parse().unwrap(),
                        vec![
                            RpslAttribute::Peering("AS1 at 9.9.9.1".parse().unwrap()),
                            RpslAttribute::Descr("example peering-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_sect5_6_peering_set_example7_2: "\
peering-set:    prng-foo
peering:        prng-bar
peering:        AS2 at 9.9.9.1
descr:          Example peering-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
                    RpslObject::PeeringSet(PeeringSet::new(
                        "prng-foo".parse().unwrap(),
                        vec![
                            RpslAttribute::Peering("prng-bar".parse().unwrap()),
                            RpslAttribute::Peering("AS2 at 9.9.9.1".parse().unwrap()),
                            RpslAttribute::Descr("example peering-set".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_sect5_6_autnum_example7: "\
aut-num:    AS1
import:     from prng-foo accept { 128.9.0.0/16 }
as-name:    Example-AS
descr:      Example aut-num
tech-c:     RW488-RIPE
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
                    RpslObject::AutNum(AutNum::new(
                        "AS1".parse().unwrap(),
                        vec![
                            RpslAttribute::Import("from prng-foo accept { 128.9.0.0/16 }".parse().unwrap()),
                            RpslAttribute::AsName("Example-AS".into()),
                            RpslAttribute::Descr("example aut-num".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ],
                    ).unwrap())
                }
                rfc2622_sect6_autnum_example0: "\
aut-num:     AS1
as-name:     Example-AS
descr:       Example aut-num from RFC2622
import:      from AS2 accept AS2
admin-c:     CO19-RIPE
tech-c:      RW488-RIPE
mnt-by:      RIPE-NCC-MNT
changed:     roderik@ripe.net 19970926
source:      RIPE" => {
                    RpslObject::AutNum(AutNum::new(
                        "AS1".parse().unwrap(),
                        vec![
                            RpslAttribute::AsName("Example-AS".into()),
                            RpslAttribute::Descr("Example aut-num from RFC2622".into()),
                            RpslAttribute::Import("from AS2 accept AS2".parse().unwrap()),
                            RpslAttribute::AdminC("CO19-RIPE".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
                rfc2622_sect6_autnum_example1: "\
aut-num:     AS1
as-name:     Example-AS
descr:       Example aut-num from RFC2622
import:      from AS2 action pref = 1; accept { 128.9.0.0/16 }
admin-c:     CO19-RIPE
tech-c:      RW488-RIPE
mnt-by:      RIPE-NCC-MNT
changed:     roderik@ripe.net 19970926
source:      RIPE" => {
                    RpslObject::AutNum(AutNum::new(
                        "AS1".parse().unwrap(),
                        vec![
                            RpslAttribute::AsName("Example-AS".into()),
                            RpslAttribute::Descr("Example aut-num from RFC2622".into()),
                            RpslAttribute::Import("from AS2 action pref = 1; accept { 128.9.0.0/16 }".parse().unwrap()),
                            RpslAttribute::AdminC("CO19-RIPE".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
                rfc2622_sect6_autnum_example2: "\
aut-num:     AS1
as-name:     Example-AS
descr:       Example aut-num from RFC2622
import:      from AS2
             action pref = 10; med = 0; community.append(10250, 3561:10);
             accept { 128.9.0.0/16 }
admin-c:     CO19-RIPE
tech-c:      RW488-RIPE
mnt-by:      RIPE-NCC-MNT
changed:     roderik@ripe.net 19970926
source:      RIPE" => {
                    RpslObject::AutNum(AutNum::new(
                        "AS1".parse().unwrap(),
                        vec![
                            RpslAttribute::AsName("Example-AS".into()),
                            RpslAttribute::Descr("Example aut-num from RFC2622".into()),
                            RpslAttribute::Import(
                                "from AS2 \
                                 action pref = 10; \
                                 med = 0; \
                                 community.append(10250, 3561:10); \
                                 accept { 128.9.0.0/16 }".parse().unwrap()),
                            RpslAttribute::AdminC("CO19-RIPE".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
                rfc2622_sect6_autnum_example3: "\
aut-num:     AS1
as-name:     Example-AS
descr:       Example aut-num from RFC2622
import:      from AS2 7.7.7.2 at 7.7.7.1 action pref = 1;
             from AS2                    action pref = 2;
             accept AS4
admin-c:     CO19-RIPE
tech-c:      RW488-RIPE
mnt-by:      RIPE-NCC-MNT
changed:     roderik@ripe.net 19970926
source:      RIPE" => {
                    RpslObject::AutNum(AutNum::new(
                        "AS1".parse().unwrap(),
                        vec![
                            RpslAttribute::AsName("Example-AS".into()),
                            RpslAttribute::Descr("Example aut-num from RFC2622".into()),
                            RpslAttribute::Import(
                                "from AS2 7.7.7.2 at 7.7.7.1 action pref = 1; \
                             from AS2 action pref = 2;
                             accept AS4".parse().unwrap()),
                            RpslAttribute::AdminC("CO19-RIPE".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
                rfc2622_sect6_autnum_example4: "\
aut-num:     AS1
as-name:     Example-AS
descr:       Example aut-num from RFC2622
export:      to AS2 action med = 5; community .= { 70 };
             announce AS4
admin-c:     CO19-RIPE
tech-c:      RW488-RIPE
mnt-by:      RIPE-NCC-MNT
changed:     roderik@ripe.net 19970926
source:      RIPE" => {
                    RpslObject::AutNum(AutNum::new(
                        "AS1".parse().unwrap(),
                        vec![
                            RpslAttribute::AsName("Example-AS".into()),
                            RpslAttribute::Descr("Example aut-num from RFC2622".into()),
                            RpslAttribute::Export(
                                "to AS2 action med = 5; community .= { 70 };
                                 announce AS4".parse().unwrap()
                            ),
                            RpslAttribute::AdminC("CO19-RIPE".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
                rfc2622_sect6_autnum_example5: "\
aut-num:     AS1
as-name:     Example-AS
descr:       Example aut-num from RFC2622
import:      from AS2 accept AS2^+
export:      protocol BGP4 into OSPF
             to AS1 announce AS2
admin-c:     CO19-RIPE
tech-c:      RW488-RIPE
mnt-by:      RIPE-NCC-MNT
changed:     roderik@ripe.net 19970926
source:      RIPE" => {
                    RpslObject::AutNum(AutNum::new(
                        "AS1".parse().unwrap(),
                        vec![
                            RpslAttribute::AsName("Example-AS".into()),
                            RpslAttribute::Descr("Example aut-num from RFC2622".into()),
                            RpslAttribute::Import(
                                "from AS2 accept AS2^+".parse().unwrap()
                            ),
                            RpslAttribute::Export(
                                "protocol BGP4 into OSPF
                                 to AS1 announce AS2".parse().unwrap()
                            ),
                            RpslAttribute::AdminC("CO19-RIPE".into()),
                            RpslAttribute::TechC("RW488-RIPE".into()),
                            RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "roderik@ripe.net".into(),
                                "19970926".parse().unwrap(),
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
                rfc2726_sect6_mntner: "\
mntner:      AS3244-MNT
descr:       BankNet, Budapest HU
descr:       Eastern European Internet Provider via own VSAT network
admin-c:     JZ38
tech-c:      JZ38
tech-c:      IR2-RIPE
upd-to:      ncc@banknet.net
mnt-nfy:     ncc@banknet.net
auth:        PGPKEY-23F5CE35
remarks:     This is the maintainer of all BankNet related objects
notify:      ncc@banknet.net
mnt-by:      AS3244-MNT
changed:     zsako@banknet.net 19980525
source:      RIPE" => {
                    RpslObject::Mntner(Mntner::new(
                        "AS3244-MNT".into(),
                        vec![
                            RpslAttribute::Descr("BankNet, Budapest HU".into()),
                            RpslAttribute::Descr("Eastern European Internet Provider via own VSAT network".into()),
                            RpslAttribute::AdminC("JZ38".into()),
                            RpslAttribute::TechC("JZ38".into()),
                            RpslAttribute::TechC("IR2-RIPE".into()),
                            RpslAttribute::UpdTo("ncc@banknet.net".into()),
                            RpslAttribute::MntNfy("ncc@banknet.net".into()),
                            RpslAttribute::Auth(AuthExpr::KeyCert(names::KeyCert::Pgp("PGPKEY-23F5CE35".into()))),
                            RpslAttribute::Remarks("This is the maintainer of all BankNet related objects".into()),
                            RpslAttribute::Notify("ncc@banknet.net".into()),
                            RpslAttribute::MntBy(vec!["AS3244-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "zsako@banknet.net".into(),
                                "19980525".parse().unwrap()
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
                rfc2726_sect6_key_cert: "\
key-cert: PGPKEY-23F5CE35
method:   PGP
owner:    Janos Zsako <zsako@banknet.net>
fingerpr: B5 D0 96 D0 D0 D3 2B B2  B8 C2 5D 22 D4 F5 78 92
certif: -----BEGIN PGP PUBLIC KEY BLOCK-----
 Version: 2.6.2i
+
 mQCNAzCqKdIAAAEEAPMSQtBNFFuTS0duoUiqnPHm05dxrI76rrOGwx+OU5tzGavx
 cm2iCInNtikeKjlIMD7FiCH1J8PWdZivpwhzuGeeMimT8ZmNn4z3bb6ELRyiZOvs
 4nfxVlh+kKKD9JjBfy8DnuMs5sT0jw4FEt/PYogJinFdndzywXHzGHEj9c41AAUR
 tB9KYW5vcyBac2FrbyA8enNha29AYmFua25ldC5uZXQ+iQCVAwUQMjkx2XHzGHEj
 9c41AQEuagP/dCIBJP+R16Y70yH75kraRzXY5rnsHmT0Jknrc/ihEEviRYdMV7X1
 osP4pmDU8tNGf0OfGrok7KDTCmygIh7/me+PKrDIj0YkAVUhBX3gBtpSkhEmkLqf
 xbhYwDn4DV3zF7f5AMsbD0UCBDyf+vpkMzgd1Pbr439iXdgwgwta50qJAHUDBRAy
 OSsrO413La462EEBAdIuAv4+Cao1wqBG7+gIm1czIb1M2cAM7Ussx6y+oL1d+HqN
 PRhx4upLVg8Eqm1w4BYpOxdZKkxumIrIvrSxUYv4NBnbwQaa0/NmBou44jqeN+y2
 xwxAEVd9BCUtT+YJ9iMzZlE=
 =w8xL
 -----END PGP PUBLIC KEY BLOCK-----
remarks: This is an example of PGP key certificate
mnt-by:  AS3244-MNT
changed: zsako@banknet.net 19980525
source:  RIPE" => {
                    RpslObject::KeyCert(KeyCert::new(
                        names::KeyCert::Pgp("PGPKEY-23F5CE35".into()),
                        vec![
                            RpslAttribute::Method(SigningMethod::Pgp),
                            RpslAttribute::Owner("Janos Zsako <zsako@banknet.net>".into()),
                            RpslAttribute::Fingerpr("B5 D0 96 D0 D0 D3 2B B2  B8 C2 5D 22 D4 F5 78 92".into()),
                            RpslAttribute::Certif("\
-----BEGIN PGP PUBLIC KEY BLOCK-----
 Version: 2.6.2i
+
 mQCNAzCqKdIAAAEEAPMSQtBNFFuTS0duoUiqnPHm05dxrI76rrOGwx+OU5tzGavx
 cm2iCInNtikeKjlIMD7FiCH1J8PWdZivpwhzuGeeMimT8ZmNn4z3bb6ELRyiZOvs
 4nfxVlh+kKKD9JjBfy8DnuMs5sT0jw4FEt/PYogJinFdndzywXHzGHEj9c41AAUR
 tB9KYW5vcyBac2FrbyA8enNha29AYmFua25ldC5uZXQ+iQCVAwUQMjkx2XHzGHEj
 9c41AQEuagP/dCIBJP+R16Y70yH75kraRzXY5rnsHmT0Jknrc/ihEEviRYdMV7X1
 osP4pmDU8tNGf0OfGrok7KDTCmygIh7/me+PKrDIj0YkAVUhBX3gBtpSkhEmkLqf
 xbhYwDn4DV3zF7f5AMsbD0UCBDyf+vpkMzgd1Pbr439iXdgwgwta50qJAHUDBRAy
 OSsrO413La462EEBAdIuAv4+Cao1wqBG7+gIm1czIb1M2cAM7Ussx6y+oL1d+HqN
 PRhx4upLVg8Eqm1w4BYpOxdZKkxumIrIvrSxUYv4NBnbwQaa0/NmBou44jqeN+y2
 xwxAEVd9BCUtT+YJ9iMzZlE=
 =w8xL
 -----END PGP PUBLIC KEY BLOCK-----".into()),
                            RpslAttribute::Remarks("This is an example of PGP key certificate".into()),
                            RpslAttribute::MntBy(vec!["AS3244-MNT".parse().unwrap()].into_iter().collect()),
                            RpslAttribute::Changed(ChangedExpr::new(
                                "zsako@banknet.net".into(),
                                "19980525".parse().unwrap()
                            )),
                            RpslAttribute::Source("RIPE".into()),
                        ]
                    ).unwrap())
                }
            }
        }
}
