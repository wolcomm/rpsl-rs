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

use self::{
    misc::{Dictionary, InetRtr},
    route::{Route, Route6},
    set::{AsSet, FilterSet, PeeringSet, RouteSet, RtrSet},
};

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
            // TODO
            ParserRule::route_obj
            | ParserRule::route6_obj
            | ParserRule::as_set_obj
            | ParserRule::route_set_obj
            | ParserRule::filter_set_obj
            | ParserRule::rtr_set_obj
            | ParserRule::peering_set_obj
            | ParserRule::inet_rtr_obj
            | ParserRule::dictionary_obj => {
                unimplemented!()
            }
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

rpsl_object_class! {
    Mntner {
        class: "mntner",
        name: names::Mntner,
        parser_rule: ParserRule::mntner_obj,
        attributes: [
            Descr,
            TechC (+),
            MntBy (+),
            Changed (+),
            Source,
            Auth (+),
            UpdTo (+),
        ],
    }
}

rpsl_object_class! {
    Person {
        class: "person",
        name: names::Person,
        parser_rule: ParserRule::person_obj,
        attributes: [
            MntBy (+),
            Changed (+),
            Source,
            NicHdl,
            Address (+),
            Phone (+),
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
            MntBy (+),
            Changed (+),
            Source,
            NicHdl,
            Address (+),
            Phone (+),
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
            MntBy (+),
            Changed (+),
            Source,
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
            AdminC (+),
            TechC (+),
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
            AsName,
            Descr,
            AdminC (+),
            TechC (+),
            MntBy (+),
            Changed (+),
            Source,
        ],
    }
}

rpsl_object_class! {
    InetNum {
        class: "inet-num",
        name: names::InetNum,
        parser_rule: ParserRule::inetnum_obj,
        attributes: [
            Netname,
            Descr (*),
            Country (+),
            AdminC (+),
            TechC (+),
            // TODO
            // Status,
            MntBy (+),
            Changed (+),
            Source,
        ],
    }
}

rpsl_object_class! {
    Inet6Num {
        class: "inet6-num",
        name: names::Inet6Num,
        parser_rule: ParserRule::inet6num_obj,
        attributes: [
            Netname,
            Descr (*),
            Country (+),
            AdminC (+),
            TechC (+),
            // TODO
            // Status,
            MntBy (+),
            Changed (+),
            Source,
        ],
    }
}

pub mod misc;
pub mod route;
pub mod set;

#[cfg(test)]
mod tests {
    use crate::{
        attr::RpslAttribute,
        expr::{AuthExpr, ChangedExpr},
        primitive::SigningMethod,
    };

    use super::*;

    compare_ast! {
        RpslObject {
            rfc2622_fig2_mntner: "\
            mntner:      RIPE-NCC-MNT\n\
            descr:       RIPE-NCC Maintainer\n\
            admin-c:     DK58\n\
            tech-c:      OPS4-RIPE\n\
            upd-to:      ops@ripe.net\n\
            mnt-nfy:     ops-fyi@ripe.net\n\
            auth:        CRYPT-PW lz1A7/JnfkTtI\n\
            mnt-by:      RIPE-NCC-MNT\n\
            changed:     ripe-dbm@ripe.net 19970820\n\
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
            person:      Daniel Karrenberg\n\
            address:     RIPE Network Coordination Centre (NCC)\n\
            address:     Singel 258\n\
            address:     NL-1016 AB  Amsterdam\n\
            address:     Netherlands\n\
            phone:       +31 20 535 4444\n\
            fax-no:      +31 20 535 4445\n\
            e-mail:      Daniel.Karrenberg@ripe.net\n\
            nic-hdl:     DK58\n\
            mnt-by:      RIPE-NCC-MNT\n\
            changed:     Daniel.Karrenberg@ripe.net 19970616\n\
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
            role:        RIPE NCC Operations\n\
            trouble:\n\
            address:     Singel 258\n\
            address:     1016 AB Amsterdam\n\
            address:     The Netherlands\n\
            phone:       +31 20 535 4444\n\
            fax-no:      +31 20 545 4445\n\
            e-mail:      ops@ripe.net\n\
            admin-c:     CO19-RIPE\n\
            tech-c:      RW488-RIPE\n\
            tech-c:      JLSD1-RIPE\n\
            nic-hdl:     OPS4-RIPE\n\
            notify:      ops@ripe.net\n\
            mnt-by:      RIPE-NCC-MNT\n\
            changed:     roderik@ripe.net 19970926\n\
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
            rfc2726_sect6_mntner: "\
            mntner:      AS3244-MNT\n\
            descr:       BankNet, Budapest HU\n\
            descr:       Eastern European Internet Provider via own VSAT network\n\
            admin-c:     JZ38\n\
            tech-c:      JZ38\n\
            tech-c:      IR2-RIPE\n\
            upd-to:      ncc@banknet.net\n\
            mnt-nfy:     ncc@banknet.net\n\
            auth:        PGPKEY-23F5CE35\n\
            remarks:     This is the maintainer of all BankNet related objects\n\
            notify:      ncc@banknet.net\n\
            mnt-by:      AS3244-MNT\n\
            changed:     zsako@banknet.net 19980525\n\
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
            rfc2622_sect6_autnum_example0: "\
            aut-num:     AS1\n\
            as-name:     Example-AS\n\
            descr:       Example aut-num from RFC2622\n\
            import:      from AS2 accept AS2\n\
            admin-c:     CO19-RIPE\n\
            tech-c:      RW488-RIPE\n\
            mnt-by:      RIPE-NCC-MNT\n\
            changed:     roderik@ripe.net 19970926\n\
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
            aut-num:     AS1\n\
            as-name:     Example-AS\n\
            descr:       Example aut-num from RFC2622\n\
            import:      from AS2 action pref = 1; accept { 128.9.0.0/16 }\n\
            admin-c:     CO19-RIPE\n\
            tech-c:      RW488-RIPE\n\
            mnt-by:      RIPE-NCC-MNT\n\
            changed:     roderik@ripe.net 19970926\n\
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
        }
    }
}
