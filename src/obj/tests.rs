use super::*;

use crate::{
    attr::RpslAttribute,
    expr::{AsSetMember, AuthExpr, ChangedExpr, RtrSetMember},
    primitive::SigningMethod,
    tests::{compare_ast, display_fmt_parses},
};

display_fmt_parses! {
    RpslObject,
}

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
                        "128.9.0.0/16".parse().unwrap(),
                        "128.9.0.0/24".parse().unwrap(),
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
                        "128.7.0.0/16".parse().unwrap(),
                        "rs-foo".parse().unwrap(),
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
                        "5.0.0.0/8^+".parse().unwrap(),
                        "30.0.0.0/8^24-32".parse().unwrap(),
                        "rs-foo^+".parse().unwrap(),
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
                        "128.7.0.0/16".parse().unwrap(),
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
                        "128.9.0.0/16".parse().unwrap(),
                        "AS1".parse().unwrap(),
                        "AS2".parse().unwrap(),
                        "AS-FOO".parse().unwrap(),
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
        rfc2622_fig29_route_example1: "\
route:      128.8.0.0/15
origin:     AS1
components: <^AS2>
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
            RpslObject::Route(Route::new(
                "128.8.0.0/15".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS1".parse().unwrap()),
                    RpslAttribute::Components("<^AS2>".parse().unwrap()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_fig29_route_example2: "\
route:      128.8.0.0/15
origin:     AS1
components: protocol BGP4 {128.8.0.0/16^+}
            protocol OSPF {128.9.0.0/16^+}
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
            RpslObject::Route(Route::new(
                "128.8.0.0/15".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS1".parse().unwrap()),
                    RpslAttribute::Components("protocol BGP4 {128.8.0.0/16^+}\n protocol OSPF {128.9.0.0/16^+}".parse().unwrap()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_fig30_route_example1: "\
route:      128.8.0.0/15
origin:     AS1
components: {128.8.0.0/15^-}
aggr-bndry: AS1 OR AS2
aggr-mtd:   outbound AS-ANY
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
            RpslObject::Route(Route::new(
                "128.8.0.0/15".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS1".parse().unwrap()),
                    RpslAttribute::Components("{128.8.0.0/15^-}".parse().unwrap()),
                    RpslAttribute::AggrBndry("AS1 OR AS2".parse().unwrap()),
                    RpslAttribute::AggrMtd("outbound AS-ANY".parse().unwrap()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_fig31_route_example: "\
route:          128.8.0.0/15
origin:         AS1
components:     {128.8.0.0/15^-}
aggr-mtd:       outbound AS-ANY
export-comps:   {128.8.8.0/24}
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
            RpslObject::Route(Route::new(
                "128.8.0.0/15".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS1".parse().unwrap()),
                    RpslAttribute::Components("{128.8.0.0/15^-}".parse().unwrap()),
                    RpslAttribute::AggrMtd("outbound AS-ANY".parse().unwrap()),
                    RpslAttribute::ExportComps("{128.8.8.0/24}".parse().unwrap()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_fig32_route_example1: "\
route:      128.8.0.0/15
origin:     AS1
components: {128.8.0.0/15^-}
aggr-mtd:   outbound AS-ANY
inject:     at 1.1.1.1 action dpa = 100;
inject:     at 1.1.1.2 action dpa = 110;
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
            RpslObject::Route(Route::new(
                "128.8.0.0/15".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS1".parse().unwrap()),
                    RpslAttribute::Components("{128.8.0.0/15^-}".parse().unwrap()),
                    RpslAttribute::AggrMtd("outbound AS-ANY".parse().unwrap()),
                    RpslAttribute::Inject("at 1.1.1.1 action dpa = 100;".parse().unwrap()),
                    RpslAttribute::Inject("at 1.1.1.2 action dpa = 110;".parse().unwrap()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_fig32_route_example2: "\
route:      128.8.0.0/15
origin:     AS1
components: {128.8.0.0/15^-}
aggr-mtd:   outbound AS-ANY
inject:     upon HAVE-COMPONENTS {128.8.0.0/16, 128.9.0.0/16}
holes:      128.8.8.0/24
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
            RpslObject::Route(Route::new(
                "128.8.0.0/15".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS1".parse().unwrap()),
                    RpslAttribute::Components("{128.8.0.0/15^-}".parse().unwrap()),
                    RpslAttribute::AggrMtd("outbound AS-ANY".parse().unwrap()),
                    RpslAttribute::Inject("upon HAVE-COMPONENTS {128.8.0.0/16, 128.9.0.0/16}".parse().unwrap()),
                    RpslAttribute::Holes(vec!["128.8.8.0/24".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_fig33_route_example: "\
route:      128.8.0.0/15
origin:     AS1
aggr-bndry: AS1 or AS2 or AS3
aggr-mtd:   outbound AS3 or AS4 or AS5
components: {128.8.0.0/16, 128.9.0.0/16}
inject:     upon HAVE-COMPONENTS {128.9.0.0/16, 128.8.0.0/16}
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
            RpslObject::Route(Route::new(
                "128.8.0.0/15".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS1".parse().unwrap()),
                    RpslAttribute::AggrBndry("AS1 or AS2 or AS3".parse().unwrap()),
                    RpslAttribute::AggrMtd("outbound AS3 or AS4 or AS5".parse().unwrap()),
                    RpslAttribute::Components("{128.8.0.0/16, 128.9.0.0/16}".parse().unwrap()),
                    RpslAttribute::Inject("upon HAVE-COMPONENTS {128.9.0.0/16, 128.8.0.0/16}".parse().unwrap()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_fig34_route_example1: "\
route:      128.8.0.0/15
origin:     AS1
aggr-bndry: AS1 or AS2
aggr-mtd:   outbound
inject:     upon HAVE-COMPONENTS {128.8.0.0/16, 128.9.0.0/16}
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
            RpslObject::Route(Route::new(
                "128.8.0.0/15".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS1".parse().unwrap()),
                    RpslAttribute::AggrBndry("AS1 or AS2".parse().unwrap()),
                    RpslAttribute::AggrMtd("outbound".parse().unwrap()),
                    RpslAttribute::Inject("upon HAVE-COMPONENTS {128.8.0.0/16, 128.9.0.0/16}".parse().unwrap()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_fig34_route_example2: "\
route:          128.10.0.0/15
origin:         AS1
aggr-bndry:     AS1 or AS3
aggr-mtd:       outbound
inject:         upon HAVE-COMPONENTS {128.10.0.0/16, 128.11.0.0/16}
export-comps:   {128.11.0.0/16}
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
            RpslObject::Route(Route::new(
                "128.10.0.0/15".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS1".parse().unwrap()),
                    RpslAttribute::AggrBndry("AS1 or AS3".parse().unwrap()),
                    RpslAttribute::AggrMtd("outbound".parse().unwrap()),
                    RpslAttribute::Inject("upon HAVE-COMPONENTS {128.10.0.0/16, 128.11.0.0/16}".parse().unwrap()),
                    RpslAttribute::ExportComps("{128.11.0.0/16}".parse().unwrap()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_fig34_route_example3: "\
route:          128.8.0.0/14
origin:         AS1
aggr-bndry:     AS1 or AS2 or AS3
aggr-mtd:       outbound
inject:         upon HAVE-COMPONENTS {128.8.0.0/15, 128.10.0.0/15}
export-comps:   {128.10.0.0/15}
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
            RpslObject::Route(Route::new(
                "128.8.0.0/14".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS1".parse().unwrap()),
                    RpslAttribute::AggrBndry("AS1 or AS2 or AS3".parse().unwrap()),
                    RpslAttribute::AggrMtd("outbound".parse().unwrap()),
                    RpslAttribute::Inject("upon HAVE-COMPONENTS {128.8.0.0/15, 128.10.0.0/15}".parse().unwrap()),
                    RpslAttribute::ExportComps("{128.10.0.0/15}".parse().unwrap()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_sect8_2_route_example: "\
route:      128.7.0.0/16
origin:     AS1
inject:     at 7.7.7.1 action next-hop = 7.7.7.2; cost = 10; upon static
inject:     at 7.7.7.1 action next-hop = 7.7.7.3; cost = 20; upon static
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
            RpslObject::Route(Route::new(
                "128.7.0.0/16".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS1".parse().unwrap()),
                    RpslAttribute::Inject("at 7.7.7.1 action next-hop = 7.7.7.2; cost = 10; upon static".parse().unwrap()),
                    RpslAttribute::Inject("at 7.7.7.1 action next-hop = 7.7.7.3; cost = 20; upon static".parse().unwrap()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_fig36_inet_rtr_example: "\
inet-rtr:   Amsterdam.ripe.net
alias:      amsterdam1.ripe.net
local-as:   AS3333
ifaddr:     192.87.45.190 masklen 24
ifaddr:     192.87.4.28   masklen 24
ifaddr:     193.0.0.222   masklen 27
ifaddr:     193.0.0.158   masklen 27
peer:       BGP4 192.87.45.195 asno(AS3334), flap_damp()
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
            RpslObject::InetRtr(InetRtr::new(
                "Amsterdam.ripe.net".into(),
                vec![
                    RpslAttribute::Alias("amsterdam1.ripe.net".into()),
                    RpslAttribute::LocalAs("AS3333".parse().unwrap()),
                    RpslAttribute::Ifaddr("192.87.45.190 masklen 24".parse().unwrap()),
                    RpslAttribute::Ifaddr("192.87.4.28   masklen 24".parse().unwrap()),
                    RpslAttribute::Ifaddr("193.0.0.222   masklen 27".parse().unwrap()),
                    RpslAttribute::Ifaddr("193.0.0.158   masklen 27".parse().unwrap()),
                    RpslAttribute::Peer("BGP4 192.87.45.195 asno(AS3334), flap_damp()".parse().unwrap()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_fig37_rtr_set_example: "\
rtr-set:    rtrs-ibgp-peers
members:    1.1.1.1, 2.2.2.2, 3.3.3.3
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
            RpslObject::RtrSet(RtrSet::new(
                "rtrs-ibgp-peers".parse().unwrap(),
                vec![
                    RpslAttribute::RtrSetMembers(vec![
                        RtrSetMember::Addr("1.1.1.1".parse().unwrap()),
                        RtrSetMember::Addr("2.2.2.2".parse().unwrap()),
                        RtrSetMember::Addr("3.3.3.3".parse().unwrap()),
                    ].into_iter().collect()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_fig37_peering_set_example: "\
peering-set:    prng-ebgp-peers
peering:        AS3334 192.87.45.195
peering:        AS3335 192.87.45.196
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
            RpslObject::PeeringSet(PeeringSet::new(
                "prng-ebgp-peers".parse().unwrap(),
                vec![
                    RpslAttribute::Peering("AS3334 192.87.45.195".parse().unwrap()),
                    RpslAttribute::Peering("AS3335 192.87.45.196".parse().unwrap()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        rfc2622_fig37_inet_rtr_example: "\
inet-rtr:   Amsterdam.ripe.net
alias:      amsterdam1.ripe.net
local-as:   AS3333
ifaddr:     192.87.45.190 masklen 24
ifaddr:     192.87.4.28   masklen 24
ifaddr:     193.0.0.222   masklen 27
ifaddr:     193.0.0.158   masklen 27
peer:       BGP4 rtrs-ibgp-peers asno(AS3333), flap_damp()
peer:       BGP4 prng-ebgp-peers asno(PeerAS), flap_damp()
mnt-by:     RIPE-NCC-MNT
changed:    roderik@ripe.net 19970926
source:     RIPE" => {
            RpslObject::InetRtr(InetRtr::new(
                "Amsterdam.ripe.net".into(),
                vec![
                    RpslAttribute::Alias("amsterdam1.ripe.net".into()),
                    RpslAttribute::LocalAs("AS3333".parse().unwrap()),
                    RpslAttribute::Ifaddr("192.87.45.190 masklen 24".parse().unwrap()),
                    RpslAttribute::Ifaddr("192.87.4.28   masklen 24".parse().unwrap()),
                    RpslAttribute::Ifaddr("193.0.0.222   masklen 27".parse().unwrap()),
                    RpslAttribute::Ifaddr("193.0.0.158   masklen 27".parse().unwrap()),
                    RpslAttribute::Peer("BGP4 rtrs-ibgp-peers asno(AS3333), flap_damp()".parse().unwrap()),
                    RpslAttribute::Peer("BGP4 prng-ebgp-peers asno(PeerAS), flap_damp()".parse().unwrap()),
                    RpslAttribute::MntBy(vec!["RIPE-NCC-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "roderik@ripe.net".into(),
                        "19970926".parse().unwrap(),
                    )),
                    RpslAttribute::Source("RIPE".into()),
                ]
            ).unwrap())
        }
        // `referral` is mis-spelled in the original examples in rfc2725. LOL.
        rfc2725_mntner_example1: "\
mntner:         ROOT-MAINTAINER
auth:           pgpkey-12345678
mnt-by:         ROOT-MAINTAINER
referral-by:    ROOT-MAINTAINER
upd-to:         foo@example.net
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::Mntner(Mntner::new(
                "ROOT-MAINTAINER".parse().unwrap(),
                vec![
                    RpslAttribute::Auth(AuthExpr::KeyCert("pgpkey-12345678".parse().unwrap())),
                    RpslAttribute::MntBy(vec!["ROOT-MAINTAINER".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::ReferralBy("ROOT-MAINTAINER".parse().unwrap()),
                    RpslAttribute::UpdTo("foo@example.net".into()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        rfc2725_mntner_example2: "\
mntner:         WIZARDS
descr:          High level Technical Folks
auth:           pgpkey-23456789
auth:           pgpkey-3456789a
mnt-by:         WIZARDS
referral-by:    ROOT-MAINTAINER
upd-to:         foo@example.net
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::Mntner(Mntner::new(
                "WIZARDS".parse().unwrap(),
                vec![
                    RpslAttribute::Descr("High level Technical Folks".into()),
                    RpslAttribute::Auth(AuthExpr::KeyCert("pgpkey-23456789".parse().unwrap())),
                    RpslAttribute::Auth(AuthExpr::KeyCert("pgpkey-3456789a".parse().unwrap())),
                    RpslAttribute::MntBy(vec!["WIZARDS".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::ReferralBy("ROOT-MAINTAINER".parse().unwrap()),
                    RpslAttribute::UpdTo("foo@example.net".into()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        rfc2725_mntner_example3: "\
mntner:         MORTALS
descr:          Maintain day to day operations
auth:           pgpkey-456789ab
auth:           pgpkey-56789abc
auth:           pgpkey-6789abcd
mnt-by:         WIZARDS
referral-by:    WIZARDS
upd-to:         foo@example.net
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::Mntner(Mntner::new(
                "MORTALS".parse().unwrap(),
                vec![
                    RpslAttribute::Descr("Maintain day to day operations".into()),
                    RpslAttribute::Auth(AuthExpr::KeyCert("pgpkey-456789ab".parse().unwrap())),
                    RpslAttribute::Auth(AuthExpr::KeyCert("pgpkey-56789abc".parse().unwrap())),
                    RpslAttribute::Auth(AuthExpr::KeyCert("pgpkey-6789abcd".parse().unwrap())),
                    RpslAttribute::MntBy(vec!["WIZARDS".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::ReferralBy("WIZARDS".parse().unwrap()),
                    RpslAttribute::UpdTo("foo@example.net".into()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        rfc2725_as_block_example1: "\
as-block:       AS65500-AS65510
mnt-by:         SOME-REGISTRY
mnt-lower:      WIZARDS
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::AsBlock(AsBlock::new(
                "AS65500-AS65510".parse().unwrap(),
                vec![
                    RpslAttribute::MntBy(vec!["SOME-REGISTRY".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::MntLower(vec!["WIZARDS".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        rfc2725_aut_num_example1: "\
aut-num:        AS65501
as-name:        Example-AS
mnt-by:         WIZARDS
mnt-lower:      MORTALS
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::AutNum(AutNum::new(
                "AS65501".parse().unwrap(),
                vec![
                    RpslAttribute::AsName("Example-AS".into()),
                    RpslAttribute::MntBy(vec!["WIZARDS".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::MntLower(vec!["MORTALS".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        rfc2725_inetnum_example1: "\
inetnum:        192.168.144.0-192.168.151.255
netname:        Example-Net
mnt-by:         SOME-REGISTRY
mnt-lower:      ISP
reclaim:        ALL
country:        XX
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::InetNum(InetNum::new(
                "192.168.144.0-192.168.151.255".parse().unwrap(),
                vec![
                    RpslAttribute::Netname("Example-Net".into()),
                    RpslAttribute::MntBy(vec!["SOME-REGISTRY".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::MntLower(vec!["ISP".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Reclaim("ALL".parse().unwrap()),
                    RpslAttribute::Country("XX".into()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        rfc2725_inetnum_example2: "\
inetnum:        192.168.144.0-192.168.147.255
netname:        Example-Net
mnt-by:         ISP
mnt-lower:      EBG-COM
reclaim:        192.168.146/23+
country:        XX
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::InetNum(InetNum::new(
                "192.168.144.0-192.168.147.255".parse().unwrap(),
                vec![
                    RpslAttribute::Netname("Example-Net".into()),
                    RpslAttribute::MntBy(vec!["ISP".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::MntLower(vec!["EBG-COM".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Reclaim("192.168.146/23+".parse().unwrap()),
                    RpslAttribute::Country("XX".into()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        // the `mnt-routes` qualifier in the original example from rfc2725
        // contains an invalid ipv4-prefix "192.168.144".
        // This form is expressly prohibited by rfc2622 section 2.
        rfc2725_aut_num_example2: "\
aut-num:        AS65501
as-name:        Example-AS
mnt-by:         WIZARDS
mnt-lower:      MORTALS
mnt-routes:     EBG-COM {192.168.144.0/23}
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::AutNum(AutNum::new(
                "AS65501".parse().unwrap(),
                vec![
                    RpslAttribute::AsName("Example-AS".into()),
                    RpslAttribute::MntBy(vec!["WIZARDS".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::MntLower(vec!["MORTALS".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::MntRoutes("EBG-COM {192.168.144.0/23}".parse().unwrap()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        // the `mnt-routes` qualifier in the original example from rfc2725
        // contains an invalid ipv4-prefix "192.168.144".
        // This form is expressly prohibited by rfc2622 section 2.
        //
        // TODO: support for `SOURCE::OBJECT` name refs (RFC2725 sect 9.6)
        // mnt-by:         FICTION::MORTALS
        rfc2725_route_example1: "\
route:          192.168.144.0/24
origin:         AS65501
descr:          These boneheads don't aggregate
mnt-by:         EBG-COM
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::Route(Route::new(
                "192.168.144.0/24".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS65501".parse().unwrap()),
                    RpslAttribute::Descr("These boneheads don't aggregate".into()),
                    RpslAttribute::MntBy(vec!["EBG-COM".parse().unwrap()].into_iter().collect()),
                    // RpslAttribute::MntBy(vec!["FICTION::MORTALS".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        // The `route-set` name components in the original examples from rfc2725
        // are invalid, because they do not have the `RS-` prefix.
        rfc2725_route_set_example1: "\
route-set:      AS65501:RS-Customers
mnt-by:         WIZARDS
mnt-lower:      MORTALS
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::RouteSet(RouteSet::new(
                "AS65501:RS-Customers".parse().unwrap(),
                vec![
                    RpslAttribute::MntBy(vec!["WIZARDS".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::MntLower(vec!["MORTALS".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        rfc2725_route_set_example2: "\
route-set:      AS65501:RS-Customers:RS-EBG-COM
mnt-by:         MORTALS
mnt-lower:      EBG-COM
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::RouteSet(RouteSet::new(
                "AS65501:RS-Customers:RS-EBG-COM".parse().unwrap(),
                vec![
                    RpslAttribute::MntBy(vec!["MORTALS".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::MntLower(vec!["EBG-COM".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        rfc2725_mntner_example4: "\
mntner:         EBG-COM
mnt-by:         EBG-COM
auth-override:  19990401
auth:           PGPKEY-DEADBEEF
upd-to:         foo@example.net
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::Mntner(Mntner::new(
                "EBG-COM".parse().unwrap(),
                vec![
                    RpslAttribute::MntBy(vec!["EBG-COM".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::AuthOverride("19990401".parse().unwrap()),
                    RpslAttribute::Auth("PGPKEY-DEADBEEF".parse().unwrap()),
                    RpslAttribute::UpdTo("foo@example.net".into()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
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
        rfc4012_sect2_5_3_aut_num_example1: "\
aut-num:        AS65534
mp-import:      afi any.unicast from AS65001 accept as-foo;
                  except afi any.unicast {
                    from AS65002 accept AS65226;
                  } except afi ipv6.unicast {
                      from AS65003 accept {2001:0DB8::/32};
                    }
as-name:        Example-AS
mnt-by:         EXAMPLE-MNT
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::AutNum(AutNum::new(
                "AS65534".parse().unwrap(),
                vec![
                    RpslAttribute::MpImport("\
                        afi any.unicast from AS65001 accept as-foo;
                          except afi any.unicast {
                            from AS65002 accept AS65226;
                          } except afi ipv6.unicast {
                              from AS65003 accept {2001:0DB8::/32};
                            }".parse().unwrap()),
                    RpslAttribute::AsName("Example-AS".into()),
                    RpslAttribute::MntBy(vec!["EXAMPLE-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        rfc4012_sect2_5_3_aut_num_example2: "\
aut-num:        AS65002
mp-import:      afi ipv6.unicast from AS65001 accept {192.0.2.0/24}
as-name:        Example-AS
mnt-by:         EXAMPLE-MNT
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::AutNum(AutNum::new(
                "AS65002".parse().unwrap(),
                vec![
                    RpslAttribute::MpImport("afi ipv6.unicast from AS65001 accept {192.0.2.0/24}".parse().unwrap()),
                    RpslAttribute::AsName("Example-AS".into()),
                    RpslAttribute::MntBy(vec!["EXAMPLE-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        rfc4012_sect3_route6_example: "\
route6:     2001:0DB8::/32
origin:     AS65001
descr:      Example route6 object
mnt-by:     EXAMPLE-MNT
changed:    foo@example.net 20220224
source:     BAR" => {
            RpslObject::Route6(Route6::new(
                "2001:0DB8::/32".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS65001".parse().unwrap()),
                    RpslAttribute::Descr("Example route6 object".into()),
                    RpslAttribute::MntBy(vec!["EXAMPLE-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        rfc4012_sect4_2_route_set_example: "\
route-set:      rs-foo
mp-members:     rs-bar
mp-members:     2001:0DB8::/32  # v6 member
mp-members:     192.0.2.0/24   # v4 member
mnt-by:         EXAMPLE-MNT
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::RouteSet(RouteSet::new(
                "rs-foo".parse().unwrap(),
                vec![
                    RpslAttribute::RouteSetMpMembers(vec![
                        "rs-bar".parse().unwrap(),
                    ].into_iter().collect()),
                    RpslAttribute::RouteSetMpMembers(vec![
                        "2001:0DB8::/32".parse().unwrap(),
                    ].into_iter().collect()),
                    RpslAttribute::RouteSetMpMembers(vec![
                        "192.0.2.0/24".parse().unwrap(),
                    ].into_iter().collect()),
                    RpslAttribute::MntBy(vec!["EXAMPLE-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        rfc4012_sect4_4_peering_set_example: "\
peering-set:    prng-ebgp-peers
mp-peering:     AS65002 2001:0DB8::1 at 2001:0DB8::2
descr:          Example peering-set
tech-c:         RW488-RIPE
mnt-by:         RIPE-NCC-MNT
changed:        roderik@ripe.net 19970926
source:         RIPE" => {
            RpslObject::PeeringSet(PeeringSet::new(
                "prng-ebgp-peers".parse().unwrap(),
                vec![
                    RpslAttribute::MpPeering("AS65002 2001:0DB8::1 at 2001:0DB8::2".parse().unwrap()),
                    RpslAttribute::Descr("Example peering-set".into()),
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
        rfc4012_sect4_aut_num_example1: "\
aut-num:        AS65002
mnt-routes:     MAINT-AS65001 {2001:0DB8::/32^+, 192.0.2.0/24^+}
as-name:        Example-AS
mnt-by:         EXAMPLE-MNT
changed:        foo@example.net 20220224
source:         BAR" => {
            RpslObject::AutNum(AutNum::new(
                "AS65002".parse().unwrap(),
                vec![
                    RpslAttribute::MntRoutes("MAINT-AS65001 {2001:0DB8::/32^+, 192.0.2.0/24^+}".parse().unwrap()),
                    RpslAttribute::AsName("Example-AS".into()),
                    RpslAttribute::MntBy(vec!["EXAMPLE-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
        rfc5943_sect2_route6_example: "\
route6:     2001:DB8::/32
origin:     AS64500
pingable:   2001:DB8::DEAD:BEEF
ping-hdl:   OPS4-RIPE
mnt-by:     EXAMPLE-MNT
changed:    foo@example.net 20220224
source:     BAR" => {
            RpslObject::Route6(Route6::new(
                "2001:DB8::/32".parse().unwrap(),
                vec![
                    RpslAttribute::Origin("AS64500".parse().unwrap()),
                    RpslAttribute::Pingable6("2001:DB8::DEAD:BEEF".parse().unwrap()),
                    RpslAttribute::PingHdl("OPS4-RIPE".into()),
                    RpslAttribute::MntBy(vec!["EXAMPLE-MNT".parse().unwrap()].into_iter().collect()),
                    RpslAttribute::Changed(ChangedExpr::new(
                        "foo@example.net".into(),
                        "20220224".parse().unwrap(),
                    )),
                    RpslAttribute::Source("BAR".into()),
                ]
            ).unwrap())
        }
    }
}
