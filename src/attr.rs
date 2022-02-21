use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::iter::FromIterator;

use strum::EnumDiscriminants;

use crate::{
    addr_family::afi,
    error::{ParseError, ParseResult},
    expr::{
        AuthExpr, ChangedExpr, DefaultExpr, ExportExpr, FilterExpr, IfaddrExpr, ImportExpr,
        InterfaceExpr, MpDefaultExpr, MpExportExpr, MpImportExpr, MpPeerExpr, PeerExpr,
        PeeringExpr,
    },
    list::ListOf,
    members::{AsSetMember, RouteSetMember, RtrSetMember},
    names,
    parser::{ParserRule, TokenPair},
    primitive::{
        Address, AsName, Certificate, CountryCode, DnsName, EmailAddress, Fingerprint, KeyOwner,
        Netname, NicHdl, ObjectDescr, RegistryName, Remarks, SigningMethod, TelNumber, Trouble,
    },
};

#[derive(Clone, Debug, EnumDiscriminants, Hash, PartialEq, Eq)]
#[strum_discriminants(name(AttributeType))]
#[strum_discriminants(derive(Hash, strum::Display))]
pub enum RpslAttribute {
    // common attributes
    #[strum_discriminants(strum(to_string = "descr"))]
    Descr(ObjectDescr),
    #[strum_discriminants(strum(to_string = "tech-c"))]
    TechC(NicHdl),
    #[strum_discriminants(strum(to_string = "admin-c"))]
    AdminC(NicHdl),
    #[strum_discriminants(strum(to_string = "remarks"))]
    Remarks(Remarks),
    #[strum_discriminants(strum(to_string = "notify"))]
    Notify(EmailAddress),
    #[strum_discriminants(strum(to_string = "mnt-by"))]
    MntBy(ListOf<names::Mntner>),
    #[strum_discriminants(strum(to_string = "changed"))]
    Changed(ChangedExpr),
    #[strum_discriminants(strum(to_string = "source"))]
    Source(RegistryName),
    // contact attributes
    #[strum_discriminants(strum(to_string = "nic-hdl"))]
    NicHdl(NicHdl),
    #[strum_discriminants(strum(to_string = "address"))]
    Address(Address),
    #[strum_discriminants(strum(to_string = "phone"))]
    Phone(TelNumber),
    #[strum_discriminants(strum(to_string = "fax-no"))]
    FaxNo(TelNumber),
    #[strum_discriminants(strum(to_string = "e-mail"))]
    EMail(EmailAddress),
    // common set attributes
    #[strum_discriminants(strum(to_string = "mbrs-by-ref"))]
    MbrsByRef(ListOf<names::Mntner>),
    // mntner attributes
    #[strum_discriminants(strum(to_string = "auth"))]
    Auth(AuthExpr),
    #[strum_discriminants(strum(to_string = "upd-to"))]
    UpdTo(EmailAddress),
    #[strum_discriminants(strum(to_string = "mnt-nfy"))]
    MntNfy(EmailAddress),
    // role attributes
    #[strum_discriminants(strum(to_string = "trouble"))]
    Trouble(Trouble),
    // key-cert attributes
    #[strum_discriminants(strum(to_string = "method"))]
    Method(SigningMethod),
    #[strum_discriminants(strum(to_string = "owner"))]
    Owner(KeyOwner),
    #[strum_discriminants(strum(to_string = "fingerpr"))]
    Fingerpr(Fingerprint),
    #[strum_discriminants(strum(to_string = "certif"))]
    Certif(Certificate),
    // aut-num attributes
    #[strum_discriminants(strum(to_string = "as-name"))]
    AsName(AsName),
    #[strum_discriminants(strum(to_string = "member-of"))]
    AutNumMemberOf(ListOf<names::AsSet>),
    #[strum_discriminants(strum(to_string = "import"))]
    Import(ImportExpr),
    #[strum_discriminants(strum(to_string = "mp-import"))]
    MpImport(MpImportExpr),
    #[strum_discriminants(strum(to_string = "export"))]
    Export(ExportExpr),
    #[strum_discriminants(strum(to_string = "mp-export"))]
    MpExport(MpExportExpr),
    #[strum_discriminants(strum(to_string = "default"))]
    Default(DefaultExpr),
    #[strum_discriminants(strum(to_string = "mp-default"))]
    MpDefault(MpDefaultExpr),
    // inet(6)num attributes
    #[strum_discriminants(strum(to_string = "netname"))]
    Netname(Netname),
    #[strum_discriminants(strum(to_string = "country"))]
    Country(CountryCode),
    // route(6) attributes
    #[strum_discriminants(strum(to_string = "origin"))]
    Origin(names::AutNum),
    #[strum_discriminants(strum(to_string = "member-of"))]
    RouteMemberOf(ListOf<names::RouteSet>),
    // as-set attributes
    #[strum_discriminants(strum(to_string = "members"))]
    AsSetMembers(ListOf<AsSetMember>),
    // route-set attributes
    #[strum_discriminants(strum(to_string = "members"))]
    RouteSetMembers(ListOf<RouteSetMember<afi::Ipv4>>),
    #[strum_discriminants(strum(to_string = "mp-members"))]
    RouteSetMpMembers(ListOf<RouteSetMember<afi::Any>>),
    // filter-set attributes
    #[strum_discriminants(strum(to_string = "filter"))]
    Filter(FilterExpr),
    // rtr-set attributes
    #[strum_discriminants(strum(to_string = "members"))]
    RtrSetMembers(ListOf<RtrSetMember<afi::Ipv4>>),
    // peering-set attributes
    #[strum_discriminants(strum(to_string = "peering"))]
    Peering(PeeringExpr),
    // inet-rtr attributes
    #[strum_discriminants(strum(to_string = "alias"))]
    Alias(DnsName),
    #[strum_discriminants(strum(to_string = "local-as"))]
    LocalAs(names::AutNum),
    #[strum_discriminants(strum(to_string = "ifaddr"))]
    Ifaddr(IfaddrExpr),
    #[strum_discriminants(strum(to_string = "interface"))]
    Interface(InterfaceExpr),
    #[strum_discriminants(strum(to_string = "peer"))]
    Peer(PeerExpr),
    #[strum_discriminants(strum(to_string = "mp-peer"))]
    MpPeer(MpPeerExpr),
    #[strum_discriminants(strum(to_string = "member-of"))]
    InetRtrMemberOf(ListOf<names::RtrSet>),
}

impl TryFrom<TokenPair<'_>> for RpslAttribute {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => RpslAttribute);
        match pair.as_rule() {
            ParserRule::descr_attr => Ok(Self::Descr(
                next_into_or!(pair.into_inner() => "failed to get description")?,
            )),
            ParserRule::tech_c_attr => Ok(Self::TechC(
                next_into_or!(pair.into_inner() => "failed to get tech-c hdl")?,
            )),
            ParserRule::admin_c_attr => Ok(Self::AdminC(
                next_into_or!(pair.into_inner() => "failed to get admin-c hdl")?,
            )),
            ParserRule::remarks_attr => Ok(Self::Remarks(
                next_into_or!(pair.into_inner() => "failed to get remarks")?,
            )),
            ParserRule::notify_attr => Ok(Self::Notify(
                next_into_or!(pair.into_inner() => "failed to get notify address")?,
            )),
            ParserRule::mnt_by_attr => Ok(Self::MntBy(pair.try_into()?)),
            ParserRule::changed_attr => Ok(Self::Changed(
                next_into_or!(pair.into_inner() => "failed to get changed expression")?,
            )),
            ParserRule::source_attr => Ok(Self::Source(
                next_into_or!(pair.into_inner() => "failed to get source registry name")?,
            )),
            ParserRule::nic_hdl_attr => Ok(Self::NicHdl(
                next_into_or!(pair.into_inner() => "failed to get nic-hdl")?,
            )),
            ParserRule::address_attr => Ok(Self::Address(
                next_into_or!(pair.into_inner() => "failed to get address")?,
            )),
            ParserRule::phone_attr => Ok(Self::Phone(
                next_into_or!(pair.into_inner() => "failed to get phone number")?,
            )),
            ParserRule::fax_no_attr => Ok(Self::FaxNo(
                next_into_or!(pair.into_inner() => "failed to get fax number")?,
            )),
            ParserRule::e_mail_attr => Ok(Self::EMail(
                next_into_or!(pair.into_inner() => "failed to get email address")?,
            )),
            ParserRule::mbrs_by_ref_attr => Ok(Self::MbrsByRef(pair.try_into()?)),
            ParserRule::auth_attr => Ok(Self::Auth(
                next_into_or!(pair.into_inner() => "failed to get auth expression")?,
            )),
            ParserRule::upd_to_attr => Ok(Self::UpdTo(
                next_into_or!(pair.into_inner() => "failed to get upd-to address")?,
            )),
            ParserRule::mnt_nfy_attr => Ok(Self::MntNfy(
                next_into_or!(pair.into_inner() => "failed to get mnt-nfy address")?,
            )),
            ParserRule::trouble_attr => Ok(Self::Trouble(
                next_into_or!(pair.into_inner() => "failed to get trouble contact")?,
            )),
            ParserRule::method_attr => Ok(Self::Method(
                next_into_or!(pair.into_inner() => "failed to get signing method")?,
            )),
            ParserRule::owner_attr => Ok(Self::Owner(
                next_into_or!(pair.into_inner() => "failed to get key owner")?,
            )),
            ParserRule::fingerpr_attr => Ok(Self::Fingerpr(
                next_into_or!(pair.into_inner() => "failed to get key fingerprint")?,
            )),
            ParserRule::certif_attr => Ok(Self::Certif(
                next_into_or!(pair.into_inner() => "failed to get certificate")?,
            )),
            ParserRule::as_name_attr => Ok(Self::AsName(
                next_into_or!(pair.into_inner() => "failed to get AS name")?,
            )),
            ParserRule::aut_num_member_of_attr => Ok(Self::AutNumMemberOf(pair.try_into()?)),
            ParserRule::import_attr => Ok(Self::Import(
                next_into_or!(pair.into_inner() => "failed to get import expression")?,
            )),
            ParserRule::mp_import_attr => Ok(Self::MpImport(
                next_into_or!(pair.into_inner() => "failed to get mp-import expression")?,
            )),
            ParserRule::export_attr => Ok(Self::Export(
                next_into_or!(pair.into_inner() => "failed to get export expression")?,
            )),
            ParserRule::mp_export_attr => Ok(Self::MpExport(
                next_into_or!(pair.into_inner() => "failed to get mp-export expression")?,
            )),
            ParserRule::default_attr => Ok(Self::Default(
                next_into_or!(pair.into_inner() => "failed to get default expression")?,
            )),
            ParserRule::mp_default_attr => Ok(Self::MpDefault(
                next_into_or!(pair.into_inner() => "failed to get mp-default expression")?,
            )),
            ParserRule::netname_attr => Ok(Self::Netname(
                next_into_or!(pair.into_inner() => "failed to get network name")?,
            )),
            ParserRule::country_attr => Ok(Self::Country(
                next_into_or!(pair.into_inner() => "failed to get country code")?,
            )),
            ParserRule::origin_attr => Ok(Self::Origin(
                next_into_or!(pair.into_inner() => "failed to get origin")?,
            )),
            ParserRule::route_member_of_attr => Ok(Self::RouteMemberOf(pair.try_into()?)),
            ParserRule::as_set_members_attr => Ok(Self::AsSetMembers(pair.try_into()?)),
            ParserRule::route_set_members_attr => Ok(Self::RouteSetMembers(pair.try_into()?)),
            ParserRule::route_set_mp_members_attr => Ok(Self::RouteSetMpMembers(pair.try_into()?)),
            ParserRule::filter_attr => Ok(Self::Filter(
                next_into_or!(pair.into_inner() => "failed to get filter expression")?,
            )),
            ParserRule::rtr_set_members_attr => Ok(Self::RtrSetMembers(pair.try_into()?)),
            ParserRule::peering_attr => Ok(Self::Peering(
                next_into_or!(pair.into_inner() => "failed to get peering expression")?,
            )),
            ParserRule::alias_attr => Ok(Self::Alias(
                next_into_or!(pair.into_inner() => "failed to get alias name")?,
            )),
            ParserRule::local_as_attr => Ok(Self::LocalAs(
                next_into_or!(pair.into_inner() => "failed to get local-as")?,
            )),
            ParserRule::ifaddr_attr => Ok(Self::Ifaddr(
                next_into_or!(pair.into_inner() => "failed to get ifaddr expression")?,
            )),
            ParserRule::interface_attr => Ok(Self::Interface(
                next_into_or!(pair.into_inner() => "failed to get interface expression")?,
            )),
            ParserRule::peer_attr => Ok(Self::Peer(
                next_into_or!(pair.into_inner() => "failed to get peer expression")?,
            )),
            ParserRule::mp_peer_attr => Ok(Self::MpPeer(
                next_into_or!(pair.into_inner() => "failed to get mp-peer expression")?,
            )),
            ParserRule::inet_rtr_member_of_attr => Ok(Self::InetRtrMemberOf(pair.try_into()?)),
            _ => Err(rule_mismatch!(pair => "attribute")),
        }
    }
}

impl fmt::Display for RpslAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let attr_type: AttributeType = self.into();
        write!(f, "{}: ", attr_type)?;
        match self {
            Self::Descr(inner) => write!(f, "{}", inner),
            Self::TechC(inner) => write!(f, "{}", inner),
            Self::AdminC(inner) => write!(f, "{}", inner),
            Self::Remarks(inner) => write!(f, "{}", inner),
            Self::Notify(inner) => write!(f, "{}", inner),
            Self::MntBy(inner) => write!(f, "{}", inner),
            Self::Changed(inner) => write!(f, "{}", inner),
            Self::Source(inner) => write!(f, "{}", inner),
            Self::NicHdl(inner) => write!(f, "{}", inner),
            Self::Address(inner) => write!(f, "{}", inner),
            Self::Phone(inner) => write!(f, "{}", inner),
            Self::FaxNo(inner) => write!(f, "{}", inner),
            Self::EMail(inner) => write!(f, "{}", inner),
            Self::MbrsByRef(inner) => write!(f, "{}", inner),
            Self::Auth(inner) => write!(f, "{}", inner),
            Self::UpdTo(inner) => write!(f, "{}", inner),
            Self::MntNfy(inner) => write!(f, "{}", inner),
            Self::Trouble(inner) => write!(f, "{}", inner),
            Self::Method(inner) => write!(f, "{}", inner),
            Self::Owner(inner) => write!(f, "{}", inner),
            Self::Fingerpr(inner) => write!(f, "{}", inner),
            Self::Certif(inner) => write!(f, "{}", inner),
            Self::AsName(inner) => write!(f, "{}", inner),
            Self::AutNumMemberOf(inner) => write!(f, "{}", inner),
            Self::Import(inner) => write!(f, "{}", inner),
            Self::MpImport(inner) => write!(f, "{}", inner),
            Self::Export(inner) => write!(f, "{}", inner),
            Self::MpExport(inner) => write!(f, "{}", inner),
            Self::Default(inner) => write!(f, "{}", inner),
            Self::MpDefault(inner) => write!(f, "{}", inner),
            Self::Netname(inner) => write!(f, "{}", inner),
            Self::Country(inner) => write!(f, "{}", inner),
            Self::Origin(inner) => write!(f, "{}", inner),
            Self::RouteMemberOf(inner) => write!(f, "{}", inner),
            Self::AsSetMembers(inner) => write!(f, "{}", inner),
            Self::RouteSetMembers(inner) => write!(f, "{}", inner),
            Self::RouteSetMpMembers(inner) => write!(f, "{}", inner),
            Self::Filter(inner) => write!(f, "{}", inner),
            Self::RtrSetMembers(inner) => write!(f, "{}", inner),
            Self::Peering(inner) => write!(f, "{}", inner),
            Self::Alias(inner) => write!(f, "{}", inner),
            Self::LocalAs(inner) => write!(f, "{}", inner),
            Self::Ifaddr(inner) => write!(f, "{}", inner),
            Self::Interface(inner) => write!(f, "{}", inner),
            Self::Peer(inner) => write!(f, "{}", inner),
            Self::MpPeer(inner) => write!(f, "{}", inner),
            Self::InetRtrMemberOf(inner) => write!(f, "{}", inner),
        }
    }
}

// TODO: impl Arbitrary for RpslAttribute

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AttributeSeq(Vec<RpslAttribute>);

impl FromIterator<RpslAttribute> for AttributeSeq {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = RpslAttribute>,
    {
        Self(iter.into_iter().collect())
    }
}

impl<'a> IntoIterator for &'a AttributeSeq {
    type Item = &'a RpslAttribute;
    type IntoIter = std::slice::Iter<'a, RpslAttribute>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl fmt::Display for AttributeSeq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.iter().try_for_each(|attr| writeln!(f, "{}", attr))
    }
}

// TODO: impl Arbitrary for AttributeSeq
