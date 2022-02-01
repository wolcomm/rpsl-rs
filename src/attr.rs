use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::iter::FromIterator;

use strum::EnumDiscriminants;

use crate::{
    error::{ParseError, ParseResult},
    expr::{AuthExpr, ChangedExpr, ImportExpr, MpImportExpr},
    list::ListOf,
    names,
    parser::{ParserRule, TokenPair},
    primitive::{
        Address, AsName, Certificate, CountryCode, EmailAddress, Fingerprint, KeyOwner, Netname,
        NicHdl, ObjectDescr, RegistryName, Remarks, SigningMethod, TelNumber, Trouble,
    },
};

#[derive(Clone, Debug, EnumDiscriminants, Hash, PartialEq, Eq)]
#[strum_discriminants(name(AttributeType))]
#[strum_discriminants(derive(Hash))]
pub enum RpslAttribute {
    // common attributes
    Descr(ObjectDescr),
    TechC(NicHdl),
    AdminC(NicHdl),
    Remarks(Remarks),
    Notify(EmailAddress),
    MntBy(ListOf<names::Mntner>),
    Changed(ChangedExpr),
    Source(RegistryName),
    // contact attributes
    NicHdl(NicHdl),
    Address(Address),
    Phone(TelNumber),
    FaxNo(TelNumber),
    EMail(EmailAddress),
    // common set attributes
    MbrsByRef(ListOf<names::Mntner>),
    // mntner attributes
    Auth(AuthExpr),
    UpdTo(EmailAddress),
    MntNfy(EmailAddress),
    // role attributes
    Trouble(Trouble),
    // key-cert attributes
    Method(SigningMethod),
    Owner(KeyOwner),
    Fingerpr(Fingerprint),
    Certif(Certificate),
    // aut-num attributes
    AsName(AsName),
    AutNumMemberOf(ListOf<names::AsSet>),
    Import(ImportExpr),
    MpImport(MpImportExpr),
    // TODO
    // Export(ExportExpr),
    // TODO
    // MpExport(MpExportExpr),
    // TODO
    // Default(DefaultExpr),
    // TODO
    // MpDefault(MpDefaultExpr),
    // TODO
    // inet(6)num attributes
    Netname(Netname),
    Country(CountryCode),
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
            // TODO
            // ParserRule::export_attr => Ok(Self::Export(
            //     next_into_or!(pair.into_inner() => "failed to get export expression")?,
            // )),
            // TODO
            // ParserRule::mp_export_attr => Ok(Self::MpExport(
            //     next_into_or!(pair.into_inner() => "failed to get mp-export expression")?,
            // )),
            // TODO
            // ParserRule::default_attr => Ok(Self::Default(
            //     next_into_or!(pair.into_inner() => "failed to get default expression")?,
            // )),
            // TODO
            // ParserRule::mp_default_attr => Ok(Self::MpDefault(
            //     next_into_or!(pair.into_inner() => "failed to get mp-default expression")?,
            // )),
            ParserRule::netname_attr => Ok(Self::Netname(
                next_into_or!(pair.into_inner() => "failed to get network name")?,
            )),
            ParserRule::country_attr => Ok(Self::Country(
                next_into_or!(pair.into_inner() => "failed to get country code")?,
            )),
            _ => Err(rule_mismatch!(pair => "attribute")),
        }
    }
}

impl fmt::Display for RpslAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Descr(inner) => write!(f, "descr: {}", inner),
            Self::TechC(inner) => write!(f, "tech-c: {}", inner),
            Self::AdminC(inner) => write!(f, "admin-c: {}", inner),
            Self::Remarks(inner) => write!(f, "remarks: {}", inner),
            Self::Notify(inner) => write!(f, "notify: {}", inner),
            Self::MntBy(inner) => write!(f, "mnt-by: {}", inner),
            Self::Changed(inner) => write!(f, "changed: {}", inner),
            Self::Source(inner) => write!(f, "source: {}", inner),
            Self::NicHdl(inner) => write!(f, "nic-hdl: {}", inner),
            Self::Address(inner) => write!(f, "address: {}", inner),
            Self::Phone(inner) => write!(f, "phone: {}", inner),
            Self::FaxNo(inner) => write!(f, "fax-no: {}", inner),
            Self::EMail(inner) => write!(f, "email: {}", inner),
            Self::MbrsByRef(inner) => write!(f, "mbrs-by-ref: {}", inner),
            Self::Auth(inner) => write!(f, "auth: {}", inner),
            Self::UpdTo(inner) => write!(f, "upd-to: {}", inner),
            Self::MntNfy(inner) => write!(f, "mnt-nfy: {}", inner),
            Self::Trouble(inner) => write!(f, "trouble: {}", inner),
            Self::Method(inner) => write!(f, "method: {}", inner),
            Self::Owner(inner) => write!(f, "owner: {}", inner),
            Self::Fingerpr(inner) => write!(f, "fingerpr: {}", inner),
            Self::Certif(inner) => write!(f, "certif: {}", inner),
            Self::AsName(inner) => write!(f, "as-name: {}", inner),
            Self::AutNumMemberOf(inner) => write!(f, "member-of: {}", inner),
            Self::Import(inner) => write!(f, "import: {}", inner),
            Self::MpImport(inner) => write!(f, "mp-import: {}", inner),
            // TODO
            // Self::Export(inner) => write!(f, "export: {}", inner),
            // TODO
            // Self::MpExport(inner) => write!(f, "mp-export: {}", inner),
            // TODO
            // Self::Default(inner) => write!(f, "default: {}", inner),
            // TODO
            // Self::MpDefault(inner) => write!(f, "mp-default: {}", inner),
            Self::Netname(inner) => write!(f, "netname: {}", inner),
            Self::Country(inner) => write!(f, "country: {}", inner),
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
