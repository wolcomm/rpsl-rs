use std::fmt;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net, PrefixLenError};

use crate::parser::ParserRule;

/// IP address family trait.
pub trait Afi
where
    Self: fmt::Display,
    Self::Addr: FromStr<Err = std::net::AddrParseError>
        + Clone
        + Copy
        + fmt::Debug
        + fmt::Display
        + Hash
        + PartialEq
        + Eq,
    Self::Net: FromStr<Err = ipnet::AddrParseError>
        + Clone
        + Copy
        + fmt::Debug
        + fmt::Display
        + Hash
        + PartialEq
        + Eq,
{
    /// Address family IP address type.
    type Addr;
    /// Address family IP prefix type.
    type Net;
    /// Address family specific [`ParserRule`] for IP address literals.
    const LITERAL_ADDR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for IP prefix literals.
    const LITERAL_PREFIX_RULE: ParserRule;
    /// Get the maximum prefix length for IP address `addr`.
    fn max_len(addr: &Self::Addr) -> u8;
    /// Construct a [`Self::Net`] from `addr` and `len`.
    fn addr_to_net(addr: Self::Addr, len: u8) -> Self::Net;
    /// Check that `len` is a valid prefix length for address `addr`.
    fn check_addr_len(addr: Self::Addr, len: u8) -> Result<(), PrefixLenError>;
}

/// Trait describing parser variations per RPSL `afi`.
pub trait LiteralPrefixSetAfi: Afi {
    /// Address family specific [`ParserRule`] for IP prefix set literals.
    const LITERAL_PREFIX_SET_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for ranged IP prefix set literals.
    const LITERAL_RANGED_PREFIX_SET_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for literal filter terms.
    const LITERAL_FILTER_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for named filter terms.
    const NAMED_FILTER_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for unit filter expressions.
    const FILTER_EXPR_UNIT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for negated filter expressions.
    const FILTER_EXPR_NOT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for conjunctive filter expressions.
    const FILTER_EXPR_AND_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for disjunctive filter expressions.
    const FILTER_EXPR_OR_RULE: ParserRule;
    /// Array of address family specific [`ParserRule`] for filter expressions.
    const FILTER_EXPR_RULES: [ParserRule; 4] = [
        Self::FILTER_EXPR_UNIT_RULE,
        Self::FILTER_EXPR_NOT_RULE,
        Self::FILTER_EXPR_AND_RULE,
        Self::FILTER_EXPR_OR_RULE,
    ];
    /// Check whether a [`ParserRule`] variant is a `filter` expression for
    /// this address family.
    fn match_filter_expr_rule(rule: ParserRule) -> bool {
        Self::FILTER_EXPR_RULES
            .iter()
            .any(|filter_expr_rule| &rule == filter_expr_rule)
    }

    /// Address family specific [`ParserRule`] for router IP address literals.
    const RTR_ADDR_LITERAL_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for unit router expressions.
    const RTR_EXPR_UNIT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for unit router expressions.
    const RTR_EXPR_AND_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for conjunctive router expressions.
    const RTR_EXPR_OR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for exclusive router expressions.
    const RTR_EXPR_EXCEPT_RULE: ParserRule;
    /// Array of address family specific [`ParserRule`] for router expressions.
    const RTR_EXPR_RULES: [ParserRule; 4] = [
        Self::RTR_EXPR_UNIT_RULE,
        Self::RTR_EXPR_AND_RULE,
        Self::RTR_EXPR_OR_RULE,
        Self::RTR_EXPR_EXCEPT_RULE,
    ];
    /// Check whether a [`ParserRule`] variant is a `router` expression for
    /// this address family.
    fn match_rtr_expr_rule(rule: ParserRule) -> bool {
        Self::RTR_EXPR_RULES
            .iter()
            .any(|rtr_expr_rule| &rule == rtr_expr_rule)
    }

    /// Address family specific [`ParserRule`] for remote router expressions.
    const REMOTE_RTR_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for local router expressions.
    const LOCAL_RTR_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for literal peering expressions.
    const PEERING_EXPR_LITERAL_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for named peering expressions.
    const PEERING_EXPR_NAMED_RULE: ParserRule;
    /// Array of address family specific [`ParserRule`] for peering expressions.
    const PEERING_EXPR_RULES: [ParserRule; 2] = [
        Self::PEERING_EXPR_NAMED_RULE,
        Self::PEERING_EXPR_LITERAL_RULE,
    ];
    /// Check whether a [`ParserRule`] variant is a `peering` expression for
    /// this address family.
    fn match_peering_expr_rule(rule: ParserRule) -> bool {
        Self::PEERING_EXPR_RULES
            .iter()
            .any(|peering_expr_rule| &rule == peering_expr_rule)
    }

    /// Address family specific [`ParserRule`] for inject expressions.
    const INJECT_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for unit inject expressions.
    const INJECT_COND_UNIT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for conjunctive inject expressions.
    const INJECT_COND_AND_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for disjunctive inject expressions.
    const INJECT_COND_OR_RULE: ParserRule;
    /// Array of address family specific [`ParserRule`] for inject expressions.
    const INJECT_COND_RULES: [ParserRule; 3] = [
        Self::INJECT_COND_UNIT_RULE,
        Self::INJECT_COND_AND_RULE,
        Self::INJECT_COND_OR_RULE,
    ];
    /// Check whether a [`ParserRule`] variant is an `inject` expression for
    /// this address family.
    fn match_inject_condition_rule(rule: ParserRule) -> bool {
        Self::INJECT_COND_RULES
            .iter()
            .any(|inject_cond_rule| &rule == inject_cond_rule)
    }
    /// Address family specific [`ParserRule`] for inject `have-components`
    /// condition term.
    const INJECT_COND_TERM_HAVE_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for inject `exclude` condition
    /// term.
    const INJECT_COND_TERM_EXCLUDE_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for inject `static` condition
    /// term.
    const INJECT_COND_TERM_STATIC_RULE: ParserRule;

    /// Address family specific [`ParserRule`] for components expressions.
    const COMPONENTS_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for components protocol terms.
    const COMPONENTS_PROTO_TERMS_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for components protocol term.
    const COMPONENTS_PROTO_TERM_RULE: ParserRule;

    /// Address family specific [`ParserRule`] for peer expressions.
    const PEER_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for peer specifications.
    const PEER_SPEC_RULE: ParserRule;

    /// Address family specific [`ParserRule`] for `default` expressions.
    const DEFAULT_EXPR_RULE: ParserRule;

    /// Address family specific [`ParserRule`] for `import` factors.
    const IMPORT_FACTOR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `import` terms.
    const IMPORT_TERM_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for unit `import` expressions.
    const IMPORT_EXPR_UNIT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `EXCEPT` `import` expressions.
    const IMPORT_EXPR_EXCEPT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `REFINE` `import` expressions.
    const IMPORT_EXPR_REFINE_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `import` afi-expressions.
    const IMPORT_AFI_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `import` statements.
    const IMPORT_STMT_RULE: ParserRule;

    /// Address family specific [`ParserRule`] for `export` factors.
    const EXPORT_FACTOR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `export` terms.
    const EXPORT_TERM_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for unit `export` expressions.
    const EXPORT_EXPR_UNIT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `EXCEPT` `export` expressions.
    const EXPORT_EXPR_EXCEPT_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `REFINE` `export` expressions.
    const EXPORT_EXPR_REFINE_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `export` afi-expressions.
    const EXPORT_AFI_EXPR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for `export` statements.
    const EXPORT_STMT_RULE: ParserRule;

    /// Address family specific [`ParserRule`] for `route-set` member items.
    const ROUTE_SET_MEMBER_RULE: ParserRule;
}

/// Concrete address family definitions.
pub mod afi {
    use super::*;

    /// RPSL `ipv4` address family.
    #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
    pub struct Ipv4;

    impl Afi for Ipv4 {
        type Addr = Ipv4Addr;
        type Net = Ipv4Net;

        const LITERAL_ADDR_RULE: ParserRule = ParserRule::ipv4_addr;
        const LITERAL_PREFIX_RULE: ParserRule = ParserRule::ipv4_prefix;

        fn max_len(_: &Self::Addr) -> u8 {
            32
        }

        fn addr_to_net(addr: Self::Addr, len: u8) -> Self::Net {
            Self::Net::new(addr, len).unwrap().trunc()
        }

        fn check_addr_len(addr: Self::Addr, len: u8) -> Result<(), PrefixLenError> {
            Self::Net::new(addr, len)?;
            Ok(())
        }
    }

    impl LiteralPrefixSetAfi for Ipv4 {
        const LITERAL_PREFIX_SET_RULE: ParserRule = ParserRule::literal_prefix_set;
        const LITERAL_RANGED_PREFIX_SET_RULE: ParserRule = ParserRule::ranged_prefix_set;
        const LITERAL_FILTER_RULE: ParserRule = ParserRule::literal_filter;
        const NAMED_FILTER_RULE: ParserRule = ParserRule::named_filter;
        const FILTER_EXPR_UNIT_RULE: ParserRule = ParserRule::filter_expr_unit;
        const FILTER_EXPR_NOT_RULE: ParserRule = ParserRule::filter_expr_not;
        const FILTER_EXPR_AND_RULE: ParserRule = ParserRule::filter_expr_and;
        const FILTER_EXPR_OR_RULE: ParserRule = ParserRule::filter_expr_or;

        const RTR_ADDR_LITERAL_RULE: ParserRule = ParserRule::rtr_addr_literal;
        const RTR_EXPR_UNIT_RULE: ParserRule = ParserRule::rtr_expr_unit;
        const RTR_EXPR_AND_RULE: ParserRule = ParserRule::rtr_expr_and;
        const RTR_EXPR_OR_RULE: ParserRule = ParserRule::rtr_expr_or;
        const RTR_EXPR_EXCEPT_RULE: ParserRule = ParserRule::rtr_expr_except;

        const REMOTE_RTR_EXPR_RULE: ParserRule = ParserRule::remote_rtr_expr;
        const LOCAL_RTR_EXPR_RULE: ParserRule = ParserRule::local_rtr_expr;
        const PEERING_EXPR_LITERAL_RULE: ParserRule = ParserRule::peering_expr_literal;
        const PEERING_EXPR_NAMED_RULE: ParserRule = ParserRule::peering_expr_named;

        const INJECT_EXPR_RULE: ParserRule = ParserRule::inject_expr;
        const INJECT_COND_UNIT_RULE: ParserRule = ParserRule::inject_cond_unit;
        const INJECT_COND_AND_RULE: ParserRule = ParserRule::inject_cond_and;
        const INJECT_COND_OR_RULE: ParserRule = ParserRule::inject_cond_or;
        const INJECT_COND_TERM_HAVE_RULE: ParserRule = ParserRule::inject_cond_term_have;
        const INJECT_COND_TERM_EXCLUDE_RULE: ParserRule = ParserRule::inject_cond_term_excl;
        const INJECT_COND_TERM_STATIC_RULE: ParserRule = ParserRule::inject_cond_term_stat;

        const COMPONENTS_EXPR_RULE: ParserRule = ParserRule::components_expr;
        const COMPONENTS_PROTO_TERMS_RULE: ParserRule = ParserRule::components_proto_terms;
        const COMPONENTS_PROTO_TERM_RULE: ParserRule = ParserRule::components_proto_term;

        const PEER_EXPR_RULE: ParserRule = ParserRule::peer_expr;
        const PEER_SPEC_RULE: ParserRule = ParserRule::peer_spec;

        const DEFAULT_EXPR_RULE: ParserRule = ParserRule::default_expr;

        const IMPORT_FACTOR_RULE: ParserRule = ParserRule::import_factor;
        const IMPORT_TERM_RULE: ParserRule = ParserRule::import_term;
        const IMPORT_EXPR_UNIT_RULE: ParserRule = ParserRule::import_expr_unit;
        const IMPORT_EXPR_EXCEPT_RULE: ParserRule = ParserRule::import_expr_except;
        const IMPORT_EXPR_REFINE_RULE: ParserRule = ParserRule::import_expr_refine;
        const IMPORT_AFI_EXPR_RULE: ParserRule = ParserRule::import_afi_expr;
        const IMPORT_STMT_RULE: ParserRule = ParserRule::import_stmt;

        const EXPORT_FACTOR_RULE: ParserRule = ParserRule::export_factor;
        const EXPORT_TERM_RULE: ParserRule = ParserRule::export_term;
        const EXPORT_EXPR_UNIT_RULE: ParserRule = ParserRule::export_expr_unit;
        const EXPORT_EXPR_EXCEPT_RULE: ParserRule = ParserRule::export_expr_except;
        const EXPORT_EXPR_REFINE_RULE: ParserRule = ParserRule::export_expr_refine;
        const EXPORT_AFI_EXPR_RULE: ParserRule = ParserRule::export_afi_expr;
        const EXPORT_STMT_RULE: ParserRule = ParserRule::export_stmt;

        const ROUTE_SET_MEMBER_RULE: ParserRule = ParserRule::route_set_member_choice;
    }

    impl fmt::Display for Ipv4 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "ipv4")
        }
    }

    /// RPSL `ipv6` address family.
    #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
    pub struct Ipv6;

    impl Afi for Ipv6 {
        type Addr = Ipv6Addr;
        type Net = Ipv6Net;

        const LITERAL_ADDR_RULE: ParserRule = ParserRule::ipv6_addr;
        const LITERAL_PREFIX_RULE: ParserRule = ParserRule::ipv6_prefix;

        fn max_len(_: &Self::Addr) -> u8 {
            128
        }

        fn addr_to_net(addr: Self::Addr, len: u8) -> Self::Net {
            Self::Net::new(addr, len).unwrap().trunc()
        }

        fn check_addr_len(addr: Self::Addr, len: u8) -> Result<(), PrefixLenError> {
            Self::Net::new(addr, len)?;
            Ok(())
        }
    }

    impl fmt::Display for Ipv6 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "ipv6")
        }
    }

    /// RPSL `any` pseudo address family.
    #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
    pub struct Any;

    impl Afi for Any {
        type Addr = IpAddr;
        type Net = IpNet;

        const LITERAL_ADDR_RULE: ParserRule = ParserRule::ip_addr_choice;
        const LITERAL_PREFIX_RULE: ParserRule = ParserRule::ip_prefix_choice;

        fn max_len(addr: &Self::Addr) -> u8 {
            match addr {
                Self::Addr::V4(_) => 32,
                Self::Addr::V6(_) => 128,
            }
        }

        fn addr_to_net(addr: Self::Addr, len: u8) -> Self::Net {
            match addr {
                Self::Addr::V4(addr) => Ipv4Net::new(addr, len).unwrap().trunc().into(),
                Self::Addr::V6(addr) => Ipv6Net::new(addr, len).unwrap().trunc().into(),
            }
        }

        fn check_addr_len(addr: Self::Addr, len: u8) -> Result<(), PrefixLenError> {
            match addr {
                Self::Addr::V4(addr) => {
                    Ipv4Net::new(addr, len)?;
                }
                Self::Addr::V6(addr) => {
                    Ipv6Net::new(addr, len)?;
                }
            };
            Ok(())
        }
    }

    impl LiteralPrefixSetAfi for Any {
        const LITERAL_PREFIX_SET_RULE: ParserRule = ParserRule::mp_literal_prefix_set;
        const LITERAL_RANGED_PREFIX_SET_RULE: ParserRule = ParserRule::mp_ranged_prefix_set;
        const LITERAL_FILTER_RULE: ParserRule = ParserRule::mp_literal_filter;
        const NAMED_FILTER_RULE: ParserRule = ParserRule::mp_named_filter;
        const FILTER_EXPR_UNIT_RULE: ParserRule = ParserRule::mp_filter_expr_unit;
        const FILTER_EXPR_NOT_RULE: ParserRule = ParserRule::mp_filter_expr_not;
        const FILTER_EXPR_AND_RULE: ParserRule = ParserRule::mp_filter_expr_and;
        const FILTER_EXPR_OR_RULE: ParserRule = ParserRule::mp_filter_expr_or;

        const RTR_ADDR_LITERAL_RULE: ParserRule = ParserRule::mp_rtr_addr_literal;
        const RTR_EXPR_UNIT_RULE: ParserRule = ParserRule::mp_rtr_expr_unit;
        const RTR_EXPR_AND_RULE: ParserRule = ParserRule::mp_rtr_expr_and;
        const RTR_EXPR_OR_RULE: ParserRule = ParserRule::mp_rtr_expr_or;
        const RTR_EXPR_EXCEPT_RULE: ParserRule = ParserRule::mp_rtr_expr_except;

        const REMOTE_RTR_EXPR_RULE: ParserRule = ParserRule::remote_mp_rtr_expr;
        const LOCAL_RTR_EXPR_RULE: ParserRule = ParserRule::local_mp_rtr_expr;
        const PEERING_EXPR_LITERAL_RULE: ParserRule = ParserRule::mp_peering_expr_literal;
        const PEERING_EXPR_NAMED_RULE: ParserRule = ParserRule::mp_peering_expr_named;

        const INJECT_EXPR_RULE: ParserRule = ParserRule::inject6_expr;
        const INJECT_COND_UNIT_RULE: ParserRule = ParserRule::inject6_cond_unit;
        const INJECT_COND_AND_RULE: ParserRule = ParserRule::inject6_cond_and;
        const INJECT_COND_OR_RULE: ParserRule = ParserRule::inject6_cond_or;
        const INJECT_COND_TERM_HAVE_RULE: ParserRule = ParserRule::inject6_cond_term_have;
        const INJECT_COND_TERM_EXCLUDE_RULE: ParserRule = ParserRule::inject6_cond_term_excl;
        const INJECT_COND_TERM_STATIC_RULE: ParserRule = ParserRule::inject6_cond_term_stat;

        const COMPONENTS_EXPR_RULE: ParserRule = ParserRule::components6_expr;
        const COMPONENTS_PROTO_TERMS_RULE: ParserRule = ParserRule::components6_proto_terms;
        const COMPONENTS_PROTO_TERM_RULE: ParserRule = ParserRule::components6_proto_term;

        const PEER_EXPR_RULE: ParserRule = ParserRule::mp_peer_expr;
        const PEER_SPEC_RULE: ParserRule = ParserRule::mp_peer_spec;

        const DEFAULT_EXPR_RULE: ParserRule = ParserRule::mp_default_expr;

        const IMPORT_FACTOR_RULE: ParserRule = ParserRule::mp_import_factor;
        const IMPORT_TERM_RULE: ParserRule = ParserRule::mp_import_term;
        const IMPORT_EXPR_UNIT_RULE: ParserRule = ParserRule::mp_import_expr_unit;
        const IMPORT_EXPR_EXCEPT_RULE: ParserRule = ParserRule::mp_import_expr_except;
        const IMPORT_EXPR_REFINE_RULE: ParserRule = ParserRule::mp_import_expr_refine;
        const IMPORT_AFI_EXPR_RULE: ParserRule = ParserRule::mp_import_afi_expr;
        const IMPORT_STMT_RULE: ParserRule = ParserRule::mp_import_stmt;

        const EXPORT_FACTOR_RULE: ParserRule = ParserRule::mp_export_factor;
        const EXPORT_TERM_RULE: ParserRule = ParserRule::mp_export_term;
        const EXPORT_EXPR_UNIT_RULE: ParserRule = ParserRule::mp_export_expr_unit;
        const EXPORT_EXPR_EXCEPT_RULE: ParserRule = ParserRule::mp_export_expr_except;
        const EXPORT_EXPR_REFINE_RULE: ParserRule = ParserRule::mp_export_expr_refine;
        const EXPORT_AFI_EXPR_RULE: ParserRule = ParserRule::mp_export_afi_expr;
        const EXPORT_STMT_RULE: ParserRule = ParserRule::mp_export_stmt;

        const ROUTE_SET_MEMBER_RULE: ParserRule = ParserRule::route_set_mp_member_choice;
    }

    impl fmt::Display for Any {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "any")
        }
    }
}
