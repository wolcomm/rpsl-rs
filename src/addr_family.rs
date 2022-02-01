use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::{
    error::{ParseError, ParseResult},
    parser::{ParserRule, TokenPair},
};

pub trait Afi
where
    // Self: TryFrom<TokenPair<'a>>,
    // Self::Error: Into<ParseError>,
    Self: fmt::Display,
    Self::Addr: FromStr<Err = std::net::AddrParseError>
        + Clone
        + fmt::Debug
        + fmt::Display
        + Hash
        + PartialEq
        + Eq,
    Self::Net: FromStr<Err = ipnet::AddrParseError>
        + Clone
        + fmt::Debug
        + fmt::Display
        + Hash
        + PartialEq
        + Eq,
{
    type Addr;
    type Net;

    fn max_len(addr: &Self::Addr) -> u8;
    fn addr_to_net(addr: Self::Addr, len: u8) -> Self::Net;
}

pub trait LiteralPrefixSetAfi: Afi {
    const LITERAL_PREFIX_SET_RULE: ParserRule;
    const LITERAL_RANGED_PREFIX_SET_RULE: ParserRule;
    const LITERAL_FILTER_RULE: ParserRule;
    const NAMED_FILTER_RULE: ParserRule;
    const FILTER_EXPR_UNIT_RULE: ParserRule;
    const FILTER_EXPR_NOT_RULE: ParserRule;
    const FILTER_EXPR_AND_RULE: ParserRule;
    const FILTER_EXPR_OR_RULE: ParserRule;
    const FILTER_EXPR_RULES: [ParserRule; 4] = [
        Self::FILTER_EXPR_UNIT_RULE,
        Self::FILTER_EXPR_NOT_RULE,
        Self::FILTER_EXPR_AND_RULE,
        Self::FILTER_EXPR_OR_RULE,
    ];
    fn match_filter_expr_rule(rule: ParserRule) -> bool {
        Self::FILTER_EXPR_RULES
            .iter()
            .any(|filter_expr_rule| &rule == filter_expr_rule)
    }

    const RTR_ADDR_LITERAL_RULE: ParserRule;
    const RTR_EXPR_UNIT_RULE: ParserRule;
    const RTR_EXPR_AND_RULE: ParserRule;
    const RTR_EXPR_OR_RULE: ParserRule;
    const RTR_EXPR_EXCEPT_RULE: ParserRule;
    const RTR_EXPR_RULES: [ParserRule; 4] = [
        Self::RTR_EXPR_UNIT_RULE,
        Self::RTR_EXPR_AND_RULE,
        Self::RTR_EXPR_OR_RULE,
        Self::RTR_EXPR_EXCEPT_RULE,
    ];
    fn match_rtr_expr_rule(rule: ParserRule) -> bool {
        Self::RTR_EXPR_RULES
            .iter()
            .any(|rtr_expr_rule| &rule == rtr_expr_rule)
    }

    const REMOTE_RTR_EXPR_RULE: ParserRule;
    const LOCAL_RTR_EXPR_RULE: ParserRule;
    const PEERING_EXPR_LITERAL_RULE: ParserRule;
    const PEERING_EXPR_NAMED_RULE: ParserRule;
    const PEERING_EXPR_RULES: [ParserRule; 2] = [
        Self::PEERING_EXPR_NAMED_RULE,
        Self::PEERING_EXPR_LITERAL_RULE,
    ];
    fn match_peering_expr_rule(rule: ParserRule) -> bool {
        Self::PEERING_EXPR_RULES
            .iter()
            .any(|peering_expr_rule| &rule == peering_expr_rule)
    }

    const IMPORT_FACTOR_RULE: ParserRule;
    const IMPORT_TERM_RULE: ParserRule;
    const IMPORT_EXPR_UNIT_RULE: ParserRule;
    const IMPORT_EXPR_EXCEPT_RULE: ParserRule;
    const IMPORT_EXPR_REFINE_RULE: ParserRule;
    const IMPORT_STMT_SIMPLE_RULE: ParserRule;
    const IMPORT_STMT_PROTOCOL_RULE: ParserRule;
}

pub mod afi {
    use super::*;

    #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
    pub struct Ipv4;

    impl Afi for Ipv4 {
        type Addr = Ipv4Addr;
        type Net = Ipv4Net;

        fn max_len(_: &Self::Addr) -> u8 {
            32
        }

        fn addr_to_net(addr: Self::Addr, len: u8) -> Self::Net {
            Self::Net::new(addr, len).unwrap().trunc()
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

        const IMPORT_FACTOR_RULE: ParserRule = ParserRule::import_factor;
        const IMPORT_TERM_RULE: ParserRule = ParserRule::import_term;
        const IMPORT_EXPR_UNIT_RULE: ParserRule = ParserRule::import_expr_unit;
        const IMPORT_EXPR_EXCEPT_RULE: ParserRule = ParserRule::import_expr_except;
        const IMPORT_EXPR_REFINE_RULE: ParserRule = ParserRule::import_expr_refine;
        const IMPORT_STMT_SIMPLE_RULE: ParserRule = ParserRule::import_stmt_simple;
        const IMPORT_STMT_PROTOCOL_RULE: ParserRule = ParserRule::import_stmt_protocol;
    }

    impl fmt::Display for Ipv4 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "ipv4")
        }
    }

    #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
    pub struct Ipv6;

    impl Afi for Ipv6 {
        type Addr = Ipv6Addr;
        type Net = Ipv6Net;

        fn max_len(_: &Self::Addr) -> u8 {
            128
        }

        fn addr_to_net(addr: Self::Addr, len: u8) -> Self::Net {
            Self::Net::new(addr, len).unwrap().trunc()
        }
    }

    impl fmt::Display for Ipv6 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "ipv6")
        }
    }

    #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
    pub struct Any;

    impl Afi for Any {
        type Addr = IpAddr;
        type Net = IpNet;

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

        const IMPORT_FACTOR_RULE: ParserRule = ParserRule::mp_import_factor;
        const IMPORT_TERM_RULE: ParserRule = ParserRule::mp_import_term;
        const IMPORT_EXPR_UNIT_RULE: ParserRule = ParserRule::mp_import_expr_unit;
        const IMPORT_EXPR_EXCEPT_RULE: ParserRule = ParserRule::mp_import_expr_except;
        const IMPORT_EXPR_REFINE_RULE: ParserRule = ParserRule::mp_import_expr_refine;
        const IMPORT_STMT_SIMPLE_RULE: ParserRule = ParserRule::mp_import_stmt_simple;
        const IMPORT_STMT_PROTOCOL_RULE: ParserRule = ParserRule::mp_import_stmt_protocol;
    }

    impl fmt::Display for Any {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "any")
        }
    }
}
