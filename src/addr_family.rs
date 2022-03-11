use std::fmt;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{IpNet, IpSubnets, Ipv4Net, Ipv4Subnets, Ipv6Net, Ipv6Subnets, PrefixLenError};

use crate::parser::ParserRule;

/// IP address family trait.
pub trait Afi: AfiClass {
    const MAX_PREFIX_LEN: u8;
}

pub trait AfiClass: Clone + Copy + fmt::Display + fmt::Debug + Hash + PartialEq + Eq {
    /// Address family IP address type.
    type Addr: FromStr<Err = std::net::AddrParseError>
        + Clone
        + Copy
        + fmt::Debug
        + fmt::Display
        + Hash
        + PartialEq
        + Eq;
    /// Address family IP prefix type.
    type Net: FromStr<Err = ipnet::AddrParseError>
        + Clone
        + Copy
        + Default
        + fmt::Debug
        + fmt::Display
        + Hash
        + PartialEq
        + Eq;
    /// Address family IP sub-prefixes iterator type.
    type Subnets: Iterator<Item = Self::Net>;
    /// Address family specific [`ParserRule`] for IP address literals.
    const LITERAL_ADDR_RULE: ParserRule;
    /// Address family specific [`ParserRule`] for IP prefix literals.
    const LITERAL_PREFIX_RULE: ParserRule;
    /// Get the maximum prefix length for IP address `addr`.
    fn max_len(addr: &Self::Addr) -> u8;
    /// Construct a [`Self::Net`] from `addr` and `len`.
    ///
    /// # Panic
    /// This method may panic if `len` is out of range.
    fn addr_to_net(addr: Self::Addr, len: u8) -> Self::Net;
    fn net_to_addr(prefix: &Self::Net) -> Self::Addr;
    fn net_to_subnets(prefix: &Self::Net, len: u8) -> Result<Self::Subnets, PrefixLenError>;
    /// Check that `len` is a valid prefix length for address `addr`.
    fn check_addr_len(addr: Self::Addr, len: u8) -> Result<(), PrefixLenError>;
    fn prefix_len(prefix: &Self::Net) -> u8;
}

/// Concrete address family definitions.
pub mod afi {
    use super::*;

    /// RPSL `ipv4` address family.
    #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
    pub struct Ipv4;

    impl Afi for Ipv4 {
        const MAX_PREFIX_LEN: u8 = 32;
    }

    impl AfiClass for Ipv4 {
        type Addr = Ipv4Addr;
        type Net = Ipv4Net;
        type Subnets = Ipv4Subnets;

        const LITERAL_ADDR_RULE: ParserRule = ParserRule::ipv4_addr;
        const LITERAL_PREFIX_RULE: ParserRule = ParserRule::ipv4_prefix;

        fn max_len(_: &Self::Addr) -> u8 {
            Self::MAX_PREFIX_LEN
        }

        fn addr_to_net(addr: Self::Addr, len: u8) -> Self::Net {
            Self::Net::new(addr, len).unwrap().trunc()
        }

        fn net_to_addr(prefix: &Self::Net) -> Self::Addr {
            prefix.addr()
        }

        fn net_to_subnets(prefix: &Self::Net, len: u8) -> Result<Self::Subnets, PrefixLenError> {
            prefix.subnets(len)
        }

        fn check_addr_len(addr: Self::Addr, len: u8) -> Result<(), PrefixLenError> {
            Self::Net::new(addr, len)?;
            Ok(())
        }

        fn prefix_len(prefix: &Self::Net) -> u8 {
            prefix.prefix_len()
        }
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
        const MAX_PREFIX_LEN: u8 = 128;
    }

    impl AfiClass for Ipv6 {
        type Addr = Ipv6Addr;
        type Net = Ipv6Net;
        type Subnets = Ipv6Subnets;

        const LITERAL_ADDR_RULE: ParserRule = ParserRule::ipv6_addr;
        const LITERAL_PREFIX_RULE: ParserRule = ParserRule::ipv6_prefix;

        fn max_len(_: &Self::Addr) -> u8 {
            Self::MAX_PREFIX_LEN
        }

        fn addr_to_net(addr: Self::Addr, len: u8) -> Self::Net {
            Self::Net::new(addr, len).unwrap().trunc()
        }

        fn net_to_addr(prefix: &Self::Net) -> Self::Addr {
            prefix.addr()
        }

        fn net_to_subnets(prefix: &Self::Net, len: u8) -> Result<Self::Subnets, PrefixLenError> {
            prefix.subnets(len)
        }

        fn check_addr_len(addr: Self::Addr, len: u8) -> Result<(), PrefixLenError> {
            Self::Net::new(addr, len)?;
            Ok(())
        }

        fn prefix_len(prefix: &Self::Net) -> u8 {
            prefix.prefix_len()
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

    impl AfiClass for Any {
        type Addr = IpAddr;
        type Net = IpNet;
        type Subnets = IpSubnets;

        const LITERAL_ADDR_RULE: ParserRule = ParserRule::ip_addr_choice;
        const LITERAL_PREFIX_RULE: ParserRule = ParserRule::ip_prefix_choice;

        fn max_len(addr: &Self::Addr) -> u8 {
            match addr {
                Self::Addr::V4(_) => Ipv4::MAX_PREFIX_LEN,
                Self::Addr::V6(_) => Ipv6::MAX_PREFIX_LEN,
            }
        }

        fn addr_to_net(addr: Self::Addr, len: u8) -> Self::Net {
            match addr {
                Self::Addr::V4(addr) => Ipv4Net::new(addr, len).unwrap().trunc().into(),
                Self::Addr::V6(addr) => Ipv6Net::new(addr, len).unwrap().trunc().into(),
            }
        }

        fn net_to_addr(prefix: &Self::Net) -> Self::Addr {
            prefix.addr()
        }

        fn net_to_subnets(prefix: &Self::Net, len: u8) -> Result<Self::Subnets, PrefixLenError> {
            prefix.subnets(len)
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

        fn prefix_len(prefix: &Self::Net) -> u8 {
            match prefix {
                Self::Net::V4(p) => p.prefix_len(),
                Self::Net::V6(p) => p.prefix_len(),
            }
        }
    }

    impl fmt::Display for Any {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "any")
        }
    }
}
