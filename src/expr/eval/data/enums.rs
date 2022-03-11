use std::convert::{TryFrom, TryInto};

use crate::{
    addr_family::{afi, AfiClass},
    primitive::{IpPrefix, IpPrefixRange as AstIpPrefixRange},
};

use super::{Apply, EvaluationError, EvaluationResult, IpPrefixRange};

pub enum IpPrefixRangeEnum {
    Ipv4(IpPrefixRange<afi::Ipv4>),
    Ipv6(IpPrefixRange<afi::Ipv6>),
}

impl TryFrom<AstIpPrefixRange<afi::Ipv4>> for IpPrefixRangeEnum {
    type Error = EvaluationError;
    fn try_from(range: AstIpPrefixRange<afi::Ipv4>) -> EvaluationResult<Self> {
        Ok(Self::Ipv4(range.try_into()?))
    }
}

impl TryFrom<AstIpPrefixRange<afi::Ipv6>> for IpPrefixRangeEnum {
    type Error = EvaluationError;
    fn try_from(range: AstIpPrefixRange<afi::Ipv6>) -> EvaluationResult<Self> {
        Ok(Self::Ipv6(range.try_into()?))
    }
}

impl TryFrom<AstIpPrefixRange<afi::Any>> for IpPrefixRangeEnum {
    type Error = EvaluationError;
    fn try_from(range: AstIpPrefixRange<afi::Any>) -> EvaluationResult<Self> {
        type Net = <afi::Any as AfiClass>::Net;
        match range.prefix().as_ref() {
            Net::V4(prefix) => Ok(Self::Ipv4(range.operator().apply(IpPrefix::new(*prefix))?)),
            Net::V6(prefix) => Ok(Self::Ipv6(range.operator().apply(IpPrefix::new(*prefix))?)),
        }
    }
}
