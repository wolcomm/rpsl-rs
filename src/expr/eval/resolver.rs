use std::iter::{Extend, FromIterator};
use std::ops::{BitAnd, BitOr, Not};

use num::{One, Zero};

use crate::{
    addr_family::afi,
    names::{AsSet, AutNum, RouteSet},
};

use super::data::IpPrefixRange;

pub trait Resolver {
    type Ipv4PrefixSet: Default
        + One
        + Zero
        + Not<Output = Self::Ipv4PrefixSet>
        + BitAnd<Output = Self::Ipv4PrefixSet>
        + BitOr<Output = Self::Ipv4PrefixSet>
        + Extend<IpPrefixRange<afi::Ipv4>>
        + FromIterator<IpPrefixRange<afi::Ipv4>>
        + IntoIterator<Item = IpPrefixRange<afi::Ipv4>>;
    type Ipv6PrefixSet: Default
        + One
        + Zero
        + Not<Output = Self::Ipv6PrefixSet>
        + BitAnd<Output = Self::Ipv6PrefixSet>
        + BitOr<Output = Self::Ipv6PrefixSet>
        + Extend<IpPrefixRange<afi::Ipv6>>
        + FromIterator<IpPrefixRange<afi::Ipv6>>
        + IntoIterator<Item = IpPrefixRange<afi::Ipv6>>;
    type AsPathRegexp;

    type Error: ResolverError;

    fn resolve_route_set(&mut self, route_set: RouteSet) -> ResolverResult<Self>;
    fn resolve_as_set_as_route_set(&mut self, as_set: AsSet) -> ResolverResult<Self>;
    fn resolve_aut_num_as_route_set(&mut self, aut_num: AutNum) -> ResolverResult<Self>;
}

pub trait ResolverError: std::error::Error + Send + Sync + 'static {}

pub type ResolverOutput<R> = (
    Option<<R as Resolver>::Ipv4PrefixSet>,
    Option<<R as Resolver>::Ipv6PrefixSet>,
);
pub type ResolverResult<R> = Result<ResolverOutput<R>, <R as Resolver>::Error>;
