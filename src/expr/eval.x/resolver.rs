use crate::{
    addr_family::afi,
    expr::filter,
    names::{AsSet, AutNum, FilterSet, RouteSet},
};

use super::data::PrefixSet;

pub trait Resolver {
    type Ipv4PrefixSet: PrefixSet<afi::Ipv4>;
    type Ipv6PrefixSet: PrefixSet<afi::Ipv6>;
    type AsPathRegexp;

    type Error: ResolverError;

    fn resolve_route_set(&mut self, route_set: RouteSet) -> ResolverResult<Self>;
    fn resolve_as_set_as_route_set(&mut self, as_set: AsSet) -> ResolverResult<Self>;
    fn resolve_aut_num_as_route_set(&mut self, aut_num: AutNum) -> ResolverResult<Self>;
    fn resolve_named_filter_set<A>(
        &mut self,
        filter_set: FilterSet,
    ) -> Result<filter::Expr<A>, Self::Error>
    where
        A: filter::ExprAfi;
}

pub trait ResolverError: std::error::Error + Send + Sync + 'static {}

pub type ResolverOutput<R> = (
    Option<<R as Resolver>::Ipv4PrefixSet>,
    Option<<R as Resolver>::Ipv6PrefixSet>,
);
pub type ResolverResult<R> = Result<ResolverOutput<R>, <R as Resolver>::Error>;
