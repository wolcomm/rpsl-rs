use std::convert::TryInto;

use crate::{expr::filter, primitive::IpPrefixRange};

use super::{
    apply::Apply,
    data::{IpPrefixRangeEnum, PrefixSet},
    error::{EvaluationError, EvaluationResult},
    resolver::{Resolver, ResolverOutput},
    state,
    subst::PeerAs,
    Evaluate, Evaluation,
};

macro_rules! debug_resolution {
    ( $node:ty: $ex:expr ) => {
        log::debug!(
            concat!("resolving AST node '", stringify!($node), "': {}"),
            $ex
        )
    };
}

macro_rules! err {
    ( $( $arg:tt )* ) => {
        super::error::err!(
            super::error::EvaluationErrorKind::Resolution,
            $($arg)*
        )
    };
}

pub trait Resolve<R: Resolver>: Sized {
    type Output;
    fn resolve(self, resolver: &mut R) -> EvaluationResult<Self::Output>;
}

impl<R, T, O> Resolve<R> for Evaluation<T, state::Ready>
where
    R: Resolver,
    T: Resolve<R, Output = O>,
{
    type Output = O;

    fn resolve(self, resolver: &mut R) -> EvaluationResult<Self::Output> {
        self.into_inner().resolve(resolver)
    }
}

impl<R: Resolver + PeerAs, A: filter::ExprAfi> Resolve<R> for filter::Expr<A>
where
    IpPrefixRange<A>: TryInto<IpPrefixRangeEnum, Error = EvaluationError>,
{
    type Output = ResolverOutput<R>;

    fn resolve(self, resolver: &mut R) -> EvaluationResult<Self::Output> {
        debug_resolution!(filter::Expr: self);
        match self {
            Self::Unit(term) => dbg!(term.resolve(resolver)),
            Self::Not(term) => {
                let (mut ipv4_set, mut ipv6_set) = term.resolve(resolver)?;
                ipv4_set = ipv4_set.map(|set| !set);
                ipv6_set = ipv6_set.map(|set| !set);
                Ok(dbg!((ipv4_set, ipv6_set)))
            }
            Self::And(lhs, rhs) => {
                let (lhs_ipv4_set, lhs_ipv6_set) = lhs.resolve(resolver)?;
                let (rhs_ipv4_set, rhs_ipv6_set) = rhs.resolve(resolver)?;
                let ipv4_set = match (lhs_ipv4_set, rhs_ipv4_set) {
                    (Some(lhs), Some(rhs)) => Some(lhs & rhs),
                    (None, None) => None,
                    _ => return Err(err!("failed to take union of ipv4 sets")),
                };
                let ipv6_set = match (lhs_ipv6_set, rhs_ipv6_set) {
                    (Some(lhs), Some(rhs)) => Some(lhs & rhs),
                    (None, None) => None,
                    _ => return Err(err!("failed to take union of ipv6 sets")),
                };
                Ok(dbg!((ipv4_set, ipv6_set)))
            }
            Self::Or(lhs, rhs) => {
                let (lhs_ipv4_set, lhs_ipv6_set) = lhs.resolve(resolver)?;
                let (rhs_ipv4_set, rhs_ipv6_set) = rhs.resolve(resolver)?;
                let ipv4_set = match (lhs_ipv4_set, rhs_ipv4_set) {
                    (Some(lhs), Some(rhs)) => Some(lhs | rhs),
                    (None, None) => None,
                    _ => return Err(err!("failed to take union of ipv4 sets")),
                };
                let ipv6_set = match (lhs_ipv6_set, rhs_ipv6_set) {
                    (Some(lhs), Some(rhs)) => Some(lhs | rhs),
                    (None, None) => None,
                    _ => return Err(err!("failed to take union of ipv6 sets")),
                };
                Ok(dbg!((ipv4_set, ipv6_set)))
            }
        }
    }
}

impl<R: Resolver + PeerAs, A: filter::ExprAfi> Resolve<R> for filter::Term<A>
where
    IpPrefixRange<A>: TryInto<IpPrefixRangeEnum, Error = EvaluationError>,
{
    type Output = ResolverOutput<R>;

    fn resolve(self, resolver: &mut R) -> EvaluationResult<Self::Output> {
        debug_resolution!(filter::Term: self);
        match self {
            Self::Any => Ok((Some(R::Ipv4PrefixSet::any()), Some(R::Ipv6PrefixSet::any()))),
            Self::Literal(literal) => literal.resolve(resolver),
            Self::Named(filter_set) => resolver
                .resolve_named_filter_set(filter_set)?
                .evaluate(resolver),
            Self::Expr(expr) => expr.resolve(resolver),
        }
    }
}

impl<R: Resolver, A: filter::ExprAfi> Resolve<R> for filter::Literal<A>
where
    IpPrefixRange<A>: TryInto<IpPrefixRangeEnum, Error = EvaluationError>,
{
    type Output = ResolverOutput<R>;

    fn resolve(self, resolver: &mut R) -> EvaluationResult<Self::Output> {
        debug_resolution!(filter::Literal: self);
        match self {
            Self::PrefixSet(prefix_set_expr, op) => {
                let (mut ipv4_set, mut ipv6_set) = prefix_set_expr.resolve(resolver)?;
                ipv4_set = ipv4_set
                    .map(|set| op.apply(set))
                    .transpose()?
                    .map(|apply_map| apply_map.collect());
                ipv6_set = ipv6_set
                    .map(|set| op.apply(set))
                    .transpose()?
                    .map(|apply_map| apply_map.collect());
                Ok((ipv4_set, ipv6_set))
            }
            // TODO
            Self::AsPath(_) => unimplemented!(),
            Self::AttrMatch(_) => unimplemented!(),
        }
    }
}

impl<R: Resolver, A: filter::ExprAfi> Resolve<R> for filter::PrefixSetExpr<A>
where
    IpPrefixRange<A>: TryInto<IpPrefixRangeEnum, Error = EvaluationError>,
{
    type Output = ResolverOutput<R>;

    fn resolve(self, resolver: &mut R) -> EvaluationResult<Self::Output> {
        debug_resolution!(filter::PrefixSetExpr: self);
        match self {
            Self::Literal(entries) => {
                let (mut ipv4_set, mut ipv6_set) =
                    (R::Ipv4PrefixSet::empty(), R::Ipv6PrefixSet::empty());
                entries
                    .into_iter()
                    .filter_map(|prefix_range| {
                        prefix_range
                            .try_into()
                            .map_err(|err| {
                                log::warn!("failed to apply prefix range operator: {}", err)
                            })
                            .ok()
                    })
                    .for_each(|prefix_range_enum| match prefix_range_enum {
                        IpPrefixRangeEnum::Ipv4(prefix_range) => {
                            ipv4_set.extend(Some(prefix_range))
                        }
                        IpPrefixRangeEnum::Ipv6(prefix_range) => {
                            ipv6_set.extend(Some(prefix_range))
                        }
                    });
                Ok((Some(ipv4_set), Some(ipv6_set)))
            }
            Self::Named(set) => set.resolve(resolver),
        }
    }
}

impl<R: Resolver> Resolve<R> for filter::NamedPrefixSet {
    type Output = ResolverOutput<R>;

    fn resolve(self, resolver: &mut R) -> EvaluationResult<Self::Output> {
        debug_resolution!(filter::NamedPrefixSet: self);
        match self {
            Self::RsAny | Self::AsAny => {
                Ok((Some(R::Ipv4PrefixSet::any()), Some(R::Ipv6PrefixSet::any())))
            }
            Self::PeerAs => Err(err!(
                "expected named prefix set, found un-substituted 'PeerAS' token"
            )),
            Self::RouteSet(route_set) => Ok(resolver.resolve_route_set(route_set)?),
            Self::AsSet(as_set) => Ok(resolver.resolve_as_set_as_route_set(as_set)?),
            Self::AutNum(autnum) => Ok(resolver.resolve_aut_num_as_route_set(autnum)?),
        }
    }
}
