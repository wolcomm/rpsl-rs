use std::iter::{Extend, FromIterator};
use std::ops::{BitAnd, BitOr, Not};

use num::{One, Zero};

use crate::{
    addr_family::{afi, Afi, LiteralPrefixSetAfi},
    error::ResolutionError,
    expr::filter,
    names::{AsSet, AutNum, RouteSet},
    primitive::PrefixRange,
};

trait ExpressionAfi: LiteralPrefixSetAfi + Sized {
    fn partition_range<Ipv4Elem, Ipv6Elem>(
        range: PrefixRange<Self>,
    ) -> IpPrefixRange<Ipv4Elem, Ipv6Elem>;
}

impl ExpressionAfi for afi::Ipv4 {
    fn partition_range<Ipv4Elem, Ipv6Elem>(
        range: PrefixRange<Self>,
    ) -> IpPrefixRange<Ipv4Elem, Ipv6Elem> {
        IpPrefixRange::Ipv4(range.into())
    }
}

impl ExpressionAfi for afi::Any {
    fn partition_range<Ipv4Elem, Ipv6Elem>(
        range: PrefixRange<Self>,
    ) -> IpPrefixRange<Ipv4Elem, Ipv6Elem> {
        match range.prefix() {
            Self::Net::V4(prefix) => IpPrefixRange::Ipv4(range.into()),
            Self::Net::V6(prefix) => IpPrefixRange::Ipv6(range.into()),
        }
    }
}

trait IpPrefixAfi: Afi {}

impl IpPrefixAfi for afi::Ipv4 {}
impl IpPrefixAfi for afi::Ipv6 {}

struct Ipv4PrefixRange {
    prefix: ipnet::Ipv4Net,
    lower: u8,
    upper: u8,
}

struct Ipv6PrefixRange {
    prefix: ipnet::Ipv6Net,
    lower: u8,
    upper: u8,
}

enum IpPrefixRange<Ipv4Elem = Ipv4PrefixRange, Ipv6Elem = Ipv6PrefixRange> {
    Ipv4(Ipv4Elem),
    Ipv6(Ipv6Elem),
}

pub trait Resolver<Ipv4Elem = Ipv4PrefixRange, Ipv6Elem = Ipv6PrefixRange> {
    type Ipv4PrefixSet: Default + One + Zero + Not + BitAnd + BitOr + Extend<Ipv4Elem>;
    type Ipv6PrefixSet: Default + One + Zero + Not + BitAnd + BitOr + Extend<Ipv6Elem>;
    type AsPathRegexp;

    type Error: ResolverError;

    fn resolve_route_set(&mut self, route_set: RouteSet) -> ResolveFilterResult<Self>;
    fn resolve_as_set_as_route_set(&mut self, as_set: AsSet) -> ResolveFilterResult<Self>;
    fn resolve_aut_num_as_route_set(&mut self, aut_num: AutNum) -> ResolveFilterResult<Self>;
}

pub trait ResolverError: std::error::Error + Send + Sync + 'static {}

impl<E: ResolverError> From<E> for ResolutionError {
    fn from(err: E) -> Self {
        Self::new("expression resolution error", Some(err))
    }
}

pub type ResolveFilterOutput<R> = (
    Option<<R as Resolver>::Ipv4PrefixSet>,
    Option<<R as Resolver>::Ipv6PrefixSet>,
);
pub type ResolveFilterResult<R> = Result<ResolveFilterOutput<R>, <R as Resolver>::Error>;

macro_rules! debug_resolution {
    ( $node:ty: $ex:expr ) => {
        log::debug!(
            concat!("resolving AST node '", stringify!($node), "': {}"),
            $ex
        )
    };
}

macro_rules! err {
    ( $msg:literal $(,)? ) => {
        $crate::error::ResolutionError::from_msg($msg)
    };
    ( $fmt:expr, $( $arg:tt )* ) => {
        $crate::error::ResolutionError::from_msg(format!($fmt, $($arg)*))
    };
}

/// Custom [`Result<T, E>`] containing a possible [`SubstitutionError`].
type ResolutionResult<T> = Result<T, ResolutionError>;

trait Resolve<R: Resolver>: Sized {
    type Output;
    fn resolve(self, resolver: &mut R) -> ResolutionResult<Self::Output>;
}

impl<R: Resolver, A: LiteralPrefixSetAfi> Resolve<R> for filter::Expr<A> {
    type Output = (Option<R::Ipv4PrefixSet>, Option<R::Ipv6PrefixSet>);

    fn resolve(self, resolver: &mut R) -> ResolutionResult<Self::Output> {
        debug_resolution!(filter::Expr: self);
        match self {
            Self::Unit(term) => term.resolve(resolver),
            Self::Not(term) => {
                let (ipv4, ipv6) = term.resolve(resolver)?;
                Ok((ipv4.map(|set| !set), ipv6.map(|set| !set)))
            }
            Self::And(lhs, rhs) => {
                let (lhs_ipv4, lhs_ipv6) = lhs.resolve(resolver)?;
                let (rhs_ipv4, rhs_ipv6) = rhs.resolve(resolver)?;
                let ipv4 = match (lhs_ipv4, rhs_ipv4) {
                    (Some(lhs), Some(rhs)) => Some(lhs & rhs),
                    (None, None) => None,
                    _ => return Err(err!("failed to take intersection of sets")),
                };
                let ipv6 = match (lhs_ipv6, rhs_ipv6) {
                    (Some(lhs), Some(rhs)) => Some(lhs & rhs),
                    (None, None) => None,
                    _ => return Err(err!("failed to take intersection of sets")),
                };
                Ok((ipv4, ipv6))
            }
            Self::Or(lhs, rhs) => {
                let (lhs_ipv4, lhs_ipv6) = lhs.resolve(resolver)?;
                let (rhs_ipv4, rhs_ipv6) = rhs.resolve(resolver)?;
                let ipv4 = match (lhs_ipv4, rhs_ipv4) {
                    (Some(lhs), Some(rhs)) => Some(lhs | rhs),
                    (None, None) => None,
                    _ => return Err(err!("failed to take union of sets")),
                };
                let ipv6 = match (lhs_ipv6, rhs_ipv6) {
                    (Some(lhs), Some(rhs)) => Some(lhs | rhs),
                    (None, None) => None,
                    _ => return Err(err!("failed to take union of sets")),
                };
                Ok((ipv4, ipv6))
            }
        }
    }
}

impl<R: Resolver, A: LiteralPrefixSetAfi> Resolve<R> for filter::Term<A> {
    type Output = (Option<R::Ipv4PrefixSet>, Option<R::Ipv6PrefixSet>);

    fn resolve(self, resolver: &mut R) -> ResolutionResult<Self::Output> {
        debug_resolution!(filter::Term: self);
        match self {
            Self::Literal(set_expr, op) => Ok(op.apply(set_expr.eval(resolver)?)),
            // TODO
            Self::Named(_) => unimplemented!(),
            Self::Expr(expr) => expr.resolve(resolver),
        }
    }
}

// impl PrefixSetOp {
//     fn apply(&self, pair: PrefixSetPair) -> PrefixSetPair {
//         let (ipv4, ipv6) = pair;
//         (
//             ipv4.map(|set| self.apply_map(set)),
//             ipv6.map(|set| self.apply_map(set)),
//         )
//     }

//     fn apply_map<P: IpPrefix>(&self, set: PrefixSet<P>) -> PrefixSet<P> {
//         set.ranges()
//             .filter_map(|range| {
//                 self.apply_each(range)
//                     .map_err(|err| log::warn!("failed to apply prefix range operator: {}", err))
//                     .ok()
//             })
//             .collect()
//     }

//     fn apply_each<P: IpPrefix>(
//         &self,
//         range: IpPrefixRange<P>,
//     ) -> Result<IpPrefixRange<P>, prefixset::Error> {
//         let lower = match self {
//             Self::None => return Ok(range),
//             Self::LessExcl => *range.range().start() + 1,
//             Self::LessIncl => *range.range().start(),
//         };
//         let upper = P::MAX_LENGTH;
//         IpPrefixRange::new(*range.base(), lower, upper)
//     }
// }

impl<R: Resolver, A: LiteralPrefixSetAfi> Resolve<R> for filter::PrefixSetExpr<A> {
    type Output = ResolveFilterOutput<R>;

    fn resolve(self, resolver: &mut R) -> ResolutionResult<Self::Output> {
        debug_resolution!(filter::PrefixSetExpr: self);
        match self {
            Self::Literal(entries) => {
                let sets = entries
                    .into_iter()
                    .filter_map(|entry| {
                        entry
                            .into_prefix_range()
                            .map_err(|err| {
                                log::warn!("failed to apply prefix range operator: {}", err)
                            })
                            .ok()
                    })
                    .partition_map(|range| range);
                Ok(resolver.filter_pair(sets))
            }
            Self::Named(set) => set.resolve(resolver),
        }
    }
}

// impl LiteralPrefixSetEntry {
//     fn into_prefix_range(
//         self,
//     ) -> Result<Either<IpPrefixRange<Ipv4Prefix>, IpPrefixRange<Ipv6Prefix>>> {
//         match self.prefix {
//             IpNet::V4(prefix) => Ok(Either::Left(self.op.apply(prefix.into())?)),
//             IpNet::V6(prefix) => Ok(Either::Right(self.op.apply(prefix.into())?)),
//         }
//     }
// }

// impl PrefixOp {
//     fn apply<P: IpPrefix>(&self, prefix: P) -> Result<IpPrefixRange<P>, prefixset::Error> {
//         let (lower, upper) = match self {
//             Self::None => (prefix.length(), prefix.length()),
//             Self::LessExcl => (prefix.length() + 1, P::MAX_LENGTH),
//             Self::LessIncl => (prefix.length(), P::MAX_LENGTH),
//             Self::Exact(length) => (*length, *length),
//             Self::Range(upper, lower) => (*upper, *lower),
//         };
//         IpPrefixRange::new(prefix, lower, upper)
//     }
// }

impl<R: Resolver> Resolve<R> for filter::NamedPrefixSet {
    type Output = ResolveFilterOutput<R>;

    fn resolve(self, resolver: &mut R) -> ResolutionResult<Self::Output> {
        debug_resolution!(filter::NamedPrefixSet: self);
        match self {
            Self::RsAny | Self::AsAny => {
                Ok((Some(R::Ipv4PrefixSet::one()), Some(R::Ipv6PrefixSet::one())))
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
