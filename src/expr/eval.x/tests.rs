use std::borrow::Borrow;
use std::collections::{hash_set, HashSet};
use std::fmt;
use std::hash::Hash;
use std::iter::{Extend, FromIterator, IntoIterator};
use std::ops::{BitAnd, BitOr, Not};

use crate::{
    addr_family::{afi, Afi},
    expr::{filter, MpFilterExpr},
    names::{AsSet, AutNum, FilterSet, RouteSet},
    primitive::IpPrefix,
};

use super::{
    data::{IpPrefixRange, PrefixSet},
    resolver::{Resolver, ResolverError, ResolverResult},
    subst::PeerAs,
    Evaluate,
};

struct TestResolver {
    peer_as: AutNum,
}

impl Default for TestResolver {
    fn default() -> Self {
        Self {
            peer_as: "AS65000".parse().unwrap(),
        }
    }
}

impl PeerAs for TestResolver {
    fn peeras(&self) -> Option<&AutNum> {
        Some(&self.peer_as)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TestPrefixSetIncl<A: Afi> {
    Any,
    Set(HashSet<IpPrefix<A>>),
}

impl<A: Afi> TestPrefixSetIncl<A> {
    fn contains<Q>(&self, prefix: &Q) -> bool
    where
        IpPrefix<A>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        match self {
            Self::Any => true,
            Self::Set(inner) => inner.contains(prefix),
        }
    }
}

impl<A: Afi> Default for TestPrefixSetIncl<A> {
    fn default() -> Self {
        Self::Set(Default::default())
    }
}

impl<A: Afi> From<HashSet<IpPrefix<A>>> for TestPrefixSetIncl<A> {
    fn from(set: HashSet<IpPrefix<A>>) -> Self {
        Self::Set(set)
    }
}

impl<A: Afi> Extend<IpPrefix<A>> for TestPrefixSetIncl<A> {
    fn extend<I: IntoIterator<Item = IpPrefix<A>>>(&mut self, iter: I) {
        if let Self::Set(inner) = self {
            inner.extend(iter)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TestPrefixSet<A: Afi> {
    include: TestPrefixSetIncl<A>,
    exclude: HashSet<IpPrefix<A>>,
}

impl<A: Afi> TestPrefixSet<A> {
    fn contains<Q>(&self, prefix: &Q) -> bool
    where
        IpPrefix<A>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.include.contains(prefix) && !self.exclude.contains(prefix)
    }
    fn contains_some<Q>(&self, prefix: Q) -> Option<Q>
    where
        IpPrefix<A>: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.contains(&prefix).then_some(prefix)
    }
}

impl<A: Afi> Default for TestPrefixSet<A> {
    fn default() -> Self {
        Self {
            include: Default::default(),
            exclude: Default::default(),
        }
    }
}

impl<A: Afi, T: AsRef<[&'static str]>> From<T> for TestPrefixSet<A> {
    fn from(prefixes: T) -> Self {
        let include = prefixes
            .as_ref()
            .iter()
            .map(|p| p.parse().unwrap())
            .collect::<HashSet<_>>()
            .into();
        Self {
            include,
            exclude: Default::default(),
        }
    }
}

impl<A: Afi> Extend<IpPrefixRange<A>> for TestPrefixSet<A> {
    fn extend<I: IntoIterator<Item = IpPrefixRange<A>>>(&mut self, iter: I) {
        let excl = &mut self.exclude;
        self.include.extend(
            iter.into_iter()
                .flat_map(|range| range.prefixes())
                .inspect(|prefix| {
                    excl.remove(prefix);
                }),
        )
    }
}

impl<A: Afi> FromIterator<IpPrefixRange<A>> for TestPrefixSet<A> {
    fn from_iter<I: IntoIterator<Item = IpPrefixRange<A>>>(iter: I) -> Self {
        let mut set = Self::default();
        set.extend(iter);
        set
    }
}

impl<A: Afi> IntoIterator for TestPrefixSet<A> {
    type Item = IpPrefixRange<A>;
    type IntoIter = TestPrefixSetIter<A>;
    fn into_iter(self) -> Self::IntoIter {
        let inner = match self.include {
            TestPrefixSetIncl::Any => panic!("iterating over Any is a bad idea!"),
            TestPrefixSetIncl::Set(inner) => inner.into_iter(),
        };
        Self::IntoIter {
            inner,
            exclude: self.exclude,
        }
    }
}

struct TestPrefixSetIter<A: Afi> {
    inner: hash_set::IntoIter<IpPrefix<A>>,
    exclude: HashSet<IpPrefix<A>>,
}

impl<A: Afi> Iterator for TestPrefixSetIter<A> {
    type Item = IpPrefixRange<A>;
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(prefix) = self.inner.next() {
            if !self.exclude.contains(&prefix) {
                return Some(prefix.into());
            }
        }
        None
    }
}

impl<A: Afi> BitAnd for TestPrefixSet<A> {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        self.into_iter()
            .flat_map(IpPrefixRange::prefixes)
            .filter_map(|prefix| rhs.contains_some(prefix).map(IpPrefixRange::from))
            .collect()
    }
}

impl<A: Afi> BitOr for TestPrefixSet<A> {
    type Output = Self;
    fn bitor(mut self, rhs: Self) -> Self::Output {
        self.extend(rhs);
        self
    }
}

impl<A: Afi> Not for TestPrefixSet<A> {
    type Output = Self;
    fn not(self) -> Self::Output {
        let exclude = self.into_iter().flat_map(IpPrefixRange::prefixes).collect();
        Self {
            include: TestPrefixSetIncl::Any,
            exclude,
        }
    }
}

impl<A: Afi> PrefixSet<A> for TestPrefixSet<A> {
    fn any() -> Self {
        Self {
            include: TestPrefixSetIncl::Any,
            exclude: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct TestResolverError(String);

impl fmt::Display for TestResolverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl<S: AsRef<str>> From<S> for TestResolverError {
    fn from(s: S) -> Self {
        Self(s.as_ref().to_owned())
    }
}
impl std::error::Error for TestResolverError {}
impl ResolverError for TestResolverError {}

impl Resolver for TestResolver {
    type Ipv4PrefixSet = TestPrefixSet<afi::Ipv4>;
    type Ipv6PrefixSet = TestPrefixSet<afi::Ipv6>;
    type AsPathRegexp = ();
    type Error = TestResolverError;
    fn resolve_route_set(&mut self, _: RouteSet) -> ResolverResult<Self> {
        Ok((None, None))
    }
    fn resolve_as_set_as_route_set(&mut self, _: AsSet) -> ResolverResult<Self> {
        Ok((None, None))
    }
    fn resolve_aut_num_as_route_set(&mut self, _: AutNum) -> ResolverResult<Self> {
        Ok((None, None))
    }
    fn resolve_named_filter_set<A: filter::ExprAfi>(
        &mut self,
        name: FilterSet,
    ) -> Result<filter::Expr<A>, Self::Error> {
        match name.to_string().as_str() {
            "FLTR-NONE" => Ok("{}".parse().unwrap()),
            "FLTR-ERROR" => Err("resolver error".into()),
            "FLTR-ANY" => Ok("ANY".parse().unwrap()),
            "FLTR-ONE" => Ok("{1.1.1.1/32, 1::1/128}".parse().unwrap()),
            _ => panic!("bad filter name"),
        }
    }
}

macro_rules! eval_filters {
    ( $( $case:ident: $expr:literal => ( $ipv4_set:expr, $ipv6_set:expr $(,)? ) );* $(;)? ) => {
        $(
            #[test]
            fn $case() {
                let expr: MpFilterExpr = $expr.parse().unwrap();
                let mut resolver = TestResolver::default();
                let result = expr.evaluate(&mut resolver).unwrap();
                let expect = (
                    $ipv4_set.map(TestPrefixSet::from),
                    $ipv6_set.map(TestPrefixSet::from),
                );
                assert_eq!(expect, result)
            }
        )*
    };
}

eval_filters! {
    empty: "{}" => (Some([]), Some([]));
    simple: "{10.0.0.0/8, 2001:db8::/32}" => (Some(["10.0.0.0/8"]), Some(["2001:db8::/32"]));
    less_incl_ranges: "{10.0.0.0/31^+, 2001:db8::/127^+}" => (
        Some(["10.0.0.0/31", "10.0.0.0/32", "10.0.0.1/32"]),
        Some(["2001:db8::/127", "2001:db8::/128", "2001:db8::1/128"]),
    );
    less_excl_ranges: "{10.0.0.0/30^-, 2001:db8::/126^-}" => (
        Some([
            "10.0.0.0/31", "10.0.0.2/31", "10.0.0.0/32",
            "10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32"
        ]),
        Some([
            "2001:db8::/127", "2001:db8::2/127", "2001:db8::/128",
            "2001:db8::1/128", "2001:db8::2/128", "2001:db8::3/128"
        ]),
    );
    exact_ranges: "{10.0.0.0/24^25, 2001:db8::/47^48}" => (
        Some(["10.0.0.0/25", "10.0.0.128/25"]),
        Some(["2001:db8::/48", "2001:db8:1::/48"]),
    );
    bounded_ranges: "{10.0.0.0/16^17-18, 2001:db8::/32^33-34}" => (
        Some([
            "10.0.0.0/17", "10.0.128.0/17", "10.0.0.0/18",
            "10.0.64.0/18", "10.0.128.0/18", "10.0.192.0/18"
        ]),
        Some([
            "2001:db8::/33", "2001:db8:8000::/33", "2001:db8::/34",
            "2001:db8:4000::/34", "2001:db8:8000::/34", "2001:db8:c000::/34"
        ]),
    );
    disjoint_ranges: "{10.0.0.0/8^7, 2001:db8::/32^30-31}" => (Some([]), Some([]));
    less_incl_over_less_incl: "{192.168.0.0/31^+}^+" => (
        Some(["192.168.0.0/31", "192.168.0.0/32", "192.168.0.1/32"]),
        Some([]),
    );
    less_incl_over_less_excl: "{2001:db8::/127^-}^+" => (
        Some([]),
        Some(["2001:db8::/128", "2001:db8::1/128"]),
    );
    less_incl_over_exact: "{192.168.0.248/29^31}^+" => (
        Some([
            "192.168.0.248/31", "192.168.0.250/31", "192.168.0.252/31", "192.168.0.254/31",
            "192.168.0.248/32", "192.168.0.249/32", "192.168.0.250/32", "192.168.0.251/32",
            "192.168.0.252/32", "192.168.0.253/32", "192.168.0.254/32", "192.168.0.255/32",
        ]),
        Some([]),
    );
    less_incl_over_range: "{2001:db8::f0/124^126-127}^+" => (
        Some([]),
        Some([
            "2001:db8::f0/126", "2001:db8::f4/126", "2001:db8::f8/126", "2001:db8::fc/126",
            "2001:db8::f0/127", "2001:db8::f2/127", "2001:db8::f4/127", "2001:db8::f6/127",
            "2001:db8::f8/127", "2001:db8::fa/127", "2001:db8::fc/127", "2001:db8::fe/127",
            "2001:db8::f0/128", "2001:db8::f1/128", "2001:db8::f2/128", "2001:db8::f3/128",
            "2001:db8::f4/128", "2001:db8::f5/128", "2001:db8::f6/128", "2001:db8::f7/128",
            "2001:db8::f8/128", "2001:db8::f9/128", "2001:db8::fa/128", "2001:db8::fb/128",
            "2001:db8::fc/128", "2001:db8::fd/128", "2001:db8::fe/128", "2001:db8::ff/128",
        ]),
    );
    less_excl_over_less_incl: "{192.168.0.0/31^+}^-" => (
        Some(["192.168.0.0/32", "192.168.0.1/32"]),
        Some([]),
    );
    less_excl_over_less_excl: "{2001:db8::/126^-}^-" => (
        Some([]),
        Some(["2001:db8::/128",  "2001:db8::1/128",  "2001:db8::2/128", "2001:db8::3/128"]),
    );
    less_excl_over_exact: "{192.168.0.248/29^30}^-" => (
        Some([
            "192.168.0.248/31", "192.168.0.250/31", "192.168.0.252/31", "192.168.0.254/31",
            "192.168.0.248/32", "192.168.0.249/32", "192.168.0.250/32", "192.168.0.251/32",
            "192.168.0.252/32", "192.168.0.253/32", "192.168.0.254/32", "192.168.0.255/32",
        ]),
        Some([]),
    );
    less_excl_over_range: "{2001:db8::f0/124^126-127}^-" => (
        Some([]),
        Some([
            "2001:db8::f0/127", "2001:db8::f2/127", "2001:db8::f4/127", "2001:db8::f6/127",
            "2001:db8::f8/127", "2001:db8::fa/127", "2001:db8::fc/127", "2001:db8::fe/127",
            "2001:db8::f0/128", "2001:db8::f1/128", "2001:db8::f2/128", "2001:db8::f3/128",
            "2001:db8::f4/128", "2001:db8::f5/128", "2001:db8::f6/128", "2001:db8::f7/128",
            "2001:db8::f8/128", "2001:db8::f9/128", "2001:db8::fa/128", "2001:db8::fb/128",
            "2001:db8::fc/128", "2001:db8::fd/128", "2001:db8::fe/128", "2001:db8::ff/128",
        ]),
    );
    exact_over_less_incl: "{192.168.0.0/31^+}^32" => (
        Some(["192.168.0.0/32", "192.168.0.1/32"]),
        Some([]),
    );
    exact_over_less_excl: "{2001:db8::/126^-}^128" => (
        Some([]),
        Some(["2001:db8::/128",  "2001:db8::1/128",  "2001:db8::2/128", "2001:db8::3/128"]),
    );
    exact_over_exact: "{192.168.0.248/29^30}^31" => (
        Some(["192.168.0.248/31", "192.168.0.250/31", "192.168.0.252/31", "192.168.0.254/31"]),
        Some([]),
    );
    exact_over_exact_disjoint: "{192.168.0.248/29^30}^29" => (
        Some([]),
        Some([]),
    );
    exact_over_range: "{2001:db8::f0/124^126-127}^128" => (
        Some([]),
        Some([
            "2001:db8::f0/128", "2001:db8::f1/128", "2001:db8::f2/128", "2001:db8::f3/128",
            "2001:db8::f4/128", "2001:db8::f5/128", "2001:db8::f6/128", "2001:db8::f7/128",
            "2001:db8::f8/128", "2001:db8::f9/128", "2001:db8::fa/128", "2001:db8::fb/128",
            "2001:db8::fc/128", "2001:db8::fd/128", "2001:db8::fe/128", "2001:db8::ff/128",
        ]),
    );
    exact_over_range_disjoint: "{2001:db8::f0/124^126-127}^125" => (
        Some([]),
        Some([]),
    );
    range_over_less_incl: "{192.168.0.0/31^+}^30-32" => (
        Some(["192.168.0.0/31", "192.168.0.0/32", "192.168.0.1/32"]),
        Some([]),
    );
    range_over_less_excl: "{2001:db8::/126^-}^127-128" => (
        Some([]),
        Some([
            "2001:db8::/127", "2001:db8::2/127",
            "2001:db8::/128", "2001:db8::1/128",  "2001:db8::2/128", "2001:db8::3/128"
        ]),
    );
    range_over_exact: "{192.168.0.248/29^30}^31-32" => (
        Some([
            "192.168.0.248/31", "192.168.0.250/31", "192.168.0.252/31", "192.168.0.254/31",
            "192.168.0.248/32", "192.168.0.249/32", "192.168.0.250/32", "192.168.0.251/32",
            "192.168.0.252/32", "192.168.0.253/32", "192.168.0.254/32", "192.168.0.255/32",
        ]),
        Some([]),
    );
    range_over_exact_disjoint: "{192.168.0.248/29^30}^28-29" => (
        Some([]),
        Some([]),
    );
    range_over_range: "{2001:db8::f0/124^126-127}^125-128" => (
        Some([]),
        Some([
            "2001:db8::f0/126", "2001:db8::f4/126", "2001:db8::f8/126", "2001:db8::fc/126",
            "2001:db8::f0/127", "2001:db8::f2/127", "2001:db8::f4/127", "2001:db8::f6/127",
            "2001:db8::f8/127", "2001:db8::fa/127", "2001:db8::fc/127", "2001:db8::fe/127",
            "2001:db8::f0/128", "2001:db8::f1/128", "2001:db8::f2/128", "2001:db8::f3/128",
            "2001:db8::f4/128", "2001:db8::f5/128", "2001:db8::f6/128", "2001:db8::f7/128",
            "2001:db8::f8/128", "2001:db8::f9/128", "2001:db8::fa/128", "2001:db8::fb/128",
            "2001:db8::fc/128", "2001:db8::fd/128", "2001:db8::fe/128", "2001:db8::ff/128",
        ]),
    );
    range_over_range_disjoint: "{2001:db8::f0/124^126-127}^124-125" => (
        Some([]),
        Some([]),
    );
    intersection: "{192.168.0.0/16^16-24, 2001:db8::/32^32-48} AND {192.0.0.0/8^17, 2001::/16^33}" => (
        Some(["192.168.0.0/17", "192.168.128.0/17"]),
        Some(["2001:db8::/33", "2001:db8:8000::/33"]),
    );
    union: "{192.168.0.0/24, 2001:db8:f00::/48} OR {10.0.0.0/8, 2001:db8:baa::/64}" => (
        Some(["192.168.0.0/24", "10.0.0.0/8"]),
        Some(["2001:db8:f00::/48", "2001:db8:baa::/64"]),
    );
    subtraction: "{192.168.0.0/22^24, 2001:db8:f00::/48^50} AND NOT {192.168.2.0/23^24, 2001:db8:f00::/49^50}" => (
        Some(["192.168.0.0/24", "192.168.1.0/24"]),
        Some(["2001:db8:f00:8000::/50", "2001:db8:f00:c000::/50"]),
    );
    intersect_any: "{192.0.2.0/24, 2001:db8::/32} AND ANY" => (
        Some(["192.0.2.0/24"]),
        Some(["2001:db8::/32"]),
    );
    union_over_intersection: "{192.0.2.0/26} OR ({192.0.2.64/26, 192.0.2.128/26} AND {192.0.2.128/25^26})" => (
        Some(["192.0.2.0/26", "192.0.2.128/26"]),
        Some([]),
    );
    intersection_over_union: "({192.0.2.0/26} OR {192.0.2.64/26, 192.0.2.128/26}) AND {192.0.2.128/25^26}" => (
        Some(["192.0.2.128/26"]),
        Some([]),
    );
}
