use std::collections::{hash_set, HashSet};
use std::fmt;
use std::iter::{Extend, FromIterator, IntoIterator, Map};
use std::ops::{BitAnd, BitOr, Not};

use crate::{
    addr_family::{afi, Afi},
    expr::MpFilterExpr,
    names::{AsSet, AutNum, RouteSet},
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
struct TestPrefixSet<A: Afi>(HashSet<IpPrefix<A>>);

impl<A: Afi> Default for TestPrefixSet<A> {
    fn default() -> Self {
        Self(HashSet::default())
    }
}

impl<A: Afi, T: AsRef<[&'static str]>> From<T> for TestPrefixSet<A> {
    fn from(prefixes: T) -> Self {
        Self(
            prefixes
                .as_ref()
                .iter()
                .map(|p| p.parse().unwrap())
                .collect(),
        )
    }
}

impl<A: Afi> Extend<IpPrefixRange<A>> for TestPrefixSet<A> {
    fn extend<I: IntoIterator<Item = IpPrefixRange<A>>>(&mut self, iter: I) {
        self.0
            .extend(iter.into_iter().flat_map(|range| range.prefixes()))
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
    type IntoIter = Map<hash_set::IntoIter<IpPrefix<A>>, fn(IpPrefix<A>) -> IpPrefixRange<A>>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter().map(IpPrefixRange::from)
    }
}

impl<A: Afi> BitAnd for TestPrefixSet<A> {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        self.0
            .into_iter()
            .filter(|prefix| rhs.0.contains(prefix))
            .map(|prefix| prefix.into())
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
        Self(
            IpPrefixRange::all()
                .prefixes()
                .filter(|prefix| !self.0.contains(prefix))
                .collect(),
        )
    }
}

impl<A: Afi> PrefixSet<A> for TestPrefixSet<A> {}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct TestResolverError(String);

impl fmt::Display for TestResolverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
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
}
