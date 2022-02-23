use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::iter::FromIterator;

use crate::{
    addr_family::{afi, LiteralPrefixSetAfi},
    error::{ParseError, ParseResult},
    list::ListOf,
    parser::{
        debug_construction, impl_from_str, next_into_or, rule_mismatch, ParserRule, TokenPair,
    },
    primitive::{PrefixRange, Protocol},
};

use super::{action, autnum, filter, rtr};

/// RPSL `inject` expression for `route` objects. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-8.1
pub type InjectExpr = inject::Expr<afi::Ipv4>;
impl_from_str!(ParserRule::just_inject_expr => InjectExpr);

/// RPSL `inject` expression for `route6` objects. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-3
pub type Inject6Expr = inject::Expr<afi::Any>;
impl_from_str!(ParserRule::just_inject6_expr => Inject6Expr);

mod inject {
    use super::*;

    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    pub struct Expr<A: LiteralPrefixSetAfi> {
        at: Option<rtr::Expr<A>>,
        action: Option<action::Expr>,
        condition: Option<Condition<A>>,
    }

    impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for Expr<A> {
        type Error = ParseError;

        fn try_from(pair: TokenPair) -> ParseResult<Self> {
            debug_construction!(pair => Expr);
            match pair.as_rule() {
                rule if rule == A::INJECT_EXPR_RULE => {
                    let (mut at, mut action, mut condition) = (None, None, None);
                    for inner_pair in pair.into_inner() {
                        match inner_pair.as_rule() {
                            rule if A::match_rtr_expr_rule(rule) => {
                                at = Some(inner_pair.try_into()?);
                            }
                            ParserRule::action_expr => {
                                action = Some(inner_pair.try_into()?);
                            }
                            rule if A::match_inject_condition_rule(rule) => {
                                condition = Some(inner_pair.try_into()?);
                            }
                            _ => {
                                return Err(
                                    rule_mismatch!(inner_pair => "inject expression element"),
                                )
                            }
                        }
                    }
                    Ok(Self {
                        at,
                        action,
                        condition,
                    })
                }
                _ => Err(rule_mismatch!(pair => "inject expression")),
            }
        }
    }

    impl<A: LiteralPrefixSetAfi> fmt::Display for Expr<A> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let mut statements = Vec::new();
            if let Some(rtr_expr) = &self.at {
                statements.push(format!("at {}", rtr_expr));
            }
            if let Some(action_expr) = &self.action {
                statements.push(format!("action {}", action_expr));
            }
            if let Some(condition) = &self.condition {
                statements.push(format!("upon {}", condition));
            }
            statements.join(" ").fmt(f)
        }
    }

    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    pub enum Condition<A: LiteralPrefixSetAfi> {
        Unit(Term<A>),
        And(Term<A>, Term<A>),
        Or(Term<A>, Term<A>),
    }

    impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for Condition<A> {
        type Error = ParseError;

        fn try_from(pair: TokenPair) -> ParseResult<Self> {
            debug_construction!(pair => Condition);
            match pair.as_rule() {
                rule if rule == A::INJECT_COND_UNIT_RULE => Ok(Self::Unit(
                    next_into_or!(pair.into_inner() => "failed to get inject condition term")?,
                )),
                rule if rule == A::INJECT_COND_AND_RULE => {
                    let mut pairs = pair.into_inner();
                    Ok(Self::And(
                        next_into_or!(pairs => "failed to get left inject condition term")?,
                        next_into_or!(pairs => "failed to get right inject condition term")?,
                    ))
                }
                rule if rule == A::INJECT_COND_OR_RULE => {
                    let mut pairs = pair.into_inner();
                    Ok(Self::Or(
                        next_into_or!(pairs => "failed to get left inject condition term")?,
                        next_into_or!(pairs => "failed to get right inject condition term")?,
                    ))
                }
                _ => Err(rule_mismatch!(pair => "inject condition")),
            }
        }
    }

    impl<A: LiteralPrefixSetAfi> fmt::Display for Condition<A> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::Unit(term) => term.fmt(f),
                Self::And(lhs, rhs) => write!(f, "{} AND {}", lhs, rhs),
                Self::Or(lhs, rhs) => write!(f, "{} OR {}", lhs, rhs),
            }
        }
    }

    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    pub enum Term<A: LiteralPrefixSetAfi> {
        HaveComps(ListOf<PrefixRange<A>>),
        Exclude(ListOf<PrefixRange<A>>),
        Static,
    }

    impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for Term<A> {
        type Error = ParseError;

        fn try_from(pair: TokenPair) -> ParseResult<Self> {
            debug_construction!(pair => Term);
            match pair.as_rule() {
                rule if rule == A::INJECT_COND_TERM_HAVE_RULE => Ok(Self::HaveComps(
                    next_into_or!(pair.into_inner() => "failed to get inject have-components condition prefix ranges")?,
                )),
                rule if rule == A::INJECT_COND_TERM_EXCLUDE_RULE => Ok(Self::Exclude(
                    next_into_or!(pair.into_inner() => "failed to get inject exclude condition prefix ranges")?,
                )),
                rule if rule == A::INJECT_COND_TERM_STATIC_RULE => Ok(Self::Static),
                _ => Err(rule_mismatch!(pair => "inject condition term")),
            }
        }
    }

    impl<A: LiteralPrefixSetAfi> fmt::Display for Term<A> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::HaveComps(prefixes) => write!(f, "have-components {}", prefixes),
                Self::Exclude(prefixes) => write!(f, "exclude {}", prefixes),
                Self::Static => write!(f, "static"),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{primitive::RangeOperator, tests::compare_ast};

        compare_ast! {
            InjectExpr {
                rfc2622_fig32_route_example1_1: "at 1.1.1.1 action dpa = 100;" => {
                    InjectExpr {
                        at: Some("1.1.1.1".parse().unwrap()),
                        action: Some("dpa = 100;".parse().unwrap()),
                        condition: None,
                    }
                }
                rfc2622_fig32_route_example1_2: "at 1.1.1.2 action dpa = 110;" => {
                    InjectExpr {
                        at: Some("1.1.1.2".parse().unwrap()),
                        action: Some("dpa = 110;".parse().unwrap()),
                        condition: None,
                    }
                }
                rfc2622_fig32_route_example2: "upon HAVE-COMPONENTS {128.8.0.0/16, 128.9.0.0/16}" => {
                    InjectExpr {
                        at: None,
                        action: None,
                        condition: Some(Condition::Unit(Term::HaveComps(vec![
                            PrefixRange::new("128.8.0.0/16".parse().unwrap(), RangeOperator::None),
                            PrefixRange::new("128.9.0.0/16".parse().unwrap(), RangeOperator::None),
                        ].into_iter().collect())))
                    }
                }
                rfc2622_sect8_2_route_example1: "at 7.7.7.1 action next-hop = 7.7.7.2; cost = 10; upon static" => {
                    InjectExpr {
                        at: Some("7.7.7.1".parse().unwrap()),
                        action: Some("next-hop = 7.7.7.2; cost = 10;".parse().unwrap()),
                        condition: Some(Condition::Unit(Term::Static)),
                    }
                }
                rfc2622_sect8_2_route_example2: "at 7.7.7.1 action next-hop = 7.7.7.3; cost = 20; upon static" => {
                    InjectExpr {
                        at: Some("7.7.7.1".parse().unwrap()),
                        action: Some("next-hop = 7.7.7.3; cost = 20;".parse().unwrap()),
                        condition: Some(Condition::Unit(Term::Static)),
                    }
                }
            }
        }
    }
}

/// RPSL `components` expression for `route` objects. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-8.1
pub type ComponentsExpr = components::Expr<afi::Ipv4>;
impl_from_str!(ParserRule::just_components_expr => ComponentsExpr);

/// RPSL `components` expression for `route6` objects. See [RFC4012].
///
/// [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012#section-3
pub type Components6Expr = components::Expr<afi::Any>;
impl_from_str!(ParserRule::just_components6_expr => Components6Expr);

mod components {
    use super::*;

    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    pub struct Expr<A: LiteralPrefixSetAfi> {
        atomic: bool,
        filter: Option<filter::Expr<A>>,
        proto_terms: ProtocolTerms<A>,
    }

    impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for Expr<A> {
        type Error = ParseError;

        fn try_from(pair: TokenPair) -> ParseResult<Self> {
            debug_construction!(pair => Expr);
            match pair.as_rule() {
                rule if rule == A::COMPONENTS_EXPR_RULE => {
                    let (mut atomic, mut filter, mut proto_terms) =
                        (false, None, ProtocolTerms::default());
                    for inner_pair in pair.into_inner() {
                        match inner_pair.as_rule() {
                            ParserRule::atomic => {
                                atomic = true;
                            }
                            rule if A::match_filter_expr_rule(rule) => {
                                filter = Some(inner_pair.try_into()?);
                            }
                            rule if rule == A::COMPONENTS_PROTO_TERMS_RULE => {
                                proto_terms = inner_pair.try_into()?;
                            }
                            _ => {
                                return Err(
                                    rule_mismatch!(inner_pair => "components expression element"),
                                )
                            }
                        }
                    }
                    Ok(Self {
                        atomic,
                        filter,
                        proto_terms,
                    })
                }
                _ => Err(rule_mismatch!(pair => "components expression")),
            }
        }
    }

    impl<A: LiteralPrefixSetAfi> fmt::Display for Expr<A> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let mut statements = Vec::new();
            if self.atomic {
                statements.push("ATOMIC".to_string());
            }
            if let Some(filter_expr) = &self.filter {
                statements.push(filter_expr.to_string());
            }
            statements.push(self.proto_terms.to_string());
            statements.join(" ").fmt(f)
        }
    }

    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    pub struct ProtocolTerms<A: LiteralPrefixSetAfi>(Vec<ProtocolTerm<A>>);

    impl<A: LiteralPrefixSetAfi> Default for ProtocolTerms<A> {
        fn default() -> Self {
            Self(Vec::default())
        }
    }

    impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for ProtocolTerms<A> {
        type Error = ParseError;

        fn try_from(pair: TokenPair) -> ParseResult<Self> {
            debug_construction!(pair => ProtocolTerms);
            match pair.as_rule() {
                rule if rule == A::COMPONENTS_PROTO_TERMS_RULE => Ok(Self(
                    pair.into_inner()
                        .map(|inner_pair| inner_pair.try_into())
                        .collect::<ParseResult<_>>()?,
                )),
                _ => Err(rule_mismatch!(pair => "components expression protocol terms")),
            }
        }
    }

    impl<A: LiteralPrefixSetAfi> fmt::Display for ProtocolTerms<A> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            self.0
                .iter()
                .map(|term| term.to_string())
                .collect::<Vec<_>>()
                .join(" ")
                .fmt(f)
        }
    }

    impl<A: LiteralPrefixSetAfi> FromIterator<ProtocolTerm<A>> for ProtocolTerms<A> {
        fn from_iter<I>(iter: I) -> Self
        where
            I: IntoIterator<Item = ProtocolTerm<A>>,
        {
            Self(iter.into_iter().collect())
        }
    }

    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    pub struct ProtocolTerm<A: LiteralPrefixSetAfi> {
        protocol: Protocol,
        filter: filter::Expr<A>,
    }

    impl<A: LiteralPrefixSetAfi> TryFrom<TokenPair<'_>> for ProtocolTerm<A> {
        type Error = ParseError;

        fn try_from(pair: TokenPair) -> ParseResult<Self> {
            debug_construction!(pair => ProtocolTerm);
            match pair.as_rule() {
                rule if rule == A::COMPONENTS_PROTO_TERM_RULE => {
                    let mut pairs = pair.into_inner();
                    let protocol = next_into_or!(pairs => "failed to get protocol name")?;
                    let filter = next_into_or!(pairs => "failed to get filter expression")?;
                    Ok(Self { protocol, filter })
                }
                _ => Err(rule_mismatch!(pair => "components protocol term")),
            }
        }
    }

    impl<A: LiteralPrefixSetAfi> fmt::Display for ProtocolTerm<A> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "protocol {} {}", self.protocol, self.filter)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::tests::compare_ast;

        compare_ast! {
            ComponentsExpr {
                rfc2622_fig29_route_example1: "<^AS2>" => {
                    ComponentsExpr {
                        atomic: false,
                        filter: Some("<^AS2>".parse().unwrap()),
                        proto_terms: Default::default(),
                    }
                }
                rfc2622_fig29_route_example2: "\
                    protocol BGP4 {128.8.0.0/16^+}
                    protocol OSPF {128.9.0.0/16^+}" => {
                    ComponentsExpr {
                        atomic: false,
                        filter: None,
                        proto_terms: vec![
                            ProtocolTerm {
                                protocol: Protocol::Bgp4,
                                filter: "{128.8.0.0/16^+}".parse().unwrap(),
                            },
                            ProtocolTerm {
                                protocol: Protocol::Ospf,
                                filter: "{128.9.0.0/16^+}".parse().unwrap(),
                            },
                        ].into_iter().collect(),
                    }
                }
                rfc2622_fig30_route_example1: "{128.8.0.0/15^-}" => {
                    ComponentsExpr {
                        atomic: false,
                        filter: Some("{128.8.0.0/15^-}".parse().unwrap()),
                        proto_terms: Default::default(),
                    }
                }
                rfc2622_fig33_route_example: "{128.8.0.0/16, 128.9.0.0/16}" => {
                    ComponentsExpr {
                        atomic: false,
                        filter: Some("{128.8.0.0/16, 128.9.0.0/16}".parse().unwrap()),
                        proto_terms: Default::default(),
                    }
                }
            }
        }
    }
}

pub use aggr_mtd::AggrMtdExpr;

mod aggr_mtd {
    use super::*;

    /// RPSL `aggr-mtd` expression for `route` and `route6` objects. See [RFC2622].
    ///
    /// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-8.1
    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    pub enum AggrMtdExpr {
        /// `INBOUND` variant.
        Inbound,
        /// `OUTBOUND` variant.
        Outbound(Option<autnum::Expr>),
    }

    impl_from_str!(ParserRule::just_aggr_mtd_expr => AggrMtdExpr);

    impl TryFrom<TokenPair<'_>> for AggrMtdExpr {
        type Error = ParseError;

        fn try_from(pair: TokenPair) -> ParseResult<Self> {
            debug_construction!(pair => AggrMtdExpr);
            match pair.as_rule() {
                ParserRule::aggr_mtd_expr_inbound => Ok(Self::Inbound),
                ParserRule::aggr_mtd_expr_outbound => {
                    let as_expr = if let Some(inner_pair) = pair.into_inner().next() {
                        Some(inner_pair.try_into()?)
                    } else {
                        None
                    };
                    Ok(Self::Outbound(as_expr))
                }
                _ => Err(rule_mismatch!(pair => "aggr-mtd expression")),
            }
        }
    }

    impl fmt::Display for AggrMtdExpr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::Inbound => write!(f, "INBOUND"),
                Self::Outbound(None) => write!(f, "OUTBOUND"),
                Self::Outbound(Some(as_expr)) => write!(f, "OUTBOUND {}", as_expr),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::tests::compare_ast;

        compare_ast! {
            AggrMtdExpr {
                rfc2622_fig30_route_example1: "outbound AS-ANY" => {
                    AggrMtdExpr::Outbound(Some("AS-ANY".parse().unwrap()))
                }
                rfc2622_fig33_route_example: "outbound AS1 or AS2 or AS5" => {
                    AggrMtdExpr::Outbound(Some("AS1 or AS2 or AS5".parse().unwrap()))
                }
                rfc2622_fig34_route_example1: "outbound" => {
                    AggrMtdExpr::Outbound(None)
                }
            }
        }
    }
}
