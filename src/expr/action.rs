use std::convert::{TryFrom, TryInto};
use std::fmt;

#[cfg(any(test, feature = "arbitrary"))]
use proptest::{arbitrary::ParamsFor, prelude::*};

use crate::{
    error::{ParseError, ParseResult},
    parser::{
        debug_construction, impl_case_insensitive_str_primitive, impl_from_str, next_into_or,
        rule_mismatch, ParserRule, TokenPair,
    },
};

/// RPSL `action` expression. See [RFC2622].
///
/// [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622#section-6.1.1
pub type ActionExpr = Expr;
impl_from_str!(ParserRule::just_action_expr => Expr);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Expr(Vec<Stmt>);

impl TryFrom<TokenPair<'_>> for Expr {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Expr);
        match pair.as_rule() {
            ParserRule::action_expr => Ok(Self(
                pair.into_inner()
                    .map(|inner_pair| inner_pair.try_into())
                    .collect::<ParseResult<_>>()?,
            )),
            _ => Err(rule_mismatch!(pair => "action expression")),
        }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s = self
            .0
            .iter()
            .map(|stmt| stmt.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        s.push(';');
        s.fmt(f)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Expr {
    type Parameters = ParamsFor<Stmt>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        prop::collection::vec(any_with::<Stmt>(params), 1..8)
            .prop_map(Self)
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Stmt {
    Operator(OperatorStmt),
    Method(MethodStmt),
}

impl TryFrom<TokenPair<'_>> for Stmt {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Stmt);
        match pair.as_rule() {
            ParserRule::action_stmt_oper => Ok(Self::Operator(pair.try_into()?)),
            ParserRule::action_stmt_meth => Ok(Self::Method(pair.try_into()?)),
            _ => Err(rule_mismatch!(pair => "action expression statement")),
        }
    }
}

impl fmt::Display for Stmt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Operator(stmt) => stmt.fmt(f),
            Self::Method(stmt) => stmt.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Stmt {
    type Parameters = ParamsFor<MethodStmt>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<OperatorStmt>().prop_map(Self::Operator),
            any_with::<MethodStmt>(params).prop_map(Self::Method),
        ]
        .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct OperatorStmt {
    prop: Property,
    op: Operator,
    val: Value,
}

impl TryFrom<TokenPair<'_>> for OperatorStmt {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => OperatorStmt);
        match pair.as_rule() {
            ParserRule::action_stmt_oper => {
                let mut pairs = pair.into_inner();
                Ok(Self {
                    prop: next_into_or!(pairs => "failed to get action property")?,
                    op: next_into_or!(pairs => "failed to get action operator")?,
                    val: next_into_or!(pairs => "failed to get action operand")?,
                })
            }
            _ => Err(rule_mismatch!(pair => "action expression operator statement")),
        }
    }
}

impl fmt::Display for OperatorStmt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {}", self.prop, self.op, self.val)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for OperatorStmt {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (any::<Property>(), any::<Operator>(), any::<Value>())
            .prop_map(|(prop, op, val)| Self { prop, op, val })
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct MethodStmt {
    prop: Property,
    method: Option<Method>,
    val: Value,
}

impl TryFrom<TokenPair<'_>> for MethodStmt {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => MethodStmt);
        match pair.as_rule() {
            ParserRule::action_stmt_meth => {
                let mut pairs = pair.into_inner().peekable();
                let prop = next_into_or!(pairs => "failed to get action property")?;
                let method = if let Some(ParserRule::action_meth) =
                    pairs.peek().map(|pair| pair.as_rule())
                {
                    Some(next_into_or!(pairs => "failed to get action method")?)
                } else {
                    None
                };
                let val = next_into_or!(pairs => "failed to get action operand")?;
                Ok(Self { prop, method, val })
            }
            _ => Err(rule_mismatch!(pair => "action expression method statement")),
        }
    }
}

impl fmt::Display for MethodStmt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.prop)?;
        if let Some(method) = &self.method {
            write!(f, ".{}", method)?;
        }
        write!(f, "({})", self.val)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for MethodStmt {
    type Parameters = ParamsFor<Option<Method>>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        (
            any::<Property>(),
            any_with::<Option<Method>>(params),
            any::<Value>(),
        )
            .prop_map(|(prop, method, val)| Self { prop, method, val })
            .boxed()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Property {
    Pref,
    Med,
    Dpa,
    AsPath,
    Community,
    NextHop,
    Cost,
    Unknown(UnknownProperty),
}

impl TryFrom<TokenPair<'_>> for Property {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Property);
        match pair.as_rule() {
            ParserRule::rp_pref => Ok(Self::Pref),
            ParserRule::rp_med => Ok(Self::Med),
            ParserRule::rp_dpa => Ok(Self::Dpa),
            ParserRule::rp_aspath => Ok(Self::AsPath),
            ParserRule::rp_community => Ok(Self::Community),
            ParserRule::rp_next_hop => Ok(Self::NextHop),
            ParserRule::rp_cost => Ok(Self::Cost),
            ParserRule::rp_unknown => Ok(Self::Unknown(pair.try_into()?)),
            _ => Err(rule_mismatch!(pair => "action property name")),
        }
    }
}

impl fmt::Display for Property {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Pref => write!(f, "pref"),
            Self::Med => write!(f, "med"),
            Self::Dpa => write!(f, "dpa"),
            Self::AsPath => write!(f, "aspath"),
            Self::Community => write!(f, "community"),
            Self::NextHop => write!(f, "next-hop"),
            Self::Cost => write!(f, "cost"),
            Self::Unknown(property) => property.fmt(f),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Property {
    type Parameters = ParamsFor<UnknownProperty>;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(Self::Pref),
            Just(Self::Med),
            Just(Self::Dpa),
            Just(Self::AsPath),
            Just(Self::Community),
            Just(Self::NextHop),
            Just(Self::Cost),
            any_with::<UnknownProperty>(params).prop_map(Self::Unknown),
        ]
        .boxed()
    }
}

#[derive(Clone, Debug)]
pub struct UnknownProperty(String);
impl_case_insensitive_str_primitive!(ParserRule::rp_unknown => UnknownProperty);

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for UnknownProperty {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        r"[A-Za-z]([0-9A-Za-z_-]*[0-9A-Za-z])?"
            .prop_map(Self)
            .boxed()
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Operator {
    Assign,
    Append,
    LshAssign,
    RshAssign,
    AddAssign,
    SubAssign,
    MulAssign,
    DivAssign,
    Eq,
    Ne,
    Le,
    Ge,
    Lt,
    Gt,
}

impl TryFrom<TokenPair<'_>> for Operator {
    type Error = ParseError;

    fn try_from(pair: TokenPair) -> ParseResult<Self> {
        debug_construction!(pair => Operator);
        match pair.as_rule() {
            ParserRule::action_op_assign => Ok(Self::Assign),
            ParserRule::action_op_append => Ok(Self::Append),
            ParserRule::action_op_lsh_assign => Ok(Self::LshAssign),
            ParserRule::action_op_rsh_assign => Ok(Self::RshAssign),
            ParserRule::action_op_add_assign => Ok(Self::AddAssign),
            ParserRule::action_op_sub_assign => Ok(Self::SubAssign),
            ParserRule::action_op_mul_assign => Ok(Self::MulAssign),
            ParserRule::action_op_div_assign => Ok(Self::DivAssign),
            ParserRule::action_op_eq => Ok(Self::Eq),
            ParserRule::action_op_ne => Ok(Self::Ne),
            ParserRule::action_op_le => Ok(Self::Le),
            ParserRule::action_op_ge => Ok(Self::Ge),
            ParserRule::action_op_lt => Ok(Self::Lt),
            ParserRule::action_op_gt => Ok(Self::Gt),
            _ => Err(rule_mismatch!(pair => "action expression operator")),
        }
    }
}

impl fmt::Display for Operator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Assign => write!(f, "="),
            Self::Append => write!(f, ".="),
            Self::LshAssign => write!(f, "<<="),
            Self::RshAssign => write!(f, ">>="),
            Self::AddAssign => write!(f, "+="),
            Self::SubAssign => write!(f, "-="),
            Self::MulAssign => write!(f, "*="),
            Self::DivAssign => write!(f, "/="),
            Self::Eq => write!(f, "=="),
            Self::Ne => write!(f, "!="),
            Self::Le => write!(f, "<="),
            Self::Ge => write!(f, ">="),
            Self::Lt => write!(f, "<"),
            Self::Gt => write!(f, ">"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Operator {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(Self::Assign),
            Just(Self::Append),
            Just(Self::LshAssign),
            Just(Self::RshAssign),
            Just(Self::AddAssign),
            Just(Self::SubAssign),
            Just(Self::MulAssign),
            Just(Self::DivAssign),
            Just(Self::Eq),
            Just(Self::Ne),
            Just(Self::Le),
            Just(Self::Ge),
            Just(Self::Lt),
            Just(Self::Gt),
        ]
        .boxed()
    }
}

#[derive(Clone, Debug)]
pub struct Method(String);
impl_case_insensitive_str_primitive!(ParserRule::action_meth => Method);

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Method {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        r"[A-Za-z]([0-9A-Za-z_-]*[0-9A-Za-z])?"
            .prop_map(Self)
            .boxed()
    }
}

#[derive(Clone, Debug)]
pub struct Value(String);
impl_case_insensitive_str_primitive!(ParserRule::action_val => Value);

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for Value {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        r"[0-9A-Za-z]+".prop_map(Self).boxed()
    }
}

// #[derive(Clone, Debug, Hash, PartialEq, Eq)]
// pub enum Value {
//     EmailAddr(EmailAddress),
//     AutNum(AutNum),
//     Ipv4Addr(Ipv4Addr),
//     Ipv4Prefix(Ipv4Net),
//     Ipv4PrefixRange(PrefixRange<Ipv4>),
//     Ipv6Addr(Ipv6Addr),
//     Ipv6Prefix(Ipv6Net),
//     Ipv6PrefixRange(PrefixRange<Ipv6>),
//     DnsName(DnsName),
//     Filter(MpFilterExpr),
//     AsSet(AsSet),
//     RouteSet(RouteSet),
//     RtrSet(RtrSet),
//     FilterSet(FilterSet),
//     PeeringSet(PeeringSet),
//     Num(u64),
//     Unknown(String),
// }

// impl TryFrom<TokenPair<'_>> for Value {
//     type Error = ParseError;

//     fn try_from(pair: TokenPair) -> ParseResult<Self> {
//         debug_construction!(pair => Value);
//         match pair.as_rule() {
//             ParserRule::email_addr => Ok(Self::EmailAddr(pair.try_into()?)),
//             ParserRule::aut_num => Ok(Self::AutNum(pair.try_into()?)),
//             ParserRule::ipv4_addr => Ok(Self::Ipv4Addr(pair.as_str().parse()?)),
//             ParserRule::ipv4_prefix => Ok(Self::Ipv4Prefix(pair.as_str().parse()?)),
//             ParserRule::ipv4_prefix_range => Ok(Self::Ipv4PrefixRange(pair.try_into()?)),
//             ParserRule::ipv6_addr => Ok(Self::Ipv6Addr(pair.as_str().parse()?)),
//             ParserRule::ipv6_prefix => Ok(Self::Ipv6Prefix(pair.as_str().parse()?)),
//             ParserRule::ipv6_prefix_range => Ok(Self::Ipv6PrefixRange(pair.try_into()?)),
//             ParserRule::dns_name => Ok(Self::DnsName(pair.try_into()?)),
//             ParserRule::mp_filter_expr_unit
//             | ParserRule::mp_filter_expr_and
//             | ParserRule::mp_filter_expr_or
//             | ParserRule::mp_filter_expr_not => Ok(Self::Filter(pair.try_into()?)),
//             ParserRule::as_set => Ok(Self::AsSet(pair.try_into()?)),
//             ParserRule::route_set => Ok(Self::RouteSet(pair.try_into()?)),
//             ParserRule::rtr_set => Ok(Self::RtrSet(pair.try_into()?)),
//             ParserRule::filter_set => Ok(Self::FilterSet(pair.try_into()?)),
//             ParserRule::peering_set => Ok(Self::PeeringSet(pair.try_into()?)),
//             ParserRule::num => Ok(Self::Num(pair.as_str().parse()?)),
//             ParserRule::action_val_unknown => Ok(Self::Unknown(pair.as_str().to_owned())),
//             _ => Err(rule_mismatch!(pair => "action expression operand value")),
//         }
//     }
// }

// impl fmt::Display for Value {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         match self {
//             Self::EmailAddr(val) => val.fmt(f),
//             Self::AutNum(val) => val.fmt(f),
//             Self::Ipv4Addr(val) => val.fmt(f),
//             Self::Ipv4Prefix(val) => val.fmt(f),
//             Self::Ipv4PrefixRange(val) => val.fmt(f),
//             Self::Ipv6Addr(val) => val.fmt(f),
//             Self::Ipv6Prefix(val) => val.fmt(f),
//             Self::Ipv6PrefixRange(val) => val.fmt(f),
//             Self::DnsName(val) => val.fmt(f),
//             Self::Filter(val) => val.fmt(f),
//             Self::AsSet(val) => val.fmt(f),
//             Self::RouteSet(val) => val.fmt(f),
//             Self::RtrSet(val) => val.fmt(f),
//             Self::FilterSet(val) => val.fmt(f),
//             Self::PeeringSet(val) => val.fmt(f),
//             Self::Num(val) => val.fmt(f),
//             Self::Unknown(val) => val.fmt(f),
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{compare_ast, display_fmt_parses};

    display_fmt_parses! {
        ActionExpr,
    }

    compare_ast! {
        ActionExpr {
            rfc2622_sect6_autnum_example1: "pref = 1;" => {
                Expr(vec![Stmt::Operator(OperatorStmt {
                    prop: Property::Pref,
                    op: Operator::Assign,
                    val: Value("1".into()),
                })])
            }
            rfc2622_sect6_autnum_example2: "\
            pref = 10; med = 0; community.append(10250, 3561:10);" => {
                Expr(vec![
                    Stmt::Operator(OperatorStmt {
                        prop: Property::Pref,
                        op: Operator::Assign,
                        val: Value("10".into()),
                    }),
                    Stmt::Operator(OperatorStmt {
                        prop: Property::Med,
                        op: Operator::Assign,
                        val: Value("0".into()),
                    }),
                    Stmt::Method(MethodStmt {
                        prop: Property::Community,
                        method: Some("append".into()),
                        val: Value("10250, 3561:10".into())
                    })
                ])
            }
        }
    }
}
