use std::cmp::{Eq, PartialEq};
use std::hash::Hash;

use pest::iterators::Pair;

/// Parser for RSPL filter expressions.
#[derive(Debug, Parser)]
#[grammar = "grammar.pest"]
pub struct RpslParser;

pub type ParserRule = Rule;
pub type TokenPair<'a> = Pair<'a, ParserRule>;

macro_rules! impl_from_str {
    ( $rule:expr => $t:ty ) => {
        impl std::str::FromStr for $t {
            type Err = $crate::error::ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use pest::Parser;
                log::info!(concat!("trying to parse ", stringify!($t), " expression"));
                let root = $crate::parser::RpslParser::parse($rule, s)?
                    .next()
                    .ok_or_else(|| $crate::error::err!("failed to parse expression",))?;
                root.try_into()
            }
        }
    };
    ( forall $( $bound_ty:ident: $bound:path ),+ $(,)? {
        $rule:expr => $t:ty
    } ) => {
        impl<$($bound_ty),+> std::str::FromStr for $t
        where
            $($bound_ty: $bound),+
        {
            type Err = $crate::error::ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use pest::Parser;
                log::info!(concat!("trying to parse ", stringify!($t), " expression"));
                let root = $crate::parser::RpslParser::parse($rule, s)?
                    .next()
                    .ok_or_else(|| $crate::error::err!("failed to parse expression",))?;
                root.try_into()
            }
        }
    };
}
pub(crate) use impl_from_str;

macro_rules! impl_str_primitive {
    ( $( $rule:pat )|+ => $t:ty ) => {
        impl TryFrom<TokenPair<'_>> for $t {
            type Error = ParseError;
            fn try_from(pair: TokenPair) -> ParseResult<Self> {
                $crate::parser::debug_construction!(pair => $t);
                match pair.as_rule() {
                    $( $rule )|+ => Ok(Self(pair.as_str().to_string())),
                    _   => Err($crate::error::err!(
                            concat!("expected a '", stringify!($( $rule )|+), "' expression, got {:?}: {}"),
                            pair.as_rule(),
                            pair.as_str(),
                    )),
                }
            }
        }
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.0.fmt(f)
            }
        }
        impl std::convert::From<&str> for $t {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }
    }
}
pub(crate) use impl_str_primitive;

macro_rules! impl_case_insensitive_str_primitive {
    ( $( $rule:pat )|+ => $t:ty ) => {
        $crate::parser::impl_str_primitive!($( $rule )|+ => $t);
        impl std::cmp::PartialEq for $t {
            fn eq(&self, other: &Self) -> bool {
                self.0.to_uppercase() == other.0.to_uppercase()
            }
        }
        impl std::cmp::Eq for $t {}
        impl std::hash::Hash for $t {
            fn hash<H>(&self, state: &mut H)
            where
                H: std::hash::Hasher,
            {
                self.0.hash(state)
            }
        }
    }
}
pub(crate) use impl_case_insensitive_str_primitive;

macro_rules! next_into_or {
    ( $pairs:expr => $err:literal ) => {
        $pairs
            .next()
            .ok_or_else(|| $crate::error::err!($err))?
            .try_into()
    };
}
pub(crate) use next_into_or;

macro_rules! next_parse_or {
    ( $pairs:expr => $err:literal ) => {
        $pairs
            .next()
            .ok_or_else(|| $crate::error::err!($err))?
            .as_str()
            .parse()
    };
}
pub(crate) use next_parse_or;

macro_rules! debug_construction {
    ( $pair:ident => $node:ty ) => {
        log::debug!(
            concat!(
                "constructing AST node '",
                stringify!($node),
                "' from token pair {:?}: '{}'"
            ),
            $pair.as_rule(),
            $pair.as_str()
        )
    };
}
pub(crate) use debug_construction;

macro_rules! rule_mismatch {
    ( $pair:expr => $expected:literal ) => {
        $crate::error::err!(
            concat!("expected ", $expected, ", got {:?}: '{}'"),
            $pair.as_rule(),
            $pair.as_str(),
        )
    };
}
pub(crate) use rule_mismatch;

#[cfg(test)]
#[allow(non_fmt_panics)]
mod tests {
    use paste::paste;
    use pest::{consumes_to, parses_to};

    use super::*;

    #[test]
    fn parse_aut_num() {
        parses_to! {
            parser: RpslParser,
            input: "AS65000",
            rule: Rule::aut_num,
            tokens: [aut_num(0, 7, [
                num(2, 7)
            ])]
        }
    }

    #[test]
    fn parse_as_set() {
        parses_to! {
            parser: RpslParser,
            input: "AS-FOO",
            rule: Rule::as_set,
            tokens: [as_set(0, 6, [
                as_set_name(0, 6)
            ])]
        }
    }

    #[test]
    fn parse_hierarchical_as_set() {
        parses_to! {
            parser: RpslParser,
            input: "AS65000:AS-FOO",
            rule: Rule::as_set,
            tokens: [as_set(0, 14, [
                aut_num(0, 7, [
                    num(2, 7)
                ]),
                as_set_name(8, 14)
            ])]
        }
    }

    #[test]
    fn parse_hierarchical_peeras_as_set() {
        parses_to! {
            parser: RpslParser,
            input: "AS65000:AS-FOO:PeerAS",
            rule: Rule::as_set,
            tokens: [as_set(0, 21, [
                aut_num(0, 7, [
                    num(2, 7)
                ]),
                as_set_name(8, 14),
                peeras(15, 21)
            ])]
        }
    }

    #[test]
    fn parse_route_set() {
        parses_to! {
            parser: RpslParser,
            input: "RS-FOO",
            rule: Rule::route_set,
            tokens: [route_set(0, 6, [
                route_set_name(0, 6)
            ])]
        }
    }

    #[test]
    fn parse_hierarchical_route_set() {
        parses_to! {
            parser: RpslParser,
            input: "RS-FOO:RS-BAR",
            rule: Rule::route_set,
            tokens: [route_set(0, 13, [
                route_set_name(0, 6),
                route_set_name(7, 13)
            ])]
        }
    }

    #[test]
    fn parse_filter_set() {
        parses_to! {
            parser: RpslParser,
            input: "FLTR-FOO",
            rule: Rule::filter_set,
            tokens: [filter_set(0, 8, [
                filter_set_name(0, 8)
            ])]
        }
    }

    #[test]
    fn parse_hierarchical_filter_set() {
        parses_to! {
            parser: RpslParser,
            input: "AS65000:FLTR-FOO:PeerAS",
            rule: Rule::filter_set,
            tokens: [filter_set(0, 23, [
                aut_num(0, 7, [
                    num(2, 7)
                ]),
                filter_set_name(8, 16),
                peeras(17, 23)
            ])]
        }
    }

    #[test]
    fn parse_ipv4_prefix() {
        parses_to! {
            parser: RpslParser,
            input: "192.0.2.0/24",
            rule: Rule::ipv4_prefix,
            tokens: [ipv4_prefix(0, 12)]
        }
    }

    #[test]
    fn parse_ipv6_prefix() {
        parses_to! {
            parser: RpslParser,
            input: "2001:db8::/32",
            rule: Rule::ipv6_prefix,
            tokens: [ipv6_prefix(0, 13)]
        }
    }

    #[test]
    fn parse_ipv4_prefix_range() {
        parses_to! {
            parser: RpslParser,
            input: "192.0.2.0/24^-",
            rule: Rule::ranged_prefix,
            tokens: [
                ranged_prefix(0, 14, [
                    ipv4_prefix(0, 12),
                    less_excl(12, 14)
                ])
            ]
        }
    }

    #[test]
    fn parse_ipv6_prefix_range() {
        parses_to! {
            parser: RpslParser,
            input: "2001:db8:f00::/48^+",
            rule: Rule::mp_ranged_prefix,
            tokens: [
                mp_ranged_prefix(0, 19, [
                    ipv6_prefix(0, 17),
                    less_incl(17, 19)
                ])
            ]
        }
    }

    #[test]
    fn parse_ipv4_literal_prefix_set_singleton() {
        parses_to! {
            parser: RpslParser,
            input: "{ 192.0.2.0/24^26 }",
            rule: Rule::literal_prefix_set,
            tokens: [
                literal_prefix_set(0, 19, [
                    ranged_prefix(2, 17, [
                        ipv4_prefix(2, 14),
                        exact(14, 17, [
                            num(15, 17)
                        ])
                    ])
                ])
            ]
        }
    }

    #[test]
    fn parse_ipv6_literal_prefix_set_singleton() {
        parses_to! {
            parser: RpslParser,
            input: "{ 2001:db8::/32^48 }",
            rule: Rule::mp_literal_prefix_set,
            tokens: [
                mp_literal_prefix_set(0, 20, [
                    mp_ranged_prefix(2, 18, [
                        ipv6_prefix(2, 15),
                        exact(15, 18, [
                            num(16, 18)
                        ])
                    ])
                ])
            ]
        }
    }

    #[test]
    fn parse_ipv4_literal_prefix_set_multiple() {
        parses_to! {
            parser: RpslParser,
            input: "{ 192.0.2.0/24, 10.0.0.0/8^+, }",
            rule: Rule::literal_prefix_set,
            tokens: [
                literal_prefix_set(0, 31, [
                    ranged_prefix(2, 14, [
                        ipv4_prefix(2, 14)
                    ]),
                    ranged_prefix(16, 28, [
                        ipv4_prefix(16, 26),
                        less_incl(26, 28)
                    ])
                ])
            ]
        }
    }

    #[test]
    fn parse_mixed_literal_prefix_set_multiple() {
        parses_to! {
            parser: RpslParser,
            input: "{ 2001:db8:baa::/48^56-64, 10.0.0.0/8^+, }",
            rule: Rule::mp_literal_prefix_set,
            tokens: [
                mp_literal_prefix_set(0, 42, [
                    mp_ranged_prefix(2, 25, [
                        ipv6_prefix(2, 19),
                        range(19, 25, [
                            num(20, 22),
                            num(23, 25)
                        ])
                    ]),
                    mp_ranged_prefix(27, 39, [
                        ipv4_prefix(27, 37),
                        less_incl(37, 39)
                    ])
                ])
            ]
        }
    }

    #[test]
    fn parse_named_prefix_set_any() {
        parses_to! {
            parser: RpslParser,
            input: "RS-ANY",
            rule: Rule::named_prefix_set,
            tokens: [
                named_prefix_set(0, 6, [
                    any_rs(0, 6)
                ])
            ]
        }
    }

    #[test]
    fn parse_named_prefix_set_peeras() {
        parses_to! {
            parser: RpslParser,
            input: "PeerAS",
            rule: Rule::named_prefix_set,
            tokens: [
                named_prefix_set(0, 6, [
                    peeras(0, 6)
                ])
            ]
        }
    }

    #[test]
    fn parse_named_prefix_set_aut_num() {
        parses_to! {
            parser: RpslParser,
            input: "AS65512",
            rule: Rule::named_prefix_set,
            tokens: [
                named_prefix_set(0, 7, [
                    aut_num(0, 7, [
                        num(2, 7)
                    ])
                ])
            ]
        }
    }

    #[test]
    fn parse_named_prefix_set_as_set() {
        parses_to! {
            parser: RpslParser,
            input: "AS-BAR",
            rule: Rule::named_prefix_set,
            tokens: [
                named_prefix_set(0, 6, [
                    as_set(0, 6, [
                        as_set_name(0, 6)
                    ])
                ])
            ]
        }
    }

    #[test]
    fn parse_literal_filter_ranged_as_set() {
        parses_to! {
            parser: RpslParser,
            input: "AS-BAR^+",
            rule: Rule::literal_filter,
            tokens: [
                literal_filter(0, 8, [
                    ranged_prefix_set(0, 8, [
                        named_prefix_set(0, 6, [
                            as_set(0, 6, [
                                as_set_name(0, 6)
                            ])
                        ]),
                        less_incl(6, 8)
                    ])
                ])
            ]
        }
    }

    #[test]
    fn empty_action_val_nested_list() {
        parses_to! {
            parser: RpslParser,
            input: "pref = {};",
            rule: Rule::action_expr,
            tokens: [
                action_expr(0, 10, [
                    action_stmt_oper(0, 9, [
                        rp_pref(0, 4),
                        action_op_assign(5, 6),
                        action_val_nested(7, 9, [
                            action_val_list(8, 8)
                        ]),
                    ])
                ])
            ]
        }
    }

    macro_rules! parse_filter {
        ( $( $name:ident: $filter:expr => [ $( $names:ident $calls:tt ),* $(,)* ] ),* $(,)? ) => {
            paste! {
                $(
                    #[test]
                    fn [< $name _filter_parses >]() {
                        parses_to! {
                            parser: RpslParser,
                            input: $filter,
                            rule: Rule::just_filter_expr,
                            tokens: [ $( $names $calls ),* ]
                        }
                    }
                )*
            }
        }
    }

    parse_filter! {
        empty_literal: "{}" => [
            filter_expr_unit(0, 2, [
                literal_filter(0, 2, [
                    ranged_prefix_set(0, 2, [
                        literal_prefix_set(0, 2)
                    ])
                ])
            ])
        ],
        singleton_literal: "{ 10.0.0.0/0 }" => [
            filter_expr_unit(0, 14, [
                literal_filter(0, 14, [
                    ranged_prefix_set(0, 14, [
                        literal_prefix_set(0, 14, [
                            ranged_prefix(2, 12, [
                                ipv4_prefix(2, 12)
                            ])
                        ])
                    ])
                ])
            ])
        ],
        single_filter_set: "FLTR-FOO" => [
            filter_expr_unit(0, 8, [
                named_filter(0, 8, [
                    filter_set(0, 8, [
                        filter_set_name(0, 8)
                    ])
                ])
            ])
        ],
        single_as_set: "AS-FOO" => [
            filter_expr_unit(0, 6, [
                literal_filter(0, 6, [
                    ranged_prefix_set(0, 6, [
                        named_prefix_set(0, 6, [
                            as_set(0, 6, [
                                as_set_name(0, 6)
                            ])
                        ])
                    ])
                ])
            ])
        ],
        parens_as_set: "(AS-FOO)" => [
            filter_expr_unit(0, 8, [
                filter_expr_unit(1, 7, [
                    literal_filter(1, 7, [
                        ranged_prefix_set(1, 7, [
                            named_prefix_set(1, 7, [
                                as_set(1, 7, [
                                    as_set_name(1, 7)
                                ])
                            ])
                        ])
                    ])
                ])
            ])
        ],
        not_expr: "NOT AS65000" => [
            filter_expr_not(0, 11, [
                filter_expr_unit(4, 11, [
                    literal_filter(4, 11, [
                        ranged_prefix_set(4, 11, [
                            named_prefix_set(4, 11, [
                                aut_num(4, 11, [
                                    num(6, 11)
                                ])
                            ])
                        ])
                    ])
                ])
            ])
        ],
        and_expr: "{ 192.0.2.0/24 } AND AS-FOO" => [
            filter_expr_and(0, 27, [
                literal_filter(0, 16, [
                    ranged_prefix_set(0, 16, [
                        literal_prefix_set(0, 16, [
                            ranged_prefix(2, 14, [
                                ipv4_prefix(2, 14)
                            ])
                        ])
                    ])
                ]),
                filter_expr_unit(21, 27, [
                    literal_filter(21, 27, [
                        ranged_prefix_set(21, 27, [
                            named_prefix_set(21, 27, [
                                as_set(21, 27, [
                                    as_set_name(21, 27)
                                ])
                            ])
                        ])
                    ])
                ])
            ])
        ],
        or_expr: "FLTR-FOO OR RS-BAR" => [
            filter_expr_or(0, 18, [
                named_filter(0, 8, [
                    filter_set(0, 8, [
                        filter_set_name(0, 8)
                    ])
                ]),
                filter_expr_unit(12, 18, [
                    literal_filter(12, 18, [
                        ranged_prefix_set(12, 18, [
                            named_prefix_set(12, 18, [
                                route_set(12, 18, [
                                    route_set_name(12, 18)
                                ])
                            ])
                        ])
                    ])
                ])
            ])
        ],
        complex_expr: "((PeerAS^+ OR AS65000:AS-FOO:PeerAS^+) AND {0.0.0.0/0^8-24})" => [
            filter_expr_unit(0, 60, [
                filter_expr_and(1, 59, [
                    filter_expr_or(2, 37, [
                        literal_filter(2, 10, [
                            ranged_prefix_set(2, 10, [
                                named_prefix_set(2, 8, [
                                    peeras(2, 8)
                                ]),
                                less_incl(8, 10)
                            ])
                        ]),
                        filter_expr_unit(14, 37, [
                            literal_filter(14, 37, [
                                ranged_prefix_set(14, 37, [
                                    named_prefix_set(14, 35, [
                                        as_set(14, 35, [
                                            aut_num(14, 21, [
                                                num(16, 21)
                                            ]),
                                            as_set_name(22, 28),
                                            peeras(29, 35)
                                        ])
                                    ]),
                                    less_incl(35, 37)
                                ])
                            ])
                        ])
                    ]),
                    filter_expr_unit(43, 59, [
                        literal_filter(43, 59, [
                            ranged_prefix_set(43, 59, [
                                literal_prefix_set(43, 59, [
                                    ranged_prefix(44, 58, [
                                        ipv4_prefix(44, 53),
                                        range(53, 58, [
                                            num(54, 55),
                                            num(56, 58)
                                        ])
                                    ])
                                ])
                            ])
                        ])
                    ])
                ])
            ])
        ]
    }
}
