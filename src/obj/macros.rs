macro_rules! attribute_rule {
    (? $attr:ident) => {
        AttributeRule::new(AttributeType::$attr, false, false)
    };
    (* $attr:ident) => {
        AttributeRule::new(AttributeType::$attr, false, true)
    };
    (+ $attr:ident) => {
        AttributeRule::new(AttributeType::$attr, true, true)
    };
    ($attr:ident) => {
        AttributeRule::new(AttributeType::$attr, true, false)
    };
}
pub(crate) use attribute_rule;

macro_rules! rpsl_object_class {
    (
        $( #[$doc:meta] )*
        $obj:ident {
            class: $class:literal,
            name: $name:ty,
            parser_rule: $rule:pat,
            attributes: [
                $( $attr_type:ident $( ( $attr_rule:tt ) )? ),* $(,)?
            ],
        }
    ) => {
        $(#[$doc])*
        #[derive(Clone, Debug, Hash, PartialEq, Eq)]
        pub struct $obj {
            name: $name,
            attrs: AttributeSeq,
        }

        impl RpslObjectClass for $obj {
            const CLASS: &'static str = $class;
            const ATTRS: &'static [AttributeRule] = &[
                $( $crate::obj::macros::attribute_rule!( $( $attr_rule )? $attr_type) ),*
            ];
            type Name = $name;

            fn new<I>(name: Self::Name, iter: I) -> ValidationResult<Self>
            where
                I: IntoIterator<Item=RpslAttribute>,
            {
                let attrs = Self::validate(iter)?;
                Ok(Self { name, attrs })
            }

            fn name(&self) -> &Self::Name {
                &self.name
            }

            fn attrs(&self) -> &AttributeSeq {
                &self.attrs
            }
        }

        impl TryFrom<TokenPair<'_>> for $obj {
            type Error = ParseError;
            fn try_from(pair: TokenPair) -> ParseResult<Self> {
                $crate::parser::debug_construction!(pair => $obj);
                match pair.as_rule() {
                    $rule => {
                        let mut pairs = pair.into_inner();
                        // TODO: class-specific error msg
                        let name = $crate::parser::next_into_or!(pairs => "failed to get object name")?;
                        let attrs = pairs
                            .map(|inner_pair| {
                                $crate::parser::next_into_or!(inner_pair.into_inner() => "failed to get attribute")
                            })
                            .collect::<ParseResult<Vec<_>>>()?;
                        Ok(Self::new(name, attrs)?)
                    }
                    // TODO: class-specific error msg
                    _ => Err($crate::parser::rule_mismatch!(pair => "object")),
                }
            }
        }

        impl fmt::Display for $obj {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                writeln!(f, "{}: {}", Self::CLASS, self.name)?;
                write!(f, "{}", self.attrs)
            }
        }

        #[cfg(any(test, feature = "arbitrary"))]
        impl proptest::arbitrary::Arbitrary for $obj
        where
            Self: RpslObjectClass,
            <Self as RpslObjectClass>::Name: proptest::arbitrary::Arbitrary,
        {
            type Parameters = proptest::arbitrary::ParamsFor<<Self as RpslObjectClass>::Name>;
            type Strategy = proptest::strategy::BoxedStrategy<Self>;
            fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
                use proptest::strategy::Strategy;
                let name = <Self as RpslObjectClass>::Name::arbitrary_with(params);
                let attrs = <Self as RpslObjectClass>::ATTRS
                    .iter()
                    .map(|rule| {
                        let attr = RpslAttribute::arbitrary_variant(rule.attr);
                        let lower = if !rule.mandatory {0} else {1};
                        let upper = if !rule.multivalued {1} else {4};
                        proptest::collection::vec(attr, lower..=upper)
                    })
                    .collect::<Vec<_>>();
                // let attrs = proptest::collection::vec(RpslAttribute::arbitrary(), 0..8);
                (name, attrs)
                    .prop_map(|(name, attrs)| {
                        <Self as RpslObjectClass>::new(name, attrs.into_iter().flatten())
                            .unwrap()
                    })
                    .boxed()
            }
        }
    }
}
pub(crate) use rpsl_object_class;
