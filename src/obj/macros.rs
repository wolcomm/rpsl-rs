macro_rules! attribute_rule {
    (? $attr:ident) => {
        $crate::obj::AttributeRule::new($crate::attr::AttributeType::$attr, false, false)
    };
    (* $attr:ident) => {
        $crate::obj::AttributeRule::new($crate::attr::AttributeType::$attr, false, true)
    };
    (+ $attr:ident) => {
        $crate::obj::AttributeRule::new($crate::attr::AttributeType::$attr, true, true)
    };
    ($attr:ident) => {
        $crate::obj::AttributeRule::new($crate::attr::AttributeType::$attr, true, false)
    };
}
pub(super) use attribute_rule;

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
        rpsl_object_class! {
            $( #[$doc] )*
            $obj {
                class: $class,
                name: $name,
                key: $name,
                parser_rule: $rule,
                attributes: [
                    $( $attr_type $( ($attr_rule) )?, )*
                ],
            }
        }
    };

    (
        $( #[$doc:meta] )*
        $obj:ident {
            class: $class:literal,
            name: $name:ty,
            key: $key:ty,
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
            attrs: $crate::attr::AttributeSeq,
        }

        impl $crate::obj::RpslObjectClass for $obj {
            const CLASS: &'static str = $class;
            const ATTRS: &'static [$crate::obj::AttributeRule] = &[
                $( $crate::obj::macros::attribute_rule!( $( $attr_rule )? $attr_type) ),*
            ];
            type Name = $name;

            fn new<I>(name: Self::Name, iter: I) -> $crate::error::ValidationResult<Self>
            where
                I: ::std::iter::IntoIterator<Item=$crate::attr::RpslAttribute>,
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

        impl ::std::convert::TryFrom<$crate::parser::TokenPair<'_>> for $obj {
            type Error = $crate::error::ParseError;
            fn try_from(pair: $crate::parser::TokenPair<'_>) -> $crate::error::ParseResult<Self> {
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
                            .collect::<$crate::error::ParseResult<Vec<_>>>()?;
                        Ok(Self::new(name, attrs)?)
                    }
                    // TODO: class-specific error msg
                    _ => Err($crate::parser::rule_mismatch!(pair => "object")),
                }
            }
        }

        impl ::std::fmt::Display for $obj {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                writeln!(f, "{}: {}", Self::CLASS, self.name)?;
                write!(f, "{}", self.attrs)
            }
        }

        #[cfg(any(test, feature = "arbitrary"))]
        impl ::proptest::arbitrary::Arbitrary for $obj
        where
            Self: $crate::obj::RpslObjectClass,
            <Self as $crate::obj::RpslObjectClass>::Name: ::proptest::arbitrary::Arbitrary,
        {
            type Parameters = ::proptest::arbitrary::ParamsFor<<Self as $crate::obj::RpslObjectClass>::Name>;
            type Strategy = ::proptest::strategy::BoxedStrategy<Self>;
            fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
                use ::proptest::strategy::Strategy as _;
                let name = <Self as $crate::obj::RpslObjectClass>::Name::arbitrary_with(params);
                let attrs = <Self as $crate::obj::RpslObjectClass>::ATTRS
                    .iter()
                    .map(|rule| {
                        let attr = $crate::attr::RpslAttribute::arbitrary_variant(rule.attr);
                        let lower = if !rule.mandatory {0} else {1};
                        let upper = if !rule.multivalued {1} else {4};
                        ::proptest::collection::vec(attr, lower..=upper)
                    })
                    .collect::<Vec<_>>();
                (name, attrs)
                    .prop_map(|(name, attrs)| {
                        <Self as $crate::obj::RpslObjectClass>::new(name, attrs.into_iter().flatten())
                            .unwrap()
                    })
                    .boxed()
            }
        }

        impl $crate::obj::ObjectKey for $key {
            type Class = $obj;
        }
    }
}
pub(super) use rpsl_object_class;
