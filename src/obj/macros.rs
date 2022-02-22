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
    }
}
pub(crate) use rpsl_object_class;
