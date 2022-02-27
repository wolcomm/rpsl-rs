macro_rules! display_fmt_parses {
    ( $( $t:ty ),* $(,)? ) => {
        paste::paste! {
            $(
                mod [<$t:snake>] {
                    use super::*;

                    proptest::proptest! {
                        #![proptest_config(proptest::prelude::ProptestConfig {
                            max_shrink_iters: 10000,
                            ..proptest::prelude::ProptestConfig::default()
                        })]
                        #[test]
                        fn display_fmt_parses(obj in proptest::prelude::any::<$t>()) {
                            let display = dbg!(obj.to_string());
                            let parsed = dbg!(display.parse().unwrap());
                            assert_eq!(obj, parsed)
                        }
                    }
                }
            )*
        }
    }
}
pub(crate) use display_fmt_parses;

macro_rules! compare_ast {
    (
        $( $root_ty:ty {
            $( $name:ident: $input:literal => {
                $ast:expr
            } )*
        } )*
    ) => {
        paste::paste! {
            $(
                mod [<compare_ast_for_ $root_ty:snake>] {
                    use super::*;
                    $(
                        #[test]
                        fn [<$name>]() {
                            let input = $input;
                            let expect: $root_ty = $ast;
                            let ast = dbg!(input.parse::<$root_ty>().unwrap());
                            assert_eq!(ast, expect);
                        }
                    )*
                }
            )*

        }
    }
}
pub(crate) use compare_ast;
