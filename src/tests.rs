macro_rules! display_fmt_parses {
    ( $( $t:ty ),* $(,)? ) => {
        paste! {
            $(
                mod [<$t:snake>] {
                    use super::*;

                    proptest! {
                        #![proptest_config(ProptestConfig {
                            max_shrink_iters: 1000,
                            ..ProptestConfig::default()
                        })]
                        #[test]
                        fn display_fmt_parses(obj in any::<$t>()) {
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
