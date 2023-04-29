//!  A parser and syntax tree implementation for the Routing Policy
//!  Specification Language (RPSL) defined in [RFC2622] and [RFC4012].
//!
//! [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622
//! [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012
// clippy lints
#![warn(clippy::pedantic)]
#![warn(clippy::cargo)]
#![warn(clippy::nursery)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::multiple_crate_versions)]
// rustc lints
#![allow(box_pointers)]
#![warn(absolute_paths_not_starting_with_crate)]
#![warn(deprecated_in_future)]
#![warn(elided_lifetimes_in_paths)]
#![warn(explicit_outlives_requirements)]
#![warn(keyword_idents)]
#![warn(macro_use_extern_crate)]
#![warn(meta_variable_misuse)]
#![warn(missing_abi)]
#![warn(missing_copy_implementations)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(non_ascii_idents)]
#![warn(noop_method_call)]
#![warn(pointer_structural_match)]
#![warn(rust_2021_incompatible_closure_captures)]
#![warn(rust_2021_incompatible_or_patterns)]
#![warn(rust_2021_prefixes_incompatible_syntax)]
#![warn(rust_2021_prelude_collisions)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unreachable_pub)]
#![warn(unsafe_code)]
#![warn(unsafe_op_in_unsafe_fn)]
#![warn(unstable_features)]
#![warn(unused_crate_dependencies)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_lifetimes)]
#![warn(unused_qualifications)]
#![warn(unused_results)]
#![warn(variant_size_differences)]
// docs.rs build config
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc(html_root_url = "https://docs.rs/rpsl/0.1.0-alpha.1")]

// silence unused dev-dependency warnings
#[cfg(test)]
mod deps {
    use version_sync as _;
}

mod parser;

/// RPSL attributes.
pub mod attr;
/// RPSL container-like syntax types.
pub mod containers;
/// Error types
pub mod error;
/// RPSL policy and filter expressions.
pub mod expr;
/// RPSL object class names.
pub mod names;
/// RPSL objects.
pub mod obj;
/// Primitive RPSL syntax types.
pub mod primitive;

#[cfg(test)]
mod tests;
