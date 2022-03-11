//!  A parser and syntax tree implementation for the Routing Policy
//!  Specification Language (RPSL) defined in [RFC2622] and [RFC4012].
//!
//! [RFC2622]: https://datatracker.ietf.org/doc/html/rfc2622
//! [RFC4012]: https://datatracker.ietf.org/doc/html/rfc4012
#![doc(html_root_url = "https://docs.rs/rpsl/0.1.0-alpha.1")]
#![warn(missing_docs)]

#[macro_use]
extern crate pest_derive;

mod parser;

/// AFI definitions.
pub mod addr_family;
/// RPSL attributes.
pub mod attr;
/// Error types
pub mod error;
/// RPSL policy and filter expressions.
pub mod expr;
/// RPSL list-like syntax types.
pub mod list;
/// RPSL object class names.
pub mod names;
/// RPSL objects.
pub mod obj;
/// Primitive RPSL syntax types.
pub mod primitive;

#[cfg(test)]
mod tests;
