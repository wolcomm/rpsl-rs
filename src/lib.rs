//!  A parser and syntax tree implementation for the Routing Policy
//!  Specification Language (RPSL) defined in [RFC2622] and [RFC4012].
//!
//! # Example
//!
//! ``` rust
//! use std::error::Error;
//! use rpsl::{
//!     expr::MpFilterExpr,
//!     names::AutNum,
//!     subst::Substitute,
//! };
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     let peeras = "AS65000".parse::<AutNum>()?;
//!     let filter = "PeerAS:AS-FOO AND {0.0.0.0/0^8-24, ::/0^16-48}"
//!         .parse::<MpFilterExpr>()?
//!         .substitute(&peeras)?;
//!
//!     assert_eq!(filter.to_string(), "AS65000:AS-FOO AND {0.0.0.0/0^8-24, ::/0^16-48}");
//!     Ok(())
//! }
//! ```
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
/// RPSL set member elements.
pub mod members;
/// RPSL object class names.
pub mod names;
/// RPSL objects.
pub mod obj;
/// Primitive RPSL syntax types.
pub mod primitive;

#[cfg(test)]
mod tests;
