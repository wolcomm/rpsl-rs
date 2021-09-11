//!  A parser and syntax tree implementation for the Routing Policy
//!  Specification Language (RPSL) defined in RFC2622 and RFC4012.
//!
//! # Example
//!
//! ``` rust
//! use std::error::Error;
//! use rpsl::{
//!     expr::FilterExpr,
//!     names::AutNum,
//!     subst::Substitute,
//! };
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     let peeras = "AS65000".parse::<AutNum>()?;
//!     let filter = "PeerAS:AS-FOO AND {0.0.0.0/0^8-24, ::/0^16-48}"
//!         .parse::<FilterExpr>()?
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

#[macro_use]
mod error;

#[macro_use]
mod parser;

#[cfg(test)]
#[macro_use]
mod tests;

/// RPSL policy and filter expressions.
pub mod expr;
/// RPSL object class names.
pub mod names;
/// Primitive RPSL syntax types.
pub mod primitive;
/// traits for performing value substitution on RPSL expressions.
pub mod subst;
