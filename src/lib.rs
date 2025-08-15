#![deny(unused_must_use)]
// Don't allow dbg! prints in release.
#![cfg_attr(not(debug_assertions), deny(clippy::dbg_macro))]
// Suppress warnings from num_derive macros when using nightly compiler
#![allow(non_local_definitions)]

#[macro_use]
extern crate num_derive;

pub use attribute::x10::StandardInfoAttr;
pub use attribute::x30::FileNameAttr;
pub use attribute::MftAttribute;

pub use crate::mft::MftParser;
pub use entry::{EntryHeader, MftEntry};

pub mod attribute;
pub mod csv;
pub mod entry;
pub mod err;
pub mod mft;
pub mod fast_fixup; // fast slice-based fixup & helpers
pub mod fast_entry; // fast filename scanning
pub mod path_resolve; // basic path resolution

pub(crate) mod macros;
pub(crate) mod utils;

#[cfg(test)]
pub(crate) mod tests;
