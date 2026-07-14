#![forbid(unsafe_code)]

//! Dappnode package testing harness.
//!
//! The crate is split by capability rather than by architectural pattern:
//! local supervision lives in [`api`], Tropibot protocol handling in
//! [`coordinator`], persisted state in [`storage`], package operations in
//! [`package_manager`], log analysis in [`analysis`], and the end-to-end
//! baseline/candidate workflow in [`runner`].

pub mod analysis;
pub mod api;
pub mod clock;
pub mod config;
pub mod coordinator;
pub mod model;
pub mod package_manager;
pub mod runner;
pub mod storage;
mod tls;
pub mod worker;
