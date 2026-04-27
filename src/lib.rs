//! Core library for the Artisan Dynamic Auditing Platform backend.
//!
//! The crate exposes the backend service layer plus the discovery, planning,
//! plugin, and runner components it builds on.

pub mod backend;
pub mod config;
pub mod discovery;
pub mod facts;
pub mod planner;
pub mod plugins;
pub mod python_env;
pub mod runner;
pub mod tests;
pub mod workspace;

pub use config::RunConfig;
pub use facts::Fact;
