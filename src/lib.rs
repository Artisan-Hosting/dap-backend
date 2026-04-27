//! Core library for the Artisan Dynamic Auditing Platform (DAP).
//!
//! This crate provides heavily-commented building blocks so new engineers can follow
//! along without cross-referencing multiple documents. The modules exposed here
//! mirror the major system components defined in `objective.md` and `outline.md`.

pub mod config;
pub mod discovery;
pub mod facts;
pub mod orchestrator;
pub mod planner;
pub mod plugins;
pub mod python_env;
pub mod report;
pub mod runner;
pub mod tests;
pub mod workspace;

pub use config::RunConfig;
pub use facts::Fact;
pub use orchestrator::Orchestrator;
