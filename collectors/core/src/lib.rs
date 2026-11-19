//! Shared core for the LSADRA endpoint collectors.
//!
//! Every source crate turns host log records into [`event::Event`]s; this crate
//! checks them against event-schema v1 ([`event::Event::validate`]), writes
//! them to a size-capped on-disk [`spool::Spool`], and ships them to the core
//! in batches ([`ship::Shipper`]). The device API key lives in the OS keychain
//! ([`keystore`]), never in the config file.

pub mod config;
pub mod event;
pub mod keystore;
pub mod ship;
pub mod spool;
pub mod time;

pub use event::{ContractError, Event};
