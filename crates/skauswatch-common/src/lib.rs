//! Shared configuration loading and error types used by every skauswatch
//! service. Keeps env-var handling and error taxonomy consistent so services
//! never hand-roll `std::env` parsing.

pub mod config;
pub mod error;

pub use config::load_config;
pub use error::Error;
