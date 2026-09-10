//! Source-specific field mappings that shape a raw record before
//! [`crate::normalize`] runs. Each submodule below is declared active from
//! Task 0.1 onward; Wave 1 tasks fill in the stub bodies without ever
//! editing this file again.

pub mod generic;
pub mod otlp;
pub mod syslog;
