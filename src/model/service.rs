//! Typed project-service lifecycle contracts.

use std::path::PathBuf;

/// One daemon-owned project service operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceAction {
    Up,
    Down,
    Status,
    Config,
}

/// Non-secret canonical service configuration resolved by the daemon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceConfiguration {
    pub project_root: PathBuf,
    pub global_environment_file: PathBuf,
    pub project_environment_file: PathBuf,
    pub database_url: String,
    pub qdrant_url: String,
    pub state_directory: String,
}

/// Result of one serialized daemon-owned service operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceResult {
    Completed { output: String },
    Configuration(ServiceConfiguration),
}
