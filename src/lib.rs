//! Contracts for the Runroom host daemon and foreground launcher.
//!
//! The process selects exactly one concrete role at startup. Platform
//! mechanisms remain source-level backend interfaces; role-specific operations
//! will be inherent methods on `Daemon` and `Launcher`.

pub mod atomic;
pub mod backend;
pub mod environment;
pub mod model;
pub mod process;
mod transport;

pub use atomic::run_atomic_worker;
pub use process::{
    AlreadyStarted, Application, Daemon, DaemonConfig, HostClient, Launcher, LauncherConfig,
    RunMode, start,
};
pub mod protocol;
