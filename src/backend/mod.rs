//! Compiled-in platform seams used by the two process roles.
//!
//! These traits are source interfaces, not dynamic plugin ABIs.

mod herdr;
mod runtime;
mod scope;
mod services;
mod workspace;

pub(crate) use herdr::{HerdrActivityState, HerdrError, HerdrPane, NativeHerdrBackend};
pub use runtime::{
    BUBBLEWRAP_EXECUTABLE, BubblewrapRuntimeBackend, NativeRuntimeBackend, RuntimeBackend,
    RuntimeError,
};
pub use scope::{
    ScopeAttachment, ScopeBackend, ScopeHandle, ScopeState, SystemdScopeBackend, SystemdScopeError,
};
pub(crate) use services::{DockerComposeBackend, SERVICE_TIMEOUT, ServiceError, ServiceInvocation};
pub use workspace::{GitWorkspaceBackend, GitWorkspaceError, WorkspaceBackend};
