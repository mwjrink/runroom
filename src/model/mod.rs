//! Shared domain types used across the daemon, launcher, and backends.

mod identity;
mod instance;
mod launch;
mod service;
mod workspace;

pub use identity::{InstanceId, ProcessId, ProjectId, UserId, WorkspaceName};
pub use instance::{
    ActivityState, ActivityUpdate, AgentSession, HerdrContext, InstanceRecord, InstanceState,
    SessionAgent, StopMode,
};
pub use launch::{
    BindAccess, BindMount, BindMountSource, DeviceMount, EnvironmentVariable, ForegroundCommand,
    LaunchHandoff, LaunchRequest, LaunchSpec, LauncherContinuation, NetworkMode,
    PrepareLaunchRequest, PreparedExec, PreparedLaunch, ResourceLimits, RuntimeDataFile,
    RuntimeKind, RuntimePolicy,
};
pub use service::{ServiceAction, ServiceConfiguration, ServiceResult};
pub use workspace::{
    CanonicalProject, PrunedWorktrees, ResolvedWorkspace, RetiredWorkspace, WorkspaceOrigin,
    WorkspaceSelection, WorkspaceSupportMount,
};

/// Herdr's bounded single-line agent label rules.
pub fn valid_agent_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= 512 && !label.chars().any(char::is_control)
}
