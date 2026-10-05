//! Lifecycle state for one supervised foreground process tree.

use super::{InstanceId, ProcessId, ResolvedWorkspace, ResourceLimits};

/// Verified Herdr identity supplied by the foreground launcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HerdrContext {
    pub workspace_id: Option<String>,
    pub pane_id: Option<String>,
    pub session_name: Option<String>,
}

/// Observable lifecycle state reported by the daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceState {
    Starting,
    Running,
    Stopping,
    Exited,
    Failed,
}

/// Durable registration joining an instance to its workspace and managed scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceRecord {
    pub id: InstanceId,
    pub scope_handle: String,
    pub workspace: ResolvedWorkspace,
    pub profile: String,
    pub limits: ResourceLimits,
    pub leader: ProcessId,
    pub state: InstanceState,
    pub activity: Option<ActivityUpdate>,
    pub herdr: Option<HerdrContext>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

/// User-visible workload activity forwarded to Herdr.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityState {
    Working,
    Idle,
    Blocked,
}

/// Activity update attributed from the caller's supervised process scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityUpdate {
    pub state: ActivityState,
    pub message: Option<String>,
}

/// Requested shutdown behavior for one supervised instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopMode {
    Graceful,
    Force,
}
