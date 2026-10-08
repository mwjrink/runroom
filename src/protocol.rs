//! Versioned messages exchanged over the authenticated local daemon socket.
//!
//! Peer PID and UID are transport metadata and never appear in these messages.

use std::path::PathBuf;

use crate::model::{
    HerdrContext, InstanceId, InstanceRecord, LauncherContinuation, PrepareLaunchRequest,
    PreparedLaunch, PrunedWorktrees, RetiredWorkspace, ServiceAction, ServiceResult, StopMode,
    WorkspaceName,
};

/// Application version shared by the CLI and the exact-match connection handshake.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Request envelope accepted after a successful handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlRequest {
    pub request_id: u64,
    pub operation: ControlOperation,
}

/// Typed daemon operations; no generic host execution operation exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlOperation {
    PrepareLaunch(PrepareLaunchRequest),
    ResumeLaunch {
        token: String,
        herdr: HerdrContext,
    },
    ListInstances {
        after: Option<InstanceId>,
        limit: u16,
    },
    GetInstance {
        id: InstanceId,
    },
    StopInstance {
        id: InstanceId,
        mode: StopMode,
    },
    RetireWorkspace {
        current_directory: PathBuf,
        name: WorkspaceName,
    },
    RepairWorkspaceMetadata {
        current_directory: PathBuf,
    },
    ManageServices {
        current_directory: PathBuf,
        action: ServiceAction,
    },
}

/// Response envelope returned for exactly one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlResponse {
    pub request_id: u64,
    pub result: Result<ControlResult, ControlError>,
}

/// Successful results for the typed daemon operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlResult {
    LaunchPrepared(PreparedLaunch),
    LaunchRedirected,
    LaunchContinuation(LauncherContinuation),
    Instances(Vec<InstanceRecord>),
    Instance(Option<InstanceRecord>),
    InstanceStopped(InstanceRecord),
    WorkspaceRetired(RetiredWorkspace),
    WorkspaceMetadataRepaired(PrunedWorktrees),
    Services(ServiceResult),
}

/// Stable machine-readable error plus a bounded human diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlError {
    pub code: String,
    pub message: String,
}
