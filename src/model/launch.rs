//! Inputs and resolved outputs for one foreground program launch.

use std::ffi::OsString;
use std::os::fd::RawFd;
use std::path::PathBuf;

use serde::Deserialize;

use super::{HerdrContext, InstanceId, ResolvedWorkspace};

/// User intent sent by the launcher.
///
/// The project is a hint derived from the launcher's current directory. The
/// daemon independently resolves it before selecting a workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchRequest {
    pub workspace: super::WorkspaceSelection,
    /// Always starts as the launcher's current directory. The daemon discovers
    /// its project unless `workspace` selects the directory itself.
    pub current_directory: PathBuf,
}
/// Exact launcher inputs retained across one Herdr workspace handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LauncherContinuation {
    pub socket_path: PathBuf,
    pub workspace: super::WorkspaceSelection,
    pub profile: String,
    pub agent_label: String,
    pub command: String,
    /// Normalized CLI-added mounts, reapplied by the routed launcher.
    pub mount_arguments: Vec<String>,
    /// Resolved normal launcher arguments retained for durable replay.
    pub replay_arguments: Vec<String>,
}

/// Handoff inputs not already supplied by the enclosing launch request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchHandoff {
    pub socket_path: PathBuf,
    pub command: String,
    pub mount_arguments: Vec<String>,
    pub replay_arguments: Vec<String>,
}

/// Complete bounded metadata required to prepare and register one launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareLaunchRequest {
    pub workspace: LaunchRequest,
    pub profile: String,
    /// Trusted Herdr identity, independent of the selected policy profile.
    pub agent_label: String,
    /// Empty for launches that cannot be durably replayed.
    pub replay_arguments: Vec<String>,
    pub limits: ResourceLimits,
    /// Optional host pane identity, validated even when routing is disabled.
    pub herdr: Option<HerdrContext>,
    /// Execute in the current terminal without routing; retain optional Herdr identity.
    pub no_multiplex: bool,
    /// Handoff inputs used only when Herdr must continue in another pane.
    pub continuation: Option<Box<LaunchHandoff>>,
    /// One-time token binding a resumed launcher to its routed Herdr destination.
    pub continuation_token: Option<String>,
}

/// Daemon-resolved workspace plus the identity of its attached process scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedLaunch {
    pub instance_id: InstanceId,
    pub workspace: ResolvedWorkspace,
}

/// Trusted foreground executable and arguments selected for this launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForegroundCommand {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
}

/// Coordinator-selected outer runtime.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RuntimeKind {
    /// Execute directly on the host without filesystem or network confinement.
    #[default]
    Native,
    /// Execute through Bubblewrap using the selected profile policy.
    Bubblewrap,
}

/// Network namespace policy for one launch profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NetworkMode {
    /// Create an isolated network namespace.
    #[default]
    None,
    /// Retain the host network namespace.
    Host,
    /// Isolate host interfaces and forward internet/LAN traffic with slirp4netns.
    Private,
}

/// Access granted by one bind mount.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindAccess {
    ReadOnly,
    ReadWrite,
}

/// Source resolved for one profile bind mount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindMountSource {
    /// Canonical host path.
    Host(PathBuf),
    /// PATH-resolved executable, retaining its canonical location and an alias.
    Executable(PathBuf),
    /// Worktree selected by the daemon.
    Workspace,
}

/// One validated bind mount in a launch profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindMount {
    pub source: BindMountSource,
    pub destination: PathBuf,
    pub access: BindAccess,
}

/// One host character or block device explicitly exposed inside Bubblewrap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceMount {
    /// Canonical host device node beneath `/dev`.
    pub source: PathBuf,
    /// Selected absolute device path, retaining an explicitly requested alias.
    pub destination: PathBuf,
}

/// One host environment value deliberately projected into the outer runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentVariable {
    pub name: String,
    pub value: OsString,
}

/// One TCP service explicitly published on the host's IPv4 loopback interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortForward {
    pub host_port: u16,
    pub room_port: u16,
}

/// Fully parsed outer-runtime policy selected for one launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePolicy {
    pub kind: RuntimeKind,
    pub network: NetworkMode,
    pub port_forwards: Vec<PortForward>,
    pub bind_mounts: Vec<BindMount>,
    pub devices: Vec<DeviceMount>,
    pub environment: Vec<EnvironmentVariable>,
    pub home: Option<PathBuf>,
}

/// Resource settings applied to one supervised process tree.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResourceLimits {
    pub memory_max_bytes: Option<u64>,
    pub tasks_max: Option<u64>,
    /// CPU quota in basis points: `10_000` means one full CPU.
    pub cpu_quota_basis_points: Option<u32>,
    /// Hard, non-exclusive CPU placement restriction; distinct IDs below 1024.
    pub cpu_cores: Option<Vec<u32>>,
    /// Select this many lowest-numbered available CPUs, without reserving them.
    pub cpu_count: Option<u32>,
}

impl ResourceLimits {
    /// Check CPU selection structure independently of the launcher's affinity.
    #[must_use]
    pub fn valid_cpu_selection(&self) -> bool {
        match (&self.cpu_cores, self.cpu_count) {
            (Some(_), Some(_)) => false,
            (None, Some(count)) => (1..=1024).contains(&count),
            (None, None) => true,
            (Some(cores), None) => {
                if cores.is_empty() || cores.len() > 1024 {
                    return false;
                }
                let mut seen = [false; 1024];
                for &core in cores {
                    if core >= 1024 || seen[core as usize] {
                        return false;
                    }
                    seen[core as usize] = true;
                }
                true
            }
        }
    }
}

/// Fully resolved launch state supplied to the selected runtime backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchSpec {
    pub workspace: ResolvedWorkspace,
    pub runtime: RuntimePolicy,
    pub command: ForegroundCommand,
    /// Access the launcher grants to backend-required support mounts.
    pub support_mount_access: BindAccess,
}

/// Final process image prepared by a runtime backend for launcher `exec`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedExec {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub working_directory: PathBuf,
}

/// Borrowed descriptor data to inject into a Bubblewrap process image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeDataFile<'a> {
    pub descriptor: RawFd,
    pub destination: &'a str,
}
