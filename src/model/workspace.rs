//! Backend-neutral project and workspace state.

use std::path::PathBuf;

use super::ProjectId;

/// Canonical project resolved by the selected workspace backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalProject {
    pub id: ProjectId,
    pub primary_checkout: PathBuf,
}

/// Chooses the exact current directory, primary workspace, or one named workspace.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum WorkspaceSelection {
    /// Use the backend's primary workspace and current change/branch name.
    #[default]
    Primary,
    /// Find or create a named workspace scoped to this project.
    Named(super::WorkspaceName),
    /// Use the launcher's exact current directory without project discovery.
    Here,
}

/// Indicates how the actual workspace was resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceOrigin {
    Primary,
    Created,
    Existing,
    Directory,
}

/// Backend-owned host mount required for a resolved workspace to function.
///
/// The launcher decides its access mode from the selected runtime profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceSupportMount {
    pub source: PathBuf,
    pub destination: PathBuf,
}

/// One actual filesystem workspace selected by the daemon.
///
/// `change_name` is backend-neutral presentation metadata: a Git backend may
/// return a branch, while Jujutsu or Lore may return their corresponding name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedWorkspace {
    pub project: ProjectId,
    /// Canonical primary checkout used for project-level configuration.
    pub primary_checkout: PathBuf,
    pub selection: WorkspaceSelection,
    pub path: PathBuf,
    pub change_name: Option<String>,
    pub origin: WorkspaceOrigin,
    pub support_mounts: Vec<WorkspaceSupportMount>,
}

/// One named worktree safely removed from disk. Its Git branch is retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetiredWorkspace {
    pub project: ProjectId,
    pub name: super::WorkspaceName,
    pub path: PathBuf,
    pub branch: String,
}

/// Stale linked-worktree metadata removed by one explicit repair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrunedWorktrees {
    pub project: ProjectId,
    pub paths: Vec<PathBuf>,
}
