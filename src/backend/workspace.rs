//! Project/workspace discovery and Git linked-worktree resolution.

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tracing::debug;

use crate::model::{
    CanonicalProject, ProjectId, PrunedWorktrees, ResolvedWorkspace, RetiredWorkspace,
    WorkspaceName, WorkspaceOrigin, WorkspaceSelection, WorkspaceSupportMount,
};

const MAX_GIT_OUTPUT: usize = 4 * 1024 * 1024;
const GIT_DEADLINE: Duration = Duration::from_secs(30);
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Discovers projects and atomically manages filesystem workspaces for launches.
pub trait WorkspaceBackend: Send + Sync {
    type Error;

    /// Resolve the canonical project without creating or selecting a workspace.
    ///
    /// # Errors
    ///
    /// Returns the backend's error when the current directory or repository
    /// metadata cannot be resolved into a canonical project.
    fn canonical_project(&self, current_directory: &Path) -> Result<CanonicalProject, Self::Error>;

    /// Select the exact directory without project discovery, or discover its
    /// project and select the primary or one named workspace.
    ///
    /// # Errors
    ///
    /// Returns the backend's error when repository metadata is invalid or the
    /// requested workspace cannot be selected or created.
    fn resolve_workspace(
        &self,
        current_directory: &Path,
        selection: &WorkspaceSelection,
    ) -> Result<ResolvedWorkspace, Self::Error>;

    /// Remove one clean, daemon-managed named worktree while retaining its branch.
    ///
    /// # Errors
    ///
    /// Returns the backend's error when the selection is primary, missing,
    /// ambiguous, unmanaged, unsafe, or dirty.
    fn retire_workspace(
        &self,
        current_directory: &Path,
        selection: &WorkspaceSelection,
    ) -> Result<RetiredWorkspace, Self::Error>;

    /// Remove only stale linked-worktree administrative metadata.
    ///
    /// # Errors
    ///
    /// Returns the backend's error when discovery or Git's fixed prune operation fails.
    fn prune_stale_worktrees(
        &self,
        current_directory: &Path,
    ) -> Result<PrunedWorktrees, Self::Error>;
}

/// Git linked-worktree backend with project-independent directory selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitWorkspaceBackend {
    workspace_root: PathBuf,
}

impl GitWorkspaceBackend {
    /// Store managed linked worktrees beneath `workspace_root`.
    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
        }
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        name = "discover_git_project",
        fields(current_directory = %current_directory.display(), allow_prunable)
    )]
    fn discover(
        current_directory: &Path,
        allow_prunable: bool,
    ) -> Result<GitProject, GitWorkspaceError> {
        debug!(
            current_directory = %current_directory.display(),
            "checking Git repository"
        );
        let current_directory =
            current_directory
                .canonicalize()
                .map_err(|source| GitWorkspaceError::Io {
                    context: "canonicalize launcher current directory",
                    source,
                })?;
        if !current_directory.is_dir() {
            return Err(GitWorkspaceError::InvalidRepository(
                "launcher current directory is not a directory".to_owned(),
            ));
        }

        debug!(
            current_directory = %current_directory.display(),
            "resolving Git common directory"
        );
        let common_dir = git_stdout(
            &current_directory,
            [
                OsStr::new("rev-parse"),
                OsStr::new("--path-format=absolute"),
                OsStr::new("--git-common-dir"),
            ],
        )?;
        let common_dir = trim_one_line(common_dir, "Git common directory")?;
        let common_dir = PathBuf::from(OsString::from_vec(common_dir))
            .canonicalize()
            .map_err(|source| GitWorkspaceError::Io {
                context: "canonicalize Git common directory",
                source,
            })?;

        debug!(
            common_directory = %common_dir.display(),
            "resolved Git common directory"
        );
        let worktrees = if allow_prunable {
            list_worktrees_including_prunable(&current_directory)?
        } else {
            list_worktrees(&current_directory)?
        };
        let primary = worktrees.first().ok_or_else(|| {
            GitWorkspaceError::InvalidRepository("Git reported no worktrees".to_owned())
        })?;
        if primary.bare {
            return Err(GitWorkspaceError::InvalidRepository(
                "bare repositories are not supported".to_owned(),
            ));
        }
        let primary_path = primary
            .path
            .canonicalize()
            .map_err(|source| GitWorkspaceError::Io {
                context: "canonicalize primary Git worktree",
                source,
            })?;
        debug!(
            primary_workspace = %primary_path.display(),
            worktree_count = worktrees.len(),
            "validated Git worktrees"
        );
        let id = project_id(&common_dir);

        Ok(GitProject {
            id,
            common_dir,
            primary_path,
            worktrees,
        })
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        name = "resolve_named_workspace",
        fields(project = %project.id.0, workspace = name)
    )]
    fn resolve_named(
        &self,
        project: &GitProject,
        name: &str,
    ) -> Result<ResolvedWorkspace, GitWorkspaceError> {
        validate_branch(&project.primary_path, name)?;
        let branch = format!("refs/heads/{name}");
        if let Some(existing) = project
            .worktrees
            .iter()
            .find(|worktree| worktree.branch.as_deref() == Some(branch.as_str()))
        {
            debug!(
                workspace = name,
                path = %existing.path.display(),
                "using existing named workspace"
            );
            return resolved_named(project, name, existing, WorkspaceOrigin::Existing);
        }

        debug!(
            workspace = name,
            workspace_root = %self.workspace_root.display(),
            "preparing managed named workspace"
        );
        create_private_directory(&self.workspace_root)?;
        let project_directory = self.workspace_root.join(project_directory_name(project));
        create_private_directory(&project_directory)?;
        let destination = project_directory.join(workspace_directory_name(name));
        if fs::symlink_metadata(&destination).is_ok() {
            return Err(GitWorkspaceError::DestinationExists(destination));
        }

        let branch_exists = git_status(
            &project.primary_path,
            [
                OsStr::new("show-ref"),
                OsStr::new("--verify"),
                OsStr::new("--quiet"),
                OsStr::new(&branch),
            ],
        )?;
        let mut arguments = vec![
            OsString::from("worktree"),
            OsString::from("add"),
            OsString::from("--no-guess-remote"),
        ];
        if branch_exists {
            arguments.push(destination.as_os_str().to_owned());
            arguments.push(OsString::from(name));
        } else {
            let head = git_stdout(
                &project.primary_path,
                [
                    OsStr::new("rev-parse"),
                    OsStr::new("--verify"),
                    OsStr::new("HEAD^{commit}"),
                ],
            )?;
            let head = trim_one_line(head, "primary HEAD commit")?;
            arguments.push(OsString::from("-b"));
            arguments.push(OsString::from(name));
            arguments.push(destination.as_os_str().to_owned());
            arguments.push(OsString::from_vec(head));
        }

        debug!(
            workspace = name,
            destination = %destination.display(),
            branch_exists,
            "creating Git worktree"
        );
        let creation = git_output(
            &project.primary_path,
            arguments.iter().map(OsString::as_os_str),
        )?;
        let refreshed = list_worktrees(&project.primary_path)?;
        if let Some(created) = refreshed
            .iter()
            .find(|worktree| worktree.branch.as_deref() == Some(branch.as_str()))
        {
            let origin = if creation.status.success() {
                WorkspaceOrigin::Created
            } else {
                WorkspaceOrigin::Existing
            };
            debug!(
                workspace = name,
                path = %created.path.display(),
                ?origin,
                "resolved named workspace"
            );
            return resolved_named(project, name, created, origin);
        }
        if !creation.status.success() {
            return Err(command_failed("git worktree add", &creation));
        }
        Err(GitWorkspaceError::InvalidRepository(
            "created worktree was absent from refreshed Git metadata".to_owned(),
        ))
    }

    /// Retire a managed worktree only after checking its actual canonical path.
    /// The caller holds the workspace gate before taking the registry lock.
    pub(crate) fn retire_inactive_workspace(
        &self,
        current_directory: &Path,
        name: &WorkspaceName,
        is_active: impl FnOnce(&Path) -> bool,
    ) -> Result<RetiredWorkspace, GitWorkspaceError> {
        let project = Self::discover(current_directory, false)?;
        self.retire_named(&project, name, is_active)
    }

    fn retire_named(
        &self,
        project: &GitProject,
        name: &WorkspaceName,
        is_active: impl FnOnce(&Path) -> bool,
    ) -> Result<RetiredWorkspace, GitWorkspaceError> {
        validate_branch(&project.primary_path, &name.0)?;
        let branch = format!("refs/heads/{}", name.0);
        let mut matches = project
            .worktrees
            .iter()
            .filter(|worktree| worktree.branch.as_deref() == Some(branch.as_str()));
        let Some(worktree) = matches.next() else {
            return Err(GitWorkspaceError::WorkspaceNotFound(name.0.clone()));
        };
        if matches.next().is_some() {
            return Err(GitWorkspaceError::AmbiguousWorkspace(name.0.clone()));
        }
        let path = self.managed_worktree_path(project, name, worktree)?;
        if path == project.primary_path {
            return Err(GitWorkspaceError::PrimaryRetirement);
        }
        if is_active(&path) {
            return Err(GitWorkspaceError::ActiveWorkspace(path));
        }

        let status = git_stdout(
            &path,
            [
                OsStr::new("status"),
                OsStr::new("--porcelain=v1"),
                OsStr::new("-z"),
                OsStr::new("--untracked-files=all"),
            ],
        )?;
        if !status.is_empty() {
            return Err(GitWorkspaceError::DirtyWorkspace(path));
        }

        let removal = git_output(
            &project.primary_path,
            [
                OsStr::new("worktree"),
                OsStr::new("remove"),
                OsStr::new("--"),
                path.as_os_str(),
            ],
        )?;
        let refreshed = list_worktrees(&project.primary_path)?;
        let still_present = refreshed.iter().any(|candidate| {
            candidate.branch.as_deref() == Some(branch.as_str()) || candidate.path == path
        });
        if still_present {
            if !removal.status.success() {
                return Err(command_failed("git worktree remove", &removal));
            }
            return Err(GitWorkspaceError::InvalidRepository(
                "removed worktree remained in refreshed Git metadata".to_owned(),
            ));
        }
        if fs::symlink_metadata(&path).is_ok() {
            if !removal.status.success() {
                return Err(command_failed("git worktree remove", &removal));
            }
            return Err(GitWorkspaceError::InvalidRepository(
                "removed worktree directory still exists".to_owned(),
            ));
        }
        if !git_status(
            &project.primary_path,
            [
                OsStr::new("show-ref"),
                OsStr::new("--verify"),
                OsStr::new("--quiet"),
                OsStr::new(&branch),
            ],
        )? {
            return Err(GitWorkspaceError::InvalidRepository(
                "retired worktree branch was unexpectedly removed".to_owned(),
            ));
        }

        Ok(RetiredWorkspace {
            project: project.id.clone(),
            name: name.clone(),
            path,
            branch,
        })
    }

    fn managed_worktree_path(
        &self,
        project: &GitProject,
        name: &WorkspaceName,
        worktree: &GitWorktree,
    ) -> Result<PathBuf, GitWorkspaceError> {
        let root_metadata = fs::symlink_metadata(&self.workspace_root)
            .map_err(|_| GitWorkspaceError::UnmanagedWorkspace(worktree.path.clone()))?;
        if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
            return Err(GitWorkspaceError::UnsafeWorkspacePath(
                self.workspace_root.clone(),
            ));
        }
        let root = self
            .workspace_root
            .canonicalize()
            .map_err(|source| GitWorkspaceError::Io {
                context: "canonicalize managed workspace root",
                source,
            })?;
        let project_directory = root.join(project_directory_name(project));
        let project_metadata = fs::symlink_metadata(&project_directory)
            .map_err(|_| GitWorkspaceError::UnmanagedWorkspace(worktree.path.clone()))?;
        if !project_metadata.is_dir() || project_metadata.file_type().is_symlink() {
            return Err(GitWorkspaceError::UnsafeWorkspacePath(project_directory));
        }
        let project_directory =
            project_directory
                .canonicalize()
                .map_err(|source| GitWorkspaceError::Io {
                    context: "canonicalize managed project workspace directory",
                    source,
                })?;
        if project_directory.parent() != Some(root.as_path()) {
            return Err(GitWorkspaceError::UnsafeWorkspacePath(project_directory));
        }

        let expected = project_directory.join(workspace_directory_name(&name.0));
        let expected_metadata = fs::symlink_metadata(&expected)
            .map_err(|_| GitWorkspaceError::UnmanagedWorkspace(worktree.path.clone()))?;
        if !expected_metadata.is_dir() || expected_metadata.file_type().is_symlink() {
            return Err(GitWorkspaceError::UnsafeWorkspacePath(expected));
        }
        let expected = expected
            .canonicalize()
            .map_err(|source| GitWorkspaceError::Io {
                context: "canonicalize managed named workspace",
                source,
            })?;
        let actual = worktree
            .path
            .canonicalize()
            .map_err(|source| GitWorkspaceError::Io {
                context: "canonicalize named Git worktree for retirement",
                source,
            })?;
        if actual != expected || !actual.starts_with(&root) {
            return Err(GitWorkspaceError::UnmanagedWorkspace(actual));
        }
        Ok(actual)
    }
    fn select_workspace(
        &self,
        project: &GitProject,
        selection: &WorkspaceSelection,
    ) -> Result<ResolvedWorkspace, GitWorkspaceError> {
        match selection {
            WorkspaceSelection::Primary => {
                let primary = project.worktrees.first().ok_or_else(|| {
                    GitWorkspaceError::InvalidRepository(
                        "Git reported no primary worktree".to_owned(),
                    )
                })?;
                debug!(
                    project = %project.id.0,
                    workspace = %project.primary_path.display(),
                    "selected primary workspace"
                );
                Ok(ResolvedWorkspace {
                    project: project.id.clone(),
                    primary_checkout: project.primary_path.clone(),
                    selection: WorkspaceSelection::Primary,
                    path: project.primary_path.clone(),
                    change_name: primary.branch.as_deref().map(short_branch),
                    origin: WorkspaceOrigin::Primary,
                    support_mounts: Vec::new(),
                })
            }
            WorkspaceSelection::Named(name) => self.resolve_named(project, &name.0),
            WorkspaceSelection::Here => {
                unreachable!("directory selections bypass Git discovery")
            }
        }
    }

    /// Resolve one launch without repeating canonical Git discovery.
    pub(crate) fn resolve_launch_workspace(
        &self,
        current_directory: &Path,
        selection: &WorkspaceSelection,
    ) -> Result<(CanonicalProject, ResolvedWorkspace), GitWorkspaceError> {
        if matches!(selection, WorkspaceSelection::Here) {
            let path =
                current_directory
                    .canonicalize()
                    .map_err(|source| GitWorkspaceError::Io {
                        context: "canonicalize launcher current directory",
                        source,
                    })?;
            if !path.is_dir() {
                return Err(GitWorkspaceError::InvalidRepository(
                    "launcher current directory is not a directory".to_owned(),
                ));
            }
            let id = ProjectId(format!(
                "directory-{}",
                hex_digest(path.as_os_str().as_bytes())
            ));
            let canonical = CanonicalProject {
                id: id.clone(),
                primary_checkout: path.clone(),
            };
            let workspace = ResolvedWorkspace {
                project: id,
                primary_checkout: path.clone(),
                selection: WorkspaceSelection::Here,
                path,
                change_name: None,
                origin: WorkspaceOrigin::Directory,
                support_mounts: Vec::new(),
            };
            return Ok((canonical, workspace));
        }
        debug!("discovering project for workspace selection");
        let project = Self::discover(current_directory, false)?;
        let canonical = CanonicalProject {
            id: project.id.clone(),
            primary_checkout: project.primary_path.clone(),
        };
        let workspace = self.select_workspace(&project, selection)?;
        Ok((canonical, workspace))
    }
}

impl WorkspaceBackend for GitWorkspaceBackend {
    type Error = GitWorkspaceError;

    fn canonical_project(&self, current_directory: &Path) -> Result<CanonicalProject, Self::Error> {
        let project = Self::discover(current_directory, false)?;
        Ok(CanonicalProject {
            id: project.id,
            primary_checkout: project.primary_path,
        })
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        name = "resolve_workspace",
        fields(current_directory = %current_directory.display(), selection = ?selection)
    )]
    fn resolve_workspace(
        &self,
        current_directory: &Path,
        selection: &WorkspaceSelection,
    ) -> Result<ResolvedWorkspace, Self::Error> {
        self.resolve_launch_workspace(current_directory, selection)
            .map(|(_, workspace)| workspace)
    }

    fn retire_workspace(
        &self,
        current_directory: &Path,
        selection: &WorkspaceSelection,
    ) -> Result<RetiredWorkspace, Self::Error> {
        let WorkspaceSelection::Named(name) = selection else {
            return Err(GitWorkspaceError::PrimaryRetirement);
        };
        self.retire_inactive_workspace(current_directory, name, |_| false)
    }

    fn prune_stale_worktrees(
        &self,
        current_directory: &Path,
    ) -> Result<PrunedWorktrees, Self::Error> {
        let project = Self::discover(current_directory, true)?;
        let stale: Vec<_> = project
            .worktrees
            .iter()
            .filter(|worktree| worktree.prunable)
            .map(|worktree| worktree.path.clone())
            .collect();
        if stale.is_empty() {
            return Ok(PrunedWorktrees {
                project: project.id,
                paths: Vec::new(),
            });
        }

        let output = git_output(
            &project.primary_path,
            [
                OsStr::new("worktree"),
                OsStr::new("prune"),
                OsStr::new("--expire=now"),
            ],
        )?;
        if !output.status.success() {
            return Err(command_failed("git worktree prune", &output));
        }
        let remaining = list_worktrees_including_prunable(&project.primary_path)?;
        let paths = stale
            .into_iter()
            .filter(|path| !remaining.iter().any(|worktree| worktree.path == *path))
            .collect();
        Ok(PrunedWorktrees {
            project: project.id,
            paths,
        })
    }
}

#[derive(Debug)]
struct GitProject {
    id: ProjectId,
    common_dir: PathBuf,
    primary_path: PathBuf,
    worktrees: Vec<GitWorktree>,
}

#[derive(Debug)]
struct GitWorktree {
    path: PathBuf,
    branch: Option<String>,
    bare: bool,
    prunable: bool,
}

#[tracing::instrument(
    level = "debug",
    skip_all,
    name = "list_git_worktrees",
    fields(directory = %directory.display())
)]
fn list_worktrees(directory: &Path) -> Result<Vec<GitWorktree>, GitWorkspaceError> {
    let worktrees = list_worktrees_including_prunable(directory)?;
    if worktrees.iter().any(|worktree| worktree.prunable) {
        return Err(GitWorkspaceError::InvalidRepository(
            "repository contains prunable worktree metadata; repair it explicitly".to_owned(),
        ));
    }
    Ok(worktrees)
}

#[tracing::instrument(
    level = "debug",
    skip_all,
    name = "list_git_worktrees_including_prunable",
    fields(directory = %directory.display())
)]
fn list_worktrees_including_prunable(
    directory: &Path,
) -> Result<Vec<GitWorktree>, GitWorkspaceError> {
    let output = git_stdout(
        directory,
        [
            OsStr::new("worktree"),
            OsStr::new("list"),
            OsStr::new("--porcelain"),
            OsStr::new("-z"),
        ],
    )?;
    debug!(
        directory = %directory.display(),
        output_bytes = output.len(),
        "received Git worktree metadata"
    );
    parse_worktrees(&output)
}

fn parse_worktrees(output: &[u8]) -> Result<Vec<GitWorktree>, GitWorkspaceError> {
    let mut worktrees = Vec::new();
    let mut current: Option<GitWorktree> = None;
    for field in output.split(|byte| *byte == 0) {
        if field.is_empty() {
            if let Some(worktree) = current.take() {
                worktrees.push(worktree);
            }
            continue;
        }
        if let Some(path) = field.strip_prefix(b"worktree ") {
            if current.is_some() {
                return Err(GitWorkspaceError::InvalidRepository(
                    "malformed Git worktree records".to_owned(),
                ));
            }
            current = Some(GitWorktree {
                path: PathBuf::from(OsString::from_vec(path.to_vec())),
                branch: None,
                bare: false,
                prunable: false,
            });
        } else {
            let record = current.as_mut().ok_or_else(|| {
                GitWorkspaceError::InvalidRepository(
                    "Git worktree attribute appeared before a path".to_owned(),
                )
            })?;
            if let Some(branch) = field.strip_prefix(b"branch ") {
                record.branch = Some(String::from_utf8(branch.to_vec()).map_err(|_| {
                    GitWorkspaceError::InvalidRepository(
                        "Git returned a non-UTF-8 branch name".to_owned(),
                    )
                })?);
            } else if field == b"bare" {
                record.bare = true;
            } else if field.starts_with(b"prunable") {
                record.prunable = true;
            }
        }
    }
    if let Some(worktree) = current {
        worktrees.push(worktree);
    }
    Ok(worktrees)
}

fn resolved_named(
    project: &GitProject,
    name: &str,
    worktree: &GitWorktree,
    origin: WorkspaceOrigin,
) -> Result<ResolvedWorkspace, GitWorkspaceError> {
    let path = worktree
        .path
        .canonicalize()
        .map_err(|source| GitWorkspaceError::Io {
            context: "canonicalize named Git worktree",
            source,
        })?;
    Ok(ResolvedWorkspace {
        project: project.id.clone(),
        primary_checkout: project.primary_path.clone(),
        selection: WorkspaceSelection::Named(crate::model::WorkspaceName(name.to_owned())),
        path,
        change_name: Some(name.to_owned()),
        origin,
        support_mounts: vec![WorkspaceSupportMount {
            source: project.common_dir.clone(),
            destination: project.common_dir.clone(),
        }],
    })
}

fn validate_branch(directory: &Path, name: &str) -> Result<(), GitWorkspaceError> {
    let output = git_output(
        directory,
        [
            OsStr::new("check-ref-format"),
            OsStr::new("--branch"),
            OsStr::new(name),
        ],
    )?;
    if output.status.success() {
        Ok(())
    } else {
        Err(GitWorkspaceError::InvalidWorkspaceName(name.to_owned()))
    }
}

fn git_status<'a>(
    directory: &Path,
    arguments: impl IntoIterator<Item = &'a OsStr>,
) -> Result<bool, GitWorkspaceError> {
    let output = git_output(directory, arguments)?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(command_failed("git", &output)),
    }
}

fn git_stdout<'a>(
    directory: &Path,
    arguments: impl IntoIterator<Item = &'a OsStr>,
) -> Result<Vec<u8>, GitWorkspaceError> {
    let output = git_output(directory, arguments)?;
    if !output.status.success() {
        return Err(command_failed("git", &output));
    }
    Ok(output.stdout)
}

fn git_output<'a>(
    directory: &Path,
    arguments: impl IntoIterator<Item = &'a OsStr>,
) -> Result<Output, GitWorkspaceError> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("LC_ALL", "C");
    run_bounded(&mut command, "git", GIT_DEADLINE, MAX_GIT_OUTPUT)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureStream {
    Stdout = 1,
    Stderr = 2,
}

impl CaptureStream {
    const fn name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

enum CaptureResult {
    Data(Vec<u8>),
    Overflow(CaptureStream),
}

#[tracing::instrument(
    level = "debug",
    skip_all,
    name = "run_bounded_git_command",
    fields(command = command_name)
)]
fn run_bounded(
    command: &mut Command,
    command_name: &'static str,
    deadline: Duration,
    output_limit: usize,
) -> Result<Output, GitWorkspaceError> {
    debug!(command = ?command, "executing Git command");
    let started = Instant::now();
    let mut child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| GitWorkspaceError::Io {
            context: "execute Git",
            source,
        })?;
    let process_group =
        Pid::from_raw(
            i32::try_from(child.id()).map_err(|_| GitWorkspaceError::Io {
                context: "read Git process group",
                source: io::Error::other("Git PID does not fit pid_t"),
            })?,
        );
    let (stdout_reader, stderr_reader, overflow) =
        start_capture_readers(&mut child, process_group, output_limit)?;

    let mut status = None;
    loop {
        let overflowed = overflow.load(Ordering::Acquire);
        if overflowed != 0 {
            kill_group_and_reap(&mut child, process_group)?;
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            let stream = if overflowed & CaptureStream::Stdout as u8 != 0 {
                CaptureStream::Stdout
            } else {
                CaptureStream::Stderr
            };
            return Err(GitWorkspaceError::OutputOverflow {
                command: command_name,
                stream: stream.name(),
                limit: output_limit,
            });
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(observed) => status = observed,
                Err(source) => {
                    let cleanup = kill_group_and_reap(&mut child, process_group);
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    cleanup?;
                    return Err(GitWorkspaceError::Io {
                        context: "wait for Git",
                        source,
                    });
                }
            }
        }
        if status.is_some() && stdout_reader.is_finished() && stderr_reader.is_finished() {
            break;
        }
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            kill_group_and_reap(&mut child, process_group)?;
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(GitWorkspaceError::CommandTimedOut {
                command: command_name,
                deadline,
            });
        }
        thread::sleep(COMMAND_POLL_INTERVAL.min(remaining));
    }

    let status = status.expect("Git status is available before readers finish");
    let stdout = join_capture(stdout_reader, "read Git stdout", command_name, output_limit)?;
    let stderr = join_capture(stderr_reader, "read Git stderr", command_name, output_limit)?;
    debug!(
        status = ?status.code(),
        elapsed_ms = started.elapsed().as_millis(),
        stdout_bytes = stdout.len(),
        stderr_bytes = stderr.len(),
        "Git command finished"
    );
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

type CaptureReader = thread::JoinHandle<io::Result<CaptureResult>>;

fn start_capture_readers(
    child: &mut std::process::Child,
    process_group: Pid,
    output_limit: usize,
) -> Result<(CaptureReader, CaptureReader, Arc<AtomicU8>), GitWorkspaceError> {
    let Some(stdout) = child.stdout.take() else {
        kill_group_and_reap(child, process_group)?;
        return Err(GitWorkspaceError::Io {
            context: "capture Git stdout",
            source: io::Error::other("spawned command had no stdout pipe"),
        });
    };
    let Some(stderr) = child.stderr.take() else {
        kill_group_and_reap(child, process_group)?;
        return Err(GitWorkspaceError::Io {
            context: "capture Git stderr",
            source: io::Error::other("spawned command had no stderr pipe"),
        });
    };
    let overflow = Arc::new(AtomicU8::new(0));
    let stdout_overflow = Arc::clone(&overflow);
    let stdout_reader = match thread::Builder::new().spawn(move || {
        capture_output(
            stdout,
            output_limit,
            CaptureStream::Stdout,
            &stdout_overflow,
        )
    }) {
        Ok(reader) => reader,
        Err(source) => {
            kill_group_and_reap(child, process_group)?;
            return Err(GitWorkspaceError::Io {
                context: "start Git stdout reader",
                source,
            });
        }
    };
    let stderr_overflow = Arc::clone(&overflow);
    let stderr_reader = match thread::Builder::new().spawn(move || {
        capture_output(
            stderr,
            output_limit,
            CaptureStream::Stderr,
            &stderr_overflow,
        )
    }) {
        Ok(reader) => reader,
        Err(source) => {
            kill_group_and_reap(child, process_group)?;
            let _ = stdout_reader.join();
            return Err(GitWorkspaceError::Io {
                context: "start Git stderr reader",
                source,
            });
        }
    };
    Ok((stdout_reader, stderr_reader, overflow))
}

fn capture_output(
    mut pipe: impl Read,
    limit: usize,
    stream: CaptureStream,
    overflow: &AtomicU8,
) -> io::Result<CaptureResult> {
    let mut output = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = pipe.read(&mut buffer)?;
        if count == 0 {
            return Ok(CaptureResult::Data(output));
        }
        if count > limit.saturating_sub(output.len()) {
            overflow.fetch_or(stream as u8, Ordering::Release);
            return Ok(CaptureResult::Overflow(stream));
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

fn join_capture(
    reader: thread::JoinHandle<io::Result<CaptureResult>>,
    context: &'static str,
    command: &'static str,
    limit: usize,
) -> Result<Vec<u8>, GitWorkspaceError> {
    match reader.join() {
        Ok(Ok(CaptureResult::Data(output))) => Ok(output),
        Ok(Ok(CaptureResult::Overflow(stream))) => Err(GitWorkspaceError::OutputOverflow {
            command,
            stream: stream.name(),
            limit,
        }),
        Ok(Err(source)) => Err(GitWorkspaceError::Io { context, source }),
        Err(_) => Err(GitWorkspaceError::Io {
            context,
            source: io::Error::other("Git output reader panicked"),
        }),
    }
}

fn kill_group_and_reap(
    child: &mut std::process::Child,
    process_group: Pid,
) -> Result<(), GitWorkspaceError> {
    if let Err(error) = killpg(process_group, Signal::SIGKILL)
        && error != Errno::ESRCH
    {
        let _ = child.wait();
        return Err(GitWorkspaceError::Io {
            context: "kill Git process group",
            source: io::Error::from_raw_os_error(error as i32),
        });
    }
    child.wait().map_err(|source| GitWorkspaceError::Io {
        context: "reap Git",
        source,
    })?;
    Ok(())
}

fn trim_one_line(mut output: Vec<u8>, field: &str) -> Result<Vec<u8>, GitWorkspaceError> {
    if output.last() == Some(&b'\n') {
        output.pop();
    }
    if output.is_empty() || output.contains(&b'\n') || output.contains(&0) {
        return Err(GitWorkspaceError::InvalidRepository(format!(
            "invalid {field}"
        )));
    }
    Ok(output)
}

fn create_private_directory(path: &Path) -> Result<(), GitWorkspaceError> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            GitWorkspaceError::Io {
                context: "secure workspace directory",
                source,
            }
        }),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|source| GitWorkspaceError::Io {
                context: "inspect workspace directory",
                source,
            })?;
            if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
                Ok(())
            } else {
                Err(GitWorkspaceError::InvalidRepository(format!(
                    "workspace directory is not a real directory: {}",
                    path.display()
                )))
            }
        }
        Err(source) => Err(GitWorkspaceError::Io {
            context: "create workspace directory",
            source,
        }),
    }
}

fn project_id(common_dir: &Path) -> ProjectId {
    ProjectId(hex_digest(common_dir.as_os_str().as_bytes()))
}

fn project_directory_name(project: &GitProject) -> String {
    let slug = project
        .primary_path
        .file_name()
        .and_then(OsStr::to_str)
        .map(sanitize_slug)
        .filter(|slug| !slug.is_empty())
        .unwrap_or_else(|| "project".to_owned());
    format!("{slug}--{}", &project.id.0[..16])
}

fn workspace_directory_name(name: &str) -> String {
    let slug = sanitize_slug(name);
    let slug = if slug.is_empty() { "workspace" } else { &slug };
    format!("{slug}--{}", &hex_digest(name.as_bytes())[..16])
}

fn sanitize_slug(value: &str) -> String {
    value
        .chars()
        .take(48)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn hex_digest(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("write to String");
    }
    encoded
}

fn short_branch(reference: &str) -> String {
    reference
        .strip_prefix("refs/heads/")
        .unwrap_or(reference)
        .to_owned()
}

fn command_failed(command: &'static str, output: &Output) -> GitWorkspaceError {
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    GitWorkspaceError::Command {
        command,
        status: output.status.code(),
        diagnostic: diagnostic.trim().chars().take(1_024).collect(),
    }
}

#[derive(Debug)]
pub enum GitWorkspaceError {
    Io {
        context: &'static str,
        source: io::Error,
    },
    Command {
        command: &'static str,
        status: Option<i32>,
        diagnostic: String,
    },
    CommandTimedOut {
        command: &'static str,
        deadline: Duration,
    },
    OutputOverflow {
        command: &'static str,
        stream: &'static str,
        limit: usize,
    },
    DestinationExists(PathBuf),
    PrimaryRetirement,
    WorkspaceNotFound(String),
    AmbiguousWorkspace(String),
    UnmanagedWorkspace(PathBuf),
    UnsafeWorkspacePath(PathBuf),
    DirtyWorkspace(PathBuf),
    ActiveWorkspace(PathBuf),
    InvalidRepository(String),
    InvalidWorkspaceName(String),
}

impl GitWorkspaceError {
    /// Stable machine-readable control-protocol code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "io_error",
            Self::Command { .. } => "git_failed",
            Self::CommandTimedOut { .. } => "git_timeout",
            Self::OutputOverflow { .. } => "git_output_overflow",
            Self::DestinationExists(_) => "workspace_path_exists",
            Self::PrimaryRetirement => "primary_workspace",
            Self::WorkspaceNotFound(_) => "workspace_not_found",
            Self::AmbiguousWorkspace(_) => "workspace_ambiguous",
            Self::UnmanagedWorkspace(_) => "workspace_unmanaged",
            Self::UnsafeWorkspacePath(_) => "workspace_path_unsafe",
            Self::DirtyWorkspace(_) => "workspace_dirty",
            Self::ActiveWorkspace(_) => "workspace_active",
            Self::InvalidRepository(_) => "invalid_repository",
            Self::InvalidWorkspaceName(_) => "invalid_workspace_name",
        }
    }
}

impl Display for GitWorkspaceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(formatter, "{context}: {source}"),
            Self::Command {
                command,
                status,
                diagnostic,
            } => write!(
                formatter,
                "{command} failed with status {status:?}: {diagnostic}"
            ),
            Self::CommandTimedOut { command, deadline } => {
                write!(formatter, "{command} exceeded its {deadline:?} deadline")
            }
            Self::OutputOverflow {
                command,
                stream,
                limit,
            } => write!(
                formatter,
                "{command} {stream} exceeded its {limit}-byte capture limit"
            ),
            Self::DestinationExists(path) => write!(
                formatter,
                "managed workspace destination already exists: {}",
                path.display()
            ),
            Self::PrimaryRetirement => {
                formatter.write_str("the primary worktree cannot be retired")
            }
            Self::WorkspaceNotFound(name) => write!(formatter, "workspace not found: {name}"),
            Self::AmbiguousWorkspace(name) => {
                write!(formatter, "multiple active worktrees use branch {name}")
            }
            Self::UnmanagedWorkspace(path) => {
                write!(
                    formatter,
                    "worktree is not daemon-managed: {}",
                    path.display()
                )
            }
            Self::UnsafeWorkspacePath(path) => {
                write!(formatter, "workspace path is unsafe: {}", path.display())
            }
            Self::DirtyWorkspace(path) => {
                write!(
                    formatter,
                    "workspace has uncommitted changes: {}",
                    path.display()
                )
            }
            Self::ActiveWorkspace(path) => {
                write!(
                    formatter,
                    "workspace has an active instance: {}",
                    path.display()
                )
            }
            Self::InvalidRepository(message) => formatter.write_str(message),
            Self::InvalidWorkspaceName(name) => {
                write!(formatter, "invalid Git workspace branch name: {name}")
            }
        }
    }
}

impl std::error::Error for GitWorkspaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "runroom-workspace-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn successful_git(directory: &Path, arguments: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(arguments)
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::null())
            .output()
            .expect("execute test Git");
        assert!(
            output.status.success(),
            "Git command failed: {arguments:?}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn repository(test: &TestDirectory) -> PathBuf {
        let primary = test.0.join("primary");
        fs::create_dir(&primary).expect("create primary directory");
        successful_git(&primary, &["init", "--quiet"]);
        successful_git(&primary, &["config", "user.name", "Runroom Test"]);
        successful_git(
            &primary,
            &["config", "user.email", "runroom-test@example.invalid"],
        );
        fs::write(primary.join("tracked"), b"initial\n").expect("write tracked file");
        successful_git(&primary, &["add", "tracked"]);
        successful_git(&primary, &["commit", "--quiet", "-m", "initial"]);
        primary
    }

    #[test]
    fn here_resolves_non_git_directory_and_canonical_alias_to_one_identity() {
        let test = TestDirectory::new("here-non-git");
        let directory = test.0.join("working");
        fs::create_dir(&directory).expect("create working directory");
        let alias = test.0.join("alias");
        std::os::unix::fs::symlink(&directory, &alias).expect("create directory alias");
        let backend = GitWorkspaceBackend::new(test.0.join("managed"));
        let (project, workspace) = backend
            .resolve_launch_workspace(&directory, &WorkspaceSelection::Here)
            .expect("resolve non-Git directory");
        let aliased = backend
            .resolve_workspace(&alias, &WorkspaceSelection::Here)
            .expect("resolve aliased directory");
        let canonical = directory.canonicalize().expect("canonical directory");
        assert_eq!(workspace, aliased);
        assert_eq!(workspace.path, canonical);
        assert_eq!(workspace.primary_checkout, canonical);
        assert_eq!(project.primary_checkout, canonical);
        assert_eq!(project.id, workspace.project);
        assert_ne!(workspace.project, project_id(&canonical));
        assert_eq!(workspace.origin, WorkspaceOrigin::Directory);
        assert_eq!(workspace.change_name, None);
        assert_eq!(workspace.support_mounts, Vec::new());
        assert!(!test.0.join("managed").exists());
    }

    #[test]
    fn here_keeps_nested_git_directory_and_uses_distinct_path_identity() {
        let test = TestDirectory::new("here-nested-git");
        let primary = repository(&test);
        let nested = primary.join("nested");
        fs::create_dir(&nested).expect("create nested directory");
        let backend = GitWorkspaceBackend::new(test.0.join("managed"));
        let workspace = backend
            .resolve_workspace(&nested, &WorkspaceSelection::Here)
            .expect("resolve nested directory");
        let root = backend
            .resolve_workspace(&primary, &WorkspaceSelection::Here)
            .expect("resolve root directory");
        let git = backend
            .canonical_project(&nested)
            .expect("resolve Git project");
        assert_eq!(
            workspace.path,
            nested.canonicalize().expect("canonical nested")
        );
        assert_eq!(workspace.primary_checkout, workspace.path);
        assert_ne!(workspace.project, root.project);
        assert_ne!(workspace.project, git.id);
        assert_eq!(workspace.support_mounts, Vec::new());
        fs::write(nested.join(".git"), b"invalid Git metadata")
            .expect("write invalid nested Git marker");
        let without_git = backend
            .resolve_workspace(&nested, &WorkspaceSelection::Here)
            .expect("directory selection ignores invalid Git metadata");
        assert_eq!(without_git, workspace);
        assert!(!test.0.join("managed").exists());
    }

    #[test]
    fn here_rejects_missing_paths_and_regular_files() {
        let test = TestDirectory::new("here-invalid");
        let backend = GitWorkspaceBackend::new(test.0.join("managed"));
        let missing = backend
            .resolve_workspace(&test.0.join("missing"), &WorkspaceSelection::Here)
            .expect_err("reject missing path");
        assert_eq!(missing.code(), "io_error");
        let file = test.0.join("file");
        fs::write(&file, b"not a directory").expect("write file");
        let error = backend
            .resolve_workspace(&file, &WorkspaceSelection::Here)
            .expect_err("reject regular file");
        assert_eq!(error.code(), "invalid_repository");
    }

    #[test]
    fn bounded_runner_captures_stdout_and_stderr_concurrently() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "i=0; while [ \"$i\" -lt 2000 ]; do printf o; printf e >&2; i=$((i + 1)); done",
        ]);

        let output = run_bounded(&mut command, "capture-test", Duration::from_secs(2), 4_096)
            .expect("bounded command succeeds");

        assert!(output.status.success());
        assert_eq!(output.stdout, vec![b'o'; 2_000]);
        assert_eq!(output.stderr, vec![b'e'; 2_000]);
    }

    #[test]
    fn bounded_runner_distinguishes_deadline_from_output_overflow() {
        let mut timeout = Command::new("sh");
        timeout.args(["-c", "while :; do :; done"]);
        let timeout_error =
            run_bounded(&mut timeout, "timeout-test", Duration::from_millis(40), 64)
                .expect_err("busy command times out");
        assert_eq!(timeout_error.code(), "git_timeout");

        let mut overflow = Command::new("sh");
        overflow.args(["-c", "while :; do printf 1234567890; done"]);
        let overflow_error =
            run_bounded(&mut overflow, "overflow-test", Duration::from_secs(2), 64)
                .expect_err("large output is rejected");
        assert_eq!(overflow_error.code(), "git_output_overflow");
        assert!(matches!(
            overflow_error,
            GitWorkspaceError::OutputOverflow {
                stream: "stdout",
                limit: 64,
                ..
            }
        ));
    }

    #[test]
    fn retirement_rejects_primary_and_unmanaged_worktrees() {
        let test = TestDirectory::new("retire-unmanaged");
        let primary = repository(&test);
        let root = test.0.join("managed");
        fs::create_dir(&root).expect("create managed root");
        let external = test.0.join("external");
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&primary)
                .args(["worktree", "add", "--quiet", "-b", "foreign"])
                .arg(&external)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("create external worktree")
                .success()
        );
        let backend = GitWorkspaceBackend::new(&root);

        let primary_error = backend
            .retire_workspace(&primary, &WorkspaceSelection::Primary)
            .expect_err("primary retirement is rejected");
        assert_eq!(primary_error.code(), "primary_workspace");

        let unmanaged_error = backend
            .retire_workspace(
                &primary,
                &WorkspaceSelection::Named(WorkspaceName("foreign".to_owned())),
            )
            .expect_err("external worktree is rejected");
        assert_eq!(unmanaged_error.code(), "workspace_unmanaged");
        assert!(external.exists());
    }

    #[test]
    fn retirement_rejects_ambiguous_active_branch() {
        let test = TestDirectory::new("retire-ambiguous");
        let primary = repository(&test);
        let backend = GitWorkspaceBackend::new(test.0.join("managed"));
        let mut project =
            GitWorkspaceBackend::discover(&primary, false).expect("discover test repository");
        project.worktrees.push(GitWorktree {
            path: test.0.join("one"),
            branch: Some("refs/heads/ambiguous".to_owned()),
            bare: false,
            prunable: false,
        });
        project.worktrees.push(GitWorktree {
            path: test.0.join("two"),
            branch: Some("refs/heads/ambiguous".to_owned()),
            bare: false,
            prunable: false,
        });

        let error = backend
            .retire_named(&project, &WorkspaceName("ambiguous".to_owned()), |_| false)
            .expect_err("duplicate active branch is rejected");

        assert_eq!(error.code(), "workspace_ambiguous");
    }

    #[test]
    fn retirement_rejects_dirty_managed_worktree() {
        let test = TestDirectory::new("retire-dirty");
        let primary = repository(&test);
        let backend = GitWorkspaceBackend::new(test.0.join("managed"));
        let selection = WorkspaceSelection::Named(WorkspaceName("dirty".to_owned()));
        let workspace = backend
            .resolve_workspace(&primary, &selection)
            .expect("create managed worktree");
        fs::write(workspace.path.join("untracked"), b"dirty\n").expect("dirty worktree");

        let error = backend
            .retire_workspace(&primary, &selection)
            .expect_err("dirty worktree is rejected");

        assert_eq!(error.code(), "workspace_dirty");
        assert!(workspace.path.exists());
    }

    #[test]
    fn retirement_removes_clean_worktree_but_retains_branch() {
        let test = TestDirectory::new("retire-clean");
        let primary = repository(&test);
        let backend = GitWorkspaceBackend::new(test.0.join("managed"));
        let selection = WorkspaceSelection::Named(WorkspaceName("finished".to_owned()));
        let workspace = backend
            .resolve_workspace(&primary, &selection)
            .expect("create managed worktree");

        let retired = backend
            .retire_workspace(&primary, &selection)
            .expect("retire clean worktree");

        assert_eq!(retired.path, workspace.path);
        assert!(!retired.path.exists());
        successful_git(
            &primary,
            &["show-ref", "--verify", "--quiet", "refs/heads/finished"],
        );
    }

    #[test]
    fn retirement_rejects_symlink_at_managed_destination() {
        use std::os::unix::fs::symlink;

        let test = TestDirectory::new("retire-symlink");
        let root = test.0.join("managed");
        fs::create_dir(&root).expect("create managed root");
        let outside = test.0.join("outside");
        fs::create_dir(&outside).expect("create outside directory");
        let project = GitProject {
            id: ProjectId("0123456789abcdef0123456789abcdef".to_owned()),
            common_dir: test.0.join("common"),
            primary_path: test.0.join("primary"),
            worktrees: Vec::new(),
        };
        let project_directory = root.join(project_directory_name(&project));
        fs::create_dir(&project_directory).expect("create project directory");
        let name = WorkspaceName("unsafe".to_owned());
        let destination = project_directory.join(workspace_directory_name(&name.0));
        symlink(&outside, &destination).expect("create escaping symlink");
        let worktree = GitWorktree {
            path: destination,
            branch: Some("refs/heads/unsafe".to_owned()),
            bare: false,
            prunable: false,
        };
        let backend = GitWorkspaceBackend::new(root);

        let error = backend
            .managed_worktree_path(&project, &name, &worktree)
            .expect_err("symlink destination is unsafe");

        assert_eq!(error.code(), "workspace_path_unsafe");
    }

    #[test]
    fn prune_reports_only_metadata_it_removed() {
        let test = TestDirectory::new("prune");
        let primary = repository(&test);
        let stale = test.0.join("stale");
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&primary)
                .args(["worktree", "add", "--quiet", "-b", "stale"])
                .arg(&stale)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("create stale worktree")
                .success()
        );
        fs::remove_dir_all(&stale).expect("remove worktree behind Git's back");
        let backend = GitWorkspaceBackend::new(test.0.join("managed"));
        let resolution_error = backend
            .resolve_workspace(&primary, &WorkspaceSelection::Primary)
            .expect_err("normal resolution does not implicitly prune");
        assert_eq!(resolution_error.code(), "invalid_repository");

        let repaired = backend
            .prune_stale_worktrees(&primary)
            .expect("prune stale metadata");
        let unchanged = backend
            .prune_stale_worktrees(&primary)
            .expect("second prune is empty");

        assert_eq!(repaired.paths, vec![stale]);
        assert_eq!(unchanged.paths, Vec::<PathBuf>::new());
    }
}
