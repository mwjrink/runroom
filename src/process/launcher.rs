//! Concrete foreground launcher role.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use nix::fcntl::{FcntlArg, SealFlag, fcntl};
use nix::sys::memfd::{MFdFlags, memfd_create};
use serde::Serialize;
use tracing::debug;

use crate::backend::{BubblewrapRuntimeBackend, NativeRuntimeBackend, RuntimeBackend};
use crate::environment::{PROJECT_ENV_KEYS, ProjectEnvironment};
use crate::model::{
    BindAccess, BindMountSource, EnvironmentVariable, ForegroundCommand, HerdrContext,
    LaunchHandoff, LaunchRequest, LaunchSpec, LauncherContinuation, PrepareLaunchRequest,
    PreparedLaunch, ResourceLimits, RuntimeDataFile, RuntimeKind, RuntimePolicy, WorkspaceName,
    WorkspaceOrigin, WorkspaceSelection,
};
use crate::protocol::{ControlOperation, ControlRequest, ControlResult};
use crate::transport::{connect_control, read_control_response, write_control_request};

use super::RunToken;

/// Launcher startup state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LauncherConfig {
    socket_path: PathBuf,
    workspace_selection: WorkspaceSelection,
    profile: String,
    command: ForegroundCommand,
    runtime: RuntimePolicy,
    herdr_identity: bool,
    no_multiplex: bool,
    limits: ResourceLimits,
    project_environment: bool,
    environment_allowlist: Vec<String>,
    resume_token: Option<String>,
    continuation_token: Option<String>,
}

impl LauncherConfig {
    /// Configure a launcher connecting to `socket_path`.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        profile: String,
        command: ForegroundCommand,
        runtime: RuntimePolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            workspace_selection: WorkspaceSelection::Primary,
            profile,
            command,
            runtime,
            herdr_identity: false,
            no_multiplex: false,
            limits: ResourceLimits::default(),
            project_environment: false,
            environment_allowlist: Vec::new(),
            resume_token: None,
            continuation_token: None,
        }
    }

    /// Select a default named workspace instead of the project's primary workspace.
    #[must_use]
    pub fn workspace_name(mut self, workspace_name: WorkspaceName) -> Self {
        self.workspace_selection = WorkspaceSelection::Named(workspace_name);
        self
    }

    /// Require Herdr launch identity and publish it inside the isolated runtime.
    #[must_use]
    pub const fn herdr_identity(mut self, enabled: bool) -> Self {
        self.herdr_identity = enabled;
        self
    }

    /// Select the exact current directory, or return directory selection to primary.
    #[must_use]
    pub fn here(mut self, enabled: bool) -> Self {
        if enabled {
            self.workspace_selection = WorkspaceSelection::Here;
        } else if matches!(self.workspace_selection, WorkspaceSelection::Here) {
            self.workspace_selection = WorkspaceSelection::Primary;
        }
        self
    }

    /// Execute in this terminal without Herdr routing or identity.
    #[must_use]
    pub const fn no_multiplex(mut self, enabled: bool) -> Self {
        self.no_multiplex = enabled;
        self
    }
    /// Apply validated resource limits to the daemon-owned process scope.
    #[must_use]
    pub fn resource_limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }
    /// Resolve the selected project's Runroom environment after workspace selection.
    #[must_use]
    pub fn project_environment(mut self, enabled: bool, allowlist: Vec<String>) -> Self {
        self.project_environment = enabled;
        self.environment_allowlist = allowlist;
        self
    }

    /// Resume one daemon-issued Herdr handoff token.
    #[must_use]
    pub fn resume_token(mut self, token: String) -> Self {
        self.resume_token = Some(token);
        self
    }

    /// Bind this launcher to one daemon-issued Herdr destination.
    #[must_use]
    pub fn continuation_token(mut self, token: String) -> Self {
        self.continuation_token = Some(token);
        self
    }
}

/// Foreground launcher state.
#[derive(Debug)]
pub struct Launcher {
    config: LauncherConfig,
    _private: (),
}

impl Launcher {
    pub(super) fn new(_run_token: RunToken, config: LauncherConfig) -> Self {
        Self {
            config,
            _private: (),
        }
    }

    #[tracing::instrument(level = "debug", skip_all, name = "run_launcher")]
    pub(super) fn run(mut self) -> io::Result<()> {
        if self.config.no_multiplex
            && (self.config.resume_token.is_some() || self.config.continuation_token.is_some())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "foreground launch cannot resume a Herdr continuation",
            ));
        }
        if let Some(token) = self.config.resume_token.as_deref() {
            return self.resume_handoff(token);
        }
        let selection = std::mem::replace(
            &mut self.config.workspace_selection,
            WorkspaceSelection::Primary,
        );
        let here = matches!(selection, WorkspaceSelection::Here);
        self.config.herdr_identity = !self.config.no_multiplex
            && if here {
                self.config.continuation_token.is_some()
            } else {
                self.config.herdr_identity
            };
        let current_directory = env::current_dir()?;
        debug!(
            socket = %self.config.socket_path.display(),
            current_directory = %current_directory.display(),
            workspace = match &selection {
                WorkspaceSelection::Primary => "primary",
                WorkspaceSelection::Named(name) => &name.0,
                WorkspaceSelection::Here => "here",
            },
            profile = self.config.profile,
            "starting launcher"
        );
        let mut stream = connect_control(&self.config.socket_path)?;

        debug!(
            herdr_identity = self.config.herdr_identity,
            "resolving launch identity"
        );
        let herdr = if self.config.herdr_identity {
            Some(HerdrContext {
                workspace_id: Some(required_herdr_value("HERDR_WORKSPACE_ID")?),
                pane_id: Some(required_herdr_value("HERDR_PANE_ID")?),
                session_name: herdr_session_name()?,
            })
        } else {
            None
        };
        let continuation = (!self.config.no_multiplex && (here || self.config.herdr_identity))
            .then(|| self.build_handoff())
            .transpose()?;
        debug!("building launch preparation request");
        let request = ControlRequest {
            request_id: 1,
            operation: ControlOperation::PrepareLaunch(PrepareLaunchRequest {
                workspace: LaunchRequest {
                    current_directory,
                    workspace: selection,
                },
                profile: self.config.profile.clone(),
                no_multiplex: self.config.no_multiplex,
                limits: std::mem::take(&mut self.config.limits),
                herdr,
                continuation,
                continuation_token: self.config.continuation_token.clone(),
            }),
        };
        debug!("requesting launch preparation from daemon");
        write_control_request(&mut stream, &request)?;
        let response = read_control_response(&mut stream)?;
        debug!("received launch preparation response");
        if response.request_id != request.request_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "daemon response request ID does not match",
            ));
        }
        match response.result {
            Ok(ControlResult::LaunchPrepared(launch)) => {
                debug!(
                    instance = %launch.instance_id.0,
                    project = %launch.workspace.project.0,
                    workspace = %launch.workspace.path.display(),
                    origin = ?launch.workspace.origin,
                    "daemon prepared launch"
                );
                self.execute_foreground(&launch)
            }
            Ok(ControlResult::LaunchRedirected) => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "daemon returned an unexpected launch result",
            )),
            Err(error) => Err(io::Error::other(format!(
                "daemon rejected workspace [{}]: {}",
                error.code, error.message
            ))),
        }
    }

    fn build_handoff(&self) -> io::Result<LaunchHandoff> {
        let executable = self
            .config
            .command
            .executable
            .to_str()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "foreground executable is not valid UTF-8",
                )
            })?
            .to_owned();
        let mut words = Vec::with_capacity(1 + self.config.command.arguments.len());
        words.push(executable);
        for argument in &self.config.command.arguments {
            words.push(
                argument
                    .to_str()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "foreground argument is not valid UTF-8",
                        )
                    })?
                    .to_owned(),
            );
        }
        Ok(LaunchHandoff {
            socket_path: self.config.socket_path.clone(),
            command: shell_words::join(words),
        })
    }

    fn resume_handoff(&self, token: &str) -> io::Result<()> {
        let herdr = HerdrContext {
            workspace_id: Some(required_herdr_value("HERDR_WORKSPACE_ID")?),
            pane_id: Some(required_herdr_value("HERDR_PANE_ID")?),
            session_name: herdr_session_name()?,
        };
        let mut stream = connect_control(&self.config.socket_path)?;
        let request = ControlRequest {
            request_id: 1,
            operation: ControlOperation::ResumeLaunch {
                token: token.to_owned(),
                herdr,
            },
        };
        write_control_request(&mut stream, &request)?;
        let response = read_control_response(&mut stream)?;
        if response.request_id != request.request_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "daemon response request ID does not match",
            ));
        }
        match response.result {
            Ok(ControlResult::LaunchContinuation(continuation)) => {
                Self::exec_continuation(token, continuation)
            }
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "daemon returned an unexpected continuation result",
            )),
            Err(error) => Err(io::Error::other(format!(
                "daemon rejected launch continuation [{}]: {}",
                error.code, error.message
            ))),
        }
    }

    fn exec_continuation(token: &str, continuation: LauncherContinuation) -> io::Result<()> {
        let executable = env::current_exe()?;
        let mut arguments = vec![
            OsString::from("launcher"),
            OsString::from("--socket"),
            continuation.socket_path.into_os_string(),
            OsString::from("--profile"),
            OsString::from(continuation.profile),
            OsString::from("--command"),
            OsString::from(continuation.command),
            OsString::from("--continuation-token"),
            OsString::from(token),
        ];
        match continuation.workspace {
            WorkspaceSelection::Named(name) => {
                arguments.push(OsString::from("--name"));
                arguments.push(OsString::from(name.0));
            }
            WorkspaceSelection::Here => arguments.push(OsString::from("--here")),
            WorkspaceSelection::Primary => {}
        }
        let error = Command::new(&executable).args(arguments).exec();
        Err(io::Error::new(
            error.kind(),
            format!(
                "cannot execute routed Runroom launcher {}: {error}",
                executable.display()
            ),
        ))
    }

    #[tracing::instrument(level = "debug", skip_all, name = "execute_foreground")]
    fn execute_foreground(self, prepared_launch: &PreparedLaunch) -> io::Result<()> {
        let workspace = &prepared_launch.workspace;
        let metadata = workspace.path.metadata().map_err(|source| {
            io::Error::new(
                source.kind(),
                format!(
                    "resolved workspace {} cannot be inspected: {source}",
                    workspace.path.display()
                ),
            )
        })?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "resolved workspace is not a directory: {}",
                    workspace.path.display()
                ),
            ));
        }
        let mut runtime = self.config.runtime.clone();
        if self.config.project_environment {
            apply_project_environment(workspace, &self.config.environment_allowlist, &mut runtime)?;
        }
        let support_mount_access = runtime
            .bind_mounts
            .iter()
            .find_map(|mount| {
                matches!(mount.source, BindMountSource::Workspace).then_some(mount.access)
            })
            .unwrap_or(BindAccess::ReadOnly);
        let descriptor = (self.config.herdr_identity && runtime.kind == RuntimeKind::Bubblewrap)
            .then(|| create_launch_descriptor(prepared_launch, &self.config))
            .transpose()?;
        let runtime_kind = self.config.runtime.kind;
        let foreground_executable = self.config.command.executable.clone();
        let launch = LaunchSpec {
            workspace: workspace.clone(),
            runtime,
            command: self.config.command,
            support_mount_access,
        };
        let prepared = match runtime_kind {
            RuntimeKind::Native => NativeRuntimeBackend.prepare(&launch),
            RuntimeKind::Bubblewrap => {
                let data_files = descriptor
                    .as_ref()
                    .map(|file| {
                        vec![RuntimeDataFile {
                            descriptor: file.as_raw_fd(),
                            destination: "/runtime/launch.json",
                        }]
                    })
                    .unwrap_or_default();
                BubblewrapRuntimeBackend.prepare_with_data_files(&launch, &data_files)
            }
        }
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        env::set_current_dir(&prepared.working_directory).map_err(|source| {
            io::Error::new(
                source.kind(),
                format!(
                    "cannot enter runtime working directory {}: {source}",
                    prepared.working_directory.display()
                ),
            )
        })?;
        debug!(
            project = %workspace.project.0,
            workspace = %workspace.path.display(),
            origin = ?workspace.origin,
            profile = self.config.profile,
            runtime = ?runtime_kind,
            network = ?launch.runtime.network,
            mount_count = launch.runtime.bind_mounts.len() + launch.workspace.support_mounts.len(),
            executable = %foreground_executable.display(),
            "launcher executing foreground command"
        );
        let mut command = Command::new(&prepared.executable);
        command.args(&prepared.arguments);
        if runtime_kind == RuntimeKind::Native {
            for variable in &launch.runtime.environment {
                command.env(&variable.name, &variable.value);
            }
        }
        let error = command.exec();
        let message = match runtime_kind {
            RuntimeKind::Native => format!(
                "cannot execute foreground command {}: {error}",
                foreground_executable.display()
            ),
            RuntimeKind::Bubblewrap => format!(
                "cannot execute Bubblewrap runtime {} for foreground command {}: {error}",
                prepared.executable.display(),
                foreground_executable.display()
            ),
        };
        Err(io::Error::new(error.kind(), message))
    }
}

#[tracing::instrument(level = "debug", skip_all, name = "apply_project_environment")]
fn apply_project_environment(
    workspace: &crate::model::ResolvedWorkspace,
    allowlist: &[String],
    runtime: &mut RuntimePolicy,
) -> io::Result<()> {
    let inherited: BTreeMap<String, String> = PROJECT_ENV_KEYS
        .into_iter()
        .filter_map(|key| env::var(key).ok().map(|value| (key.to_owned(), value)))
        .collect();
    debug!(
        inherited_count = inherited.len(),
        allowlist_count = allowlist.len(),
        "resolving project environment"
    );
    let resolved = ProjectEnvironment::resolve(workspace, &inherited)?;
    apply_resolved_environment(resolved.values, allowlist, runtime);
    Ok(())
}

#[tracing::instrument(level = "debug", skip_all, name = "apply_resolved_environment")]
fn apply_resolved_environment(
    resolved: BTreeMap<String, String>,
    allowlist: &[String],
    runtime: &mut RuntimePolicy,
) {
    let selected: BTreeMap<_, _> = resolved
        .into_iter()
        .filter(|(name, _)| allowlist.iter().any(|allowed| allowed == name))
        .collect();
    debug!(
        selected_count = selected.len(),
        selected_names = ?selected.keys(),
        "selected project environment variables"
    );
    runtime
        .environment
        .retain(|variable| !selected.contains_key(&variable.name));
    runtime.environment.extend(
        selected
            .into_iter()
            .map(|(name, value)| EnvironmentVariable {
                name,
                value: value.into(),
            }),
    );
}

const MAX_IDENTITY_VALUE_BYTES: usize = 255;

#[derive(Serialize)]
struct LaunchDescriptor<'a> {
    version: u8,
    instance_id: &'a str,
    project_id: &'a str,
    runtime_profile: &'a str,
    workspace: DescriptorWorkspace<'a>,
    agent: DescriptorAgent<'a>,
    herdr: DescriptorHerdr<'a>,
}

#[derive(Serialize)]
struct DescriptorWorkspace<'a> {
    kind: &'static str,
    host_path: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    path: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    change_name: Option<&'a str>,
    origin: &'static str,
}

#[derive(Serialize)]
struct DescriptorAgent<'a> {
    id: &'a str,
    kind: &'static str,
}

#[derive(Serialize)]
struct DescriptorHerdr<'a> {
    workspace_id: &'a str,
    pane_id: &'a str,
}

fn validate_identity_value<'a>(name: &str, value: &'a str) -> io::Result<&'a str> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is empty, too long, or contains control characters"),
        ));
    }
    Ok(value)
}

fn required_herdr_value(name: &str) -> io::Result<String> {
    let value = env::var(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is required by the Herdr identity profile"),
        )
    })?;
    validate_identity_value(name, &value)?;
    Ok(value)
}
fn optional_herdr_value(name: &str) -> io::Result<Option<String>> {
    let Some(value) = env::var_os(name) else {
        return Ok(None);
    };
    let value = value.into_string().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is not valid UTF-8"),
        )
    })?;
    validate_identity_value(name, &value)?;
    Ok(Some(value))
}

fn herdr_session_name() -> io::Result<Option<String>> {
    Ok(optional_herdr_value("HERDR_SESSION")?.filter(|session| session != "default"))
}

#[tracing::instrument(level = "debug", skip_all, name = "create_launch_descriptor")]
fn create_launch_descriptor(launch: &PreparedLaunch, config: &LauncherConfig) -> io::Result<File> {
    if required_herdr_value("HERDR_ENV")? != "1" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HERDR_ENV must be 1 for the Herdr identity profile",
        ));
    }
    let workspace_id = required_herdr_value("HERDR_WORKSPACE_ID")?;
    let pane_id = required_herdr_value("HERDR_PANE_ID")?;
    let (kind, name) = match &launch.workspace.selection {
        WorkspaceSelection::Primary => ("primary", None),
        WorkspaceSelection::Named(name) => ("named", Some(name.0.as_str())),
        WorkspaceSelection::Here => ("directory", None),
    };
    let origin = match launch.workspace.origin {
        WorkspaceOrigin::Primary => "primary",
        WorkspaceOrigin::Created => "created",
        WorkspaceOrigin::Existing => "existing",
        WorkspaceOrigin::Directory => "directory",
    };
    let descriptor = LaunchDescriptor {
        version: 1,
        instance_id: &launch.instance_id.0,
        project_id: &launch.workspace.project.0,
        runtime_profile: &config.profile,
        workspace: DescriptorWorkspace {
            kind,
            name,
            host_path: &launch.workspace.path,
            path: "/workspace",
            change_name: launch.workspace.change_name.as_deref(),
            origin,
        },
        agent: DescriptorAgent {
            id: &pane_id,
            kind: "persistent",
        },
        herdr: DescriptorHerdr {
            workspace_id: &workspace_id,
            pane_id: &pane_id,
        },
    };

    debug!(
        instance = %launch.instance_id.0,
        project = %launch.workspace.project.0,
        "sealing launch descriptor"
    );
    let descriptor_fd = memfd_create("runroom-launch.json", MFdFlags::MFD_ALLOW_SEALING)
        .map_err(io::Error::other)?;
    let mut file = File::from(descriptor_fd);
    serde_json::to_writer(&mut file, &descriptor).map_err(io::Error::other)?;
    file.write_all(b"\n")?;
    file.seek(SeekFrom::Start(0))?;
    fcntl(
        &file,
        FcntlArg::F_ADD_SEALS(
            SealFlag::F_SEAL_WRITE
                | SealFlag::F_SEAL_GROW
                | SealFlag::F_SEAL_SHRINK
                | SealFlag::F_SEAL_SEAL,
        ),
    )
    .map_err(io::Error::other)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_environment_overrides_only_allowlisted_values() {
        let mut runtime = RuntimePolicy {
            kind: RuntimeKind::Bubblewrap,
            network: crate::model::NetworkMode::Host,
            bind_mounts: Vec::new(),
            environment: vec![
                EnvironmentVariable {
                    name: "TERM".to_owned(),
                    value: "xterm".into(),
                },
                EnvironmentVariable {
                    name: "RUNROOM_DATABASE_URL".to_owned(),
                    value: "stale".into(),
                },
            ],
            home: Some(PathBuf::from("/home/user")),
        };

        apply_resolved_environment(
            BTreeMap::from([
                (
                    "RUNROOM_DATABASE_URL".to_owned(),
                    "postgresql://resolved".to_owned(),
                ),
                ("UNRELATED".to_owned(), "rejected".to_owned()),
            ]),
            &["RUNROOM_DATABASE_URL".to_owned()],
            &mut runtime,
        );

        assert!(runtime.environment.iter().any(|variable| {
            variable.name == "RUNROOM_DATABASE_URL" && variable.value == "postgresql://resolved"
        }));
        assert!(
            runtime
                .environment
                .iter()
                .any(|variable| { variable.name == "TERM" && variable.value == "xterm" })
        );
        assert!(
            !runtime
                .environment
                .iter()
                .any(|variable| variable.name == "UNRELATED")
        );
    }
}
