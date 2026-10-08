//! Concrete foreground launcher role.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
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
    LaunchHandoff, LaunchRequest, LaunchSpec, LauncherContinuation, NetworkMode,
    PrepareLaunchRequest, PreparedLaunch, ResourceLimits, RuntimeDataFile, RuntimeKind,
    RuntimePolicy, WorkspaceName, WorkspaceOrigin, WorkspaceSelection,
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
    agent_label: String,
    command: ForegroundCommand,
    runtime: RuntimePolicy,
    herdr_identity: bool,
    no_multiplex: bool,
    limits: ResourceLimits,
    project_environment: bool,
    environment_allowlist: Vec<String>,
    resume_token: Option<String>,
    continuation_token: Option<String>,
    replay_arguments: Vec<String>,
}

impl LauncherConfig {
    /// Configure a launcher connecting to `socket_path`.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        profile: String,
        agent_label: String,
        command: ForegroundCommand,
        runtime: RuntimePolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            workspace_selection: WorkspaceSelection::Primary,
            profile,
            agent_label,
            command,
            runtime,
            herdr_identity: false,
            no_multiplex: false,
            limits: ResourceLimits::default(),
            project_environment: false,
            environment_allowlist: Vec::new(),
            resume_token: None,
            continuation_token: None,
            replay_arguments: Vec::new(),
        }
    }

    /// Select a default named workspace instead of the project's primary workspace.
    #[must_use]
    pub fn workspace_name(mut self, workspace_name: WorkspaceName) -> Self {
        self.workspace_selection = WorkspaceSelection::Named(workspace_name);
        self
    }

    /// Require routed Herdr identity; current-terminal launches detect host identity instead.
    #[must_use]
    pub const fn herdr_identity(mut self, enabled: bool) -> Self {
        self.herdr_identity = enabled;
        self
    }

    /// Select the exact current directory, or return directory selection to primary.
    #[must_use]
    pub fn no_worktree(mut self, enabled: bool) -> Self {
        if enabled {
            self.workspace_selection = WorkspaceSelection::Here;
        } else if matches!(self.workspace_selection, WorkspaceSelection::Here) {
            self.workspace_selection = WorkspaceSelection::Primary;
        }
        self
    }

    /// Execute in this terminal without routing, retaining any host Herdr identity.
    #[must_use]
    pub const fn here(mut self, enabled: bool) -> Self {
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

    /// Retain resolved launcher arguments for durable conversation restoration.
    #[must_use]
    pub fn replay_arguments(mut self, arguments: Vec<String>) -> Self {
        self.replay_arguments = arguments;
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

fn replay_mount_arguments(arguments: &[String]) -> Vec<String> {
    let mut arguments = arguments.iter();
    let mut mounts = Vec::new();
    while let Some(flag) = arguments.next() {
        if matches!(flag.as_str(), "--here" | "--no-worktree" | "--verbose") {
            continue;
        }
        let Some(value) = arguments.next() else {
            break;
        };
        if flag == "--mount" {
            mounts.push(value.clone());
        }
    }
    mounts
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
                "current-terminal launch cannot resume a Herdr continuation",
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
        if !self.config.no_multiplex && here {
            self.config.herdr_identity = self.config.continuation_token.is_some();
        }
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
        let herdr = self.herdr_context()?;
        self.config.herdr_identity = herdr.is_some();
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
                agent_label: self.config.agent_label.clone(),
                no_multiplex: self.config.no_multiplex,
                limits: std::mem::take(&mut self.config.limits),
                herdr,
                continuation: continuation.map(Box::new),
                continuation_token: self.config.continuation_token.clone(),
                replay_arguments: self.config.replay_arguments.clone(),
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
                let ControlOperation::PrepareLaunch(request) = request.operation else {
                    unreachable!("launcher constructed a launch preparation request");
                };
                self.execute_foreground(&launch, request.herdr.as_ref())
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

    fn herdr_context(&self) -> io::Result<Option<HerdrContext>> {
        if self.config.no_multiplex {
            current_terminal_herdr_context()
        } else if self.config.herdr_identity {
            Ok(Some(HerdrContext {
                workspace_id: Some(required_herdr_value("HERDR_WORKSPACE_ID")?),
                pane_id: Some(required_herdr_value("HERDR_PANE_ID")?),
                session_name: herdr_session_name()?,
            }))
        } else {
            Ok(None)
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
            mount_arguments: replay_mount_arguments(&self.config.replay_arguments),
            replay_arguments: self.config.replay_arguments.clone(),
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
        let arguments = continuation_arguments(token, continuation);
        // The continuation carries normal resolved options, but keeps its original
        // workspace routing rather than the durable replay's exact-directory mode.
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
    fn execute_foreground(
        self,
        prepared_launch: &PreparedLaunch,
        herdr: Option<&HerdrContext>,
    ) -> io::Result<()> {
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
        let reporting = herdr.filter(|_| runtime.kind == RuntimeKind::Bubblewrap);
        let activity_socket = reporting
            .map(|_| projected_activity_socket(&self.config.socket_path, &runtime))
            .transpose()?
            .flatten();
        let descriptor = reporting
            .map(|herdr| {
                create_launch_descriptor(
                    prepared_launch,
                    &self.config,
                    herdr,
                    activity_socket.as_deref(),
                )
            })
            .transpose()?;
        let companion = reporting
            .map(|_| create_agent_companion(&runtime, &self.config.command))
            .transpose()?;
        let runtime_kind = self.config.runtime.kind;
        let launch = LaunchSpec {
            workspace: workspace.clone(),
            runtime,
            command: self.config.command,
            support_mount_access,
        };
        let resolver = (launch.runtime.network == NetworkMode::Private)
            .then(|| {
                sealed_runtime_file("runroom-resolv.conf", |file| {
                    file.write_all(b"nameserver 10.0.2.3\n")
                })
            })
            .transpose()?;
        let prepared = prepare_runtime(
            &launch,
            descriptor.as_ref(),
            companion.as_ref(),
            resolver.as_ref(),
        )?;
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
            executable = %launch.command.executable.display(),
            "launcher executing foreground command"
        );
        execute_runtime(&launch, &prepared)
    }
}

fn continuation_arguments(token: &str, continuation: LauncherContinuation) -> Vec<OsString> {
    let mut arguments = vec![OsString::from("launcher")];
    if continuation.replay_arguments.is_empty() {
        // Programmatic launchers may not opt into durable replay.
        arguments.extend([
            OsString::from("--socket"),
            continuation.socket_path.into_os_string(),
            OsString::from("--profile"),
            OsString::from(continuation.profile),
            OsString::from("--herdr-agent"),
            OsString::from(continuation.agent_label),
            OsString::from("--command"),
            OsString::from(continuation.command),
        ]);
        for mount in continuation.mount_arguments {
            arguments.extend([OsString::from("--mount"), OsString::from(mount)]);
        }
    } else {
        let mut replay = continuation.replay_arguments.into_iter();
        while let Some(option) = replay.next() {
            if option == "--here" || option == "--no-worktree" {
                continue;
            }
            if option == "--herdr-agent" {
                replay.next();
                continue;
            }
            let takes_value = option != "--verbose";
            arguments.push(OsString::from(option));
            // Only remove switches in option positions, never a command or grant
            // value which happens to have the same spelling.
            if takes_value && let Some(value) = replay.next() {
                arguments.push(OsString::from(value));
            }
        }
        arguments.extend([
            OsString::from("--herdr-agent"),
            OsString::from(continuation.agent_label),
        ]);
    }
    arguments.extend([
        OsString::from("--continuation-token"),
        OsString::from(token),
    ]);
    match continuation.workspace {
        WorkspaceSelection::Named(name) => {
            arguments.extend([OsString::from("--name"), OsString::from(name.0)]);
        }
        WorkspaceSelection::Here => arguments.push(OsString::from("--no-worktree")),
        WorkspaceSelection::Primary => {}
    }
    arguments
}

fn execute_runtime(launch: &LaunchSpec, prepared: &crate::model::PreparedExec) -> io::Result<()> {
    if launch.runtime.network == NetworkMode::Private {
        let status = super::network::run(prepared, &launch.command)?;
        std::process::exit(
            status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)),
        );
    }
    let mut command = Command::new(&prepared.executable);
    command.args(&prepared.arguments);
    if launch.runtime.kind == RuntimeKind::Native {
        for variable in &launch.runtime.environment {
            command.env(&variable.name, &variable.value);
        }
    }
    let error = command.exec();
    let message = match launch.runtime.kind {
        RuntimeKind::Native => format!(
            "cannot execute foreground command {}: {error}",
            launch.command.executable.display()
        ),
        RuntimeKind::Bubblewrap => format!(
            "cannot execute Bubblewrap runtime {} for foreground command {}: {error}",
            prepared.executable.display(),
            launch.command.executable.display()
        ),
    };
    Err(io::Error::new(error.kind(), message))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompanionEngine {
    Pi,
    Omp,
}

fn companion_engine(command: &ForegroundCommand) -> CompanionEngine {
    match command
        .executable
        .file_name()
        .and_then(|name| name.to_str())
    {
        Some("pi") => CompanionEngine::Pi,
        // Other commands retain the OMP activity companion, without session authority.
        _ => CompanionEngine::Omp,
    }
}

fn create_agent_companion(
    runtime: &RuntimePolicy,
    command: &ForegroundCommand,
) -> io::Result<(File, PathBuf)> {
    let engine = companion_engine(command);
    let destination = extension_destination(runtime, engine)?;
    let source = match engine {
        CompanionEngine::Pi => include_str!("../../assets/pi/runroom-agent-state.ts"),
        CompanionEngine::Omp => include_str!("../../assets/omp/runroom-agent-state.ts"),
    };
    let file = sealed_runtime_file("runroom-agent-state.ts", |file| {
        file.write_all(source.as_bytes())
    })?;
    Ok((file, destination))
}

fn prepare_runtime(
    launch: &LaunchSpec,
    descriptor: Option<&File>,
    companion: Option<&(File, PathBuf)>,
    resolver: Option<&File>,
) -> io::Result<crate::model::PreparedExec> {
    let prepare_bubblewrap = |files: &[RuntimeDataFile<'_>]| {
        if let Some(resolver) = resolver {
            BubblewrapRuntimeBackend::prepare_with_private_resolver(
                launch,
                files,
                resolver.as_raw_fd(),
            )
        } else {
            BubblewrapRuntimeBackend::prepare_with_data_files(launch, files)
        }
    };
    match launch.runtime.kind {
        RuntimeKind::Native => NativeRuntimeBackend.prepare(launch),
        RuntimeKind::Bubblewrap => {
            if let Some((descriptor, (companion, destination))) = descriptor.zip(companion) {
                let destination = destination.to_str().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "agent extension destination is not valid UTF-8",
                    )
                })?;
                prepare_bubblewrap(&[
                    RuntimeDataFile {
                        descriptor: descriptor.as_raw_fd(),
                        destination: "/runtime/launch.json",
                    },
                    RuntimeDataFile {
                        descriptor: companion.as_raw_fd(),
                        destination,
                    },
                ])
            } else {
                prepare_bubblewrap(&[])
            }
        }
    }
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
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

fn projected_activity_socket(
    control_socket: &Path,
    runtime: &RuntimePolicy,
) -> io::Result<Option<PathBuf>> {
    let control_parent = control_socket.parent().unwrap_or_else(|| Path::new(""));
    let host_socket = std::fs::canonicalize(control_parent)?.join("activity/status.sock");
    Ok(runtime
        .bind_mounts
        .iter()
        .filter_map(|mount| {
            let BindMountSource::Host(source) = &mount.source else {
                return None;
            };
            host_socket
                .strip_prefix(source)
                .ok()
                .map(|suffix| (source.components().count(), &mount.destination, suffix))
        })
        .max_by_key(|(depth, _, _)| *depth)
        .map(|(_, destination, suffix)| destination.join(suffix)))
}

fn extension_destination(runtime: &RuntimePolicy, engine: CompanionEngine) -> io::Result<PathBuf> {
    let projected = |name| {
        runtime
            .environment
            .iter()
            .rev()
            .find(|variable| variable.name == name)
            .map(|variable| Path::new(&variable.value))
    };
    let agent_directory = if let Some(directory) = projected("PI_CODING_AGENT_DIR") {
        directory.to_owned()
    } else {
        let home = projected("HOME")
            .or(runtime.home.as_deref())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "agent companion requires a runtime HOME",
                )
            })?;
        let config_directory = match engine {
            CompanionEngine::Pi => Path::new(".pi"),
            CompanionEngine::Omp => projected("PI_CONFIG_DIR").unwrap_or_else(|| Path::new(".omp")),
        };
        home.join(config_directory).join("agent")
    };
    let destination = agent_directory.join("extensions/runroom-agent-state.ts");
    if !destination.is_absolute()
        || destination.as_os_str().as_bytes().contains(&0)
        || destination.as_os_str().as_bytes()[1..]
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "agent extension destination must be normalized, absolute, and contain no NUL: {}",
                destination.display()
            ),
        ));
    }
    Ok(destination)
}

fn descriptor_herdr_value<'a>(name: &str, value: Option<&'a str>) -> io::Result<&'a str> {
    validate_identity_value(
        name,
        value.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} is required by the prepared Herdr context"),
            )
        })?,
    )
}

#[derive(Serialize)]
struct LaunchDescriptor<'a> {
    version: u8,
    instance_id: &'a str,
    project_id: &'a str,
    runtime_profile: &'a str,
    workspace: DescriptorWorkspace<'a>,
    agent: DescriptorAgent<'a>,
    herdr: DescriptorHerdr<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    activity_socket: Option<&'a Path>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_agent: Option<&'static str>,
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

fn current_terminal_herdr_context() -> io::Result<Option<HerdrContext>> {
    let marker = optional_herdr_value("HERDR_ENV")?;
    let workspace_id = optional_herdr_value("HERDR_WORKSPACE_ID")?;
    let pane_id = optional_herdr_value("HERDR_PANE_ID")?;
    let session_name = optional_herdr_value("HERDR_SESSION")?;
    if marker.is_none() && workspace_id.is_none() && pane_id.is_none() && session_name.is_none() {
        return Ok(None);
    }
    if marker.as_deref() != Some("1") || workspace_id.is_none() || pane_id.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "current-terminal Herdr identity requires HERDR_ENV=1, HERDR_WORKSPACE_ID, and HERDR_PANE_ID",
        ));
    }
    Ok(Some(HerdrContext {
        workspace_id,
        pane_id,
        session_name: session_name.filter(|session| session != "default"),
    }))
}

#[tracing::instrument(level = "debug", skip_all, name = "create_launch_descriptor")]
fn create_launch_descriptor(
    launch: &PreparedLaunch,
    config: &LauncherConfig,
    herdr: &HerdrContext,
    activity_socket: Option<&Path>,
) -> io::Result<File> {
    let workspace_id = descriptor_herdr_value("HERDR_WORKSPACE_ID", herdr.workspace_id.as_deref())?;
    let pane_id = descriptor_herdr_value("HERDR_PANE_ID", herdr.pane_id.as_deref())?;
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
            id: pane_id,
            kind: "persistent",
        },
        herdr: DescriptorHerdr {
            workspace_id,
            pane_id,
        },
        activity_socket,
        session_agent: match config
            .command
            .executable
            .file_name()
            .and_then(|name| name.to_str())
        {
            Some("pi") => Some("pi"),
            Some("omp") => Some("omp"),
            _ => None,
        },
    };

    debug!(
        instance = %launch.instance_id.0,
        project = %launch.workspace.project.0,
        "sealing launch descriptor"
    );
    sealed_runtime_file("runroom-launch.json", |file| {
        serde_json::to_writer(&mut *file, &descriptor).map_err(io::Error::other)?;
        file.write_all(b"\n")
    })
}

fn sealed_runtime_file(
    name: &str,
    write_contents: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<File> {
    let descriptor_fd =
        memfd_create(name, MFdFlags::MFD_ALLOW_SEALING).map_err(io::Error::other)?;
    let mut file = File::from(descriptor_fd);
    write_contents(&mut file)?;
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
    fn pi_companion_uses_foreground_engine_and_projected_pi_directory() {
        let mut runtime = reporting_runtime();
        let pi = ForegroundCommand {
            executable: "/opt/agents/pi".into(),
            arguments: Vec::new(),
        };
        assert_eq!(companion_engine(&pi), CompanionEngine::Pi);
        assert_eq!(
            extension_destination(&runtime, companion_engine(&pi)).unwrap(),
            Path::new("/home/sandbox/.pi/agent/extensions/runroom-agent-state.ts"),
        );
        runtime.environment.push(EnvironmentVariable {
            name: "PI_CONFIG_DIR".into(),
            value: ".custom-omp".into(),
        });
        assert_eq!(
            extension_destination(&runtime, CompanionEngine::Pi).unwrap(),
            Path::new("/home/sandbox/.pi/agent/extensions/runroom-agent-state.ts"),
        );
        runtime.environment.push(EnvironmentVariable {
            name: "PI_CODING_AGENT_DIR".into(),
            value: "/custom/pi-agent".into(),
        });
        assert_eq!(
            extension_destination(&runtime, CompanionEngine::Pi).unwrap(),
            Path::new("/custom/pi-agent/extensions/runroom-agent-state.ts"),
        );
        let omp = ForegroundCommand {
            executable: "/opt/agents/omp".into(),
            arguments: Vec::new(),
        };
        assert_eq!(companion_engine(&omp), CompanionEngine::Omp);
    }

    #[test]
    fn live_continuation_retains_overrides_but_restores_original_workspace_routing() {
        let continuation = LauncherContinuation {
            socket_path: "/unused.sock".into(),
            profile: "custom".to_owned(),
            agent_label: "rr:pi".to_owned(),
            command: "pi --model configured".to_owned(),
            mount_arguments: Vec::new(),
            workspace: WorkspaceSelection::Named(WorkspaceName("original".to_owned())),
            replay_arguments: [
                "--socket",
                "/control.sock",
                "--profile",
                "custom",
                "--herdr-agent",
                "stale:pi",
                "--network",
                "private",
                "--here",
                "--no-worktree",
                "--cpu-count",
                "2",
                "--mount",
                "/host/grant@/grant:ro",
                "--command",
                "pi --model 'CLI model'",
            ]
            .map(str::to_owned)
            .to_vec(),
        };
        assert_eq!(
            continuation_arguments("token", continuation),
            [
                "launcher",
                "--socket",
                "/control.sock",
                "--profile",
                "custom",
                "--network",
                "private",
                "--cpu-count",
                "2",
                "--mount",
                "/host/grant@/grant:ro",
                "--command",
                "pi --model 'CLI model'",
                "--herdr-agent",
                "rr:pi",
                "--continuation-token",
                "token",
                "--name",
                "original",
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn programmatic_continuation_preserves_profile_and_frozen_agent_label() {
        let continuation = LauncherContinuation {
            socket_path: "/control.sock".into(),
            profile: "coding".to_owned(),
            agent_label: "rr:omp".to_owned(),
            command: "omp --model 'configured model'".to_owned(),
            mount_arguments: Vec::new(),
            workspace: WorkspaceSelection::Here,
            replay_arguments: Vec::new(),
        };
        assert_eq!(
            continuation_arguments("token", continuation),
            [
                "launcher",
                "--socket",
                "/control.sock",
                "--profile",
                "coding",
                "--herdr-agent",
                "rr:omp",
                "--command",
                "omp --model 'configured model'",
                "--continuation-token",
                "token",
                "--no-worktree",
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn project_environment_overrides_only_allowlisted_values() {
        let mut runtime = RuntimePolicy {
            kind: RuntimeKind::Bubblewrap,
            network: crate::model::NetworkMode::Host,
            bind_mounts: Vec::new(),
            devices: Vec::new(),
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

    fn reporting_runtime() -> RuntimePolicy {
        RuntimePolicy {
            kind: RuntimeKind::Bubblewrap,
            network: crate::model::NetworkMode::None,
            bind_mounts: Vec::new(),
            devices: Vec::new(),
            environment: Vec::new(),
            home: Some(PathBuf::from("/home/sandbox")),
        }
    }

    #[test]
    fn activity_socket_uses_only_the_longest_explicit_host_mount() {
        let parent = std::fs::canonicalize(env!("CARGO_MANIFEST_DIR")).unwrap();
        let control_socket = parent.join("control.sock");
        let mut runtime = reporting_runtime();
        assert_eq!(
            projected_activity_socket(&control_socket, &runtime).unwrap(),
            None
        );
        runtime.bind_mounts.push(crate::model::BindMount {
            source: BindMountSource::Host(parent.clone()),
            destination: PathBuf::from("/runtime/runroom"),
            access: BindAccess::ReadOnly,
        });
        assert_eq!(
            projected_activity_socket(&control_socket, &runtime).unwrap(),
            Some(PathBuf::from("/runtime/runroom/activity/status.sock")),
        );
        runtime.bind_mounts.push(crate::model::BindMount {
            source: BindMountSource::Host(parent.join("activity")),
            destination: PathBuf::from("/runtime/activity"),
            access: BindAccess::ReadOnly,
        });
        assert_eq!(
            projected_activity_socket(&control_socket, &runtime).unwrap(),
            Some(PathBuf::from("/runtime/activity/status.sock")),
        );
        runtime.bind_mounts[1].source = BindMountSource::Executable(parent.join("activity"));
        assert_eq!(
            projected_activity_socket(&control_socket, &runtime).unwrap(),
            Some(PathBuf::from("/runtime/runroom/activity/status.sock")),
        );
    }

    #[test]
    fn companion_uses_projected_agent_directory_configuration() {
        let mut runtime = reporting_runtime();
        assert_eq!(
            extension_destination(&runtime, CompanionEngine::Omp).unwrap(),
            Path::new("/home/sandbox/.omp/agent/extensions/runroom-agent-state.ts"),
        );
        runtime.environment.extend([
            EnvironmentVariable {
                name: "HOME".into(),
                value: "/projected/home".into(),
            },
            EnvironmentVariable {
                name: "PI_CONFIG_DIR".into(),
                value: ".custom-omp".into(),
            },
        ]);
        assert_eq!(
            extension_destination(&runtime, CompanionEngine::Omp).unwrap(),
            Path::new("/projected/home/.custom-omp/agent/extensions/runroom-agent-state.ts"),
        );
        runtime.environment.push(EnvironmentVariable {
            name: "PI_CODING_AGENT_DIR".into(),
            value: "/custom/agent".into(),
        });
        assert_eq!(
            extension_destination(&runtime, CompanionEngine::Omp).unwrap(),
            Path::new("/custom/agent/extensions/runroom-agent-state.ts"),
        );
        runtime.environment.push(EnvironmentVariable {
            name: "PI_CODING_AGENT_DIR".into(),
            value: "/last/agent".into(),
        });
        assert_eq!(
            extension_destination(&runtime, CompanionEngine::Omp).unwrap(),
            Path::new("/last/agent/extensions/runroom-agent-state.ts"),
        );
    }

    #[test]
    fn companion_rejects_nonabsolute_and_unnormalized_runtime_destinations() {
        for directory in [
            "relative",
            "/home/../agent",
            "/home/./agent",
            "/home//agent",
            "/home/\0agent",
        ] {
            let mut runtime = reporting_runtime();
            runtime.environment.push(EnvironmentVariable {
                name: "PI_CODING_AGENT_DIR".into(),
                value: directory.into(),
            });
            assert!(
                extension_destination(&runtime, CompanionEngine::Omp).is_err(),
                "{directory:?}"
            );
        }
    }

    #[test]
    fn injected_runtime_files_reject_writes_and_resizing() {
        let mut file =
            sealed_runtime_file("sealed-test", |file| file.write_all(b"immutable")).unwrap();
        assert_eq!(
            file.write_all(b"changed").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        for length in [1, 32] {
            assert_eq!(
                file.set_len(length).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }
}
