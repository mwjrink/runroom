//! User configuration and command-line override resolution.

use std::collections::{BTreeMap, HashSet};
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use runroom::model::{
    BindAccess, BindMount, BindMountSource, EnvironmentVariable, ForegroundCommand, NetworkMode,
    ResourceLimits, RuntimeKind, RuntimePolicy, WorkspaceName,
};
use serde::Deserialize;
use tracing::debug;

const CONFIG_DIRECTORY: &str = "runroom";
const CONFIG_FILE: &str = "config.toml";
const WORKSPACE_SOURCE: &str = "@workspace";
const BUBBLEWRAP: &str = "/usr/bin/bwrap";
const LEGACY_TIOCSTI: &str = "/proc/sys/dev/tty/legacy_tiocsti";
const MAX_MEMORY_BYTES: u64 = 1 << 50;
const MAX_TASKS: u64 = 1_000_000;
const MAX_CPU_QUOTA_BASIS_POINTS: u32 = 1_000_000;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub runtime: Option<RuntimeFileKind>,
    pub socket: Option<PathBuf>,
    #[serde(default)]
    pub launcher: LauncherFileConfig,
    #[serde(default)]
    pub daemon: DaemonFileConfig,
}

impl FileConfig {
    /// Replace both profile CPU selection values when either CLI override is supplied.
    pub fn override_cpu_selection(
        &mut self,
        profile_override: Option<&str>,
        cpu_cores: Option<Vec<u32>>,
        cpu_count: Option<u32>,
    ) -> Result<(), SettingsError> {
        if cpu_cores.is_none() && cpu_count.is_none() {
            return Ok(());
        }
        let profile = profile_override
            .or(self.launcher.profile.as_deref())
            .ok_or(SettingsError::MissingProfile)?;
        let configured = self
            .launcher
            .profiles
            .get_mut(profile)
            .ok_or_else(|| SettingsError::UnknownProfile(profile.to_owned()))?;
        configured.cpu_cores = cpu_cores;
        configured.cpu_count = cpu_count;
        Ok(())
    }

    /// Apply directory and foreground launch policy before validating the selected profile.
    pub fn override_launch_mode(
        &mut self,
        profile_override: Option<&str>,
        here: bool,
        no_multiplex: bool,
    ) -> Result<(), SettingsError> {
        if !here && !no_multiplex {
            return Ok(());
        }
        if here {
            self.launcher.name = None;
        }
        let profile = profile_override
            .or(self.launcher.profile.as_deref())
            .ok_or(SettingsError::MissingProfile)?;
        let configured = self
            .launcher
            .profiles
            .get_mut(profile)
            .ok_or_else(|| SettingsError::UnknownProfile(profile.to_owned()))?;
        if no_multiplex {
            configured.identity = None;
        }
        if here && self.runtime == Some(RuntimeFileKind::Bubblewrap) {
            configured
                .bind_mounts
                .retain(|mount| mount.source != WORKSPACE_SOURCE);
            configured.bind_mounts.insert(
                0,
                BindMountFileConfig {
                    source: WORKSPACE_SOURCE.to_owned(),
                    destination: Some(PathBuf::from("/workspace")),
                    access: BindAccessFileMode::Rw,
                    required: true,
                },
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeFileKind {
    #[default]
    Native,
    Bubblewrap,
}

impl From<RuntimeFileKind> for RuntimeKind {
    fn from(value: RuntimeFileKind) -> Self {
        match value {
            RuntimeFileKind::Native => Self::Native,
            RuntimeFileKind::Bubblewrap => Self::Bubblewrap,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LauncherFileConfig {
    pub name: Option<String>,
    pub profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileFileConfig>,
    pub verbose: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProfileFileConfig {
    pub command: Option<String>,
    pub project_environment: Option<bool>,
    pub network: Option<NetworkFileMode>,
    pub identity: Option<IdentityFileKind>,
    #[serde(default)]
    pub environment: Vec<String>,
    #[serde(default)]
    pub set_environment: BTreeMap<String, String>,
    #[serde(default)]
    pub bind_mounts: Vec<BindMountFileConfig>,
    pub memory_max_bytes: Option<u64>,
    pub tasks_max: Option<u64>,
    pub cpu_quota_basis_points: Option<u32>,
    pub cpu_cores: Option<Vec<u32>>,
    pub cpu_count: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkFileMode {
    #[default]
    None,
    Host,
}

impl From<NetworkFileMode> for NetworkMode {
    fn from(value: NetworkFileMode) -> Self {
        match value {
            NetworkFileMode::None => Self::None,
            NetworkFileMode::Host => Self::Host,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IdentityFileKind {
    Herdr,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BindMountFileConfig {
    pub source: String,
    pub destination: Option<PathBuf>,
    pub access: BindAccessFileMode,
    #[serde(default = "required_by_default")]
    pub required: bool,
}

const fn required_by_default() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BindAccessFileMode {
    Ro,
    Rw,
}

impl From<BindAccessFileMode> for BindAccess {
    fn from(value: BindAccessFileMode) -> Self {
        match value {
            BindAccessFileMode::Ro => Self::ReadOnly,
            BindAccessFileMode::Rw => Self::ReadWrite,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonFileConfig {
    pub workspace_root: Option<PathBuf>,
    pub state_file: Option<PathBuf>,
    pub herdr_socket: Option<PathBuf>,
    #[serde(default)]
    pub resource_ceiling: ResourceCeilingFileConfig,
    pub verbose: Option<bool>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceCeilingFileConfig {
    pub memory_max_bytes: Option<u64>,
    pub tasks_max: Option<u64>,
    pub cpu_quota_basis_points: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LauncherSettings {
    pub socket: PathBuf,
    pub name: Option<WorkspaceName>,
    pub profile: String,
    pub command: ForegroundCommand,
    pub runtime: RuntimePolicy,
    pub project_environment: bool,
    pub environment_allowlist: Vec<String>,
    pub identity: Option<IdentityFileKind>,
    pub limits: ResourceLimits,
    pub verbose: bool,
}

impl LauncherSettings {
    #[tracing::instrument(level = "debug", skip_all, name = "resolve_launcher_settings")]
    pub fn resolve(
        socket_override: Option<PathBuf>,
        name_override: Option<String>,
        profile_override: Option<String>,
        command_override: Option<String>,
        verbose_override: bool,
        file: &FileConfig,
    ) -> Result<Self, SettingsError> {
        let socket = resolve_socket(socket_override, file)?;
        let name = name_override
            .or_else(|| file.launcher.name.clone())
            .map(validate_workspace_name)
            .transpose()?;
        let profile = profile_override
            .or_else(|| file.launcher.profile.clone())
            .ok_or(SettingsError::MissingProfile)
            .and_then(validate_profile_name)?;
        let profile_config = file
            .launcher
            .profiles
            .get(&profile)
            .ok_or_else(|| SettingsError::UnknownProfile(profile.clone()))?;
        let command = command_override
            .or_else(|| profile_config.command.clone())
            .ok_or_else(|| SettingsError::MissingCommand(profile.clone()))
            .and_then(|command| parse_command(&command))?;
        let kind = file.runtime.unwrap_or_default().into();
        let home = match kind {
            RuntimeKind::Native => None,
            RuntimeKind::Bubblewrap => Some(validate_bubblewrap_host()?),
        };
        let network = profile_config.network.map_or_else(
            || match kind {
                RuntimeKind::Native => NetworkMode::Host,
                RuntimeKind::Bubblewrap => NetworkMode::None,
            },
            Into::into,
        );
        let bind_mounts = resolve_bind_mounts(profile_config, kind)?;
        let environment = resolve_environment(profile_config)?;
        let project_environment = profile_config.project_environment.unwrap_or(false);
        let limits = ResourceLimits {
            memory_max_bytes: profile_config.memory_max_bytes,
            tasks_max: profile_config.tasks_max,
            cpu_quota_basis_points: profile_config.cpu_quota_basis_points,
            cpu_cores: profile_config.cpu_cores.clone(),
            cpu_count: profile_config.cpu_count,
        };
        validate_resource_limits(&limits, &protocol_ceiling(), "launcher profile")?;
        validate_resource_limits(
            &limits,
            &configured_resource_ceiling(file)?,
            "launcher profile",
        )?;
        let identity = profile_config.identity;
        if identity.is_some() && kind != RuntimeKind::Bubblewrap {
            return Err(SettingsError::IdentityRequiresBubblewrap);
        }
        if identity.is_some()
            && !bind_mounts.iter().any(|mount| {
                mount.source == BindMountSource::Workspace
                    && mount.destination == Path::new("/workspace")
            })
        {
            return Err(SettingsError::IdentityRequiresWorkspaceDestination);
        }
        let verbose = verbose_override || file.launcher.verbose.unwrap_or(false);
        debug!(
            profile,
            runtime = ?kind,
            network = ?network,
            executable = %command.executable.display(),
            argument_count = command.arguments.len(),
            bind_mount_count = bind_mounts.len(),
            environment_count = environment.len(),
            project_environment,
            "resolved launcher settings"
        );
        Ok(Self {
            socket,
            name,
            profile,
            command,
            runtime: RuntimePolicy {
                kind,
                network,
                bind_mounts,
                environment,
                home,
            },
            project_environment,
            environment_allowlist: profile_config.environment.clone(),
            identity,
            limits,
            verbose,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonSettings {
    pub socket: PathBuf,
    pub workspace_root: PathBuf,
    pub state_file: PathBuf,
    pub herdr_socket: PathBuf,
    pub resource_ceiling: ResourceLimits,
    pub verbose: bool,
}

impl DaemonSettings {
    #[tracing::instrument(level = "debug", skip_all, name = "resolve_daemon_settings")]
    pub fn resolve(
        socket_override: Option<PathBuf>,
        workspace_root_override: Option<PathBuf>,
        state_file_override: Option<PathBuf>,
        verbose_override: bool,
        file: &FileConfig,
    ) -> Result<Self, SettingsError> {
        let socket = resolve_socket(socket_override, file)?;
        let workspace_root =
            match workspace_root_override.or_else(|| file.daemon.workspace_root.clone()) {
                Some(path) => path,
                None => default_workspace_root()?,
            };
        if !workspace_root.is_absolute() {
            return Err(SettingsError::RelativeWorkspaceRoot(workspace_root));
        }
        let state_file = match state_file_override.or_else(|| file.daemon.state_file.clone()) {
            Some(path) => path,
            None => default_state_file()?,
        };
        if !state_file.is_absolute() {
            return Err(SettingsError::RelativeStateFile(state_file));
        }
        let herdr_socket = match &file.daemon.herdr_socket {
            Some(path) => path.clone(),
            None => default_herdr_socket()?,
        };
        if !herdr_socket.is_absolute() {
            return Err(SettingsError::RelativeHerdrSocket(herdr_socket));
        }
        let resource_ceiling = configured_resource_ceiling(file)?;
        debug!(
            socket = %socket.display(),
            workspace_root = %workspace_root.display(),
            state_file = %state_file.display(),
            "resolved daemon settings"
        );
        Ok(Self {
            socket,
            workspace_root,
            state_file,
            herdr_socket,
            resource_ceiling,
            verbose: verbose_override || file.daemon.verbose.unwrap_or(false),
        })
    }
}

pub fn load_default() -> Result<FileConfig, ConfigError> {
    let Some(path) = default_config_path() else {
        return Ok(FileConfig::default());
    };
    load(&path)
}
pub fn load_path(path: &Path) -> Result<FileConfig, ConfigError> {
    let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })?;
    toml::from_str(&contents).map_err(|source| ConfigError::Parse {
        path: path.to_owned(),
        source,
    })
}

pub fn validate_all_profiles(file: &FileConfig) -> Result<Vec<LauncherSettings>, SettingsError> {
    if file.launcher.profiles.is_empty() {
        return Err(SettingsError::NoProfiles);
    }
    file.launcher
        .profiles
        .keys()
        .map(|profile| {
            LauncherSettings::resolve(None, None, Some(profile.clone()), None, false, file)
        })
        .collect()
}

pub fn control_socket(
    socket_override: Option<PathBuf>,
    file: &FileConfig,
) -> Result<PathBuf, SettingsError> {
    resolve_socket(socket_override, file)
}

fn resolve_socket(
    socket_override: Option<PathBuf>,
    file: &FileConfig,
) -> Result<PathBuf, SettingsError> {
    match socket_override.or_else(|| file.socket.clone()) {
        Some(socket) => Ok(socket),
        None => default_socket_path().map_err(SettingsError::DefaultSocket),
    }
}

fn parse_command(command: &str) -> Result<ForegroundCommand, SettingsError> {
    let mut words =
        shell_words::split(command).map_err(|source| SettingsError::InvalidCommand { source })?;
    if words.is_empty() {
        return Err(SettingsError::EmptyCommand);
    }
    Ok(ForegroundCommand {
        executable: PathBuf::from(words.remove(0)),
        arguments: words.into_iter().map(OsString::from).collect(),
    })
}
fn resolve_environment(
    profile: &ProfileFileConfig,
) -> Result<Vec<EnvironmentVariable>, SettingsError> {
    let mut names =
        HashSet::with_capacity(profile.environment.len() + profile.set_environment.len());
    let mut environment = Vec::with_capacity(names.capacity());
    for name in &profile.environment {
        validate_environment_name(name)?;
        if !names.insert(name.clone()) {
            return Err(SettingsError::DuplicateEnvironmentName(name.clone()));
        }
        if let Some(value) = env::var_os(name) {
            environment.push(EnvironmentVariable {
                name: name.clone(),
                value,
            });
        }
    }
    for (name, value) in &profile.set_environment {
        validate_environment_name(name)?;
        if !names.insert(name.clone()) {
            return Err(SettingsError::DuplicateEnvironmentName(name.clone()));
        }
        environment.push(EnvironmentVariable {
            name: name.clone(),
            value: value.into(),
        });
    }
    Ok(environment)
}

fn validate_environment_name(name: &str) -> Result<(), SettingsError> {
    let bytes = name.as_bytes();
    if name == "HOME"
        || bytes
            .first()
            .is_none_or(|byte| !byte.is_ascii_alphabetic() && *byte != b'_')
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return Err(SettingsError::InvalidEnvironmentName(name.to_owned()));
    }
    Ok(())
}

fn resolve_bind_mounts(
    profile: &ProfileFileConfig,
    runtime: RuntimeKind,
) -> Result<Vec<BindMount>, SettingsError> {
    let mut mounts = Vec::with_capacity(profile.bind_mounts.len());
    let mut destinations = HashSet::with_capacity(profile.bind_mounts.len());
    let mut workspace_mounts = 0;
    for configured in &profile.bind_mounts {
        let (source, default_destination) = if configured.source == WORKSPACE_SOURCE {
            if !configured.required {
                return Err(SettingsError::OptionalWorkspaceMount);
            }
            workspace_mounts += 1;
            (BindMountSource::Workspace, None)
        } else {
            let expanded = expand_host_path(&configured.source)?;
            let source = match fs::canonicalize(&expanded) {
                Ok(path) => path,
                Err(error) if !configured.required && error.kind() == io::ErrorKind::NotFound => {
                    continue;
                }
                Err(source) => {
                    return Err(SettingsError::InvalidBindSource {
                        path: expanded,
                        source,
                    });
                }
            };
            (BindMountSource::Host(source), Some(expanded))
        };
        let destination = configured
            .destination
            .clone()
            .or(default_destination)
            .ok_or(SettingsError::MissingWorkspaceDestination)
            .and_then(normalize_destination)?;
        if !destinations.insert(destination.clone()) {
            return Err(SettingsError::DuplicateBindDestination(destination));
        }
        mounts.push(BindMount {
            source,
            destination,
            access: configured.access.into(),
        });
    }
    if runtime == RuntimeKind::Bubblewrap {
        match workspace_mounts {
            0 => return Err(SettingsError::MissingWorkspaceMount),
            1 => {}
            _ => return Err(SettingsError::DuplicateWorkspaceMount),
        }
    }
    Ok(mounts)
}

fn expand_host_path(source: &str) -> Result<PathBuf, SettingsError> {
    if let Some(relative) = source.strip_prefix("~/") {
        let home = absolute_environment_path("HOME").ok_or(SettingsError::MissingHome)?;
        return Ok(home.join(relative));
    }
    let path = PathBuf::from(source);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(SettingsError::RelativeBindSource(path))
    }
}

fn normalize_destination(destination: PathBuf) -> Result<PathBuf, SettingsError> {
    if !destination.is_absolute() {
        return Err(SettingsError::InvalidBindDestination(destination));
    }
    if destination.as_os_str().as_bytes().contains(&0) {
        return Err(SettingsError::InvalidBindDestination(destination));
    }
    let mut normalized = PathBuf::from("/");
    for component in destination.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(SettingsError::InvalidBindDestination(destination));
            }
        }
    }
    if ["/", "/usr", "/etc", "/proc", "/dev", "/run", "/tmp"]
        .iter()
        .any(|root| normalized == Path::new(root) || normalized.starts_with(root) && *root != "/")
    {
        return Err(SettingsError::ProtectedBindDestination(normalized));
    }
    Ok(normalized)
}

fn validate_bubblewrap_host() -> Result<PathBuf, SettingsError> {
    let metadata = fs::metadata(BUBBLEWRAP).map_err(SettingsError::BubblewrapUnavailable)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(SettingsError::BubblewrapNotExecutable);
    }
    let tiocsti =
        fs::read_to_string(LEGACY_TIOCSTI).map_err(SettingsError::TerminalPolicyUnavailable)?;
    if tiocsti.trim() != "0" {
        return Err(SettingsError::LegacyTiocstiEnabled);
    }
    absolute_environment_path("HOME").ok_or(SettingsError::MissingHome)
}

fn load(path: &Path) -> Result<FileConfig, ConfigError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(FileConfig::default()),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_owned(),
                source,
            });
        }
    };

    toml::from_str(&contents).map_err(|source| ConfigError::Parse {
        path: path.to_owned(),
        source,
    })
}

fn default_config_path() -> Option<PathBuf> {
    absolute_environment_path("XDG_CONFIG_HOME")
        .or_else(|| absolute_environment_path("HOME").map(|home| home.join(".config")))
        .map(|directory| directory.join(CONFIG_DIRECTORY).join(CONFIG_FILE))
}

fn default_socket_path() -> io::Result<PathBuf> {
    let runtime_directory = absolute_environment_path("XDG_RUNTIME_DIR").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "XDG_RUNTIME_DIR is unset or invalid; set socket in config.toml or pass --socket PATH",
        )
    })?;
    Ok(runtime_directory
        .join(CONFIG_DIRECTORY)
        .join("control.sock"))
}

fn default_workspace_root() -> Result<PathBuf, SettingsError> {
    let data_directory = absolute_environment_path("XDG_DATA_HOME")
        .or_else(|| absolute_environment_path("HOME").map(|home| home.join(".local/share")))
        .ok_or(SettingsError::MissingDataHome)?;
    Ok(data_directory.join(CONFIG_DIRECTORY).join("workspaces"))
}
fn default_state_file() -> Result<PathBuf, SettingsError> {
    let state_directory = absolute_environment_path("XDG_STATE_HOME")
        .or_else(|| absolute_environment_path("HOME").map(|home| home.join(".local/state")))
        .ok_or(SettingsError::MissingStateHome)?;
    Ok(state_directory
        .join(CONFIG_DIRECTORY)
        .join("instances.json"))
}
fn default_herdr_socket() -> Result<PathBuf, SettingsError> {
    let home = absolute_environment_path("HOME").ok_or(SettingsError::MissingHome)?;
    Ok(home.join(".config/herdr/herdr.sock"))
}

fn configured_resource_ceiling(file: &FileConfig) -> Result<ResourceLimits, SettingsError> {
    let ceiling = ResourceLimits {
        memory_max_bytes: file
            .daemon
            .resource_ceiling
            .memory_max_bytes
            .or(Some(MAX_MEMORY_BYTES)),
        tasks_max: file.daemon.resource_ceiling.tasks_max.or(Some(MAX_TASKS)),
        cpu_quota_basis_points: file
            .daemon
            .resource_ceiling
            .cpu_quota_basis_points
            .or(Some(MAX_CPU_QUOTA_BASIS_POINTS)),
        cpu_cores: None,
        cpu_count: None,
    };
    validate_resource_limits(&ceiling, &protocol_ceiling(), "daemon resource ceiling")?;
    Ok(ceiling)
}

const fn protocol_ceiling() -> ResourceLimits {
    ResourceLimits {
        memory_max_bytes: Some(MAX_MEMORY_BYTES),
        tasks_max: Some(MAX_TASKS),
        cpu_quota_basis_points: Some(MAX_CPU_QUOTA_BASIS_POINTS),
        cpu_cores: None,
        cpu_count: None,
    }
}

fn validate_resource_limits(
    limits: &ResourceLimits,
    ceiling: &ResourceLimits,
    context: &'static str,
) -> Result<(), SettingsError> {
    let invalid = limits.memory_max_bytes == Some(0)
        || limits.tasks_max == Some(0)
        || limits.cpu_quota_basis_points == Some(0)
        || !limits.valid_cpu_selection()
        || exceeds(limits.memory_max_bytes, ceiling.memory_max_bytes)
        || exceeds(limits.tasks_max, ceiling.tasks_max)
        || exceeds(
            limits.cpu_quota_basis_points.map(u64::from),
            ceiling.cpu_quota_basis_points.map(u64::from),
        );
    if invalid {
        return Err(SettingsError::InvalidResourceLimits(context));
    }
    Ok(())
}

fn exceeds<T: Ord>(value: Option<T>, ceiling: Option<T>) -> bool {
    matches!((value, ceiling), (Some(value), Some(ceiling)) if value > ceiling)
}

fn absolute_environment_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

fn validate_workspace_name(name: String) -> Result<WorkspaceName, SettingsError> {
    if name.trim().is_empty() {
        return Err(SettingsError::InvalidWorkspaceName);
    }
    Ok(WorkspaceName(name))
}

fn validate_profile_name(name: String) -> Result<String, SettingsError> {
    if name.trim().is_empty() {
        return Err(SettingsError::InvalidProfileName);
    }
    Ok(name)
}

#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

impl Display for ConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(formatter, "cannot read {}: {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(formatter, "invalid {}: {source}", path.display())
            }
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
        }
    }
}

#[derive(Debug)]
pub enum SettingsError {
    DefaultSocket(io::Error),
    InvalidWorkspaceName,
    NoProfiles,
    MissingProfile,
    InvalidProfileName,
    UnknownProfile(String),
    MissingCommand(String),
    EmptyCommand,
    InvalidCommand { source: shell_words::ParseError },
    InvalidEnvironmentName(String),
    DuplicateEnvironmentName(String),
    IdentityRequiresBubblewrap,
    IdentityRequiresWorkspaceDestination,
    BubblewrapUnavailable(io::Error),
    BubblewrapNotExecutable,
    TerminalPolicyUnavailable(io::Error),
    LegacyTiocstiEnabled,
    MissingHome,
    RelativeBindSource(PathBuf),
    InvalidBindSource { path: PathBuf, source: io::Error },
    MissingWorkspaceDestination,
    InvalidBindDestination(PathBuf),
    ProtectedBindDestination(PathBuf),
    DuplicateBindDestination(PathBuf),
    OptionalWorkspaceMount,
    MissingWorkspaceMount,
    DuplicateWorkspaceMount,
    MissingDataHome,
    MissingStateHome,
    RelativeStateFile(PathBuf),
    InvalidResourceLimits(&'static str),
    RelativeWorkspaceRoot(PathBuf),
    RelativeHerdrSocket(PathBuf),
}

impl Display for SettingsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultSocket(source) => source.fmt(formatter),
            Self::InvalidWorkspaceName => formatter.write_str("workspace name must not be empty"),
            Self::MissingProfile => formatter.write_str(
                "launcher profile is not configured; set launcher.profile or pass --profile",
            ),
            Self::InvalidProfileName => formatter.write_str("launcher profile must not be empty"),
            Self::NoProfiles => formatter.write_str("no launcher profiles are configured"),
            Self::UnknownProfile(profile) => {
                write!(formatter, "launcher profile is not configured: {profile}")
            }
            Self::MissingCommand(profile) => fmt_missing_command(formatter, profile),
            Self::EmptyCommand => {
                formatter.write_str("launcher command must contain an executable")
            }
            Self::InvalidCommand { source } => {
                write!(formatter, "invalid launcher command: {source}")
            }
            Self::InvalidEnvironmentName(name) => write!(
                formatter,
                "invalid or runtime-managed profile environment name: {name}"
            ),
            Self::DuplicateEnvironmentName(name) => {
                write!(formatter, "duplicate profile environment name: {name}")
            }
            Self::IdentityRequiresBubblewrap => {
                formatter.write_str("launch identity descriptors require the Bubblewrap runtime")
            }
            Self::IdentityRequiresWorkspaceDestination => formatter.write_str(
                "launch identity descriptors require @workspace destination /workspace",
            ),
            Self::BubblewrapUnavailable(source) => {
                write!(formatter, "bubblewrap is unavailable at {BUBBLEWRAP}: {source}")
            }
            Self::BubblewrapNotExecutable => {
                write!(formatter, "bubblewrap is not executable: {BUBBLEWRAP}")
            }
            Self::TerminalPolicyUnavailable(source) => write!(
                formatter,
                "cannot verify terminal injection policy at {LEGACY_TIOCSTI}: {source}"
            ),
            Self::LegacyTiocstiEnabled => formatter.write_str(
                "legacy TIOCSTI is enabled; refusing interactive Bubblewrap without a controlling-terminal-safe seccomp filter",
            ),
            Self::MissingHome => {
                formatter.write_str("HOME is unset or invalid; cannot expand bind source")
            }
            Self::RelativeBindSource(path) => write!(
                formatter,
                "bind source must be absolute or start with ~/: {}",
                path.display()
            ),
            Self::InvalidBindSource { path, source } => fmt_bind_source(formatter, path, source),
            Self::MissingWorkspaceDestination => {
                formatter.write_str("@workspace bind requires an explicit destination")
            }
            Self::InvalidBindDestination(path) => write!(
                formatter,
                "bind destination must be a normalized absolute path: {}",
                path.display()
            ),
            Self::ProtectedBindDestination(path) => write!(
                formatter,
                "bind destination overlaps a protected runtime path: {}",
                path.display()
            ),
            Self::DuplicateBindDestination(path) => {
                write!(formatter, "duplicate bind destination: {}", path.display())
            }
            Self::OptionalWorkspaceMount => formatter.write_str("@workspace bind cannot be optional"),
            Self::MissingWorkspaceMount => {
                formatter.write_str("bubblewrap profile requires one @workspace bind")
            }
            Self::DuplicateWorkspaceMount => {
                formatter.write_str("bubblewrap profile contains multiple @workspace binds")
            }
            Self::MissingDataHome => formatter.write_str(
                "XDG_DATA_HOME and HOME are unset or invalid; set daemon.workspace_root",
            ),
            Self::MissingStateHome => formatter.write_str(
                "XDG_STATE_HOME and HOME are unset or invalid; set daemon.state_file",
            ),
            Self::RelativeStateFile(path) => write!(
                formatter,
                "instance state file must be absolute: {}",
                path.display()
            ),
            Self::InvalidResourceLimits(context) => fmt_resource_limits(formatter, context),
            Self::RelativeWorkspaceRoot(path) => write!(
                formatter,
                "workspace root must be absolute: {}",
                path.display()
            ),
            Self::RelativeHerdrSocket(path) => write!(
                formatter,
                "Herdr socket must be absolute: {}",
                path.display()
            ),
        }
    }
}

fn fmt_missing_command(formatter: &mut Formatter<'_>, profile: &str) -> fmt::Result {
    write!(
        formatter,
        "launcher command is not configured for profile {profile}; set its command or pass --command"
    )
}

fn fmt_bind_source(formatter: &mut Formatter<'_>, path: &Path, source: &io::Error) -> fmt::Result {
    write!(
        formatter,
        "cannot resolve bind source {}: {source}",
        path.display()
    )
}

fn fmt_resource_limits(formatter: &mut Formatter<'_>, context: &str) -> fmt::Result {
    write!(
        formatter,
        "{context} resource limits must be nonzero and within protocol ceilings; CPU selection requires either unique logical CPU IDs below 1024 or a count in 1..=1024"
    )
}

impl Error for SettingsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DefaultSocket(source) | Self::InvalidBindSource { source, .. } => Some(source),
            Self::InvalidCommand { source } => Some(source),
            Self::BubblewrapUnavailable(source) | Self::TerminalPolicyUnavailable(source) => {
                Some(source)
            }
            Self::InvalidWorkspaceName
            | Self::MissingProfile
            | Self::InvalidProfileName
            | Self::UnknownProfile(_)
            | Self::NoProfiles
            | Self::MissingCommand(_)
            | Self::EmptyCommand
            | Self::InvalidEnvironmentName(_)
            | Self::DuplicateEnvironmentName(_)
            | Self::IdentityRequiresBubblewrap
            | Self::IdentityRequiresWorkspaceDestination
            | Self::BubblewrapNotExecutable
            | Self::LegacyTiocstiEnabled
            | Self::MissingHome
            | Self::RelativeBindSource(_)
            | Self::MissingWorkspaceDestination
            | Self::InvalidBindDestination(_)
            | Self::ProtectedBindDestination(_)
            | Self::DuplicateBindDestination(_)
            | Self::OptionalWorkspaceMount
            | Self::MissingWorkspaceMount
            | Self::DuplicateWorkspaceMount
            | Self::MissingDataHome
            | Self::MissingStateHome
            | Self::RelativeStateFile(_)
            | Self::InvalidResourceLimits(_)
            | Self::RelativeWorkspaceRoot(_)
            | Self::RelativeHerdrSocket(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    use super::*;
    fn profile(command: Option<&str>) -> ProfileFileConfig {
        ProfileFileConfig {
            command: command.map(str::to_owned),
            project_environment: None,
            network: Some(NetworkFileMode::Host),
            identity: None,
            environment: Vec::new(),
            set_environment: BTreeMap::new(),
            bind_mounts: Vec::new(),
            memory_max_bytes: None,
            tasks_max: None,
            cpu_quota_basis_points: None,
            cpu_cores: None,
            cpu_count: None,
        }
    }

    fn file_config() -> FileConfig {
        FileConfig {
            runtime: Some(RuntimeFileKind::Native),
            socket: Some(PathBuf::from("/file.sock")),
            launcher: LauncherFileConfig {
                name: Some("file".to_owned()),
                profile: Some("pi".to_owned()),
                profiles: BTreeMap::from([(
                    "pi".to_owned(),
                    profile(Some("pi --model 'file model'")),
                )]),
                verbose: Some(true),
            },
            daemon: DaemonFileConfig {
                workspace_root: Some(PathBuf::from("/file/workspaces")),
                state_file: Some(PathBuf::from("/file/instances.json")),
                herdr_socket: Some(PathBuf::from("/file/herdr.sock")),
                resource_ceiling: ResourceCeilingFileConfig::default(),
                verbose: Some(true),
            },
        }
    }
    fn daemon_file_config() -> FileConfig {
        let mut file = file_config();
        file.runtime = Some(RuntimeFileKind::Bubblewrap);
        file
    }

    #[test]
    fn parses_global_runtime_and_flat_profiles() {
        let parsed: FileConfig = toml::from_str(
            r#"
runtime = "bubblewrap"
socket = "/tmp/runroom.sock"

[launcher]
name = "docs"
profile = "review"
verbose = true

[launcher.profiles.review]
command = "less"
identity = "herdr"
environment = ["PATH", "TERM"]
set_environment = { LANG = "C.UTF-8" }
network = "none"
bind_mounts = [
  { source = "@workspace", destination = "/workspace", access = "rw" },
  { source = "~/.config/less", access = "ro", required = false },
]

[daemon]
workspace_root = "/var/tmp/runroom-workspaces"
verbose = false
"#,
        )
        .expect("parse config");

        assert_eq!(parsed.runtime, Some(RuntimeFileKind::Bubblewrap));
        assert_eq!(parsed.socket, Some(PathBuf::from("/tmp/runroom.sock")));
        assert_eq!(parsed.launcher.name.as_deref(), Some("docs"));
        assert_eq!(parsed.launcher.profile.as_deref(), Some("review"));
        let profile = &parsed.launcher.profiles["review"];
        assert_eq!(profile.identity, Some(IdentityFileKind::Herdr));
        assert_eq!(profile.environment, ["PATH", "TERM"]);
        assert_eq!(profile.set_environment["LANG"], "C.UTF-8");
        assert_eq!(profile.command.as_deref(), Some("less"));
        assert_eq!(profile.network, Some(NetworkFileMode::None));
        assert_eq!(
            profile.bind_mounts,
            [
                BindMountFileConfig {
                    source: "@workspace".to_owned(),
                    destination: Some(PathBuf::from("/workspace")),
                    access: BindAccessFileMode::Rw,
                    required: true,
                },
                BindMountFileConfig {
                    source: "~/.config/less".to_owned(),
                    destination: None,
                    access: BindAccessFileMode::Ro,
                    required: false,
                },
            ]
        );
        assert_eq!(parsed.launcher.verbose, Some(true));
        assert_eq!(
            parsed.daemon.workspace_root,
            Some(PathBuf::from("/var/tmp/runroom-workspaces"))
        );
        assert_eq!(parsed.daemon.verbose, Some(false));
    }

    #[test]
    fn rejects_unknown_keys_and_invalid_policy_values() {
        for config in [
            "backend = 'git'\n",
            "runtime = 'container'\n",
            "[launcher]\nbackend = 'git'\n",
            "[launcher.profiles.pi]\ncommand = 'pi'\nnetwork = 'internet'\n",
            "[launcher.profiles.pi]\ncommand = 'pi'\nbind_mounts = [{ source = '/x', access = 'write' }]\n",
            "[daemon]\nname = 'docs'\n",
        ] {
            assert!(toml::from_str::<FileConfig>(config).is_err());
        }
    }

    #[test]
    fn command_line_values_override_selected_profile() {
        let file = file_config();
        let launcher = LauncherSettings::resolve(
            Some(PathBuf::from("/cli-launcher.sock")),
            Some("cli".to_owned()),
            Some("pi".to_owned()),
            Some("pi --model 'cli model'".to_owned()),
            false,
            &file,
        )
        .expect("resolve launcher settings");
        let daemon_file = daemon_file_config();
        let daemon = DaemonSettings::resolve(
            Some(PathBuf::from("/cli-daemon.sock")),
            Some(PathBuf::from("/cli/workspaces")),
            None,
            false,
            &daemon_file,
        )
        .expect("resolve daemon settings");

        assert_eq!(launcher.socket, PathBuf::from("/cli-launcher.sock"));
        assert_eq!(launcher.name, Some(WorkspaceName("cli".to_owned())));
        assert_eq!(launcher.profile, "pi");
        assert_eq!(launcher.command.executable, PathBuf::from("pi"));
        assert_eq!(
            launcher.command.arguments,
            [OsString::from("--model"), OsString::from("cli model")]
        );
        assert_eq!(launcher.runtime.kind, RuntimeKind::Native);
        assert_eq!(launcher.runtime.network, NetworkMode::Host);
        assert!(launcher.verbose);
        assert_eq!(daemon.socket, PathBuf::from("/cli-daemon.sock"));
        assert_eq!(daemon.workspace_root, PathBuf::from("/cli/workspaces"));
        assert!(daemon.verbose);
    }

    #[test]
    fn resolves_bubblewrap_workspace_and_host_mounts() {
        let host_source = env::current_dir()
            .expect("current directory")
            .canonicalize()
            .expect("canonical current directory");
        let profile = ProfileFileConfig {
            identity: None,
            environment: Vec::new(),
            set_environment: BTreeMap::new(),
            command: Some("/bin/true".to_owned()),
            project_environment: None,
            network: Some(NetworkFileMode::None),
            bind_mounts: vec![
                BindMountFileConfig {
                    source: WORKSPACE_SOURCE.to_owned(),
                    destination: Some(PathBuf::from("/workspace")),
                    access: BindAccessFileMode::Rw,
                    required: true,
                },
                BindMountFileConfig {
                    source: host_source.to_string_lossy().into_owned(),
                    destination: Some(PathBuf::from("/home/source")),
                    access: BindAccessFileMode::Ro,
                    required: true,
                },
            ],
            memory_max_bytes: None,
            tasks_max: None,
            cpu_quota_basis_points: None,
            cpu_cores: None,
            cpu_count: None,
        };
        let file = FileConfig {
            runtime: Some(RuntimeFileKind::Bubblewrap),
            socket: Some(PathBuf::from("/unused.sock")),
            launcher: LauncherFileConfig {
                profile: Some("test".to_owned()),
                profiles: BTreeMap::from([("test".to_owned(), profile)]),
                ..LauncherFileConfig::default()
            },
            ..FileConfig::default()
        };

        let settings = LauncherSettings::resolve(None, None, None, None, false, &file)
            .expect("resolve Bubblewrap profile");

        assert_eq!(settings.runtime.kind, RuntimeKind::Bubblewrap);
        assert_eq!(settings.runtime.network, NetworkMode::None);
        assert_eq!(
            settings.runtime.bind_mounts,
            [
                BindMount {
                    source: BindMountSource::Workspace,
                    destination: PathBuf::from("/workspace"),
                    access: BindAccess::ReadWrite,
                },
                BindMount {
                    source: BindMountSource::Host(host_source),
                    destination: PathBuf::from("/home/source"),
                    access: BindAccess::ReadOnly,
                },
            ]
        );
    }

    #[test]
    fn here_replaces_workspace_mappings_without_dropping_host_permissions() {
        for destinations in [vec![], vec!["/other"], vec!["/other", "/workspace"]] {
            let mut file = file_config();
            file.runtime = Some(RuntimeFileKind::Bubblewrap);
            let selected = file.launcher.profiles.get_mut("pi").expect("profile");
            selected.bind_mounts = destinations
                .into_iter()
                .map(|destination| BindMountFileConfig {
                    source: WORKSPACE_SOURCE.to_owned(),
                    destination: Some(PathBuf::from(destination)),
                    access: BindAccessFileMode::Ro,
                    required: true,
                })
                .collect();
            selected.bind_mounts.push(BindMountFileConfig {
                source: "/tmp".to_owned(),
                destination: Some(PathBuf::from("/permitted")),
                access: BindAccessFileMode::Ro,
                required: true,
            });

            file.override_launch_mode(None, true, false)
                .expect("select directory launch");
            let mounts =
                resolve_bind_mounts(&file.launcher.profiles["pi"], RuntimeKind::Bubblewrap)
                    .expect("resolve directory permissions");
            assert_eq!(
                mounts,
                [
                    BindMount {
                        source: BindMountSource::Workspace,
                        destination: PathBuf::from("/workspace"),
                        access: BindAccess::ReadWrite,
                    },
                    BindMount {
                        source: BindMountSource::Host(
                            fs::canonicalize("/tmp").expect("canonical temporary directory"),
                        ),
                        destination: PathBuf::from("/permitted"),
                        access: BindAccess::ReadOnly,
                    },
                ]
            );
        }
    }

    #[test]
    fn foreground_launch_disables_herdr_constraints_without_changing_native_runtime() {
        for here in [false, true] {
            let mut file = file_config();
            if here {
                file.launcher.name = Some("../invalid-default".to_owned());
            }
            file.launcher
                .profiles
                .get_mut("pi")
                .expect("profile")
                .identity = Some(IdentityFileKind::Herdr);
            file.override_launch_mode(None, here, true)
                .expect("select foreground launch");
            let settings = LauncherSettings::resolve(None, None, None, None, false, &file)
                .expect("resolve without Herdr restrictions");
            assert_eq!(
                settings.name,
                if here {
                    None
                } else {
                    Some(WorkspaceName("file".to_owned()))
                }
            );
            assert_eq!(settings.identity, None);
            assert_eq!(settings.runtime.kind, RuntimeKind::Native);
        }
    }

    #[test]
    fn rejects_missing_profiles_and_invalid_commands() {
        let base = FileConfig {
            socket: Some(PathBuf::from("/unused.sock")),
            launcher: LauncherFileConfig {
                profiles: BTreeMap::from([("test".to_owned(), profile(None))]),
                ..LauncherFileConfig::default()
            },
            ..FileConfig::default()
        };
        let missing_profile = LauncherSettings::resolve(None, None, None, None, false, &base)
            .expect_err("reject missing profile");
        let unknown =
            LauncherSettings::resolve(None, None, Some("unknown".to_owned()), None, false, &base)
                .expect_err("reject unknown profile");
        let missing_command =
            LauncherSettings::resolve(None, None, Some("test".to_owned()), None, false, &base)
                .expect_err("reject missing command");
        let empty = LauncherSettings::resolve(
            None,
            None,
            Some("test".to_owned()),
            Some("  # no executable".to_owned()),
            false,
            &base,
        )
        .expect_err("reject empty command");
        let malformed = LauncherSettings::resolve(
            None,
            None,
            Some("test".to_owned()),
            Some("pi 'unterminated".to_owned()),
            false,
            &base,
        )
        .expect_err("reject malformed command");

        assert!(matches!(missing_profile, SettingsError::MissingProfile));
        assert!(matches!(unknown, SettingsError::UnknownProfile(_)));
        assert!(matches!(
            missing_command,
            SettingsError::MissingCommand(profile) if profile == "test"
        ));
        assert!(matches!(empty, SettingsError::EmptyCommand));
        assert!(matches!(malformed, SettingsError::InvalidCommand { .. }));
    }

    #[test]
    fn rejects_invalid_workspace_and_mount_configuration() {
        let empty_name = LauncherSettings::resolve(
            Some(PathBuf::from("/unused.sock")),
            Some("  ".to_owned()),
            Some("pi".to_owned()),
            None,
            false,
            &file_config(),
        )
        .expect_err("reject empty workspace name");
        let relative_root = DaemonSettings::resolve(
            Some(PathBuf::from("/unused.sock")),
            Some(PathBuf::from("relative")),
            None,
            false,
            &FileConfig::default(),
        )
        .expect_err("reject relative root");
        let missing_workspace = resolve_bind_mounts(
            &ProfileFileConfig {
                identity: None,
                set_environment: BTreeMap::new(),
                environment: Vec::new(),
                command: Some("pi".to_owned()),
                project_environment: None,
                network: None,
                bind_mounts: Vec::new(),
                memory_max_bytes: None,
                tasks_max: None,
                cpu_quota_basis_points: None,
                cpu_cores: None,
                cpu_count: None,
            },
            RuntimeKind::Bubblewrap,
        )
        .expect_err("reject missing workspace mount");
        let relative_source = resolve_bind_mounts(
            &ProfileFileConfig {
                identity: None,
                set_environment: BTreeMap::new(),
                environment: Vec::new(),
                command: Some("pi".to_owned()),
                project_environment: None,
                network: None,
                bind_mounts: vec![BindMountFileConfig {
                    source: "relative".to_owned(),
                    destination: None,
                    access: BindAccessFileMode::Ro,
                    required: true,
                }],
                memory_max_bytes: None,
                tasks_max: None,
                cpu_quota_basis_points: None,
                cpu_cores: None,
                cpu_count: None,
            },
            RuntimeKind::Native,
        )
        .expect_err("reject relative source");
        let protected_destination = normalize_destination(PathBuf::from("/etc/credentials"))
            .expect_err("reject protected destination");
        let nul_destination = normalize_destination(PathBuf::from(OsString::from_vec(
            b"/home/user/\0secret".to_vec(),
        )))
        .expect_err("reject destination containing NUL");

        assert!(matches!(empty_name, SettingsError::InvalidWorkspaceName));
        assert!(matches!(
            relative_root,
            SettingsError::RelativeWorkspaceRoot(_)
        ));
        assert!(matches!(
            missing_workspace,
            SettingsError::MissingWorkspaceMount
        ));
        assert!(matches!(
            relative_source,
            SettingsError::RelativeBindSource(_)
        ));
        assert!(matches!(
            protected_destination,
            SettingsError::ProtectedBindDestination(_)
        ));
        assert!(matches!(
            nul_destination,
            SettingsError::InvalidBindDestination(_)
        ));
    }

    #[test]
    fn validates_profile_limits_and_daemon_resource_ceiling() {
        let mut file = file_config();
        let profile = file.launcher.profiles.get_mut("pi").expect("pi profile");
        profile.memory_max_bytes = Some(1 << 30);
        profile.tasks_max = Some(128);
        profile.cpu_quota_basis_points = Some(15_000);
        let launcher =
            LauncherSettings::resolve(None, None, Some("pi".to_owned()), None, false, &file)
                .expect("valid limits");
        assert_eq!(launcher.limits.memory_max_bytes, Some(1 << 30));

        file.daemon.resource_ceiling.memory_max_bytes = Some(1 << 29);
        let mut daemon_file = daemon_file_config();
        daemon_file.daemon.resource_ceiling.memory_max_bytes = Some(1 << 29);
        let daemon = DaemonSettings::resolve(None, None, None, false, &daemon_file)
            .expect("valid daemon ceiling");
        assert_eq!(daemon.resource_ceiling.memory_max_bytes, Some(1 << 29));
        assert!(matches!(
            LauncherSettings::resolve(None, None, Some("pi".to_owned()), None, false, &file),
            Err(SettingsError::InvalidResourceLimits("launcher profile"))
        ));

        file.launcher
            .profiles
            .get_mut("pi")
            .expect("pi profile")
            .tasks_max = Some(0);
        assert!(matches!(
            LauncherSettings::resolve(None, None, Some("pi".to_owned()), None, false, &file),
            Err(SettingsError::InvalidResourceLimits("launcher profile"))
        ));
    }

    #[test]
    fn validates_cpu_selection_in_profiles() {
        for (selection, valid) in [
            ("cpu_count = 1", true),
            ("cpu_count = 1024", true),
            ("cpu_cores = [0, 1023]", true),
            ("cpu_count = 0", false),
            ("cpu_count = 1025", false),
            ("cpu_cores = []", false),
            ("cpu_cores = [1, 1]", false),
            ("cpu_cores = [1024]", false),
            ("cpu_cores = [0]\ncpu_count = 1", false),
        ] {
            let file: FileConfig = toml::from_str(&format!(
                "socket = '/tmp/runroom.sock'\n[launcher]\nprofile = 'pi'\n\
                 [launcher.profiles.pi]\ncommand = '/bin/true'\n{selection}\n"
            ))
            .expect("parse CPU selection");
            let result = LauncherSettings::resolve(None, None, None, None, false, &file);
            if valid {
                result.expect("valid CPU selection");
            } else {
                assert!(matches!(
                    result,
                    Err(SettingsError::InvalidResourceLimits("launcher profile"))
                ));
            }
        }
    }

    #[test]
    fn cpu_override_replaces_both_values_only_in_the_selected_profile() {
        let mut file = file_config();
        file.launcher.profiles.get_mut("pi").unwrap().cpu_count = Some(8);
        let mut other = profile(Some("/bin/true"));
        other.cpu_cores = Some(vec![1, 1]);
        other.cpu_count = Some(0);
        file.launcher.profiles.insert("other".to_owned(), other);

        file.override_cpu_selection(Some("other"), None, Some(2))
            .expect("apply count override to invalid configured selection");
        let settings =
            LauncherSettings::resolve(None, None, Some("other".to_owned()), None, false, &file)
                .expect("resolve effective count selection");
        assert_eq!(settings.limits.cpu_count, Some(2));
        assert_eq!(settings.limits.cpu_cores, None);
        assert_eq!(file.launcher.profiles["pi"].cpu_count, Some(8));

        file.override_cpu_selection(None, Some(vec![4, 7]), None)
            .expect("apply core IDs to the default profile");
        file.override_cpu_selection(None, None, None)
            .expect("absent CLI selection preserves profile values");
        let settings = LauncherSettings::resolve(None, None, None, None, false, &file)
            .expect("resolve effective explicit core selection");
        assert_eq!(settings.limits.cpu_cores, Some(vec![4, 7]));
        assert_eq!(settings.limits.cpu_count, None);

        file.override_cpu_selection(None, None, Some(0))
            .expect("apply invalid CLI selection before validation");
        assert!(matches!(
            LauncherSettings::resolve(None, None, None, None, false, &file),
            Err(SettingsError::InvalidResourceLimits("launcher profile"))
        ));
    }
}
