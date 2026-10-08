//! User configuration and command-line override resolution.

use std::collections::{BTreeMap, HashSet};
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use runroom::model::{
    BindAccess, BindMount, BindMountSource, DeviceMount, EnvironmentVariable, ForegroundCommand,
    NetworkMode, ResourceLimits, RuntimeKind, RuntimePolicy, WorkspaceName,
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
            .unwrap_or("default");
        validate_profile_name(profile)?;
        let configured = self
            .launcher
            .profiles
            .get_mut(profile)
            .ok_or_else(|| SettingsError::UnknownProfile(profile.to_owned()))?;
        configured.cpu_cores = cpu_cores;
        configured.cpu_count = cpu_count;
        Ok(())
    }

    /// Select the exact directory before validating the selected profile.
    pub fn override_launch_mode(
        &mut self,
        profile_override: Option<&str>,
        no_worktree: bool,
    ) -> Result<(), SettingsError> {
        if !no_worktree {
            return Ok(());
        }
        self.launcher.name = None;
        let profile = profile_override
            .or(self.launcher.profile.as_deref())
            .unwrap_or("default");
        validate_profile_name(profile)?;
        let configured = self
            .launcher
            .profiles
            .get_mut(profile)
            .ok_or_else(|| SettingsError::UnknownProfile(profile.to_owned()))?;
        if self.runtime == Some(RuntimeFileKind::Bubblewrap) {
            configured
                .bind_mounts
                .retain(|mount| !matches!(&mount.source, BindMountFileSource::Path(path) if path == WORKSPACE_SOURCE));
            configured.bind_mounts.insert(
                0,
                BindMountFileConfig {
                    source: BindMountFileSource::Path(WORKSPACE_SOURCE.to_owned()),
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
#[serde(try_from = "RawLauncherFileConfig")]
pub struct LauncherFileConfig {
    pub name: Option<String>,
    pub profile: Option<String>,
    pub profiles: BTreeMap<String, ProfileFileConfig>,
    pub verbose: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(from = "RawProfileFileConfig")]
pub struct ProfileFileConfig {
    pub command: Option<String>,
    pub project_environment: Option<bool>,
    pub network: Option<NetworkFileMode>,
    pub identity: Option<IdentityFileKind>,
    pub environment: Vec<String>,
    pub set_environment: BTreeMap<String, String>,
    pub bind_mounts: Vec<BindMountFileConfig>,
    pub devices: Vec<DeviceFileConfig>,
    pub memory_max_bytes: Option<u64>,
    pub tasks_max: Option<u64>,
    pub cpu_quota_basis_points: Option<u32>,
    pub cpu_cores: Option<Vec<u32>>,
    pub cpu_count: Option<u32>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLauncherFileConfig {
    name: Option<String>,
    profile: Option<String>,
    base: Option<RawProfileFileConfig>,
    #[serde(default)]
    profiles: BTreeMap<String, RawProfileFileConfig>,
    verbose: Option<bool>,
}

impl TryFrom<RawLauncherFileConfig> for LauncherFileConfig {
    type Error = SettingsError;

    fn try_from(raw: RawLauncherFileConfig) -> Result<Self, Self::Error> {
        let base = ProfileFileConfig::from(raw.base.unwrap_or_default());
        validate_base_profile(&base)?;
        let profiles = raw
            .profiles
            .into_iter()
            .map(|(name, profile)| Ok((name, profile.inherit(&base)?)))
            .collect::<Result<_, SettingsError>>()?;
        Ok(Self {
            name: raw.name,
            profile: raw.profile,
            profiles,
            verbose: raw.verbose,
        })
    }
}

/// Collection presence distinguishes inheritance from an explicit empty clear.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfileFileConfig {
    command: Option<String>,
    project_environment: Option<bool>,
    network: Option<NetworkFileMode>,
    identity: Option<IdentityFileKind>,
    environment: Option<Vec<String>>,
    set_environment: Option<BTreeMap<String, String>>,
    bind_mounts: Option<Vec<BindMountFileConfig>>,
    devices: Option<Vec<DeviceFileConfig>>,
    memory_max_bytes: Option<u64>,
    tasks_max: Option<u64>,
    cpu_quota_basis_points: Option<u32>,
    cpu_cores: Option<Vec<u32>>,
    cpu_count: Option<u32>,
}

impl From<RawProfileFileConfig> for ProfileFileConfig {
    fn from(raw: RawProfileFileConfig) -> Self {
        Self {
            command: raw.command,
            project_environment: raw.project_environment,
            network: raw.network,
            identity: raw.identity,
            environment: raw.environment.unwrap_or_default(),
            set_environment: raw.set_environment.unwrap_or_default(),
            bind_mounts: raw.bind_mounts.unwrap_or_default(),
            devices: raw.devices.unwrap_or_default(),
            memory_max_bytes: raw.memory_max_bytes,
            tasks_max: raw.tasks_max,
            cpu_quota_basis_points: raw.cpu_quota_basis_points,
            cpu_cores: raw.cpu_cores,
            cpu_count: raw.cpu_count,
        }
    }
}

impl RawProfileFileConfig {
    fn inherit(self, base: &ProfileFileConfig) -> Result<ProfileFileConfig, SettingsError> {
        let environment = match self.environment {
            None => base.environment.clone(),
            Some(names) if names.is_empty() => names,
            Some(names) => {
                validate_environment_allowlist(&names)?;
                let mut merged = base.environment.clone();
                merged.extend(
                    names
                        .into_iter()
                        .filter(|name| !base.environment.contains(name)),
                );
                merged
            }
        };
        let set_environment = match self.set_environment {
            None => base.set_environment.clone(),
            Some(values) if values.is_empty() => values,
            Some(values) => {
                let mut merged = base.set_environment.clone();
                merged.extend(values);
                merged
            }
        };
        let overrides_cpu = self.cpu_cores.is_some() || self.cpu_count.is_some();
        Ok(ProfileFileConfig {
            command: self.command.or_else(|| base.command.clone()),
            project_environment: self.project_environment.or(base.project_environment),
            network: self.network.or(base.network),
            identity: self.identity.or(base.identity),
            environment,
            set_environment,
            bind_mounts: merge_keyed_entries(&base.bind_mounts, self.bind_mounts, bind_mount_key)?,
            devices: merge_keyed_entries(&base.devices, self.devices, |device| {
                Ok(device.selector.clone())
            })?,
            memory_max_bytes: self.memory_max_bytes.or(base.memory_max_bytes),
            tasks_max: self.tasks_max.or(base.tasks_max),
            cpu_quota_basis_points: self.cpu_quota_basis_points.or(base.cpu_quota_basis_points),
            cpu_cores: if overrides_cpu {
                self.cpu_cores
            } else {
                base.cpu_cores.clone()
            },
            cpu_count: if overrides_cpu {
                self.cpu_count
            } else {
                base.cpu_count
            },
        })
    }
}

/// Retain shared entries in order, then append the child layer unchanged.
/// Duplicates inside a layer remain visible to normal runtime validation.
fn merge_keyed_entries<T: Clone, K: Eq>(
    base: &[T],
    child: Option<Vec<T>>,
    key: impl Fn(&T) -> Result<K, SettingsError>,
) -> Result<Vec<T>, SettingsError> {
    let Some(child) = child else {
        return Ok(base.to_vec());
    };
    if child.is_empty() || base.is_empty() {
        return Ok(child);
    }
    let child_keys = child.iter().map(&key).collect::<Result<Vec<_>, _>>()?;
    let mut merged = Vec::with_capacity(base.len() + child.len());
    for entry in base {
        if !child_keys.contains(&key(entry)?) {
            merged.push(entry.clone());
        }
    }
    merged.extend(child);
    Ok(merged)
}

#[derive(Debug, Eq, PartialEq)]
enum BindMountKey {
    Destination(PathBuf),
    Executable(String),
}

fn bind_mount_key(mount: &BindMountFileConfig) -> Result<BindMountKey, SettingsError> {
    if let Some(destination) = &mount.destination {
        return normalize_destination(destination.clone()).map(BindMountKey::Destination);
    }
    match &mount.source {
        BindMountFileSource::Path(path) if path == WORKSPACE_SOURCE => {
            Err(SettingsError::MissingWorkspaceDestination)
        }
        BindMountFileSource::Path(path) => {
            normalize_destination(expand_host_path(path)?).map(BindMountKey::Destination)
        }
        BindMountFileSource::Executable(name) => Ok(BindMountKey::Executable(name.clone())),
    }
}

fn validate_environment_allowlist(names: &[String]) -> Result<(), SettingsError> {
    let mut seen = HashSet::with_capacity(names.len());
    for name in names {
        validate_environment_name(name)?;
        if !seen.insert(name) {
            return Err(SettingsError::DuplicateEnvironmentName(name.clone()));
        }
    }
    Ok(())
}

/// Validate abstract settings without requiring a command or accessing host grants.
fn validate_base_profile(base: &ProfileFileConfig) -> Result<(), SettingsError> {
    if let Some(command) = &base.command {
        parse_command(command)?;
    }
    validate_environment_allowlist(&base.environment)?;
    for name in base.set_environment.keys() {
        validate_environment_name(name)?;
    }
    let mut destinations = Vec::with_capacity(base.bind_mounts.len());
    let mut workspace_mounts = 0;
    for mount in &base.bind_mounts {
        match &mount.source {
            BindMountFileSource::Path(path) if path == WORKSPACE_SOURCE => {
                if !mount.required {
                    return Err(SettingsError::OptionalWorkspaceMount);
                }
                workspace_mounts += 1;
            }
            BindMountFileSource::Path(path) => {
                expand_host_path(path)?;
            }
            BindMountFileSource::Executable(name) => validate_executable_name(name)?,
        }
        let key = bind_mount_key(mount)?;
        if destinations.contains(&key) {
            let destination = match key {
                BindMountKey::Destination(path) => path,
                BindMountKey::Executable(name) => Path::new("/opt/runroom/bin").join(name),
            };
            return Err(SettingsError::DuplicateBindDestination(destination));
        }
        destinations.push(key);
    }
    if workspace_mounts > 1 {
        return Err(SettingsError::DuplicateWorkspaceMount);
    }
    for device in &base.devices {
        match &device.selector {
            DeviceSelector::Path(path) => validate_device_path(path)?,
            DeviceSelector::Class(class) => validate_device_class(class)?,
        }
    }
    validate_resource_limits(
        &ResourceLimits {
            memory_max_bytes: base.memory_max_bytes,
            tasks_max: base.tasks_max,
            cpu_quota_basis_points: base.cpu_quota_basis_points,
            cpu_cores: base.cpu_cores.clone(),
            cpu_count: base.cpu_count,
        },
        &protocol_ceiling(),
        "launcher base",
    )
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkFileMode {
    #[default]
    None,
    Host,
    Private,
}

impl From<NetworkFileMode> for NetworkMode {
    fn from(value: NetworkFileMode) -> Self {
        match value {
            NetworkFileMode::None => Self::None,
            NetworkFileMode::Host => Self::Host,
            NetworkFileMode::Private => Self::Private,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IdentityFileKind {
    Herdr,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(try_from = "RawBindMountFileConfig")]
pub struct BindMountFileConfig {
    pub source: BindMountFileSource,
    pub destination: Option<PathBuf>,
    pub access: BindAccessFileMode,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindMountFileSource {
    Path(String),
    Executable(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBindMountFileConfig {
    source: Option<String>,
    executable: Option<String>,
    destination: Option<PathBuf>,
    access: BindAccessFileMode,
    #[serde(default = "required_by_default")]
    required: bool,
}

impl TryFrom<RawBindMountFileConfig> for BindMountFileConfig {
    type Error = &'static str;

    fn try_from(raw: RawBindMountFileConfig) -> Result<Self, Self::Error> {
        let source = match (raw.source, raw.executable) {
            (Some(path), None) => BindMountFileSource::Path(path),
            (None, Some(name)) => BindMountFileSource::Executable(name),
            _ => return Err("bind mount requires exactly one of source or executable"),
        };
        Ok(Self {
            source,
            destination: raw.destination,
            access: raw.access,
            required: raw.required,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(try_from = "RawDeviceFileConfig")]
pub struct DeviceFileConfig {
    pub selector: DeviceSelector,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceSelector {
    Path(PathBuf),
    Class(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeviceFileConfig {
    path: Option<PathBuf>,
    class: Option<String>,
    #[serde(default = "required_by_default")]
    required: bool,
}

impl TryFrom<RawDeviceFileConfig> for DeviceFileConfig {
    type Error = &'static str;

    fn try_from(raw: RawDeviceFileConfig) -> Result<Self, Self::Error> {
        let selector = match (raw.path, raw.class) {
            (Some(path), None) => DeviceSelector::Path(path),
            (None, Some(class)) => DeviceSelector::Class(class),
            _ => return Err("device entry requires exactly one of path or class"),
        };
        Ok(Self {
            selector,
            required: raw.required,
        })
    }
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
            .unwrap_or_else(|| "default".to_owned());
        validate_profile_name(&profile)?;
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
        let network = resolve_network(kind, profile_config.network)?;
        let bind_mounts = resolve_bind_mounts(profile_config, kind)?;
        let devices = resolve_devices(profile_config, kind)?;
        let mut environment = resolve_environment(profile_config)?;
        if kind == RuntimeKind::Bubblewrap
            && profile_config
                .bind_mounts
                .iter()
                .any(|mount| matches!(mount.source, BindMountFileSource::Executable(_)))
        {
            prepend_executable_path(&mut environment);
        }
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
            device_count = devices.len(),
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
                devices,
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

fn resolve_network(
    kind: RuntimeKind,
    configured: Option<NetworkFileMode>,
) -> Result<NetworkMode, SettingsError> {
    let network = configured.map_or_else(
        || match kind {
            RuntimeKind::Native => NetworkMode::Host,
            RuntimeKind::Bubblewrap => NetworkMode::None,
        },
        Into::into,
    );
    if network == NetworkMode::Private && kind != RuntimeKind::Bubblewrap {
        return Err(SettingsError::PrivateNetworkRequiresBubblewrap);
    }
    Ok(network)
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
                Some(path) => expand_user_path(path)?,
                None => default_workspace_root()?,
            };
        if !workspace_root.is_absolute() {
            return Err(SettingsError::RelativeWorkspaceRoot(workspace_root));
        }
        let state_file = match state_file_override.or_else(|| file.daemon.state_file.clone()) {
            Some(path) => expand_user_path(path)?,
            None => default_state_file()?,
        };
        if !state_file.is_absolute() {
            return Err(SettingsError::RelativeStateFile(state_file));
        }
        let herdr_socket = match &file.daemon.herdr_socket {
            Some(path) => expand_user_path(path.clone())?,
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
        Some(socket) => expand_user_path(socket),
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
        if profile.set_environment.contains_key(name) {
            continue;
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

/// Merge CLI grants into this launch only, retaining absolute arguments for pane routing.
pub fn apply_launch_mounts(
    runtime: &mut RuntimePolicy,
    read_only: &[PathBuf],
    specifications: &[String],
    current_directory: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    if read_only.is_empty() && specifications.is_empty() {
        return Ok(Vec::new());
    }
    if runtime.kind != RuntimeKind::Bubblewrap {
        return Err("launch mount flags require the bubblewrap runtime".into());
    }
    if read_only.len() + specifications.len() > 128 {
        return Err("at most 128 launch mounts are allowed".into());
    }
    let mut arguments = Vec::with_capacity(read_only.len() + specifications.len());
    for path in read_only {
        let source = resolve_launch_source(path, current_directory)?;
        let expanded = expand_user_path(path.clone())?;
        let name = expanded
            .file_name()
            .ok_or("read-only mount source needs a basename; use --mount SOURCE@DEST:ro")?;
        let destination = Path::new("/").join(name);
        append_launch_mount(
            runtime,
            source,
            destination,
            BindAccess::ReadOnly,
            &mut arguments,
        )?;
    }
    for specification in specifications {
        let (paths, mode) = specification
            .rsplit_once(':')
            .ok_or("mount must use SOURCE@DEST:ro|rw")?;
        let access = match mode {
            "ro" => BindAccess::ReadOnly,
            "rw" => BindAccess::ReadWrite,
            _ => return Err("mount access must be ro or rw".into()),
        };
        let (source, destination) = paths
            .rsplit_once('@')
            .filter(|(source, destination)| !source.is_empty() && !destination.is_empty())
            .ok_or("mount must use SOURCE@DEST:ro|rw")?;
        let source = resolve_launch_source(Path::new(source), current_directory)?;
        let destination = normalize_destination(PathBuf::from(destination))?;
        append_launch_mount(runtime, source, destination, access, &mut arguments)?;
    }
    Ok(arguments)
}

fn resolve_launch_source(path: &Path, current_directory: &Path) -> Result<PathBuf, SettingsError> {
    let expanded = expand_user_path(path.to_owned())?;
    let absolute = current_directory.join(expanded);
    fs::canonicalize(&absolute).map_err(|source| SettingsError::InvalidBindSource {
        path: absolute,
        source,
    })
}

fn append_launch_mount(
    runtime: &mut RuntimePolicy,
    source: PathBuf,
    destination: PathBuf,
    access: BindAccess,
    arguments: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let destination = normalize_destination(destination)?;
    if runtime
        .bind_mounts
        .iter()
        .any(|mount| mount.destination == destination)
    {
        return Err(SettingsError::DuplicateBindDestination(destination).into());
    }
    let source_text = source
        .to_str()
        .ok_or("launch mount source must be valid UTF-8")?;
    let destination_text = destination
        .to_str()
        .ok_or("launch mount destination must be valid UTF-8")?;
    if destination_text.contains('@') {
        return Err("launch mount destination cannot contain @".into());
    }
    let mode = match access {
        BindAccess::ReadOnly => "ro",
        BindAccess::ReadWrite => "rw",
    };
    arguments.push(format!("{source_text}@{destination_text}:{mode}"));
    runtime.bind_mounts.push(BindMount {
        source: BindMountSource::Host(source),
        destination,
        access,
    });
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
        let (source, default_destination) = if matches!(&configured.source, BindMountFileSource::Path(path) if path == WORKSPACE_SOURCE)
        {
            if !configured.required {
                return Err(SettingsError::OptionalWorkspaceMount);
            }
            workspace_mounts += 1;
            (BindMountSource::Workspace, None)
        } else {
            let (expanded, destination) = match &configured.source {
                BindMountFileSource::Path(path) => {
                    let expanded = expand_host_path(path)?;
                    (expanded.clone(), expanded)
                }
                BindMountFileSource::Executable(name) => {
                    let path = env::var_os("PATH").unwrap_or_default();
                    let Some(executable) = executable_on_path(name, &path)? else {
                        if configured.required {
                            return Err(SettingsError::ExecutableNotFound(name.clone()));
                        }
                        continue;
                    };
                    (executable, Path::new("/opt/runroom/bin").join(name))
                }
            };
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
            let source = if matches!(configured.source, BindMountFileSource::Executable(_)) {
                BindMountSource::Executable(source)
            } else {
                BindMountSource::Host(source)
            };
            (source, Some(destination))
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

fn resolve_devices(
    profile: &ProfileFileConfig,
    runtime: RuntimeKind,
) -> Result<Vec<DeviceMount>, SettingsError> {
    if runtime != RuntimeKind::Bubblewrap && !profile.devices.is_empty() {
        return Err(SettingsError::DevicesRequireBubblewrap);
    }
    resolve_devices_at(&profile.devices, Path::new("/dev"), Path::new("/sys/class"))
}

// Explicit discovery roots let tests exercise sysfs and NVIDIA discovery
// without GPU hardware. Canonical sources must still be real /dev nodes.
fn resolve_devices_at(
    configured: &[DeviceFileConfig],
    dev_root: &Path,
    class_root: &Path,
) -> Result<Vec<DeviceMount>, SettingsError> {
    let mut mounts = BTreeMap::new();
    for entry in configured {
        match &entry.selector {
            DeviceSelector::Path(path) => {
                validate_device_path(path)?;
                let relative = path.strip_prefix("/dev").expect("validated device path");
                if let Some(mount) =
                    resolve_device_node(&dev_root.join(relative), path, entry.required, false)?
                {
                    mounts.insert(mount.destination, mount.source);
                }
            }
            DeviceSelector::Class(class) => {
                validate_device_class(class)?;
                let candidates = if class == "nvidia" {
                    discover_nvidia_devices(dev_root, entry.required)?
                } else {
                    discover_class_devices(&class_root.join(class), entry.required)?
                };
                let mut found = false;
                for destination in candidates {
                    validate_device_path(&destination)?;
                    let relative = destination
                        .strip_prefix("/dev")
                        .expect("validated device path");
                    if let Some(mount) = resolve_device_node(
                        &dev_root.join(relative),
                        &destination,
                        entry.required,
                        true,
                    )? {
                        found = true;
                        mounts.insert(mount.destination, mount.source);
                    }
                }
                if entry.required && !found {
                    return Err(SettingsError::MissingDeviceClass(class.clone()));
                }
            }
        }
    }
    Ok(mounts
        .into_iter()
        .map(|(destination, source)| DeviceMount {
            source,
            destination,
        })
        .collect())
}

fn validate_device_path(path: &Path) -> Result<(), SettingsError> {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(SettingsError::InvalidDevicePath(path.to_owned()));
            }
        }
    }
    if !path.is_absolute()
        || path.as_os_str().as_bytes().contains(&0)
        || normalized.as_os_str() != path.as_os_str()
        || path == Path::new("/dev")
        || !path.starts_with("/dev")
        || [
            "/dev/shm",
            "/dev/pts",
            "/dev/ptmx",
            "/dev/fd",
            "/dev/stdin",
            "/dev/stdout",
            "/dev/stderr",
            "/dev/core",
        ]
        .iter()
        .any(|protected| path.starts_with(protected))
    {
        return Err(SettingsError::InvalidDevicePath(path.to_owned()));
    }
    Ok(())
}

fn validate_device_class(class: &str) -> Result<(), SettingsError> {
    if class.is_empty()
        || class == "."
        || class == ".."
        || class
            .as_bytes()
            .iter()
            .any(|byte| *byte == b'/' || *byte == 0)
    {
        return Err(SettingsError::InvalidDeviceClass(class.to_owned()));
    }
    Ok(())
}

fn device_io(path: &Path, source: io::Error) -> SettingsError {
    SettingsError::DeviceIo {
        path: path.to_owned(),
        source,
    }
}

fn resolve_device_node(
    path: &Path,
    destination: &Path,
    required: bool,
    class_member: bool,
) -> Result<Option<DeviceMount>, SettingsError> {
    let source = match fs::canonicalize(path) {
        Ok(source) => source,
        Err(error) if !required && error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(device_io(path, error)),
    };
    let metadata = match fs::metadata(&source) {
        Ok(metadata) => metadata,
        Err(error) if !required && error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(device_io(&source, error)),
    };
    if !metadata.file_type().is_char_device() && !metadata.file_type().is_block_device() {
        return if class_member {
            Ok(None)
        } else {
            Err(SettingsError::DeviceNotNode(source))
        };
    }
    if source == Path::new("/dev") || !source.starts_with("/dev") {
        return Err(SettingsError::InvalidDevicePath(source));
    }
    Ok(Some(DeviceMount {
        source,
        destination: destination.to_owned(),
    }))
}

fn device_directory(path: &Path, required: bool) -> Result<Option<fs::ReadDir>, SettingsError> {
    match fs::read_dir(path) {
        Ok(entries) => Ok(Some(entries)),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !required => Ok(None),
        Err(error) => Err(device_io(path, error)),
    }
}

fn discover_nvidia_devices(dev_root: &Path, required: bool) -> Result<Vec<PathBuf>, SettingsError> {
    let mut candidates = Vec::new();
    let Some(entries) = device_directory(dev_root, required)? else {
        return Ok(candidates);
    };
    for entry in entries {
        let entry = entry.map_err(|error| device_io(dev_root, error))?;
        let name = entry.file_name();
        let bytes = name.as_bytes();
        let gpu = bytes
            .strip_prefix(b"nvidia")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.iter().all(u8::is_ascii_digit));
        if gpu
            || matches!(
                bytes,
                b"nvidiactl" | b"nvidia-modeset" | b"nvidia-uvm" | b"nvidia-uvm-tools"
            )
        {
            candidates.push(Path::new("/dev").join(name));
        }
    }
    let caps = dev_root.join("nvidia-caps");
    // Capability nodes and individual driver components are not installed by
    // every driver; only the selected class as a whole must be present.
    if let Some(entries) = device_directory(&caps, false)? {
        for entry in entries {
            let entry = entry.map_err(|error| device_io(&caps, error))?;
            candidates.push(Path::new("/dev/nvidia-caps").join(entry.file_name()));
        }
    }
    Ok(candidates)
}

fn discover_class_devices(
    class_path: &Path,
    required: bool,
) -> Result<Vec<PathBuf>, SettingsError> {
    let mut candidates = Vec::new();
    let Some(entries) = device_directory(class_path, false)? else {
        return Ok(candidates);
    };
    for entry in entries {
        let entry = entry.map_err(|error| device_io(class_path, error))?;
        let path = entry.path();
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if !required && error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(device_io(&path, error)),
        };
        if metadata.is_dir() {
            collect_class_devices(&path, &mut candidates)?;
        }
    }
    Ok(candidates)
}

fn collect_class_devices(
    member: &Path,
    candidates: &mut Vec<PathBuf>,
) -> Result<(), SettingsError> {
    let uevent = member.join("uevent");
    match fs::read_to_string(&uevent) {
        Ok(contents) => {
            for name in contents
                .lines()
                .filter_map(|line| line.strip_prefix("DEVNAME="))
            {
                if Path::new(name).is_absolute() || name.is_empty() {
                    return Err(SettingsError::InvalidDevicePath(PathBuf::from(name)));
                }
                candidates.push(Path::new("/dev").join(name));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(device_io(&uevent, error)),
    }
    for entry in fs::read_dir(member).map_err(|error| device_io(member, error))? {
        let entry = entry.map_err(|error| device_io(member, error))?;
        // Follow membership symlinks once, above, but not sysfs device/subsystem
        // links back into the tree. Nested input/event nodes are real directories.
        if entry
            .file_type()
            .map_err(|error| device_io(&entry.path(), error))?
            .is_dir()
        {
            collect_class_devices(&entry.path(), candidates)?;
        }
    }
    Ok(())
}

fn executable_on_path(
    name: &str,
    search_path: &std::ffi::OsStr,
) -> Result<Option<PathBuf>, SettingsError> {
    validate_executable_name(name)?;
    for directory in env::split_paths(search_path) {
        let candidate = directory.join(name);
        match fs::metadata(&candidate) {
            Ok(metadata) if metadata.is_file() => {
                match nix::unistd::access(&candidate, nix::unistd::AccessFlags::X_OK) {
                    Ok(()) => return Ok(Some(candidate)),
                    Err(
                        nix::errno::Errno::EACCES
                        | nix::errno::Errno::ENOENT
                        | nix::errno::Errno::ENOTDIR,
                    ) => {}
                    Err(source) => {
                        return Err(SettingsError::InvalidBindSource {
                            path: candidate,
                            source: source.into(),
                        });
                    }
                }
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::NotADirectory
                        | io::ErrorKind::PermissionDenied
                ) => {}
            Err(source) => {
                return Err(SettingsError::InvalidBindSource {
                    path: candidate,
                    source,
                });
            }
        }
    }
    Ok(None)
}

fn validate_executable_name(name: &str) -> Result<(), SettingsError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name
            .as_bytes()
            .iter()
            .any(|byte| *byte == b'/' || *byte == 0)
    {
        return Err(SettingsError::InvalidExecutableName(name.to_owned()));
    }
    Ok(())
}

fn prepend_executable_path(environment: &mut Vec<EnvironmentVariable>) {
    if let Some(variable) = environment
        .iter_mut()
        .find(|variable| variable.name == "PATH")
    {
        let mut value = OsString::from("/opt/runroom/bin:");
        value.push(&variable.value);
        variable.value = value;
    } else {
        let mut value = OsString::from("/opt/runroom/bin:");
        value.push(env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()));
        environment.push(EnvironmentVariable {
            name: "PATH".to_owned(),
            value,
        });
    }
}

fn expand_user_path(path: PathBuf) -> Result<PathBuf, SettingsError> {
    if let Ok(relative) = path.strip_prefix("~") {
        let home = absolute_environment_path("HOME").ok_or(SettingsError::MissingHome)?;
        Ok(home.join(relative))
    } else {
        Ok(path)
    }
}

fn expand_host_path(source: &str) -> Result<PathBuf, SettingsError> {
    let path = expand_user_path(PathBuf::from(source))?;
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(SettingsError::RelativeBindSource(path))
    }
}

fn normalize_destination(destination: PathBuf) -> Result<PathBuf, SettingsError> {
    let destination = expand_user_path(destination)?;
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

fn validate_profile_name(name: &str) -> Result<(), SettingsError> {
    if name.trim().is_empty() {
        return Err(SettingsError::InvalidProfileName);
    }
    if name == "base" {
        return Err(SettingsError::AbstractProfile);
    }
    Ok(())
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
    AbstractProfile,
    InvalidProfileName,
    UnknownProfile(String),
    MissingCommand(String),
    EmptyCommand,
    InvalidCommand { source: shell_words::ParseError },
    InvalidEnvironmentName(String),
    DuplicateEnvironmentName(String),
    IdentityRequiresBubblewrap,
    IdentityRequiresWorkspaceDestination,
    PrivateNetworkRequiresBubblewrap,
    BubblewrapUnavailable(io::Error),
    BubblewrapNotExecutable,
    TerminalPolicyUnavailable(io::Error),
    LegacyTiocstiEnabled,
    MissingHome,
    RelativeBindSource(PathBuf),
    InvalidBindSource { path: PathBuf, source: io::Error },
    InvalidExecutableName(String),
    ExecutableNotFound(String),
    MissingWorkspaceDestination,
    InvalidBindDestination(PathBuf),
    ProtectedBindDestination(PathBuf),
    DuplicateBindDestination(PathBuf),
    DevicesRequireBubblewrap,
    InvalidDevicePath(PathBuf),
    InvalidDeviceClass(String),
    DeviceNotNode(PathBuf),
    MissingDeviceClass(String),
    DeviceIo { path: PathBuf, source: io::Error },
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
    // Keep user-facing messages in one exhaustive match over configuration errors.
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultSocket(source) => source.fmt(formatter),
            Self::InvalidWorkspaceName => formatter.write_str("workspace name must not be empty"),
            Self::AbstractProfile => {
                formatter.write_str("launcher profile 'base' is abstract and cannot be selected")
            }
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
            Self::PrivateNetworkRequiresBubblewrap => formatter.write_str(
                "network = \"private\" requires the Bubblewrap runtime; set runtime = \"bubblewrap\"",
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
            Self::InvalidExecutableName(name) => write!(formatter, "executable selector must be a bare command name: {name}"),
            Self::ExecutableNotFound(name) => write!(formatter, "required executable was not found on PATH: {name}"),
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
            Self::DevicesRequireBubblewrap => formatter.write_str(
                "device configuration requires Bubblewrap; native execution cannot confine devices",
            ),
            Self::InvalidDevicePath(path) => write!(
                formatter,
                "device path must be a normalized node beneath /dev outside runtime-managed paths: {}",
                path.display()
            ),
            Self::InvalidDeviceClass(class) => write!(
                formatter,
                "device class must be one /sys/class component: {class}"
            ),
            Self::DeviceNotNode(path) => write!(
                formatter,
                "device source is not a character or block device: {}",
                path.display()
            ),
            Self::MissingDeviceClass(class) => write!(
                formatter,
                "required device class has no available device nodes: {class}"
            ),
            Self::DeviceIo { path, source } => write!(
                formatter,
                "cannot resolve device path {}: {source}",
                path.display()
            ),
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
            Self::DefaultSocket(source)
            | Self::InvalidBindSource { source, .. }
            | Self::DeviceIo { source, .. } => Some(source),
            Self::InvalidCommand { source } => Some(source),
            Self::BubblewrapUnavailable(source) | Self::TerminalPolicyUnavailable(source) => {
                Some(source)
            }
            Self::InvalidWorkspaceName
            | Self::AbstractProfile
            | Self::InvalidProfileName
            | Self::UnknownProfile(_)
            | Self::NoProfiles
            | Self::MissingCommand(_)
            | Self::EmptyCommand
            | Self::InvalidEnvironmentName(_)
            | Self::DuplicateEnvironmentName(_)
            | Self::IdentityRequiresBubblewrap
            | Self::IdentityRequiresWorkspaceDestination
            | Self::PrivateNetworkRequiresBubblewrap
            | Self::BubblewrapNotExecutable
            | Self::LegacyTiocstiEnabled
            | Self::MissingHome
            | Self::RelativeBindSource(_)
            | Self::InvalidExecutableName(_)
            | Self::ExecutableNotFound(_)
            | Self::MissingWorkspaceDestination
            | Self::InvalidBindDestination(_)
            | Self::ProtectedBindDestination(_)
            | Self::DuplicateBindDestination(_)
            | Self::DevicesRequireBubblewrap
            | Self::InvalidDevicePath(_)
            | Self::InvalidDeviceClass(_)
            | Self::DeviceNotNode(_)
            | Self::MissingDeviceClass(_)
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
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

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
            devices: Vec::new(),
            memory_max_bytes: None,
            tasks_max: None,
            cpu_quota_basis_points: None,
            cpu_cores: None,
            cpu_count: None,
        }
    }

    #[test]
    fn profiles_inherit_scalars_and_merge_collections_by_key() {
        let file: FileConfig = toml::from_str(
            r#"
socket = "/unused.sock"
[launcher.base]
command = "/bin/true"
project_environment = true
network = "host"
identity = "herdr"
environment = ["PATH", "TERM"]
set_environment = { PATH = "/shared/bin", LANG = "C", KEEP = "shared" }
bind_mounts = [
  { source = "/shared/keep", destination = "/keep", access = "ro" },
  { source = "/shared/old", destination = "/replace", access = "ro" },
  { source = "/implicit", access = "ro" },
  { executable = "tool", access = "ro" },
]
devices = [{ path = "/dev/null" }, { class = "drm" }, { class = "input" }]
memory_max_bytes = 4096
tasks_max = 10
cpu_quota_basis_points = 10000
cpu_cores = [0, 1]
[launcher.profiles.default]
project_environment = false
network = "none"
environment = ["TERM", "LANG"]
set_environment = { PATH = "/child/bin", LANG = "child", ADDED = "child" }
bind_mounts = [
  { source = "/child/new", destination = "/replace", access = "rw", required = false },
  { source = "/other", destination = "/implicit", access = "rw" },
  { executable = "tool", access = "rw", required = false },
  { source = "/added", access = "ro" },
]
devices = [{ path = "/dev/null", required = false }, { class = "drm", required = false }, { path = "/dev/zero" }]
tasks_max = 20
cpu_count = 3
"#,
        )
        .expect("parse inherited profile");
        let effective = &file.launcher.profiles["default"];
        assert_eq!(effective.command.as_deref(), Some("/bin/true"));
        assert_eq!(effective.project_environment, Some(false));
        assert_eq!(effective.network, Some(NetworkFileMode::None));
        assert_eq!(effective.identity, Some(IdentityFileKind::Herdr));
        assert_eq!(effective.memory_max_bytes, Some(4096));
        assert_eq!(effective.tasks_max, Some(20));
        assert_eq!(effective.cpu_quota_basis_points, Some(10000));
        assert_eq!(effective.cpu_cores, None);
        assert_eq!(effective.cpu_count, Some(3));
        assert_eq!(effective.environment, ["PATH", "TERM", "LANG"]);
        assert_eq!(
            effective.set_environment,
            BTreeMap::from([
                ("ADDED".to_owned(), "child".to_owned()),
                ("KEEP".to_owned(), "shared".to_owned()),
                ("LANG".to_owned(), "child".to_owned()),
                ("PATH".to_owned(), "/child/bin".to_owned()),
            ])
        );
        assert_eq!(effective.bind_mounts.len(), 5);
        assert_eq!(
            effective
                .bind_mounts
                .iter()
                .map(|mount| &mount.source)
                .collect::<Vec<_>>(),
            [
                &BindMountFileSource::Path("/shared/keep".to_owned()),
                &BindMountFileSource::Path("/child/new".to_owned()),
                &BindMountFileSource::Path("/other".to_owned()),
                &BindMountFileSource::Executable("tool".to_owned()),
                &BindMountFileSource::Path("/added".to_owned()),
            ]
        );
        assert_eq!(effective.bind_mounts[1].access, BindAccessFileMode::Rw);
        assert!(!effective.bind_mounts[1].required);
        assert!(!effective.bind_mounts[3].required);
        assert_eq!(
            effective.devices,
            [
                device_class("input", true),
                device_path("/dev/null", false),
                device_class("drm", false),
                device_path("/dev/zero", true),
            ]
        );
    }

    #[test]
    fn child_layer_duplicates_are_not_hidden_by_inheritance() {
        let file: FileConfig = toml::from_str(
            r#"
[launcher.base]
bind_mounts = [{ source = "/tmp", destination = "/duplicate", access = "ro" }]
devices = [{ path = "/dev/null" }]
[launcher.profiles.default]
bind_mounts = [
  { source = "/tmp", destination = "/duplicate", access = "ro" },
  { source = "/tmp", destination = "/duplicate", access = "rw" },
]
devices = [{ path = "/dev/null" }, { path = "/dev/null", required = false }]
"#,
        )
        .unwrap();
        let effective = &file.launcher.profiles["default"];
        assert_eq!(effective.bind_mounts.len(), 2);
        assert!(matches!(
            resolve_bind_mounts(effective, RuntimeKind::Native),
            Err(SettingsError::DuplicateBindDestination(path)) if path == Path::new("/duplicate")
        ));
        assert_eq!(
            effective.devices,
            [
                device_path("/dev/null", true),
                device_path("/dev/null", false)
            ]
        );
    }

    #[test]
    fn explicit_empty_collections_clear_inheritance_but_omissions_retain_it() {
        let file: FileConfig = toml::from_str(
            r#"
[launcher.base]
command = "/bin/true"
environment = ["PATH"]
set_environment = { LANG = "C" }
bind_mounts = [{ source = "/shared", access = "ro" }]
devices = [{ path = "/dev/null" }]
[launcher.profiles.inherited]
[launcher.profiles.cleared]
environment = []
set_environment = {}
bind_mounts = []
devices = []
"#,
        )
        .expect("parse inherited and cleared profiles");
        let inherited = &file.launcher.profiles["inherited"];
        assert_eq!(inherited.environment, ["PATH"]);
        assert_eq!(inherited.set_environment["LANG"], "C");
        assert_eq!(inherited.bind_mounts.len(), 1);
        assert_eq!(inherited.devices.len(), 1);
        let cleared = &file.launcher.profiles["cleared"];
        assert_eq!(cleared.environment, Vec::<String>::new());
        assert_eq!(cleared.set_environment, BTreeMap::<String, String>::new());
        assert_eq!(cleared.bind_mounts, Vec::<BindMountFileConfig>::new());
        assert_eq!(cleared.devices, Vec::<DeviceFileConfig>::new());
        assert_eq!(cleared.command.as_deref(), Some("/bin/true"));
    }

    #[test]
    fn expanded_implicit_path_mounts_are_replaced_by_effective_destination() {
        let home = absolute_environment_path("HOME").expect("absolute test home");
        let mut file: FileConfig = toml::from_str(
            r#"
[launcher.base]
bind_mounts = [{ source = "~/.config/tool", access = "ro" }]
[launcher.profiles.default]
"#,
        )
        .unwrap();
        let raw: RawProfileFileConfig = toml::from_str(
            r#"bind_mounts = [{ source = "/replacement", destination = "~/.config/tool", access = "rw" }]"#,
        ).unwrap();
        let inherited = file.launcher.profiles.remove("default").unwrap();
        let merged = raw.inherit(&inherited).unwrap();
        assert_eq!(merged.bind_mounts.len(), 1);
        assert_eq!(merged.bind_mounts[0].access, BindAccessFileMode::Rw);
        assert_eq!(
            bind_mount_key(&merged.bind_mounts[0]).unwrap(),
            BindMountKey::Destination(home.join(".config/tool"))
        );
    }

    #[test]
    fn literal_assignments_override_inherited_host_environment() {
        let file: FileConfig = toml::from_str(
            r#"
socket = "/unused.sock"
[launcher.base]
command = "/bin/true"
environment = ["PATH", "TERM"]
[launcher.profiles.default]
set_environment = { PATH = "/child/bin", TERM = "child-terminal" }
"#,
        )
        .unwrap();
        let settings = LauncherSettings::resolve(None, None, None, None, false, &file).unwrap();
        assert_eq!(
            settings.runtime.environment,
            [
                EnvironmentVariable {
                    name: "PATH".to_owned(),
                    value: OsString::from("/child/bin"),
                },
                EnvironmentVariable {
                    name: "TERM".to_owned(),
                    value: OsString::from("child-terminal"),
                },
            ]
        );
    }

    #[test]
    fn default_selection_yields_to_explicit_config_and_cli_profiles() {
        let mut file: FileConfig = toml::from_str(
            r#"
socket = "/unused.sock"
[launcher.base]
command = "/bin/true"
[launcher.profiles.default]
[launcher.profiles.configured]
[launcher.profiles.cli]
"#,
        )
        .unwrap();
        let resolve = |file: &FileConfig, selected: Option<&str>| {
            LauncherSettings::resolve(None, None, selected.map(str::to_owned), None, false, file)
                .unwrap()
                .profile
        };
        assert_eq!(resolve(&file, None), "default");
        file.launcher.profile = Some("configured".to_owned());
        assert_eq!(resolve(&file, None), "configured");
        assert_eq!(resolve(&file, Some("cli")), "cli");
        file.launcher.profile = None;
        file.launcher.profiles.remove("default");
        assert!(matches!(
            LauncherSettings::resolve(None, None, None, None, false, &file),
            Err(SettingsError::UnknownProfile(name)) if name == "default"
        ));
    }

    #[test]
    fn abstract_base_cannot_be_selected_or_validated_as_runnable() {
        let mut file: FileConfig = toml::from_str(
            r#"
socket = "/unused.sock"
[launcher.base]
environment = ["PATH"]
[launcher.profiles.default]
command = "/bin/true"
[launcher.profiles.base]
command = "/bin/true"
"#,
        )
        .unwrap();
        assert!(matches!(
            LauncherSettings::resolve(None, None, Some("base".to_owned()), None, false, &file),
            Err(SettingsError::AbstractProfile)
        ));
        assert!(matches!(
            file.override_cpu_selection(Some("base"), None, Some(1)),
            Err(SettingsError::AbstractProfile)
        ));
        assert!(matches!(
            file.override_launch_mode(Some("base"), true),
            Err(SettingsError::AbstractProfile)
        ));
        file.launcher.profile = Some("base".to_owned());
        assert!(matches!(
            LauncherSettings::resolve(None, None, None, None, false, &file),
            Err(SettingsError::AbstractProfile)
        ));
        file.launcher.profiles.remove("base");
        assert_eq!(validate_all_profiles(&file).unwrap().len(), 1);
        let only_base: FileConfig =
            toml::from_str("[launcher.base]\nenvironment = ['PATH']").unwrap();
        assert!(matches!(
            validate_all_profiles(&only_base),
            Err(SettingsError::NoProfiles)
        ));
    }

    #[test]
    fn malformed_base_is_rejected_even_without_runnable_profiles() {
        for settings in [
            "unknown = true",
            "extends = 'other'",
            "command = ''",
            "environment = ['PATH', 'PATH']",
            "environment = ['BAD=NAME']",
            "set_environment = { 'BAD=NAME' = 'value' }",
            "cpu_count = 0",
            "cpu_cores = [0]\ncpu_count = 1",
            "memory_max_bytes = 0",
            "bind_mounts = [{ source = 'relative', access = 'ro' }]",
            "bind_mounts = [{ source = '@workspace', access = 'ro' }]",
            "bind_mounts = [{ executable = '/bin/sh', access = 'ro' }]",
            "bind_mounts = [{ source = '/valid', destination = '/etc/tool', access = 'ro' }]",
            "devices = [{ path = '/outside' }]",
            "devices = [{ class = '../unsafe' }]",
        ] {
            assert!(
                toml::from_str::<FileConfig>(&format!("[launcher.base]\n{settings}")).is_err(),
                "{settings}"
            );
        }
        for layer in ["base", "profiles.default"] {
            let config = format!(
                "[launcher.base]\nenvironment = ['PATH']\n[launcher.{layer}]\nenvironment = ['PATH', 'PATH']"
            );
            assert!(toml::from_str::<FileConfig>(&config).is_err());
        }
    }

    #[test]
    fn inherited_cpu_selection_is_replaced_by_child_and_cli_selection() {
        for (base, child, expected_cores, expected_count) in [
            ("cpu_cores = [0, 1]", "cpu_count = 3", None, Some(3)),
            (
                "cpu_count = 3",
                "cpu_cores = [0, 1]",
                Some(vec![0, 1]),
                None,
            ),
            ("cpu_count = 3", "", None, Some(3)),
        ] {
            let mut file: FileConfig = toml::from_str(&format!(
                "socket = '/unused.sock'\n[launcher.base]\ncommand = '/bin/true'\n{base}\n\
                 [launcher.profiles.default]\n{child}\n[launcher.profiles.other]"
            ))
            .unwrap();
            let settings = LauncherSettings::resolve(None, None, None, None, false, &file).unwrap();
            assert_eq!(settings.limits.cpu_cores, expected_cores);
            assert_eq!(settings.limits.cpu_count, expected_count);
            let other = file.launcher.profiles["other"].clone();
            file.override_cpu_selection(None, Some(vec![4, 7]), None)
                .unwrap();
            let settings = LauncherSettings::resolve(None, None, None, None, false, &file).unwrap();
            assert_eq!(settings.limits.cpu_cores, Some(vec![4, 7]));
            assert_eq!(settings.limits.cpu_count, None);
            file.override_cpu_selection(None, None, Some(2)).unwrap();
            let settings = LauncherSettings::resolve(None, None, None, None, false, &file).unwrap();
            assert_eq!(settings.limits.cpu_cores, None);
            assert_eq!(settings.limits.cpu_count, Some(2));
            assert_eq!(file.launcher.profiles["other"], other);
        }
        let file: FileConfig = toml::from_str(
            "socket = '/unused.sock'\n[launcher.base]\ncommand = '/bin/true'\ncpu_count = 2\n\
             [launcher.profiles.default]\ncpu_count = 1\ncpu_cores = [0]",
        )
        .unwrap();
        assert!(matches!(
            LauncherSettings::resolve(None, None, None, None, false, &file),
            Err(SettingsError::InvalidResourceLimits("launcher profile"))
        ));
    }

    struct DeviceFixture {
        root: PathBuf,
        dev: PathBuf,
        classes: PathBuf,
    }

    impl DeviceFixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = env::temp_dir().join(format!(
                "runroom-config-devices-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).expect("create unique device fixture");
            let dev = root.join("dev");
            let classes = root.join("sys/class");
            fs::create_dir(&dev).expect("create fixture dev");
            fs::create_dir_all(&classes).expect("create fixture classes");
            Self { root, dev, classes }
        }

        fn node(&self, name: &str, source: &str) {
            let path = self.dev.join(name);
            fs::create_dir_all(path.parent().expect("node parent")).expect("create node parent");
            symlink(source, path).expect("alias baseline host device");
        }

        fn uevent(&self, member: &str, contents: &str) {
            let path = self.classes.join(member);
            fs::create_dir_all(&path).expect("create fixture class member");
            fs::write(path.join("uevent"), contents).expect("write fixture uevent");
        }

        fn resolve(&self, entries: &[DeviceFileConfig]) -> Result<Vec<DeviceMount>, SettingsError> {
            resolve_devices_at(entries, &self.dev, &self.classes)
        }
    }

    impl Drop for DeviceFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn launch_mounts_reject_conflicting_and_unsafe_grants() {
        let fixture = DeviceFixture::new();
        let runtime = RuntimePolicy {
            kind: RuntimeKind::Bubblewrap,
            network: NetworkMode::None,
            bind_mounts: vec![BindMount {
                source: BindMountSource::Workspace,
                destination: PathBuf::from("/workspace"),
                access: BindAccess::ReadWrite,
            }],
            devices: Vec::new(),
            environment: Vec::new(),
            home: None,
        };
        fs::create_dir(fixture.root.join("docs")).unwrap();
        fs::create_dir_all(fixture.root.join("other/docs")).unwrap();
        let error = apply_launch_mounts(
            &mut runtime.clone(),
            &[PathBuf::from("docs"), PathBuf::from("other/docs")],
            &[],
            &fixture.root,
        )
        .unwrap_err();
        assert!(matches!(error.downcast_ref::<SettingsError>(),
            Some(SettingsError::DuplicateBindDestination(path)) if path == Path::new("/docs")));
        for specification in [
            "dev@/workspace:ro",
            "dev@/etc/tool:rw",
            "dev@relative:ro",
            "dev@/docs/../other:ro",
            "dev@/docs:invalid",
            "@/docs:ro",
            "missing@/docs:ro",
        ] {
            assert!(
                apply_launch_mounts(
                    &mut runtime.clone(),
                    &[],
                    &[specification.to_owned()],
                    &fixture.root,
                )
                .is_err(),
                "accepted {specification}"
            );
        }
        let mut duplicate = runtime.clone();
        apply_launch_mounts(
            &mut duplicate,
            &[],
            &["dev@/docs:ro".to_owned()],
            &fixture.root,
        )
        .unwrap();
        let error = apply_launch_mounts(
            &mut duplicate,
            &[],
            &["dev@/docs:rw".to_owned()],
            &fixture.root,
        )
        .unwrap_err();
        assert!(
            matches!(error.downcast_ref::<SettingsError>(), Some(SettingsError::DuplicateBindDestination(path)) if path == Path::new("/docs"))
        );
        let mut native = runtime;
        native.kind = RuntimeKind::Native;
        assert!(
            apply_launch_mounts(
                &mut native,
                &[],
                &["dev@/docs:ro".to_owned()],
                &fixture.root
            )
            .is_err()
        );
    }

    #[test]
    fn executable_mounts_require_one_bare_name_selector() {
        for entry in [
            r#"{ source = "/bin/sh", executable = "sh", access = "ro" }"#,
            r#"{ access = "ro" }"#,
        ] {
            assert!(
                toml::from_str::<ProfileFileConfig>(&format!("bind_mounts = [{entry}]")).is_err()
            );
        }
        for name in ["", ".", "..", "/bin/sh", "bin/sh", "bad\0name"] {
            assert!(matches!(
                executable_on_path(name, std::ffi::OsStr::new("/bin")),
                Err(SettingsError::InvalidExecutableName(_))
            ));
        }
        let optional: ProfileFileConfig = toml::from_str(
            r#"bind_mounts = [{ executable = "runroom-test-absent-executable", access = "ro", required = false }]"#,
        ).unwrap();
        assert_eq!(
            resolve_bind_mounts(&optional, RuntimeKind::Native).unwrap(),
            Vec::<BindMount>::new()
        );
        let required: ProfileFileConfig = toml::from_str(
            r#"bind_mounts = [{ executable = "runroom-test-absent-executable", access = "ro" }]"#,
        )
        .unwrap();
        assert!(matches!(
            resolve_bind_mounts(&required, RuntimeKind::Native),
            Err(SettingsError::ExecutableNotFound(_))
        ));
    }

    #[test]
    fn executable_path_lookup_skips_nonexecutables_and_respects_symlink_precedence() {
        let fixture = DeviceFixture::new();
        let first = fixture.root.join("first");
        let second = fixture.root.join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        fs::write(first.join("tool"), "not executable").unwrap();
        fs::write(second.join("tool"), "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(second.join("tool"), fs::Permissions::from_mode(0o755)).unwrap();
        let path = env::join_paths([&first, &second]).unwrap();
        assert_eq!(
            executable_on_path("tool", &path).unwrap(),
            Some(second.join("tool"))
        );
        fs::remove_file(first.join("tool")).unwrap();
        symlink(second.join("tool"), first.join("tool")).unwrap();
        assert_eq!(
            executable_on_path("tool", &path).unwrap(),
            Some(first.join("tool"))
        );
    }

    #[test]
    fn home_relative_destinations_expand_before_protected_path_validation() {
        let home = absolute_environment_path("HOME").unwrap();
        assert_eq!(
            normalize_destination(PathBuf::from("~/.config/tool")).unwrap(),
            home.join(".config/tool")
        );
        assert!(matches!(
            normalize_destination(PathBuf::from("~/../escaped")),
            Err(SettingsError::InvalidBindDestination(_))
        ));
        let file: FileConfig = toml::from_str(
            "[daemon]\nstate_file = '~/.local/state/runroom/instances.json'\nworkspace_root = '~/.local/share/runroom/workspaces'\n",
        ).unwrap();
        let settings = DaemonSettings::resolve(None, None, None, false, &file).unwrap();
        assert_eq!(
            settings.state_file,
            home.join(".local/state/runroom/instances.json")
        );
        assert_eq!(
            settings.workspace_root,
            home.join(".local/share/runroom/workspaces")
        );
    }

    fn device_path(path: &str, required: bool) -> DeviceFileConfig {
        DeviceFileConfig {
            selector: DeviceSelector::Path(PathBuf::from(path)),
            required,
        }
    }

    fn device_class(class: &str, required: bool) -> DeviceFileConfig {
        DeviceFileConfig {
            selector: DeviceSelector::Class(class.to_owned()),
            required,
        }
    }

    #[test]
    fn device_entries_require_one_selector_and_default_to_required() {
        let parsed: ProfileFileConfig = toml::from_str(
            r#"devices = [{ path = "/dev/ttyUSB0" }, { class = "drm", required = false }]"#,
        )
        .expect("parse device selectors");
        assert_eq!(
            parsed.devices,
            [
                device_path("/dev/ttyUSB0", true),
                device_class("drm", false),
            ]
        );
        for entries in [
            "[{}]",
            "[{ required = false }]",
            r#"[{ path = "/dev/null", class = "drm" }]"#,
            r#"[{ path = "/dev/null", access = "ro" }]"#,
            r#"[{ class = "drm", required = "no" }]"#,
        ] {
            assert!(
                toml::from_str::<ProfileFileConfig>(&format!("devices = {entries}")).is_err(),
                "{entries}"
            );
        }
    }

    #[test]
    fn device_aliases_preserve_destinations_and_canonicalize_sources() {
        let fixture = DeviceFixture::new();
        fixture.node("serial/by-id/controller", "/dev/null");
        fixture.node("null", "/dev/null");
        let mounts = fixture
            .resolve(&[
                device_path("/dev/serial/by-id/controller", true),
                device_path("/dev/null", true),
                device_path("/dev/serial/by-id/controller", true),
            ])
            .expect("resolve node aliases");
        assert_eq!(
            mounts,
            [
                DeviceMount {
                    source: PathBuf::from("/dev/null"),
                    destination: PathBuf::from("/dev/null"),
                },
                DeviceMount {
                    source: PathBuf::from("/dev/null"),
                    destination: PathBuf::from("/dev/serial/by-id/controller"),
                },
            ]
        );
    }

    #[test]
    fn generic_classes_follow_membership_and_include_nested_nodes_without_cycles() {
        let fixture = DeviceFixture::new();
        fixture.node("input/input7", "/dev/null");
        fixture.node("input/event7", "/dev/zero");
        fixture.uevent("input/input7", "DEVNAME=input/input7\n");
        fixture.uevent("input/input7/event7", "DEVNAME=input/event7\n");
        fixture.uevent("input/no-node", "SUBSYSTEM=input\n");
        symlink(
            &fixture.classes,
            fixture.classes.join("input/input7/subsystem"),
        )
        .expect("create sysfs backlink");
        let target = fixture.root.join("sys/devices/render");
        fs::create_dir_all(&target).expect("create sysfs membership target");
        fs::write(target.join("uevent"), "DEVNAME=input/event7\n").expect("write target uevent");
        fs::create_dir(fixture.classes.join("drm")).expect("create drm class");
        symlink(target, fixture.classes.join("drm/renderD128")).expect("create class membership");

        let mounts = fixture
            .resolve(&[
                device_class("input", true),
                device_class("drm", true),
                device_path("/dev/input/event7", true),
            ])
            .expect("resolve nested classes and overlapping node");
        assert_eq!(
            mounts,
            [
                DeviceMount {
                    source: PathBuf::from("/dev/zero"),
                    destination: PathBuf::from("/dev/input/event7"),
                },
                DeviceMount {
                    source: PathBuf::from("/dev/null"),
                    destination: PathBuf::from("/dev/input/input7"),
                },
            ]
        );
    }

    #[test]
    fn nvidia_class_exposes_only_driver_nodes_and_capability_nodes() {
        let fixture = DeviceFixture::new();
        let expected = [
            "nvidia-caps/nvidia-cap1",
            "nvidia-modeset",
            "nvidia-uvm",
            "nvidia-uvm-tools",
            "nvidia0",
            "nvidia12",
            "nvidiactl",
        ];
        for name in expected {
            fixture.node(name, "/dev/null");
        }
        for name in ["nvidia", "nvidia-debug", "nvidia1extra", "unrelated"] {
            fixture.node(name, "/dev/zero");
        }
        fs::write(fixture.dev.join("nvidia9"), "not a device").expect("write non-node GPU file");
        fs::write(fixture.dev.join("nvidia-caps/readme"), "not a device")
            .expect("write non-node capability file");
        fs::create_dir(fixture.dev.join("nvidia8")).expect("create non-node GPU directory");
        let mounts = fixture
            .resolve(&[
                device_class("nvidia", true),
                device_path("/dev/nvidia0", true),
            ])
            .expect("resolve NVIDIA device class without GPU hardware");
        assert_eq!(mounts.len(), expected.len());
        assert_eq!(
            mounts
                .iter()
                .map(|mount| mount.destination.clone())
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|name| Path::new("/dev").join(name))
                .collect::<Vec<_>>()
        );
        assert!(
            mounts
                .iter()
                .all(|mount| mount.source == Path::new("/dev/null"))
        );
    }

    #[test]
    fn missing_devices_and_classes_are_optional_only_when_requested() {
        let fixture = DeviceFixture::new();
        assert_eq!(
            fixture
                .resolve(&[device_path("/dev/missing", false)])
                .unwrap(),
            Vec::<DeviceMount>::new()
        );
        assert!(matches!(
            fixture.resolve(&[device_path("/dev/missing", true)]),
            Err(SettingsError::DeviceIo { source, .. }) if source.kind() == io::ErrorKind::NotFound
        ));
        for class in ["missing", "nvidia", "empty"] {
            if class == "empty" {
                fs::create_dir(fixture.classes.join(class)).expect("create empty class");
            }
            assert_eq!(
                fixture.resolve(&[device_class(class, false)]).unwrap(),
                Vec::<DeviceMount>::new()
            );
            assert!(matches!(
                fixture.resolve(&[device_class(class, true)]),
                Err(SettingsError::MissingDeviceClass(name)) if name == class
            ));
        }
        fixture.uevent("input/event0", "DEVNAME=input/event0\n");
        assert_eq!(
            fixture.resolve(&[device_class("input", false)]).unwrap(),
            Vec::<DeviceMount>::new()
        );
        assert!(matches!(
            fixture.resolve(&[device_class("input", true)]),
            Err(SettingsError::DeviceIo { source, .. }) if source.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn optional_devices_do_not_hide_wrong_types_or_unexpected_io_errors() {
        let fixture = DeviceFixture::new();
        fs::write(fixture.dev.join("regular"), "not a device").expect("create regular file");
        fs::create_dir(fixture.dev.join("directory")).expect("create directory");
        for name in ["regular", "directory"] {
            assert!(matches!(
                fixture.resolve(&[device_path(&format!("/dev/{name}"), false)]),
                Err(SettingsError::DeviceNotNode(_))
            ));
        }
        symlink("loop", fixture.dev.join("loop")).expect("create broken cyclic alias");
        assert!(matches!(
            fixture.resolve(&[device_path("/dev/loop", false)]),
            Err(SettingsError::DeviceIo { source, .. }) if source.kind() != io::ErrorKind::NotFound
        ));
        fixture.uevent("drm/card0", "DEVNAME=card0\n");
        fs::write(fixture.classes.join("drm/card0/uevent"), [0xff]).expect("write invalid uevent");
        assert!(matches!(
            fixture.resolve(&[device_class("drm", false)]),
            Err(SettingsError::DeviceIo { source, .. }) if source.kind() == io::ErrorKind::InvalidData
        ));
        fs::write(fixture.classes.join("invalid"), "not a directory").expect("write invalid class");
        assert!(matches!(
            fixture.resolve(&[device_class("invalid", false)]),
            Err(SettingsError::DeviceIo { .. })
        ));
    }

    #[test]
    fn optional_classes_preserve_permission_errors() {
        if nix::unistd::Uid::effective().is_root() {
            return; // Root bypasses filesystem mode permissions.
        }
        let fixture = DeviceFixture::new();
        fixture.uevent("drm/card0", "DEVNAME=card0\n");
        let path = fixture.classes.join("drm/card0/uevent");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o0))
            .expect("make uevent unreadable");
        assert!(matches!(
            fixture.resolve(&[device_class("drm", false)]),
            Err(SettingsError::DeviceIo { source, .. }) if source.kind() == io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn rejects_unsafe_device_paths_classes_and_sysfs_devnames() {
        for path in [
            "dev/null",
            "/dev",
            "/dev/",
            "/dev//null",
            "/dev/./null",
            "/dev/../etc/passwd",
            "/dev/null/",
            "/etc/passwd",
            "/device/null",
            "/dev/pts/0",
            "/dev/shm/node",
            "/dev/fd/0",
            "/dev/ptmx",
            "/dev/stdin",
            "/dev/stdout",
            "/dev/stderr",
            "/dev/core",
        ] {
            assert!(
                matches!(
                    validate_device_path(Path::new(path)),
                    Err(SettingsError::InvalidDevicePath(_))
                ),
                "{path}"
            );
        }
        let nul = PathBuf::from(OsString::from_vec(b"/dev/nu\0ll".to_vec()));
        assert!(matches!(
            validate_device_path(&nul),
            Err(SettingsError::InvalidDevicePath(_))
        ));
        for class in ["", ".", "..", "../drm", "drm/card0", "/drm", "drm\0"] {
            assert!(
                matches!(
                    validate_device_class(class),
                    Err(SettingsError::InvalidDeviceClass(_))
                ),
                "{class}"
            );
        }
        let fixture = DeviceFixture::new();
        for devname in ["/etc/passwd", "../etc/passwd", "pts/0", ""] {
            fixture.uevent("drm/card0", &format!("DEVNAME={devname}\n"));
            assert!(
                matches!(
                    fixture.resolve(&[device_class("drm", false)]),
                    Err(SettingsError::InvalidDevicePath(_))
                ),
                "{devname}"
            );
        }
    }

    #[test]
    fn native_runtime_rejects_device_configuration_even_when_optional() {
        let mut file = file_config();
        file.launcher
            .profiles
            .get_mut("pi")
            .expect("profile")
            .devices = vec![device_class("nvidia", false)];
        assert!(matches!(
            LauncherSettings::resolve(None, None, None, None, false, &file),
            Err(SettingsError::DevicesRequireBubblewrap)
        ));
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
                    source: BindMountFileSource::Path("@workspace".to_owned()),
                    destination: Some(PathBuf::from("/workspace")),
                    access: BindAccessFileMode::Rw,
                    required: true,
                },
                BindMountFileConfig {
                    source: BindMountFileSource::Path("~/.config/less".to_owned()),
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
    fn private_network_cannot_be_ignored_by_native_configuration() {
        let mut file: FileConfig = toml::from_str(
            r#"
            socket = "/unused.sock"
            [launcher]
            profile = "test"
            [launcher.profiles.test]
            command = "/bin/true"
            network = "private"
            "#,
        )
        .expect("parse private network profile");
        for runtime in [None, Some(RuntimeFileKind::Native)] {
            file.runtime = runtime;
            assert!(matches!(
                LauncherSettings::resolve(None, None, None, None, false, &file),
                Err(SettingsError::PrivateNetworkRequiresBubblewrap),
            ));
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
                    source: BindMountFileSource::Path(WORKSPACE_SOURCE.to_owned()),
                    destination: Some(PathBuf::from("/workspace")),
                    access: BindAccessFileMode::Rw,
                    required: true,
                },
                BindMountFileConfig {
                    source: BindMountFileSource::Path(host_source.to_string_lossy().into_owned()),
                    destination: Some(PathBuf::from("/home/source")),
                    access: BindAccessFileMode::Ro,
                    required: true,
                },
            ],
            devices: Vec::new(),
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
    fn no_worktree_replaces_workspace_mappings_without_dropping_host_permissions() {
        for destinations in [vec![], vec!["/other"], vec!["/other", "/workspace"]] {
            let mut file = file_config();
            file.runtime = Some(RuntimeFileKind::Bubblewrap);
            let selected = file.launcher.profiles.get_mut("pi").expect("profile");
            selected.bind_mounts = destinations
                .into_iter()
                .map(|destination| BindMountFileConfig {
                    source: BindMountFileSource::Path(WORKSPACE_SOURCE.to_owned()),
                    destination: Some(PathBuf::from(destination)),
                    access: BindAccessFileMode::Ro,
                    required: true,
                })
                .collect();
            selected.bind_mounts.push(BindMountFileConfig {
                source: BindMountFileSource::Path("/tmp".to_owned()),
                destination: Some(PathBuf::from("/permitted")),
                access: BindAccessFileMode::Ro,
                required: true,
            });

            file.override_launch_mode(None, true)
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

        assert!(
            matches!(missing_profile, SettingsError::UnknownProfile(name) if name == "default")
        );
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
                devices: Vec::new(),
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
                    source: BindMountFileSource::Path("relative".to_owned()),
                    destination: None,
                    access: BindAccessFileMode::Ro,
                    required: true,
                }],
                devices: Vec::new(),
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
