//! Declarative launcher intent, host resolution, and daemon configuration.

use std::collections::{BTreeMap, BTreeSet, HashSet};
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
    NetworkMode, PortForward, ResourceLimits, RuntimeKind, RuntimePolicy, WorkspaceName,
    valid_agent_label,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
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
    /// Transient launch context, never part of the declarative policy.
    #[serde(skip)]
    no_worktree: bool,
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

    /// Apply the CLI network policy before normal runtime validation.
    pub fn override_network(
        &mut self,
        profile_override: Option<&str>,
        network: Option<NetworkFileMode>,
    ) -> Result<(), SettingsError> {
        let Some(network) = network else {
            return Ok(());
        };
        let profile = profile_override
            .or(self.launcher.profile.as_deref())
            .unwrap_or("default");
        validate_profile_name(profile)?;
        let configured = self
            .launcher
            .profiles
            .get_mut(profile)
            .ok_or_else(|| SettingsError::UnknownProfile(profile.to_owned()))?;
        configured.network = Some(network);
        Ok(())
    }

    /// Apply CLI mappings before validating the final effective host ports.
    pub fn override_port_forwards(
        &mut self,
        profile_override: Option<&str>,
        forwards: Vec<PortForward>,
    ) -> Result<(), SettingsError> {
        validate_port_forward_layer(&forwards)?;
        if forwards.is_empty() {
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
        configured.port_forwards =
            merge_keyed_entries(&configured.port_forwards, Some(forwards), |forward| {
                Ok(forward.room_port)
            })?;
        Ok(())
    }

    /// Select the exact directory without changing declarative profile policy.
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
        self.launcher
            .profiles
            .get(profile)
            .ok_or_else(|| SettingsError::UnknownProfile(profile.to_owned()))?;
        self.no_worktree = true;
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
    pub herdr_agent: Option<String>,
    pub project_environment: Option<bool>,
    pub network: Option<NetworkFileMode>,
    pub port_forwards: Vec<PortForward>,
    pub identity: Option<IdentityFileKind>,
    pub environment: Vec<String>,
    pub set_environment: BTreeMap<String, String>,
    pub bind_mounts: Vec<BindMountFileConfig>,
    // Retained base entries form a prefix; host aliases may still be overridden by the child.
    inherited_bind_mount_count: usize,
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
    herdr_agent: Option<String>,
    project_environment: Option<bool>,
    network: Option<NetworkFileMode>,
    port_forwards: Option<Vec<PortForward>>,
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
            herdr_agent: raw.herdr_agent,
            project_environment: raw.project_environment,
            network: raw.network,
            port_forwards: raw.port_forwards.unwrap_or_default(),
            identity: raw.identity,
            environment: raw.environment.unwrap_or_default(),
            set_environment: raw.set_environment.unwrap_or_default(),
            bind_mounts: raw.bind_mounts.unwrap_or_default(),
            inherited_bind_mount_count: 0,
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
        if let Some(forwards) = &self.port_forwards {
            validate_port_forward_layer(forwards)?;
        }
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
        let child_mount_count = self.bind_mounts.as_ref().map(Vec::len);
        let bind_mounts = merge_bind_mounts(&base.bind_mounts, self.bind_mounts)?;
        let inherited_bind_mount_count = match child_mount_count {
            None => bind_mounts.len(),
            Some(count) => bind_mounts.len() - count,
        };
        Ok(ProfileFileConfig {
            command: self.command.or_else(|| base.command.clone()),
            herdr_agent: self.herdr_agent.or_else(|| base.herdr_agent.clone()),
            project_environment: self.project_environment.or(base.project_environment),
            network: self.network.or(base.network),
            port_forwards: merge_keyed_entries(
                &base.port_forwards,
                self.port_forwards,
                |forward| Ok(forward.room_port),
            )?,
            identity: self.identity.or(base.identity),
            environment,
            set_environment,
            bind_mounts,
            inherited_bind_mount_count,
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

fn validate_port_forward_layer(forwards: &[PortForward]) -> Result<(), SettingsError> {
    let mut rooms = BTreeSet::new();
    for forward in forwards {
        if forward.host_port == 0 || forward.room_port == 0 {
            return Err(SettingsError::InvalidPortForward);
        }
        if !rooms.insert(forward.room_port) {
            return Err(SettingsError::DuplicateRoomPort(forward.room_port));
        }
    }
    Ok(())
}

fn validate_port_forward_policy(
    forwards: &[PortForward],
    kind: RuntimeKind,
    network: NetworkMode,
) -> Result<(), SettingsError> {
    validate_port_forward_layer(forwards)?;
    if !forwards.is_empty() && (kind != RuntimeKind::Bubblewrap || network != NetworkMode::Private)
    {
        return Err(SettingsError::PortForwardsRequirePrivateBubblewrap);
    }
    let mut host_ports = BTreeSet::new();
    for forward in forwards {
        if !host_ports.insert(forward.host_port) {
            return Err(SettingsError::DuplicateHostPort(forward.host_port));
        }
    }
    Ok(())
}

fn fingerprint_port_forwards(policy: &mut PolicyFingerprint, forwards: &[PortForward]) {
    // Preserve fingerprints produced before publishing existed when no ports are exposed.
    if !forwards.is_empty() {
        policy.bytes(b"port_forwards");
        policy.number(forwards.len() as u64);
        for forward in forwards {
            policy.number(u64::from(forward.room_port));
            policy.number(u64::from(forward.host_port));
        }
    }
}

pub fn parse_port_forward(value: &str) -> Result<PortForward, String> {
    let invalid = || "publish must use HOST_PORT:ROOM_PORT with ports in 1..=65535".to_owned();
    let (host, room) = value.split_once(':').ok_or_else(invalid)?;
    let port = |text: &str| -> Result<u16, String> {
        if text.is_empty() || text.len() > 5 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        text.parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(invalid)
    };
    Ok(PortForward {
        host_port: port(host)?,
        room_port: port(room)?,
    })
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

fn is_workspace_mount(mount: &BindMountFileConfig) -> bool {
    matches!(&mount.source, BindMountFileSource::Path(path) if path == WORKSPACE_SOURCE)
}

fn merge_bind_mounts(
    base: &[BindMountFileConfig],
    child: Option<Vec<BindMountFileConfig>>,
) -> Result<Vec<BindMountFileConfig>, SettingsError> {
    if let Some(child) = &child
        && child
            .iter()
            .filter(|mount| is_workspace_mount(mount))
            .count()
            > 1
    {
        return Err(SettingsError::DuplicateWorkspaceMount);
    }
    let Some(child) = child else {
        return Ok(base.to_vec());
    };
    if child.is_empty() || base.is_empty() {
        return Ok(child);
    }
    let replaces_workspace = child.iter().any(is_workspace_mount);
    let child_keys = child
        .iter()
        .map(bind_mount_key)
        .collect::<Result<Vec<_>, _>>()?;
    let mut merged = Vec::with_capacity(base.len() + child.len());
    for mount in base {
        if !(replaces_workspace && is_workspace_mount(mount)
            || child_keys.contains(&bind_mount_key(mount)?))
        {
            merged.push(mount.clone());
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
        if destination.as_os_str() == "/@workspace" && !is_workspace_mount(mount) {
            return Err(SettingsError::InvalidBindDestination(destination.clone()));
        }
        return normalize_declarative_destination(destination.clone())
            .map(BindMountKey::Destination);
    }
    match &mount.source {
        BindMountFileSource::Path(path) if path == WORKSPACE_SOURCE => {
            Err(SettingsError::MissingWorkspaceDestination)
        }
        BindMountFileSource::Path(path) => {
            validate_declarative_source(path)?;
            normalize_declarative_destination(PathBuf::from(path)).map(BindMountKey::Destination)
        }
        BindMountFileSource::Executable(name) => Ok(BindMountKey::Executable(name.clone())),
    }
}

fn resolved_bind_mount_key(mount: &BindMountFileConfig) -> Result<BindMountKey, SettingsError> {
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
    validate_port_forward_layer(&base.port_forwards)?;
    if let Some(command) = &base.command {
        parse_command(command)?;
    }
    if let Some(label) = &base.herdr_agent {
        validate_agent_label(label)?;
    }
    validate_profile_declarations(base)?;
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

fn validate_profile_declarations(base: &ProfileFileConfig) -> Result<(), SettingsError> {
    validate_launch_declarations(base, false)
}

fn validate_launch_declarations(
    base: &ProfileFileConfig,
    no_worktree: bool,
) -> Result<(), SettingsError> {
    validate_environment_allowlist(&base.environment)?;
    for name in base.set_environment.keys() {
        validate_environment_name(name)?;
    }
    let mut destinations = Vec::with_capacity(base.bind_mounts.len() + 1);
    let workspace_mounts = base
        .bind_mounts
        .iter()
        .filter(|mount| is_workspace_mount(mount))
        .count();
    if workspace_mounts > 1 {
        return Err(SettingsError::DuplicateWorkspaceMount);
    }
    if no_worktree && workspace_mounts == 0 {
        destinations.push(BindMountKey::Destination(PathBuf::from("/workspace")));
    }
    for mount in &base.bind_mounts {
        match &mount.source {
            BindMountFileSource::Path(path) if path == WORKSPACE_SOURCE => {
                if !mount.required {
                    return Err(SettingsError::OptionalWorkspaceMount);
                }
            }
            BindMountFileSource::Path(path) => {
                validate_declarative_source(path)?;
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
    for device in &base.devices {
        match &device.selector {
            DeviceSelector::Path(path) => validate_device_path(path)?,
            DeviceSelector::Class(class) => validate_device_class(class)?,
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, clap::ValueEnum)]
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

/// Complete launch intent, independent of the host on which it will run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveLauncherConfig {
    pub socket: Option<PathBuf>,
    pub name: Option<WorkspaceName>,
    pub profile: String,
    pub agent_label: String,
    pub command: ForegroundCommand,
    pub runtime: EffectiveRuntimeConfig,
    pub project_environment: bool,
    pub environment_allowlist: Vec<String>,
    pub identity: Option<IdentityFileKind>,
    pub limits: ResourceLimits,
    pub verbose: bool,
    pub launch_mounts: Vec<LaunchMount>,
    /// Exact-directory routing context; excluded from the policy fingerprint.
    no_worktree: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveRuntimeConfig {
    pub kind: RuntimeKind,
    pub network: NetworkMode,
    pub port_forwards: Vec<PortForward>,
    inherited_bind_mount_count: usize,
    pub bind_mounts: Vec<BindMountFileConfig>,
    pub devices: Vec<DeviceFileConfig>,
    pub set_environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchMount {
    pub source: PathBuf,
    /// None means the read-only shorthand's source basename.
    pub destination: Option<PathBuf>,
    pub access: BindAccess,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedLauncherConfig {
    pub socket: PathBuf,
    pub name: Option<WorkspaceName>,
    pub profile: String,
    pub agent_label: String,
    pub command: ForegroundCommand,
    pub runtime: RuntimePolicy,
    pub project_environment: bool,
    pub environment_allowlist: Vec<String>,
    pub identity: Option<IdentityFileKind>,
    pub limits: ResourceLimits,
    pub verbose: bool,
    pub mount_arguments: Vec<String>,
    /// Frozen invoking-directory basename, only for a symbolic workspace destination.
    pub workspace_directory: Option<String>,
}

impl EffectiveLauncherConfig {
    pub fn merge(
        socket_override: Option<PathBuf>,
        name_override: Option<String>,
        profile_override: Option<String>,
        command_override: Option<String>,
        herdr_agent_override: Option<String>,
        verbose_override: bool,
        file: &FileConfig,
    ) -> Result<Self, SettingsError> {
        let socket = socket_override.or_else(|| file.socket.clone());
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
        let agent_label = resolve_agent_label(
            &command,
            herdr_agent_override.or_else(|| profile_config.herdr_agent.clone()),
        )?;
        let kind = file.runtime.unwrap_or_default().into();
        let network = resolve_network(kind, profile_config.network)?;
        validate_port_forward_policy(&profile_config.port_forwards, kind, network)?;
        let no_worktree = file.no_worktree && kind == RuntimeKind::Bubblewrap;
        validate_launch_declarations(profile_config, no_worktree)?;
        if kind == RuntimeKind::Bubblewrap
            && !no_worktree
            && !profile_config.bind_mounts.iter().any(|mount|
                matches!(&mount.source, BindMountFileSource::Path(path) if path == WORKSPACE_SOURCE))
        {
            return Err(SettingsError::MissingWorkspaceMount);
        }
        if kind != RuntimeKind::Bubblewrap && !profile_config.devices.is_empty() {
            return Err(SettingsError::DevicesRequireBubblewrap);
        }
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
        Ok(Self {
            socket,
            name,
            profile,
            agent_label,
            command,
            runtime: EffectiveRuntimeConfig {
                kind,
                network,
                port_forwards: {
                    let mut forwards = profile_config.port_forwards.clone();
                    forwards.sort_unstable_by_key(|forward| forward.room_port);
                    forwards
                },
                bind_mounts: profile_config.bind_mounts.clone(),
                devices: profile_config.devices.clone(),
                inherited_bind_mount_count: profile_config.inherited_bind_mount_count,
                set_environment: profile_config.set_environment.clone(),
            },
            project_environment: profile_config.project_environment.unwrap_or(false),
            environment_allowlist: profile_config.environment.clone(),
            identity,
            limits,
            verbose: verbose_override || file.launcher.verbose.unwrap_or(false),
            launch_mounts: Vec::new(),
            no_worktree,
        })
    }

    /// Hash only declarative launch policy, before reading host paths or values.
    ///
    /// Version 1 uses explicit field tags and length-prefixed bytes, fixed-width
    /// big-endian integers, and presence markers. Collection order is retained;
    /// literal environment assignments are ordered by their `BTreeMap` keys.
    pub fn fingerprint(&self) -> Result<String, Box<dyn Error>> {
        use std::fmt::Write as _;
        let mut policy = PolicyFingerprint(Sha256::new());
        policy.bytes(b"runroom-launch-policy-v1");
        policy.bytes(b"runtime");
        policy.bytes(match self.runtime.kind {
            RuntimeKind::Native => b"native",
            RuntimeKind::Bubblewrap => b"bubblewrap",
        });
        policy.bytes(b"network");
        policy.bytes(match self.runtime.network {
            NetworkMode::None => b"none",
            NetworkMode::Host => b"host",
            NetworkMode::Private => b"private",
        });
        policy.bytes(b"bind_mounts");
        policy.number(self.runtime.bind_mounts.len() as u64);
        for (index, mount) in self.runtime.bind_mounts.iter().enumerate() {
            policy.flag(index < self.runtime.inherited_bind_mount_count);
            match &mount.source {
                BindMountFileSource::Path(path) => {
                    policy.bytes(b"path");
                    policy.bytes(path.as_bytes());
                }
                BindMountFileSource::Executable(name) => {
                    policy.bytes(b"executable");
                    policy.bytes(name.as_bytes());
                }
            }
            policy.flag(mount.destination.is_some());
            if let Some(destination) = &mount.destination {
                policy.bytes(destination.as_os_str().as_bytes());
            }
            policy.bytes(match mount.access {
                BindAccessFileMode::Ro => b"ro",
                BindAccessFileMode::Rw => b"rw",
            });
            policy.flag(mount.required);
        }
        policy.bytes(b"devices");
        policy.number(self.runtime.devices.len() as u64);
        for device in &self.runtime.devices {
            match &device.selector {
                DeviceSelector::Path(path) => {
                    policy.bytes(b"path");
                    policy.bytes(path.as_os_str().as_bytes());
                }
                DeviceSelector::Class(class) => {
                    policy.bytes(b"class");
                    policy.bytes(class.as_bytes());
                }
            }
            policy.flag(device.required);
        }
        policy.bytes(b"environment_names");
        policy.number(self.environment_allowlist.len() as u64);
        for name in &self.environment_allowlist {
            policy.bytes(name.as_bytes());
        }
        policy.bytes(b"literal_environment");
        policy.number(self.runtime.set_environment.len() as u64);
        for (name, value) in &self.runtime.set_environment {
            policy.bytes(name.as_bytes());
            policy.bytes(value.as_bytes());
        }
        policy.bytes(b"project_environment");
        policy.flag(self.project_environment);
        policy.bytes(b"identity");
        policy.bytes(match self.identity {
            None => b"none",
            Some(IdentityFileKind::Herdr) => b"herdr",
        });
        policy.bytes(b"memory_max_bytes");
        policy.optional_number(self.limits.memory_max_bytes);
        policy.bytes(b"tasks_max");
        policy.optional_number(self.limits.tasks_max);
        policy.bytes(b"cpu_quota_basis_points");
        policy.optional_number(self.limits.cpu_quota_basis_points.map(u64::from));
        policy.bytes(b"cpu_cores");
        policy.flag(self.limits.cpu_cores.is_some());
        if let Some(cores) = &self.limits.cpu_cores {
            policy.number(cores.len() as u64);
            for core in cores {
                policy.number(u64::from(*core));
            }
        }
        policy.bytes(b"cpu_count");
        policy.optional_number(self.limits.cpu_count.map(u64::from));
        policy.bytes(b"agent_label");
        policy.bytes(self.agent_label.as_bytes());
        fingerprint_port_forwards(&mut policy, &self.runtime.port_forwards);

        let mut fingerprint = String::with_capacity(67);
        fingerprint.push_str("v1:");
        for byte in policy.0.finalize() {
            write!(fingerprint, "{byte:02x}")?;
        }
        Ok(fingerprint)
    }

    pub fn with_launch_mounts(
        mut self,
        read_only: Vec<PathBuf>,
        specifications: Vec<String>,
    ) -> Result<Self, Box<dyn Error>> {
        if read_only.is_empty() && specifications.is_empty() {
            return Ok(self);
        }
        if self.runtime.kind != RuntimeKind::Bubblewrap {
            return Err("launch mount flags require the bubblewrap runtime".into());
        }
        if self.launch_mounts.len() + read_only.len() + specifications.len() > 128 {
            return Err("at most 128 launch mounts are allowed".into());
        }
        for source in read_only {
            if source.file_name().is_none() {
                return Err(
                    "read-only mount source needs a basename; use --mount SOURCE@DEST:ro".into(),
                );
            }
            self.launch_mounts.push(LaunchMount {
                source,
                destination: None,
                access: BindAccess::ReadOnly,
            });
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
            self.launch_mounts.push(LaunchMount {
                source: PathBuf::from(source),
                destination: Some(normalize_declarative_destination(PathBuf::from(
                    destination,
                ))?),
                access,
            });
        }
        let mut destinations = self
            .runtime
            .bind_mounts
            .iter()
            .map(bind_mount_key)
            .collect::<Result<Vec<_>, _>>()?;
        if self.no_worktree && !self.runtime.bind_mounts.iter().any(is_workspace_mount) {
            destinations.push(BindMountKey::Destination(PathBuf::from("/workspace")));
        }
        for mount in &self.launch_mounts {
            let destination = match &mount.destination {
                Some(destination) => destination.clone(),
                None if mount.source == Path::new("~") => continue,
                None => Path::new("/").join(mount.source.file_name().ok_or(
                    "read-only mount source needs a basename; use --mount SOURCE@DEST:ro",
                )?),
            };
            let destination = normalize_declarative_destination(destination)?;
            let text = destination
                .to_str()
                .ok_or("launch mount destination must be valid UTF-8")?;
            if text.contains('@') {
                return Err("launch mount destination cannot contain @".into());
            }
            let key = BindMountKey::Destination(destination.clone());
            if destinations.contains(&key) {
                return Err(SettingsError::DuplicateBindDestination(destination).into());
            }
            destinations.push(key);
        }
        Ok(self)
    }

    pub fn resolve(
        self,
        current_directory: &Path,
        workspace_directory: Option<&str>,
    ) -> Result<ResolvedLauncherConfig, Box<dyn Error>> {
        let kind = self.runtime.kind;
        let mut profile_config = ProfileFileConfig {
            environment: self.environment_allowlist,
            set_environment: self.runtime.set_environment,
            bind_mounts: self.runtime.bind_mounts,
            devices: self.runtime.devices,
            inherited_bind_mount_count: self.runtime.inherited_bind_mount_count,
            ..ProfileFileConfig::default()
        };
        if self.no_worktree {
            rewrite_workspace_binding(&mut profile_config);
        }
        let workspace_directory = expand_workspace_destination(
            &mut profile_config,
            current_directory,
            workspace_directory,
        )?;
        if let Some(directory) = &workspace_directory {
            let workspace_destination = Path::new("/").join(directory);
            for mount in &self.launch_mounts {
                let destination = if let Some(destination) = &mount.destination {
                    normalize_destination(destination.clone())?
                } else {
                    let source = expand_user_path(mount.source.clone())?;
                    Path::new("/").join(source.file_name().ok_or(
                        "read-only mount source needs a basename; use --mount SOURCE@DEST:ro",
                    )?)
                };
                if destination == workspace_destination {
                    return Err(SettingsError::DuplicateBindDestination(destination).into());
                }
            }
        }
        let socket = match self.socket {
            Some(socket) => expand_user_path(socket)?,
            None => default_socket_path().map_err(SettingsError::DefaultSocket)?,
        };
        let socket = current_directory.join(socket);
        let home = match kind {
            RuntimeKind::Native => None,
            RuntimeKind::Bubblewrap => Some(validate_bubblewrap_host()?),
        };
        let bind_mounts = resolve_bind_mounts(&profile_config, kind)?;
        let devices = resolve_devices(&profile_config, kind)?;
        let mut environment = resolve_environment(&profile_config)?;
        if kind == RuntimeKind::Bubblewrap
            && profile_config
                .bind_mounts
                .iter()
                .any(|mount| matches!(mount.source, BindMountFileSource::Executable(_)))
        {
            prepend_executable_path(&mut environment);
        }
        let mut runtime = RuntimePolicy {
            kind,
            network: self.runtime.network,
            port_forwards: self.runtime.port_forwards,
            bind_mounts,
            devices,
            environment,
            home,
        };
        let mut mount_arguments = Vec::with_capacity(self.launch_mounts.len());
        for mount in self.launch_mounts {
            let source = resolve_launch_source(&mount.source, current_directory)?;
            let destination = if let Some(destination) = mount.destination {
                destination
            } else {
                let expanded = expand_user_path(mount.source)?;
                let name = expanded
                    .file_name()
                    .ok_or("read-only mount source needs a basename; use --mount SOURCE@DEST:ro")?;
                Path::new("/").join(name)
            };
            append_launch_mount(
                &mut runtime,
                source,
                destination,
                mount.access,
                &mut mount_arguments,
            )?;
        }
        debug!(profile = self.profile, runtime = ?kind, "resolved launcher config");
        Ok(ResolvedLauncherConfig {
            socket,
            name: self.name,
            profile: self.profile,
            agent_label: self.agent_label,
            command: self.command,
            runtime,
            project_environment: self.project_environment,
            environment_allowlist: profile_config.environment,
            identity: self.identity,
            limits: self.limits,
            verbose: self.verbose,
            mount_arguments,
            workspace_directory,
        })
    }
}

/// Streaming, unambiguous encoding; no host resolution or serialization buffer.
struct PolicyFingerprint(Sha256);

impl PolicyFingerprint {
    fn bytes(&mut self, value: &[u8]) {
        self.number(value.len() as u64);
        self.0.update(value);
    }

    fn number(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    fn flag(&mut self, value: bool) {
        self.0.update([u8::from(value)]);
    }

    fn optional_number(&mut self, value: Option<u64>) {
        self.flag(value.is_some());
        if let Some(value) = value {
            self.number(value);
        }
    }
}

/// Resolve exact-directory routing without altering the saved declared policy.
fn rewrite_workspace_binding(profile: &mut ProfileFileConfig) {
    if let Some(mount) = profile
        .bind_mounts
        .iter_mut()
        .find(|mount| is_workspace_mount(mount))
    {
        mount.access = BindAccessFileMode::Rw;
        mount.required = true;
    } else {
        profile.bind_mounts.insert(
            0,
            BindMountFileConfig {
                source: BindMountFileSource::Path(WORKSPACE_SOURCE.to_owned()),
                destination: Some(PathBuf::from("/workspace")),
                access: BindAccessFileMode::Rw,
                required: true,
            },
        );
        profile.inherited_bind_mount_count += 1;
    }
}

fn validate_workspace_directory(directory: &str) -> Result<(), SettingsError> {
    if directory.is_empty() || matches!(directory, "." | "..") || directory.contains(['/', '\0']) {
        return Err(SettingsError::InvalidWorkspaceDirectory(PathBuf::from(
            directory,
        )));
    }
    Ok(())
}

fn expand_workspace_destination(
    profile: &mut ProfileFileConfig,
    current_directory: &Path,
    frozen_directory: Option<&str>,
) -> Result<Option<String>, SettingsError> {
    if let Some(directory) = frozen_directory {
        validate_workspace_directory(directory)?;
    }
    let Some(index) = profile.bind_mounts.iter().position(|mount| {
        is_workspace_mount(mount)
            && mount
                .destination
                .as_ref()
                .is_some_and(|path| path.as_os_str() == "/@workspace")
    }) else {
        return Ok(None);
    };
    let directory = frozen_directory
        .or_else(|| current_directory.file_name().and_then(|name| name.to_str()))
        .ok_or_else(|| SettingsError::InvalidWorkspaceDirectory(current_directory.to_owned()))?;
    validate_workspace_directory(directory)?;
    let destination = normalize_destination(Path::new("/").join(directory))?;
    // Expansion is resolution context, not an inheritance override: a grant at
    // the expanded path must fail rather than silently revoke another source.
    for (other_index, mount) in profile.bind_mounts.iter().enumerate() {
        if other_index != index
            && matches!(resolved_bind_mount_key(mount)?, BindMountKey::Destination(path) if path == destination)
        {
            return Err(SettingsError::DuplicateBindDestination(destination));
        }
    }
    profile.bind_mounts[index].destination = Some(destination);
    Ok(Some(directory.to_owned()))
}

fn validate_agent_label(label: &str) -> Result<(), SettingsError> {
    if valid_agent_label(label) {
        Ok(())
    } else {
        Err(SettingsError::InvalidAgentLabel(label.to_owned()))
    }
}

fn resolve_agent_label(
    command: &ForegroundCommand,
    override_label: Option<String>,
) -> Result<String, SettingsError> {
    let label = override_label
        .or_else(|| {
            command
                .executable
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| SettingsError::InvalidAgentLabel(String::new()))?;
    validate_agent_label(&label)?;
    Ok(label)
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

pub fn validate_all_profiles(
    file: &FileConfig,
) -> Result<Vec<EffectiveLauncherConfig>, SettingsError> {
    if file.launcher.profiles.is_empty() {
        return Err(SettingsError::NoProfiles);
    }
    file.launcher
        .profiles
        .keys()
        .map(|profile| {
            EffectiveLauncherConfig::merge(
                None,
                None,
                Some(profile.clone()),
                None,
                None,
                false,
                file,
            )
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
    // Resolve layer keys before touching sources: an absent optional child still
    // revokes its base grant, and an overridden required base need not exist.
    let child_keys = if profile.inherited_bind_mount_count > 0 {
        profile
            .bind_mounts
            .iter()
            .skip(profile.inherited_bind_mount_count)
            .map(resolved_bind_mount_key)
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    for (index, configured) in profile.bind_mounts.iter().enumerate() {
        if index < profile.inherited_bind_mount_count
            && !child_keys.is_empty()
            && child_keys.contains(&resolved_bind_mount_key(configured)?)
        {
            continue;
        }
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
    normalize_declarative_destination(expand_user_path(destination)?)
}

fn validate_declarative_source(source: &str) -> Result<(), SettingsError> {
    let path = Path::new(source);
    if path.is_absolute() || path.starts_with("~") {
        Ok(())
    } else {
        Err(SettingsError::RelativeBindSource(path.to_owned()))
    }
}

fn normalize_declarative_destination(destination: PathBuf) -> Result<PathBuf, SettingsError> {
    // HOME remains symbolic until host resolution.
    if let Ok(relative) = destination.strip_prefix("~") {
        if destination.as_os_str().as_bytes().contains(&0)
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(SettingsError::InvalidBindDestination(destination));
        }
        return Ok(destination);
    }
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

/// Existing selected configuration file, using the same lookup as `load_default`.
pub fn selected_config_path() -> Option<PathBuf> {
    default_config_path().filter(|path| path.is_file())
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
    InvalidWorkspaceDirectory(PathBuf),
    NoProfiles,
    AbstractProfile,
    InvalidProfileName,
    InvalidAgentLabel(String),
    UnknownProfile(String),
    MissingCommand(String),
    EmptyCommand,
    InvalidCommand { source: shell_words::ParseError },
    InvalidEnvironmentName(String),
    DuplicateEnvironmentName(String),
    IdentityRequiresBubblewrap,
    PrivateNetworkRequiresBubblewrap,
    InvalidPortForward,
    DuplicateRoomPort(u16),
    DuplicateHostPort(u16),
    PortForwardsRequirePrivateBubblewrap,
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
            Self::InvalidPortForward => formatter.write_str("published ports must be in 1..=65535"),
            Self::DuplicateRoomPort(port) => write!(formatter, "duplicate published room port in one layer: {port}"),
            Self::DuplicateHostPort(port) => write!(formatter, "duplicate published host port: {port}"),
            Self::PortForwardsRequirePrivateBubblewrap => formatter.write_str("port publishing requires the Bubblewrap runtime and network = \"private\""),
            Self::DefaultSocket(source) => source.fmt(formatter),
            Self::InvalidWorkspaceName => formatter.write_str("workspace name must not be empty"),
            Self::InvalidWorkspaceDirectory(path) => write!(
                formatter,
                "invalid workspace directory basename {}: must be one nonempty UTF-8 directory component, not . or ..",
                path.display(),
            ),
            Self::AbstractProfile => {
                formatter.write_str("launcher profile 'base' is abstract and cannot be selected")
            }
            Self::InvalidProfileName => formatter.write_str("launcher profile must not be empty"),
            Self::InvalidAgentLabel(label) => write!(
                formatter,
                "invalid Herdr agent label {label:?}: must contain 1..=512 bytes and no control characters",
            ),
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
            | Self::InvalidAgentLabel(_)
            | Self::UnknownProfile(_)
            | Self::NoProfiles
            | Self::MissingCommand(_)
            | Self::EmptyCommand
            | Self::InvalidEnvironmentName(_)
            | Self::DuplicateEnvironmentName(_)
            | Self::IdentityRequiresBubblewrap
            | Self::InvalidWorkspaceDirectory(_)
            | Self::PrivateNetworkRequiresBubblewrap
            | Self::InvalidPortForward
            | Self::DuplicateRoomPort(_)
            | Self::DuplicateHostPort(_)
            | Self::PortForwardsRequirePrivateBubblewrap
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
            herdr_agent: None,
            project_environment: None,
            network: Some(NetworkFileMode::Host),
            port_forwards: Vec::new(),
            identity: None,
            environment: Vec::new(),
            set_environment: BTreeMap::new(),
            bind_mounts: Vec::new(),
            inherited_bind_mount_count: 0,
            devices: Vec::new(),
            memory_max_bytes: None,
            tasks_max: None,
            cpu_quota_basis_points: None,
            cpu_cores: None,
            cpu_count: None,
        }
    }

    fn publishing_file(base: &str, child: &str) -> FileConfig {
        toml::from_str(&format!(
            "runtime='bubblewrap'\n[launcher.base]\ncommand='pi'\nnetwork='private'\n\
             bind_mounts=[{{source='@workspace',destination='/workspace',access='rw'}}]\n\
             {base}\n[launcher.profiles.default]\n{child}"
        ))
        .unwrap()
    }

    fn publishing_policy(file: &FileConfig) -> Result<EffectiveLauncherConfig, SettingsError> {
        EffectiveLauncherConfig::merge(None, None, None, None, None, false, file)
    }

    #[test]
    fn published_ports_merge_clear_and_cli_repair_collisions() {
        let mut file = publishing_file(
            "port_forwards=[{host_port=23001,room_port=3000}]",
            "port_forwards=[{host_port=23001,room_port=4000}]",
        );
        assert!(matches!(
            publishing_policy(&file),
            Err(SettingsError::DuplicateHostPort(23001))
        ));
        file.override_port_forwards(None, vec![parse_port_forward("23002:3000").unwrap()])
            .unwrap();
        assert_eq!(
            publishing_policy(&file).unwrap().runtime.port_forwards,
            vec![
                PortForward {
                    host_port: 23002,
                    room_port: 3000
                },
                PortForward {
                    host_port: 23001,
                    room_port: 4000
                },
            ]
        );
        assert_eq!(
            publishing_policy(&publishing_file(
                "port_forwards=[{host_port=23001,room_port=3000}]",
                "port_forwards=[]",
            ))
            .unwrap()
            .runtime
            .port_forwards,
            [] as [PortForward; 0]
        );
        assert!(
            file.override_port_forwards(
                None,
                vec![
                    parse_port_forward("23003:3000").unwrap(),
                    parse_port_forward("23004:3000").unwrap(),
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn published_ports_validate_layers_and_runtime() {
        for layer in ["launcher.base", "launcher.profiles.default"] {
            for entries in [
                "[{host_port=0,room_port=3000}]",
                "[{host_port=65536,room_port=3000}]",
                "[{host_port=1,room_port=3000},{host_port=2,room_port=3000}]",
                "[{host_port=1,room_port=3000,udp=true}]",
            ] {
                assert!(
                    toml::from_str::<FileConfig>(&format!("[{layer}]\nport_forwards={entries}"))
                        .is_err()
                );
            }
        }
        let mut file = publishing_file("", "port_forwards=[{host_port=23001,room_port=3000}]");
        for network in [NetworkFileMode::Host, NetworkFileMode::None] {
            file.override_network(None, Some(network)).unwrap();
            assert!(matches!(
                publishing_policy(&file),
                Err(SettingsError::PortForwardsRequirePrivateBubblewrap)
            ));
        }
        file.runtime = Some(RuntimeFileKind::Native);
        assert!(matches!(
            publishing_policy(&file),
            Err(SettingsError::PortForwardsRequirePrivateBubblewrap)
        ));
    }

    #[test]
    fn published_ports_fingerprint_tracks_sorted_effective_policy() {
        let hash = |entries: &str| {
            publishing_policy(&publishing_file("", entries))
                .unwrap()
                .fingerprint()
                .unwrap()
        };
        assert_eq!(hash(""), hash("port_forwards=[]"));
        let first = hash(
            "port_forwards=[{host_port=23001,room_port=3000},{host_port=23002,room_port=4000}]",
        );
        assert_eq!(
            first,
            hash(
                "port_forwards=[{host_port=23002,room_port=4000},{host_port=23001,room_port=3000}]"
            )
        );
        assert_ne!(
            first,
            hash(
                "port_forwards=[{host_port=23003,room_port=3000},{host_port=23002,room_port=4000}]"
            )
        );
        assert_ne!(first, hash(""));
    }

    #[test]
    fn agent_label_defaults_to_selected_command_basename_not_profile() {
        let file: FileConfig = toml::from_str(
            r#"
socket = "/unused.sock"
[launcher]
profile = "coding"
[launcher.profiles.coding]
command = "/opt/agents/omp --model configured"
"#,
        )
        .unwrap();
        let settings =
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
        assert_eq!(settings.profile, "coding");
        assert_eq!(settings.agent_label, "omp");
        assert_eq!(settings.command.executable, Path::new("/opt/agents/omp"));
        assert_eq!(
            settings.command.arguments,
            ["--model", "configured"].map(OsString::from)
        );

        let overridden = EffectiveLauncherConfig::merge(
            None,
            None,
            None,
            Some("/other/bin/pi --model cli".to_owned()),
            None,
            false,
            &file,
        )
        .unwrap();
        assert_eq!(overridden.profile, "coding");
        assert_eq!(overridden.agent_label, "pi");
        assert_eq!(overridden.command.executable, Path::new("/other/bin/pi"));
    }

    #[test]
    fn agent_label_inherits_base_and_yields_to_profile_and_replay_overrides() {
        let file: FileConfig = toml::from_str(
            r#"
socket = "/unused.sock"
[launcher]
profile = "coding"
[launcher.base]
command = "omp"
herdr_agent = "rr:omp"
[launcher.profiles.coding]
[launcher.profiles.custom]
herdr_agent = "team:omp"
"#,
        )
        .unwrap();
        let inherited =
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
        assert_eq!(inherited.agent_label, "rr:omp");
        assert_eq!(inherited.profile, "coding");
        assert_eq!(inherited.command.executable, Path::new("omp"));

        let custom = EffectiveLauncherConfig::merge(
            None,
            None,
            Some("custom".to_owned()),
            Some("pi".to_owned()),
            None,
            false,
            &file,
        )
        .unwrap();
        assert_eq!(custom.agent_label, "team:omp");
        assert_eq!(custom.profile, "custom");
        assert_eq!(custom.command.executable, Path::new("pi"));

        let frozen = EffectiveLauncherConfig::merge(
            None,
            None,
            None,
            None,
            Some("omp".to_owned()),
            false,
            &file,
        )
        .unwrap();
        assert_eq!(frozen.agent_label, "omp");
        assert_eq!(frozen.profile, "coding");
    }

    #[test]
    fn agent_label_rejects_invalid_config_and_replay_labels() {
        let mut file: FileConfig =
            toml::from_str("socket = '/unused.sock'\n[launcher.profiles.default]\ncommand = 'omp'")
                .unwrap();
        for label in [
            String::new(),
            "x".repeat(513),
            "omp\n".to_owned(),
            "rr:\0omp".to_owned(),
            "rr:\u{0085}omp".to_owned(),
        ] {
            file.launcher
                .profiles
                .get_mut("default")
                .unwrap()
                .herdr_agent = Some(label.clone());
            assert!(matches!(
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file),
                Err(SettingsError::InvalidAgentLabel(rejected)) if rejected == label
            ));
            file.launcher
                .profiles
                .get_mut("default")
                .unwrap()
                .herdr_agent = None;
            assert!(matches!(
                EffectiveLauncherConfig::merge(None, None, None, None, Some(label.clone()), false, &file),
                Err(SettingsError::InvalidAgentLabel(rejected)) if rejected == label
            ));
            let base = format!(
                "[launcher.base]\ncommand = 'omp'\nherdr_agent = {}\n[launcher.profiles.default]",
                serde_json::to_string(&label).unwrap()
            );
            assert!(toml::from_str::<FileConfig>(&base).is_err());
        }
        file.launcher
            .profiles
            .get_mut("default")
            .unwrap()
            .herdr_agent = Some("é".repeat(256));
        assert_eq!(
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file)
                .unwrap()
                .agent_label
                .len(),
            512
        );
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
        let settings = EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file)
            .unwrap()
            .resolve(Path::new("/"), None)
            .unwrap();
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
            EffectiveLauncherConfig::merge(
                None,
                None,
                selected.map(str::to_owned),
                None,
                None,
                false,
                file,
            )
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
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file),
            Err(SettingsError::UnknownProfile(name)) if name == "default"
        ));
    }

    #[test]
    fn network_override_replaces_only_selected_profile_and_keeps_runtime_validation() {
        let mut file: FileConfig = toml::from_str(
            r#"
socket = "/unused.sock"
[launcher]
profile = "selected"
[launcher.base]
command = "/bin/true"
network = "host"
[launcher.profiles.selected]
[launcher.profiles.other]
"#,
        )
        .unwrap();
        file.override_network(None, Some(NetworkFileMode::None))
            .unwrap();
        let settings =
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
        assert_eq!(settings.runtime.network, NetworkMode::None);
        assert_eq!(
            file.launcher.profiles["other"].network,
            Some(NetworkFileMode::Host)
        );
        file.override_network(Some("other"), Some(NetworkFileMode::Private))
            .unwrap();
        assert!(matches!(
            EffectiveLauncherConfig::merge(
                None,
                None,
                Some("other".to_owned()),
                None,
                None,
                false,
                &file
            ),
            Err(SettingsError::PrivateNetworkRequiresBubblewrap)
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
            EffectiveLauncherConfig::merge(
                None,
                None,
                Some("base".to_owned()),
                None,
                None,
                false,
                &file
            ),
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
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file),
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
            let settings =
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
            assert_eq!(settings.limits.cpu_cores, expected_cores);
            assert_eq!(settings.limits.cpu_count, expected_count);
            let other = file.launcher.profiles["other"].clone();
            file.override_cpu_selection(None, Some(vec![4, 7]), None)
                .unwrap();
            let settings =
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
            assert_eq!(settings.limits.cpu_cores, Some(vec![4, 7]));
            assert_eq!(settings.limits.cpu_count, None);
            file.override_cpu_selection(None, None, Some(2)).unwrap();
            let settings =
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
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
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file),
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

    fn mount_file() -> FileConfig {
        toml::from_str(
            r#"
runtime = "bubblewrap"
socket = "/unused.sock"
[launcher.profiles.default]
command = "sh"
bind_mounts = [{ source = "@workspace", destination = "/workspace", access = "rw" }]
"#,
        )
        .unwrap()
    }

    fn workspace_destination_file(destination: &str) -> FileConfig {
        let mut file = mount_file();
        // Native resolution exercises the public consumer boundary without
        // depending on host Bubblewrap availability or creating a daemon.
        file.runtime = Some(RuntimeFileKind::Native);
        file.launcher
            .profiles
            .get_mut("default")
            .unwrap()
            .bind_mounts[0]
            .destination = Some(PathBuf::from(destination));
        file
    }

    #[test]
    fn workspace_destinations_resolve_at_the_consumer_boundary() {
        for (declaration, expected, captured) in [
            ("/@workspace", "/src", Some("src")),
            ("/custom", "/custom", None),
            ("/@workspace/child", "/@workspace/child", None),
            ("/prefix-@workspace", "/prefix-@workspace", None),
        ] {
            let file = workspace_destination_file(declaration);
            let effective =
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
            assert_eq!(
                effective.runtime.bind_mounts[0].destination.as_deref(),
                Some(Path::new(declaration))
            );
            let fingerprint = effective.fingerprint().unwrap();
            let resolved = effective
                .clone()
                .resolve(Path::new("/project/src"), None)
                .unwrap();
            assert_eq!(
                resolved.runtime.bind_mounts[0].source,
                BindMountSource::Workspace
            );
            assert_eq!(
                resolved.runtime.bind_mounts[0].destination,
                Path::new(expected)
            );
            assert_eq!(resolved.workspace_directory.as_deref(), captured);
            assert_eq!(effective.fingerprint().unwrap(), fingerprint);
        }
    }

    #[test]
    fn frozen_workspace_directory_overrides_generated_worktree_context() {
        let file = workspace_destination_file("/@workspace");
        let effective =
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
        let fingerprint = effective.fingerprint().unwrap();
        for current in [
            "/generated/runroom-worktree-123",
            "/",
            "/different/checkout",
        ] {
            let resolved = effective
                .clone()
                .resolve(Path::new(current), Some("original-src"))
                .unwrap();
            assert_eq!(
                resolved.runtime.bind_mounts[0].destination,
                Path::new("/original-src")
            );
            assert_eq!(
                resolved.workspace_directory.as_deref(),
                Some("original-src")
            );
            assert_eq!(effective.fingerprint().unwrap(), fingerprint);
        }
        let other = effective
            .clone()
            .resolve(Path::new("/different/src"), Some("other"))
            .unwrap();
        assert_eq!(
            other.runtime.bind_mounts[0].destination,
            Path::new("/other")
        );
        assert_eq!(effective.fingerprint().unwrap(), fingerprint);
        let explicit = workspace_destination_file("/custom");
        assert_ne!(fingerprint_of(&explicit), fingerprint);
        let resolved =
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &explicit)
                .unwrap()
                .resolve(Path::new("/"), Some("ignored"))
                .unwrap();
        assert_eq!(
            resolved.runtime.bind_mounts[0].destination,
            Path::new("/custom")
        );
        assert_eq!(resolved.workspace_directory, None);
    }

    #[test]
    fn invalid_workspace_directory_context_is_rejected_before_host_resolution() {
        let mut file = mount_file();
        file.socket = None;
        file.launcher
            .profiles
            .get_mut("default")
            .unwrap()
            .bind_mounts[0]
            .destination = Some(PathBuf::from("/@workspace"));
        let effective =
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
        for directory in ["", ".", "..", "a/b", "/absolute", "a\0b"] {
            let error = effective
                .clone()
                .resolve(Path::new("/generated/worktree"), Some(directory))
                .unwrap_err();
            assert!(
                matches!(
                    error.downcast_ref::<SettingsError>(),
                    Some(SettingsError::InvalidWorkspaceDirectory(_))
                ),
                "{directory:?}"
            );
        }
        for current in [
            PathBuf::from("/"),
            PathBuf::from(""),
            PathBuf::from(OsString::from_vec(b"/bad-\xff".to_vec())),
        ] {
            let error = effective.clone().resolve(&current, None).unwrap_err();
            assert!(matches!(
                error.downcast_ref::<SettingsError>(),
                Some(SettingsError::InvalidWorkspaceDirectory(_))
            ));
        }
        for protected in ["usr", "etc", "proc", "dev", "run", "tmp"] {
            let error = effective
                .clone()
                .resolve(Path::new("/generated/worktree"), Some(protected))
                .unwrap_err();
            assert!(matches!(error.downcast_ref::<SettingsError>(),
                Some(SettingsError::ProtectedBindDestination(path)) if path == &Path::new("/").join(protected)));
        }
        let mut explicit = file;
        explicit
            .launcher
            .profiles
            .get_mut("default")
            .unwrap()
            .bind_mounts[0]
            .destination = Some(PathBuf::from("/custom"));
        let error = EffectiveLauncherConfig::merge(None, None, None, None, None, false, &explicit)
            .unwrap()
            .resolve(Path::new("/"), Some("../bad"))
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<SettingsError>(),
            Some(SettingsError::InvalidWorkspaceDirectory(_))
        ));
    }

    #[test]
    fn workspace_expansion_cannot_mask_inherited_or_optional_host_grants() {
        for inherited_workspace in [true, false] {
            let (base, child) = if inherited_workspace {
                (
                    "{source='@workspace',destination='/@workspace',access='rw'}",
                    "{source='/absent-expansion-host',destination='/src',access='ro',required=false}",
                )
            } else {
                (
                    "{source='/absent-expansion-host',destination='/src',access='ro',required=false}",
                    "{source='@workspace',destination='/@workspace',access='rw'}",
                )
            };
            let file: FileConfig = toml::from_str(&format!(
                "socket='/unused.sock'\n[launcher.base]\ncommand='sh'\nbind_mounts=[{base}]\n\
                 [launcher.profiles.default]\nbind_mounts=[{child}]"
            ))
            .unwrap();
            let error = EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file)
                .unwrap()
                .resolve(Path::new("/project/src"), None)
                .unwrap_err();
            assert!(matches!(error.downcast_ref::<SettingsError>(),
                Some(SettingsError::DuplicateBindDestination(path)) if path == Path::new("/src")));
        }
    }

    #[test]
    fn symbolic_workspace_collisions_include_cli_grants_before_source_checks() {
        let mut file = mount_file();
        file.launcher
            .profiles
            .get_mut("default")
            .unwrap()
            .bind_mounts[0]
            .destination = Some(PathBuf::from("/@workspace"));
        for (read_only, specifications) in [
            (vec![PathBuf::from("src")], vec![]),
            (vec![], vec!["absent@/src:ro".to_owned()]),
        ] {
            let effective =
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file)
                    .unwrap()
                    .with_launch_mounts(read_only, specifications)
                    .unwrap();
            let error = effective
                .resolve(Path::new("/project/src"), None)
                .unwrap_err();
            assert!(matches!(error.downcast_ref::<SettingsError>(),
                Some(SettingsError::DuplicateBindDestination(path)) if path == Path::new("/src")));
        }
    }

    #[test]
    fn workspace_source_overrides_base_destination_and_accepts_herdr_custom_paths() {
        for (base, child) in [
            ("/@workspace", "/custom"),
            ("/custom", "/@workspace"),
            ("~/workspace", "/custom"),
        ] {
            let mut file: FileConfig = toml::from_str(&format!(
                "runtime='bubblewrap'\nsocket='/unused.sock'\n[launcher.base]\ncommand='sh'\nidentity='herdr'\n\
                 bind_mounts=[{{source='@workspace',destination='{base}',access='ro'}}]\n\
                 [launcher.profiles.default]\nbind_mounts=[{{source='@workspace',destination='{child}',access='rw'}}]"
            )).unwrap();
            let effective =
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
            assert_eq!(effective.runtime.bind_mounts.len(), 1);
            assert_eq!(
                effective.runtime.bind_mounts[0].destination.as_deref(),
                Some(Path::new(child))
            );
            assert_eq!(effective.identity, Some(IdentityFileKind::Herdr));
            file.runtime = Some(RuntimeFileKind::Native);
            file.launcher.profiles.get_mut("default").unwrap().identity = None;
            let resolved =
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file)
                    .unwrap()
                    .resolve(Path::new("/project/src"), None)
                    .unwrap();
            assert_eq!(
                resolved.runtime.bind_mounts[0].destination,
                Path::new(if child == "/@workspace" {
                    "/src"
                } else {
                    child
                })
            );
        }
    }

    #[test]
    fn workspace_layer_duplicates_and_nonworkspace_symbolic_destinations_are_rejected() {
        for layer in ["launcher.base", "launcher.profiles.default"] {
            let text = format!(
                "[{layer}]\ncommand='sh'\nbind_mounts=[\
                 {{source='@workspace',destination='/one',access='ro'}},\
                 {{source='@workspace',destination='/two',access='rw'}}]\n"
            );
            assert!(toml::from_str::<FileConfig>(&text).is_err());
        }
        let mut file = workspace_destination_file("/@workspace");
        file.launcher
            .profiles
            .get_mut("default")
            .unwrap()
            .bind_mounts[0]
            .source = BindMountFileSource::Path("/host-source".to_owned());
        assert!(
            matches!(EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file),
            Err(SettingsError::InvalidBindDestination(path)) if path == Path::new("/@workspace"))
        );
        let mut file = mount_file();
        let workspace = file.launcher.profiles["default"].bind_mounts[0].clone();
        file.launcher
            .profiles
            .get_mut("default")
            .unwrap()
            .bind_mounts
            .push(workspace);
        file.override_launch_mode(None, true).unwrap();
        assert!(matches!(
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file),
            Err(SettingsError::DuplicateWorkspaceMount)
        ));
    }

    #[test]
    fn exact_directory_resolution_preserves_declared_and_frozen_workspace_destinations() {
        if validate_bubblewrap_host().is_err() {
            return;
        }
        for declaration in [None, Some("/custom"), Some("/@workspace")] {
            let mut file = mount_file();
            let profile = file.launcher.profiles.get_mut("default").unwrap();
            profile.identity = Some(IdentityFileKind::Herdr);
            if let Some(destination) = declaration {
                profile.bind_mounts[0].destination = Some(PathBuf::from(destination));
                profile.bind_mounts[0].access = BindAccessFileMode::Ro;
            } else {
                profile.bind_mounts.clear();
            }
            file.override_launch_mode(None, true).unwrap();
            let effective =
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
            let fingerprint = effective.fingerprint().unwrap();
            let resolved = effective
                .clone()
                .resolve(Path::new("/generated/worktree-123"), Some("captured-src"))
                .unwrap();
            let expected = match declaration {
                None => "/workspace",
                Some("/@workspace") => "/captured-src",
                Some(path) => path,
            };
            assert_eq!(
                resolved.runtime.bind_mounts[0].destination,
                Path::new(expected)
            );
            assert_eq!(
                resolved.runtime.bind_mounts[0].source,
                BindMountSource::Workspace
            );
            assert_eq!(
                resolved.runtime.bind_mounts[0].access,
                BindAccess::ReadWrite
            );
            assert_eq!(
                resolved.workspace_directory.as_deref(),
                if declaration == Some("/@workspace") {
                    Some("captured-src")
                } else {
                    None
                }
            );
            assert_eq!(effective.fingerprint().unwrap(), fingerprint);
            assert_eq!(resolved.identity, Some(IdentityFileKind::Herdr));
        }
    }

    fn fingerprint_file() -> FileConfig {
        toml::from_str(r#"
runtime = "bubblewrap"
[launcher.profiles.default]
command = "omp --model initial"
herdr_agent = "omp"
network = "host"
identity = "herdr"
environment = ["PATH", "RUNROOM_FINGERPRINT_MIRROR_TEST_8AD790"]
set_environment = { RUNROOM_LITERAL = "declared" }
bind_mounts = [
    { source = "@workspace", destination = "/workspace", access = "rw" },
    { source = "~/runroom-fingerprint-required-absent-8ad790", destination = "~/state", access = "ro" },
    { executable = "runroom-fingerprint-absent-8ad790", access = "ro", required = false },
]
devices = [{ class = "runroom_fingerprint_absent_8ad790", required = false }]
memory_max_bytes = 1048576
tasks_max = 64
cpu_quota_basis_points = 10000
"#).unwrap()
    }

    fn fingerprint_of(file: &FileConfig) -> String {
        EffectiveLauncherConfig::merge(None, None, None, None, None, false, file)
            .unwrap()
            .fingerprint()
            .unwrap()
    }

    #[test]
    fn fingerprint_detects_declared_policy_changes_without_host_resolution() {
        type PolicyMutation = (&'static str, fn(&mut ProfileFileConfig));
        let file = fingerprint_file();
        let original = fingerprint_of(&file);
        assert_eq!(original.len(), 67);
        assert!(original.starts_with("v1:"));
        assert!(
            original[3..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        let mutations: &[PolicyMutation] = &[
            ("network", |p| p.network = Some(NetworkFileMode::None)),
            ("project environment", |p| {
                p.project_environment = Some(true);
            }),
            ("identity", |p| p.identity = None),
            ("agent label", |p| p.herdr_agent = Some("different".into())),
            ("mirrored name", |p| {
                p.environment.push("RUNROOM_ANOTHER_NAME".into());
            }),
            ("literal value", |p| {
                p.set_environment
                    .insert("RUNROOM_LITERAL".into(), "changed".into());
            }),
            ("literal name", |p| {
                p.set_environment
                    .insert("RUNROOM_ADDED".into(), "declared".into());
            }),
            ("workspace access", |p| {
                p.bind_mounts[0].access = BindAccessFileMode::Ro;
            }),
            ("workspace order", |p| p.bind_mounts.swap(0, 1)),
            ("bind access", |p| {
                p.bind_mounts[1].access = BindAccessFileMode::Rw;
            }),
            ("bind optionality", |p| p.bind_mounts[1].required = false),
            ("bind source", |p| {
                p.bind_mounts[1].source = BindMountFileSource::Path("~/other".into());
            }),
            ("bind destination", |p| {
                p.bind_mounts[1].destination = Some("/other".into());
            }),
            ("executable selector", |p| {
                p.bind_mounts[2].source = BindMountFileSource::Executable("different-tool".into());
            }),
            ("executable required", |p| p.bind_mounts[2].required = true),
            ("device selector", |p| {
                p.devices[0].selector = DeviceSelector::Path("/dev/null".into());
            }),
            ("device required", |p| p.devices[0].required = true),
            ("memory", |p| p.memory_max_bytes = Some(2_097_152)),
            ("tasks", |p| p.tasks_max = Some(128)),
            ("cpu quota", |p| p.cpu_quota_basis_points = Some(20_000)),
            ("cpu cores", |p| p.cpu_cores = Some(vec![1, 3])),
            ("cpu count", |p| p.cpu_count = Some(2)),
        ];
        for (name, change) in mutations {
            let mut candidate = file.clone();
            change(candidate.launcher.profiles.get_mut("default").unwrap());
            assert_ne!(fingerprint_of(&candidate), original, "{name}");
        }
        let mut native = file;
        native.runtime = Some(RuntimeFileKind::Native);
        let profile = native.launcher.profiles.get_mut("default").unwrap();
        profile.identity = None;
        profile.devices.clear();
        let mut bubblewrap = native.clone();
        bubblewrap.runtime = Some(RuntimeFileKind::Bubblewrap);
        assert_ne!(fingerprint_of(&native), fingerprint_of(&bubblewrap));
    }

    #[test]
    fn fingerprint_excludes_command_routing_and_frozen_cli_grants() {
        let file = fingerprint_file();
        let original = fingerprint_of(&file);
        let mut replay = file.clone();
        replay.socket = Some("~/other-control.sock".into());
        replay.launcher.name = Some("different-workspace".into());
        replay.launcher.verbose = Some(true);
        replay.launcher.profiles.get_mut("default").unwrap().command =
            Some("omp --resume 'opaque session reference'".into());
        assert_eq!(fingerprint_of(&replay), original);
        let declared = replay.launcher.profiles["default"].clone();
        replay.override_launch_mode(None, true).unwrap();
        assert_eq!(replay.launcher.profiles["default"], declared);
        assert_eq!(replay.launcher.name, None);
        let effective = EffectiveLauncherConfig::merge(
            None,
            None,
            None,
            Some("omp -r another --resume latest".into()),
            None,
            false,
            &replay,
        )
        .unwrap()
        .with_launch_mounts(
            vec![PathBuf::from("unresolved-cli-grant")],
            vec!["unresolved@/frozen:rw".into()],
        )
        .unwrap();
        assert_eq!(effective.fingerprint().unwrap(), original);
    }

    #[test]
    fn fingerprint_ignores_formatting_and_unselected_profiles() {
        let first: FileConfig = toml::from_str(
            r#"
[launcher.profiles.default]
command = "omp"
set_environment = { B = "two", A = "one" }
"#,
        )
        .unwrap();
        let formatted: FileConfig = toml::from_str(
            r#"
# A reordered, formatted declaration has identical selected intent.
[launcher.profiles.default]
set_environment={A="one",B="two"}
command='omp'
[launcher.profiles.unselected]
command = "pi --resume whatever"
environment = ["AN_UNRELATED_NAME"]
"#,
        )
        .unwrap();
        assert_eq!(fingerprint_of(&first), fingerprint_of(&formatted));
    }

    #[test]
    fn fingerprint_retains_binding_layer_provenance_and_order() {
        let inherited: FileConfig = toml::from_str(
            r#"
[launcher.base]
command = "omp"
bind_mounts = [{ source = "~/absent", destination = "~/grant", access = "ro", required = false }]
[launcher.profiles.default]
bind_mounts = [{ source = "/absent", destination = "/grant", access = "rw", required = false }]
"#,
        )
        .unwrap();
        let direct: FileConfig = toml::from_str(
            r#"
[launcher.profiles.default]
command = "omp"
bind_mounts = [
    { source = "~/absent", destination = "~/grant", access = "ro", required = false },
    { source = "/absent", destination = "/grant", access = "rw", required = false },
]
"#,
        )
        .unwrap();
        assert_eq!(
            inherited.launcher.profiles["default"].bind_mounts,
            direct.launcher.profiles["default"].bind_mounts
        );
        assert_ne!(fingerprint_of(&inherited), fingerprint_of(&direct));
        let mut reversed = direct.clone();
        reversed
            .launcher
            .profiles
            .get_mut("default")
            .unwrap()
            .bind_mounts
            .reverse();
        assert_ne!(fingerprint_of(&reversed), fingerprint_of(&direct));
    }

    #[test]
    fn fingerprint_does_not_read_home_path_mirrored_values_or_cwd() {
        const CHILD: &str = "RUNROOM_FINGERPRINT_CHILD_TEST_8AD790";
        if env::var_os(CHILD).is_some() {
            println!("FINGERPRINT:{}", fingerprint_of(&fingerprint_file()));
            return;
        }
        let fixture = DeviceFixture::new();
        let mut fingerprints = Vec::new();
        for (home, path, value, directory) in [
            (None, None, "first", fixture.root.clone()),
            (
                Some("/missing-home-one"),
                Some("/missing-path-one"),
                "second",
                fixture.dev.clone(),
            ),
            (
                Some("/missing-home-two"),
                Some("/missing-path-two"),
                "third",
                fixture.classes.clone(),
            ),
        ] {
            let mut child = std::process::Command::new(env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "config::tests::fingerprint_does_not_read_home_path_mirrored_values_or_cwd",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("RUNROOM_FINGERPRINT_MIRROR_TEST_8AD790", value)
                .env_remove("HOME")
                .env_remove("PATH")
                .current_dir(directory);
            if let Some(home) = home {
                child.env("HOME", home);
            }
            if let Some(path) = path {
                child.env("PATH", path);
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            fingerprints.push(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .lines()
                    .find_map(|line| {
                        line.find("FINGERPRINT:")
                            .map(|offset| line[offset..].to_owned())
                    })
                    .unwrap(),
            );
        }
        assert!(
            fingerprints
                .iter()
                .all(|fingerprint| fingerprint == &fingerprints[0])
        );
    }

    #[test]
    fn no_worktree_supplies_missing_workspace_only_at_resolution() {
        for (mount, destination) in [
            ("", "/workspace"),
            (
                "bind_mounts = [{ source = '@workspace', destination = '/other', access = 'ro' }]",
                "/other",
            ),
            (
                "bind_mounts = [{ source = '@workspace', destination = '/@workspace', access = 'ro' }]",
                "/src",
            ),
        ] {
            let mut file: FileConfig = toml::from_str(&format!(
                r#"
runtime = "bubblewrap"
[launcher.profiles.default]
command = "omp"
identity = "herdr"
{mount}
"#
            ))
            .unwrap();
            file.override_launch_mode(None, true).unwrap();
            let declared = file.launcher.profiles["default"].clone();
            let effective =
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
            assert_eq!(effective.runtime.bind_mounts, declared.bind_mounts);
            let mut resolved_profile = declared;
            rewrite_workspace_binding(&mut resolved_profile);
            expand_workspace_destination(&mut resolved_profile, Path::new("/project/src"), None)
                .unwrap();
            let mounts = resolve_bind_mounts(&resolved_profile, RuntimeKind::Bubblewrap).unwrap();
            assert_eq!(mounts.len(), 1);
            assert_eq!(mounts[0].source, BindMountSource::Workspace);
            assert_eq!(mounts[0].destination, Path::new(destination));
            assert_eq!(mounts[0].access, BindAccess::ReadWrite);
        }
    }

    #[test]
    fn no_worktree_rewrite_preserves_alias_override_provenance() {
        const CHILD: &str = "RUNROOM_NO_WORKTREE_ALIAS_CHILD_8AD790";
        if env::var_os(CHILD).is_some() {
            let home = PathBuf::from(env::var_os("HOME").unwrap());
            let root = PathBuf::from(env::var_os(CHILD).unwrap());
            let existing = root.join("source");
            fs::write(&existing, "base grant").unwrap();
            let mut file: FileConfig = toml::from_str(&format!(
                r#"
runtime = "bubblewrap"
[launcher.base]
command = "omp"
bind_mounts = [
    {{ source = "@workspace", destination = "~/workspace", access = "ro" }},
    {{ source = "{}", destination = "~/grant", access = "ro" }},
]
[launcher.profiles.default]
bind_mounts = [
    {{ source = "@workspace", destination = "/workspace", access = "rw" }},
    {{ source = "{}", destination = "{}", access = "rw", required = false }},
]
"#,
                existing.display(),
                root.join("absent").display(),
                home.join("grant").display()
            ))
            .unwrap();
            let original = fingerprint_of(&file);
            file.override_launch_mode(None, true).unwrap();
            assert_eq!(fingerprint_of(&file), original);
            let mut profile = file.launcher.profiles["default"].clone();
            rewrite_workspace_binding(&mut profile);
            let mounts = resolve_bind_mounts(&profile, RuntimeKind::Bubblewrap).unwrap();
            // The absent optional child still revokes the inherited host grant.
            assert_eq!(mounts.len(), 1);
            assert_eq!(mounts[0].source, BindMountSource::Workspace);
            assert_eq!(mounts[0].destination, Path::new("/workspace"));
            assert_eq!(mounts[0].access, BindAccess::ReadWrite);
            return;
        }
        let fixture = DeviceFixture::new();
        let output = std::process::Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "config::tests::no_worktree_rewrite_preserves_alias_override_provenance",
            ])
            .env(CHILD, &fixture.root)
            .env("HOME", "/home/runroom-no-worktree-test")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn selected_config_path_matches_default_lookup_without_hiding_load_errors() {
        const CHILD: &str = "RUNROOM_CONFIG_PATH_CHILD_8AD790";
        const EXPECTED: &str = "RUNROOM_CONFIG_PATH_EXPECTED_8AD790";
        if let Some(expectation) = env::var_os(CHILD) {
            let expected = env::var_os(EXPECTED).map(PathBuf::from);
            assert_eq!(selected_config_path(), expected);
            match expectation.to_str().unwrap() {
                "loaded" => assert!(
                    load_default()
                        .unwrap()
                        .launcher
                        .profiles
                        .contains_key("default")
                ),
                "absent" => assert_eq!(load_default().unwrap(), FileConfig::default()),
                "parse" => assert!(matches!(load_default(), Err(ConfigError::Parse { .. }))),
                "read" => assert!(matches!(load_default(), Err(ConfigError::Read { .. }))),
                _ => unreachable!(),
            }
            return;
        }
        let fixture = DeviceFixture::new();
        let home = fixture.root.join("home");
        let default = home.join(".config/runroom/config.toml");
        let xdg = fixture.root.join("xdg");
        let override_path = xdg.join("runroom/config.toml");
        let missing = fixture.root.join("missing");
        let invalid = fixture.root.join("invalid");
        let invalid_path = invalid.join("runroom/config.toml");
        let directory = fixture.root.join("directory");
        for path in [&default, &override_path, &invalid_path] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "[launcher.profiles.default]\ncommand = 'omp'\n").unwrap();
        }
        fs::write(&invalid_path, "not valid toml!").unwrap();
        fs::create_dir_all(directory.join("runroom/config.toml")).unwrap();
        let relative = PathBuf::from("relative-invalid-xdg");
        for (xdg_value, home_value, expected, result) in [
            (Some(&xdg), Some(&home), Some(&override_path), "loaded"),
            (None, Some(&home), Some(&default), "loaded"),
            (Some(&relative), Some(&home), Some(&default), "loaded"),
            (Some(&missing), Some(&home), None, "absent"),
            (None, None, None, "absent"),
            (Some(&invalid), Some(&home), Some(&invalid_path), "parse"),
            (Some(&directory), Some(&home), None, "read"),
        ] {
            let mut child = std::process::Command::new(env::current_exe().unwrap());
            child.args([
                "--exact", "config::tests::selected_config_path_matches_default_lookup_without_hiding_load_errors",
            ]).env(CHILD, result).env_remove(EXPECTED)
                .env_remove("XDG_CONFIG_HOME").env_remove("HOME");
            if let Some(xdg) = xdg_value {
                child.env("XDG_CONFIG_HOME", xdg);
            }
            if let Some(home) = home_value {
                child.env("HOME", home);
            }
            if let Some(expected) = expected {
                child.env(EXPECTED, expected);
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn merge_retains_missing_mounts_and_defers_required_host_checks() {
        let fixture = DeviceFixture::new();
        let missing = fixture.root.join("missing");
        for required in [true, false] {
            let mut file = file_config();
            file.launcher.profiles.get_mut("pi").unwrap().bind_mounts = vec![BindMountFileConfig {
                source: BindMountFileSource::Path(missing.to_str().unwrap().to_owned()),
                destination: Some(PathBuf::from("/missing")),
                access: BindAccessFileMode::Ro,
                required,
            }];
            let effective =
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
            assert_eq!(
                effective.runtime.bind_mounts,
                file.launcher.profiles["pi"].bind_mounts
            );
            let result = effective.resolve(&fixture.root, None);
            if required {
                assert!(
                    matches!(result.unwrap_err().downcast_ref::<SettingsError>(),
                    Some(SettingsError::InvalidBindSource { path, .. }) if path == &missing)
                );
            } else {
                assert_eq!(result.unwrap().runtime.bind_mounts, []);
            }
        }
        let mut file = file_config();
        file.launcher.profiles.get_mut("pi").unwrap().bind_mounts = vec![BindMountFileConfig {
            source: BindMountFileSource::Executable(
                "runroom-guaranteed-missing-executable-8ad790".to_owned(),
            ),
            destination: None,
            access: BindAccessFileMode::Ro,
            required: true,
        }];
        let effective =
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
        assert!(matches!(
            effective
                .resolve(&fixture.root, None)
                .unwrap_err()
                .downcast_ref::<SettingsError>(),
            Some(SettingsError::ExecutableNotFound(_))
        ));
    }

    #[test]
    fn merge_retains_device_selectors_and_cli_grants_without_discovery() {
        let mut file = mount_file();
        file.launcher.profiles.get_mut("default").unwrap().devices = vec![
            device_class("runroom_missing_class_8ad790", true),
            device_path("/dev/runroom_missing_device_8ad790", false),
        ];
        let effective = EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file)
            .unwrap()
            .with_launch_mounts(vec![], vec!["missing@/documents:ro".to_owned()])
            .unwrap();
        assert_eq!(
            effective.runtime.devices,
            file.launcher.profiles["default"].devices
        );
        assert_eq!(effective.launch_mounts[0].source, Path::new("missing"));
        assert_eq!(
            effective.launch_mounts[0].destination.as_deref(),
            Some(Path::new("/documents"))
        );
        let host_available = validate_bubblewrap_host().is_ok();
        let error = effective.resolve(Path::new("/"), None).unwrap_err();
        if host_available {
            assert!(matches!(
                error.downcast_ref::<SettingsError>(),
                Some(SettingsError::DeviceIo { .. } | SettingsError::MissingDeviceClass(_))
            ));
        }
        let fixture = DeviceFixture::new();
        file.launcher
            .profiles
            .get_mut("default")
            .unwrap()
            .devices
            .clear();
        let effective = EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file)
            .unwrap()
            .with_launch_mounts(vec![], vec!["missing@/documents:ro".to_owned()])
            .unwrap();
        let error = effective.resolve(&fixture.root, None).unwrap_err();
        if host_available {
            assert!(matches!(error.downcast_ref::<SettingsError>(),
                Some(SettingsError::InvalidBindSource { path, .. }) if path == &fixture.root.join("missing")));
        }
    }

    #[test]
    fn resolves_cli_mounts_with_canonical_replay_and_declared_basename() {
        if validate_bubblewrap_host().is_err() {
            return;
        }
        let fixture = DeviceFixture::new();
        let source = fixture.root.join("documents");
        fs::create_dir(&source).unwrap();
        symlink(&source, fixture.root.join("alias")).unwrap();
        let effective =
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &mount_file())
                .unwrap()
                .with_launch_mounts(
                    vec![PathBuf::from("alias")],
                    vec!["documents@/editable:rw".to_owned()],
                )
                .unwrap();
        let resolved = effective.resolve(&fixture.root, None).unwrap();
        let canonical = source.canonicalize().unwrap();
        assert_eq!(
            resolved.mount_arguments,
            [
                format!("{}@/alias:ro", canonical.display()),
                format!("{}@/editable:rw", canonical.display()),
            ]
        );
        assert_eq!(
            resolved.runtime.bind_mounts[1],
            BindMount {
                source: BindMountSource::Host(canonical.clone()),
                destination: PathBuf::from("/alias"),
                access: BindAccess::ReadOnly,
            }
        );
        assert_eq!(
            resolved.runtime.bind_mounts[2],
            BindMount {
                source: BindMountSource::Host(canonical),
                destination: PathBuf::from("/editable"),
                access: BindAccess::ReadWrite,
            }
        );
    }

    #[test]
    fn mirrored_environment_changes_resolution_not_effective_policy() {
        const NAME: &str = "RUNROOM_CONFIG_MIRROR_TEST_8AD790";
        if let Some(value) = env::var_os(NAME) {
            let file: FileConfig = toml::from_str(
                r#"
socket = "relative.sock"
[launcher.profiles.default]
command = "sh"
environment = ["RUNROOM_CONFIG_MIRROR_TEST_8AD790"]
set_environment = { RUNROOM_CONFIG_LITERAL_TEST = "literal" }
"#,
            )
            .unwrap();
            let symbolic_file: FileConfig = toml::from_str(
                r#"
[launcher.base]
command = "sh"
bind_mounts = [{ source = "~/absent", destination = "~/granted", access = "ro", required = false }]
[launcher.profiles.default]
"#,
            )
            .unwrap();
            let symbolic =
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &symbolic_file)
                    .unwrap();
            assert_eq!(symbolic.socket, None);
            assert_eq!(
                symbolic.runtime.bind_mounts[0].source,
                BindMountFileSource::Path("~/absent".to_owned())
            );
            let explicit_home = EffectiveLauncherConfig::merge(
                Some(PathBuf::from("~/control.sock")),
                None,
                None,
                None,
                None,
                false,
                &symbolic_file,
            )
            .unwrap();
            assert!(matches!(
                explicit_home
                    .resolve(Path::new("/launch"), None)
                    .unwrap_err()
                    .downcast_ref::<SettingsError>(),
                Some(SettingsError::MissingHome)
            ));
            let effective =
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file).unwrap();
            assert_eq!(effective.environment_allowlist, [NAME]);
            assert_eq!(
                effective.runtime.set_environment["RUNROOM_CONFIG_LITERAL_TEST"],
                "literal"
            );
            println!("POLICY:{}", effective.fingerprint().unwrap());
            let resolved = effective.resolve(Path::new("/launch"), None).unwrap();
            assert_eq!(resolved.socket, Path::new("/launch/relative.sock"));
            assert_eq!(
                resolved.runtime.environment,
                vec![
                    EnvironmentVariable {
                        name: NAME.to_owned(),
                        value
                    },
                    EnvironmentVariable {
                        name: "RUNROOM_CONFIG_LITERAL_TEST".to_owned(),
                        value: "literal".into()
                    },
                ]
            );
            return;
        }
        // Change environment only in subprocesses, never in the parallel test host.
        let mut policies = Vec::new();
        for value in ["first host value", "second host value"] {
            let output = std::process::Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "config::tests::mirrored_environment_changes_resolution_not_effective_policy",
                    "--nocapture",
                ])
                .env(NAME, value)
                .env_remove("HOME")
                .env_remove("PATH")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            policies.push(
                stdout
                    .lines()
                    .find_map(|line| line.find("POLICY:").map(|offset| line[offset..].to_owned()))
                    .unwrap(),
            );
        }
        assert_eq!(policies[0], policies[1]);
    }

    #[test]
    fn host_equivalent_inherited_mounts_override_before_source_resolution() {
        const CHILD: &str = "RUNROOM_CONFIG_INHERIT_CHILD_8AD790";
        if env::var_os(CHILD).is_some() {
            let home = PathBuf::from(env::var_os("HOME").unwrap());
            let missing = home.join("missing").to_str().unwrap().to_owned();
            let existing = "/dev/null";
            for (base_source, base_destination, child_source, child_destination, required) in [
                ("~/missing", None, existing, Some(missing.as_str()), true),
                (missing.as_str(), None, existing, Some("~/missing"), true),
                (existing, Some(missing.as_str()), "~/missing", None, false),
                (existing, Some("~/missing"), missing.as_str(), None, false),
            ] {
                let entry = |source: &str, destination: Option<&str>, required: bool| {
                    let destination = destination
                        .map(|path| {
                            format!(", destination = {}", serde_json::to_string(path).unwrap())
                        })
                        .unwrap_or_default();
                    format!(
                        "{{ source = {}, access = 'ro', required = {required}{destination} }}",
                        serde_json::to_string(source).unwrap()
                    )
                };
                let text = format!(
                    "socket = '/unused.sock'\n[launcher.base]\ncommand = 'sh'\nbind_mounts = [{}]\n[launcher.profiles.default]\nbind_mounts = [{}]",
                    entry(base_source, base_destination, true),
                    entry(child_source, child_destination, required),
                );
                let file: FileConfig = toml::from_str(&text).unwrap();
                let effective =
                    EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file)
                        .unwrap();
                let resolved = effective.resolve(&home, None).unwrap();
                if required {
                    assert_eq!(resolved.runtime.bind_mounts.len(), 1);
                    assert_eq!(
                        resolved.runtime.bind_mounts[0].destination,
                        Path::new(&missing)
                    );
                    assert_eq!(
                        resolved.runtime.bind_mounts[0].source,
                        BindMountSource::Host(Path::new(existing).canonicalize().unwrap())
                    );
                } else {
                    assert_eq!(resolved.runtime.bind_mounts, []);
                }
            }
            return;
        }
        let fixture = DeviceFixture::new();
        let home = Path::new("/home").join(fixture.root.file_name().unwrap());
        let output = std::process::Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "config::tests::host_equivalent_inherited_mounts_override_before_source_resolution",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("HOME", home)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn launch_mounts_reject_conflicting_and_unsafe_grants() {
        let effective =
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &mount_file())
                .unwrap();
        let error = effective
            .clone()
            .with_launch_mounts(
                vec![PathBuf::from("docs"), PathBuf::from("other/docs")],
                vec![],
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
        ] {
            assert!(
                effective
                    .clone()
                    .with_launch_mounts(vec![], vec![specification.to_owned()])
                    .is_err(),
                "accepted {specification}"
            );
        }
        let duplicate = effective
            .clone()
            .with_launch_mounts(vec![], vec!["dev@/docs:ro".to_owned()])
            .unwrap();
        let error = duplicate
            .with_launch_mounts(vec![], vec!["dev@/docs:rw".to_owned()])
            .unwrap_err();
        assert!(matches!(error.downcast_ref::<SettingsError>(),
            Some(SettingsError::DuplicateBindDestination(path)) if path == Path::new("/docs")));
        let mut native = effective;
        native.runtime.kind = RuntimeKind::Native;
        assert!(
            native
                .with_launch_mounts(vec![], vec!["dev@/docs:ro".to_owned()])
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
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file),
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
            no_worktree: false,
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
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file),
                Err(SettingsError::PrivateNetworkRequiresBubblewrap),
            ));
        }
    }

    #[test]
    fn command_line_values_override_selected_profile() {
        let file = file_config();
        let launcher = EffectiveLauncherConfig::merge(
            Some(PathBuf::from("/cli-launcher.sock")),
            Some("cli".to_owned()),
            Some("pi".to_owned()),
            Some("pi --model 'cli model'".to_owned()),
            None,
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

        assert_eq!(launcher.socket, Some(PathBuf::from("/cli-launcher.sock")));
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
            herdr_agent: None,
            project_environment: None,
            network: Some(NetworkFileMode::None),
            port_forwards: Vec::new(),
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
            inherited_bind_mount_count: 0,
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

        let settings = EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file)
            .expect("merge Bubblewrap profile")
            .resolve(Path::new("/"), None)
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
    fn no_worktree_preserves_workspace_destination_without_dropping_host_permissions() {
        for destination in [None, Some("/other"), Some("/@workspace")] {
            let mut file = file_config();
            file.runtime = Some(RuntimeFileKind::Bubblewrap);
            let selected = file.launcher.profiles.get_mut("pi").expect("profile");
            selected.bind_mounts = destination
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
            let effective =
                EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file)
                    .expect("merge directory launch before host resolution");
            assert_eq!(
                effective.runtime.bind_mounts,
                file.launcher.profiles["pi"].bind_mounts
            );
            let mut resolved_profile = file.launcher.profiles["pi"].clone();
            rewrite_workspace_binding(&mut resolved_profile);
            expand_workspace_destination(&mut resolved_profile, Path::new("/project/src"), None)
                .unwrap();
            let mounts = resolve_bind_mounts(&resolved_profile, RuntimeKind::Bubblewrap)
                .expect("resolve directory permissions");
            assert_eq!(
                mounts,
                [
                    BindMount {
                        source: BindMountSource::Workspace,
                        destination: PathBuf::from(match destination {
                            None => "/workspace",
                            Some("/@workspace") => "/src",
                            Some(path) => path,
                        }),
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
        let missing_profile =
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &base)
                .expect_err("reject missing profile");
        let unknown = EffectiveLauncherConfig::merge(
            None,
            None,
            Some("unknown".to_owned()),
            None,
            None,
            false,
            &base,
        )
        .expect_err("reject unknown profile");
        let missing_command = EffectiveLauncherConfig::merge(
            None,
            None,
            Some("test".to_owned()),
            None,
            None,
            false,
            &base,
        )
        .expect_err("reject missing command");
        let empty = EffectiveLauncherConfig::merge(
            None,
            None,
            Some("test".to_owned()),
            Some("  # no executable".to_owned()),
            None,
            false,
            &base,
        )
        .expect_err("reject empty command");
        let malformed = EffectiveLauncherConfig::merge(
            None,
            None,
            Some("test".to_owned()),
            Some("pi 'unterminated".to_owned()),
            None,
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
        let empty_name = EffectiveLauncherConfig::merge(
            Some(PathBuf::from("/unused.sock")),
            Some("  ".to_owned()),
            Some("pi".to_owned()),
            None,
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
                herdr_agent: None,
                project_environment: None,
                network: None,
                port_forwards: Vec::new(),
                bind_mounts: Vec::new(),
                inherited_bind_mount_count: 0,
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
                herdr_agent: None,
                project_environment: None,
                network: None,
                port_forwards: Vec::new(),
                bind_mounts: vec![BindMountFileConfig {
                    source: BindMountFileSource::Path("relative".to_owned()),
                    destination: None,
                    access: BindAccessFileMode::Ro,
                    required: true,
                }],
                inherited_bind_mount_count: 0,
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
        let launcher = EffectiveLauncherConfig::merge(
            None,
            None,
            Some("pi".to_owned()),
            None,
            None,
            false,
            &file,
        )
        .expect("valid limits");
        assert_eq!(launcher.limits.memory_max_bytes, Some(1 << 30));

        file.daemon.resource_ceiling.memory_max_bytes = Some(1 << 29);
        let mut daemon_file = daemon_file_config();
        daemon_file.daemon.resource_ceiling.memory_max_bytes = Some(1 << 29);
        let daemon = DaemonSettings::resolve(None, None, None, false, &daemon_file)
            .expect("valid daemon ceiling");
        assert_eq!(daemon.resource_ceiling.memory_max_bytes, Some(1 << 29));
        assert!(matches!(
            EffectiveLauncherConfig::merge(
                None,
                None,
                Some("pi".to_owned()),
                None,
                None,
                false,
                &file
            ),
            Err(SettingsError::InvalidResourceLimits("launcher profile"))
        ));

        file.launcher
            .profiles
            .get_mut("pi")
            .expect("pi profile")
            .tasks_max = Some(0);
        assert!(matches!(
            EffectiveLauncherConfig::merge(
                None,
                None,
                Some("pi".to_owned()),
                None,
                None,
                false,
                &file
            ),
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
            let result = EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file);
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
        let settings = EffectiveLauncherConfig::merge(
            None,
            None,
            Some("other".to_owned()),
            None,
            None,
            false,
            &file,
        )
        .expect("resolve effective count selection");
        assert_eq!(settings.limits.cpu_count, Some(2));
        assert_eq!(settings.limits.cpu_cores, None);
        assert_eq!(file.launcher.profiles["pi"].cpu_count, Some(8));

        file.override_cpu_selection(None, Some(vec![4, 7]), None)
            .expect("apply core IDs to the default profile");
        file.override_cpu_selection(None, None, None)
            .expect("absent CLI selection preserves profile values");
        let settings = EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file)
            .expect("resolve effective explicit core selection");
        assert_eq!(settings.limits.cpu_cores, Some(vec![4, 7]));
        assert_eq!(settings.limits.cpu_count, None);

        file.override_cpu_selection(None, None, Some(0))
            .expect("apply invalid CLI selection before validation");
        assert!(matches!(
            EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file),
            Err(SettingsError::InvalidResourceLimits("launcher profile"))
        ));
    }
}
