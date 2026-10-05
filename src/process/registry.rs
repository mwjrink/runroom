//! Durable private registry for supervised Runroom instances.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::num::NonZeroU32;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{Flock, FlockArg};
use nix::sys::socket::UnixCredentials;
use serde::{Deserialize, Serialize};

use crate::backend::{ScopeHandle, ScopeState};
use crate::model::{
    ActivityState, ActivityUpdate, HerdrContext, InstanceId, InstanceRecord, InstanceState,
    ProcessId, ProjectId, ResolvedWorkspace, ResourceLimits, WorkspaceName, WorkspaceOrigin,
    WorkspaceSelection, WorkspaceSupportMount,
};

const REGISTRY_VERSION: u32 = 2;
const MAX_REGISTRY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REGISTRY_RECORDS: usize = 10_000;
const RETAINED_TERMINAL_RECORDS: usize = 1_000;

/// Registry-path exclusivity survives atomic replacement of the registry file.
#[derive(Debug)]
pub(super) struct RegistryLease {
    path: PathBuf,
    _lock: Flock<File>,
}

impl RegistryLease {
    pub(super) fn acquire(path: &Path) -> io::Result<Self> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "state file has no parent")
        })?;
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let parent = parent.canonicalize()?;
        let metadata = fs::metadata(&parent)?;
        if !metadata.is_dir()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != UnixCredentials::new().uid()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "instance registry directory must be owned by this user and private",
            ));
        }
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "state file has no file name")
        })?;
        let path = parent.join(name);
        let mut lock_name = name.to_os_string();
        lock_name.push(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(parent.join(lock_name))?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != UnixCredentials::new().uid()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "instance registry lock must be owned by this user and private",
            ));
        }
        let lock = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, error)| {
            io::Error::new(
                io::Error::from(error).kind(),
                "another daemon owns this instance registry",
            )
        })?;
        Ok(Self { path, _lock: lock })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug)]
pub(super) struct InstanceRegistry {
    path: PathBuf,
    records: BTreeMap<String, InstanceRecord>,
}

impl InstanceRegistry {
    pub(super) fn load(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    path,
                    records: BTreeMap::new(),
                });
            }
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != UnixCredentials::new().uid()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "instance registry must be owned by this user and be a private regular file",
            ));
        }
        if metadata.len() > MAX_REGISTRY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "instance registry exceeds maximum size",
            ));
        }
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        let stored: StoredRegistry = serde_json::from_slice(&contents).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("corrupt instance registry {}: {error}", path.display()),
            )
        })?;
        if stored.version != 1 && stored.version != REGISTRY_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported instance registry version {}", stored.version),
            ));
        }
        if stored.instances.len() > MAX_REGISTRY_RECORDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "instance registry contains too many records",
            ));
        }
        let mut records = BTreeMap::new();
        for stored in stored.instances {
            let record = InstanceRecord::try_from(stored)?;
            if records.insert(record.id.0.clone(), record).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate instance ID in registry",
                ));
            }
        }
        Ok(Self { path, records })
    }

    pub(super) fn insert(&mut self, record: InstanceRecord) -> io::Result<()> {
        if !valid_limits(&record.limits) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "instance has invalid resource limits",
            ));
        }
        let id = record.id.0.clone();
        if self.records.contains_key(&id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("duplicate instance {id}"),
            ));
        }
        let removed = self.prune_terminal_records(RETAINED_TERMINAL_RECORDS);
        if self.records.len() >= MAX_REGISTRY_RECORDS {
            self.records.extend(removed);
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "instance registry reached its active record limit",
            ));
        }
        self.records.insert(id.clone(), record);
        if let Err(error) = self.persist() {
            self.records.remove(&id);
            self.records.extend(removed);
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn get(&self, id: &InstanceId) -> Option<&InstanceRecord> {
        self.records.get(&id.0)
    }

    pub(super) fn scope_handles(&self) -> Vec<ScopeHandle> {
        self.records
            .values()
            .map(|record| ScopeHandle(record.scope_handle.clone()))
            .collect()
    }

    pub(super) fn list(&self, after: Option<&InstanceId>, limit: u16) -> Vec<InstanceRecord> {
        let start = after.map_or("", |id| id.0.as_str());
        self.records
            .range((
                std::ops::Bound::Excluded(start.to_owned()),
                std::ops::Bound::Unbounded,
            ))
            .take(usize::from(limit))
            .map(|(_, record)| record.clone())
            .collect()
    }
    fn prune_terminal_records(&mut self, retain: usize) -> Vec<(String, InstanceRecord)> {
        let mut terminal = self
            .records
            .iter()
            .filter(|(_, record)| {
                matches!(record.state, InstanceState::Exited | InstanceState::Failed)
            })
            .map(|(id, record)| (record.updated_at_ms, id.clone()))
            .collect::<Vec<_>>();
        if terminal.len() <= retain {
            return Vec::new();
        }
        terminal.sort_unstable();
        let remove = terminal.len() - retain;
        terminal
            .into_iter()
            .take(remove)
            .filter_map(|(_, id)| self.records.remove(&id).map(|record| (id, record)))
            .collect()
    }

    pub(super) fn has_active_workspace(&self, path: &Path) -> bool {
        self.records.values().any(|record| {
            record.workspace.path.starts_with(path)
                && !matches!(record.state, InstanceState::Exited | InstanceState::Failed)
        })
    }

    pub(super) fn update<F>(
        &mut self,
        id: &InstanceId,
        update: F,
    ) -> io::Result<Option<InstanceRecord>>
    where
        F: FnOnce(&mut InstanceRecord),
    {
        let Some(record) = self.records.get_mut(&id.0) else {
            return Ok(None);
        };
        let previous = record.clone();
        update(record);
        let result = record.clone();
        if let Err(error) = self.persist() {
            self.records.insert(id.0.clone(), previous);
            return Err(error);
        }
        Ok(Some(result))
    }

    pub(super) fn reconcile<F>(
        &mut self,
        managed: &[ScopeHandle],
        mut inspect: F,
    ) -> io::Result<Vec<ScopeHandle>>
    where
        F: FnMut(&ScopeHandle) -> io::Result<ScopeState>,
    {
        // The list is only an orphan candidate snapshot. Launch registration may
        // have happened after it was observed, so inspect every recorded handle.
        let known_names: HashSet<&str> = self
            .records
            .values()
            .map(|record| record.scope_handle.as_str())
            .collect();
        let orphans = managed
            .iter()
            .filter(|handle| !known_names.contains(handle.0.as_str()))
            .cloned()
            .collect();
        let now = now_ms();
        for record in self.records.values_mut() {
            let state = inspect(&ScopeHandle(record.scope_handle.clone()))?.into();
            if record.state != state {
                record.state = state;
                record.updated_at_ms = now;
            }
        }
        self.persist()?;
        Ok(orphans)
    }

    fn persist(&self) -> io::Result<()> {
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let parent_metadata = fs::symlink_metadata(parent)?;
        if !parent_metadata.is_dir() || parent_metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "instance registry directory must be private",
            ));
        }
        let file_name = self.path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "state file has no file name")
        })?;
        let temporary = parent.join(format!(
            ".{}.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            now_ms()
        ));
        let stored = StoredRegistry {
            version: REGISTRY_VERSION,
            instances: self.records.values().map(StoredInstance::from).collect(),
        };
        let bytes = serde_json::to_vec_pretty(&stored).map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_REGISTRY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "instance registry exceeds maximum size",
            ));
        }
        let write_result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
            File::open(parent)?.sync_all()
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }
}

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

impl From<ScopeState> for InstanceState {
    fn from(value: ScopeState) -> Self {
        match value {
            ScopeState::Starting => Self::Starting,
            ScopeState::Active => Self::Running,
            ScopeState::Stopping => Self::Stopping,
            ScopeState::Inactive => Self::Exited,
            ScopeState::Failed => Self::Failed,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredRegistry {
    version: u32,
    instances: Vec<StoredInstance>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredInstance {
    id: String,
    scope_handle: String,
    workspace: StoredWorkspace,
    profile: String,
    limits: StoredLimits,
    leader: u32,
    state: StoredInstanceState,
    activity: Option<StoredActivity>,
    #[serde(default, alias = "multiplexer")]
    herdr: Option<StoredHerdr>,
    #[serde(default, rename = "agent", skip_serializing)]
    _legacy_agent: Option<serde_json::Value>,
    created_at_ms: u64,
    updated_at_ms: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredWorkspace {
    project: String,
    #[serde(default)]
    primary_checkout: Vec<u8>,
    name: Option<String>,
    #[serde(default)]
    here: bool,
    path: Vec<u8>,
    change_name: Option<String>,
    origin: StoredWorkspaceOrigin,
    support_mounts: Vec<StoredMount>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredMount {
    source: Vec<u8>,
    destination: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    writable: Option<bool>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredWorkspaceOrigin {
    Primary,
    Created,
    Existing,
    Directory,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredInstanceState {
    Starting,
    Running,
    Stopping,
    Exited,
    Failed,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredActivityState {
    Working,
    Idle,
    Blocked,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredLimits {
    memory_max_bytes: Option<u64>,
    tasks_max: Option<u64>,
    cpu_quota_basis_points: Option<u32>,
    #[serde(default)]
    cpu_cores: Option<Vec<u32>>,
    #[serde(default)]
    cpu_count: Option<u32>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredActivity {
    state: StoredActivityState,
    message: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredHerdr {
    workspace_id: Option<String>,
    pane_id: Option<String>,
    session_name: Option<String>,
}

impl From<&InstanceRecord> for StoredInstance {
    fn from(record: &InstanceRecord) -> Self {
        Self {
            id: record.id.0.clone(),
            scope_handle: record.scope_handle.clone(),
            workspace: StoredWorkspace::from(&record.workspace),
            profile: record.profile.clone(),
            limits: StoredLimits {
                memory_max_bytes: record.limits.memory_max_bytes,
                tasks_max: record.limits.tasks_max,
                cpu_quota_basis_points: record.limits.cpu_quota_basis_points,
                cpu_cores: record.limits.cpu_cores.clone(),
                cpu_count: record.limits.cpu_count,
            },
            leader: record.leader.0.get(),
            state: record.state.into(),
            activity: record.activity.as_ref().map(StoredActivity::from),
            herdr: record.herdr.as_ref().map(StoredHerdr::from),
            _legacy_agent: None,
            created_at_ms: record.created_at_ms,
            updated_at_ms: record.updated_at_ms,
        }
    }
}

impl TryFrom<StoredInstance> for InstanceRecord {
    type Error = io::Error;
    fn try_from(record: StoredInstance) -> io::Result<Self> {
        let limits = ResourceLimits {
            memory_max_bytes: record.limits.memory_max_bytes,
            tasks_max: record.limits.tasks_max,
            cpu_quota_basis_points: record.limits.cpu_quota_basis_points,
            cpu_cores: record.limits.cpu_cores,
            cpu_count: record.limits.cpu_count,
        };
        if !valid_name(&record.id)
            || !valid_scope_handle(&record.scope_handle, &record.id)
            || !valid_name(&record.profile)
            || record.created_at_ms > record.updated_at_ms
            || !valid_limits(&limits)
            || record.activity.as_ref().is_some_and(|activity| {
                activity.message.as_ref().is_some_and(|value| {
                    value.len() > 4 * 1024 || value.chars().any(char::is_control)
                })
            })
            || record.herdr.as_ref().is_some_and(|context| {
                [
                    context.workspace_id.as_ref(),
                    context.pane_id.as_ref(),
                    context.session_name.as_ref(),
                ]
                .into_iter()
                .flatten()
                .any(|value| !valid_name(value))
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "registry contains invalid instance metadata",
            ));
        }
        let leader = NonZeroU32::new(record.leader).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "registry contains zero leader PID",
            )
        })?;
        Ok(Self {
            id: InstanceId(record.id),
            scope_handle: record.scope_handle,
            workspace: record.workspace.try_into()?,
            profile: record.profile,
            limits,
            leader: ProcessId(leader),
            state: record.state.into(),
            activity: record.activity.map(ActivityUpdate::from),
            herdr: record.herdr.map(HerdrContext::from),
            created_at_ms: record.created_at_ms,
            updated_at_ms: record.updated_at_ms,
        })
    }
}

impl From<&ResolvedWorkspace> for StoredWorkspace {
    fn from(workspace: &ResolvedWorkspace) -> Self {
        Self {
            project: workspace.project.0.clone(),
            primary_checkout: workspace.primary_checkout.as_os_str().as_bytes().to_vec(),
            name: match &workspace.selection {
                WorkspaceSelection::Primary | WorkspaceSelection::Here => None,
                WorkspaceSelection::Named(name) => Some(name.0.clone()),
            },
            here: matches!(workspace.selection, WorkspaceSelection::Here),
            path: workspace.path.as_os_str().as_bytes().to_vec(),
            change_name: workspace.change_name.clone(),
            origin: workspace.origin.into(),
            support_mounts: workspace
                .support_mounts
                .iter()
                .map(|mount| StoredMount {
                    source: mount.source.as_os_str().as_bytes().to_vec(),
                    destination: mount.destination.as_os_str().as_bytes().to_vec(),
                    writable: None,
                })
                .collect(),
        }
    }
}

impl TryFrom<StoredWorkspace> for ResolvedWorkspace {
    type Error = io::Error;

    fn try_from(workspace: StoredWorkspace) -> io::Result<Self> {
        let primary_checkout = if workspace.primary_checkout.is_empty() {
            workspace.path.clone()
        } else {
            workspace.primary_checkout
        };
        let valid_path =
            |path: &[u8]| !path.is_empty() && path.len() <= 16 * 1024 && !path.contains(&0);
        if !valid_name(&workspace.project)
            || !valid_path(&primary_checkout)
            || !valid_path(&workspace.path)
            || workspace.support_mounts.len() > 32
            || workspace
                .name
                .as_ref()
                .is_some_and(|name| !valid_name(name))
            || workspace
                .change_name
                .as_ref()
                .is_some_and(|name| !valid_name(name))
            || workspace
                .support_mounts
                .iter()
                .any(|mount| !valid_path(&mount.source) || !valid_path(&mount.destination))
            || (workspace.here && workspace.name.is_some())
            || (workspace.here != matches!(workspace.origin, StoredWorkspaceOrigin::Directory))
            || (workspace.here
                && (primary_checkout != workspace.path
                    || workspace.change_name.is_some()
                    || !workspace.support_mounts.is_empty()))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "registry contains invalid workspace",
            ));
        }
        Ok(Self {
            project: ProjectId(workspace.project),
            primary_checkout: PathBuf::from(std::ffi::OsString::from_vec(primary_checkout)),
            selection: if workspace.here {
                WorkspaceSelection::Here
            } else {
                workspace.name.map_or(WorkspaceSelection::Primary, |name| {
                    WorkspaceSelection::Named(WorkspaceName(name))
                })
            },
            path: PathBuf::from(std::ffi::OsString::from_vec(workspace.path)),
            change_name: workspace.change_name,
            origin: workspace.origin.into(),
            support_mounts: workspace
                .support_mounts
                .into_iter()
                .map(|mount| WorkspaceSupportMount {
                    source: PathBuf::from(std::ffi::OsString::from_vec(mount.source)),
                    destination: PathBuf::from(std::ffi::OsString::from_vec(mount.destination)),
                })
                .collect(),
        })
    }
}

fn valid_scope_handle(value: &str, instance_id: &str) -> bool {
    let Some(identity) = value
        .strip_prefix("runroom-")
        .and_then(|value| value.strip_suffix(".scope"))
    else {
        return false;
    };
    let (owner, id) = identity
        .split_once('-')
        .map_or((None, identity), |(owner, id)| (Some(owner), id));
    let valid_digest = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    id == instance_id && valid_digest(id) && owner.is_none_or(valid_digest)
}

fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_control)
}

fn valid_limits(limits: &ResourceLimits) -> bool {
    limits
        .memory_max_bytes
        .is_none_or(|value| value > 0 && value <= 1 << 50)
        && limits
            .tasks_max
            .is_none_or(|value| value > 0 && value <= 1_000_000)
        && limits
            .cpu_quota_basis_points
            .is_none_or(|value| value > 0 && value <= 1_000_000)
        && limits.valid_cpu_selection()
}

macro_rules! conversions {
    ($model:ty, $stored:ty, {$($variant:ident),+ $(,)?}) => {
        impl From<$model> for $stored { fn from(value: $model) -> Self { match value { $(<$model>::$variant => Self::$variant),+ } } }
        impl From<$stored> for $model { fn from(value: $stored) -> Self { match value { $(<$stored>::$variant => Self::$variant),+ } } }
    };
}
conversions!(WorkspaceOrigin, StoredWorkspaceOrigin, { Primary, Created, Existing, Directory });
conversions!(InstanceState, StoredInstanceState, { Starting, Running, Stopping, Exited, Failed });
conversions!(ActivityState, StoredActivityState, { Working, Idle, Blocked });

impl From<&ActivityUpdate> for StoredActivity {
    fn from(value: &ActivityUpdate) -> Self {
        Self {
            state: value.state.into(),
            message: value.message.clone(),
        }
    }
}
impl From<StoredActivity> for ActivityUpdate {
    fn from(value: StoredActivity) -> Self {
        Self {
            state: value.state.into(),
            message: value.message,
        }
    }
}
impl From<&HerdrContext> for StoredHerdr {
    fn from(value: &HerdrContext) -> Self {
        Self {
            workspace_id: value.workspace_id.clone(),
            pane_id: value.pane_id.clone(),
            session_name: value.session_name.clone(),
        }
    }
}
impl From<StoredHerdr> for HerdrContext {
    fn from(value: StoredHerdr) -> Self {
        Self {
            workspace_id: value.workspace_id,
            pane_id: value.pane_id,
            session_name: value.session_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRegistry(PathBuf);

    impl TestRegistry {
        fn new(name: &str) -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "runroom-registry-{name}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            Self(directory)
        }

        fn path(&self) -> PathBuf {
            self.0.join("instances.json")
        }
    }

    impl Drop for TestRegistry {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn stale_scope_snapshot_cannot_exit_a_new_live_registration() {
        let fixture = TestRegistry::new("stale-snapshot");
        let mut registry = InstanceRegistry::load(fixture.path()).unwrap();
        let stale_snapshot = Vec::new();
        let launched = record(1, InstanceState::Starting);
        registry.insert(launched.clone()).unwrap();
        let orphans = registry
            .reconcile(&stale_snapshot, |handle| {
                assert_eq!(handle.0, launched.scope_handle);
                Ok(ScopeState::Active)
            })
            .unwrap();
        assert_eq!(orphans, []);
        assert_eq!(
            registry.get(&launched.id).unwrap().state,
            InstanceState::Running
        );
        assert!(registry.has_active_workspace(Path::new("/project")));
        let restored = InstanceRegistry::load(fixture.path()).unwrap();
        assert_eq!(
            restored.get(&launched.id).unwrap().state,
            InstanceState::Running
        );
        assert!(restored.has_active_workspace(Path::new("/project")));
    }

    #[test]
    fn retirement_protection_uses_paths_and_active_state_not_selection_or_project() {
        let target = Path::new("/managed/docs");
        for selection in [
            WorkspaceSelection::Named(WorkspaceName("docs".to_owned())),
            WorkspaceSelection::Here,
        ] {
            for (path, inside) in [
                ("/managed/docs", true),
                ("/managed/docs/subdirectory", true),
                ("/managed/docs-other", false),
                ("/unrelated", false),
            ] {
                for (state, active) in [
                    (InstanceState::Starting, true),
                    (InstanceState::Running, true),
                    (InstanceState::Stopping, true),
                    (InstanceState::Exited, false),
                    (InstanceState::Failed, false),
                ] {
                    let mut instance = record(1, state);
                    instance.workspace.project = ProjectId("different-project".to_owned());
                    instance.workspace.selection = selection.clone();
                    instance.workspace.path = PathBuf::from(path);
                    let registry = InstanceRegistry {
                        path: PathBuf::from("/unused"),
                        records: BTreeMap::from([(instance.id.0.clone(), instance)]),
                    };
                    assert_eq!(
                        registry.has_active_workspace(target),
                        inside && active,
                        "{selection:?} {path} {state:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn registry_exclusivity_survives_path_aliases_and_atomic_persistence() {
        let fixture = TestRegistry::new("lease");
        let lease = RegistryLease::acquire(&fixture.path()).unwrap();
        let alias = fixture.0.join(".").join("instances.json");
        let mut registry = InstanceRegistry::load(lease.path()).unwrap();
        registry.insert(record(1, InstanceState::Running)).unwrap();
        assert_eq!(
            RegistryLease::acquire(&alias).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        registry
            .update(&InstanceId(format!("{:064x}", 1)), |record| {
                record.state = InstanceState::Stopping;
            })
            .unwrap();
        assert_eq!(
            RegistryLease::acquire(&alias).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(lease);
        let replacement = RegistryLease::acquire(&alias).unwrap();
        let restored = InstanceRegistry::load(replacement.path()).unwrap();
        assert_eq!(
            restored
                .get(&InstanceId(format!("{:064x}", 1)))
                .unwrap()
                .state,
            InstanceState::Stopping
        );
    }

    #[test]
    fn recorded_live_legacy_instances_survive_upgrade_and_restart() {
        for version in [1, 2] {
            let fixture = TestRegistry::new("legacy");
            let instance = record(1, InstanceState::Running);
            let mut stored = serde_json::to_value(StoredInstance::from(&instance)).unwrap();
            stored["workspace"].as_object_mut().unwrap().remove("here");
            let limits = stored["limits"].as_object_mut().unwrap();
            limits.remove("cpu_cores");
            limits.remove("cpu_count");
            let bytes = serde_json::to_vec(&serde_json::json!({
                "version": version,
                "instances": [stored],
            }))
            .unwrap();
            fs::write(fixture.path(), bytes).unwrap();
            fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o600)).unwrap();
            let mut registry = InstanceRegistry::load(fixture.path()).unwrap();
            let orphans = registry.reconcile(&[], |_| Ok(ScopeState::Active)).unwrap();
            assert_eq!(orphans, []);
            let restarted = InstanceRegistry::load(fixture.path()).unwrap();
            assert_eq!(restarted.get(&instance.id), Some(&instance));
        }
    }

    #[test]
    fn namespaced_handles_persist_and_cannot_claim_another_instance_identity() {
        let fixture = TestRegistry::new("namespaced");
        let mut registry = InstanceRegistry::load(fixture.path()).unwrap();
        let mut instance = record(1, InstanceState::Running);
        instance.scope_handle = format!("runroom-{}-{}.scope", "a".repeat(64), instance.id.0);
        registry.insert(instance.clone()).unwrap();
        let restored = InstanceRegistry::load(fixture.path()).unwrap();
        assert_eq!(restored.get(&instance.id), Some(&instance));
        instance.scope_handle = format!("runroom-{}-{}.scope", "a".repeat(64), "b".repeat(64));
        assert_eq!(
            InstanceRecord::try_from(StoredInstance::from(&instance))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn directory_records_survive_serialization_and_legacy_records_without_here() {
        let mut original = record(1, InstanceState::Running);
        original.workspace.selection = WorkspaceSelection::Here;
        original.workspace.origin = WorkspaceOrigin::Directory;
        original.workspace.change_name = None;
        let bytes =
            serde_json::to_vec(&StoredInstance::from(&original)).expect("encode directory record");
        let stored: StoredInstance =
            serde_json::from_slice(&bytes).expect("decode directory record");
        let restored = InstanceRecord::try_from(stored).expect("restore directory record");
        assert_eq!(restored, original);

        let legacy = record(2, InstanceState::Running);
        let mut value =
            serde_json::to_value(StoredInstance::from(&legacy)).expect("encode legacy record");
        value["workspace"]
            .as_object_mut()
            .expect("workspace object")
            .remove("here");
        let stored: StoredInstance = serde_json::from_value(value).expect("decode legacy record");
        assert_eq!(
            InstanceRecord::try_from(stored).expect("restore legacy record"),
            legacy
        );
    }

    #[test]
    fn directory_records_reject_inconsistent_selection_and_metadata() {
        let mut original = record(1, InstanceState::Running);
        original.workspace.selection = WorkspaceSelection::Here;
        original.workspace.origin = WorkspaceOrigin::Directory;
        original.workspace.change_name = None;
        let value =
            serde_json::to_value(StoredInstance::from(&original)).expect("encode directory record");
        for (field, malformed) in [
            ("name", serde_json::json!("named")),
            ("here", serde_json::json!(false)),
            ("origin", serde_json::json!("primary")),
            ("primary_checkout", serde_json::json!(b"/parent".to_vec())),
            ("change_name", serde_json::json!("main")),
            (
                "support_mounts",
                serde_json::json!([{
                    "source": b"/parent/.git".to_vec(),
                    "destination": b"/parent/.git".to_vec()
                }]),
            ),
        ] {
            let mut malformed_record = value.clone();
            malformed_record["workspace"][field] = malformed;
            let stored: StoredInstance = serde_json::from_value(malformed_record)
                .expect("decode structurally invalid record");
            let error =
                InstanceRecord::try_from(stored).expect_err("reject inconsistent directory");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{field}");
        }
    }

    fn record(id: usize, state: InstanceState) -> InstanceRecord {
        InstanceRecord {
            id: InstanceId(format!("{id:064x}")),
            scope_handle: format!("runroom-{id:064x}.scope"),
            workspace: ResolvedWorkspace {
                project: ProjectId("project".to_owned()),
                primary_checkout: PathBuf::from("/project"),
                selection: WorkspaceSelection::Primary,
                path: PathBuf::from("/project"),
                change_name: Some("main".to_owned()),
                origin: WorkspaceOrigin::Primary,
                support_mounts: Vec::new(),
            },
            profile: "pi".to_owned(),
            limits: ResourceLimits::default(),
            leader: ProcessId(NonZeroU32::new(1).expect("nonzero")),
            state,
            activity: None,
            herdr: None,
            created_at_ms: id as u64,
            updated_at_ms: id as u64,
        }
    }

    #[test]
    fn legacy_registry_limits_without_cpu_selection_remain_readable() {
        let original = record(1, InstanceState::Running);
        let mut value =
            serde_json::to_value(StoredInstance::from(&original)).expect("encode stored instance");
        let limits = value["limits"].as_object_mut().expect("limits object");
        limits.remove("cpu_cores");
        limits.remove("cpu_count");
        let stored: StoredInstance = serde_json::from_value(value).expect("decode legacy instance");
        let restored = InstanceRecord::try_from(stored).expect("restore legacy instance");
        assert_eq!(restored.limits.cpu_cores, None);
        assert_eq!(restored.limits.cpu_count, None);
    }

    #[test]
    fn invalid_cpu_selections_are_rejected_in_durable_records() {
        for (cores, count) in [
            (Some(vec![]), None),
            (Some(vec![0, 0]), None),
            (Some(vec![1024]), None),
            (None, Some(0)),
            (None, Some(1025)),
            (Some(vec![0]), Some(1)),
        ] {
            let mut instance = record(1, InstanceState::Running);
            instance.limits.cpu_cores = cores;
            instance.limits.cpu_count = count;
            let error = InstanceRecord::try_from(StoredInstance::from(&instance))
                .expect_err("reject invalid persisted CPU selection");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            let mut registry = InstanceRegistry {
                path: PathBuf::from("/unused"),
                records: BTreeMap::new(),
            };
            let error = registry
                .insert(instance)
                .expect_err("reject invalid CPU selection before persistence");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(registry.records, BTreeMap::new());
        }
    }

    #[test]
    fn pruning_discards_old_terminal_records_before_capacity() {
        let mut registry = InstanceRegistry {
            path: PathBuf::from("/unused"),
            records: BTreeMap::new(),
        };
        for id in 0..1_002 {
            let record = record(id, InstanceState::Exited);
            registry.records.insert(record.id.0.clone(), record);
        }
        let active = record(2_000, InstanceState::Running);
        registry.records.insert(active.id.0.clone(), active);
        let _removed = registry.prune_terminal_records(RETAINED_TERMINAL_RECORDS);
        assert_eq!(registry.records.len(), RETAINED_TERMINAL_RECORDS + 1);
        assert!(registry.records.contains_key(&format!("{:064x}", 2_000)));
        assert!(!registry.records.contains_key(&format!("{:064x}", 0)));
    }
}
