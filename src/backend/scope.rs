//! Process-tree supervision owned by the host daemon.

use std::collections::HashSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use nix::sched::{CpuSet, sched_getaffinity};
use nix::unistd::Pid;
use sha2::{Digest, Sha256};
use tracing::debug;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, Value};

use crate::model::{InstanceId, ProcessId, ResourceLimits, StopMode};

const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const UNIT_PREFIX: &str = "runroom-";
const UNIT_SUFFIX: &str = ".scope";
const ATTACH_TIMEOUT: Duration = Duration::from_secs(5);
const ATTACH_POLL_INTERVAL: Duration = Duration::from_millis(5);

type SystemdUnit = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);

/// Opaque backend identity for one supervised process tree.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ScopeHandle(pub String);

/// Request to attach the launcher's existing PID to a new managed scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeAttachment {
    pub instance_id: InstanceId,
    pub leader: ProcessId,
    pub limits: ResourceLimits,
    pub description: String,
}

/// Backend-neutral scope liveness used during cleanup and restart reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeState {
    Starting,
    Active,
    Stopping,
    Inactive,
    Failed,
}

/// Controls and observes complete descendant process trees.
pub trait ScopeBackend: Send + Sync {
    type Error;

    /// Attach an already-running launcher PID and return its durable scope handle.
    ///
    /// # Errors
    ///
    /// Returns the backend error when the process cannot be attached.
    fn attach(&self, request: ScopeAttachment) -> Result<ScopeHandle, Self::Error>;

    /// Return current liveness for a previously attached scope.
    ///
    /// # Errors
    ///
    /// Returns the backend error when scope state cannot be read.
    fn inspect(&self, handle: &ScopeHandle) -> Result<ScopeState, Self::Error>;

    /// Stop every process still contained by the scope.
    ///
    /// # Errors
    ///
    /// Returns the backend error when scope termination cannot be requested.
    fn stop(&self, handle: &ScopeHandle, mode: StopMode) -> Result<(), Self::Error>;

    /// Enumerate scopes owned by this backend's registry for restart reconciliation.
    ///
    /// # Errors
    ///
    /// Returns the backend error when managed scopes cannot be enumerated.
    fn list_managed(&self) -> Result<Vec<ScopeHandle>, Self::Error>;

    /// Resolve a socket peer PID to its managed instance, if any.
    ///
    /// # Errors
    ///
    /// Returns the backend error when process ownership cannot be resolved.
    fn resolve_process(&self, process: ProcessId) -> Result<Option<InstanceId>, Self::Error>;
}

/// Linux process-tree supervision through transient systemd user scopes.
#[derive(Debug)]
pub struct SystemdScopeBackend {
    connection: Connection,
    ownership: ScopeOwnership,
}

impl SystemdScopeBackend {
    /// Connect to the current user's manager for one durable registry owner.
    ///
    /// Only legacy scopes explicitly present in `recorded` are accessible.
    /// Unrecorded legacy scopes are never enumerated, adopted, or stopped.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid registry path, foreign recorded scope,
    /// or unavailable user manager.
    #[tracing::instrument(level = "debug", skip_all, name = "connect_systemd_scope_backend")]
    pub fn connect(
        registry_path: &Path,
        recorded: &[ScopeHandle],
    ) -> Result<Self, SystemdScopeError> {
        let ownership = ScopeOwnership::new(registry_path, recorded)?;
        Ok(Self {
            connection: Connection::session()?,
            ownership,
        })
    }

    fn manager(&self) -> Result<Proxy<'_>, SystemdScopeError> {
        Proxy::new(
            &self.connection,
            SYSTEMD_DESTINATION,
            SYSTEMD_MANAGER_PATH,
            SYSTEMD_MANAGER_INTERFACE,
        )
        .map_err(SystemdScopeError::from)
    }

    fn unit(&self, path: OwnedObjectPath) -> Result<Proxy<'_>, SystemdScopeError> {
        Proxy::new(
            &self.connection,
            SYSTEMD_DESTINATION,
            path,
            SYSTEMD_UNIT_INTERFACE,
        )
        .map_err(SystemdScopeError::from)
    }

    fn unit_path(&self, handle: &ScopeHandle) -> Result<OwnedObjectPath, SystemdScopeError> {
        self.ownership.authorize(handle)?;
        self.manager()?
            .call("GetUnit", &(handle.0.as_str(),))
            .map_err(SystemdScopeError::from)
    }
}

/// Scope identity is derived from the canonical registry pathname, not a socket
/// or daemon PID, so isolated registries stay isolated across daemon restarts.
#[derive(Debug)]
struct ScopeOwnership {
    prefix: String,
    legacy: HashSet<String>,
}

impl ScopeOwnership {
    fn new(registry_path: &Path, recorded: &[ScopeHandle]) -> Result<Self, SystemdScopeError> {
        let invalid_path = || {
            SystemdScopeError::Ownership(io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry path must be absolute and have a file name",
            ))
        };
        if !registry_path.is_absolute() {
            return Err(invalid_path());
        }
        let parent = registry_path.parent().ok_or_else(invalid_path)?;
        let name = registry_path.file_name().ok_or_else(invalid_path)?;
        let canonical = parent
            .canonicalize()
            .map_err(SystemdScopeError::Ownership)?
            .join(name);
        let owner = Sha256::digest(canonical.as_os_str().as_bytes());
        let mut ownership = Self {
            prefix: format!("{UNIT_PREFIX}{owner:x}-"),
            legacy: HashSet::new(),
        };
        for handle in recorded {
            if ownership.owned_id(&handle.0).is_some() {
                continue;
            }
            if legacy_instance_id(&handle.0).is_none() {
                return Err(SystemdScopeError::ForeignScope(handle.clone()));
            }
            ownership.legacy.insert(handle.0.clone());
        }
        Ok(ownership)
    }

    fn handle(&self, instance: &InstanceId) -> Result<ScopeHandle, SystemdScopeError> {
        if !valid_instance_id(&instance.0) {
            return Err(SystemdScopeError::Ownership(io::Error::new(
                io::ErrorKind::InvalidInput,
                "scope instance ID must be a lowercase SHA-256 digest",
            )));
        }
        Ok(ScopeHandle(format!(
            "{}{}{UNIT_SUFFIX}",
            self.prefix, instance.0
        )))
    }

    fn owned_id<'a>(&self, name: &'a str) -> Option<&'a str> {
        let id = name.strip_prefix(&self.prefix)?.strip_suffix(UNIT_SUFFIX)?;
        valid_instance_id(id).then_some(id)
    }

    fn instance(&self, name: &str) -> Option<InstanceId> {
        self.owned_id(name)
            .or_else(|| {
                self.legacy
                    .contains(name)
                    .then(|| legacy_instance_id(name))
                    .flatten()
            })
            .map(|id| InstanceId(id.to_owned()))
    }

    fn authorize(&self, handle: &ScopeHandle) -> Result<(), SystemdScopeError> {
        if self.owned_id(&handle.0).is_some() || self.legacy.contains(&handle.0) {
            Ok(())
        } else {
            Err(SystemdScopeError::ForeignScope(handle.clone()))
        }
    }
}

impl ScopeBackend for SystemdScopeBackend {
    type Error = SystemdScopeError;

    #[tracing::instrument(level = "debug", skip_all, name = "attach_systemd_scope")]
    fn attach(&self, request: ScopeAttachment) -> Result<ScopeHandle, Self::Error> {
        let handle = self.ownership.handle(&request.instance_id)?;
        debug!(
            instance = %request.instance_id.0,
            scope = %handle.0,
            leader_pid = request.leader.0.get(),
            memory_max_bytes = ?request.limits.memory_max_bytes,
            tasks_max = ?request.limits.tasks_max,
            cpu_quota_basis_points = ?request.limits.cpu_quota_basis_points,
            cpu_cores = ?request.limits.cpu_cores,
            cpu_count = ?request.limits.cpu_count,
            "starting transient systemd scope"
        );
        let cpu_mask = if request.limits.cpu_cores.is_some() || request.limits.cpu_count.is_some() {
            let pid = i32::try_from(request.leader.0.get())
                .map_err(|_| io::Error::other("launcher PID exceeds the Linux PID range"))?;
            let available = sched_getaffinity(Pid::from_raw(pid)).map_err(io::Error::from)?;
            selected_cpu_mask(&request.limits, &available)?
        } else {
            None
        };
        let mut properties = vec![
            ("Description", Value::from(request.description.as_str())),
            ("PIDs", Value::from(vec![request.leader.0.get()])),
            ("CollectMode", Value::from("inactive-or-failed")),
        ];
        if let Some(memory_max) = request.limits.memory_max_bytes {
            properties.push(("MemoryMax", Value::from(memory_max)));
        }
        if let Some(tasks_max) = request.limits.tasks_max {
            properties.push(("TasksMax", Value::from(tasks_max)));
        }
        if let Some(cpu_quota) = request.limits.cpu_quota_basis_points {
            properties.push((
                "CPUQuotaPerSecUSec",
                Value::from(u64::from(cpu_quota) * 100),
            ));
        }
        if let Some(mask) = &cpu_mask {
            properties.push((
                "AllowedCPUs",
                Value::from(zbus::zvariant::Array::from(mask)),
            ));
        }
        let auxiliary = Vec::<(&str, Vec<(&str, Value<'_>)>)>::new();
        let _: OwnedObjectPath = self.manager()?.call(
            "StartTransientUnit",
            &(handle.0.as_str(), "fail", properties, auxiliary),
        )?;
        let started = Instant::now();
        let deadline = started + ATTACH_TIMEOUT;
        while self.resolve_process(request.leader)? != Some(request.instance_id.clone()) {
            if Instant::now() >= deadline {
                return Err(SystemdScopeError::AttachTimeout {
                    process: request.leader,
                    scope: handle.clone(),
                });
            }
            thread::sleep(ATTACH_POLL_INTERVAL);
        }
        if let Some(expected) = &cpu_mask {
            let scope = Proxy::new(
                &self.connection,
                SYSTEMD_DESTINATION,
                self.unit_path(&handle)?,
                "org.freedesktop.systemd1.Scope",
            )?;
            let effective: Vec<u8> = scope.get_property("EffectiveCPUs")?;
            let matches = effective
                .iter()
                .enumerate()
                .all(|(index, byte)| *byte == expected.get(index).copied().unwrap_or(0))
                && expected
                    .iter()
                    .enumerate()
                    .all(|(index, byte)| *byte == effective.get(index).copied().unwrap_or(0));
            if !matches {
                let _ = self.stop(&handle, StopMode::Force);
                return Err(io::Error::other(
                    "systemd did not enforce the requested CPU set; cpuset delegation is required",
                )
                .into());
            }
        }
        debug!(
            instance = %request.instance_id.0,
            scope = %handle.0,
            elapsed_ms = started.elapsed().as_millis(),
            "transient systemd scope active"
        );
        Ok(handle)
    }

    fn inspect(&self, handle: &ScopeHandle) -> Result<ScopeState, Self::Error> {
        let path = match self.unit_path(handle) {
            Ok(path) => path,
            Err(SystemdScopeError::Bus(error)) if is_missing_unit(&error) => {
                return Ok(ScopeState::Inactive);
            }
            Err(error) => return Err(error),
        };
        let active_state: String = self.unit(path)?.get_property("ActiveState")?;
        match active_state.as_str() {
            "activating" | "reloading" => Ok(ScopeState::Starting),
            "active" => Ok(ScopeState::Active),
            "deactivating" => Ok(ScopeState::Stopping),
            "inactive" => Ok(ScopeState::Inactive),
            "failed" => Ok(ScopeState::Failed),
            state => Err(SystemdScopeError::UnknownState(state.to_owned())),
        }
    }

    fn stop(&self, handle: &ScopeHandle, mode: StopMode) -> Result<(), Self::Error> {
        self.ownership.authorize(handle)?;
        let manager = self.manager()?;
        if mode == StopMode::Force {
            let killed: Result<(), zbus::Error> =
                manager.call("KillUnit", &(handle.0.as_str(), "all", 9_i32));
            if let Err(error) = killed {
                if is_missing_unit(&error) {
                    return Ok(());
                }
                return Err(error.into());
            }
        }
        let stopped: Result<OwnedObjectPath, zbus::Error> =
            manager.call("StopUnit", &(handle.0.as_str(), "replace"));
        match stopped {
            Ok(_) => Ok(()),
            Err(error) if is_missing_unit(&error) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    #[tracing::instrument(level = "debug", skip_all, name = "list_managed_systemd_scopes")]
    fn list_managed(&self) -> Result<Vec<ScopeHandle>, Self::Error> {
        let states = Vec::<&str>::new();
        let patterns = vec![format!("{}*{UNIT_SUFFIX}", self.ownership.prefix)];
        let units: Vec<SystemdUnit> = self
            .manager()?
            .call("ListUnitsByPatterns", &(states, patterns))?;
        let managed = units
            .into_iter()
            .filter(|unit| self.ownership.owned_id(&unit.0).is_some())
            .map(|unit| ScopeHandle(unit.0))
            .collect::<Vec<_>>();
        debug!(scope_count = managed.len(), "listed managed systemd scopes");
        Ok(managed)
    }

    fn resolve_process(&self, process: ProcessId) -> Result<Option<InstanceId>, Self::Error> {
        let path: OwnedObjectPath = match self.manager()?.call("GetUnitByPID", &(process.0.get(),))
        {
            Ok(path) => path,
            Err(error) if is_missing_unit(&error) || is_missing_process(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let unit_name: String = self.unit(path)?.get_property("Id")?;
        Ok(self.ownership.instance(&unit_name))
    }
}

/// Failure returned by the systemd scope backend.
#[derive(Debug)]
pub enum SystemdScopeError {
    Bus(zbus::Error),
    CpuSelection(io::Error),
    Ownership(io::Error),
    ForeignScope(ScopeHandle),
    UnknownState(String),
    AttachTimeout {
        process: ProcessId,
        scope: ScopeHandle,
    },
}

impl Display for SystemdScopeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bus(error) => write!(formatter, "systemd user manager: {error}"),
            Self::CpuSelection(error) => write!(formatter, "CPU selection: {error}"),
            Self::Ownership(error) => write!(formatter, "scope ownership: {error}"),
            Self::ForeignScope(handle) => write!(
                formatter,
                "scope {} does not belong to this instance registry",
                handle.0
            ),
            Self::UnknownState(state) => write!(formatter, "unknown systemd unit state: {state}"),
            Self::AttachTimeout { process, scope } => write!(
                formatter,
                "timed out attaching PID {} to {}",
                process.0, scope.0
            ),
        }
    }
}

impl Error for SystemdScopeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bus(error) => Some(error),
            Self::CpuSelection(error) | Self::Ownership(error) => Some(error),
            Self::UnknownState(_) | Self::AttachTimeout { .. } | Self::ForeignScope(_) => None,
        }
    }
}

impl From<zbus::Error> for SystemdScopeError {
    fn from(error: zbus::Error) -> Self {
        Self::Bus(error)
    }
}

impl From<io::Error> for SystemdScopeError {
    fn from(error: io::Error) -> Self {
        Self::CpuSelection(error)
    }
}

fn selected_cpu_mask(limits: &ResourceLimits, available: &CpuSet) -> io::Result<Option<Vec<u8>>> {
    if !limits.valid_cpu_selection() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid CPU selection",
        ));
    }
    if limits.cpu_cores.is_none() && limits.cpu_count.is_none() {
        return Ok(None);
    }
    let mut mask = Vec::new();
    let required = limits.cpu_count.unwrap_or_else(|| {
        u32::try_from(limits.cpu_cores.as_ref().map_or(0, Vec::len)).unwrap_or(u32::MAX)
    });
    let mut selected = 0;
    for cpu in 0..CpuSet::count() {
        let requested = limits.cpu_cores.as_ref().map_or_else(
            || selected < limits.cpu_count.unwrap_or(0),
            |cores| u32::try_from(cpu).is_ok_and(|cpu| cores.contains(&cpu)),
        );
        if !requested {
            continue;
        }
        if !available.is_set(cpu).map_err(io::Error::from)? {
            if limits.cpu_cores.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("CPU {cpu} is unavailable to the launcher"),
                ));
            }
            continue;
        }
        mask.resize(cpu / 8 + 1, 0);
        mask[cpu / 8] |= 1 << (cpu % 8);
        selected += 1;
        if selected == required {
            break;
        }
    }
    if selected != required {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("requested {required} CPUs, but only {selected} are available"),
        ));
    }
    Ok(Some(mask))
}

fn legacy_instance_id(unit_name: &str) -> Option<&str> {
    let name = unit_name
        .strip_prefix(UNIT_PREFIX)?
        .strip_suffix(UNIT_SUFFIX)?;
    valid_instance_id(name).then_some(name)
}

fn valid_instance_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_missing_unit(error: &zbus::Error) -> bool {
    matches!(
        error,
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit"
                || name.as_str() == "org.freedesktop.systemd1.UnitMasked"
    )
}

fn is_missing_process(error: &zbus::Error) -> bool {
    matches!(
        error,
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.systemd1.NoSuchProcess"
                || name.as_str() == "org.freedesktop.DBus.Error.UnixProcessIdUnknown"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_selects_lowest_available_cpus_and_rejects_oversubscription() {
        let mut available = CpuSet::new();
        for cpu in [3, 9, 15] {
            available.set(cpu).unwrap();
        }
        let mut limits = ResourceLimits {
            cpu_count: Some(2),
            ..ResourceLimits::default()
        };
        assert_eq!(
            selected_cpu_mask(&limits, &available).unwrap(),
            Some(vec![8, 2])
        );
        limits.cpu_count = Some(4);
        assert_eq!(
            selected_cpu_mask(&limits, &available).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn explicit_cpus_preserve_sparse_ids_and_reject_unavailable_cpus() {
        let mut available = CpuSet::new();
        for cpu in [3, 9, 15] {
            available.set(cpu).unwrap();
        }
        let mut limits = ResourceLimits {
            cpu_cores: Some(vec![15, 3]),
            ..ResourceLimits::default()
        };
        assert_eq!(
            selected_cpu_mask(&limits, &available).unwrap(),
            Some(vec![8, 128])
        );
        limits.cpu_cores = Some(vec![3, 8]);
        assert_eq!(
            selected_cpu_mask(&limits, &available).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn registry_owners_cannot_resolve_or_control_each_others_scopes() {
        let directory = std::env::temp_dir();
        let first_path = directory.join("runroom-owner-a.json");
        let second_path = directory.join("runroom-owner-b.json");
        let first = ScopeOwnership::new(&first_path, &[]).unwrap();
        let second = ScopeOwnership::new(&second_path, &[]).unwrap();
        let id = InstanceId("a".repeat(64));
        let first_handle = first.handle(&id).unwrap();
        let second_handle = second.handle(&id).unwrap();
        assert_eq!(first.instance(&first_handle.0), Some(id.clone()));
        assert_eq!(second.instance(&second_handle.0), Some(id));
        assert_eq!(second.instance(&first_handle.0), None);
        assert_eq!(first.instance(&second_handle.0), None);
        assert!(matches!(
            second.authorize(&first_handle),
            Err(SystemdScopeError::ForeignScope(_))
        ));
        assert!(matches!(
            first.authorize(&second_handle),
            Err(SystemdScopeError::ForeignScope(_))
        ));
        assert!(matches!(
            ScopeOwnership::new(&first_path, &[second_handle]),
            Err(SystemdScopeError::ForeignScope(_))
        ));
    }

    #[test]
    fn restart_preserves_owned_scopes_and_only_recorded_legacy_scopes() {
        let directory = std::env::temp_dir();
        let path = directory.join("runroom-legacy-owner.json");
        let legacy_id = InstanceId("a".repeat(64));
        let legacy = ScopeHandle(format!("runroom-{}.scope", legacy_id.0));
        let unrecorded = ScopeHandle(format!("runroom-{}.scope", "b".repeat(64)));
        let initial = ScopeOwnership::new(&path, std::slice::from_ref(&legacy)).unwrap();
        let id = InstanceId("c".repeat(64));
        let handle = initial.handle(&id).unwrap();
        let alias = directory.join(".").join("runroom-legacy-owner.json");
        let restarted = ScopeOwnership::new(&alias, &[legacy.clone(), handle.clone()]).unwrap();
        assert_eq!(restarted.instance(&handle.0), Some(id));
        assert_eq!(restarted.instance(&legacy.0), Some(legacy_id));
        assert_eq!(restarted.instance(&unrecorded.0), None);
        assert!(matches!(
            restarted.authorize(&unrecorded),
            Err(SystemdScopeError::ForeignScope(_))
        ));
        let isolated = ScopeOwnership::new(&directory.join("runroom-isolated.json"), &[]).unwrap();
        assert_eq!(isolated.instance(&legacy.0), None);
        assert!(matches!(
            isolated.authorize(&legacy),
            Err(SystemdScopeError::ForeignScope(_))
        ));
    }
}
