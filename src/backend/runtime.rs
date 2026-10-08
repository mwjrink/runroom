//! Outer runtime preparation performed by the foreground launcher.

use std::collections::HashSet;
use std::error::Error;
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path, PathBuf};
use tracing::debug;

use crate::model::{
    BindAccess, BindMountSource, DeviceMount, LaunchSpec, NetworkMode, PreparedExec,
    RuntimeDataFile, RuntimeKind,
};

pub const BUBBLEWRAP_EXECUTABLE: &str = "/usr/bin/bwrap";

/// Converts one daemon-approved launch into the final process image.
pub trait RuntimeBackend: Send + Sync {
    type Error;

    /// Prepare the outer runtime command without starting another process.
    ///
    /// # Errors
    ///
    /// Returns the backend's error when the resolved launch cannot be represented
    /// as a safe executable handoff.
    fn prepare(&self, launch: &LaunchSpec) -> Result<PreparedExec, Self::Error>;
}

/// Direct host execution without namespace confinement.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeRuntimeBackend;

impl RuntimeBackend for NativeRuntimeBackend {
    type Error = RuntimeError;

    #[tracing::instrument(level = "debug", skip_all, name = "prepare_native_runtime")]
    fn prepare(&self, launch: &LaunchSpec) -> Result<PreparedExec, Self::Error> {
        if launch.runtime.kind != RuntimeKind::Native {
            return Err(RuntimeError::WrongBackend {
                expected: RuntimeKind::Native,
                actual: launch.runtime.kind,
            });
        }
        if launch.runtime.network == NetworkMode::Private {
            return Err(RuntimeError::PrivateNetworkRequiresBubblewrap);
        }
        if !launch.runtime.devices.is_empty() {
            return Err(RuntimeError::NativeDevicesUnsupported);
        }
        debug!(
            executable = %launch.command.executable.display(),
            argument_count = launch.command.arguments.len(),
            working_directory = %launch.workspace.path.display(),
            "native runtime prepared"
        );
        Ok(PreparedExec {
            executable: launch.command.executable.clone(),
            arguments: launch.command.arguments.clone(),
            working_directory: launch.workspace.path.clone(),
        })
    }
}

/// Bubblewrap command compiler for one validated launch policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct BubblewrapRuntimeBackend;

impl BubblewrapRuntimeBackend {
    /// Compile a Bubblewrap execution and mount sealed runtime-owned data files.
    ///
    /// Data files beneath host binds use a private overlay of their existing
    /// parent directory. Missing host parents are rejected rather than created,
    /// and sibling agent settings, authentication, and sessions stay persistent.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when the launch targets another backend or its
    /// namespace, mount, command, home, or data-file policy is invalid.
    pub fn prepare_with_data_files(
        launch: &LaunchSpec,
        data_files: &[RuntimeDataFile<'_>],
    ) -> Result<PreparedExec, RuntimeError> {
        Self::prepare_inner(launch, data_files, None)
    }

    /// Compile a private network with the launcher's sealed virtual-DNS resolver.
    ///
    /// The descriptor must contain `nameserver 10.0.2.3\n`, remain open through
    /// Bubblewrap startup, and be inherited by Bubblewrap. Its only destination
    /// is the backend-owned `/etc/resolv.conf`; generic runtime data still cannot
    /// target protected paths.
    ///
    /// # Errors
    ///
    /// Returns an error unless the launch selects private Bubblewrap networking,
    /// the resolver descriptor is non-negative, and its remaining policy is valid.
    pub fn prepare_with_private_resolver(
        launch: &LaunchSpec,
        data_files: &[RuntimeDataFile<'_>],
        resolver_descriptor: RawFd,
    ) -> Result<PreparedExec, RuntimeError> {
        Self::prepare_inner(launch, data_files, Some(resolver_descriptor))
    }

    #[tracing::instrument(level = "debug", skip_all, name = "prepare_bubblewrap_runtime")]
    fn prepare_inner(
        launch: &LaunchSpec,
        data_files: &[RuntimeDataFile<'_>],
        resolver_descriptor: Option<RawFd>,
    ) -> Result<PreparedExec, RuntimeError> {
        debug!(
            network = ?launch.runtime.network,
            profile_mount_count = launch.runtime.bind_mounts.len(),
            support_mount_count = launch.workspace.support_mounts.len(),
            environment_count = launch.runtime.environment.len(),
            data_file_count = data_files.len(),
            "compiling Bubblewrap runtime"
        );
        if launch.runtime.kind != RuntimeKind::Bubblewrap {
            return Err(RuntimeError::WrongBackend {
                expected: RuntimeKind::Bubblewrap,
                actual: launch.runtime.kind,
            });
        }
        Self::validate_data_files(data_files)?;
        Self::validate_private_network(launch, resolver_descriptor)?;
        let home = launch
            .runtime
            .home
            .as_ref()
            .ok_or(RuntimeError::MissingHome)?;
        if !home.is_absolute() {
            return Err(RuntimeError::InvalidHome(home.clone()));
        }

        let (mut mounts, sandbox_working_directory) = resolved_mounts(launch)?;
        validate_devices(&launch.runtime.devices)?;
        mounts.sort_by(|left, right| {
            left.destination
                .components()
                .count()
                .cmp(&right.destination.components().count())
                .then_with(|| left.destination.cmp(&right.destination))
        });
        let data_overlays = private_data_directories(&mounts, data_files)?;

        let mut arguments = Vec::with_capacity(
            48 + mounts.len() * 3
                + launch.runtime.devices.len() * 3
                + data_files.len() * 11
                + data_overlays.len() * 4,
        );
        arguments.extend(
            [
                "--unshare-user",
                "--unshare-ipc",
                "--unshare-pid",
                "--unshare-uts",
                "--die-with-parent",
            ]
            .into_iter()
            .map(OsString::from),
        );
        arguments.push(OsString::from("--clearenv"));
        if launch.runtime.network != NetworkMode::Host {
            arguments.push(OsString::from("--unshare-net"));
        }
        push_triplet(&mut arguments, "--ro-bind", "/usr", "/usr");
        if let Some(descriptor) = resolver_descriptor {
            Self::append_private_etc(&mut arguments, descriptor)?;
        } else {
            push_triplet(&mut arguments, "--ro-bind", "/etc", "/etc");
        }
        push_triplet(&mut arguments, "--symlink", "usr/bin", "/bin");
        push_triplet(&mut arguments, "--symlink", "usr/bin", "/sbin");
        push_triplet(&mut arguments, "--symlink", "usr/lib", "/lib");
        push_triplet(&mut arguments, "--symlink", "usr/lib", "/lib64");
        push_pair(&mut arguments, "--proc", "/proc");
        push_pair(&mut arguments, "--dev", "/dev");
        push_pair(&mut arguments, "--tmpfs", "/dev/shm");
        Self::append_devices(&mut arguments, &launch.runtime.devices);
        if launch.runtime.network == NetworkMode::Private {
            push_triplet(&mut arguments, "--dev-bind", "/dev/net/tun", "/dev/net/tun");
        }
        push_pair(&mut arguments, "--tmpfs", "/tmp");
        push_pair(&mut arguments, "--tmpfs", "/var/tmp");
        push_pair(&mut arguments, "--tmpfs", "/run");
        Self::append_environment(&mut arguments, launch, home);

        Self::append_data_directories(&mut arguments, data_files, &data_overlays)?;
        Self::append_mounts(&mut arguments, mounts, &data_overlays);
        Self::append_data_files(&mut arguments, data_files);
        push_path_pair(&mut arguments, "--chdir", &sandbox_working_directory);
        arguments.push(OsString::from("--"));
        arguments.push(launch.command.executable.as_os_str().to_owned());
        arguments.extend(launch.command.arguments.iter().cloned());

        debug!(
            executable = BUBBLEWRAP_EXECUTABLE,
            argument_count = arguments.len(),
            working_directory = %launch.workspace.path.display(),
            sandbox_working_directory = %sandbox_working_directory.display(),
            "Bubblewrap runtime prepared"
        );
        Ok(PreparedExec {
            executable: PathBuf::from(BUBBLEWRAP_EXECUTABLE),
            arguments,
            working_directory: launch.workspace.path.clone(),
        })
    }

    fn append_data_directories(
        arguments: &mut Vec<OsString>,
        data_files: &[RuntimeDataFile<'_>],
        data_overlays: &[DataDirectoryOverlay],
    ) -> Result<(), RuntimeError> {
        for file in data_files {
            let parent = Path::new(file.destination)
                .parent()
                .ok_or_else(|| RuntimeError::InvalidDestination(PathBuf::from(file.destination)))?;
            if !data_overlays
                .iter()
                .any(|overlay| overlay.destination == parent)
            {
                push_path_pair(arguments, "--dir", parent);
                push_path_pair(arguments, "--tmpfs", parent);
            }
        }
        Ok(())
    }

    fn validate_private_network(
        launch: &LaunchSpec,
        resolver_descriptor: Option<RawFd>,
    ) -> Result<(), RuntimeError> {
        match (launch.runtime.network, resolver_descriptor) {
            (NetworkMode::Private, None) => return Err(RuntimeError::MissingPrivateResolver),
            (NetworkMode::Private, Some(descriptor)) if descriptor < 0 => {
                return Err(RuntimeError::InvalidDataDescriptor);
            }
            (NetworkMode::Private, Some(_)) => {
                validate_private_tun()?;
                if let Some(device) = launch
                    .runtime
                    .devices
                    .iter()
                    .find(|device| Path::new("/dev/net/tun").starts_with(&device.destination))
                {
                    return Err(RuntimeError::ProtectedDestination(
                        device.destination.clone(),
                    ));
                }
            }
            (_, Some(_)) => return Err(RuntimeError::PrivateResolverRequiresPrivateNetwork),
            (_, None) => {}
        }
        Ok(())
    }

    fn append_private_etc(
        arguments: &mut Vec<OsString>,
        resolver_descriptor: RawFd,
    ) -> Result<(), RuntimeError> {
        // A host resolv.conf is commonly a symlink into /run. Bind-mounting onto
        // that symlink is rejected by Bubblewrap; replacing it in the host /etc
        // bind would mutate the host. Project siblings into a private directory
        // instead, retaining symlinks such as mtab rather than dereferencing them.
        push_pair(arguments, "--tmpfs", "/etc");
        let entries = std::fs::read_dir("/etc").map_err(|error| RuntimeError::PrivateEtcIo {
            path: PathBuf::from("/etc"),
            message: error.to_string(),
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| RuntimeError::PrivateEtcIo {
                path: PathBuf::from("/etc"),
                message: error.to_string(),
            })?;
            if entry.file_name() == "resolv.conf" {
                continue;
            }
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| RuntimeError::PrivateEtcIo {
                    path: path.clone(),
                    message: error.to_string(),
                })?;
            if file_type.is_symlink() {
                let target =
                    std::fs::read_link(&path).map_err(|error| RuntimeError::PrivateEtcIo {
                        path: path.clone(),
                        message: error.to_string(),
                    })?;
                arguments.push(OsString::from("--symlink"));
                arguments.push(target.into_os_string());
                arguments.push(path.into_os_string());
            } else {
                arguments.push(OsString::from("--ro-bind"));
                arguments.push(path.as_os_str().to_owned());
                arguments.push(path.into_os_string());
            }
        }
        arguments.push(OsString::from("--ro-bind-data"));
        arguments.push(resolver_descriptor.to_string().into());
        arguments.push(OsString::from("/etc/resolv.conf"));
        push_pair(arguments, "--remount-ro", "/etc");
        Ok(())
    }

    fn append_data_files(arguments: &mut Vec<OsString>, data_files: &[RuntimeDataFile<'_>]) {
        for file in data_files {
            // Keep a named inode: --ro-bind-data unlinks its backing file, so
            // realpath appends " (deleted)" and module loaders cannot import it.
            push_pair(arguments, "--perms", "0400");
            arguments.push(OsString::from("--file"));
            arguments.push(file.descriptor.to_string().into());
            arguments.push(OsString::from(file.destination));
        }
        for file in data_files {
            let parent = Path::new(file.destination)
                .parent()
                .expect("validated data parent");
            push_path_pair(arguments, "--remount-ro", parent);
        }
    }

    fn validate_data_files(data_files: &[RuntimeDataFile<'_>]) -> Result<(), RuntimeError> {
        if data_files.iter().any(|file| file.descriptor < 0) {
            return Err(RuntimeError::InvalidDataDescriptor);
        }
        for file in data_files {
            let destination = Path::new(file.destination);
            if !normalized_absolute_path(destination) {
                return Err(RuntimeError::InvalidDestination(destination.to_owned()));
            }
            if ["/", "/usr", "/etc", "/proc", "/dev"].iter().any(|root| {
                destination == Path::new(root) || *root != "/" && destination.starts_with(root)
            }) {
                return Err(RuntimeError::ProtectedDestination(destination.to_owned()));
            }
        }
        Ok(())
    }

    fn append_devices(arguments: &mut Vec<OsString>, devices: &[DeviceMount]) {
        if devices.is_empty() {
            return;
        }
        // Match Flatpak's read-only device topology, plus module metadata
        // required by NVML. Keep unrelated kernel/firmware sysfs hidden.
        for path in [
            "/sys/block",
            "/sys/bus",
            "/sys/class",
            "/sys/dev",
            "/sys/devices",
            "/sys/module",
        ] {
            push_triplet(arguments, "--ro-bind-try", path, path);
        }
        for device in devices {
            arguments.push(OsString::from("--dev-bind"));
            arguments.push(device.source.as_os_str().to_owned());
            arguments.push(device.destination.as_os_str().to_owned());
        }
    }

    fn append_environment(arguments: &mut Vec<OsString>, launch: &LaunchSpec, home: &Path) {
        push_path_pair(arguments, "--dir", home);
        push_path_pair(arguments, "--setenv", Path::new("HOME"));
        arguments.push(home.as_os_str().to_owned());
        for variable in &launch.runtime.environment {
            push_pair(arguments, "--setenv", &variable.name);
            arguments.push(variable.value.clone());
        }
        if launch.runtime.network == NetworkMode::Host {
            push_triplet(
                arguments,
                "--ro-bind-try",
                "/run/systemd/resolve/stub-resolv.conf",
                "/run/systemd/resolve/stub-resolv.conf",
            );
            push_triplet(
                arguments,
                "--ro-bind-try",
                "/run/systemd/resolve/resolv.conf",
                "/run/systemd/resolve/resolv.conf",
            );
        }
    }
    fn append_mounts(
        arguments: &mut Vec<OsString>,
        mounts: Vec<ResolvedBindMount>,
        data_overlays: &[DataDirectoryOverlay],
    ) {
        for (index, mount) in mounts.into_iter().enumerate() {
            let access = match mount.access {
                BindAccess::ReadOnly => "--ro-bind",
                BindAccess::ReadWrite => "--bind",
            };
            if mount.executable {
                // Preserve script-relative resources and Node's realpath behavior.
                // /usr and /etc are already projected read-only.
                if mount.access == BindAccess::ReadWrite
                    || (!mount.source.starts_with("/usr") && !mount.source.starts_with("/etc"))
                {
                    arguments.push(OsString::from(access));
                    arguments.push(mount.source.as_os_str().to_owned());
                    arguments.push(mount.source.as_os_str().to_owned());
                }
                if mount.source != mount.destination {
                    arguments.push(OsString::from("--symlink"));
                    arguments.push(mount.source.into_os_string());
                    arguments.push(mount.destination.into_os_string());
                }
            } else {
                arguments.push(OsString::from(access));
                arguments.push(mount.source.into_os_string());
                arguments.push(mount.destination.into_os_string());
            }
            for overlay in data_overlays
                .iter()
                .filter(|overlay| overlay.mount_index == index)
            {
                push_path_pair(arguments, "--overlay-src", &overlay.source);
                push_path_pair(arguments, "--tmp-overlay", &overlay.destination);
            }
        }
    }
}

impl RuntimeBackend for BubblewrapRuntimeBackend {
    type Error = RuntimeError;

    fn prepare(&self, launch: &LaunchSpec) -> Result<PreparedExec, Self::Error> {
        Self::prepare_with_data_files(launch, &[])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedBindMount {
    source: PathBuf,
    destination: PathBuf,
    access: BindAccess,
    executable: bool,
}

struct DataDirectoryOverlay {
    mount_index: usize,
    source: PathBuf,
    destination: PathBuf,
}

fn normalized_absolute_path(path: &Path) -> bool {
    let bytes = path.as_os_str().as_bytes();
    path.is_absolute()
        && !bytes.contains(&0)
        && bytes[1..]
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

fn private_data_directories(
    mounts: &[ResolvedBindMount],
    data_files: &[RuntimeDataFile<'_>],
) -> Result<Vec<DataDirectoryOverlay>, RuntimeError> {
    let mut overlays = Vec::<DataDirectoryOverlay>::new();
    for file in data_files {
        let parent = Path::new(file.destination)
            .parent()
            .ok_or_else(|| RuntimeError::InvalidDestination(PathBuf::from(file.destination)))?;
        if overlays.iter().any(|overlay| overlay.destination == parent) {
            continue;
        }
        let Some((mount_index, mount)) = mounts
            .iter()
            .enumerate()
            .filter(|(_, mount)| !mount.executable && parent.starts_with(&mount.destination))
            .max_by_key(|(_, mount)| mount.destination.components().count())
        else {
            continue;
        };
        let suffix = parent
            .strip_prefix(&mount.destination)
            .expect("selected mount contains the data parent");
        let source = mount.source.join(suffix);
        let destination = parent.to_owned();
        match std::fs::symlink_metadata(&source) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(RuntimeError::InvalidDestination(destination)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(RuntimeError::MissingDataParent {
                    source,
                    destination,
                });
            }
            Err(error) => {
                return Err(RuntimeError::DataParentIo {
                    path: source,
                    message: error.to_string(),
                });
            }
        }
        let canonical_source =
            std::fs::canonicalize(&source).map_err(|error| RuntimeError::DataParentIo {
                path: source.clone(),
                message: error.to_string(),
            })?;
        if !canonical_source.starts_with(&mount.source) {
            return Err(RuntimeError::InvalidDestination(destination));
        }
        // A private upper layer prevents mountpoint creation in a host bind.
        // Keep this confined to the existing data parent so agent settings,
        // authentication, and sessions outside it retain their persistence.
        overlays.push(DataDirectoryOverlay {
            mount_index,
            source: canonical_source,
            destination,
        });
    }
    overlays.sort_by_key(|overlay| overlay.destination.components().count());
    Ok(overlays)
}

#[tracing::instrument(level = "debug", skip_all, name = "resolve_runtime_mounts")]
fn resolved_mounts(launch: &LaunchSpec) -> Result<(Vec<ResolvedBindMount>, PathBuf), RuntimeError> {
    let mut mounts = Vec::with_capacity(
        launch.runtime.bind_mounts.len() + launch.workspace.support_mounts.len(),
    );
    let mut destinations = HashSet::with_capacity(mounts.capacity());
    let mut workspace_destination = None;
    for mount in &launch.runtime.bind_mounts {
        let source = match &mount.source {
            BindMountSource::Host(source) | BindMountSource::Executable(source) => source.clone(),
            BindMountSource::Workspace => {
                if workspace_destination
                    .replace(mount.destination.clone())
                    .is_some()
                {
                    return Err(RuntimeError::DuplicateWorkspaceMount);
                }
                launch.workspace.path.clone()
            }
        };
        validate_runtime_mount(&source, &mount.destination)?;
        if !destinations.insert(mount.destination.clone()) {
            return Err(RuntimeError::DuplicateDestination(
                mount.destination.clone(),
            ));
        }
        mounts.push(ResolvedBindMount {
            source,
            destination: mount.destination.clone(),
            access: mount.access,
            executable: matches!(mount.source, BindMountSource::Executable(_)),
        });
    }
    for mount in &launch.workspace.support_mounts {
        validate_runtime_mount(&mount.source, &mount.destination)?;
        if !destinations.insert(mount.destination.clone()) {
            return Err(RuntimeError::DuplicateDestination(
                mount.destination.clone(),
            ));
        }
        mounts.push(ResolvedBindMount {
            source: mount.source.clone(),
            destination: mount.destination.clone(),
            access: launch.support_mount_access,
            executable: false,
        });
    }
    if !launch.runtime.devices.is_empty()
        && let Some(mount) = mounts
            .iter()
            .find(|mount| mount.destination.starts_with("/sys"))
    {
        return Err(RuntimeError::ProtectedDestination(
            mount.destination.clone(),
        ));
    }
    let working_directory = workspace_destination.ok_or(RuntimeError::MissingWorkspaceMount)?;
    debug!(
        mount_count = mounts.len(),
        working_directory = %working_directory.display(),
        "runtime mounts resolved"
    );
    Ok((mounts, working_directory))
}

fn validate_private_tun() -> Result<(), RuntimeError> {
    let metadata = std::fs::metadata("/dev/net/tun")
        .map_err(|error| RuntimeError::PrivateTunUnavailable(error.to_string()))?;
    if !metadata.file_type().is_char_device() {
        return Err(RuntimeError::PrivateTunUnavailable(
            "path is not a character device".to_owned(),
        ));
    }
    Ok(())
}

fn validate_devices(devices: &[DeviceMount]) -> Result<(), RuntimeError> {
    let mut destinations = HashSet::with_capacity(devices.len());
    for device in devices {
        let source = &device.source;
        let destination = &device.destination;
        if !normalized_device_path(source) {
            return Err(RuntimeError::InvalidDeviceSource(source.clone()));
        }
        let canonical =
            std::fs::canonicalize(source).map_err(|error| RuntimeError::DeviceSourceIo {
                path: source.clone(),
                message: error.to_string(),
            })?;
        if canonical.as_os_str() != source.as_os_str() {
            return Err(RuntimeError::InvalidDeviceSource(source.clone()));
        }
        let file_type = std::fs::metadata(source)
            .map_err(|error| RuntimeError::DeviceSourceIo {
                path: source.clone(),
                message: error.to_string(),
            })?
            .file_type();
        if !file_type.is_char_device() && !file_type.is_block_device() {
            return Err(RuntimeError::InvalidDeviceSource(source.clone()));
        }
        if !normalized_device_path(destination) {
            return Err(RuntimeError::InvalidDestination(destination.clone()));
        }
        if [
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
        .any(|protected| destination.starts_with(protected))
        {
            return Err(RuntimeError::ProtectedDestination(destination.clone()));
        }
        if !destinations.insert(destination) {
            return Err(RuntimeError::DuplicateDestination(destination.clone()));
        }
    }
    Ok(())
}

fn normalized_device_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/dev")
        && path.starts_with("/dev")
        && !path.as_os_str().as_bytes().contains(&0)
        && path.as_os_str().as_bytes()[1..]
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

fn validate_runtime_mount(source: &Path, destination: &Path) -> Result<(), RuntimeError> {
    if !source.is_absolute() || source.as_os_str().as_bytes().contains(&0) {
        return Err(RuntimeError::InvalidSource(source.to_owned()));
    }
    if !destination.is_absolute()
        || destination.as_os_str().as_bytes().contains(&0)
        || destination.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(RuntimeError::InvalidDestination(destination.to_owned()));
    }
    if ["/", "/usr", "/etc", "/proc", "/dev", "/run", "/tmp"]
        .iter()
        .any(|root| destination == Path::new(root) || destination.starts_with(root) && *root != "/")
    {
        return Err(RuntimeError::ProtectedDestination(destination.to_owned()));
    }
    Ok(())
}

fn push_pair(arguments: &mut Vec<OsString>, option: &str, value: &str) {
    arguments.push(OsString::from(option));
    arguments.push(OsString::from(value));
}
fn push_triplet(arguments: &mut Vec<OsString>, option: &str, source: &str, destination: &str) {
    arguments.push(OsString::from(option));
    arguments.push(OsString::from(source));
    arguments.push(OsString::from(destination));
}

fn push_path_pair(arguments: &mut Vec<OsString>, option: &str, value: &Path) {
    arguments.push(OsString::from(option));
    arguments.push(value.as_os_str().to_owned());
}

/// Runtime policy or command-compilation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    WrongBackend {
        expected: RuntimeKind,
        actual: RuntimeKind,
    },
    MissingHome,
    InvalidHome(PathBuf),
    MissingWorkspaceMount,
    DuplicateWorkspaceMount,
    InvalidSource(PathBuf),
    InvalidDestination(PathBuf),
    ProtectedDestination(PathBuf),
    InvalidDataDescriptor,
    MissingDataParent {
        source: PathBuf,
        destination: PathBuf,
    },
    DataParentIo {
        path: PathBuf,
        message: String,
    },
    DuplicateDestination(PathBuf),
    NativeDevicesUnsupported,
    PrivateNetworkRequiresBubblewrap,
    MissingPrivateResolver,
    PrivateResolverRequiresPrivateNetwork,
    PrivateTunUnavailable(String),
    PrivateEtcIo {
        path: PathBuf,
        message: String,
    },
    InvalidDeviceSource(PathBuf),
    DeviceSourceIo {
        path: PathBuf,
        message: String,
    },
}

impl Display for RuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivateNetworkRequiresBubblewrap => {
                formatter.write_str("network = \"private\" requires the Bubblewrap runtime")
            }
            Self::MissingPrivateResolver => formatter.write_str(
                "private network requires a launcher-owned resolver containing nameserver 10.0.2.3",
            ),
            Self::PrivateResolverRequiresPrivateNetwork => {
                formatter.write_str("private resolver injection requires network = \"private\"")
            }
            Self::PrivateTunUnavailable(message) => write!(
                formatter,
                "private network requires /dev/net/tun: {message}; enable the kernel TUN device (for example, modprobe tun) before launching",
            ),
            Self::PrivateEtcIo { path, message } => write!(
                formatter,
                "cannot prepare private resolver projection from {}: {message}",
                path.display(),
            ),
            Self::NativeDevicesUnsupported => {
                formatter.write_str("native runtime cannot restrict configured devices")
            }
            Self::InvalidDeviceSource(path) => write!(
                formatter,
                "device source must be a canonical character or block device beneath /dev: {}",
                path.display()
            ),
            Self::DeviceSourceIo { path, message } => write!(
                formatter,
                "cannot inspect runtime device {}: {message}",
                path.display()
            ),
            Self::WrongBackend { expected, actual } => {
                write!(
                    formatter,
                    "runtime backend mismatch: expected {expected:?}, got {actual:?}"
                )
            }
            Self::MissingHome => {
                formatter.write_str("Bubblewrap runtime requires an absolute HOME")
            }
            Self::InvalidHome(path) => {
                write!(
                    formatter,
                    "Bubblewrap HOME must be absolute: {}",
                    path.display()
                )
            }
            Self::MissingWorkspaceMount => {
                formatter.write_str("Bubblewrap runtime requires one workspace bind")
            }
            Self::DuplicateWorkspaceMount => {
                formatter.write_str("Bubblewrap runtime received multiple workspace binds")
            }
            Self::InvalidSource(path) => write!(
                formatter,
                "runtime bind source must be absolute and contain no NUL: {}",
                path.display()
            ),
            Self::InvalidDestination(path) => write!(
                formatter,
                "runtime bind destination must be normalized, absolute, and contain no NUL: {}",
                path.display()
            ),
            Self::ProtectedDestination(path) => write!(
                formatter,
                "runtime bind destination overlaps a protected path: {}",
                path.display()
            ),
            Self::DuplicateDestination(path) => {
                write!(
                    formatter,
                    "duplicate runtime bind destination: {}",
                    path.display()
                )
            }
            Self::InvalidDataDescriptor => {
                formatter.write_str("runtime data file descriptor must be non-negative")
            }
            Self::DataParentIo { path, message } => write!(
                formatter,
                "cannot inspect runtime data directory {}: {message}",
                path.display()
            ),
            Self::MissingDataParent {
                source,
                destination,
            } => write!(
                formatter,
                "runtime data injection requires existing host directory {} projected at {}; create that directory before launching to keep agent settings, authentication, and sessions persistent",
                source.display(),
                destination.display(),
            ),
        }
    }
}

impl Error for RuntimeError {}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};

    use super::*;
    use crate::model::{
        BindMount, ForegroundCommand, ProjectId, ResolvedWorkspace, RuntimePolicy, WorkspaceOrigin,
        WorkspaceSelection, WorkspaceSupportMount,
    };

    fn launch(kind: RuntimeKind, network: NetworkMode) -> LaunchSpec {
        LaunchSpec {
            workspace: ResolvedWorkspace {
                project: ProjectId("project".to_owned()),
                primary_checkout: PathBuf::from("/host/project"),
                selection: WorkspaceSelection::Primary,
                path: PathBuf::from("/host/project"),
                change_name: Some("main".to_owned()),
                origin: WorkspaceOrigin::Primary,
                support_mounts: vec![WorkspaceSupportMount {
                    source: PathBuf::from("/host/project/.git"),
                    destination: PathBuf::from("/workspace/.git"),
                }],
            },
            runtime: RuntimePolicy {
                kind,
                network,
                bind_mounts: vec![
                    BindMount {
                        source: BindMountSource::Workspace,
                        destination: PathBuf::from("/workspace"),
                        access: BindAccess::ReadWrite,
                    },
                    BindMount {
                        source: BindMountSource::Host(PathBuf::from("/home/user/.config/tool")),
                        destination: PathBuf::from("/home/user/.config/tool"),
                        access: BindAccess::ReadOnly,
                    },
                ],
                environment: Vec::new(),
                devices: Vec::new(),
                home: Some(PathBuf::from("/home/user")),
            },
            command: ForegroundCommand {
                executable: PathBuf::from("/usr/bin/python3"),
                arguments: vec![OsString::from("-c"), OsString::from("print('space value')")],
            },
            support_mount_access: BindAccess::ReadWrite,
        }
    }

    fn position(arguments: &[OsString], value: &str) -> usize {
        arguments
            .iter()
            .position(|argument| argument == OsStr::new(value))
            .unwrap_or_else(|| panic!("missing argument {value}"))
    }

    #[test]
    fn native_backend_preserves_command_and_host_working_directory() {
        let launch = launch(RuntimeKind::Native, NetworkMode::Host);
        let prepared = NativeRuntimeBackend
            .prepare(&launch)
            .expect("prepare native");

        assert_eq!(prepared.executable, Path::new("/usr/bin/python3"));
        assert_eq!(prepared.arguments, launch.command.arguments);
        assert_eq!(prepared.working_directory, launch.workspace.path);
    }

    #[test]
    fn bubblewrap_backend_compiles_isolated_policy_and_exact_command_arguments() {
        let launch = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
        let prepared = BubblewrapRuntimeBackend
            .prepare(&launch)
            .expect("prepare Bubblewrap");

        assert_eq!(prepared.executable, Path::new(BUBBLEWRAP_EXECUTABLE));
        assert_eq!(prepared.working_directory, launch.workspace.path);
        assert!(
            prepared
                .arguments
                .contains(&OsString::from("--unshare-net"))
        );
        assert!(
            !prepared
                .arguments
                .contains(&OsString::from("--disable-userns")),
            "the trusted Pi controller must be able to create its inner tool sandbox",
        );
        let workspace = position(&prepared.arguments, "/workspace");
        let git = position(&prepared.arguments, "/workspace/.git");
        assert!(
            workspace < git,
            "parent mount must precede nested Git mount"
        );
        let separator = position(&prepared.arguments, "--");
        assert_eq!(
            &prepared.arguments[separator + 1..],
            &[
                OsString::from("/usr/bin/python3"),
                OsString::from("-c"),
                OsString::from("print('space value')"),
            ]
        );
    }

    #[test]
    fn host_network_retains_namespace_and_adds_resolver_mounts() {
        let launch = launch(RuntimeKind::Bubblewrap, NetworkMode::Host);
        let prepared = BubblewrapRuntimeBackend
            .prepare(&launch)
            .expect("prepare Bubblewrap");

        assert!(
            !prepared
                .arguments
                .contains(&OsString::from("--unshare-net"))
        );
        assert!(
            prepared
                .arguments
                .contains(&OsString::from("/run/systemd/resolve/resolv.conf"))
        );
    }

    #[test]
    fn bubblewrap_backend_requires_exactly_one_workspace_mount() {
        let mut missing = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
        missing
            .runtime
            .bind_mounts
            .retain(|mount| mount.source != BindMountSource::Workspace);
        assert_eq!(
            BubblewrapRuntimeBackend.prepare(&missing),
            Err(RuntimeError::MissingWorkspaceMount)
        );

        let mut duplicate = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
        duplicate.runtime.bind_mounts.push(BindMount {
            source: BindMountSource::Workspace,
            destination: PathBuf::from("/other-workspace"),
            access: BindAccess::ReadOnly,
        });
        assert_eq!(
            BubblewrapRuntimeBackend.prepare(&duplicate),
            Err(RuntimeError::DuplicateWorkspaceMount)
        );
    }

    #[test]
    fn support_mount_destinations_cannot_collide_with_profile_mounts() {
        let mut launch = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
        launch.workspace.support_mounts[0].destination = PathBuf::from("/home/user/.config/tool");

        assert_eq!(
            BubblewrapRuntimeBackend.prepare(&launch),
            Err(RuntimeError::DuplicateDestination(PathBuf::from(
                "/home/user/.config/tool"
            )))
        );
    }

    #[test]
    fn support_mounts_cannot_target_protected_or_unnormalized_paths() {
        let mut protected = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
        protected.workspace.support_mounts[0].destination = PathBuf::from("/etc/runroom-support");
        assert_eq!(
            BubblewrapRuntimeBackend.prepare(&protected),
            Err(RuntimeError::ProtectedDestination(PathBuf::from(
                "/etc/runroom-support"
            )))
        );
        assert!(matches!(
            validate_runtime_mount(
                Path::new("/run/user/1000/bus"),
                Path::new("/run/user/1000/bus"),
            ),
            Err(RuntimeError::ProtectedDestination(_)),
        ));

        let mut unnormalized = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
        unnormalized.workspace.support_mounts[0].destination =
            PathBuf::from("/workspace/../support");
        assert_eq!(
            BubblewrapRuntimeBackend.prepare(&unnormalized),
            Err(RuntimeError::InvalidDestination(PathBuf::from(
                "/workspace/../support"
            )))
        );
    }

    #[test]
    fn launcher_selected_access_applies_to_support_mounts() {
        let mut launch = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
        launch.support_mount_access = BindAccess::ReadOnly;
        let (mounts, _) = resolved_mounts(&launch).expect("resolve mounts");
        assert_eq!(
            mounts.last().expect("support mount").access,
            BindAccess::ReadOnly
        );
        launch.support_mount_access = BindAccess::ReadWrite;
        let (mounts, _) = resolved_mounts(&launch).expect("resolve mounts");
        assert_eq!(
            mounts.last().expect("support mount").access,
            BindAccess::ReadWrite
        );
    }

    fn device(source: &str, destination: &str) -> DeviceMount {
        DeviceMount {
            source: PathBuf::from(source),
            destination: PathBuf::from(destination),
        }
    }

    #[test]
    fn device_destinations_must_be_normalized_and_beneath_dev() {
        for destination in [
            "/dev",
            "/tmp/device",
            "dev/device",
            "/dev/../device",
            "/dev/./device",
            "/dev//device",
            "/dev/device/",
            "/dev/device\0",
        ] {
            let mut launch = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
            launch.runtime.devices = vec![device("/dev/null", destination)];
            assert_eq!(
                BubblewrapRuntimeBackend.prepare(&launch),
                Err(RuntimeError::InvalidDestination(PathBuf::from(destination))),
                "{destination:?}",
            );
        }
    }

    #[test]
    fn devices_cannot_overlay_private_dev_directories_or_links() {
        for destination in [
            "/dev/shm",
            "/dev/shm/device",
            "/dev/pts",
            "/dev/pts/1",
            "/dev/ptmx",
            "/dev/fd",
            "/dev/fd/1",
            "/dev/stdin",
            "/dev/stdout",
            "/dev/stderr",
            "/dev/core",
        ] {
            let mut launch = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
            launch.runtime.devices = vec![device("/dev/null", destination)];
            assert_eq!(
                BubblewrapRuntimeBackend.prepare(&launch),
                Err(RuntimeError::ProtectedDestination(PathBuf::from(
                    destination
                ))),
                "{destination}",
            );
        }
    }

    #[test]
    fn runtime_rejects_non_devices_and_noncanonical_sources() {
        for source in [
            "/dev",
            "/dev/shm",
            "/dev/fd/0",
            "/dev/../dev/null",
            "/etc/passwd",
        ] {
            let mut launch = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
            launch.runtime.devices = vec![device(source, "/dev/test-device")];
            assert_eq!(
                BubblewrapRuntimeBackend.prepare(&launch),
                Err(RuntimeError::InvalidDeviceSource(PathBuf::from(source))),
                "{source}",
            );
        }
    }

    #[test]
    fn missing_device_source_is_an_error_not_an_omitted_grant() {
        let mut launch = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
        launch.runtime.devices = vec![device(
            "/dev/runroom-nonexistent-regression-device",
            "/dev/test-device",
        )];
        assert!(matches!(
            BubblewrapRuntimeBackend.prepare(&launch),
            Err(RuntimeError::DeviceSourceIo { .. }),
        ));
    }

    #[test]
    fn device_destinations_cannot_be_duplicated() {
        let mut launch = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
        launch.runtime.devices = vec![
            device("/dev/null", "/dev/test-device"),
            device("/dev/zero", "/dev/test-device"),
        ];
        assert_eq!(
            BubblewrapRuntimeBackend.prepare(&launch),
            Err(RuntimeError::DuplicateDestination(PathBuf::from(
                "/dev/test-device"
            ))),
        );
    }

    #[test]
    fn native_execution_rejects_device_policy() {
        let mut launch = launch(RuntimeKind::Native, NetworkMode::Host);
        launch.runtime.devices = vec![device("/dev/null", "/dev/test-device")];
        assert_eq!(
            NativeRuntimeBackend.prepare(&launch),
            Err(RuntimeError::NativeDevicesUnsupported),
        );
    }

    #[test]
    fn native_execution_rejects_private_network_policy() {
        let launch = launch(RuntimeKind::Native, NetworkMode::Private);
        assert_eq!(
            NativeRuntimeBackend.prepare(&launch),
            Err(RuntimeError::PrivateNetworkRequiresBubblewrap),
        );
    }

    #[test]
    fn private_network_requires_explicit_backend_owned_resolver() {
        let launch = launch(RuntimeKind::Bubblewrap, NetworkMode::Private);
        assert_eq!(
            BubblewrapRuntimeBackend.prepare(&launch),
            Err(RuntimeError::MissingPrivateResolver),
        );
        assert_eq!(
            BubblewrapRuntimeBackend::prepare_with_private_resolver(&launch, &[], -1),
            Err(RuntimeError::InvalidDataDescriptor),
        );
        assert_eq!(
            BubblewrapRuntimeBackend::prepare_with_private_resolver(
                &launch,
                &[RuntimeDataFile {
                    descriptor: 7,
                    destination: "/etc/resolv.conf",
                }],
                8,
            ),
            Err(RuntimeError::ProtectedDestination(PathBuf::from(
                "/etc/resolv.conf"
            ))),
        );
    }

    #[test]
    fn resolver_override_is_confined_to_private_network_policy() {
        for network in [NetworkMode::None, NetworkMode::Host] {
            let launch = launch(RuntimeKind::Bubblewrap, network);
            assert_eq!(
                BubblewrapRuntimeBackend::prepare_with_private_resolver(&launch, &[], 7),
                Err(RuntimeError::PrivateResolverRequiresPrivateNetwork),
            );
        }
    }

    #[test]
    fn ordinary_binds_cannot_override_read_only_driver_sysfs() {
        let mut launch = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
        launch.runtime.devices = vec![device("/dev/null", "/dev/test-device")];
        launch.runtime.bind_mounts.push(BindMount {
            source: BindMountSource::Host(PathBuf::from("/sys")),
            destination: PathBuf::from("/sys"),
            access: BindAccess::ReadWrite,
        });
        assert_eq!(
            BubblewrapRuntimeBackend.prepare(&launch),
            Err(RuntimeError::ProtectedDestination(PathBuf::from("/sys"))),
        );
    }

    #[test]
    fn missing_bound_data_parent_requires_explicit_host_directory_creation() {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut launch = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
        launch.runtime.bind_mounts.push(BindMount {
            source: BindMountSource::Host(source.clone()),
            destination: PathBuf::from("/agent"),
            access: BindAccess::ReadWrite,
        });
        let error = BubblewrapRuntimeBackend::prepare_with_data_files(
            &launch,
            &[RuntimeDataFile {
                descriptor: 7,
                destination: "/agent/runroom-missing-test-parent/extensions/runroom-agent-state.ts",
            }],
        )
        .unwrap_err();
        assert_eq!(
            error,
            RuntimeError::MissingDataParent {
                source: source.join("runroom-missing-test-parent/extensions"),
                destination: PathBuf::from("/agent/runroom-missing-test-parent/extensions"),
            },
        );
    }

    #[test]
    fn data_file_destinations_must_be_normalized_and_outside_protected_host_roots() {
        let launch = launch(RuntimeKind::Bubblewrap, NetworkMode::None);
        for destination in [
            "relative",
            "/runtime/../extension",
            "/runtime/./extension",
            "/runtime//extension",
            "/runtime/extension\0",
        ] {
            assert_eq!(
                BubblewrapRuntimeBackend::prepare_with_data_files(
                    &launch,
                    &[RuntimeDataFile {
                        descriptor: 7,
                        destination
                    }],
                ),
                Err(RuntimeError::InvalidDestination(PathBuf::from(destination))),
            );
        }
        for destination in ["/usr/extension", "/etc/extension"] {
            assert_eq!(
                BubblewrapRuntimeBackend::prepare_with_data_files(
                    &launch,
                    &[RuntimeDataFile {
                        descriptor: 7,
                        destination
                    }],
                ),
                Err(RuntimeError::ProtectedDestination(PathBuf::from(
                    destination
                ))),
            );
        }
    }
}
