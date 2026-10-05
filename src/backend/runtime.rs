//! Outer runtime preparation performed by the foreground launcher.

use std::collections::HashSet;
use std::error::Error;
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use tracing::debug;

use crate::model::{
    BindAccess, BindMountSource, LaunchSpec, NetworkMode, PreparedExec, RuntimeDataFile,
    RuntimeKind,
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
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when the launch targets another backend or its
    /// namespace, mount, command, home, or data-file policy is invalid.
    #[tracing::instrument(level = "debug", skip_all, name = "prepare_bubblewrap_runtime")]
    pub fn prepare_with_data_files(
        &self,
        launch: &LaunchSpec,
        data_files: &[RuntimeDataFile],
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
        if data_files.iter().any(|file| file.descriptor < 0) {
            return Err(RuntimeError::InvalidDataDescriptor);
        }
        let home = launch
            .runtime
            .home
            .as_ref()
            .ok_or(RuntimeError::MissingHome)?;
        if !home.is_absolute() {
            return Err(RuntimeError::InvalidHome(home.clone()));
        }

        let (mut mounts, sandbox_working_directory) = resolved_mounts(launch)?;
        mounts.sort_by(|left, right| {
            left.destination
                .components()
                .count()
                .cmp(&right.destination.components().count())
                .then_with(|| left.destination.cmp(&right.destination))
        });

        let mut arguments = Vec::with_capacity(48 + mounts.len() * 3);
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
        if launch.runtime.network == NetworkMode::None {
            arguments.push(OsString::from("--unshare-net"));
        }
        push_triplet(&mut arguments, "--ro-bind", "/usr", "/usr");
        push_triplet(&mut arguments, "--ro-bind", "/etc", "/etc");
        push_triplet(&mut arguments, "--symlink", "usr/bin", "/bin");
        push_triplet(&mut arguments, "--symlink", "usr/bin", "/sbin");
        push_triplet(&mut arguments, "--symlink", "usr/lib", "/lib");
        push_triplet(&mut arguments, "--symlink", "usr/lib", "/lib64");
        push_pair(&mut arguments, "--proc", "/proc");
        push_pair(&mut arguments, "--dev", "/dev");
        push_pair(&mut arguments, "--tmpfs", "/dev/shm");
        push_pair(&mut arguments, "--tmpfs", "/tmp");
        push_pair(&mut arguments, "--tmpfs", "/var/tmp");
        push_pair(&mut arguments, "--tmpfs", "/run");
        Self::append_environment(&mut arguments, launch, home);

        for mount in mounts {
            arguments.push(OsString::from(match mount.access {
                BindAccess::ReadOnly => "--ro-bind",
                BindAccess::ReadWrite => "--bind",
            }));
            arguments.push(mount.source.into_os_string());
            arguments.push(mount.destination.into_os_string());
        }
        for file in data_files {
            push_pair(&mut arguments, "--perms", "0400");
            push_pair(
                &mut arguments,
                "--ro-bind-data",
                &file.descriptor.to_string(),
            );
            arguments.push(OsString::from(file.destination));
        }
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
}
impl RuntimeBackend for BubblewrapRuntimeBackend {
    type Error = RuntimeError;

    fn prepare(&self, launch: &LaunchSpec) -> Result<PreparedExec, Self::Error> {
        self.prepare_with_data_files(launch, &[])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedBindMount {
    source: PathBuf,
    destination: PathBuf,
    access: BindAccess,
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
            BindMountSource::Host(source) => source.clone(),
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
        });
    }
    let working_directory = workspace_destination.ok_or(RuntimeError::MissingWorkspaceMount)?;
    debug!(
        mount_count = mounts.len(),
        working_directory = %working_directory.display(),
        "runtime mounts resolved"
    );
    Ok((mounts, working_directory))
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
    DuplicateDestination(PathBuf),
}

impl Display for RuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
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
}
