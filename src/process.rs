//! One-time process-role selection.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::debug;

mod client;
mod daemon;
mod launcher;
mod registry;

pub use client::HostClient;
pub use daemon::{Daemon, DaemonConfig, LocalCaller};
pub use launcher::{Launcher, LauncherConfig};

static RUN_TOKEN_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Role and role-specific startup state selected once at process startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunMode {
    Daemon(DaemonConfig),
    Launcher(LauncherConfig),
}

/// The only role-specific application object created in this process image.
#[derive(Debug)]
pub enum Application {
    Daemon(Daemon),
    Launcher(Launcher),
}

impl Application {
    /// Run the selected role until its natural completion.
    ///
    /// # Errors
    ///
    /// Returns socket setup, transport, or protocol errors from the selected
    /// concrete role.
    #[tracing::instrument(level = "debug", skip_all, name = "run_application")]
    pub fn run(self) -> io::Result<()> {
        match self {
            Self::Daemon(daemon) => {
                debug!(role = "daemon", "running selected process role");
                daemon.run()
            }
            Self::Launcher(launcher) => {
                debug!(role = "launcher", "running selected process role");
                launcher.run()
            }
        }
    }
}

/// Returned when application startup is attempted more than once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlreadyStarted;

impl Display for AlreadyStarted {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("the process run token has already been claimed")
    }
}

impl Error for AlreadyStarted {}

/// Select exactly one process role for this process image.
///
/// The private, non-`Clone`, non-`Copy` token is consumed by the selected role.
/// Consequently one successful call cannot construct both a daemon and a
/// launcher. The atomic claim also rejects later startup calls at runtime.
///
/// # Errors
///
/// Returns [`AlreadyStarted`] if a role was already selected.
pub fn start(mode: RunMode) -> Result<Application, AlreadyStarted> {
    start_with(&RUN_TOKEN_CLAIMED, mode)
}

#[tracing::instrument(level = "debug", skip_all, name = "start_process_role")]
fn start_with(claimed: &AtomicBool, mode: RunMode) -> Result<Application, AlreadyStarted> {
    let role = match &mode {
        RunMode::Daemon(_) => "daemon",
        RunMode::Launcher(_) => "launcher",
    };
    debug!(role, "claiming process run token");
    let token = RunToken::claim(claimed)?;
    debug!(role, "constructing process role");
    Ok(match mode {
        RunMode::Daemon(config) => Application::Daemon(Daemon::new(token, config)),
        RunMode::Launcher(config) => Application::Launcher(Launcher::new(token, config)),
    })
}

/// Linear capability consumed to construct one process role.
///
/// Both the type and its constructor are private to the process-role module.
/// Role modules can accept it but unrelated modules cannot name it.
struct RunToken {
    _private: (),
}

impl RunToken {
    fn claim(claimed: &AtomicBool) -> Result<Self, AlreadyStarted> {
        claimed
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .map(|_| Self { _private: () })
            .map_err(|_| AlreadyStarted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_process_image_constructs_exactly_one_selected_role() {
        for daemon_mode in [true, false] {
            let claimed = AtomicBool::new(false);
            let mode = test_mode(daemon_mode);
            let application = start_with(&claimed, mode).expect("first role claim should succeed");

            assert!(matches!(
                (daemon_mode, application),
                (true, Application::Daemon(_)) | (false, Application::Launcher(_))
            ));
            assert!(matches!(
                start_with(&claimed, test_mode(daemon_mode)),
                Err(AlreadyStarted)
            ));
        }
    }

    fn test_mode(daemon: bool) -> RunMode {
        let socket_path = std::path::PathBuf::from("/unused/test.sock");
        if daemon {
            RunMode::Daemon(DaemonConfig::new(socket_path, "/unused/workspaces"))
        } else {
            RunMode::Launcher(LauncherConfig::new(
                socket_path,
                "test".to_owned(),
                crate::model::ForegroundCommand {
                    executable: "/bin/true".into(),
                    arguments: Vec::new(),
                },
                crate::model::RuntimePolicy {
                    kind: crate::model::RuntimeKind::Native,
                    network: crate::model::NetworkMode::Host,
                    bind_mounts: Vec::new(),
                    devices: Vec::new(),
                    environment: Vec::new(),
                    home: None,
                },
            ))
        }
    }
}
