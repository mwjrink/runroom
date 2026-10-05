//! Typed Docker Compose adapter for daemon-owned project services.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;

use crate::model::ServiceAction;

const DOCKER: &str = "/usr/bin/docker";
const MAX_SERVICE_OUTPUT_BYTES: usize = 64 * 1024;
pub(crate) const SERVICE_TIMEOUT: Duration = Duration::from_secs(110);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const REAP_DEADLINE: Duration = Duration::from_secs(2);

/// Docker Compose invocation inputs already resolved by daemon orchestration.
pub(crate) struct ServiceInvocation<'a> {
    pub action: ServiceAction,
    pub project_root: &'a Path,
    pub compose_file: &'a Path,
    pub environment: &'a BTreeMap<String, String>,
    pub deadline: Instant,
}

/// Typed adapter for the fixed project service stack.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DockerComposeBackend;

impl DockerComposeBackend {
    pub(crate) fn execute(invocation: &ServiceInvocation<'_>) -> Result<String, ServiceError> {
        if invocation.action == ServiceAction::Config {
            return Err(ServiceError::InvalidAction);
        }
        if !invocation.project_root.is_absolute() || !invocation.compose_file.is_absolute() {
            return Err(ServiceError::InvalidPath);
        }
        if !invocation
            .compose_file
            .metadata()
            .is_ok_and(|metadata| metadata.is_file())
        {
            return Err(ServiceError::MissingCompose(
                invocation.compose_file.to_owned(),
            ));
        }
        let arguments: &[&str] = match invocation.action {
            ServiceAction::Up => &["up", "--detach", "--wait", "--wait-timeout", "100"],
            ServiceAction::Down => &["down"],
            ServiceAction::Status => &["ps"],
            ServiceAction::Config => unreachable!(),
        };
        let mut command = Command::new(DOCKER);
        command
            .args(["compose", "--project-name", "runroom", "--file"])
            .arg(invocation.compose_file)
            .args(arguments)
            .current_dir(invocation.project_root)
            .envs(invocation.environment);
        execute_command(&mut command, invocation.deadline)
    }
}

/// The deadline covers both process exit and EOF: a descendant may retain a pipe
/// after the Compose process exits. No reader thread or blocking wait outlives it.
fn execute_command(command: &mut Command, deadline: Instant) -> Result<String, ServiceError> {
    if Instant::now() >= deadline {
        return Err(ServiceError::Timeout);
    }
    let mut child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(ServiceError::Io)?;
    let result = collect_output(&mut child, deadline);
    if result.is_err() {
        terminate_and_reap(&mut child)?;
    }
    result
}

fn collect_output(child: &mut Child, deadline: Instant) -> Result<String, ServiceError> {
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| ServiceError::Io(io::Error::other("missing stdout pipe")))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| ServiceError::Io(io::Error::other("missing stderr pipe")))?;
    set_nonblocking(&stdout)?;
    set_nonblocking(&stderr)?;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut status = None;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ServiceError::Timeout);
        }
        // Read only one bounded chunk per stream before checking the deadline
        // again; a continuously writing process cannot monopolize this loop.
        if !stdout_done {
            stdout_done = read_stream(&mut stdout, &mut stdout_bytes, stderr_bytes.len())?;
        }
        if !stderr_done {
            stderr_done = read_stream(&mut stderr, &mut stderr_bytes, stdout_bytes.len())?;
        }
        if status.is_none() {
            status = child.try_wait().map_err(ServiceError::Io)?;
        }
        if let Some(status) = status
            && stdout_done
            && stderr_done
        {
            return render_output(status, stdout_bytes, &stderr_bytes);
        }

        let mut descriptors = [
            PollFd::new(stdout.as_fd(), PollFlags::POLLIN),
            PollFd::new(stderr.as_fd(), PollFlags::POLLIN),
        ];
        // Exclude EOF descriptors, whose persistent POLLHUP would busy-loop
        // while another pipe or the process itself remains open.
        let active = match (stdout_done, stderr_done) {
            (false, false) => &mut descriptors[..],
            (false, true) => &mut descriptors[..1],
            (true, false) => &mut descriptors[1..],
            (true, true) => &mut descriptors[..0],
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = PollTimeout::try_from(remaining.min(POLL_INTERVAL))
            .map_err(|error| ServiceError::Io(io::Error::other(error)))?;
        match poll(active, timeout) {
            Ok(_) => {
                if active.iter().any(|descriptor| {
                    descriptor
                        .revents()
                        .is_some_and(|events| events.contains(PollFlags::POLLNVAL))
                }) {
                    return Err(ServiceError::Io(io::Error::other(
                        "invalid service output descriptor",
                    )));
                }
            }
            Err(Errno::EINTR) => {}
            Err(error) => return Err(ServiceError::Io(error.into())),
        }
    }
}

fn set_nonblocking(pipe: &impl AsFd) -> Result<(), ServiceError> {
    let flags = fcntl(pipe, FcntlArg::F_GETFL).map_err(|error| ServiceError::Io(error.into()))?;
    fcntl(
        pipe,
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
    )
    .map_err(|error| ServiceError::Io(error.into()))?;
    Ok(())
}

fn read_stream(
    pipe: &mut impl Read,
    output: &mut Vec<u8>,
    other_bytes: usize,
) -> Result<bool, ServiceError> {
    let mut buffer = [0_u8; 4096];
    match pipe.read(&mut buffer) {
        Ok(0) => Ok(true),
        Ok(count) => {
            if count > MAX_SERVICE_OUTPUT_BYTES - output.len() - other_bytes {
                return Err(ServiceError::OutputTooLarge);
            }
            // Check the aggregate bound before reserving or appending. Exact
            // reservations avoid doubling the capacity past the shared limit.
            output.reserve_exact(count);
            output.extend_from_slice(&buffer[..count]);
            Ok(false)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(ServiceError::Io(error)),
    }
}

fn render_output(
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: &[u8],
) -> Result<String, ServiceError> {
    let mut rendered = String::from_utf8(stdout).map_err(|_| ServiceError::InvalidOutput)?;
    let stderr = std::str::from_utf8(stderr).map_err(|_| ServiceError::InvalidOutput)?;
    rendered.reserve_exact(stderr.len());
    rendered.push_str(stderr);
    if rendered.contains('\0') {
        return Err(ServiceError::InvalidOutput);
    }
    if !status.success() {
        return Err(ServiceError::Failed {
            status: status.to_string(),
            diagnostic: rendered,
        });
    }
    Ok(rendered)
}

fn terminate_and_reap(child: &mut Child) -> Result<(), ServiceError> {
    let terminated = if let Ok(pid) = i32::try_from(child.id()) {
        match killpg(Pid::from_raw(pid), Signal::SIGKILL) {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(error) => {
                // Still stop the direct child if group termination fails.
                let _ = child.kill();
                Err(ServiceError::Io(error.into()))
            }
        }
    } else {
        let _ = child.kill();
        Err(ServiceError::Io(io::Error::other(
            "service PID does not fit pid_t",
        )))
    };
    // SIGKILL normally makes try_wait immediately reapable. Keep cleanup
    // bounded as well, including a child stuck in uninterruptible kernel I/O.
    let reaped = reap_child(child);
    terminated?;
    reaped
}

fn reap_child(child: &mut Child) -> Result<(), ServiceError> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(ServiceError::Io(error)),
        }
        let remaining = REAP_DEADLINE.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(ServiceError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "cannot reap terminated service process",
            )));
        }
        std::thread::sleep(remaining.min(POLL_INTERVAL));
    }
}

#[derive(Debug)]
pub(crate) enum ServiceError {
    InvalidAction,
    InvalidPath,
    MissingCompose(PathBuf),
    Timeout,
    OutputTooLarge,
    InvalidOutput,
    Failed { status: String, diagnostic: String },
    Io(io::Error),
}

impl Display for ServiceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAction => {
                formatter.write_str("configuration is not a backend lifecycle action")
            }
            Self::InvalidPath => formatter.write_str("service paths must be absolute"),
            Self::MissingCompose(path) => write!(
                formatter,
                "compose file is not a regular file: {}",
                path.display()
            ),
            Self::Timeout => formatter.write_str("Docker Compose execution timed out"),
            Self::OutputTooLarge => {
                formatter.write_str("Docker Compose output exceeded the response limit")
            }
            Self::InvalidOutput => formatter.write_str("Docker Compose output is not UTF-8"),
            Self::Failed { status, diagnostic } => write!(
                formatter,
                "Docker Compose exited with {status}: {diagnostic}"
            ),
            Self::Io(error) => write!(formatter, "cannot execute Docker Compose: {error}"),
        }
    }
}

impl Error for ServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use nix::sys::wait::{WaitPidFlag, waitpid};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const TEST_DEADLINE: Duration = Duration::from_secs(3);

    struct ProcessFixture(PathBuf);

    impl ProcessFixture {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "runroom-services-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create services fixture");
            Self(path)
        }

        fn pid_file(&self) -> PathBuf {
            self.0.join("pids")
        }

        fn pids(&self) -> Vec<i32> {
            fs::read_to_string(self.pid_file())
                .expect("read service fixture PIDs")
                .split_whitespace()
                .map(|pid| pid.parse().expect("parse service fixture PID"))
                .collect()
        }

        fn assert_terminated_and_reaped(&self) {
            let pids = self.pids();
            assert_eq!(
                waitpid(Pid::from_raw(pids[0]), Some(WaitPidFlag::WNOHANG)),
                Err(Errno::ECHILD),
                "the direct service subprocess was not reaped"
            );
            let started = Instant::now();
            for pid in pids {
                loop {
                    let status = fs::read_to_string(format!("/proc/{pid}/status"));
                    match status {
                        Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                        Ok(status)
                            if status.lines().any(|line| {
                                line.strip_prefix("State:")
                                    .is_some_and(|state| state.trim_start().starts_with('Z'))
                            }) =>
                        {
                            // Only a child's parent (or init after adoption) can
                            // reap it. A zombie descendant is already terminated.
                            break;
                        }
                        Err(error) => panic!("cannot inspect fixture PID {pid}: {error}"),
                        Ok(_) => {}
                    }
                    assert!(
                        started.elapsed() < Duration::from_secs(2),
                        "service subprocess {pid} survived group termination"
                    );
                    std::thread::sleep(POLL_INTERVAL);
                }
            }
            // Do not signal an already-finished group again from Drop.
            fs::remove_file(self.pid_file()).expect("remove finished fixture PIDs");
        }
    }

    impl Drop for ProcessFixture {
        fn drop(&mut self) {
            // Keep a failing regression from leaving disposable processes alive.
            if let Ok(pids) = fs::read_to_string(self.pid_file())
                && let Some(pid) = pids
                    .split_whitespace()
                    .next()
                    .and_then(|pid| pid.parse::<i32>().ok())
            {
                let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
            }
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn python(script: &str) -> Command {
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-c", script]);
        command
    }

    #[test]
    fn mixed_output_accepts_exact_shared_limit_and_renders_stdout_first() {
        let mut command = python(
            "import sys; sys.stderr.buffer.write(b'e' * 32768); \
             sys.stderr.buffer.flush(); sys.stdout.buffer.write(b'o' * 32768)",
        );
        let rendered =
            execute_command(&mut command, Instant::now() + TEST_DEADLINE).expect("bounded output");
        assert_eq!(
            rendered,
            format!("{}{}", "o".repeat(32768), "e".repeat(32768))
        );
    }

    #[test]
    fn either_stream_can_use_the_complete_shared_limit() {
        for stream in ["stdout", "stderr"] {
            let mut command = python(&format!(
                "import sys; sys.{stream}.buffer.write(b'x' * 65536)"
            ));
            let rendered = execute_command(&mut command, Instant::now() + TEST_DEADLINE)
                .expect("single-stream output");
            assert_eq!(rendered, "x".repeat(MAX_SERVICE_OUTPUT_BYTES));
        }
    }

    #[test]
    fn mixed_output_overflow_terminates_the_group_and_reaps_the_child() {
        let fixture = ProcessFixture::new();
        let mut command = python(
            "import os, pathlib, subprocess, sys, time\n\
             child = subprocess.Popen(['/bin/sh', '-c', 'sleep 30'])\n\
             pathlib.Path(sys.argv[1]).write_text(f'{os.getpid()} {child.pid}')\n\
             sys.stdout.buffer.write(b'o' * 32768)\n\
             sys.stdout.buffer.flush()\n\
             sys.stderr.buffer.write(b'e' * 32769)\n\
             sys.stderr.buffer.flush()\n\
             time.sleep(30)\n",
        );
        command.arg(fixture.pid_file());
        let error = execute_command(&mut command, Instant::now() + TEST_DEADLINE)
            .expect_err("aggregate overflow");
        assert!(matches!(error, ServiceError::OutputTooLarge));
        fixture.assert_terminated_and_reaped();
    }

    #[test]
    fn timeout_covers_a_descendant_retaining_pipes_after_the_parent_exits() {
        let fixture = ProcessFixture::new();
        let mut command = python(
            "import os, pathlib, subprocess, sys\n\
             child = subprocess.Popen(['/bin/sh', '-c', 'sleep 30'])\n\
             pathlib.Path(sys.argv[1]).write_text(f'{os.getpid()} {child.pid}')\n\
             os._exit(0)\n",
        );
        command.arg(fixture.pid_file());
        let started = Instant::now();
        let error = execute_command(&mut command, started + Duration::from_secs(1))
            .expect_err("inherited pipes remain subject to the deadline");
        assert!(matches!(error, ServiceError::Timeout));
        assert!(started.elapsed() < Duration::from_secs(4));
        fixture.assert_terminated_and_reaped();
    }

    #[test]
    fn timeout_covers_a_live_child_after_both_output_pipes_close() {
        let fixture = ProcessFixture::new();
        let mut command = python(
            "import os, pathlib, sys, time\n\
             pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n\
             os.close(1)\n\
             os.close(2)\n\
             time.sleep(30)\n",
        );
        command.arg(fixture.pid_file());
        let error = execute_command(&mut command, Instant::now() + Duration::from_secs(1))
            .expect_err("closed pipes do not bypass the process deadline");
        assert!(matches!(error, ServiceError::Timeout));
        fixture.assert_terminated_and_reaped();
    }

    #[test]
    fn failed_exit_retains_ordered_stdout_and_stderr_diagnostics() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf stdout; printf stderr >&2; exit 7"]);
        let error = execute_command(&mut command, Instant::now() + TEST_DEADLINE)
            .expect_err("failed command");
        let ServiceError::Failed { status, diagnostic } = error else {
            panic!("unexpected service error: {error}");
        };
        assert_eq!(status, "exit status: 7");
        assert_eq!(diagnostic, "stdoutstderr");
    }

    #[test]
    fn invalid_output_terminates_descendants_even_after_successful_parent_exit() {
        let fixture = ProcessFixture::new();
        let mut command = python(
            "import os, pathlib, subprocess, sys\n\
             child = subprocess.Popen(['/bin/sh', '-c', 'sleep 30'], \
             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n\
             pathlib.Path(sys.argv[1]).write_text(f'{os.getpid()} {child.pid}')\n\
             os.write(1, b'\\xff')\n",
        );
        command.arg(fixture.pid_file());
        let error = execute_command(&mut command, Instant::now() + TEST_DEADLINE)
            .expect_err("invalid UTF-8");
        assert!(matches!(error, ServiceError::InvalidOutput));
        fixture.assert_terminated_and_reaped();
    }

    #[test]
    fn invalid_stderr_and_nul_output_are_rejected() {
        for script in ["printf '\\377' >&2", "printf '\\000'"] {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", script]);
            let error = execute_command(&mut command, Instant::now() + TEST_DEADLINE)
                .expect_err("invalid output");
            assert!(matches!(error, ServiceError::InvalidOutput));
        }
    }

    #[test]
    fn spawn_error_is_reported_without_waiting_for_a_child() {
        let fixture = ProcessFixture::new();
        let mut command = Command::new(fixture.0.join("missing-command"));
        let error = execute_command(&mut command, Instant::now() + TEST_DEADLINE)
            .expect_err("missing command");
        let ServiceError::Io(error) = error else {
            panic!("unexpected service error: {error}");
        };
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn expired_deadline_does_not_start_a_queued_command() {
        let fixture = ProcessFixture::new();
        let marker = fixture.0.join("executed");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "printf executed > \"$1\"", "fixture"])
            .arg(&marker);
        let error = execute_command(&mut command, Instant::now())
            .expect_err("an expired request must not execute");
        assert!(matches!(error, ServiceError::Timeout));
        assert!(!marker.exists());
    }
}
