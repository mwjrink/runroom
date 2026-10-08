//! Launcher-owned private-network setup and subprocess lifetime management.
//!
//! The launcher releases Bubblewrap's wait pipe only after setup succeeds.
//! A read-only confirmation also prevents harness execution if that pipe closes
//! on failure: Bubblewrap treats EOF as a release, not as cancellation.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::{Pid, pipe2, write};
use serde::Deserialize;
use signal_hook::SigId;

use crate::model::{ForegroundCommand, PreparedExec};

const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const MAX_INFO_BYTES: usize = 4096;

/// Run an already prepared, isolated bubblewrap command with private networking.
///
/// Stdio and the foreground process group remain inherited for the harness.
/// Only the networking helper has a separate process group and null stdin.
/// The caller supplies `--unshare-net`, the TUN device, and sandbox DNS settings.
pub(super) fn run(
    prepared: &PreparedExec,
    foreground: &ForegroundCommand,
) -> io::Result<ExitStatus> {
    // Register before spawning, and retain handlers until all child guards drop.
    let signals = LauncherSignals::new()?;
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let (info_read, info_write) = pipe2(OFlag::O_CLOEXEC)?;
    let (gate_read, gate_write) = pipe2(OFlag::O_CLOEXEC)?;
    let mut info_read = File::from(info_read);
    set_nonblocking(&info_read)?;
    // FD bind sources need a named inode: Bubblewrap canonicalizes their paths.
    let confirmation = tempfile::Builder::new()
        .prefix("runroom-startup-")
        .tempfile()?;

    let mut command = gated_command(
        prepared,
        foreground,
        &info_write,
        &gate_read,
        confirmation.as_file(),
    )?;
    inherit(&info_write)?;
    inherit(&gate_read)?;
    inherit(confirmation.as_file())?;
    let sandbox = command.spawn().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot start Bubblewrap runtime {} for private networking: {error}",
                prepared.executable.display()
            ),
        )
    })?;
    let mut supervisor = Supervisor {
        sandbox: ManagedChild::new(sandbox, false),
        helper: None,
        gate: Some(gate_write),
        helper_exit: None,
        confirmation,
    };
    // The parent never retains the child's ends, and slirp cannot inherit them.
    drop(info_write);
    drop(gate_read);
    fcntl(
        supervisor.confirmation.as_file(),
        FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC),
    )?;

    let pid = read_child_pid(&mut info_read, &mut supervisor, &signals, deadline)?;
    drop(info_read);
    let mut ready = supervisor.start_helper(pid)?;
    wait_for_ready(&mut ready, &mut supervisor, &signals, deadline)?;
    drop(ready);

    // Any additional launcher setup belongs before this release. Bubblewrap's
    // block-fd is a generic startup barrier, not a helper-owned network gate.
    supervisor.release_gate(&signals, deadline)?;
    supervisor.monitor(&signals)
}

fn gated_command(
    prepared: &PreparedExec,
    foreground: &ForegroundCommand,
    info: &OwnedFd,
    gate: &OwnedFd,
    confirmation: &File,
) -> io::Result<Command> {
    let separator = prepared
        .arguments
        .len()
        .checked_sub(foreground.arguments.len() + 2)
        .filter(|&index| prepared.arguments[index] == "--")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing Bubblewrap command separator",
            )
        })?;
    let mut command = Command::new(&prepared.executable);
    command
        .arg("--info-fd").arg(info.as_raw_fd().to_string())
        .arg("--block-fd").arg(gate.as_raw_fd().to_string())
        .args(&prepared.arguments[..separator])
        .args(["--dir", "/run/runroom", "--ro-bind-fd"])
        .arg(confirmation.as_raw_fd().to_string())
        .arg("/run/runroom/startup-ready")
        .args(["--", "/usr/bin/sh", "-c",
            "IFS= read -r ready < /run/runroom/startup-ready && [ \"$ready\" = ready ] || exit 125; exec \"$@\"",
            "runroom-startup"])
        .arg(&foreground.executable)
        .args(&foreground.arguments)
        .current_dir(&prepared.working_directory);
    Ok(command)
}

struct Supervisor {
    sandbox: ManagedChild,
    helper: Option<ManagedChild>,
    gate: Option<OwnedFd>,
    // EOF on this parent-only writer stops slirp, including if the launcher dies.
    helper_exit: Option<OwnedFd>,
    confirmation: tempfile::NamedTempFile,
}

impl Supervisor {
    fn start_helper(&mut self, pid: Pid) -> io::Result<File> {
        let (ready_read, ready_write) = pipe2(OFlag::O_CLOEXEC)?;
        let (exit_read, exit_write) = pipe2(OFlag::O_CLOEXEC)?;
        let ready_read = File::from(ready_read);
        set_nonblocking(&ready_read)?;

        let mut command = Command::new("slirp4netns");
        command
            .arg("--configure")
            .arg("--ready-fd")
            .arg(ready_write.as_raw_fd().to_string())
            .arg("--exit-fd")
            .arg(exit_read.as_raw_fd().to_string())
            .arg(pid.as_raw().to_string())
            .arg("tap0")
            .process_group(0)
            .stdin(Stdio::null());
        inherit(&ready_write)?;
        inherit(&exit_read)?;
        let helper = command.spawn().map_err(|error| {
            let message = if error.kind() == io::ErrorKind::NotFound {
                "network=private requires slirp4netns; install it and make it available on PATH"
                    .to_owned()
            } else {
                format!("cannot start slirp4netns for network=private: {error}")
            };
            io::Error::new(error.kind(), message)
        })?;
        self.helper = Some(ManagedChild::new(helper, true));
        self.helper_exit = Some(exit_write);
        drop(ready_write);
        drop(exit_read);
        Ok(ready_read)
    }

    fn check_startup(
        &mut self,
        signals: &LauncherSignals,
        deadline: Instant,
        stage: &str,
    ) -> io::Result<()> {
        if let Some(signal) = signals.take() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("private-network setup interrupted by {signal} {stage}"),
            ));
        }
        self.check_helper(stage)?;
        if let Some(status) = self.sandbox.try_wait()? {
            return Err(io::Error::other(format!(
                "Bubblewrap exited {stage} ({status}); inspect its diagnostics above"
            )));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "private-network setup timed out after {} seconds {stage}; inspect Bubblewrap/slirp4netns diagnostics above",
                    SETUP_TIMEOUT.as_secs()
                ),
            ));
        }
        Ok(())
    }

    fn check_helper(&mut self, stage: &str) -> io::Result<()> {
        if let Some(helper) = self.helper.as_mut()
            && let Some(status) = helper.try_wait()?
        {
            return Err(io::Error::other(format!(
                "slirp4netns exited {stage} ({status}); stopping the private sandbox; inspect its diagnostics above"
            )));
        }
        Ok(())
    }

    fn release_gate(&mut self, signals: &LauncherSignals, deadline: Instant) -> io::Result<()> {
        self.check_startup(signals, deadline, "before releasing the startup gate")?;
        // The launcher authorizes execution only after every setup step succeeds.
        // Bubblewrap closes its writable source FD after the read-only bind.
        self.confirmation.write_all(b"ready\n")?;
        loop {
            let gate = self.gate.as_ref().expect("startup gate is released once");
            match write(gate, b"1") {
                Ok(1) => {
                    self.gate.take();
                    return Ok(());
                }
                Ok(_) => return Err(io::Error::other("cannot release Bubblewrap startup gate")),
                Err(Errno::EINTR) => {}
                Err(error) => {
                    return Err(io::Error::new(
                        io::Error::from(error).kind(),
                        format!("cannot release Bubblewrap startup gate: {error}"),
                    ));
                }
            }
        }
    }

    fn monitor(&mut self, signals: &LauncherSignals) -> io::Result<ExitStatus> {
        loop {
            if let Some(signal) = signals.take()
                && signal != Signal::SIGINT
            {
                return self.shutdown(signal, signals);
            }
            // Interactive harnesses may handle terminal Ctrl-C without exiting.
            // They inherit the terminal's signal themselves; do not forward it
            // again, kill their network helper, or turn it into launcher failure.
            if let Some(status) = self.sandbox.try_wait()? {
                return Ok(status);
            }
            self.check_helper("while the sandbox was running")?;
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn shutdown(&mut self, signal: Signal, signals: &LauncherSignals) -> io::Result<ExitStatus> {
        if let Some(status) = self.sandbox.try_wait()? {
            return Ok(status);
        }
        match kill(self.sandbox.pid(), signal) {
            Ok(()) | Err(Errno::ESRCH) => {}
            Err(error) => return Err(error.into()),
        }
        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        loop {
            if let Some(status) = self.sandbox.try_wait()? {
                return Ok(status);
            }
            if signals.take().is_some() || Instant::now() >= deadline {
                return self.sandbox.terminate();
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        // Stop the outer monitor before closing the gate. A pre-exec namespace
        // child might survive it, but the empty confirmation makes that child
        // exit without executing the harness when the gate reaches EOF.
        let _ = self.sandbox.terminate();
        self.gate.take();
        self.helper_exit.take();
        if let Some(helper) = self.helper.as_mut() {
            let _ = helper.terminate();
        }
    }
}

struct ManagedChild {
    child: Child,
    status: Option<ExitStatus>,
    separate_group: bool,
}

impl ManagedChild {
    fn new(child: Child, separate_group: bool) -> Self {
        Self {
            child,
            status: None,
            separate_group,
        }
    }

    fn pid(&self) -> Pid {
        // Unix child PIDs fit pid_t; a live Child owns this PID until reaped.
        Pid::from_raw(i32::try_from(self.child.id()).expect("child PID fits pid_t"))
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_none() {
            self.status = self.child.try_wait()?;
        }
        Ok(self.status)
    }

    fn terminate(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        if self.separate_group {
            let _ = killpg(self.pid(), Signal::SIGKILL);
        }
        let _ = self.child.kill();
        loop {
            match self.child.wait() {
                Ok(status) => {
                    self.status = Some(status);
                    return Ok(status);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

struct LauncherSignals {
    received: [(Signal, Arc<AtomicBool>); 4],
    registrations: Vec<SigId>,
}

impl LauncherSignals {
    fn new() -> io::Result<Self> {
        let mut signals = Self {
            // An interrupt must not overwrite a pending termination signal.
            received: [
                Signal::SIGTERM,
                Signal::SIGHUP,
                Signal::SIGQUIT,
                Signal::SIGINT,
            ]
            .map(|signal| (signal, Arc::new(AtomicBool::new(false)))),
            registrations: Vec::with_capacity(4),
        };
        for (signal, received) in &signals.received {
            signals.registrations.push(signal_hook::flag::register(
                *signal as i32,
                Arc::clone(received),
            )?);
        }
        Ok(signals)
    }

    fn take(&self) -> Option<Signal> {
        self.received.iter().find_map(|(signal, received)| {
            received.swap(false, Ordering::SeqCst).then_some(*signal)
        })
    }
}

impl Drop for LauncherSignals {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
    }
}

fn inherit(descriptor: &impl AsFd) -> io::Result<()> {
    fcntl(descriptor, FcntlArg::F_SETFD(FdFlag::empty()))?;
    Ok(())
}

fn set_nonblocking(descriptor: &File) -> io::Result<()> {
    let flags = fcntl(descriptor, FcntlArg::F_GETFL)?;
    fcntl(
        descriptor,
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
    )?;
    Ok(())
}

fn poll_setup(descriptor: &File, deadline: Instant) -> io::Result<()> {
    let mut descriptors = [PollFd::new(descriptor.as_fd(), PollFlags::POLLIN)];
    let remaining = deadline.saturating_duration_since(Instant::now());
    let timeout = PollTimeout::try_from(remaining.min(POLL_INTERVAL)).map_err(io::Error::other)?;
    match poll(&mut descriptors, timeout) {
        Ok(_) => {
            if descriptors[0]
                .revents()
                .is_some_and(|events| events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL))
            {
                return Err(io::Error::other("private-network setup pipe failed"));
            }
            Ok(())
        }
        Err(Errno::EINTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn read_child_pid(
    info: &mut File,
    supervisor: &mut Supervisor,
    signals: &LauncherSignals,
    deadline: Instant,
) -> io::Result<Pid> {
    let mut bytes = [0_u8; MAX_INFO_BYTES + 1];
    let mut used = 0;
    loop {
        supervisor.check_startup(
            signals,
            deadline,
            "while waiting for Bubblewrap child-pid JSON",
        )?;
        match info.read(&mut bytes[used..]) {
            Ok(0) => return parse_child_pid(&bytes[..used]),
            Ok(count) => {
                used += count;
                if used > MAX_INFO_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Bubblewrap child-pid JSON exceeds the 4096-byte limit",
                    ));
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
        poll_setup(info, deadline)?;
    }
}

fn parse_child_pid(bytes: &[u8]) -> io::Result<Pid> {
    #[derive(Deserialize)]
    struct ChildInfo {
        #[serde(rename = "child-pid")]
        pid: i32,
    }
    let info: ChildInfo = serde_json::from_slice(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Bubblewrap child-pid JSON: {error}"),
        )
    })?;
    if info.pid <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Bubblewrap child-pid must be an integer greater than 1",
        ));
    }
    Ok(Pid::from_raw(info.pid))
}

fn wait_for_ready(
    ready: &mut File,
    supervisor: &mut Supervisor,
    signals: &LauncherSignals,
    deadline: Instant,
) -> io::Result<()> {
    let mut byte = [0_u8; 1];
    loop {
        supervisor.check_startup(signals, deadline, "while waiting for slirp4netns readiness")?;
        match ready.read(&mut byte) {
            Ok(1) if byte[0] == b'1' => return Ok(()),
            Ok(0) => {
                return Err(io::Error::other(
                    "slirp4netns closed its ready pipe without signaling readiness; inspect its diagnostics above",
                ));
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "slirp4netns sent an invalid readiness byte (expected '1')",
                ));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
        poll_setup(ready, deadline)?;
    }
}

#[cfg(test)]
mod tests {
    use super::parse_child_pid;

    #[test]
    fn child_info_allows_namespace_metadata() {
        let pid = parse_child_pid(br#"{ "child-pid": 42, "net-namespace": 12345 }"#)
            .expect("valid bubblewrap info");
        assert_eq!(pid.as_raw(), 42);
    }

    #[test]
    fn child_info_rejects_invalid_or_ambiguous_pids() {
        for bytes in [
            &b""[..],
            &b"{}"[..],
            &b"{\"child-pid\":0}"[..],
            &b"{\"child-pid\":1}"[..],
            &b"{\"child-pid\":-42}"[..],
            &b"{\"child-pid\":2147483648}"[..],
            &b"{\"child-pid\":42.5}"[..],
            &b"{\"child-pid\":\"42\"}"[..],
            &b"{\"child-pid\":42,\"child-pid\":43}"[..],
            &b"{\"child-pid\":42} trailing"[..],
        ] {
            assert!(parse_child_pid(bytes).is_err(), "accepted {bytes:?}");
        }
    }
}
