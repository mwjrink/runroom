//! Launcher-owned private-network setup and subprocess lifetime management.
//!
//! The launcher releases Bubblewrap's wait pipe only after setup succeeds.
//! A read-only confirmation also prevents harness execution if that pipe closes
//! on failure: Bubblewrap treats EOF as a release, not as cancellation.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
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
use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, connect, socket};
use nix::unistd::{Pid, pipe2, write};
use serde::Deserialize;
use signal_hook::SigId;

use crate::model::{ForegroundCommand, PortForward, PreparedExec};

const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const MAX_INFO_BYTES: usize = 4096;
const MAX_API_BYTES: usize = 4096;

/// Run an already prepared, isolated bubblewrap command with private networking.
///
/// Stdio and the foreground process group remain inherited for the harness.
/// Only the networking helper has a separate process group and null stdin.
/// The caller supplies `--unshare-net`, the TUN device, and sandbox DNS settings.
pub(super) fn run(
    prepared: &PreparedExec,
    foreground: &ForegroundCommand,
    forwards: &[PortForward],
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
        api_directory: None,
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
    let mut ready = supervisor.start_helper(pid, !forwards.is_empty())?;
    wait_for_ready(&mut ready, &mut supervisor, &signals, deadline)?;
    drop(ready);
    supervisor.publish_ports(forwards, &signals, deadline)?;

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
    // Removed only after the helper has exited, including on setup failure.
    api_directory: Option<tempfile::TempDir>,
}

impl Supervisor {
    fn start_helper(&mut self, pid: Pid, publish: bool) -> io::Result<File> {
        let (ready_read, ready_write) = pipe2(OFlag::O_CLOEXEC)?;
        let (exit_read, exit_write) = pipe2(OFlag::O_CLOEXEC)?;
        let ready_read = File::from(ready_read);
        set_nonblocking(&ready_read)?;
        if publish {
            // Force a short, private (0700) pathname, independent of TMPDIR.
            self.api_directory = Some(
                tempfile::Builder::new()
                    .prefix("runroom-slirp-")
                    .tempdir_in("/tmp")?,
            );
        }

        let mut command = Command::new("slirp4netns");
        command
            .arg("--configure")
            .arg("--ready-fd")
            .arg(ready_write.as_raw_fd().to_string())
            .arg("--exit-fd")
            .arg(exit_read.as_raw_fd().to_string());
        if let Some(directory) = &self.api_directory {
            command
                .arg("--api-socket")
                .arg(directory.path().join("api.sock"));
        }
        command
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

    fn publish_ports(
        &mut self,
        forwards: &[PortForward],
        signals: &LauncherSignals,
        deadline: Instant,
    ) -> io::Result<()> {
        if forwards.is_empty() {
            return Ok(());
        }
        let path = self
            .api_directory
            .as_ref()
            .expect("publishing requests an API socket")
            .path()
            .join("api.sock");
        let address = UnixAddr::new(&path)?;
        for forward in forwards {
            let result = (|| {
                self.check_startup(signals, deadline, "while publishing TCP ports")?;
                let descriptor = socket(
                    AddressFamily::Unix,
                    SockType::Stream,
                    SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
                    None,
                )?;
                let stream = UnixStream::from(descriptor);
                match connect(stream.as_raw_fd(), &address) {
                    Ok(()) => {}
                    Err(Errno::EINPROGRESS) => loop {
                        self.check_startup(
                            signals,
                            deadline,
                            "while connecting to slirp4netns API",
                        )?;
                        poll_descriptor(&stream, PollFlags::POLLOUT, deadline)?;
                        if let Some(error) = stream.take_error()? {
                            return Err(error);
                        }
                        if stream.peer_addr().is_ok() {
                            break;
                        }
                    },
                    Err(error) => return Err(io::Error::from(error)),
                }
                register_forward(stream, *forward, deadline, || {
                    self.check_startup(signals, deadline, "while publishing TCP ports")
                })
            })();
            result.map_err(|error: io::Error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cannot publish TCP localhost {} to room port {}: {error}",
                        forward.host_port, forward.room_port
                    ),
                )
            })?;
        }
        Ok(())
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
        self.api_directory.take();
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
    poll_descriptor(descriptor, PollFlags::POLLIN, deadline)
}

fn poll_descriptor(descriptor: &impl AsFd, events: PollFlags, deadline: Instant) -> io::Result<()> {
    let mut descriptors = [PollFd::new(descriptor.as_fd(), events)];
    let remaining = deadline.saturating_duration_since(Instant::now());
    let timeout = PollTimeout::try_from(remaining.min(POLL_INTERVAL)).map_err(io::Error::other)?;
    match poll(&mut descriptors, timeout) {
        Ok(_) => {
            if descriptors[0]
                .revents()
                .is_some_and(|events| events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL))
            {
                return Err(io::Error::other("private-network setup descriptor failed"));
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

fn register_forward(
    mut stream: UnixStream,
    forward: PortForward,
    deadline: Instant,
    mut check_startup: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    let mut request_bytes = [0_u8; 256];
    let mut request = io::Cursor::new(request_bytes.as_mut_slice());
    write!(
        request,
        "{{\"execute\":\"add_hostfwd\",\"arguments\":{{\"proto\":\"tcp\",\"host_addr\":\"127.0.0.1\",\"host_port\":{},\"guest_addr\":\"10.0.2.100\",\"guest_port\":{}}}}}",
        forward.host_port, forward.room_port,
    )?;
    let length = usize::try_from(request.position()).map_err(io::Error::other)?;
    let mut pending = &request_bytes[..length];
    while !pending.is_empty() {
        check_startup()?;
        match stream.write(pending) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "slirp4netns API closed during request",
                ));
            }
            Ok(count) => pending = &pending[count..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                poll_descriptor(&stream, PollFlags::POLLOUT, deadline)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    // The documented API requires SHUT_WR after each request, without keep-alive.
    // https://github.com/rootless-containers/slirp4netns/blob/master/slirp4netns.1.md#api-socket
    stream.shutdown(Shutdown::Write)?;
    let mut response = [0_u8; MAX_API_BYTES + 1];
    let mut used = 0;
    loop {
        check_startup()?;
        match stream.read(&mut response[used..]) {
            Ok(0) => return parse_forward_response(&response[..used]),
            Ok(count) => {
                used += count;
                if used > MAX_API_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "slirp4netns API response exceeds the 4096-byte limit",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                poll_descriptor(&stream, PollFlags::POLLIN, deadline)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn parse_forward_response(bytes: &[u8]) -> io::Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Response {
        #[serde(rename = "return")]
        result: Option<ForwardId>,
        error: Option<ApiError>,
    }
    #[derive(Deserialize)]
    struct ForwardId {
        id: u32,
    }
    #[derive(Deserialize)]
    struct ApiError {
        desc: String,
    }
    let response: Response = serde_json::from_slice(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid slirp4netns add_hostfwd response: {error}"),
        )
    })?;
    if let Some(error) = response.error {
        return Err(io::Error::other(format!(
            "slirp4netns rejected add_hostfwd: {}; the host port may already be occupied",
            error.desc,
        )));
    }
    if response.result.is_none_or(|result| result.id == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "slirp4netns add_hostfwd response lacks a valid forwarding id",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    const FORWARD: PortForward = PortForward {
        host_port: 23001,
        room_port: 3000,
    };

    fn exchange_response(response: Vec<u8>) -> io::Result<()> {
        let (client, mut server) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        server.set_read_timeout(Some(SETUP_TIMEOUT)).unwrap();
        let responder = thread::spawn(move || {
            let mut request = Vec::new();
            // Reading to EOF exercises the mandatory client SHUT_WR.
            server.read_to_end(&mut request).unwrap();
            // An oversized reply can make the client close before all writes.
            let _ = server.write_all(&response);
        });
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let result = register_forward(client, FORWARD, deadline, || {
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "test API deadline"));
            }
            Ok(())
        });
        responder.join().unwrap();
        result
    }

    #[test]
    fn forward_api_requires_write_shutdown_and_valid_registration() {
        exchange_response(br#"{"return":{"id":42}}"#.to_vec()).unwrap();
    }

    #[test]
    fn forward_api_rejects_errors_and_malformed_responses() {
        for response in [
            &b""[..],
            &b"not JSON"[..],
            &b"{}"[..],
            &br#"{"return":{}}"#[..],
            &br#"{"return":{"id":0}}"#[..],
            &br#"{"return":{"id":-1}}"#[..],
            &br#"{"return":{"id":"42"}}"#[..],
            &br#"{"return":{"id":42,"id":43}}"#[..],
            &br#"{"return":{"id":42}} trailing"#[..],
            &br#"{"error":{"desc":"slirp_add_hostfwd failed"}}"#[..],
            &br#"{"return":{"id":42},"error":{"desc":"failure"}}"#[..],
        ] {
            assert!(
                exchange_response(response.to_vec()).is_err(),
                "accepted {response:?}"
            );
        }
    }

    #[test]
    fn forward_api_enforces_response_size_boundary() {
        let mut response = br#"{"return":{"id":42}}"#.to_vec();
        response.resize(MAX_API_BYTES, b' ');
        exchange_response(response.clone()).unwrap();
        response.push(b' ');
        assert_eq!(
            exchange_response(response).unwrap_err().kind(),
            io::ErrorKind::InvalidData,
        );
    }

    #[test]
    fn forward_api_stall_obeys_startup_deadline() {
        let (client, mut server) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_millis(100);
        let result = register_forward(client, FORWARD, deadline, || {
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "API deadline"));
            }
            Ok(())
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        // The client drops its socket on failure instead of leaving a session.
        let mut request = String::new();
        server.read_to_string(&mut request).unwrap();
        assert!(request.contains("add_hostfwd"));
    }

    #[test]
    fn failed_registration_keeps_gate_closed_and_cleans_helper_socket() {
        let signals = LauncherSignals::new().unwrap();
        let directory = tempfile::Builder::new()
            .prefix("runroom-api-test-")
            .tempdir_in("/tmp")
            .unwrap();
        let path = directory.path().to_owned();
        let listener = UnixListener::bind(path.join("api.sock")).unwrap();
        let responder = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream
                .write_all(br#"{"error":{"desc":"occupied host port"}}"#)
                .unwrap();
        });
        let sandbox = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let helper = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let (gate_read, gate_write) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).unwrap();
        let mut gate_read = File::from(gate_read);
        let mut supervisor = Supervisor {
            sandbox: ManagedChild::new(sandbox, false),
            helper: Some(ManagedChild::new(helper, true)),
            gate: Some(gate_write),
            helper_exit: None,
            confirmation: tempfile::NamedTempFile::new().unwrap(),
            api_directory: Some(directory),
        };
        let result = supervisor.publish_ports(&[FORWARD], &signals, Instant::now() + SETUP_TIMEOUT);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(
            supervisor.confirmation.as_file().metadata().unwrap().len(),
            0
        );
        assert_eq!(
            gate_read.read(&mut [0_u8; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
        );
        let sandbox_pid = supervisor.sandbox.pid();
        let helper_pid = supervisor.helper.as_ref().unwrap().pid();
        drop(supervisor);
        responder.join().unwrap();
        assert!(!path.exists());
        assert_eq!(kill(sandbox_pid, None), Err(Errno::ESRCH));
        assert_eq!(kill(helper_pid, None), Err(Errno::ESRCH));
        let deadline = Instant::now() + SETUP_TIMEOUT;
        loop {
            match gate_read.read(&mut [0_u8; 1]) {
                Ok(0) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    // Concurrent test spawns can briefly retain a forked CLOEXEC writer.
                    assert!(Instant::now() < deadline, "startup gate writer leaked");
                    poll_setup(&gate_read, deadline).unwrap();
                }
                result => panic!("failed setup unexpectedly released its gate: {result:?}"),
            }
        }
    }

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
