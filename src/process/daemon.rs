//! Concrete host daemon role and daemon-only request context.

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::num::NonZeroU32;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{
    Arc, Mutex, TryLockError,
    mpsc::{TrySendError, sync_channel},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::socket::{UnixCredentials, getsockopt, sockopt::PeerCredentials};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::backend::{
    DockerComposeBackend, GitWorkspaceBackend, GitWorkspaceError, HerdrActivityState, HerdrError,
    HerdrPane, NativeHerdrBackend, SERVICE_TIMEOUT, ScopeAttachment, ScopeBackend, ScopeHandle,
    ServiceError, ServiceInvocation, SystemdScopeBackend, SystemdScopeError, WorkspaceBackend,
};
use crate::environment::{PROJECT_ENV_KEYS, ProjectEnvironment};
use crate::model::{
    ActivityState, ActivityUpdate, AgentSession, CanonicalProject, HerdrContext, InstanceId,
    InstanceRecord, InstanceState, LauncherContinuation, PreparedLaunch, ProcessId, ProjectId,
    ResolvedWorkspace, ResourceLimits, ServiceAction, ServiceConfiguration, ServiceResult,
    SessionAgent, StopMode, UserId, WorkspaceSelection,
};
use crate::protocol::{
    APP_VERSION, ControlError, ControlOperation, ControlResponse, ControlResult,
};
use crate::transport::{
    HandshakeStatus, configure_stream, read_client_hello, read_control_request,
    write_control_response, write_daemon_hello,
};

use super::RunToken;
use super::registry::{InstanceRegistry, RegistryLease, now_ms};

static INSTANCE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static ACTIVITY_SEQUENCE: Mutex<u64> = Mutex::new(0);
const WORKER_COUNT: usize = 8;
const WORK_QUEUE: usize = 16;
const ACTIVITY_WORKER_COUNT: usize = 2;
const ACTIVITY_WORK_QUEUE: usize = 16;
const ACTIVITY_MAGIC: [u8; 4] = [0x52, 0x52, 0x41, 0x00];
const ACTIVITY_PROTOCOL_VERSION: u8 = 2;
const ACTIVITY_HEADER_BYTES: usize = 8;
const ACTIVITY_ACK: u8 = 0;
const MAX_ACTIVITY_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_ACTIVITY_BODY_BYTES: usize = 16 * 1024;
const HERDR_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_HERDR_DISCOVERY_BYTES: usize = 64 * 1024;
const CONTINUATION_TTL: Duration = Duration::from_secs(30);
const MAX_PENDING_CONTINUATIONS: usize = 128;

/// Daemon startup state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    socket_path: PathBuf,
    activity_socket_path: PathBuf,
    workspace_root: PathBuf,
    state_file: PathBuf,
    herdr_socket: PathBuf,
    resource_ceiling: ResourceLimits,
    exit_after_one_request: bool,
}

impl DaemonConfig {
    /// Configure a daemon listening at `socket_path` and owning `workspace_root`.
    pub fn new(socket_path: impl Into<PathBuf>, workspace_root: impl Into<PathBuf>) -> Self {
        let socket_path = socket_path.into();
        let activity_socket_path = activity_socket_path(&socket_path);
        Self {
            socket_path,
            activity_socket_path,
            workspace_root: workspace_root.into(),
            state_file: default_state_file(),
            herdr_socket: default_herdr_socket(),
            resource_ceiling: ResourceLimits {
                memory_max_bytes: Some(1 << 50),
                tasks_max: Some(1_000_000),
                cpu_quota_basis_points: Some(1_000_000),
                ..ResourceLimits::default()
            },
            exit_after_one_request: false,
        }
    }
    #[must_use]
    pub fn state_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.state_file = path.into();
        self
    }
    #[must_use]
    pub fn herdr_socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.herdr_socket = path.into();
        self
    }

    /// Set scalar memory, task, and CPU-quota ceilings; CPU placement is not a ceiling.
    #[must_use]
    pub fn resource_ceiling(mut self, ceiling: ResourceLimits) -> Self {
        self.resource_ceiling = ceiling;
        self
    }

    /// Exit cleanly after one accepted connection.
    ///
    /// Intended for service smoke checks and integration tests.
    #[must_use]
    pub const fn exit_after_one_request(mut self, enabled: bool) -> Self {
        self.exit_after_one_request = enabled;
        self
    }
}

/// Host daemon state.
#[derive(Debug)]
pub struct Daemon {
    config: DaemonConfig,
    _private: (),
}

#[derive(Debug)]
struct DaemonState {
    registry: InstanceRegistry,
    continuations: HashMap<String, PendingContinuation>,
}

#[derive(Clone, Debug)]
struct HerdrRouter {
    default_socket: PathBuf,
    named_sockets: Arc<Mutex<HashMap<String, PathBuf>>>,
}

#[derive(Clone)]
struct WorkerContext {
    workspace_backend: Arc<GitWorkspaceBackend>,
    scope_backend: Arc<SystemdScopeBackend>,
    workspace_gate: Arc<Mutex<()>>,
    service_gate: Arc<Mutex<()>>,
    state: Arc<Mutex<DaemonState>>,
    herdr_router: HerdrRouter,
    resource_ceiling: ResourceLimits,
}

#[derive(Clone, Debug)]
struct PendingContinuation {
    continuation: LauncherContinuation,
    context: HerdrContext,
    project: ProjectId,
    workspace_path: PathBuf,
    limits: ResourceLimits,
    expires_at: Instant,
    redeemed: bool,
}

#[derive(Deserialize)]
struct HerdrSessionList {
    sessions: Vec<HerdrSessionEntry>,
}

#[derive(Deserialize)]
struct HerdrSessionEntry {
    default: bool,
    name: String,
    running: bool,
    session_dir: PathBuf,
    socket_path: PathBuf,
}

impl Daemon {
    pub(super) fn new(_run_token: RunToken, config: DaemonConfig) -> Self {
        Self {
            config,
            _private: (),
        }
    }

    #[tracing::instrument(level = "debug", skip_all, name = "run_daemon")]
    pub(super) fn run(self) -> io::Result<()> {
        validate_daemon_config(&self.config)?;

        // Acquire registry exclusivity before touching either socket. Alternate
        // socket paths must not let two daemons operate the same scope owner.
        let registry_lease = RegistryLease::acquire(&self.config.state_file)?;
        let registry = InstanceRegistry::load(registry_lease.path())?;
        prepare_socket_parent(&self.config.socket_path)?;
        prepare_socket_parent(&self.config.activity_socket_path)?;
        remove_stale_socket(&self.config.socket_path)?;
        remove_stale_socket(&self.config.activity_socket_path)?;
        let listener = UnixListener::bind(&self.config.socket_path)?;
        fs::set_permissions(&self.config.socket_path, fs::Permissions::from_mode(0o600))?;
        let _socket_cleanup = SocketCleanup::new(&self.config.socket_path)?;
        let activity_listener = UnixListener::bind(&self.config.activity_socket_path)?;
        fs::set_permissions(
            &self.config.activity_socket_path,
            fs::Permissions::from_mode(0o600),
        )?;
        activity_listener.set_nonblocking(true)?;
        let _activity_socket_cleanup = SocketCleanup::new(&self.config.activity_socket_path)?;
        debug!(
            control_socket = %self.config.socket_path.display(),
            activity_socket = %self.config.activity_socket_path.display(),
            "daemon exclusivity acquired"
        );

        let context = initialize_worker_context(registry, registry_lease.path(), &self.config)?;
        let activity_shutdown = Arc::new(AtomicBool::new(false));
        let activity_server = spawn_activity_server(
            activity_listener,
            Arc::clone(&context.scope_backend),
            Arc::clone(&context.state),
            context.herdr_router.clone(),
            Arc::clone(&activity_shutdown),
        );
        let (sender, receiver) = sync_channel::<UnixStream>(WORK_QUEUE);
        let receiver = Arc::new(Mutex::new(receiver));
        let workers = spawn_control_workers(&receiver, &context);
        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => {
                    if sender.send(stream).is_err() {
                        break;
                    }
                }
                Err(error) => warn!(%error, "daemon accept failed"),
            }
            if self.config.exit_after_one_request {
                break;
            }
        }
        drop(sender);
        for worker in workers {
            let _ = worker.join();
        }
        activity_shutdown.store(true, Ordering::Release);
        let _ = activity_server.join();
        debug!("daemon stopped");
        Ok(())
    }
}

fn validate_daemon_config(config: &DaemonConfig) -> io::Result<()> {
    for (name, path) in [
        ("control socket", &config.socket_path),
        ("activity socket", &config.activity_socket_path),
        ("instance state file", &config.state_file),
        ("workspace root", &config.workspace_root),
        ("Herdr socket", &config.herdr_socket),
    ] {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be absolute"),
            ));
        }
    }
    if config.activity_socket_path == config.socket_path {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "activity and control sockets must be distinct",
        ));
    }
    Ok(())
}

fn initialize_worker_context(
    mut registry: InstanceRegistry,
    state_file: &Path,
    config: &DaemonConfig,
) -> io::Result<WorkerContext> {
    let scope_backend = SystemdScopeBackend::connect(state_file, &registry.scope_handles())
        .map_err(io::Error::other)?;
    let managed = scope_backend.list_managed().map_err(io::Error::other)?;
    let orphans = registry.reconcile(&managed, |handle| {
        scope_backend.inspect(handle).map_err(io::Error::other)
    })?;
    let orphan_count = orphans.len();
    for orphan in orphans {
        scope_backend
            .stop(&orphan, StopMode::Force)
            .map_err(io::Error::other)?;
    }
    debug!(orphan_count, "reconciled daemon instance registry");
    Ok(WorkerContext {
        workspace_backend: Arc::new(GitWorkspaceBackend::new(&config.workspace_root)),
        scope_backend: Arc::new(scope_backend),
        workspace_gate: Arc::new(Mutex::new(())),
        service_gate: Arc::new(Mutex::new(())),
        state: Arc::new(Mutex::new(DaemonState {
            registry,
            continuations: HashMap::new(),
        })),
        herdr_router: HerdrRouter::new(config.herdr_socket.clone()),
        resource_ceiling: ResourceLimits {
            memory_max_bytes: config.resource_ceiling.memory_max_bytes,
            tasks_max: config.resource_ceiling.tasks_max,
            cpu_quota_basis_points: config.resource_ceiling.cpu_quota_basis_points,
            ..ResourceLimits::default()
        },
    })
}

fn spawn_control_workers(
    receiver: &Arc<Mutex<std::sync::mpsc::Receiver<UnixStream>>>,
    context: &WorkerContext,
) -> Vec<thread::JoinHandle<()>> {
    let mut workers = Vec::with_capacity(WORKER_COUNT);
    for _ in 0..WORKER_COUNT {
        let receiver = Arc::clone(receiver);
        let context = context.clone();
        workers.push(thread::spawn(move || {
            loop {
                let stream = match receiver.lock() {
                    Ok(receiver) => receiver.recv(),
                    Err(_) => return,
                };
                let Ok(stream) = stream else {
                    return;
                };
                if let Err(error) = handle_connection(stream, &context) {
                    warn!(%error, "daemon connection failed");
                }
            }
        }));
    }
    workers
}

/// Peer identity supplied by the local Unix socket transport.
///
/// PID and UID come from kernel peer credentials, not request payload fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCaller {
    pub process: ProcessId,
    pub user: UserId,
}

fn spawn_activity_server(
    listener: UnixListener,
    scope_backend: Arc<SystemdScopeBackend>,
    state: Arc<Mutex<DaemonState>>,
    herdr_router: HerdrRouter,
    shutdown: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (sender, receiver) = sync_channel::<UnixStream>(ACTIVITY_WORK_QUEUE);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(ACTIVITY_WORKER_COUNT);
        for _ in 0..ACTIVITY_WORKER_COUNT {
            let receiver = Arc::clone(&receiver);
            let scope_backend = Arc::clone(&scope_backend);
            let state = Arc::clone(&state);
            let herdr_router = herdr_router.clone();
            workers.push(thread::spawn(move || {
                loop {
                    let stream = match receiver.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => return,
                    };
                    let Ok(stream) = stream else {
                        return;
                    };
                    if let Err(error) =
                        handle_activity_connection(stream, &scope_backend, &state, &herdr_router)
                    {
                        warn!(%error, "daemon activity connection failed");
                    }
                }
            }));
        }

        while !shutdown.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => match sender.try_send(stream) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        warn!("daemon activity queue is full");
                    }
                    Err(TrySendError::Disconnected(_)) => break,
                },
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    warn!(%error, "daemon activity accept failed");
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }

        drop(sender);
        for worker in workers {
            let _ = worker.join();
        }
    })
}

fn handle_activity_connection(
    mut stream: UnixStream,
    scope_backend: &SystemdScopeBackend,
    state: &Arc<Mutex<DaemonState>>,
    herdr_router: &HerdrRouter,
) -> io::Result<()> {
    configure_stream(&stream)?;
    let caller = local_caller(&stream)?;
    let instance = scope_backend
        .resolve_process(caller.process)
        .map_err(io::Error::other)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "activity must originate from a managed instance",
            )
        })?;
    let activity = read_activity_report(&mut stream)?;
    publish_instance_activity(&instance, &activity, state, herdr_router)
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.message))?;
    stream.write_all(&[ACTIVITY_ACK])
}

fn read_activity_report(stream: &mut UnixStream) -> io::Result<ActivityUpdate> {
    let mut header = [0_u8; ACTIVITY_HEADER_BYTES];
    stream.read_exact(&mut header)?;
    if header[..4] != ACTIVITY_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid activity frame magic",
        ));
    }
    if header[4] != ACTIVITY_PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported activity protocol version",
        ));
    }
    let state = match header[5] {
        0 => ActivityState::Working,
        1 => ActivityState::Blocked,
        2 => ActivityState::Idle,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid activity state",
            ));
        }
    };
    let body_len = usize::from(u16::from_be_bytes([header[6], header[7]]));
    if body_len > MAX_ACTIVITY_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "activity JSON body exceeds 16384 bytes",
        ));
    }
    let mut bytes = vec![0_u8; body_len];
    stream.read_exact(&mut bytes)?;
    let body: ActivityBody = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if body.message.as_ref().is_some_and(|message| {
        message.len() > MAX_ACTIVITY_MESSAGE_BYTES || message.chars().any(char::is_control)
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "activity message exceeds 4096 bytes or contains control characters",
        ));
    }
    if let Some(session) = &body.session {
        crate::transport::validate_session(session)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    }
    Ok(ActivityUpdate {
        state,
        message: body.message,
        session: body.session,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivityBody {
    message: Option<String>,
    session: Option<AgentSession>,
}

fn next_activity_sequence() -> u64 {
    let wall_clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .try_into()
        .unwrap_or(u64::MAX);
    let mut sequence = ACTIVITY_SEQUENCE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *sequence = wall_clock.max(sequence.saturating_add(1));
    *sequence
}

#[tracing::instrument(level = "debug", skip_all, name = "handle_daemon_connection")]
fn handle_connection(mut stream: UnixStream, context: &WorkerContext) -> io::Result<()> {
    configure_stream(&stream)?;
    let caller = local_caller(&stream)?;
    let client_version = read_client_hello(&mut stream)?;
    let status = if client_version == APP_VERSION {
        HandshakeStatus::Accepted
    } else {
        HandshakeStatus::UnsupportedVersion
    };
    write_daemon_hello(&mut stream, APP_VERSION, status)?;
    if status != HandshakeStatus::Accepted {
        return Ok(());
    }
    let request = read_control_request(&mut stream)?;
    let operation = operation_name(&request.operation);
    let request_id = request.request_id;
    let caller_instance = context
        .scope_backend
        .resolve_process(caller.process)
        .map_err(io::Error::other)?;
    let result = dispatch(request.operation, caller, caller_instance.as_ref(), context);
    debug!(
        request_id,
        operation,
        success = result.is_ok(),
        "completed daemon control request"
    );
    write_control_response(&mut stream, &ControlResponse { request_id, result })
}

fn operation_name(operation: &ControlOperation) -> &'static str {
    match operation {
        ControlOperation::PrepareLaunch(_) => "prepare_launch",
        ControlOperation::ResumeLaunch { .. } => "resume_launch",
        ControlOperation::ListInstances { .. } => "list_instances",
        ControlOperation::GetInstance { .. } => "get_instance",
        ControlOperation::StopInstance { .. } => "stop_instance",
        ControlOperation::RetireWorkspace { .. } => "retire_workspace",
        ControlOperation::RepairWorkspaceMetadata { .. } => "repair_workspace_metadata",
        ControlOperation::ManageServices { .. } => "manage_services",
    }
}

fn prepare_workspace_label(project: &CanonicalProject, workspace: &ResolvedWorkspace) -> String {
    workspace
        .change_name
        .clone()
        .or_else(|| {
            project
                .primary_checkout
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "Runroom".to_owned())
}

fn issue_continuation(
    state: &Arc<Mutex<DaemonState>>,
    pending: PendingContinuation,
) -> Result<String, ControlError> {
    let now = Instant::now();
    let mut daemon_state = lock_state(state)?;
    daemon_state
        .continuations
        .retain(|_, continuation| continuation.expires_at > now);
    if daemon_state.continuations.len() >= MAX_PENDING_CONTINUATIONS {
        return Err(ControlError {
            code: "continuation_capacity".to_owned(),
            message: "too many pending launcher continuations".to_owned(),
        });
    }
    let sequence = next_activity_sequence();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut digest = Sha256::new();
    digest.update(std::process::id().to_le_bytes());
    digest.update(sequence.to_le_bytes());
    digest.update(timestamp.to_le_bytes());
    digest.update(
        pending
            .context
            .session_name
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    digest.update(
        pending
            .context
            .pane_id
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    let token = format!("{:x}", digest.finalize());
    daemon_state.continuations.insert(token.clone(), pending);
    Ok(token)
}

fn resumed_continuation(
    state: &Arc<Mutex<DaemonState>>,
    token: &str,
    context: &HerdrContext,
) -> Result<LauncherContinuation, ControlError> {
    let now = Instant::now();
    let mut daemon_state = lock_state(state)?;
    let Some(pending) = daemon_state.continuations.get_mut(token) else {
        return Err(permission_denied("launcher continuation is unknown"));
    };
    if pending.expires_at <= now {
        daemon_state.continuations.remove(token);
        return Err(permission_denied("launcher continuation has expired"));
    }
    if pending.redeemed {
        return Err(permission_denied(
            "launcher continuation has already been redeemed",
        ));
    }
    if &pending.context != context {
        return Err(permission_denied(
            "launcher continuation is bound to another Herdr pane",
        ));
    }
    pending.redeemed = true;
    Ok(pending.continuation.clone())
}

fn consume_continuation(
    state: &Arc<Mutex<DaemonState>>,
    token: &str,
    context: &HerdrContext,
    project: &ProjectId,
    workspace_path: &Path,
) -> Result<ResourceLimits, ControlError> {
    let now = Instant::now();
    let mut daemon_state = lock_state(state)?;
    let Some(pending) = daemon_state.continuations.get(token) else {
        return Err(permission_denied("launcher continuation is unknown"));
    };
    if pending.expires_at <= now {
        daemon_state.continuations.remove(token);
        return Err(permission_denied("launcher continuation has expired"));
    }
    if !pending.redeemed {
        return Err(permission_denied(
            "launcher continuation has not been redeemed",
        ));
    }
    if &pending.context != context
        || &pending.project != project
        || pending.workspace_path != workspace_path
    {
        return Err(permission_denied(
            "launcher continuation does not match this launch",
        ));
    }
    let pending = daemon_state
        .continuations
        .remove(token)
        .ok_or_else(|| permission_denied("launcher continuation is unknown"))?;
    Ok(pending.limits)
}
struct ValidatedPrepareIdentity {
    herdr: Option<NativeHerdrBackend>,
    pane: Option<HerdrPane>,
}

fn validate_prepare_identity(
    request: &crate::model::PrepareLaunchRequest,
    herdr_router: &HerdrRouter,
) -> Result<ValidatedPrepareIdentity, ControlError> {
    if request.no_multiplex
        && (request.continuation.is_some() || request.continuation_token.is_some())
    {
        return Err(permission_denied(
            "current-terminal launch cannot carry Herdr routing inputs",
        ));
    }
    if !request.no_multiplex
        && request.workspace.workspace == WorkspaceSelection::Here
        && request.continuation_token.is_none()
    {
        if request.herdr.is_some() {
            return Err(permission_denied(
                "initial directory launch cannot carry pane identity",
            ));
        }
        return Ok(ValidatedPrepareIdentity {
            herdr: None,
            pane: None,
        });
    }
    let Some(context) = request.herdr.as_ref() else {
        if !request.no_multiplex && request.profile == "pi" {
            return Err(permission_denied("Pi launch requires Herdr identity"));
        }
        return Ok(ValidatedPrepareIdentity {
            herdr: None,
            pane: None,
        });
    };
    let pane_id = context
        .pane_id
        .as_deref()
        .ok_or_else(|| permission_denied("Herdr launch requires a pane"))?;
    let workspace_id = context
        .workspace_id
        .as_deref()
        .ok_or_else(|| permission_denied("Herdr launch requires a workspace"))?;
    let herdr = herdr_router.backend(context)?;
    let pane = herdr
        .current_pane(pane_id)
        .map_err(|error| herdr_control_error(&error))?;
    if pane.workspace_id != workspace_id {
        return Err(permission_denied("launcher Herdr identity does not match"));
    }
    Ok(ValidatedPrepareIdentity {
        herdr: Some(herdr),
        pane: Some(pane),
    })
}

fn launcher_continuation_command(
    executable: &Path,
    socket: &Path,
    token: &str,
    no_worktree: bool,
) -> Result<String, ControlError> {
    if !executable.is_absolute() || !socket.is_absolute() || token.len() != 64 {
        return Err(permission_denied("invalid launcher continuation inputs"));
    }
    let executable = executable.to_str().ok_or_else(|| ControlError {
        code: "launcher_unavailable".to_owned(),
        message: "Runroom executable path is not UTF-8".to_owned(),
    })?;
    let socket = socket.to_str().ok_or_else(|| ControlError {
        code: "launcher_unavailable".to_owned(),
        message: "Runroom control socket path is not UTF-8".to_owned(),
    })?;
    Ok(shell_words::join(
        [
            executable, "launcher", "--socket", socket, "--resume", token,
        ]
        .into_iter()
        .chain(no_worktree.then_some("--no-worktree")),
    ))
}

fn route_prepare_launch(
    request: &mut crate::model::PrepareLaunchRequest,
    project: &CanonicalProject,
    workspace: &ResolvedWorkspace,
    identity: &ValidatedPrepareIdentity,
    state: &Arc<Mutex<DaemonState>>,
    herdr_router: &HerdrRouter,
) -> Result<Option<ControlResult>, ControlError> {
    if request.no_multiplex {
        return Ok(None);
    }
    if workspace.selection == WorkspaceSelection::Here {
        if let Some(token) = request.continuation_token.as_deref() {
            let context = request.herdr.as_ref().ok_or_else(|| {
                permission_denied("directory continuation requires Herdr identity")
            })?;
            if context.session_name.is_some() || identity.pane.is_none() {
                return Err(permission_denied(
                    "directory continuation requires the default session",
                ));
            }
            request.limits =
                consume_continuation(state, token, context, &project.id, &workspace.path)?;
            return Ok(None);
        }
        if request.continuation.is_none() {
            return Err(permission_denied(
                "directory launch requires continuation inputs",
            ));
        }
        let herdr = herdr_router.backend(&HerdrContext {
            session_name: None,
            workspace_id: None,
            pane_id: None,
        })?;
        let label = prepare_workspace_label(project, workspace);
        let tab = herdr
            .create_default_launch_tab(&workspace.path, &label)
            .map_err(|error| herdr_control_error(&error))?;
        let target_pane = HerdrPane {
            pane_id: tab.pane,
            workspace_id: tab.workspace,
            tab_id: tab.tab,
            host_cwd: workspace.path.clone(),
        };
        return redirect_launch(
            request,
            project,
            workspace,
            &herdr,
            &target_pane,
            None,
            state,
        );
    }
    let (Some(herdr), Some(source_pane), Some(source_context)) = (
        identity.herdr.as_ref(),
        identity.pane.as_ref(),
        request.herdr.as_ref(),
    ) else {
        return Ok(None);
    };
    let label = prepare_workspace_label(project, workspace);
    let opened = herdr
        .open_worktree(&project.primary_checkout, &workspace.path, &label)
        .map_err(|error| herdr_control_error(&error))?;
    if opened.workspace_id == source_pane.workspace_id {
        if let Some(token) = request.continuation_token.as_deref() {
            request.limits =
                consume_continuation(state, token, source_context, &project.id, &workspace.path)?;
        }
        return Ok(None);
    }
    if request.continuation_token.is_some() {
        return Err(permission_denied(
            "launcher continuation reached the wrong Herdr workspace",
        ));
    }
    let target_pane = if opened.already_open {
        let tab = herdr
            .create_launch_tab(&opened.workspace_id, &workspace.path, &label)
            .map_err(|error| herdr_control_error(&error))?;
        HerdrPane {
            pane_id: tab.pane,
            workspace_id: tab.workspace,
            tab_id: tab.tab,
            host_cwd: workspace.path.clone(),
        }
    } else {
        opened.root_pane
    };
    let session_name = source_context.session_name.clone();
    redirect_launch(
        request,
        project,
        workspace,
        herdr,
        &target_pane,
        session_name,
        state,
    )
}

fn redirect_launch(
    request: &mut crate::model::PrepareLaunchRequest,
    project: &CanonicalProject,
    workspace: &ResolvedWorkspace,
    herdr: &NativeHerdrBackend,
    target_pane: &HerdrPane,
    session_name: Option<String>,
    state: &Arc<Mutex<DaemonState>>,
) -> Result<Option<ControlResult>, ControlError> {
    let handoff = request.continuation.take().ok_or_else(|| ControlError {
        code: "workspace_handoff_unavailable".to_owned(),
        message: "launcher did not provide continuation inputs".to_owned(),
    })?;
    let continuation = LauncherContinuation {
        socket_path: handoff.socket_path,
        profile: std::mem::take(&mut request.profile),
        agent_label: std::mem::take(&mut request.agent_label),
        command: handoff.command,
        mount_arguments: handoff.mount_arguments,
        replay_arguments: handoff.replay_arguments,
        workspace: std::mem::replace(&mut request.workspace.workspace, WorkspaceSelection::Here),
    };
    let context = HerdrContext {
        session_name,
        workspace_id: Some(target_pane.workspace_id.clone()),
        pane_id: Some(target_pane.pane_id.clone()),
    };
    let socket = continuation.socket_path.clone();
    let token = issue_continuation(
        state,
        PendingContinuation {
            continuation,
            context,
            project: project.id.clone(),
            workspace_path: workspace.path.clone(),
            limits: std::mem::take(&mut request.limits),
            expires_at: Instant::now() + CONTINUATION_TTL,
            redeemed: false,
        },
    )?;
    let executable = env::current_exe().map_err(|error| ControlError {
        code: "launcher_unavailable".to_owned(),
        message: format!("cannot resolve Runroom executable: {error}"),
    })?;
    let command = launcher_continuation_command(
        &executable,
        &socket,
        &token,
        workspace.selection == WorkspaceSelection::Here,
    )?;
    if let Err(error) = herdr.start_launcher_continuation(&target_pane.pane_id, &command) {
        if let Ok(mut daemon_state) = state.lock() {
            daemon_state.continuations.remove(&token);
        }
        return Err(herdr_control_error(&error));
    }
    Ok(Some(ControlResult::LaunchRedirected))
}

fn resolve_launch_workspace(
    workspace_backend: &GitWorkspaceBackend,
    request: &crate::model::PrepareLaunchRequest,
) -> Result<(CanonicalProject, ResolvedWorkspace), ControlError> {
    workspace_backend
        .resolve_launch_workspace(
            &request.workspace.current_directory,
            &request.workspace.workspace,
        )
        .map_err(|error| control_error(&error))
}
#[tracing::instrument(
    level = "debug",
    skip_all,
    name = "dispatch_daemon_operation",
    fields(operation = operation_name(&operation))
)]
fn dispatch(
    operation: ControlOperation,
    caller: LocalCaller,
    caller_instance: Option<&InstanceId>,
    context: &WorkerContext,
) -> Result<ControlResult, ControlError> {
    let WorkerContext {
        workspace_backend,
        scope_backend,
        workspace_gate,
        service_gate,
        state,
        ..
    } = context;
    if matches!(
        &operation,
        ControlOperation::PrepareLaunch(_)
            | ControlOperation::ListInstances { .. }
            | ControlOperation::GetInstance { .. }
            | ControlOperation::StopInstance { .. }
            | ControlOperation::RetireWorkspace { .. }
            | ControlOperation::RepairWorkspaceMetadata { .. }
    ) {
        reconcile_instances(state, scope_backend)?;
    }
    match operation {
        ControlOperation::PrepareLaunch(request) => {
            if caller_instance.is_some() {
                return Err(permission_denied(
                    "managed instances cannot prepare another launch",
                ));
            }
            prepare_launch(request, caller, context)
        }
        ControlOperation::ResumeLaunch {
            token,
            herdr: herdr_context,
        } => {
            if caller_instance.is_some() {
                return Err(permission_denied(
                    "managed instances cannot resume another launch",
                ));
            }
            resume_launch(&token, &herdr_context, &context.herdr_router, state)
        }
        ControlOperation::ListInstances { after, limit } => {
            require_host(caller_instance)?;
            let state = lock_state(state)?;
            Ok(ControlResult::Instances(
                state.registry.list(after.as_ref(), limit),
            ))
        }
        ControlOperation::GetInstance { id } => {
            authorize_instance(caller_instance, &id)?;
            let state = lock_state(state)?;
            Ok(ControlResult::Instance(state.registry.get(&id).cloned()))
        }
        ControlOperation::StopInstance { id, mode } => {
            authorize_instance(caller_instance, &id)?;
            stop_instance(&id, mode, scope_backend, state)
        }
        ControlOperation::RetireWorkspace {
            current_directory,
            name,
        } => {
            require_host(caller_instance)?;
            let _workspace_guard = workspace_gate.lock().map_err(|_| ControlError {
                code: "workspace_unavailable".to_owned(),
                message: "workspace serialization lock is unavailable".to_owned(),
            })?;
            let state = lock_state(state)?;
            workspace_backend
                .retire_inactive_workspace(&current_directory, &name, |path| {
                    state.registry.has_active_workspace(path)
                })
                .map(ControlResult::WorkspaceRetired)
                .map_err(|error| control_error(&error))
        }
        ControlOperation::RepairWorkspaceMetadata { current_directory } => {
            require_host(caller_instance)?;
            let _workspace_guard = workspace_gate.lock().map_err(|_| ControlError {
                code: "workspace_unavailable".to_owned(),
                message: "workspace serialization lock is unavailable".to_owned(),
            })?;
            workspace_backend
                .prune_stale_worktrees(&current_directory)
                .map(ControlResult::WorkspaceMetadataRepaired)
                .map_err(|error| control_error(&error))
        }
        ControlOperation::ManageServices {
            current_directory,
            action,
        } => {
            require_host(caller_instance)?;
            manage_services(&current_directory, action, workspace_backend, service_gate)
                .map(ControlResult::Services)
        }
    }
}

fn prepare_launch(
    mut request: crate::model::PrepareLaunchRequest,
    caller: LocalCaller,
    context: &WorkerContext,
) -> Result<ControlResult, ControlError> {
    let WorkerContext {
        workspace_backend,
        scope_backend,
        workspace_gate,
        state,
        herdr_router,
        resource_ceiling,
        ..
    } = context;
    if exceeds_ceiling(&request.limits, resource_ceiling) {
        return Err(ControlError {
            code: "resource_limit_exceeded".to_owned(),
            message: "requested resource limits exceed daemon ceilings".to_owned(),
        });
    }
    apply_scalar_ceiling(&mut request.limits, resource_ceiling);
    let identity = validate_prepare_identity(&request, herdr_router)?;
    let _workspace_guard = workspace_gate.lock().map_err(|_| ControlError {
        code: "workspace_unavailable".to_owned(),
        message: "workspace serialization lock is unavailable".to_owned(),
    })?;
    let (project, workspace) = resolve_launch_workspace(workspace_backend, &request)?;
    if let Some(result) = route_prepare_launch(
        &mut request,
        &project,
        &workspace,
        &identity,
        state,
        herdr_router,
    )? {
        return Ok(result);
    }
    if request.continuation_token.is_some() && identity.herdr.is_none() {
        return Err(permission_denied(
            "launcher continuation requires verified Herdr identity",
        ));
    }
    let instance_id = new_instance_id(caller.process);
    let handle = scope_backend
        .attach(scope_attachment(
            instance_id.clone(),
            caller.process,
            request.limits.clone(),
            &workspace.path,
        ))
        .map_err(|error| scope_control_error(&error))?;
    let timestamp = now_ms();
    let record = InstanceRecord {
        id: instance_id.clone(),
        scope_handle: handle.0.clone(),
        workspace: workspace.clone(),
        profile: request.profile,
        agent_label: request.agent_label,
        replay_arguments: request.replay_arguments,
        limits: request.limits,
        leader: caller.process,
        state: InstanceState::Running,
        activity: None,
        herdr: request.herdr,
        created_at_ms: timestamp,
        updated_at_ms: timestamp,
    };
    if let Err(error) = lock_state(state)?
        .registry
        .insert(record)
        .map_err(|error| state_error(&error))
    {
        let _ = scope_backend.stop(&handle, StopMode::Force);
        return Err(error);
    }
    Ok(ControlResult::LaunchPrepared(PreparedLaunch {
        instance_id,
        workspace,
    }))
}

fn resume_launch(
    token: &str,
    context: &HerdrContext,
    herdr_router: &HerdrRouter,
    state: &Arc<Mutex<DaemonState>>,
) -> Result<ControlResult, ControlError> {
    let backend = herdr_router.backend(context)?;
    let pane_id = context
        .pane_id
        .as_deref()
        .ok_or_else(|| permission_denied("launcher continuation requires a pane"))?;
    let workspace_id = context
        .workspace_id
        .as_deref()
        .ok_or_else(|| permission_denied("launcher continuation requires a workspace"))?;
    let pane = backend
        .current_pane(pane_id)
        .map_err(|error| herdr_control_error(&error))?;
    if pane.workspace_id != workspace_id {
        return Err(permission_denied(
            "launcher continuation pane does not match Herdr",
        ));
    }
    Ok(ControlResult::LaunchContinuation(resumed_continuation(
        state, token, context,
    )?))
}

fn stop_instance(
    id: &InstanceId,
    mode: StopMode,
    scope_backend: &SystemdScopeBackend,
    state: &Arc<Mutex<DaemonState>>,
) -> Result<ControlResult, ControlError> {
    let existing = {
        let state = lock_state(state)?;
        state.registry.get(id).cloned()
    }
    .ok_or_else(|| ControlError {
        code: "instance_not_found".to_owned(),
        message: format!("instance {} does not exist", id.0),
    })?;
    if stop_is_complete(existing.state) {
        return Ok(ControlResult::InstanceStopped(existing));
    }
    scope_backend
        .stop(&ScopeHandle(existing.scope_handle.clone()), mode)
        .map_err(|error| scope_control_error(&error))?;
    let mut state = lock_state(state)?;
    let stopped = state
        .registry
        .update(id, |record| {
            record.state = InstanceState::Stopping;
            record.updated_at_ms = now_ms();
        })
        .map_err(|error| state_error(&error))?
        .expect("record exists after lookup");
    Ok(ControlResult::InstanceStopped(stopped))
}
fn manage_services(
    current_directory: &Path,
    action: ServiceAction,
    workspace_backend: &GitWorkspaceBackend,
    service_gate: &Mutex<()>,
) -> Result<ServiceResult, ControlError> {
    let deadline = Instant::now() + SERVICE_TIMEOUT;
    let _service_guard = lock_service_gate(service_gate, deadline)?;
    let project = workspace_backend
        .canonical_project(current_directory)
        .map_err(|error| control_error(&error))?;
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| ControlError {
            code: "services_unavailable".to_owned(),
            message: "daemon HOME is unavailable".to_owned(),
        })?;
    let inherited = env::vars()
        .filter(|(name, _)| PROJECT_ENV_KEYS.contains(&name.as_str()))
        .collect::<BTreeMap<_, _>>();
    let environment =
        ProjectEnvironment::resolve_for_root(project.primary_checkout, &home, &inherited).map_err(
            |error| ControlError {
                code: "service_environment_invalid".to_owned(),
                message: bounded_diagnostic(&error.to_string()),
            },
        )?;
    if action == ServiceAction::Config {
        return Ok(ServiceResult::Configuration(ServiceConfiguration {
            project_root: environment.project_root,
            global_environment_file: environment.global_file,
            project_environment_file: environment.project_file,
            database_url: environment
                .values
                .get("RUNROOM_DATABASE_URL")
                .map_or_else(String::new, |value| redact_database_url(value)),
            qdrant_url: environment
                .values
                .get("RUNROOM_QDRANT_URL")
                .cloned()
                .unwrap_or_default(),
            state_directory: environment
                .values
                .get("RUNROOM_STATE_DIR")
                .cloned()
                .unwrap_or_default(),
        }));
    }
    let compose_file = home.join(".pi/agent/workflow/local/compose.yaml");
    DockerComposeBackend::execute(&ServiceInvocation {
        action,
        project_root: &environment.project_root,
        compose_file: &compose_file,
        environment: &environment.values,
        deadline,
    })
    .map(|output| ServiceResult::Completed { output })
    .map_err(service_control_error)
}

fn lock_service_gate(
    gate: &Mutex<()>,
    deadline: Instant,
) -> Result<std::sync::MutexGuard<'_, ()>, ControlError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ControlError {
                code: "services_timeout".to_owned(),
                message: "service operation serialization deadline expired".to_owned(),
            });
        }
        match gate.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => {
                return Err(ControlError {
                    code: "services_unavailable".to_owned(),
                    message: "service operation serialization lock is unavailable".to_owned(),
                });
            }
            Err(TryLockError::WouldBlock) => {
                thread::sleep(remaining.min(Duration::from_millis(10)));
            }
        }
    }
}

fn service_control_error(error: ServiceError) -> ControlError {
    let message = match error {
        ServiceError::Timeout => {
            return ControlError {
                code: "services_timeout".to_owned(),
                message: "Docker Compose execution timed out".to_owned(),
            };
        }
        ServiceError::Failed { status, .. } => format!("Docker Compose exited with {status}"),
        other => other.to_string(),
    };
    ControlError {
        code: "service_operation_failed".to_owned(),
        message: bounded_diagnostic(&message),
    }
}

fn bounded_diagnostic(message: &str) -> String {
    const LIMIT: usize = 4 * 1024;
    if message.len() <= LIMIT {
        return message.to_owned();
    }
    let mut end = LIMIT;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_owned()
}

fn redact_database_url(value: &str) -> String {
    let Some(scheme) = value.find("://") else {
        return "[redacted]".to_owned();
    };
    let credentials = scheme + 3;
    let Some(at) = value[credentials..].find('@') else {
        return "[redacted]".to_owned();
    };
    format!(
        "{}***@{}",
        &value[..credentials],
        &value[credentials + at + 1..]
    )
}

#[tracing::instrument(level = "debug", skip_all, name = "reconcile_instances")]
fn reconcile_instances(
    state: &Arc<Mutex<DaemonState>>,
    scope_backend: &SystemdScopeBackend,
) -> Result<(), ControlError> {
    debug!("listing managed systemd scopes");
    let managed = scope_backend
        .list_managed()
        .map_err(|error| scope_control_error(&error))?;
    debug!(
        managed_scope_count = managed.len(),
        "reconciling instance registry"
    );
    let mut state = lock_state(state)?;
    state
        .registry
        .reconcile(&managed, |handle| {
            scope_backend.inspect(handle).map_err(io::Error::other)
        })
        .map_err(|error| state_error(&error))?;
    Ok(())
}

fn lock_state(
    state: &Arc<Mutex<DaemonState>>,
) -> Result<std::sync::MutexGuard<'_, DaemonState>, ControlError> {
    state.lock().map_err(|_| ControlError {
        code: "state_unavailable".to_owned(),
        message: "daemon state lock is unavailable".to_owned(),
    })
}

impl HerdrRouter {
    fn new(default_socket: PathBuf) -> Self {
        Self {
            default_socket,
            named_sockets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn backend(&self, context: &HerdrContext) -> Result<NativeHerdrBackend, ControlError> {
        let socket = match context.session_name.as_deref() {
            None => self.default_socket.clone(),
            Some(session_name) => self.named_socket(session_name)?,
        };
        validate_herdr_socket(&socket)?;
        Ok(NativeHerdrBackend::new(socket))
    }

    fn named_socket(&self, session_name: &str) -> Result<PathBuf, ControlError> {
        if let Some(socket) = self
            .named_sockets
            .lock()
            .map_err(|_| herdr_discovery_error("Herdr session cache is unavailable"))?
            .get(session_name)
            .cloned()
            && validate_herdr_socket(&socket).is_ok()
        {
            return Ok(socket);
        }
        let socket = discover_herdr_session_socket(session_name)?;
        validate_herdr_socket(&socket)?;
        self.named_sockets
            .lock()
            .map_err(|_| herdr_discovery_error("Herdr session cache is unavailable"))?
            .insert(session_name.to_owned(), socket.clone());
        Ok(socket)
    }
}

fn verify_instance_pane(
    record: &InstanceRecord,
    herdr_router: &HerdrRouter,
) -> Result<(NativeHerdrBackend, crate::backend::HerdrPane), ControlError> {
    let context = record
        .herdr
        .as_ref()
        .ok_or_else(|| permission_denied("instance has no Herdr context"))?;
    let pane_id = context
        .pane_id
        .as_deref()
        .ok_or_else(|| permission_denied("instance has no Herdr pane"))?;
    let workspace_id = context
        .workspace_id
        .as_deref()
        .ok_or_else(|| permission_denied("instance has no Herdr workspace"))?;
    let herdr = herdr_router.backend(context)?;
    let pane = herdr
        .current_pane(pane_id)
        .map_err(|error| herdr_control_error(&error))?;
    if pane.pane_id != pane_id || pane.workspace_id != workspace_id {
        return Err(permission_denied("instance Herdr identity does not match"));
    }
    Ok((herdr, pane))
}

fn publish_instance_activity(
    id: &InstanceId,
    activity: &ActivityUpdate,
    state: &Arc<Mutex<DaemonState>>,
    herdr_router: &HerdrRouter,
) -> Result<(), ControlError> {
    let existing = lock_state(state)?
        .registry
        .get(id)
        .cloned()
        .ok_or_else(|| permission_denied("caller scope is not present in the instance registry"))?;
    let (herdr, pane) = verify_instance_pane(&existing, herdr_router)?;
    let resume_argv = activity
        .session
        .as_ref()
        .map(|session| session_resume_argv(&existing.replay_arguments, session))
        .transpose()?
        .flatten();
    lock_state(state)?
        .registry
        .update(id, |record| {
            let mut update = activity.clone();
            if update.session.is_none() {
                update.session = record
                    .activity
                    .as_ref()
                    .and_then(|previous| previous.session.clone());
            }
            record.activity = Some(update);
            record.updated_at_ms = now_ms();
        })
        .map_err(|error| state_error(&error))?;
    herdr
        .publish_activity(
            &pane.pane_id,
            &existing.agent_label,
            activity_state(activity.state),
            activity.message.as_deref(),
            next_activity_sequence(),
            resume_argv.as_deref(),
        )
        .map_err(|error| herdr_control_error(&error))
}

/// Rewrites only the trusted foreground command; sandbox reports supply a reference,
/// never a profile, socket, outer argument, or host executable.
fn session_resume_argv(
    replay_arguments: &[String],
    session: &AgentSession,
) -> Result<Option<Vec<String>>, ControlError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if replay_arguments.is_empty() {
        return Ok(None);
    }
    crate::transport::validate_session(session).map_err(|error| replay_error(error.to_string()))?;
    let command_index = replay_arguments
        .iter()
        .position(|argument| argument == "--command")
        .ok_or_else(|| replay_error("saved launcher arguments have no foreground command"))?;
    let command = replay_arguments
        .get(command_index + 1)
        .ok_or_else(|| replay_error("saved foreground command has no value"))?;
    let mut foreground = shell_words::split(command)
        .map_err(|error| replay_error(format!("cannot parse saved foreground command: {error}")))?;
    let provider = match session.agent {
        SessionAgent::Pi => "pi",
        SessionAgent::Omp => "omp",
    };
    if foreground
        .first()
        .and_then(|executable| Path::new(executable).file_name())
        .and_then(|name| name.to_str())
        != Some(provider)
    {
        return Err(permission_denied(
            "reported session provider does not match the trusted foreground executable",
        ));
    }
    let mut index = 1;
    let mut separator = None;
    while index < foreground.len() {
        let argument = &foreground[index];
        let flag = argument
            .split_once('=')
            .map_or(argument.as_str(), |(flag, _)| flag);
        let has_inline_value = flag.len() != argument.len();
        let session_value = matches!(flag, "--session" | "--fork")
            || (session.agent == SessionAgent::Pi && flag == "--session-id")
            || (session.agent == SessionAgent::Omp && matches!(flag, "--resume" | "-r"));
        if session_value {
            let remove_value = !has_inline_value
                && foreground.get(index + 1).is_some_and(|value| {
                    session.agent == SessionAgent::Pi
                        || (!value.is_empty() && !value.starts_with('-'))
                });
            foreground.remove(index);
            if remove_value {
                foreground.remove(index);
            }
        } else if matches!(
            flag,
            "--resume" | "-r" | "--continue" | "-c" | "--no-session"
        ) {
            foreground.remove(index);
        } else if argument == "--" {
            separator = Some(index);
            break;
        } else {
            // Values of configured flags can themselves look like session flags.
            index += if !has_inline_value && foreground_value_flag(flag, session.agent) {
                2
            } else {
                1
            };
        }
    }
    // Add options before a positional separator so provider parsers consume them.
    let insert = separator.unwrap_or(foreground.len());
    match session.agent {
        SessionAgent::Pi => {
            foreground.insert(insert, "--session".to_owned());
            foreground.insert(insert + 1, session.reference.clone());
        }
        SessionAgent::Omp => {
            foreground.insert(insert, format!("--resume={}", session.reference));
        }
    }
    let mut replay = replay_arguments.to_vec();
    replay[command_index + 1] = shell_words::join(&foreground);
    crate::transport::validate_replay_arguments(&replay)
        .map_err(|error| replay_error(error.to_string()))?;
    let json = serde_json::to_vec(&replay).map_err(|error| replay_error(error.to_string()))?;
    let encoded_len = json
        .len()
        .checked_mul(2)
        .ok_or_else(|| replay_error("replay payload is too large"))?;
    if "runroom".len() + "--restore-args".len() + encoded_len > 8192 {
        return Err(replay_error(
            "Herdr replay exceeds its 8192-byte argv limit; shorten the command, session path, or CLI mounts",
        ));
    }
    let mut encoded = String::with_capacity(encoded_len);
    for byte in json {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Ok(Some(vec![
        "runroom".to_owned(),
        "--restore-args".to_owned(),
        encoded,
    ]))
}

fn replay_error(message: impl Into<String>) -> ControlError {
    ControlError {
        code: "session_replay_invalid".to_owned(),
        message: message.into(),
    }
}

fn foreground_value_flag(flag: &str, agent: SessionAgent) -> bool {
    if matches!(
        flag,
        "--provider"
            | "--model"
            | "--api-key"
            | "--system-prompt"
            | "--append-system-prompt"
            | "--mode"
            | "--thinking"
            | "--session-dir"
            | "--models"
            | "--tools"
            | "--export"
            | "--extension"
            | "-e"
    ) {
        return true;
    }
    match agent {
        SessionAgent::Pi => matches!(
            flag,
            "--name"
                | "-n"
                | "-t"
                | "--exclude-tools"
                | "-xt"
                | "--skill"
                | "--prompt-template"
                | "--theme"
                | "--use-theme"
                | "--tui-mode"
        ),
        SessionAgent::Omp => matches!(
            flag,
            "--cwd"
                | "--config"
                | "--add-dir"
                | "--profile"
                | "--alias"
                | "--smol"
                | "--slow"
                | "--goal"
                | "--plan"
                | "--prewalk-into"
                | "--plan-yolo-into"
                | "--max-time"
                | "--service-tier"
                | "--system-prompt-template"
                | "--provider-session-id"
                | "--prompt-cache-key"
                | "--hook"
                | "--trusted-extension"
                | "--plugin-dir"
                | "--skills"
                | "--approval-mode"
        ),
    }
}

const fn activity_state(state: ActivityState) -> HerdrActivityState {
    match state {
        ActivityState::Working => HerdrActivityState::Working,
        ActivityState::Idle => HerdrActivityState::Idle,
        ActivityState::Blocked => HerdrActivityState::Blocked,
    }
}

fn herdr_discovery_error(message: impl Into<String>) -> ControlError {
    ControlError {
        code: "herdr_unavailable".to_owned(),
        message: message.into(),
    }
}

fn discover_herdr_session_socket(session_name: &str) -> Result<PathBuf, ControlError> {
    if session_name.is_empty()
        || session_name.len() > 128
        || session_name.chars().any(char::is_control)
    {
        return Err(ControlError {
            code: "invalid_herdr_session".to_owned(),
            message: "Herdr session name is invalid".to_owned(),
        });
    }
    let mut child = Command::new("herdr")
        .args(["session", "list", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| herdr_discovery_error("Herdr session discovery could not start"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| herdr_discovery_error("Herdr session discovery has no output"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| herdr_discovery_error("Herdr session discovery has no error output"))?;
    let reader = read_discovery_pipe(stdout, (MAX_HERDR_DISCOVERY_BYTES + 1) as u64);
    let error_reader = read_discovery_pipe(stderr, 4096);
    let deadline = std::time::Instant::now() + HERDR_DISCOVERY_TIMEOUT;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| herdr_discovery_error("Herdr session discovery could not be inspected"))?
        {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            let _ = error_reader.join();
            return Err(herdr_discovery_error("Herdr session discovery timed out"));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let output = reader
        .join()
        .map_err(|_| herdr_discovery_error("Herdr session discovery reader failed"))?
        .map_err(|_| herdr_discovery_error("Herdr session discovery output failed"))?;
    let stderr = error_reader
        .join()
        .map_err(|_| herdr_discovery_error("Herdr session discovery error reader failed"))?
        .map_err(|_| herdr_discovery_error("Herdr session discovery error output failed"))?;
    if !status.success() {
        let diagnostic: String = String::from_utf8_lossy(&stderr)
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect();
        return Err(herdr_discovery_error(format!(
            "Herdr session discovery failed ({status}): {}",
            diagnostic.trim()
        )));
    }
    if output.len() > MAX_HERDR_DISCOVERY_BYTES {
        return Err(herdr_discovery_error(
            "Herdr session discovery output exceeded its safety limit",
        ));
    }
    let listing: HerdrSessionList = serde_json::from_slice(&output)
        .map_err(|_| herdr_discovery_error("Herdr session discovery returned invalid JSON"))?;
    select_herdr_session_socket(listing, session_name)
}

fn read_discovery_pipe(
    pipe: impl Read + Send + 'static,
    limit: u64,
) -> thread::JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut output = Vec::new();
        pipe.take(limit).read_to_end(&mut output).map(|_| output)
    })
}

fn select_herdr_session_socket(
    listing: HerdrSessionList,
    session_name: &str,
) -> Result<PathBuf, ControlError> {
    let mut matches = listing
        .sessions
        .into_iter()
        .filter(|session| session.name == session_name);
    let session = matches
        .next()
        .ok_or_else(|| herdr_discovery_error("Herdr session is unavailable"))?;
    if matches.next().is_some() || !session.running {
        return Err(herdr_discovery_error("Herdr session is unavailable"));
    }
    if session.default && session.name != "default" {
        return Err(herdr_discovery_error(
            "Herdr session discovery returned inconsistent identity",
        ));
    }
    validate_herdr_session_directory(&session.session_dir)?;
    if session.socket_path.parent() != Some(session.session_dir.as_path()) {
        return Err(herdr_discovery_error(
            "Herdr session discovery returned an unrelated socket",
        ));
    }
    Ok(session.socket_path)
}

fn validate_herdr_session_directory(path: &Path) -> Result<(), ControlError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| herdr_discovery_error("Herdr session directory is unavailable"))?;
    if !path.is_absolute()
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != UnixCredentials::new().uid()
        || metadata.mode() & 0o022 != 0
    {
        return Err(herdr_discovery_error(
            "Herdr session directory is not trusted",
        ));
    }
    Ok(())
}

fn validate_herdr_socket(path: &Path) -> Result<(), ControlError> {
    if !path.is_absolute() {
        return Err(ControlError {
            code: "invalid_herdr_socket".to_owned(),
            message: "Herdr socket path is not absolute".to_owned(),
        });
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ControlError {
        code: "herdr_unavailable".to_owned(),
        message: "Herdr socket is unavailable".to_owned(),
    })?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != UnixCredentials::new().uid()
        || metadata.mode() & 0o022 != 0
    {
        return Err(ControlError {
            code: "invalid_herdr_socket".to_owned(),
            message: "Herdr endpoint is not a trusted direct Unix socket".to_owned(),
        });
    }
    Ok(())
}

fn herdr_control_error(error: &HerdrError) -> ControlError {
    let remote_code = match error {
        HerdrError::Remote(remote) => Some(remote.code()),
        _ => None,
    };
    warn!(?error, remote_code, "Herdr operation failed");
    ControlError {
        code: "herdr_failed".to_owned(),
        message: "Herdr operation failed".to_owned(),
    }
}

fn state_error(error: &io::Error) -> ControlError {
    ControlError {
        code: "state_persist_failed".to_owned(),
        message: error.to_string(),
    }
}

fn require_host(caller: Option<&InstanceId>) -> Result<(), ControlError> {
    if caller.is_some() {
        Err(permission_denied(
            "operation is restricted to host control clients",
        ))
    } else {
        Ok(())
    }
}

fn authorize_instance(
    caller: Option<&InstanceId>,
    requested: &InstanceId,
) -> Result<(), ControlError> {
    if caller.is_none_or(|caller| caller == requested) {
        Ok(())
    } else {
        Err(permission_denied(
            "managed instance cannot control another instance",
        ))
    }
}

fn stop_is_complete(state: InstanceState) -> bool {
    matches!(state, InstanceState::Exited | InstanceState::Failed)
}

fn scope_attachment(
    instance_id: InstanceId,
    leader: ProcessId,
    limits: ResourceLimits,
    workspace: &Path,
) -> ScopeAttachment {
    ScopeAttachment {
        instance_id,
        leader,
        limits,
        description: format!("Runroom foreground process in {}", workspace.display()),
    }
}

fn permission_denied(message: &str) -> ControlError {
    ControlError {
        code: "permission_denied".to_owned(),
        message: message.to_owned(),
    }
}

fn exceeds_ceiling(request: &ResourceLimits, ceiling: &ResourceLimits) -> bool {
    exceeds(request.memory_max_bytes, ceiling.memory_max_bytes)
        || exceeds(request.tasks_max, ceiling.tasks_max)
        || exceeds(
            request.cpu_quota_basis_points.map(u64::from),
            ceiling.cpu_quota_basis_points.map(u64::from),
        )
}

fn apply_scalar_ceiling(limits: &mut ResourceLimits, ceiling: &ResourceLimits) {
    limits.memory_max_bytes = limits.memory_max_bytes.or(ceiling.memory_max_bytes);
    limits.tasks_max = limits.tasks_max.or(ceiling.tasks_max);
    limits.cpu_quota_basis_points = limits
        .cpu_quota_basis_points
        .or(ceiling.cpu_quota_basis_points);
}

fn exceeds<T: Ord>(value: Option<T>, ceiling: Option<T>) -> bool {
    matches!((value, ceiling), (Some(value), Some(ceiling)) if value > ceiling)
}

fn control_error(error: &GitWorkspaceError) -> ControlError {
    ControlError {
        code: error.code().to_owned(),
        message: error.to_string(),
    }
}

fn scope_control_error(error: &SystemdScopeError) -> ControlError {
    ControlError {
        code: match error {
            SystemdScopeError::Ownership(_) | SystemdScopeError::ForeignScope(_) => {
                "scope_ownership_failed"
            }
            SystemdScopeError::CpuSelection(_) => "scope_limits_invalid",
            _ => "scope_backend_failed",
        }
        .to_owned(),
        message: error.to_string(),
    }
}

fn new_instance_id(process: ProcessId) -> InstanceId {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = INSTANCE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut digest = Sha256::new();
    digest.update(std::process::id().to_le_bytes());
    digest.update(process.0.get().to_le_bytes());
    digest.update(timestamp.to_le_bytes());
    digest.update(sequence.to_le_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest.finalize() {
        use std::fmt::Write;
        write!(encoded, "{byte:02x}").expect("write to string");
    }
    InstanceId(encoded)
}

fn default_state_file() -> PathBuf {
    env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|home| home.join(".local/state"))
        })
        .map_or_else(
            || PathBuf::from("/runroom-state-home-unavailable/instances.json"),
            |state| state.join("runroom/instances.json"),
        )
}
fn activity_socket_path(control_socket: &Path) -> PathBuf {
    control_socket
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join("activity/status.sock")
}

fn default_herdr_socket() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map_or_else(
            || PathBuf::from("/herdr-home-unavailable/herdr.sock"),
            |home| home.join(".config/herdr/herdr.sock"),
        )
}

fn local_caller(stream: &UnixStream) -> io::Result<LocalCaller> {
    let credentials = getsockopt(stream, PeerCredentials).map_err(io::Error::from)?;
    let daemon_uid = UnixCredentials::new().uid();
    if credentials.uid() != daemon_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "peer uid {} does not match daemon uid {daemon_uid}",
                credentials.uid()
            ),
        ));
    }

    let process = u32::try_from(credentials.pid())
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "peer PID is not positive"))?;

    Ok(LocalCaller {
        process: ProcessId(process),
        user: UserId(credentials.uid()),
    })
}

fn prepare_socket_parent(socket_path: &Path) -> io::Result<()> {
    let Some(parent) = socket_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    else {
        return Ok(());
    };
    if parent.exists() {
        return Ok(());
    }

    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
}

fn remove_stale_socket(socket_path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "daemon socket path exists and is not a Unix socket",
        ));
    }
    match UnixStream::connect(socket_path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "another daemon is already listening",
        )),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            let current = fs::symlink_metadata(socket_path)?;
            if !current.file_type().is_socket()
                || current.dev() != metadata.dev()
                || current.ino() != metadata.ino()
            {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "daemon socket path changed during stale-socket recovery",
                ));
            }
            fs::remove_file(socket_path)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[derive(Debug)]
struct SocketCleanup {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketCleanup {
    fn new(path: &Path) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        Ok(Self {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && let Err(error) = fs::remove_file(&self.path)
        {
            warn!(
                socket = %self.path.display(),
                %error,
                "failed to remove daemon socket"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved_arguments(command: &str) -> Vec<String> {
        [
            "--socket",
            "/run/user/1000/runroom.sock",
            "--profile",
            "coding",
            "--herdr-agent",
            "omp",
            "--network",
            "private",
            "--cpu-cores",
            "2,4",
            "--here",
            "--no-worktree",
            "--mount",
            "/source@/destination:ro",
            "--command",
            command,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn decode_resume(arguments: &[String]) -> Vec<String> {
        assert_eq!(&arguments[..2], ["runroom", "--restore-args"]);
        let bytes: Vec<u8> = arguments[2]
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn session_replacement_retains_outer_policy_and_inner_configured_flags() {
        for (agent, command, expected) in [
            (
                SessionAgent::Pi,
                "/opt/bin/pi --model fast --session '/old session.json' --thinking high --continue",
                vec![
                    "/opt/bin/pi",
                    "--model",
                    "fast",
                    "--thinking",
                    "high",
                    "--session",
                    "/new session's file.json",
                ],
            ),
            (
                SessionAgent::Omp,
                "/opt/bin/omp --model fast --resume=old --thinking high --resume --continue",
                vec![
                    "/opt/bin/omp",
                    "--model",
                    "fast",
                    "--thinking",
                    "high",
                    "--resume=/new session's file.json",
                ],
            ),
        ] {
            let saved = saved_arguments(command);
            let session = AgentSession {
                agent,
                reference: "/new session's file.json".to_owned(),
            };
            let wrapper = session_resume_argv(&saved, &session).unwrap().unwrap();
            assert!(!wrapper.iter().any(|value| value.contains('\'')));
            let replay = decode_resume(&wrapper);
            assert_eq!(&replay[..replay.len() - 1], &saved[..saved.len() - 1]);
            assert_eq!(
                shell_words::split(replay.last().unwrap()).unwrap(),
                expected
            );
            let changed = AgentSession {
                agent,
                reference: "replacement-id".to_owned(),
            };
            let replacement =
                decode_resume(&session_resume_argv(&replay, &changed).unwrap().unwrap());
            let inner = shell_words::split(replacement.last().unwrap()).unwrap();
            assert!(!inner.iter().any(|value| value.contains("/new session")));
            assert!(inner.iter().any(|value| value.contains("replacement-id")));
        }
    }

    #[test]
    fn pi_boolean_resume_keeps_prompt_and_configured_flag_shaped_values() {
        let session = AgentSession {
            agent: SessionAgent::Pi,
            reference: "/new.json".to_owned(),
        };
        let saved = saved_arguments(
            "pi --system-prompt --resume --resume 'keep this prompt' --session-id old --fork /old.json --session-dir /saved -- --resume",
        );
        let replay = decode_resume(&session_resume_argv(&saved, &session).unwrap().unwrap());
        assert_eq!(
            shell_words::split(replay.last().unwrap()).unwrap(),
            [
                "pi",
                "--system-prompt",
                "--resume",
                "keep this prompt",
                "--session-dir",
                "/saved",
                "--session",
                "/new.json",
                "--",
                "--resume"
            ]
        );
    }

    #[test]
    fn session_replay_rejects_provider_mismatch_and_oversized_wrapper() {
        let session = AgentSession {
            agent: SessionAgent::Pi,
            reference: "/session.json".to_owned(),
        };
        for command in ["sh -c pi", "/opt/bin/omp", "python pi"] {
            assert_eq!(
                session_resume_argv(&saved_arguments(command), &session)
                    .unwrap_err()
                    .code,
                "permission_denied"
            );
        }
        assert_eq!(session_resume_argv(&[], &session).unwrap(), None);
        let huge = saved_arguments(&format!("pi --model {}", "x".repeat(5000)));
        let error = session_resume_argv(&huge, &session).unwrap_err();
        assert_eq!(error.code, "session_replay_invalid");
        assert!(error.message.contains("8192-byte"));
    }

    fn read_report(body: &[u8], version: u8, state: u8) -> io::Result<ActivityUpdate> {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let length = u16::try_from(body.len()).unwrap().to_be_bytes();
        writer
            .write_all(&[b'R', b'R', b'A', 0, version, state, length[0], length[1]])
            .unwrap();
        writer.write_all(body).unwrap();
        drop(writer);
        read_activity_report(&mut reader)
    }

    #[test]
    fn activity_v2_consumes_ordered_state_and_session_without_host_inputs() {
        let report = read_report(
            br#"{"message":"ready","session":{"agent":"pi","reference":"/absolute/session.json"}}"#,
            2,
            1,
        )
        .unwrap();
        assert_eq!(report.state, ActivityState::Blocked);
        assert_eq!(report.message.as_deref(), Some("ready"));
        assert_eq!(
            report.session.unwrap(),
            AgentSession {
                agent: SessionAgent::Pi,
                reference: "/absolute/session.json".to_owned()
            }
        );
        let state_only = read_report(b"{}", 2, 2).unwrap();
        assert_eq!(state_only.state, ActivityState::Idle);
        assert_eq!(state_only.session, None);
    }

    #[test]
    fn activity_from_unregistered_scope_is_rejected_before_contacting_herdr() {
        let absent_path = env::temp_dir().join(format!(
            "runroom-absent-registry-{}-{}",
            std::process::id(),
            next_activity_sequence()
        ));
        let state = Arc::new(Mutex::new(DaemonState {
            registry: InstanceRegistry::load(absent_path).unwrap(),
            continuations: HashMap::new(),
        }));
        let router = HerdrRouter::new(PathBuf::from("/nonexistent-herdr.sock"));
        let report = ActivityUpdate {
            state: ActivityState::Working,
            message: None,
            session: Some(AgentSession {
                agent: SessionAgent::Pi,
                reference: "/session.json".to_owned(),
            }),
        };
        let error = publish_instance_activity(
            &InstanceId("unknown-scope".to_owned()),
            &report,
            &state,
            &router,
        )
        .unwrap_err();
        assert_eq!(error.code, "permission_denied");
        assert!(error.message.contains("not present"));
    }

    #[test]
    fn activity_rejects_old_protocol_unknown_fields_invalid_references_and_bounds() {
        for body in [
            br#"{"profile":"other"}"#.as_slice(),
            br#"{"agent_label":"sh"}"#,
            br#"{"resume_argv":["sh"]}"#,
            br#"{"session":{"agent":"pi","reference":"id","command":"sh"}}"#,
            br#"{"session":{"agent":"other","reference":"id"}}"#,
            br#"{"session":{"agent":"pi","reference":""}}"#,
            br#"{"session":{"agent":"pi","reference":"bad\nid"}}"#,
            &[0xff],
        ] {
            assert_eq!(
                read_report(body, 2, 0).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert!(read_report(b"{}", 1, 0).is_err());
        assert!(read_report(b"{}", 2, 3).is_err());
        let oversized_message =
            serde_json::to_vec(&serde_json::json!({"message": "é".repeat(2049)})).unwrap();
        assert!(read_report(&oversized_message, 2, 0).is_err());
        let oversized_reference = serde_json::to_vec(
            &serde_json::json!({"session": {"agent": "omp", "reference": "x".repeat(4097)}}),
        )
        .unwrap();
        assert!(read_report(&oversized_reference, 2, 0).is_err());
        assert!(read_report(&vec![b' '; MAX_ACTIVITY_BODY_BYTES + 1], 2, 0).is_err());
        let boundary = serde_json::to_vec(&serde_json::json!({
            "message": "é".repeat(2048),
            "session": {"agent": "pi", "reference": format!("/{}", "x".repeat(4095))},
        }))
        .unwrap();
        assert!(read_report(&boundary, 2, 0).is_ok());
    }

    #[test]
    fn activity_sequence_is_wall_clock_based_and_increases() {
        let first = next_activity_sequence();
        let second = next_activity_sequence();
        assert!(first >= now_ms().saturating_sub(1000) * 1000);
        assert!(second > first);
    }

    #[test]
    fn scalar_ceiling_fills_omissions_without_constraining_cpu_placement() {
        let ceiling = ResourceLimits {
            memory_max_bytes: Some(256 << 20),
            tasks_max: Some(64),
            cpu_quota_basis_points: Some(10_000),
            cpu_cores: Some(vec![1]),
            ..ResourceLimits::default()
        };
        let mut omitted = ResourceLimits {
            cpu_count: Some(2),
            ..ResourceLimits::default()
        };
        assert!(!exceeds_ceiling(&omitted, &ceiling));
        apply_scalar_ceiling(&mut omitted, &ceiling);
        assert_eq!(omitted.memory_max_bytes, ceiling.memory_max_bytes);
        assert_eq!(omitted.tasks_max, ceiling.tasks_max);
        assert_eq!(
            omitted.cpu_quota_basis_points,
            ceiling.cpu_quota_basis_points
        );
        assert_eq!(omitted.cpu_count, Some(2));
        assert_eq!(omitted.cpu_cores, None);
        let mut stricter = ResourceLimits {
            memory_max_bytes: Some(128 << 20),
            tasks_max: Some(32),
            cpu_quota_basis_points: Some(5_000),
            cpu_cores: Some(vec![3, 9]),
            ..ResourceLimits::default()
        };
        let original = stricter.clone();
        assert!(!exceeds_ceiling(&stricter, &ceiling));
        apply_scalar_ceiling(&mut stricter, &ceiling);
        assert_eq!(stricter, original);
    }

    #[test]
    fn larger_explicit_scalar_limits_are_rejected_independently() {
        let ceiling = ResourceLimits {
            memory_max_bytes: Some(256 << 20),
            tasks_max: Some(64),
            cpu_quota_basis_points: Some(10_000),
            ..ResourceLimits::default()
        };
        assert!(!exceeds_ceiling(&ceiling, &ceiling));
        for request in [
            ResourceLimits {
                memory_max_bytes: Some((256 << 20) + 1),
                ..ResourceLimits::default()
            },
            ResourceLimits {
                tasks_max: Some(65),
                ..ResourceLimits::default()
            },
            ResourceLimits {
                cpu_quota_basis_points: Some(10_001),
                ..ResourceLimits::default()
            },
        ] {
            assert!(exceeds_ceiling(&request, &ceiling));
        }
    }

    #[test]
    fn queued_service_operation_expires_without_acquiring_the_gate() {
        let gate = Mutex::new(());
        let held = lock_service_gate(&gate, Instant::now() + Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        let error = lock_service_gate(&gate, started + Duration::from_millis(20)).unwrap_err();
        assert_eq!(error.code, "services_timeout");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(matches!(gate.try_lock(), Err(TryLockError::WouldBlock)));
        drop(held);
        let guard = lock_service_gate(&gate, Instant::now() + Duration::from_secs(1)).unwrap();
        assert!(matches!(gate.try_lock(), Err(TryLockError::WouldBlock)));
        drop(guard);
    }

    #[test]
    fn stopping_instance_remains_eligible_for_force_escalation() {
        assert!(!stop_is_complete(InstanceState::Stopping));
        assert!(stop_is_complete(InstanceState::Exited));
        assert!(stop_is_complete(InstanceState::Failed));
    }
}
