//! Typed native client for the local Herdr newline-JSON socket.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

pub const HERDR_REQUEST_LIMIT: usize = 64 * 1024;
pub const HERDR_RESPONSE_LIMIT: usize = 256 * 1024;
pub const HERDR_DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

const MAX_COMMAND_BYTES: usize = 48 * 1024;
const MAX_ID_BYTES: usize = 512;
const MAX_PATH_BYTES: usize = 16 * 1024;
const MAX_LABEL_BYTES: usize = 512;
const MAX_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 128;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 256;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 16 * 1024;
const MAX_WIRE_STRING_BYTES: usize = 16 * 1024;

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Activity states accepted by Herdr's pane reporting endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HerdrActivityState {
    Working,
    Blocked,
    Idle,
}

/// The pane attributed to the current Runroom caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HerdrPane {
    pub pane_id: String,
    pub workspace_id: String,
    pub tab_id: String,
    pub host_cwd: PathBuf,
}

/// A Herdr tab and its root pane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HerdrTab {
    pub tab: String,
    pub pane: String,
    pub workspace: String,
}
/// A Herdr workspace explicitly associated with one Git checkout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HerdrWorktreeWorkspace {
    pub workspace_id: String,
    pub bootstrap_tab_id: String,
    pub root_pane: HerdrPane,
    pub checkout_path: PathBuf,
    pub already_open: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct HerdrRemoteError {
    code: String,
}

impl HerdrRemoteError {
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

impl Debug for HerdrRemoteError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("HerdrRemoteError([redacted])")
    }
}

impl Display for HerdrRemoteError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("Herdr rejected the request")
    }
}

impl Error for HerdrRemoteError {}

/// Redacted failures from the native Herdr backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HerdrError {
    InvalidInput(&'static str),
    RequestTooLarge,
    ConnectionFailed,
    TimedOut,
    WriteFailed,
    ReadFailed,
    ResponseTooLarge,
    IncompleteResponse,
    MultipleFrames,
    InvalidJson,
    InvalidEnvelope,
    MismatchedResponseId,
    InvalidResult,
    Remote(HerdrRemoteError),
}

impl Display for HerdrError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(field) => write!(formatter, "invalid Herdr {field}"),
            Self::RequestTooLarge => formatter.write_str("Herdr request exceeded its safety limit"),
            Self::ConnectionFailed => formatter.write_str("Herdr connection failed"),
            Self::TimedOut => formatter.write_str("Herdr request timed out"),
            Self::WriteFailed => formatter.write_str("Herdr request write failed"),
            Self::ReadFailed => formatter.write_str("Herdr response read failed"),
            Self::ResponseTooLarge => {
                formatter.write_str("Herdr response exceeded its safety limit")
            }
            Self::IncompleteResponse => formatter.write_str("Herdr response was incomplete"),
            Self::MultipleFrames => formatter.write_str("Herdr returned multiple response frames"),
            Self::InvalidJson => formatter.write_str("Herdr returned invalid JSON"),
            Self::InvalidEnvelope => {
                formatter.write_str("Herdr returned an invalid response envelope")
            }
            Self::MismatchedResponseId => {
                formatter.write_str("Herdr returned a mismatched response ID")
            }
            Self::InvalidResult => formatter.write_str("Herdr returned an invalid result"),
            Self::Remote(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for HerdrError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Remote(error) => Some(error),
            _ => None,
        }
    }
}

/// Concrete typed Herdr client. Each call uses one bounded socket connection.
#[derive(Clone, Debug)]
pub struct NativeHerdrBackend {
    socket_path: PathBuf,
    timeout: Duration,
    request_limit: usize,
    response_limit: usize,
}

impl NativeHerdrBackend {
    #[must_use]
    pub(crate) fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            timeout: HERDR_DEFAULT_TIMEOUT,
            request_limit: HERDR_REQUEST_LIMIT,
            response_limit: HERDR_RESPONSE_LIMIT,
        }
    }

    /// Resolve the pane identity Herdr assigned to a known caller pane.
    pub(crate) fn current_pane(&self, caller_pane_id: &str) -> Result<HerdrPane, HerdrError> {
        validate_text(caller_pane_id, MAX_ID_BYTES, "caller pane ID", false)?;
        let result: PaneCurrentResult = self.request(
            "pane.current",
            &PaneCurrentParams { caller_pane_id },
            self.timeout,
        )?;
        if result.kind != "pane_current" {
            return Err(HerdrError::InvalidResult);
        }
        let pane = result.pane.into_public()?;
        if pane.pane_id != caller_pane_id {
            return Err(HerdrError::InvalidResult);
        }
        Ok(pane)
    }
    /// Open or reuse the Herdr workspace attached to one existing Git worktree.
    pub(crate) fn open_worktree(
        &self,
        primary_checkout: &Path,
        checkout: &Path,
        label: &str,
    ) -> Result<HerdrWorktreeWorkspace, HerdrError> {
        let primary_checkout = primary_checkout
            .to_str()
            .ok_or(HerdrError::InvalidInput("primary checkout"))?;
        let checkout = checkout
            .to_str()
            .ok_or(HerdrError::InvalidInput("worktree checkout"))?;
        if !Path::new(primary_checkout).is_absolute() || !Path::new(checkout).is_absolute() {
            return Err(HerdrError::InvalidInput("worktree checkout"));
        }
        validate_text(primary_checkout, MAX_PATH_BYTES, "primary checkout", false)?;
        validate_text(checkout, MAX_PATH_BYTES, "worktree checkout", false)?;
        validate_text(label, MAX_LABEL_BYTES, "workspace label", false)?;
        let result: WorktreeOpenedResult = self.request(
            "worktree.open",
            &WorktreeOpenParams {
                cwd: primary_checkout,
                path: checkout,
                label,
                focus: true,
            },
            self.timeout,
        )?;
        if result.kind != "worktree_opened"
            || result.workspace.label != label
            || result.tab.workspace_id != result.workspace.workspace_id
            || result.worktree.open_workspace_id.as_deref()
                != Some(result.workspace.workspace_id.as_str())
        {
            return Err(HerdrError::InvalidResult);
        }
        let root_pane = result.root_pane.into_public()?;
        if root_pane.workspace_id != result.workspace.workspace_id
            || root_pane.tab_id != result.tab.tab_id
        {
            return Err(HerdrError::InvalidResult);
        }
        let checkout_path = PathBuf::from(result.worktree.path)
            .canonicalize()
            .map_err(|_| HerdrError::InvalidResult)?;
        let expected_path = PathBuf::from(checkout)
            .canonicalize()
            .map_err(|_| HerdrError::InvalidInput("worktree checkout"))?;
        if checkout_path != expected_path {
            return Err(HerdrError::InvalidResult);
        }
        Ok(HerdrWorktreeWorkspace {
            workspace_id: result.workspace.workspace_id,
            bootstrap_tab_id: result.tab.tab_id,
            root_pane,
            checkout_path,
            already_open: result.already_open,
        })
    }

    /// Create a focused, empty tab for a routed foreground launch.
    pub(crate) fn create_launch_tab(
        &self,
        workspace_id: &str,
        host_cwd: &Path,
        label: &str,
    ) -> Result<HerdrTab, HerdrError> {
        self.create_tab(Some(workspace_id), host_cwd, label, &BTreeMap::new(), true)
    }

    /// Create a tab in the default session's selected workspace, without Git routing.
    pub(crate) fn create_default_launch_tab(
        &self,
        host_cwd: &Path,
        label: &str,
    ) -> Result<HerdrTab, HerdrError> {
        self.create_tab(None, host_cwd, label, &BTreeMap::new(), true)
    }

    /// Enter one daemon-built launcher continuation command.
    pub(crate) fn start_launcher_continuation(
        &self,
        pane_id: &str,
        command: &str,
    ) -> Result<(), HerdrError> {
        validate_text(pane_id, MAX_ID_BYTES, "pane ID", false)?;
        validate_text(command, MAX_COMMAND_BYTES, "launcher continuation", false)?;
        self.send_input(pane_id, command)
    }

    fn create_tab(
        &self,
        workspace_id: Option<&str>,
        host_cwd: &Path,
        label: &str,
        environment: &BTreeMap<String, String>,
        focus: bool,
    ) -> Result<HerdrTab, HerdrError> {
        if let Some(workspace_id) = workspace_id {
            validate_text(workspace_id, MAX_ID_BYTES, "workspace ID", false)?;
        }
        validate_text(label, MAX_LABEL_BYTES, "tab label", false)?;
        let host_cwd = host_cwd
            .to_str()
            .ok_or(HerdrError::InvalidInput("host working directory"))?;
        if !Path::new(host_cwd).is_absolute() {
            return Err(HerdrError::InvalidInput("host working directory"));
        }
        validate_text(host_cwd, MAX_PATH_BYTES, "host working directory", false)?;
        validate_environment(environment)?;
        let result: TabCreatedResult = self.request(
            "tab.create",
            &TabCreateParams {
                workspace_id,
                cwd: host_cwd,
                label,
                env: environment,
                focus,
            },
            self.timeout,
        )?;
        if result.kind != "tab_created" {
            return Err(HerdrError::InvalidResult);
        }
        let tab = result.into_public()?;
        if workspace_id.is_some_and(|workspace_id| tab.workspace != workspace_id) {
            return Err(HerdrError::InvalidResult);
        }
        Ok(tab)
    }

    /// Publish bounded activity attributed to one pane.
    pub(crate) fn publish_activity(
        &self,
        pane_id: &str,
        agent_label: &str,
        state: HerdrActivityState,
        message: Option<&str>,
        sequence: u64,
        resume_argv: Option<&[String]>,
    ) -> Result<(), HerdrError> {
        validate_text(pane_id, MAX_ID_BYTES, "pane ID", false)?;
        validate_text(agent_label, MAX_LABEL_BYTES, "agent label", false)?;
        if let Some(message) = message {
            validate_text(message, MAX_MESSAGE_BYTES, "activity message", true)?;
        }
        if let Some(arguments) = resume_argv
            && (arguments.is_empty()
                || arguments.len() > 64
                || arguments.iter().map(String::len).sum::<usize>() > 8192
                || arguments
                    .iter()
                    .any(|argument| argument.contains(['\0', '\n', '\r', '\''])))
        {
            return Err(HerdrError::InvalidInput(
                "resume argv exceeds Herdr limits or contains forbidden characters",
            ));
        }
        let result: OkResult = self.request(
            "pane.report_agent",
            &ReportActivityParams {
                pane_id,
                source: "runroom",
                agent: agent_label,
                state,
                message,
                seq: sequence,
                resume_argv,
            },
            self.timeout,
        )?;
        result.ensure_ok()
    }

    fn send_input(&self, pane_id: &str, command: &str) -> Result<(), HerdrError> {
        let result: OkResult = self.request(
            "pane.send_input",
            &SendInputParams {
                pane_id,
                text: command,
                keys: ["enter"],
            },
            self.timeout,
        )?;
        result.ensure_ok()
    }

    fn request<P, R>(
        &self,
        method: &'static str,
        params: &P,
        timeout: Duration,
    ) -> Result<R, HerdrError>
    where
        P: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let id = next_request_id();
        let mut frame = serde_json::to_vec(&RequestEnvelope {
            id: &id,
            method,
            params,
        })
        .map_err(|_| HerdrError::InvalidInput("request"))?;
        frame.push(b'\n');
        if frame.len() > self.request_limit {
            return Err(HerdrError::RequestTooLarge);
        }

        let started = Instant::now();
        let mut stream =
            UnixStream::connect(&self.socket_path).map_err(|_| HerdrError::ConnectionFailed)?;
        stream
            .set_write_timeout(Some(remaining(started, timeout)?))
            .map_err(|_| HerdrError::ConnectionFailed)?;
        stream
            .write_all(&frame)
            .map_err(|error| classify_write_error(error.kind()))?;

        let response = read_response(&mut stream, self.response_limit, started, timeout)?;
        let decoded: Value =
            serde_json::from_slice(&response).map_err(|_| HerdrError::InvalidJson)?;
        let envelope: ResponseEnvelope =
            serde_json::from_value(decoded).map_err(|_| HerdrError::InvalidEnvelope)?;
        if envelope.id != id {
            return Err(HerdrError::MismatchedResponseId);
        }
        match (envelope.result, envelope.error) {
            (Some(result), None) => {
                serde_json::from_value(result).map_err(|_| HerdrError::InvalidResult)
            }
            (None, Some(remote)) => Err(HerdrError::Remote(remote.into_public()?)),
            _ => Err(HerdrError::InvalidEnvelope),
        }
    }
}

fn next_request_id() -> String {
    let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("runroom-{}-{sequence}", std::process::id())
}

fn remaining(started: Instant, timeout: Duration) -> Result<Duration, HerdrError> {
    timeout
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(HerdrError::TimedOut)
}

fn classify_write_error(kind: io::ErrorKind) -> HerdrError {
    match kind {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => HerdrError::TimedOut,
        _ => HerdrError::WriteFailed,
    }
}

fn classify_read_error(kind: io::ErrorKind) -> HerdrError {
    match kind {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => HerdrError::TimedOut,
        _ => HerdrError::ReadFailed,
    }
}

fn read_response(
    stream: &mut UnixStream,
    limit: usize,
    started: Instant,
    timeout: Duration,
) -> Result<Vec<u8>, HerdrError> {
    let mut response = Vec::with_capacity(limit.min(8 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        stream
            .set_read_timeout(Some(remaining(started, timeout)?))
            .map_err(|_| HerdrError::ReadFailed)?;
        let read = stream
            .read(&mut buffer)
            .map_err(|error| classify_read_error(error.kind()))?;
        if read == 0 {
            return Err(HerdrError::IncompleteResponse);
        }
        if response.len().saturating_add(read) > limit {
            return Err(HerdrError::ResponseTooLarge);
        }
        response.extend_from_slice(&buffer[..read]);
        if let Some(newline) = response.iter().position(|byte| *byte == b'\n') {
            if newline + 1 != response.len() {
                return Err(HerdrError::MultipleFrames);
            }
            stream
                .set_nonblocking(true)
                .map_err(|_| HerdrError::ReadFailed)?;
            let mut trailing = [0_u8; 1];
            loop {
                match stream.read(&mut trailing) {
                    Ok(0) => break,
                    Ok(_) => return Err(HerdrError::MultipleFrames),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => return Err(HerdrError::ReadFailed),
                }
            }
            response.truncate(newline);
            if response.is_empty() {
                return Err(HerdrError::InvalidJson);
            }
            return Ok(response);
        }
    }
}

fn validate_text(
    value: &str,
    maximum: usize,
    field: &'static str,
    allow_multiline: bool,
) -> Result<(), HerdrError> {
    let invalid_control = value.chars().any(|character| {
        character.is_control() && (!allow_multiline || !matches!(character, '\r' | '\n' | '\t'))
    });
    if value.is_empty() || value.len() > maximum || value.contains('\0') || invalid_control {
        return Err(HerdrError::InvalidInput(field));
    }
    Ok(())
}

fn validate_environment(environment: &BTreeMap<String, String>) -> Result<(), HerdrError> {
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(HerdrError::InvalidInput("tab environment"));
    }
    for (name, value) in environment {
        validate_text(
            name,
            MAX_ENVIRONMENT_NAME_BYTES,
            "tab environment name",
            false,
        )?;
        if !name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_uppercase() || (index > 0 && byte.is_ascii_digit())
        }) {
            return Err(HerdrError::InvalidInput("tab environment name"));
        }
        if value.len() > MAX_ENVIRONMENT_VALUE_BYTES || value.contains('\0') {
            return Err(HerdrError::InvalidInput("tab environment value"));
        }
    }
    Ok(())
}

fn validate_wire_string(value: &str) -> Result<(), HerdrError> {
    if value.is_empty() || value.len() > MAX_WIRE_STRING_BYTES || value.contains('\0') {
        Err(HerdrError::InvalidResult)
    } else {
        Ok(())
    }
}

#[derive(Serialize)]
struct RequestEnvelope<'a, P: ?Sized> {
    id: &'a str,
    method: &'static str,
    params: &'a P,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    id: String,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<RemoteErrorWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteErrorWire {
    code: String,
    message: String,
}

impl RemoteErrorWire {
    fn into_public(self) -> Result<HerdrRemoteError, HerdrError> {
        if self.code.is_empty()
            || self.code.len() > 64
            || !self
                .code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || self.message.is_empty()
            || self.message.len() > MAX_WIRE_STRING_BYTES
        {
            return Err(HerdrError::InvalidEnvelope);
        }
        Ok(HerdrRemoteError { code: self.code })
    }
}

#[derive(Serialize)]
struct WorktreeOpenParams<'a> {
    cwd: &'a str,
    path: &'a str,
    label: &'a str,
    focus: bool,
}

#[derive(Deserialize)]
struct WorktreeOpenedResult {
    #[serde(rename = "type")]
    kind: String,
    workspace: WorkspaceWire,
    tab: TabWire,
    root_pane: PaneWire,
    worktree: WorktreeWire,
    already_open: bool,
}

#[derive(Deserialize)]
struct WorkspaceWire {
    workspace_id: String,
    label: String,
}

#[derive(Deserialize)]
struct WorktreeWire {
    path: String,
    #[serde(default)]
    open_workspace_id: Option<String>,
}

#[derive(Serialize)]
struct PaneCurrentParams<'a> {
    caller_pane_id: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PaneCurrentResult {
    #[serde(rename = "type")]
    kind: String,
    pane: PaneWire,
}

#[derive(Deserialize)]
struct PaneWire {
    pane_id: String,
    workspace_id: String,
    tab_id: String,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    foreground_cwd: Option<String>,
}

impl PaneWire {
    fn into_public(self) -> Result<HerdrPane, HerdrError> {
        validate_wire_string(&self.pane_id)?;
        validate_wire_string(&self.workspace_id)?;
        validate_wire_string(&self.tab_id)?;
        let host_cwd = self
            .foreground_cwd
            .or(self.cwd)
            .ok_or(HerdrError::InvalidResult)?;
        validate_wire_string(&host_cwd)?;
        if !Path::new(&host_cwd).is_absolute() {
            return Err(HerdrError::InvalidResult);
        }
        Ok(HerdrPane {
            pane_id: self.pane_id,
            workspace_id: self.workspace_id,
            tab_id: self.tab_id,
            host_cwd: PathBuf::from(host_cwd),
        })
    }
}

#[derive(Serialize)]
struct TabCreateParams<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_id: Option<&'a str>,
    cwd: &'a str,
    label: &'a str,
    env: &'a BTreeMap<String, String>,
    focus: bool,
}

#[derive(Deserialize)]
struct TabCreatedResult {
    #[serde(rename = "type")]
    kind: String,
    tab: TabWire,
    root_pane: RootPaneWire,
}

#[derive(Deserialize)]
struct TabWire {
    tab_id: String,
    workspace_id: String,
}

#[derive(Deserialize)]
struct RootPaneWire {
    pane_id: String,
}

impl TabCreatedResult {
    fn into_public(self) -> Result<HerdrTab, HerdrError> {
        validate_wire_string(&self.tab.tab_id)?;
        validate_wire_string(&self.tab.workspace_id)?;
        validate_wire_string(&self.root_pane.pane_id)?;
        Ok(HerdrTab {
            tab: self.tab.tab_id,
            pane: self.root_pane.pane_id,
            workspace: self.tab.workspace_id,
        })
    }
}

#[derive(Serialize)]
struct SendInputParams<'a> {
    pane_id: &'a str,
    text: &'a str,
    keys: [&'static str; 1],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OkResult {
    #[serde(rename = "type")]
    kind: String,
}

impl OkResult {
    fn ensure_ok(self) -> Result<(), HerdrError> {
        if self.kind == "ok" {
            Ok(())
        } else {
            Err(HerdrError::InvalidResult)
        }
    }
}

#[derive(Serialize)]
struct ReportActivityParams<'a> {
    pane_id: &'a str,
    source: &'static str,
    agent: &'a str,
    state: HerdrActivityState,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
    seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    resume_argv: Option<&'a [String]>,
}
