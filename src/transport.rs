//! Bounded framing shared by daemon and launcher.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::model::{
    ActivityState, ActivityUpdate, HerdrContext, InstanceId, InstanceRecord, InstanceState,
    LaunchHandoff, LaunchRequest, LauncherContinuation, PrepareLaunchRequest, PreparedLaunch,
    ProcessId, ProjectId, PrunedWorktrees, ResolvedWorkspace, ResourceLimits, RetiredWorkspace,
    ServiceAction, ServiceConfiguration, ServiceResult, StopMode, WorkspaceName, WorkspaceOrigin,
    WorkspaceSelection, WorkspaceSupportMount,
};
use crate::protocol::{
    APP_VERSION, ControlError, ControlOperation, ControlRequest, ControlResponse, ControlResult,
};

const MAGIC: [u8; 4] = *b"RRM\0";
const CLIENT_HELLO_KIND: u8 = 1;
const DAEMON_HELLO_KIND: u8 = 2;
const REQUEST_KIND: u8 = 3;
const RESPONSE_KIND: u8 = 4;
const MAX_VERSION_LEN: usize = 128;
const MAX_HELLO_LEN: usize = 6 + MAX_VERSION_LEN;
const MAX_CONTROL_FRAME_LEN: usize = 768 * 1024;
const MAX_PATH_LEN: usize = 16 * 1024;
const MAX_NAME_LEN: usize = 255;
const MAX_COMMAND_LEN: usize = 64 * 1024;
const MAX_SUPPORT_MOUNTS: usize = 32;
const MAX_MOUNT_ARGUMENTS: usize = 128;
const MAX_DIAGNOSTIC_LEN: usize = 4 * 1024;
const MAX_LIST_LIMIT: u16 = 100;
const MAX_MEMORY_BYTES: u64 = 1 << 50;
const MAX_TASKS: u64 = 1_000_000;
const MAX_CPU_QUOTA_BASIS_POINTS: u32 = 1_000_000;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandshakeStatus {
    Accepted,
    UnsupportedVersion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaemonHello {
    pub version: String,
    pub status: HandshakeStatus,
}

pub(crate) fn configure_stream(stream: &UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))
}
pub(crate) fn connect_control(socket_path: &Path) -> io::Result<UnixStream> {
    if !socket_path.is_absolute() {
        return Err(invalid_input("control socket must be absolute"));
    }
    let mut stream = UnixStream::connect(socket_path)?;
    configure_stream(&stream)?;
    write_client_hello(&mut stream, APP_VERSION)?;
    let daemon = read_daemon_hello(&mut stream)?;
    if daemon.status != HandshakeStatus::Accepted {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "daemon version {} does not support client version {APP_VERSION}",
                daemon.version,
            ),
        ));
    }
    if daemon.version != APP_VERSION {
        return Err(invalid_data(
            "daemon accepted a different application version",
        ));
    }
    Ok(stream)
}

pub(crate) fn write_client_hello(stream: &mut UnixStream, version: &str) -> io::Result<()> {
    write_hello(stream, CLIENT_HELLO_KIND, version, None)
}

pub(crate) fn read_client_hello(stream: &mut UnixStream) -> io::Result<String> {
    let (payload, len) = read_hello(stream, CLIENT_HELLO_KIND, 5)?;
    decode_version(&payload[5..len])
}

pub(crate) fn write_daemon_hello(
    stream: &mut UnixStream,
    version: &str,
    status: HandshakeStatus,
) -> io::Result<()> {
    let status = match status {
        HandshakeStatus::Accepted => 0,
        HandshakeStatus::UnsupportedVersion => 1,
    };
    write_hello(stream, DAEMON_HELLO_KIND, version, Some(status))
}

pub(crate) fn read_daemon_hello(stream: &mut UnixStream) -> io::Result<DaemonHello> {
    let (payload, len) = read_hello(stream, DAEMON_HELLO_KIND, 6)?;
    let status = match payload[5] {
        0 => HandshakeStatus::Accepted,
        1 => HandshakeStatus::UnsupportedVersion,
        value => return Err(invalid_data(format!("unknown handshake status {value}"))),
    };
    Ok(DaemonHello {
        version: decode_version(&payload[6..len])?,
        status,
    })
}

fn write_hello(
    stream: &mut UnixStream,
    kind: u8,
    version: &str,
    status: Option<u8>,
) -> io::Result<()> {
    validate_version(version).map_err(invalid_input)?;
    let mut payload = [0_u8; MAX_HELLO_LEN];
    payload[..4].copy_from_slice(&MAGIC);
    payload[4] = kind;
    let offset = if let Some(status) = status {
        payload[5] = status;
        6
    } else {
        5
    };
    payload[offset..offset + version.len()].copy_from_slice(version.as_bytes());
    write_frame(stream, &payload[..offset + version.len()])
}

fn read_hello(
    stream: &mut UnixStream,
    expected_kind: u8,
    header_len: usize,
) -> io::Result<([u8; MAX_HELLO_LEN], usize)> {
    let len = read_frame_length(stream)?;
    if len <= header_len || len > header_len + MAX_VERSION_LEN {
        return Err(invalid_data("invalid version handshake frame length"));
    }
    let mut payload = [0_u8; MAX_HELLO_LEN];
    stream.read_exact(&mut payload[..len])?;
    validate_header(&payload[..len], expected_kind)?;
    Ok((payload, len))
}

pub(crate) fn write_control_request(
    stream: &mut UnixStream,
    request: &ControlRequest,
) -> io::Result<()> {
    let wire = WireRequest::try_from(request)?;
    write_json_frame(stream, REQUEST_KIND, &wire)
}

pub(crate) fn read_control_request(stream: &mut UnixStream) -> io::Result<ControlRequest> {
    let wire: WireRequest = read_json_frame(stream, REQUEST_KIND)?;
    wire.try_into()
}

pub(crate) fn write_control_response(
    stream: &mut UnixStream,
    response: &ControlResponse,
) -> io::Result<()> {
    let mut wire = WireResponse::try_from(response)?;
    bound_wire_response(&mut wire)?;
    write_json_frame(stream, RESPONSE_KIND, &wire)
}

pub(crate) fn read_control_response(stream: &mut UnixStream) -> io::Result<ControlResponse> {
    let wire: WireResponse = read_json_frame(stream, RESPONSE_KIND)?;
    wire.try_into()
}
fn bound_wire_response(response: &mut WireResponse) -> io::Result<()> {
    loop {
        let encoded = serde_json::to_vec(response).map_err(invalid_data)?;
        if MAGIC.len() + 1 + encoded.len() <= MAX_CONTROL_FRAME_LEN {
            return Ok(());
        }
        let removed = match &mut response.result {
            Ok(WireResult::Instances { instances }) => instances.pop().is_some(),
            Ok(WireResult::WorkspaceMetadataRepaired { repair }) => repair.paths.pop().is_some(),
            _ => false,
        };
        if !removed {
            response.result = Err(WireError {
                code: "response_too_large".to_owned(),
                message: "operation result exceeds the control response bound".to_owned(),
            });
        }
    }
}

fn validate_version(version: &str) -> Result<(), &'static str> {
    if version.is_empty()
        || version.len() > MAX_VERSION_LEN
        || !version.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err("invalid application version");
    }
    Ok(())
}

fn write_json_frame<T: Serialize>(stream: &mut UnixStream, kind: u8, value: &T) -> io::Result<()> {
    let encoded = serde_json::to_vec(value).map_err(invalid_data)?;
    let payload_len = MAGIC.len() + 1 + encoded.len();
    if payload_len > MAX_CONTROL_FRAME_LEN {
        return Err(invalid_input("control frame exceeds maximum length"));
    }
    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(&MAGIC);
    payload.push(kind);
    payload.extend_from_slice(&encoded);
    write_frame(stream, &payload)
}

fn read_json_frame<T: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
    expected_kind: u8,
) -> io::Result<T> {
    let payload_len = read_frame_length(stream)?;
    if payload_len < MAGIC.len() + 1 || payload_len > MAX_CONTROL_FRAME_LEN {
        return Err(invalid_data("invalid control frame length"));
    }
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload)?;
    validate_header(&payload, expected_kind)?;
    serde_json::from_slice(&payload[5..]).map_err(invalid_data)
}

fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| invalid_input("frame length exceeds u32"))?;
    stream.write_all(&payload_len.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

fn read_frame_length(stream: &mut UnixStream) -> io::Result<usize> {
    let mut encoded_len = [0_u8; 4];
    stream.read_exact(&mut encoded_len)?;
    Ok(u32::from_be_bytes(encoded_len) as usize)
}

fn validate_header(payload: &[u8], expected_kind: u8) -> io::Result<()> {
    if payload.get(..4) != Some(MAGIC.as_slice()) {
        return Err(invalid_data("invalid frame magic"));
    }
    if payload.get(4) != Some(&expected_kind) {
        return Err(invalid_data(format!(
            "unexpected frame kind {}; expected {expected_kind}",
            payload.get(4).copied().unwrap_or_default()
        )));
    }
    Ok(())
}

fn decode_version(payload: &[u8]) -> io::Result<String> {
    let version = std::str::from_utf8(payload).map_err(invalid_data)?;
    validate_version(version).map_err(invalid_data)?;
    Ok(version.to_owned())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    request_id: u64,
    operation: WireRequestOperation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
enum WireRequestOperation {
    PrepareLaunch {
        current_directory: Vec<u8>,
        name: Option<String>,
        here: bool,
        profile: String,
        limits: WireResourceLimits,
        herdr: Option<WireHerdrContext>,
        no_multiplex: bool,
        continuation: Option<Box<WireLaunchHandoff>>,
        continuation_token: Option<String>,
    },
    ResumeLaunch {
        token: String,
        herdr: WireHerdrContext,
    },
    ListInstances {
        after: Option<String>,
        limit: u16,
    },
    GetInstance {
        id: String,
    },
    StopInstance {
        id: String,
        mode: WireStopMode,
    },
    RetireWorkspace {
        current_directory: Vec<u8>,
        name: String,
    },
    RepairWorkspaceMetadata {
        current_directory: Vec<u8>,
    },
    ManageServices {
        current_directory: Vec<u8>,
        action: WireServiceAction,
    },
}

impl TryFrom<&ControlRequest> for WireRequest {
    type Error = io::Error;

    fn try_from(request: &ControlRequest) -> io::Result<Self> {
        let operation = match &request.operation {
            ControlOperation::PrepareLaunch(request) => wire_prepare_launch(request)?,
            ControlOperation::ResumeLaunch { token, herdr } => {
                validate_name(token, "continuation token")?;
                validate_context(herdr)?;
                WireRequestOperation::ResumeLaunch {
                    token: token.clone(),
                    herdr: herdr.into(),
                }
            }
            ControlOperation::ListInstances { after, limit } => {
                validate_list_limit(*limit)?;
                if let Some(after) = after {
                    validate_name(&after.0, "instance ID")?;
                }
                WireRequestOperation::ListInstances {
                    after: after.as_ref().map(|id| id.0.clone()),
                    limit: *limit,
                }
            }
            ControlOperation::GetInstance { id } => {
                validate_name(&id.0, "instance ID")?;
                WireRequestOperation::GetInstance { id: id.0.clone() }
            }
            ControlOperation::StopInstance { id, mode } => {
                validate_name(&id.0, "instance ID")?;
                WireRequestOperation::StopInstance {
                    id: id.0.clone(),
                    mode: (*mode).into(),
                }
            }
            ControlOperation::RetireWorkspace {
                current_directory,
                name,
            } => {
                validate_path(current_directory.as_os_str())?;
                validate_name(&name.0, "workspace name")?;
                WireRequestOperation::RetireWorkspace {
                    current_directory: current_directory.as_os_str().as_bytes().to_vec(),
                    name: name.0.clone(),
                }
            }
            ControlOperation::RepairWorkspaceMetadata { current_directory } => {
                validate_path(current_directory.as_os_str())?;
                WireRequestOperation::RepairWorkspaceMetadata {
                    current_directory: current_directory.as_os_str().as_bytes().to_vec(),
                }
            }
            ControlOperation::ManageServices {
                current_directory,
                action,
            } => {
                validate_path(current_directory.as_os_str())?;
                WireRequestOperation::ManageServices {
                    current_directory: current_directory.as_os_str().as_bytes().to_vec(),
                    action: (*action).into(),
                }
            }
        };
        Ok(Self {
            request_id: request.request_id,
            operation,
        })
    }
}

impl TryFrom<WireRequest> for ControlRequest {
    type Error = io::Error;

    fn try_from(request: WireRequest) -> io::Result<Self> {
        let operation = match request.operation {
            WireRequestOperation::PrepareLaunch {
                current_directory,
                name,
                here,
                profile,
                limits,
                herdr,
                no_multiplex,
                continuation,
                continuation_token,
            } => {
                validate_name(&profile, "profile")?;
                let limits = ResourceLimits::from(limits);
                validate_limits(&limits)?;
                let herdr = herdr.map(HerdrContext::from);
                if let Some(context) = &herdr {
                    validate_context(context)?;
                }
                if let Some(token) = continuation_token.as_deref() {
                    validate_name(token, "continuation token")?;
                }
                if no_multiplex && (continuation.is_some() || continuation_token.is_some()) {
                    return Err(invalid_data(
                        "current-terminal launch cannot contain Herdr routing metadata",
                    ));
                }
                ControlOperation::PrepareLaunch(PrepareLaunchRequest {
                    workspace: LaunchRequest {
                        current_directory: path_from_bytes(current_directory)?,
                        workspace: name_to_selection(name, here)?,
                    },
                    profile,
                    limits,
                    herdr,
                    no_multiplex,
                    continuation: continuation
                        .map(|handoff| model_handoff(*handoff).map(Box::new))
                        .transpose()?,
                    continuation_token,
                })
            }
            WireRequestOperation::ResumeLaunch { token, herdr } => {
                validate_name(&token, "continuation token")?;
                let herdr = HerdrContext::from(herdr);
                validate_context(&herdr)?;
                ControlOperation::ResumeLaunch { token, herdr }
            }
            WireRequestOperation::ListInstances { after, limit } => {
                validate_list_limit(limit)?;
                let after = after
                    .map(|id| {
                        validate_name(&id, "instance ID")?;
                        Ok::<InstanceId, io::Error>(InstanceId(id))
                    })
                    .transpose()?;
                ControlOperation::ListInstances { after, limit }
            }
            WireRequestOperation::GetInstance { id } => {
                validate_name(&id, "instance ID")?;
                ControlOperation::GetInstance { id: InstanceId(id) }
            }
            WireRequestOperation::StopInstance { id, mode } => {
                validate_name(&id, "instance ID")?;
                ControlOperation::StopInstance {
                    id: InstanceId(id),
                    mode: mode.into(),
                }
            }
            WireRequestOperation::RetireWorkspace {
                current_directory,
                name,
            } => {
                validate_name(&name, "workspace name")?;
                ControlOperation::RetireWorkspace {
                    current_directory: path_from_bytes(current_directory)?,
                    name: WorkspaceName(name),
                }
            }
            WireRequestOperation::RepairWorkspaceMetadata { current_directory } => {
                ControlOperation::RepairWorkspaceMetadata {
                    current_directory: path_from_bytes(current_directory)?,
                }
            }
            WireRequestOperation::ManageServices {
                current_directory,
                action,
            } => ControlOperation::ManageServices {
                current_directory: path_from_bytes(current_directory)?,
                action: action.into(),
            },
        };
        Ok(Self {
            request_id: request.request_id,
            operation,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    request_id: u64,
    result: Result<WireResult, WireError>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
enum WireResult {
    LaunchPrepared {
        launch: WirePreparedLaunch,
    },
    LaunchRedirected,
    LaunchContinuation {
        continuation: WireLauncherContinuation,
    },
    Instances {
        instances: Vec<WireInstanceRecord>,
    },
    Instance {
        instance: Option<WireInstanceRecord>,
    },
    InstanceStopped {
        instance: WireInstanceRecord,
    },
    WorkspaceRetired {
        workspace: WireRetiredWorkspace,
    },
    WorkspaceMetadataRepaired {
        repair: WirePrunedWorktrees,
    },
    ServicesCompleted {
        output: String,
    },
    ServiceConfiguration {
        configuration: WireServiceConfiguration,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireLaunchHandoff {
    socket_path: Vec<u8>,
    command: String,
    mount_arguments: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireLauncherContinuation {
    socket_path: Vec<u8>,
    name: Option<String>,
    here: bool,
    profile: String,
    command: String,
    mount_arguments: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePreparedLaunch {
    instance_id: String,
    workspace: WireWorkspace,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRetiredWorkspace {
    project: String,
    name: String,
    path: Vec<u8>,
    branch: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePrunedWorktrees {
    project: String,
    paths: Vec<Vec<u8>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireWorkspace {
    project: String,
    primary_checkout: Vec<u8>,
    name: Option<String>,
    here: bool,
    path: Vec<u8>,
    change_name: Option<String>,
    origin: WireOrigin,
    support_mounts: Vec<WireSupportMount>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireInstanceRecord {
    id: String,
    scope_handle: String,
    workspace: WireWorkspace,
    profile: String,
    limits: WireResourceLimits,
    leader: u32,
    state: WireInstanceState,
    activity: Option<WireActivity>,
    herdr: Option<WireHerdrContext>,
    created_at_ms: u64,
    updated_at_ms: u64,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireServiceConfiguration {
    project_root: Vec<u8>,
    global_environment_file: Vec<u8>,
    project_environment_file: Vec<u8>,
    database_url: String,
    qdrant_url: String,
    state_directory: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireOrigin {
    Primary,
    Created,
    Existing,
    Directory,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireInstanceState {
    Starting,
    Running,
    Stopping,
    Exited,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireActivityState {
    Working,
    Idle,
    Blocked,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireStopMode {
    Graceful,
    Force,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireServiceAction {
    Up,
    Down,
    Status,
    Config,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireResourceLimits {
    memory_max_bytes: Option<u64>,
    tasks_max: Option<u64>,
    cpu_quota_basis_points: Option<u32>,
    #[serde(default)]
    cpu_cores: Option<Vec<u32>>,
    #[serde(default)]
    cpu_count: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHerdrContext {
    workspace_id: Option<String>,
    pane_id: Option<String>,
    session_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireActivity {
    state: WireActivityState,
    message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireSupportMount {
    source: Vec<u8>,
    destination: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireError {
    code: String,
    message: String,
}

impl TryFrom<&ControlResponse> for WireResponse {
    type Error = io::Error;

    fn try_from(response: &ControlResponse) -> io::Result<Self> {
        let result = match &response.result {
            Ok(ControlResult::LaunchPrepared(launch)) => Ok(WireResult::LaunchPrepared {
                launch: wire_launch(launch)?,
            }),
            Ok(ControlResult::LaunchRedirected) => Ok(WireResult::LaunchRedirected),
            Ok(ControlResult::LaunchContinuation(continuation)) => {
                Ok(WireResult::LaunchContinuation {
                    continuation: wire_continuation(continuation)?,
                })
            }
            Ok(ControlResult::Instances(instances)) => {
                if instances.len() > usize::from(MAX_LIST_LIMIT) {
                    return Err(invalid_input("too many instances in response"));
                }
                Ok(WireResult::Instances {
                    instances: instances
                        .iter()
                        .map(wire_instance)
                        .collect::<io::Result<_>>()?,
                })
            }
            Ok(ControlResult::Instance(instance)) => Ok(WireResult::Instance {
                instance: instance.as_ref().map(wire_instance).transpose()?,
            }),
            Ok(ControlResult::InstanceStopped(instance)) => Ok(WireResult::InstanceStopped {
                instance: wire_instance(instance)?,
            }),
            Ok(ControlResult::WorkspaceRetired(workspace)) => {
                validate_name(&workspace.project.0, "project ID")?;
                validate_name(&workspace.name.0, "workspace name")?;
                validate_path(workspace.path.as_os_str())?;
                validate_name(&workspace.branch, "workspace branch")?;
                Ok(WireResult::WorkspaceRetired {
                    workspace: WireRetiredWorkspace {
                        project: workspace.project.0.clone(),
                        name: workspace.name.0.clone(),
                        path: workspace.path.as_os_str().as_bytes().to_vec(),
                        branch: workspace.branch.clone(),
                    },
                })
            }
            Ok(ControlResult::WorkspaceMetadataRepaired(repair)) => {
                validate_name(&repair.project.0, "project ID")?;
                let paths = repair
                    .paths
                    .iter()
                    .map(|path| {
                        validate_path(path.as_os_str())?;
                        Ok(path.as_os_str().as_bytes().to_vec())
                    })
                    .collect::<io::Result<_>>()?;
                Ok(WireResult::WorkspaceMetadataRepaired {
                    repair: WirePrunedWorktrees {
                        project: repair.project.0.clone(),
                        paths,
                    },
                })
            }
            Ok(ControlResult::Services(ServiceResult::Completed { output })) => {
                validate_service_value(output, "service output")?;
                Ok(WireResult::ServicesCompleted {
                    output: output.clone(),
                })
            }
            Ok(ControlResult::Services(ServiceResult::Configuration(configuration))) => {
                Ok(WireResult::ServiceConfiguration {
                    configuration: wire_service_configuration(configuration)?,
                })
            }
            Err(error) => {
                validate_diagnostic(&error.code, "error code")?;
                validate_diagnostic(&error.message, "error message")?;
                Err(WireError {
                    code: error.code.clone(),
                    message: error.message.clone(),
                })
            }
        };
        Ok(Self {
            request_id: response.request_id,
            result,
        })
    }
}

impl TryFrom<WireResponse> for ControlResponse {
    type Error = io::Error;

    fn try_from(response: WireResponse) -> io::Result<Self> {
        let result = match response.result {
            Ok(WireResult::LaunchPrepared { launch }) => {
                Ok(ControlResult::LaunchPrepared(model_launch(launch)?))
            }
            Ok(WireResult::LaunchRedirected) => Ok(ControlResult::LaunchRedirected),
            Ok(WireResult::LaunchContinuation { continuation }) => Ok(
                ControlResult::LaunchContinuation(model_continuation(continuation)?),
            ),
            Ok(WireResult::Instances { instances }) => {
                if instances.len() > usize::from(MAX_LIST_LIMIT) {
                    return Err(invalid_data("too many instances in response"));
                }
                Ok(ControlResult::Instances(
                    instances
                        .into_iter()
                        .map(model_instance)
                        .collect::<io::Result<_>>()?,
                ))
            }
            Ok(WireResult::Instance { instance }) => Ok(ControlResult::Instance(
                instance.map(model_instance).transpose()?,
            )),
            Ok(WireResult::InstanceStopped { instance }) => {
                Ok(ControlResult::InstanceStopped(model_instance(instance)?))
            }
            Ok(WireResult::WorkspaceRetired { workspace }) => {
                validate_name(&workspace.project, "project ID")?;
                validate_name(&workspace.name, "workspace name")?;
                validate_name(&workspace.branch, "workspace branch")?;
                Ok(ControlResult::WorkspaceRetired(RetiredWorkspace {
                    project: ProjectId(workspace.project),
                    name: WorkspaceName(workspace.name),
                    path: path_from_bytes(workspace.path)?,
                    branch: workspace.branch,
                }))
            }
            Ok(WireResult::WorkspaceMetadataRepaired { repair }) => {
                validate_name(&repair.project, "project ID")?;
                Ok(ControlResult::WorkspaceMetadataRepaired(PrunedWorktrees {
                    project: ProjectId(repair.project),
                    paths: repair
                        .paths
                        .into_iter()
                        .map(path_from_bytes)
                        .collect::<io::Result<_>>()?,
                }))
            }
            Ok(WireResult::ServicesCompleted { output }) => {
                validate_service_value(&output, "service output")?;
                Ok(ControlResult::Services(ServiceResult::Completed { output }))
            }
            Ok(WireResult::ServiceConfiguration { configuration }) => Ok(ControlResult::Services(
                ServiceResult::Configuration(model_service_configuration(configuration)?),
            )),
            Err(error) => {
                validate_diagnostic(&error.code, "error code")?;
                validate_diagnostic(&error.message, "error message")?;
                Err(ControlError {
                    code: error.code,
                    message: error.message,
                })
            }
        };
        Ok(Self {
            request_id: response.request_id,
            result,
        })
    }
}
fn wire_prepare_launch(request: &PrepareLaunchRequest) -> io::Result<WireRequestOperation> {
    validate_path(request.workspace.current_directory.as_os_str())?;
    let name = selection_name(&request.workspace.workspace)?;
    validate_name(&request.profile, "profile")?;
    validate_limits(&request.limits)?;
    if let Some(context) = &request.herdr {
        validate_context(context)?;
    }
    if let Some(token) = request.continuation_token.as_deref() {
        validate_name(token, "continuation token")?;
    }
    if request.no_multiplex
        && (request.continuation.is_some() || request.continuation_token.is_some())
    {
        return Err(invalid_input(
            "current-terminal launch cannot contain Herdr routing metadata",
        ));
    }
    Ok(WireRequestOperation::PrepareLaunch {
        current_directory: request
            .workspace
            .current_directory
            .as_os_str()
            .as_bytes()
            .to_vec(),
        name,
        here: matches!(request.workspace.workspace, WorkspaceSelection::Here),
        profile: request.profile.clone(),
        limits: (&request.limits).into(),
        herdr: request.herdr.as_ref().map(Into::into),
        no_multiplex: request.no_multiplex,
        continuation: request
            .continuation
            .as_deref()
            .map(|handoff| wire_handoff(handoff).map(Box::new))
            .transpose()?,
        continuation_token: request.continuation_token.clone(),
    })
}

fn wire_handoff(handoff: &LaunchHandoff) -> io::Result<WireLaunchHandoff> {
    validate_path(handoff.socket_path.as_os_str())?;
    if !handoff.socket_path.is_absolute() {
        return Err(invalid_input("continuation socket must be absolute"));
    }
    validate_command(&handoff.command)?;
    validate_mount_arguments(&handoff.mount_arguments)?;
    Ok(WireLaunchHandoff {
        socket_path: handoff.socket_path.as_os_str().as_bytes().to_vec(),
        command: handoff.command.clone(),
        mount_arguments: handoff.mount_arguments.clone(),
    })
}

fn model_handoff(handoff: WireLaunchHandoff) -> io::Result<LaunchHandoff> {
    let socket_path = path_from_bytes(handoff.socket_path)?;
    if !socket_path.is_absolute() {
        return Err(invalid_data("continuation socket must be absolute"));
    }
    validate_command(&handoff.command)?;
    validate_mount_arguments(&handoff.mount_arguments)
        .map_err(|error| invalid_data(error.to_string()))?;
    Ok(LaunchHandoff {
        socket_path,
        command: handoff.command,
        mount_arguments: handoff.mount_arguments,
    })
}

fn wire_continuation(continuation: &LauncherContinuation) -> io::Result<WireLauncherContinuation> {
    validate_path(continuation.socket_path.as_os_str())?;
    if !continuation.socket_path.is_absolute() {
        return Err(invalid_input("continuation socket must be absolute"));
    }
    let name = selection_name(&continuation.workspace)?;
    validate_name(&continuation.profile, "continuation profile")?;
    validate_command(&continuation.command)?;
    validate_mount_arguments(&continuation.mount_arguments)?;
    Ok(WireLauncherContinuation {
        socket_path: continuation.socket_path.as_os_str().as_bytes().to_vec(),
        name,
        here: matches!(continuation.workspace, WorkspaceSelection::Here),
        profile: continuation.profile.clone(),
        command: continuation.command.clone(),
        mount_arguments: continuation.mount_arguments.clone(),
    })
}

fn model_continuation(continuation: WireLauncherContinuation) -> io::Result<LauncherContinuation> {
    let socket_path = path_from_bytes(continuation.socket_path)?;
    if !socket_path.is_absolute() {
        return Err(invalid_data("continuation socket must be absolute"));
    }
    validate_name(&continuation.profile, "continuation profile")?;
    validate_command(&continuation.command)?;
    validate_mount_arguments(&continuation.mount_arguments)
        .map_err(|error| invalid_data(error.to_string()))?;
    Ok(LauncherContinuation {
        socket_path,
        workspace: name_to_selection(continuation.name, continuation.here)?,
        profile: continuation.profile,
        command: continuation.command,
        mount_arguments: continuation.mount_arguments,
    })
}

fn wire_launch(launch: &PreparedLaunch) -> io::Result<WirePreparedLaunch> {
    validate_name(&launch.instance_id.0, "instance ID")?;
    Ok(WirePreparedLaunch {
        instance_id: launch.instance_id.0.clone(),
        workspace: wire_workspace(&launch.workspace)?,
    })
}

fn model_launch(launch: WirePreparedLaunch) -> io::Result<PreparedLaunch> {
    validate_name(&launch.instance_id, "instance ID")?;
    Ok(PreparedLaunch {
        instance_id: InstanceId(launch.instance_id),
        workspace: model_workspace(launch.workspace)?,
    })
}

fn wire_workspace(workspace: &ResolvedWorkspace) -> io::Result<WireWorkspace> {
    validate_name(&workspace.project.0, "project ID")?;
    validate_path(workspace.primary_checkout.as_os_str())?;
    validate_path(workspace.path.as_os_str())?;
    let name = selection_name(&workspace.selection)?;
    let here = matches!(workspace.selection, WorkspaceSelection::Here);
    if here != matches!(workspace.origin, WorkspaceOrigin::Directory)
        || (here
            && (workspace.primary_checkout != workspace.path
                || workspace.change_name.is_some()
                || !workspace.support_mounts.is_empty()))
    {
        return Err(invalid_input("inconsistent directory workspace metadata"));
    }
    if workspace.support_mounts.len() > MAX_SUPPORT_MOUNTS {
        return Err(invalid_input("too many workspace support mounts"));
    }
    if let Some(change) = &workspace.change_name {
        validate_name(change, "change name")?;
    }
    Ok(WireWorkspace {
        project: workspace.project.0.clone(),
        primary_checkout: workspace.primary_checkout.as_os_str().as_bytes().to_vec(),
        name,
        here,
        path: workspace.path.as_os_str().as_bytes().to_vec(),
        change_name: workspace.change_name.clone(),
        origin: workspace.origin.into(),
        support_mounts: workspace
            .support_mounts
            .iter()
            .map(|mount| {
                validate_path(mount.source.as_os_str())?;
                validate_path(mount.destination.as_os_str())?;
                Ok(WireSupportMount {
                    source: mount.source.as_os_str().as_bytes().to_vec(),
                    destination: mount.destination.as_os_str().as_bytes().to_vec(),
                })
            })
            .collect::<io::Result<_>>()?,
    })
}

fn model_workspace(workspace: WireWorkspace) -> io::Result<ResolvedWorkspace> {
    validate_name(&workspace.project, "project ID")?;
    if workspace.support_mounts.len() > MAX_SUPPORT_MOUNTS {
        return Err(invalid_data("too many workspace support mounts"));
    }
    if let Some(change) = &workspace.change_name {
        validate_name(change, "change name")?;
    }
    if workspace.here != matches!(workspace.origin, WireOrigin::Directory)
        || (workspace.here
            && (workspace.primary_checkout != workspace.path
                || workspace.change_name.is_some()
                || !workspace.support_mounts.is_empty()))
    {
        return Err(invalid_data("inconsistent directory workspace metadata"));
    }
    Ok(ResolvedWorkspace {
        project: ProjectId(workspace.project),
        primary_checkout: path_from_bytes(workspace.primary_checkout)?,
        selection: name_to_selection(workspace.name, workspace.here)?,
        path: path_from_bytes(workspace.path)?,
        change_name: workspace.change_name,
        origin: workspace.origin.into(),
        support_mounts: workspace
            .support_mounts
            .into_iter()
            .map(|mount| {
                Ok(WorkspaceSupportMount {
                    source: path_from_bytes(mount.source)?,
                    destination: path_from_bytes(mount.destination)?,
                })
            })
            .collect::<io::Result<_>>()?,
    })
}

fn wire_instance(instance: &InstanceRecord) -> io::Result<WireInstanceRecord> {
    validate_name(&instance.id.0, "instance ID")?;
    validate_name(&instance.scope_handle, "scope handle")?;
    validate_name(&instance.profile, "profile")?;
    validate_limits(&instance.limits)?;
    if let Some(activity) = &instance.activity {
        validate_activity(activity)?;
    }
    if let Some(context) = &instance.herdr {
        validate_context(context)?;
    }
    if instance.created_at_ms > instance.updated_at_ms {
        return Err(invalid_input(
            "instance creation timestamp is after update timestamp",
        ));
    }
    Ok(WireInstanceRecord {
        id: instance.id.0.clone(),
        scope_handle: instance.scope_handle.clone(),
        workspace: wire_workspace(&instance.workspace)?,
        profile: instance.profile.clone(),
        limits: (&instance.limits).into(),
        leader: instance.leader.0.get(),
        state: instance.state.into(),
        activity: instance.activity.as_ref().map(Into::into),
        herdr: instance.herdr.as_ref().map(Into::into),
        created_at_ms: instance.created_at_ms,
        updated_at_ms: instance.updated_at_ms,
    })
}

fn model_instance(instance: WireInstanceRecord) -> io::Result<InstanceRecord> {
    validate_name(&instance.id, "instance ID")?;
    validate_name(&instance.scope_handle, "scope handle")?;
    validate_name(&instance.profile, "profile")?;
    let limits = instance.limits.into();
    validate_limits(&limits)?;
    let activity = instance.activity.map(ActivityUpdate::from);
    if let Some(activity) = &activity {
        validate_activity(activity)?;
    }
    let herdr = instance.herdr.map(HerdrContext::from);
    if let Some(context) = &herdr {
        validate_context(context)?;
    }
    if instance.created_at_ms > instance.updated_at_ms {
        return Err(invalid_data(
            "instance creation timestamp is after update timestamp",
        ));
    }
    let leader = std::num::NonZeroU32::new(instance.leader)
        .ok_or_else(|| invalid_data("instance leader PID is zero"))?;
    Ok(InstanceRecord {
        id: InstanceId(instance.id),
        scope_handle: instance.scope_handle,
        workspace: model_workspace(instance.workspace)?,
        profile: instance.profile,
        limits,
        leader: ProcessId(leader),
        state: instance.state.into(),
        activity,
        herdr,
        created_at_ms: instance.created_at_ms,
        updated_at_ms: instance.updated_at_ms,
    })
}
fn wire_service_configuration(
    configuration: &ServiceConfiguration,
) -> io::Result<WireServiceConfiguration> {
    for path in [
        &configuration.project_root,
        &configuration.global_environment_file,
        &configuration.project_environment_file,
    ] {
        validate_path(path.as_os_str())?;
    }
    for (name, value) in [
        ("database URL", configuration.database_url.as_str()),
        ("Qdrant URL", configuration.qdrant_url.as_str()),
        ("state directory", configuration.state_directory.as_str()),
    ] {
        validate_service_value(value, name)?;
    }
    Ok(WireServiceConfiguration {
        project_root: configuration.project_root.as_os_str().as_bytes().to_vec(),
        global_environment_file: configuration
            .global_environment_file
            .as_os_str()
            .as_bytes()
            .to_vec(),
        project_environment_file: configuration
            .project_environment_file
            .as_os_str()
            .as_bytes()
            .to_vec(),
        database_url: configuration.database_url.clone(),
        qdrant_url: configuration.qdrant_url.clone(),
        state_directory: configuration.state_directory.clone(),
    })
}

fn model_service_configuration(
    configuration: WireServiceConfiguration,
) -> io::Result<ServiceConfiguration> {
    for (name, value) in [
        ("database URL", configuration.database_url.as_str()),
        ("Qdrant URL", configuration.qdrant_url.as_str()),
        ("state directory", configuration.state_directory.as_str()),
    ] {
        validate_service_value(value, name)?;
    }
    Ok(ServiceConfiguration {
        project_root: path_from_bytes(configuration.project_root)?,
        global_environment_file: path_from_bytes(configuration.global_environment_file)?,
        project_environment_file: path_from_bytes(configuration.project_environment_file)?,
        database_url: configuration.database_url,
        qdrant_url: configuration.qdrant_url,
        state_directory: configuration.state_directory,
    })
}

fn selection_name(selection: &WorkspaceSelection) -> io::Result<Option<String>> {
    match selection {
        WorkspaceSelection::Primary | WorkspaceSelection::Here => Ok(None),
        WorkspaceSelection::Named(name) => {
            validate_name(&name.0, "workspace name")?;
            Ok(Some(name.0.clone()))
        }
    }
}

fn name_to_selection(name: Option<String>, here: bool) -> io::Result<WorkspaceSelection> {
    if here {
        if name.is_some() {
            return Err(invalid_data(
                "directory selection cannot contain a workspace name",
            ));
        }
        return Ok(WorkspaceSelection::Here);
    }
    match name {
        Some(name) => {
            validate_name(&name, "workspace name")?;
            Ok(WorkspaceSelection::Named(WorkspaceName(name)))
        }
        None => Ok(WorkspaceSelection::Primary),
    }
}

fn validate_mount_arguments(arguments: &[String]) -> io::Result<()> {
    if arguments.len() > MAX_MOUNT_ARGUMENTS {
        return Err(invalid_input("too many continuation mounts"));
    }
    for argument in arguments {
        let (paths, access) = argument
            .rsplit_once(':')
            .ok_or_else(|| invalid_input("continuation mount requires explicit access"))?;
        if !matches!(access, "ro" | "rw") {
            return Err(invalid_input("invalid continuation mount access"));
        }
        let (source, destination) = paths
            .rsplit_once('@')
            .ok_or_else(|| invalid_input("continuation mount requires a destination"))?;
        for path in [source, destination] {
            validate_path(OsStr::new(path))?;
            if !Path::new(path).is_absolute()
                || Path::new(path).components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
            {
                return Err(invalid_input(
                    "continuation mount paths must be absolute and normalized",
                ));
            }
        }
    }
    Ok(())
}

fn validate_name(name: &str, field: &str) -> io::Result<()> {
    if name.is_empty() || name.len() > MAX_NAME_LEN || name.chars().any(char::is_control) {
        return Err(invalid_input(format!(
            "{field} is empty, too long, or contains control characters"
        )));
    }
    Ok(())
}
fn validate_path(path: &OsStr) -> io::Result<()> {
    let bytes = path.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_PATH_LEN || bytes.contains(&0) {
        return Err(invalid_input("path is empty, too long, or contains NUL"));
    }
    Ok(())
}

fn validate_command(command: &str) -> io::Result<()> {
    if command.is_empty() || command.len() > MAX_COMMAND_LEN || command.contains('\0') {
        return Err(invalid_input(
            "continuation command is empty, too long, or contains NUL",
        ));
    }
    Ok(())
}

fn validate_list_limit(limit: u16) -> io::Result<()> {
    if limit == 0 || limit > MAX_LIST_LIMIT {
        return Err(invalid_input("list limit must be between 1 and 100"));
    }
    Ok(())
}

fn validate_limits(limits: &ResourceLimits) -> io::Result<()> {
    if limits.memory_max_bytes == Some(0)
        || limits
            .memory_max_bytes
            .is_some_and(|value| value > MAX_MEMORY_BYTES)
        || limits.tasks_max == Some(0)
        || limits.tasks_max.is_some_and(|value| value > MAX_TASKS)
        || limits.cpu_quota_basis_points == Some(0)
        || limits
            .cpu_quota_basis_points
            .is_some_and(|value| value > MAX_CPU_QUOTA_BASIS_POINTS)
        || !limits.valid_cpu_selection()
    {
        return Err(invalid_input(
            "resource limit is invalid or exceeds protocol bounds",
        ));
    }
    Ok(())
}

fn validate_context(context: &HerdrContext) -> io::Result<()> {
    for (name, value) in [
        ("workspace ID", context.workspace_id.as_deref()),
        ("pane ID", context.pane_id.as_deref()),
        ("session name", context.session_name.as_deref()),
    ] {
        if let Some(value) = value {
            validate_name(value, name)?;
        }
    }
    Ok(())
}

fn validate_activity(activity: &ActivityUpdate) -> io::Result<()> {
    if let Some(message) = &activity.message {
        validate_diagnostic(message, "activity message")?;
    }
    Ok(())
}

fn validate_diagnostic(value: &str, field: &str) -> io::Result<()> {
    if value.len() > MAX_DIAGNOSTIC_LEN || value.chars().any(char::is_control) {
        return Err(invalid_input(format!(
            "{field} exceeds maximum length or contains control characters"
        )));
    }
    Ok(())
}
fn validate_service_value(value: &str, field: &str) -> io::Result<()> {
    if value.len() > MAX_CONTROL_FRAME_LEN / 2 || value.contains('\0') {
        return Err(invalid_input(format!(
            "{field} exceeds bounds or contains NUL"
        )));
    }
    Ok(())
}

macro_rules! enum_conversions {
    ($model:ty, $wire:ty, {$($variant:ident),+ $(,)?}) => {
        impl From<$model> for $wire {
            fn from(value: $model) -> Self {
                match value { $(<$model>::$variant => Self::$variant),+ }
            }
        }
        impl From<$wire> for $model {
            fn from(value: $wire) -> Self {
                match value { $(<$wire>::$variant => Self::$variant),+ }
            }
        }
    };
}

enum_conversions!(WorkspaceOrigin, WireOrigin, { Primary, Created, Existing, Directory });
enum_conversions!(InstanceState, WireInstanceState, { Starting, Running, Stopping, Exited, Failed });
enum_conversions!(ActivityState, WireActivityState, { Working, Idle, Blocked });
enum_conversions!(StopMode, WireStopMode, { Graceful, Force });
enum_conversions!(ServiceAction, WireServiceAction, { Up, Down, Status, Config });

impl From<&ResourceLimits> for WireResourceLimits {
    fn from(value: &ResourceLimits) -> Self {
        Self {
            memory_max_bytes: value.memory_max_bytes,
            tasks_max: value.tasks_max,
            cpu_quota_basis_points: value.cpu_quota_basis_points,
            cpu_cores: value.cpu_cores.clone(),
            cpu_count: value.cpu_count,
        }
    }
}

impl From<WireResourceLimits> for ResourceLimits {
    fn from(value: WireResourceLimits) -> Self {
        Self {
            memory_max_bytes: value.memory_max_bytes,
            tasks_max: value.tasks_max,
            cpu_quota_basis_points: value.cpu_quota_basis_points,
            cpu_cores: value.cpu_cores,
            cpu_count: value.cpu_count,
        }
    }
}

impl From<&HerdrContext> for WireHerdrContext {
    fn from(value: &HerdrContext) -> Self {
        Self {
            workspace_id: value.workspace_id.clone(),
            pane_id: value.pane_id.clone(),
            session_name: value.session_name.clone(),
        }
    }
}

impl From<WireHerdrContext> for HerdrContext {
    fn from(value: WireHerdrContext) -> Self {
        Self {
            workspace_id: value.workspace_id,
            pane_id: value.pane_id,
            session_name: value.session_name,
        }
    }
}

impl From<&ActivityUpdate> for WireActivity {
    fn from(value: &ActivityUpdate) -> Self {
        Self {
            state: value.state.into(),
            message: value.message.clone(),
        }
    }
}

impl From<WireActivity> for ActivityUpdate {
    fn from(value: WireActivity) -> Self {
        Self {
            state: value.state.into(),
            message: value.message,
        }
    }
}

fn path_from_bytes(bytes: Vec<u8>) -> io::Result<PathBuf> {
    validate_path(OsStr::from_bytes(&bytes))?;
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

fn invalid_input(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory_workspace() -> ResolvedWorkspace {
        ResolvedWorkspace {
            project: ProjectId("directory-project".to_owned()),
            primary_checkout: PathBuf::from("/project/nested"),
            selection: WorkspaceSelection::Here,
            path: PathBuf::from("/project/nested"),
            change_name: None,
            origin: WorkspaceOrigin::Directory,
            support_mounts: Vec::new(),
        }
    }

    fn directory_request() -> ControlRequest {
        ControlRequest {
            request_id: 1,
            operation: ControlOperation::PrepareLaunch(PrepareLaunchRequest {
                workspace: LaunchRequest {
                    workspace: WorkspaceSelection::Here,
                    current_directory: PathBuf::from("/project/nested"),
                },
                profile: "native".to_owned(),
                limits: ResourceLimits::default(),
                herdr: None,
                no_multiplex: false,
                continuation: Some(Box::new(LaunchHandoff {
                    socket_path: PathBuf::from("/run/runroom/control.sock"),
                    command: "printf directory".to_owned(),
                    mount_arguments: Vec::new(),
                })),
                continuation_token: None,
            }),
        }
    }

    #[test]
    fn continuation_mounts_reject_malformed_and_oversized_inputs_at_both_boundaries() {
        let oversized_path = format!("/{}", "x".repeat(MAX_PATH_LEN));
        let cases = [
            vec!["/source@/destination".to_owned()],
            vec!["/source@/destination:invalid".to_owned()],
            vec!["relative@/destination:ro".to_owned()],
            vec!["/source@relative:rw".to_owned()],
            vec!["/source@/destination/../escape:ro".to_owned()],
            vec!["/source\0@/destination:ro".to_owned()],
            vec![format!("{oversized_path}@/destination:ro")],
            vec![format!("/source@{oversized_path}:rw")],
            vec!["/source@/destination:ro".to_owned(); MAX_MOUNT_ARGUMENTS + 1],
        ];
        for mount_arguments in cases {
            let handoff = LaunchHandoff {
                socket_path: PathBuf::from("/run/runroom/control.sock"),
                command: "true".to_owned(),
                mount_arguments: mount_arguments.clone(),
            };
            assert!(wire_handoff(&handoff).is_err());
            assert_eq!(
                model_handoff(WireLaunchHandoff {
                    socket_path: b"/run/runroom/control.sock".to_vec(),
                    command: "true".to_owned(),
                    mount_arguments: mount_arguments.clone(),
                })
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidData
            );
            let continuation = LauncherContinuation {
                socket_path: handoff.socket_path,
                workspace: WorkspaceSelection::Here,
                profile: "sandbox".to_owned(),
                command: handoff.command,
                mount_arguments: mount_arguments.clone(),
            };
            assert!(wire_continuation(&continuation).is_err());
            assert_eq!(
                model_continuation(WireLauncherContinuation {
                    socket_path: b"/run/runroom/control.sock".to_vec(),
                    name: None,
                    here: true,
                    profile: "sandbox".to_owned(),
                    command: "true".to_owned(),
                    mount_arguments,
                })
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidData
            );
        }
        validate_mount_arguments(&[
            "/source@with:punctuation@/destination:with:colon:ro".to_owned()
        ])
        .expect("source @ and path colons are valid");
    }

    #[test]
    fn directory_selection_rejects_names_at_all_wire_boundaries() {
        let mut request = serde_json::to_value(
            WireRequest::try_from(&directory_request()).expect("encode request"),
        )
        .expect("serialize request");
        request["operation"]["name"] = serde_json::json!("named");
        let wire: WireRequest =
            serde_json::from_value(request).expect("deserialize malformed request");
        assert!(ControlRequest::try_from(wire).is_err());

        let continuation = WireLauncherContinuation {
            socket_path: b"/run/runroom/control.sock".to_vec(),
            name: Some("named".to_owned()),
            here: true,
            profile: "native".to_owned(),
            command: "true".to_owned(),
            mount_arguments: Vec::new(),
        };
        assert!(model_continuation(continuation).is_err());

        let mut workspace = wire_workspace(&directory_workspace()).expect("encode workspace");
        workspace.name = Some("named".to_owned());
        assert!(model_workspace(workspace).is_err());
    }

    #[test]
    fn directory_wire_metadata_cannot_smuggle_git_support_mounts_or_project_root() {
        let value =
            serde_json::to_value(wire_workspace(&directory_workspace()).expect("encode workspace"))
                .expect("serialize workspace");
        for (field, malformed) in [
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
            let mut malformed_workspace = value.clone();
            malformed_workspace[field] = malformed;
            let wire: WireWorkspace = serde_json::from_value(malformed_workspace)
                .expect("deserialize malformed workspace");
            let error = model_workspace(wire).expect_err("reject inconsistent directory metadata");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{field}");
        }
        let mut workspace = directory_workspace();
        workspace.support_mounts.push(WorkspaceSupportMount {
            source: PathBuf::from("/parent/.git"),
            destination: PathBuf::from("/parent/.git"),
        });
        assert!(wire_workspace(&workspace).is_err());
    }

    #[test]
    fn current_terminal_requests_allow_identity_but_reject_routing_on_both_boundaries() {
        let mut request = directory_request();
        let ControlOperation::PrepareLaunch(launch) = &mut request.operation else {
            unreachable!()
        };
        launch.continuation = None;
        launch.no_multiplex = true;
        for herdr in [
            None,
            Some(HerdrContext {
                session_name: Some("named".to_owned()),
                workspace_id: Some("workspace".to_owned()),
                pane_id: Some("pane".to_owned()),
            }),
        ] {
            let ControlOperation::PrepareLaunch(launch) = &mut request.operation else {
                unreachable!()
            };
            launch.herdr = herdr;
            let bytes = serde_json::to_vec(
                &WireRequest::try_from(&request).expect("encode current terminal"),
            )
            .expect("serialize current terminal");
            let wire: WireRequest =
                serde_json::from_slice(&bytes).expect("deserialize current terminal");
            assert_eq!(
                ControlRequest::try_from(wire).expect("decode current terminal"),
                request
            );
        }

        for field in ["continuation", "continuation_token"] {
            let mut malformed_request = request.clone();
            let ControlOperation::PrepareLaunch(launch) = &mut malformed_request.operation else {
                unreachable!()
            };
            match field {
                "continuation" => {
                    let ControlOperation::PrepareLaunch(original) = directory_request().operation
                    else {
                        unreachable!()
                    };
                    launch.continuation = original.continuation;
                }
                "continuation_token" => launch.continuation_token = Some("token".to_owned()),
                _ => unreachable!(),
            }
            assert!(
                WireRequest::try_from(&malformed_request).is_err(),
                "{field}"
            );
            let ControlOperation::PrepareLaunch(launch) = &mut malformed_request.operation else {
                unreachable!()
            };
            launch.no_multiplex = false;
            let mut value = serde_json::to_value(
                WireRequest::try_from(&malformed_request).expect("encode multiplexed request"),
            )
            .expect("serialize multiplexed request");
            value["operation"]["no_multiplex"] = serde_json::json!(true);
            let wire: WireRequest =
                serde_json::from_value(value).expect("deserialize malformed request");
            assert!(ControlRequest::try_from(wire).is_err(), "{field}");
        }
    }

    #[test]
    fn cpu_selection_bounds_are_checked_on_both_request_boundaries() {
        for (cores, count, valid) in [
            (None, None, true),
            (Some(vec![0, 1023]), None, true),
            (Some((0..1024).collect()), None, true),
            (None, Some(1), true),
            (None, Some(1024), true),
            (Some(vec![]), None, false),
            (Some(vec![1, 2, 1]), None, false),
            (Some(vec![1024]), None, false),
            (Some(vec![u32::MAX]), None, false),
            (None, Some(0), false),
            (None, Some(1025), false),
            (Some(vec![0]), Some(1), false),
        ] {
            let limits = ResourceLimits {
                cpu_cores: cores,
                cpu_count: count,
                ..ResourceLimits::default()
            };
            let request = ControlRequest {
                request_id: 1,
                operation: ControlOperation::PrepareLaunch(PrepareLaunchRequest {
                    workspace: LaunchRequest {
                        workspace: WorkspaceSelection::Primary,
                        current_directory: PathBuf::from("/project"),
                    },
                    profile: "native".to_owned(),
                    limits: limits.clone(),
                    herdr: None,
                    no_multiplex: false,
                    continuation: None,
                    continuation_token: None,
                }),
            };
            assert_eq!(
                WireRequest::try_from(&request).is_ok(),
                valid,
                "outbound CPU selection: {limits:?}"
            );
            let wire = WireRequest {
                request_id: 1,
                operation: WireRequestOperation::PrepareLaunch {
                    current_directory: b"/project".to_vec(),
                    name: None,
                    here: false,
                    profile: "native".to_owned(),
                    limits: (&limits).into(),
                    herdr: None,
                    no_multiplex: false,
                    continuation: None,
                    continuation_token: None,
                },
            };
            assert_eq!(
                ControlRequest::try_from(wire).is_ok(),
                valid,
                "inbound CPU selection: {limits:?}"
            );
        }
    }

    #[test]
    fn response_pages_are_reduced_to_the_framing_bound() {
        let path = PathBuf::from(format!("/{}", "x".repeat(MAX_PATH_LEN - 1)));
        let response = ControlResponse {
            request_id: 9,
            result: Ok(ControlResult::WorkspaceMetadataRepaired(PrunedWorktrees {
                project: ProjectId("project".to_owned()),
                paths: vec![path; usize::from(MAX_LIST_LIMIT)],
            })),
        };
        let mut wire = WireResponse::try_from(&response).expect("encode response");
        bound_wire_response(&mut wire).expect("bound response");
        let encoded = serde_json::to_vec(&wire).expect("serialize response");
        assert!(MAGIC.len() + 1 + encoded.len() <= MAX_CONTROL_FRAME_LEN);
    }

    #[test]
    fn relative_control_socket_is_rejected_before_connect() {
        let error = connect_control(Path::new("control.sock")).expect_err("reject relative socket");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
