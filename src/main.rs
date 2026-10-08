use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io::{self, IsTerminal};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use runroom::model::{
    InstanceId, InstanceRecord, InstanceState, ServiceAction, ServiceConfiguration, ServiceResult,
    StopMode,
};
use runroom::{DaemonConfig, HostClient, LauncherConfig, RunMode, run_atomic_worker, start};
use tracing::debug;
use tracing_subscriber::fmt::format::FmtSpan;

mod config;
mod resume;

use config::{
    DaemonSettings, EffectiveLauncherConfig, ResolvedLauncherConfig, control_socket, load_default,
    load_path, selected_config_path, validate_all_profiles,
};

use crate::config::FileConfig;
use resume::confirm_config_policy;

fn configuration_help() -> String {
    match selected_config_path() {
        Some(path) => format!("Configuration: {}", path.display()),
        None => "Configuration: none".to_owned(),
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "runroom",
    version,
    about = "Run a foreground program in a managed project workspace"
)]
struct Cli {
    /// Launcher options used when no explicit mode is supplied.
    #[command(flatten)]
    launcher: LauncherArgs,

    #[command(subcommand)]
    role: Option<Role>,
}

#[derive(Clone, Debug, Args, Default)]
#[allow(clippy::struct_excessive_bools)] // Independent CLI switches plus an internal restore marker.
struct LauncherArgs {
    /// Unix control socket used by the launcher.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Byte-preserving control socket used only by resolved replay arguments.
    #[arg(long, hide = true, conflicts_with = "socket")]
    socket_bytes: Option<String>,

    /// Named workspace to select instead of the primary workspace.
    #[arg(short = 'n', long, value_name = "NAME")]
    name: Option<String>,

    /// Run the exact current directory, including non-Git directories, without a worktree.
    #[arg(long, conflicts_with = "name")]
    no_worktree: bool,

    /// Run in this shell/pane without creating a tab; retain available Herdr reporting.
    #[arg(long)]
    here: bool,

    /// Launch profile selecting the command and its capabilities.
    #[arg(long, value_name = "PROFILE")]
    profile: Option<String>,

    /// Frozen Herdr agent label carried by resolved launcher replay.
    #[arg(long, hide = true, value_name = "LABEL")]
    herdr_agent: Option<String>,

    /// Show detailed launcher lifecycle logs.
    #[arg(short, long, action = ArgAction::SetTrue)]
    verbose: bool,

    /// Foreground command. Overrides the selected profile's command.
    #[arg(short, long, value_name = "COMMAND")]
    command: Option<String>,

    /// Network policy for this launch, overriding the selected profile.
    #[arg(long, value_enum, value_name = "host|none|private")]
    network: Option<config::NetworkFileMode>,

    /// Logical CPU IDs allowed for the instance and all descendants, not a CPU-time quota.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "IDS",
        conflicts_with = "cpu_count"
    )]
    cpu_cores: Option<Vec<u32>>,

    /// Use the lowest COUNT available logical CPUs; shared, not exclusively reserved.
    #[arg(long, value_name = "COUNT", conflicts_with = "cpu_cores")]
    cpu_count: Option<u32>,

    /// Bind a host path read-only at /BASENAME; repeatable.
    #[arg(long = "read-only", visible_alias = "ro", value_name = "PATH")]
    read_only: Vec<PathBuf>,

    /// Add a launch-only bind mount; repeatable.
    #[arg(short = 'm', long = "mount", value_name = "SOURCE@DEST:ro|rw")]
    mounts: Vec<String>,

    /// Internal one-time Herdr handoff token.
    #[arg(long, value_name = "TOKEN", hide = true)]
    resume: Option<String>,

    /// Internal durable launch argument payload.
    #[arg(long, value_name = "HEX", hide = true)]
    restore_args: Option<String>,

    /// Declarative configuration fingerprint carried by launcher replay.
    #[arg(long, hide = true, value_name = "HASH")]
    config_hash: Option<String>,

    /// Set only after decoding a durable restore payload.
    #[arg(skip)]
    restored: bool,

    /// Internal destination binding for a resumed launcher.
    #[arg(long, value_name = "TOKEN", hide = true)]
    continuation_token: Option<String>,
}

impl LauncherArgs {
    const fn is_empty(&self) -> bool {
        self.socket.is_none()
            && self.socket_bytes.is_none()
            && self.name.is_none()
            && !self.no_worktree
            && !self.here
            && self.profile.is_none()
            && self.herdr_agent.is_none()
            && !self.verbose
            && self.command.is_none()
            && self.cpu_cores.is_none()
            && self.network.is_none()
            && self.cpu_count.is_none()
            && self.read_only.is_empty()
            && self.mounts.is_empty()
            && self.resume.is_none()
            && self.restore_args.is_none()
            && self.config_hash.is_none()
            && !self.restored
            && self.continuation_token.is_none()
    }

    const fn has_only_verbose(&self) -> bool {
        self.socket.is_none()
            && self.socket_bytes.is_none()
            && self.name.is_none()
            && !self.no_worktree
            && !self.here
            && self.profile.is_none()
            && self.herdr_agent.is_none()
            && self.command.is_none()
            && self.cpu_cores.is_none()
            && self.network.is_none()
            && self.cpu_count.is_none()
            && self.resume.is_none()
            && self.restore_args.is_none()
            && self.config_hash.is_none()
            && !self.restored
            && self.read_only.is_empty()
            && self.mounts.is_empty()
            && self.continuation_token.is_none()
    }
}

#[derive(Debug, Args)]
struct DaemonArgs {
    /// Unix control socket served by the daemon.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Durable root under which managed workspaces are created.
    #[arg(long, value_name = "PATH")]
    workspace_root: Option<PathBuf>,

    /// Private persistent instance registry.
    #[arg(long, value_name = "PATH")]
    state_file: Option<PathBuf>,
    /// Trusted host Herdr Unix socket.
    #[arg(long, value_name = "PATH")]
    herdr_socket: Option<PathBuf>,

    /// Show detailed daemon lifecycle logs.
    #[arg(short, long, action = ArgAction::SetTrue)]
    verbose: bool,

    /// Exit cleanly after one accepted request.
    #[arg(long)]
    once: bool,
}
#[derive(Debug, Args)]
struct AtomicWorkerArgs {
    /// Private structured request prepared by the parent Pi process.
    #[arg(long, value_name = "PATH")]
    request: PathBuf,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Configuration file to validate.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// Skip the daemon protocol handshake.
    #[arg(long)]
    offline: bool,
}

#[derive(Debug, Args)]
struct InstanceArgs {
    /// Unix control socket used by the host control client.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: InstanceCommand,
}

#[derive(Debug, Subcommand)]
enum InstanceCommand {
    /// List registered instances in stable ID order.
    List {
        #[arg(long, value_name = "ID")]
        after: Option<String>,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u16).range(1..=100))]
        limit: u16,
    },
    /// Show one registered instance.
    Get { id: String },
    /// Stop one registered instance process tree.
    Stop {
        id: String,
        #[arg(long, value_enum, default_value_t = StopModeArg::Graceful)]
        mode: StopModeArg,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum StopModeArg {
    #[default]
    Graceful,
    Force,
}

impl From<StopModeArg> for StopMode {
    fn from(value: StopModeArg) -> Self {
        match value {
            StopModeArg::Graceful => Self::Graceful,
            StopModeArg::Force => Self::Force,
        }
    }
}

#[derive(Debug, Args)]
struct WorkspaceArgs {
    /// Unix control socket used by the host control client.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Path inside the project whose worktrees are managed.
    #[arg(long, value_name = "PATH")]
    current_directory: Option<PathBuf>,

    #[command(subcommand)]
    command: WorkspaceCommand,
}

#[derive(Debug, Subcommand)]
enum WorkspaceCommand {
    /// Remove one clean managed worktree while retaining its branch.
    Retire { name: String },
    /// Prune only stale linked-worktree metadata.
    Repair,
}
#[derive(Debug, Args)]
struct ServicesArgs {
    /// Unix control socket used by the host control client.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
    /// Path inside the project whose environment applies.
    #[arg(long, value_name = "PATH")]
    current_directory: Option<PathBuf>,

    #[command(subcommand)]
    command: ServicesCommand,
}

#[derive(Clone, Copy, Debug, Subcommand)]
enum ServicesCommand {
    /// Start PostgreSQL and Qdrant and wait for health.
    Up,
    /// Stop PostgreSQL and Qdrant while retaining their volumes.
    Down,
    /// Show backend container status.
    Status,
    /// Show resolved non-secret project service configuration.
    Config,
}

#[derive(Debug, Args)]
#[command(trailing_var_arg = true)]
struct RootArgs {
    /// Show detailed service and launcher lifecycle logs.
    #[arg(short, long, action = ArgAction::SetTrue)]
    verbose: bool,

    /// Arguments forwarded to the root Pi process.
    #[arg(allow_hyphen_values = true)]
    pi_arguments: Vec<String>,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)] // Parsed once at startup; avoid an allocation per launch.
enum Role {
    /// Connect to the daemon as the foreground launcher.
    Launcher(LauncherArgs),

    /// Serve local launcher requests.
    Daemon(DaemonArgs),
    /// Run one repository-blind model turn and exit.
    AtomicWorker(AtomicWorkerArgs),

    /// Validate configuration and optionally verify the live daemon protocol.
    Verify(VerifyArgs),

    /// Inspect or stop registered instances.
    Instance(InstanceArgs),

    /// Retire managed worktrees or repair stale metadata.
    Workspace(WorkspaceArgs),
    /// Manage the project-local PostgreSQL and Qdrant services.
    Services(ServicesArgs),

    /// Start project services and launch the root Pi coordinator.
    Root(RootArgs),
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if error.kind() == clap::error::ErrorKind::DisplayHelp {
                // Only help needs the selected config path; never parse its contents here.
                Cli::command()
                    .after_help(configuration_help())
                    .try_get_matches()
                    .expect_err("the same help arguments still request help")
                    .exit();
            }
            error.exit();
        }
    };
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("runroom: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    let cli = resolve_restore_cli(cli)?;
    match cli.role {
        Some(Role::AtomicWorker(args)) => {
            reject_implicit_launcher_options(&cli.launcher)?;
            run_atomic_worker(&args.request)?;
            Ok(())
        }
        Some(Role::Verify(args)) => {
            reject_implicit_launcher_options(&cli.launcher)?;
            let file = load_path(&args.config)?;
            let profiles = validate_all_profiles(&file)?;
            let current_directory = env::current_dir()?;
            let profiles = profiles
                .into_iter()
                .map(|profile| profile.resolve(&current_directory))
                .collect::<Result<Vec<_>, _>>()?;
            if !args.offline {
                let socket = profiles
                    .first()
                    .expect("profile validation rejects an empty profile set")
                    .socket
                    .clone();
                HostClient::new(socket).verify()?;
            }
            println!("configuration valid: {} profile(s)", profiles.len());
            Ok(())
        }
        Some(Role::Instance(args)) => {
            reject_implicit_launcher_options(&cli.launcher)?;
            run_instance_command(args)
        }
        Some(Role::Services(args)) => {
            reject_implicit_launcher_options(&cli.launcher)?;
            let file = load_default()?;
            let socket = control_socket(args.socket, &file)?;
            let current_directory = args.current_directory.map_or_else(env::current_dir, Ok)?;
            run_services(args.command, &current_directory, socket)?;
            Ok(())
        }
        Some(Role::Workspace(args)) => {
            reject_implicit_launcher_options(&cli.launcher)?;
            run_workspace_command(args)
        }
        role => {
            let file = load_default()?;
            let verbose = match &role {
                None => cli.launcher.verbose || file.launcher.verbose.unwrap_or(false),
                Some(Role::Launcher(args)) => {
                    args.verbose || file.launcher.verbose.unwrap_or(false)
                }
                Some(Role::Daemon(args)) => args.verbose || file.daemon.verbose.unwrap_or(false),
                Some(Role::Root(args)) => {
                    cli.launcher.verbose || args.verbose || file.launcher.verbose.unwrap_or(false)
                }
                Some(
                    Role::Verify(_)
                    | Role::Instance(_)
                    | Role::Workspace(_)
                    | Role::Services(_)
                    | Role::AtomicWorker(_),
                ) => unreachable!(),
            };
            init_tracing(verbose)?;
            debug!("loaded Runroom configuration");
            let selected = match role {
                None => launcher_mode(cli.launcher, file)?,
                Some(Role::Launcher(args)) => {
                    reject_implicit_launcher_options(&cli.launcher)?;
                    launcher_mode(args, file)?
                }
                Some(Role::Root(args)) => {
                    reject_implicit_launcher_options_except_verbose(&cli.launcher)?;
                    root_mode(args, cli.launcher.verbose, file)?
                }
                Some(Role::Daemon(args)) => {
                    reject_implicit_launcher_options(&cli.launcher)?;
                    daemon_mode(args, &file)?
                }
                Some(
                    Role::Verify(_)
                    | Role::Instance(_)
                    | Role::Workspace(_)
                    | Role::Services(_)
                    | Role::AtomicWorker(_),
                ) => unreachable!(),
            };
            debug_assert_eq!(selected.verbose, verbose);
            debug!("selected Runroom process role");
            start(selected.mode)?.run()?;
            Ok(())
        }
    }
}

fn run_instance_command(args: InstanceArgs) -> Result<(), Box<dyn Error>> {
    let file = load_default()?;
    let socket = control_socket(args.socket, &file)?;
    let client = HostClient::new(socket);
    match args.command {
        InstanceCommand::List { after, limit } => {
            for instance in client.list_instances(after.map(InstanceId), limit)? {
                print_instance(&instance);
            }
        }
        InstanceCommand::Get { id } => {
            let instance = client
                .get_instance(InstanceId(id))?
                .ok_or("instance does not exist")?;
            print_instance(&instance);
        }
        InstanceCommand::Stop { id, mode } => {
            let instance = client.stop_instance(InstanceId(id), mode.into())?;
            print_instance(&instance);
        }
    }
    Ok(())
}

fn run_workspace_command(args: WorkspaceArgs) -> Result<(), Box<dyn Error>> {
    let file = load_default()?;
    let socket = control_socket(args.socket, &file)?;
    let current_directory = args.current_directory.map_or_else(env::current_dir, Ok)?;
    let client = HostClient::new(socket);
    match args.command {
        WorkspaceCommand::Retire { name } => {
            let retired =
                client.retire_workspace(current_directory, runroom::model::WorkspaceName(name))?;
            println!(
                "retired\\t{}\\t{}\\t{}\\t{}",
                retired.project.0,
                retired.name.0,
                retired.path.display(),
                retired.branch
            );
        }
        WorkspaceCommand::Repair => {
            let repair = client.repair_workspace_metadata(current_directory)?;
            if repair.paths.is_empty() {
                println!("repaired\\t{}\\t0", repair.project.0);
            } else {
                for path in repair.paths {
                    println!("repaired\\t{}\\t{}", repair.project.0, path.display());
                }
            }
        }
    }
    Ok(())
}

fn root_mode(
    args: RootArgs,
    implicit_verbose: bool,
    file: FileConfig,
) -> Result<SelectedMode, Box<dyn Error>> {
    let verbose = implicit_verbose || args.verbose;
    let current_directory = env::current_dir()?;
    let socket = control_socket(None, &file)?;
    let project = run_services(ServicesCommand::Config, &current_directory, socket.clone())?
        .ok_or("daemon did not return service configuration")?;
    run_services(ServicesCommand::Up, &current_directory, socket)?;
    let project_name = project
        .project_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("project root has no UTF-8 basename")?;
    let configured_command = file
        .launcher
        .profiles
        .get("pi")
        .and_then(|profile| profile.command.as_deref())
        .ok_or("Pi launcher profile has no configured command")?;
    let mut command_words = shell_words::split(configured_command)?;
    command_words.extend(["--name".to_owned(), format!("root:{project_name}")]);
    command_words.extend(args.pi_arguments);
    launcher_mode(
        LauncherArgs {
            verbose,
            profile: Some("pi".to_owned()),
            command: Some(shell_words::join(command_words)),
            ..LauncherArgs::default()
        },
        file,
    )
}

fn daemon_mode(args: DaemonArgs, file: &FileConfig) -> Result<SelectedMode, Box<dyn Error>> {
    let state_override = args.state_file;
    if state_override
        .as_ref()
        .is_some_and(|path| !path.is_absolute())
    {
        return Err("daemon state file must be absolute".into());
    }
    let herdr_override = args.herdr_socket;
    if herdr_override
        .as_ref()
        .is_some_and(|path| !path.is_absolute())
    {
        return Err("Herdr socket must be absolute".into());
    }
    let settings = DaemonSettings::resolve(
        args.socket,
        args.workspace_root,
        state_override,
        args.verbose,
        file,
    )?;
    Ok(SelectedMode {
        mode: RunMode::Daemon(
            DaemonConfig::new(settings.socket, settings.workspace_root)
                .state_file(settings.state_file)
                .herdr_socket(herdr_override.unwrap_or(settings.herdr_socket))
                .resource_ceiling(settings.resource_ceiling)
                .exit_after_one_request(args.once),
        ),
        verbose: settings.verbose,
    })
}

#[tracing::instrument(
    level = "debug",
    skip_all,
    name = "run_project_services",
    fields(command = ?command, current_directory = %current_directory.display())
)]
fn run_services(
    command: ServicesCommand,
    current_directory: &Path,
    socket: PathBuf,
) -> Result<Option<ServiceConfiguration>, Box<dyn Error>> {
    let action = match command {
        ServicesCommand::Up => ServiceAction::Up,
        ServicesCommand::Down => ServiceAction::Down,
        ServicesCommand::Status => ServiceAction::Status,
        ServicesCommand::Config => ServiceAction::Config,
    };
    match HostClient::new(socket).manage_services(current_directory.to_owned(), action)? {
        ServiceResult::Completed { output } => {
            print!("{output}");
            Ok(None)
        }
        ServiceResult::Configuration(configuration) => {
            println!("project={}", configuration.project_root.display());
            println!(
                "global_env={}",
                configuration.global_environment_file.display()
            );
            println!(
                "project_env={}",
                configuration.project_environment_file.display()
            );
            println!("database={}", configuration.database_url);
            println!("qdrant={}", configuration.qdrant_url);
            println!("state={}", configuration.state_directory);
            Ok(Some(configuration))
        }
    }
}

fn print_instance(instance: &InstanceRecord) {
    let state = match instance.state {
        InstanceState::Starting => "starting",
        InstanceState::Running => "running",
        InstanceState::Stopping => "stopping",
        InstanceState::Exited => "exited",
        InstanceState::Failed => "failed",
    };
    println!(
        "{}\\t{}\\t{}\\t{}\\t{}",
        instance.id.0,
        state,
        instance.profile,
        instance.workspace.project.0,
        instance.workspace.path.display()
    );
}

struct SelectedMode {
    mode: RunMode,
    verbose: bool,
}

// Herdr counts the executable, flag, and encoded payload toward its 8192-byte limit.
const MAX_RESTORE_HEX_BYTES: usize = 8192 - "runroom".len() - "--restore-args".len();

fn decode_hex(payload: &str) -> Result<Vec<u8>, &'static str> {
    if payload.is_empty() || !payload.len().is_multiple_of(2) {
        return Err("hexadecimal payload must be nonempty and have even length");
    }
    let nibble = |byte| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("payload must be lowercase hexadecimal"),
    };
    payload
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn resolve_restore_cli(mut cli: Cli) -> Result<Cli, Box<dyn Error>> {
    let payload = match &mut cli.role {
        None => {
            let payload = cli.launcher.restore_args.take();
            if payload.is_some() && !cli.launcher.is_empty() {
                return Err("--restore-args cannot be combined with launcher options".into());
            }
            payload
        }
        Some(Role::Launcher(args)) => {
            let payload = args.restore_args.take();
            if payload.is_some() && (!args.is_empty() || !cli.launcher.is_empty()) {
                return Err("--restore-args cannot be combined with launcher options".into());
            }
            if cli.launcher.restore_args.is_some() {
                return Err("--restore-args cannot precede an explicit role".into());
            }
            payload
        }
        Some(_) => {
            if cli.launcher.restore_args.is_some() {
                return Err("--restore-args is only valid for launching".into());
            }
            None
        }
    };
    let Some(payload) = payload else {
        return Ok(cli);
    };
    if payload.is_empty() || payload.len() > MAX_RESTORE_HEX_BYTES || payload.len() % 2 != 0 {
        return Err("restore payload is empty or exceeds Herdr's 8192-byte argument limit".into());
    }
    let decoded = decode_hex(&payload)?;
    let arguments: Vec<String> = serde_json::from_slice(&decoded)?;
    if arguments.len() > 512
        || arguments.iter().map(String::len).sum::<usize>() > 8192
        || arguments.iter().any(|argument| argument.contains('\0'))
    {
        return Err("restore arguments exceed 512 arguments/8192 bytes or contain NUL".into());
    }
    let parsed = Cli::try_parse_from(std::iter::once("runroom".to_owned()).chain(arguments))?;
    let mut launcher = match parsed.role {
        None => parsed.launcher,
        Some(Role::Launcher(args)) if parsed.launcher.is_empty() => args,
        _ => {
            return Err("restore payload must select the normal launcher, not another role".into());
        }
    };
    if launcher.restore_args.is_some()
        || launcher.resume.is_some()
        || launcher.continuation_token.is_some()
        || !launcher.here
        || !launcher.no_worktree
    {
        return Err(
            "restore payload requires --here --no-worktree and cannot recurse or resume a handoff"
                .into(),
        );
    }
    launcher.restored = true;
    Ok(Cli {
        launcher,
        role: None,
    })
}

fn canonical_replay_arguments(
    settings: &ResolvedLauncherConfig,
    config_hash: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let (socket_flag, socket) = if let Some(socket) = settings.socket.to_str() {
        ("--socket", socket.to_owned())
    } else {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let socket = settings
            .socket
            .as_os_str()
            .as_bytes()
            .iter()
            .flat_map(|byte| {
                [
                    char::from(HEX[usize::from(byte >> 4)]),
                    char::from(HEX[usize::from(byte & 15)]),
                ]
            })
            .collect::<String>();
        ("--socket-bytes", socket)
    };
    let network = match settings.runtime.network {
        runroom::model::NetworkMode::Host => "host",
        runroom::model::NetworkMode::None => "none",
        runroom::model::NetworkMode::Private => "private",
    };
    let mut arguments = vec![
        socket_flag.to_owned(),
        socket,
        "--profile".to_owned(),
        settings.profile.clone(),
        "--herdr-agent".to_owned(),
        settings.agent_label.clone(),
        "--network".to_owned(),
        network.to_owned(),
        "--here".to_owned(),
        "--no-worktree".to_owned(),
        "--config-hash".to_owned(),
        config_hash.to_owned(),
    ];
    if let Some(cores) = &settings.limits.cpu_cores {
        arguments.extend([
            "--cpu-cores".to_owned(),
            cores
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ]);
    } else if let Some(count) = settings.limits.cpu_count {
        arguments.extend(["--cpu-count".to_owned(), count.to_string()]);
    }
    for mount in &settings.mount_arguments {
        arguments.extend(["--mount".to_owned(), mount.clone()]);
    }
    if settings.verbose {
        arguments.push("--verbose".to_owned());
    }
    let words = std::iter::once(settings.command.executable.as_os_str())
        .chain(
            settings
                .command
                .arguments
                .iter()
                .map(std::ffi::OsString::as_os_str),
        )
        .map(|word| word.to_str().ok_or("foreground command is not UTF-8"))
        .collect::<Result<Vec<_>, _>>()?;
    arguments.extend(["--command".to_owned(), shell_words::join(words)]);
    Ok(arguments)
}

#[tracing::instrument(level = "debug", skip_all, name = "build_launcher_mode")]
fn launcher_mode(
    args: LauncherArgs,
    mut file: config::FileConfig,
) -> Result<SelectedMode, Box<dyn Error>> {
    // Retain recovery arguments only for guarded launches, never the ordinary hot path.
    let recovery_args = (args.restored || args.config_hash.is_some()).then(|| args.clone());
    let socket = if let Some(encoded) = args.socket_bytes {
        if encoded.len() > 8192 {
            return Err("encoded control socket is too long".into());
        }
        let bytes = decode_hex(&encoded)?;
        if bytes.contains(&0) {
            return Err("control socket must not contain NUL".into());
        }
        Some(PathBuf::from(OsString::from_vec(bytes)))
    } else {
        args.socket
    };
    file.override_cpu_selection(args.profile.as_deref(), args.cpu_cores, args.cpu_count)?;
    file.override_network(args.profile.as_deref(), args.network)?;
    file.override_launch_mode(args.profile.as_deref(), args.no_worktree)?;
    let effective = EffectiveLauncherConfig::merge(
        socket,
        args.name,
        args.profile,
        args.command,
        args.herdr_agent,
        args.verbose,
        &file,
    )?
    .with_launch_mounts(args.read_only, args.mounts)?;
    let config_hash = effective.fingerprint()?;
    if let Some(args) = recovery_args {
        let stdin = io::stdin();
        let stderr = io::stderr();
        confirm_config_policy(
            &args,
            &config_hash,
            &mut stdin.lock(),
            &mut stderr.lock(),
            stdin.is_terminal() && stderr.is_terminal(),
        )?;
    }

    // Declarative launcher intent is complete; host-dependent resolution starts here.
    let current_directory = env::current_dir()?;
    let settings = effective.resolve(&current_directory)?;
    let replay_arguments = canonical_replay_arguments(&settings, &config_hash)?;
    let has_herdr_identity = settings.identity.is_some();
    let mut config = LauncherConfig::new(
        settings.socket,
        settings.profile,
        settings.agent_label,
        settings.command,
        settings.runtime,
    )
    .replay_arguments(replay_arguments)
    .resource_limits(settings.limits)
    .no_worktree(args.no_worktree)
    .here(args.here)
    .herdr_identity(has_herdr_identity);
    config =
        config.project_environment(settings.project_environment, settings.environment_allowlist);
    if let Some(name) = settings.name {
        config = config.workspace_name(name);
    }
    if let Some(token) = args.resume {
        config = config.resume_token(token);
    }
    if let Some(token) = args.continuation_token {
        config = config.continuation_token(token);
    }
    Ok(SelectedMode {
        mode: RunMode::Launcher(config),
        verbose: settings.verbose,
    })
}

fn init_tracing(verbose: bool) -> Result<(), Box<dyn Error>> {
    let filter = if verbose { "off,runroom=debug" } else { "off" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_writer(std::io::stderr)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .try_init()
        .map_err(|error| format!("initialize tracing: {error}"))?;
    Ok(())
}

fn reject_implicit_launcher_options(args: &LauncherArgs) -> Result<(), &'static str> {
    if args.is_empty() {
        Ok(())
    } else {
        Err("launcher options must follow the launcher mode, not precede an explicit mode")
    }
}

fn reject_implicit_launcher_options_except_verbose(
    args: &LauncherArgs,
) -> Result<(), &'static str> {
    if args.has_only_verbose() {
        Ok(())
    } else {
        Err(
            "only --verbose may precede root mode; other launcher options must follow launcher mode",
        )
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    const CONFIG_HASH: &str = "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn restoration_marker_is_internal_and_outer_replay_metadata_is_rejected() {
        assert!(Cli::try_parse_from(["runroom", "--restored"]).is_err());
        let payload = restore_payload(&["--here", "--no-worktree", "--command", "pi"]);
        let restored = resolve_restore_cli(
            Cli::try_parse_from(["runroom", "--restore-args", &payload]).unwrap(),
        )
        .unwrap();
        assert!(restored.launcher.restored);
        assert!(restored.launcher.config_hash.is_none());
        for (flag, value) in [("--herdr-agent", "frozen"), ("--config-hash", CONFIG_HASH)] {
            let cli =
                Cli::try_parse_from(["runroom", "--restore-args", &payload, flag, value]).unwrap();
            assert!(resolve_restore_cli(cli).is_err());
            let cli = Cli::try_parse_from([
                "runroom",
                "launcher",
                "--restore-args",
                &payload,
                flag,
                value,
            ])
            .unwrap();
            assert!(resolve_restore_cli(cli).is_err());
        }
    }

    fn restore_payload(arguments: &[&str]) -> String {
        use std::fmt::Write;
        serde_json::to_vec(arguments)
            .unwrap()
            .iter()
            .fold(String::new(), |mut encoded, byte| {
                write!(encoded, "{byte:02x}").unwrap();
                encoded
            })
    }

    #[test]
    fn durable_replay_captures_resolved_policy_and_command_without_workspace_routing() {
        let mut file: FileConfig = toml::from_str(
            r#"
socket = "/control.sock"
[launcher]
profile = "coding"
name = "original-worktree"
[launcher.base]
command = "omp --model 'configured model'"
herdr_agent = "rr:omp"
network = "host"
cpu_cores = [0, 1]
[launcher.profiles.coding]
"#,
        )
        .unwrap();
        file.override_network(None, Some(config::NetworkFileMode::None))
            .unwrap();
        file.override_cpu_selection(None, None, Some(2)).unwrap();
        let mut settings = EffectiveLauncherConfig::merge(
            None,
            None,
            None,
            Some("omp --model 'CLI model' --foo \"a'b\"".to_owned()),
            None,
            true,
            &file,
        )
        .unwrap()
        .resolve(Path::new("/"))
        .unwrap();
        settings.mount_arguments = vec!["/host/grant@/grant:ro".to_owned()];
        let replay = canonical_replay_arguments(&settings, CONFIG_HASH).unwrap();
        assert_eq!(
            &replay[..replay.len() - 1],
            [
                "--socket",
                "/control.sock",
                "--profile",
                "coding",
                "--herdr-agent",
                "rr:omp",
                "--network",
                "none",
                "--here",
                "--no-worktree",
                "--config-hash",
                CONFIG_HASH,
                "--cpu-count",
                "2",
                "--mount",
                "/host/grant@/grant:ro",
                "--verbose",
                "--command",
            ]
            .map(str::to_owned)
        );
        let payload = restore_payload(&replay.iter().map(String::as_str).collect::<Vec<_>>());
        let restored = resolve_restore_cli(
            Cli::try_parse_from(["runroom", "--restore-args", &payload]).unwrap(),
        )
        .unwrap();
        assert!(restored.launcher.here && restored.launcher.no_worktree);
        assert!(restored.launcher.restored);
        assert_eq!(restored.launcher.config_hash.as_deref(), Some(CONFIG_HASH));
        assert_eq!(restored.launcher.profile.as_deref(), Some("coding"));
        assert_eq!(restored.launcher.herdr_agent.as_deref(), Some("rr:omp"));
        assert_eq!(
            restored.launcher.network,
            Some(config::NetworkFileMode::None)
        );
        assert_eq!(restored.launcher.cpu_count, Some(2));
        assert_eq!(restored.launcher.name, None);
        assert_eq!(restored.launcher.mounts, ["/host/grant@/grant:ro"]);
        assert_eq!(
            shell_words::split(restored.launcher.command.as_deref().unwrap()).unwrap(),
            ["omp", "--model", "CLI model", "--foo", "a'b"]
        );
        file.launcher.profile = Some("different".to_owned());
        let changed = file.launcher.profiles.get_mut("coding").unwrap();
        changed.command = Some("pi --model changed".to_owned());
        changed.herdr_agent = Some("changed:pi".to_owned());
        let frozen = EffectiveLauncherConfig::merge(
            restored.launcher.socket,
            restored.launcher.name,
            restored.launcher.profile,
            restored.launcher.command,
            restored.launcher.herdr_agent,
            restored.launcher.verbose,
            &file,
        )
        .unwrap();
        assert_eq!(frozen.profile, "coding");
        assert_eq!(frozen.agent_label, "rr:omp");
        assert_eq!(frozen.command, settings.command);
    }

    #[test]
    fn default_agent_label_replay_retains_differently_named_profile() {
        let file: FileConfig = toml::from_str(
            "socket = '/control.sock'\n[launcher]\nprofile = 'coding'\n\
             [launcher.profiles.coding]\ncommand = '/opt/agents/omp --model configured'",
        )
        .unwrap();
        let settings = EffectiveLauncherConfig::merge(None, None, None, None, None, false, &file)
            .unwrap()
            .resolve(Path::new("/"))
            .unwrap();
        let replay = canonical_replay_arguments(&settings, CONFIG_HASH).unwrap();
        let parsed = Cli::try_parse_from(
            std::iter::once("runroom").chain(replay.iter().map(String::as_str)),
        )
        .unwrap();
        assert_eq!(parsed.launcher.profile.as_deref(), Some("coding"));
        assert_eq!(parsed.launcher.herdr_agent.as_deref(), Some("omp"));
        assert_eq!(
            shell_words::split(parsed.launcher.command.as_deref().unwrap()).unwrap(),
            ["/opt/agents/omp", "--model", "configured"]
        );
        let explicit = Cli::try_parse_from([
            "runroom",
            "launcher",
            "--profile",
            "coding",
            "--herdr-agent",
            "rr:omp",
        ])
        .unwrap();
        let Some(Role::Launcher(args)) = explicit.role else {
            panic!("expected explicit launcher mode");
        };
        assert_eq!(args.profile.as_deref(), Some("coding"));
        assert_eq!(args.herdr_agent.as_deref(), Some("rr:omp"));
    }

    #[test]
    fn restore_payload_rejects_recursion_roles_missing_workspace_flags_and_bounds() {
        for arguments in [
            vec!["--here", "--no-worktree", "--restore-args", "00"],
            vec!["--here", "--no-worktree", "--resume", "token"],
            vec!["--here", "--no-worktree", "--continuation-token", "token"],
            vec!["daemon"],
            vec!["--here"],
            vec!["--no-worktree"],
        ] {
            let payload = restore_payload(&arguments);
            assert!(
                resolve_restore_cli(
                    Cli::try_parse_from(["runroom", "--restore-args", &payload]).unwrap()
                )
                .is_err()
            );
        }
        for payload in [
            "0".to_owned(),
            "zz".to_owned(),
            "FF".to_owned(),
            "00".repeat(MAX_RESTORE_HEX_BYTES / 2 + 1),
        ] {
            assert!(
                resolve_restore_cli(
                    Cli::try_parse_from(["runroom", "--restore-args", &payload]).unwrap()
                )
                .is_err()
            );
        }
        let many = vec!["--verbose"; 65];
        let payload = restore_payload(&many);
        assert!(
            resolve_restore_cli(
                Cli::try_parse_from(["runroom", "--restore-args", &payload]).unwrap()
            )
            .is_err()
        );
        let payload = restore_payload(&["--here", "--no-worktree", "--command", "pi"]);
        assert!(
            resolve_restore_cli(
                Cli::try_parse_from(["runroom", "--restore-args", &payload, "--here"]).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn accepts_network_override_only_for_launchers() {
        for prefix in [vec!["runroom"], vec!["runroom", "launcher"]] {
            for network in ["host", "none", "private"] {
                let mut arguments = prefix.clone();
                arguments.extend(["--network", network]);
                assert!(Cli::try_parse_from(arguments).is_ok());
            }
        }
        assert!(Cli::try_parse_from(["runroom", "daemon", "--network", "host"]).is_err());
    }

    #[test]
    fn defaults_to_launcher_and_preserves_non_utf8_socket_paths() {
        use std::os::unix::ffi::OsStringExt;

        let socket = OsString::from_vec(vec![b'/', b't', b'm', b'p', b'/', 0xFF]);
        let cli = Cli::try_parse_from([
            OsString::from("runroom"),
            OsString::from("--socket"),
            socket.clone(),
            OsString::from("-n"),
            OsString::from("dictation"),
            OsString::from("-c"),
            OsString::from("/bin/true"),
        ])
        .expect("parse CLI");

        assert!(cli.role.is_none());
        assert_eq!(cli.launcher.socket, Some(PathBuf::from(socket)));
        assert_eq!(cli.launcher.name.as_deref(), Some("dictation"));
        assert_eq!(cli.launcher.command.as_deref(), Some("/bin/true"));
        assert_eq!(cli.launcher.profile, None);
    }

    #[test]
    fn parses_options_only_for_the_selected_explicit_mode() {
        let launcher = Cli::try_parse_from([
            "runroom",
            "launcher",
            "--socket",
            "/launcher.sock",
            "--name",
            "docs",
            "--profile",
            "pi",
            "--command",
            "pi --model 'gpt 5'",
        ])
        .expect("parse launcher");
        let daemon = Cli::try_parse_from([
            "runroom",
            "daemon",
            "--socket",
            "/daemon.sock",
            "--workspace-root",
            "/workspaces",
            "--once",
        ])
        .expect("parse daemon");

        assert!(matches!(launcher.role, Some(Role::Launcher(_))));
        assert!(matches!(daemon.role, Some(Role::Daemon(_))));
    }

    #[test]
    fn parses_service_and_root_commands() {
        let services =
            Cli::try_parse_from(["runroom", "services", "up"]).expect("parse services command");
        assert!(matches!(
            services.role,
            Some(Role::Services(ServicesArgs {
                command: ServicesCommand::Up,
                ..
            }))
        ));

        let root = Cli::try_parse_from(["runroom", "root", "--", "--model", "gpt-5.6"])
            .expect("parse root command");
        let Some(Role::Root(root)) = root.role else {
            panic!("expected root role");
        };
        assert_eq!(root.pi_arguments, ["--model", "gpt-5.6"]);
        assert!(!root.verbose);

        for arguments in [
            ["runroom", "--verbose", "root"],
            ["runroom", "root", "--verbose"],
        ] {
            let root = Cli::try_parse_from(arguments).expect("parse verbose root command");
            assert!(
                root.launcher.verbose
                    || matches!(root.role, Some(Role::Root(RootArgs { verbose: true, .. })))
            );
        }
    }

    #[test]
    fn parses_offline_verify_and_instance_control() {
        let verify = Cli::try_parse_from([
            "runroom",
            "verify",
            "--config",
            "/tmp/candidate.toml",
            "--offline",
        ])
        .expect("parse verify");
        assert!(matches!(
            verify.role,
            Some(Role::Verify(VerifyArgs { offline: true, .. }))
        ));

        let stop = Cli::try_parse_from([
            "runroom",
            "instance",
            "--socket",
            "/tmp/control.sock",
            "stop",
            "instance-1",
            "--mode",
            "force",
        ])
        .expect("parse instance stop");
        assert!(matches!(
            stop.role,
            Some(Role::Instance(InstanceArgs {
                command: InstanceCommand::Stop {
                    mode: StopModeArg::Force,
                    ..
                },
                ..
            }))
        ));
    }

    #[test]
    fn accepts_directory_and_foreground_launches_but_rejects_named_directory_launches() {
        for prefix in [vec!["runroom"], vec!["runroom", "launcher"]] {
            for flags in [
                vec!["--no-worktree"],
                vec!["--here"],
                vec!["--no-worktree", "--here"],
                vec!["--name", "review", "--here"],
            ] {
                let mut arguments = prefix.clone();
                arguments.extend(flags);
                Cli::try_parse_from(arguments).expect("accept launch selection");
            }
            for flags in [
                ["--no-worktree", "--name", "review"],
                ["--name", "review", "--no-worktree"],
            ] {
                let mut arguments = prefix.clone();
                arguments.extend(flags);
                assert_eq!(
                    Cli::try_parse_from(arguments)
                        .expect_err("reject named directory launch")
                        .kind(),
                    clap::error::ErrorKind::ArgumentConflict
                );
            }
        }
    }

    #[test]
    fn rejects_launch_switches_in_other_modes_but_preserves_root_pi_arguments() {
        for flag in ["--here", "--no-worktree"] {
            for arguments in [
                vec!["daemon"],
                vec!["verify", "--config", "/tmp/config.toml"],
                vec!["instance", "list"],
                vec!["workspace", "repair"],
                vec!["services", "up"],
                vec!["atomic-worker", "--request", "/tmp/request.json"],
            ] {
                let mut after = vec!["runroom"];
                after.extend(arguments.iter().copied());
                after.push(flag);
                assert_eq!(
                    Cli::try_parse_from(after)
                        .expect_err("reject launch switch in explicit mode")
                        .kind(),
                    clap::error::ErrorKind::UnknownArgument
                );
                let mut before = vec!["runroom", flag];
                before.extend(arguments);
                let cli = Cli::try_parse_from(before).expect("parse switch before explicit mode");
                assert!(reject_implicit_launcher_options(&cli.launcher).is_err());
            }
            let cli =
                Cli::try_parse_from(["runroom", flag, "root"]).expect("parse switch before root");
            assert!(reject_implicit_launcher_options_except_verbose(&cli.launcher).is_err());
            let cli = Cli::try_parse_from(["runroom", "root", "--", flag])
                .expect("parse Pi passthrough switch");
            let Some(Role::Root(root)) = cli.role else {
                panic!("expected root role");
            };
            assert_eq!(root.pi_arguments, [flag]);
        }
    }

    #[test]
    fn accepts_cpu_selection_in_implicit_and_explicit_launcher_modes() {
        for prefix in [vec!["runroom"], vec!["runroom", "launcher"]] {
            for (flag, value) in [("--cpu-cores", "4,7"), ("--cpu-count", "2")] {
                let mut arguments = prefix.clone();
                arguments.extend([flag, value]);
                let cli = Cli::try_parse_from(arguments).expect("parse launcher CPU selection");
                let args = match cli.role {
                    None => cli.launcher,
                    Some(Role::Launcher(args)) => args,
                    _ => panic!("expected launcher mode"),
                };
                if flag == "--cpu-cores" {
                    assert_eq!(args.cpu_cores, Some(vec![4, 7]));
                    assert_eq!(args.cpu_count, None);
                } else {
                    assert_eq!(args.cpu_count, Some(2));
                    assert_eq!(args.cpu_cores, None);
                }
            }
            let mut arguments = prefix;
            arguments.extend(["--cpu-cores", "4,7", "--cpu-count", "2"]);
            assert_eq!(
                Cli::try_parse_from(arguments)
                    .expect_err("reject conflicting selection")
                    .kind(),
                clap::error::ErrorKind::ArgumentConflict
            );
        }
    }

    #[test]
    fn rejects_cpu_selection_outside_launcher_mode() {
        for (flag, value) in [("--cpu-cores", "4,7"), ("--cpu-count", "2")] {
            for mode in [
                "daemon",
                "verify",
                "instance",
                "workspace",
                "services",
                "atomic-worker",
            ] {
                let error = Cli::try_parse_from(["runroom", mode, flag, value])
                    .expect_err("reject CPU selection after another mode");
                assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
            }
            let cli = Cli::try_parse_from(["runroom", flag, value, "daemon"])
                .expect("parse implicit options before explicit daemon");
            assert!(reject_implicit_launcher_options(&cli.launcher).is_err());
            let cli = Cli::try_parse_from(["runroom", flag, value, "root"])
                .expect("parse implicit options before root");
            assert!(reject_implicit_launcher_options_except_verbose(&cli.launcher).is_err());
        }
    }

    #[test]
    fn rejects_options_from_the_other_mode() {
        let daemon_name = Cli::try_parse_from(["runroom", "daemon", "--name", "docs"])
            .expect_err("reject launcher name in daemon mode");
        let daemon_command = Cli::try_parse_from(["runroom", "daemon", "--command", "pi"])
            .expect_err("reject launcher command in daemon mode");
        let daemon_profile = Cli::try_parse_from(["runroom", "daemon", "--profile", "pi"])
            .expect_err("reject launcher profile in daemon mode");
        let launcher_root =
            Cli::try_parse_from(["runroom", "launcher", "--workspace-root", "/workspaces"])
                .expect_err("reject daemon root in launcher mode");
        let daemon_once = Cli::try_parse_from(["runroom", "launcher", "--once"])
            .expect_err("reject daemon once in launcher mode");
        let positional_command = Cli::try_parse_from(["runroom", "launcher", "--", "pi"])
            .expect_err("reject positional launcher command");

        for error in [
            daemon_name,
            daemon_command,
            daemon_profile,
            launcher_root,
            daemon_once,
            positional_command,
        ] {
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }
}
