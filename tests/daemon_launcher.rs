use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::num::NonZeroU32;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use runroom::backend::{ScopeBackend, ScopeState, SystemdScopeBackend};
use runroom::model::{ProcessId, StopMode};
use serde_json::Value;

const WAIT_LIMIT: Duration = Duration::from_secs(5);
const PYTHON: &str = "/usr/bin/python3";
const PROBE: &str = "import json, os, sys; print(json.dumps({'pid': os.getpid(), 'cwd': os.getcwd(), 'arg_hex': [os.fsencode(value).hex() for value in sys.argv[1:]], 'cgroup': open('/proc/self/cgroup', encoding='utf-8').read(), 'netns': os.stat('/proc/self/ns/net').st_ino}))";
const SCOPE_PROBE: &str = "import json, os, subprocess, time; child = subprocess.Popen(['/usr/bin/sleep', '30']); print(json.dumps({'pid': os.getpid(), 'child_pid': child.pid, 'cgroup': open('/proc/self/cgroup', encoding='utf-8').read()}), flush=True); time.sleep(30)";

fn probe_command(arguments: &[&str]) -> String {
    shell_words::join(
        [PYTHON, "-c", PROBE]
            .into_iter()
            .chain(arguments.iter().copied()),
    )
}

#[test]
fn daemon_requires_the_exact_application_version_including_patch_and_suffixes() {
    use std::io::Read;

    let fixture = GitFixture::new();
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, false);
    wait_for_socket(&mut daemon, &fixture.socket);
    let application_version = runroom::protocol::APP_VERSION;
    let other_patch = env!("CARGO_PKG_VERSION_PATCH").parse::<u64>().unwrap() + 1;
    for version in [
        format!(
            "{}.{}.{other_patch}",
            env!("CARGO_PKG_VERSION_MAJOR"),
            env!("CARGO_PKG_VERSION_MINOR")
        ),
        format!("{application_version}-preview"),
        format!("{application_version}+different-build"),
    ] {
        let mut stream = UnixStream::connect(&fixture.socket).expect("connect mismatch client");
        stream.set_read_timeout(Some(WAIT_LIMIT)).unwrap();
        let payload = [b"RRM\0\x01".as_slice(), version.as_bytes()].concat();
        stream
            .write_all(&u32::try_from(payload.len()).unwrap().to_be_bytes())
            .unwrap();
        stream.write_all(&payload).unwrap();
        let mut length = [0_u8; 4];
        stream
            .read_exact(&mut length)
            .expect("read daemon hello length");
        let mut hello = vec![0_u8; u32::from_be_bytes(length) as usize];
        stream
            .read_exact(&mut hello)
            .expect("read daemon rejection");
        assert_eq!(
            &hello[..6],
            b"RRM\0\x02\x01",
            "accepted mismatched version {version}"
        );
        assert_eq!(&hello[6..], application_version.as_bytes());
    }
    assert_eq!(
        runroom::HostClient::new(&fixture.socket)
            .list_instances(None, 100)
            .expect("matching-version client must remain usable"),
        Vec::<runroom::model::InstanceRecord>::new()
    );
}
#[test]
fn native_exec_applies_profile_and_project_values_without_clearing_inheritance() {
    let fixture = GitFixture::new();
    fs::write(
        fixture.config_home.join("runroom/config.toml"),
        "[launcher]\nprofile = 'native'\n\n[launcher.profiles.native]\nproject_environment = true\nenvironment = ['RUNROOM_POSTGRES_PORT']\nset_environment = { RUNROOM_ENV_PROBE = 'configured' }\n",
    )
    .expect("write native environment profile");
    fs::write(
        fixture.repository.join(".runroom.env"),
        "RUNROOM_POSTGRES_PORT=6543\n",
    )
    .expect("write project environment");
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, true);
    wait_for_socket(&mut daemon, &fixture.socket);
    let script = "import json, os; print(json.dumps({'configured': os.getenv('RUNROOM_ENV_PROBE'), 'port': os.getenv('RUNROOM_POSTGRES_PORT'), 'inherited': os.getenv('RUNROOM_UNLISTED')}))";
    let output = isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .args(["launcher", "--socket"])
        .arg(&fixture.socket)
        .arg("--command")
        .arg(shell_words::join([PYTHON, "-c", script]))
        .env("XDG_CONFIG_HOME", &fixture.config_home)
        .env("RUNROOM_ENV_PROBE", "original")
        .env("RUNROOM_UNLISTED", "preserved")
        .env_remove("RUNROOM_POSTGRES_PORT")
        .current_dir(&fixture.repository)
        .output()
        .expect("launch native environment probe");
    assert_output_succeeded("native environment probe", &output);
    assert_eq!(
        probe_output(&output),
        serde_json::json!({"configured": "configured", "port": "6543", "inherited": "preserved"})
    );
    assert_output_succeeded("native environment daemon", &daemon.wait_for_exit());
}

#[test]
fn native_exec_is_quiet_and_preserves_pid_cwd_and_scope() {
    let fixture = GitFixture::new();
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, true);
    wait_for_socket(&mut daemon, &fixture.socket);

    let (launcher_pid, output) = run_probe(&fixture, &fixture.repository, None, false, &[]);

    assert_output_succeeded("quiet launcher", &output);
    assert!(
        output.stderr.is_empty(),
        "quiet launcher emitted stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let probe = probe_output(&output);
    assert_eq!(probe["pid"].as_u64(), Some(u64::from(launcher_pid)));
    assert_eq!(
        probe["cwd"].as_str(),
        Some(fixture.repository.to_str().expect("UTF-8 fixture path"))
    );
    let cgroup = probe["cgroup"].as_str().expect("probe cgroup");
    assert!(
        cgroup.contains("/runroom-"),
        "missing Runroom scope: {cgroup}"
    );
    assert!(cgroup.contains(".scope"), "missing scope suffix: {cgroup}");
    assert_output_succeeded("quiet daemon", &daemon.wait_for_exit());
}

#[test]
fn daemon_can_inspect_and_stop_the_complete_foreground_scope() {
    let fixture = GitFixture::new();
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, true);
    wait_for_socket(&mut daemon, &fixture.socket);
    let child = isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .arg("launcher")
        .arg("--socket")
        .arg(&fixture.socket)
        .arg("--command")
        .arg(shell_words::join([PYTHON, "-c", SCOPE_PROBE]))
        .env("XDG_CONFIG_HOME", &fixture.config_home)
        .current_dir(&fixture.repository)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start scoped launcher");
    let launcher_pid = child.id();
    let mut foreground = ChildGuard(Some(child));
    let mut line = String::new();
    BufReader::new(
        foreground
            .0
            .as_mut()
            .expect("foreground child")
            .stdout
            .take()
            .expect("foreground stdout"),
    )
    .read_line(&mut line)
    .expect("read scope probe");
    let probe: Value = serde_json::from_str(&line).expect("parse scope probe");
    assert_eq!(probe["pid"].as_u64(), Some(u64::from(launcher_pid)));
    let child_pid = probe["child_pid"].as_u64().expect("probe child PID");
    assert_output_succeeded("scope daemon", &daemon.wait_for_exit());

    let scope_backend =
        SystemdScopeBackend::connect(&fixture.root.join("state/instances.json"), &[])
            .expect("connect to user systemd");
    let process = ProcessId(NonZeroU32::new(launcher_pid).expect("positive launcher PID"));
    let instance = scope_backend
        .resolve_process(process)
        .expect("resolve scoped process")
        .expect("Runroom instance");
    let handle = scope_backend
        .list_managed()
        .expect("list Runroom scopes")
        .into_iter()
        .find(|handle| handle.0.contains(&instance.0))
        .expect("launcher scope");
    assert_eq!(
        scope_backend
            .inspect(&handle)
            .expect("inspect active scope"),
        ScopeState::Active
    );

    scope_backend
        .stop(&handle, StopMode::Graceful)
        .expect("stop foreground scope");
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let exited = foreground
            .0
            .as_mut()
            .expect("foreground child")
            .try_wait()
            .expect("inspect foreground child")
            .is_some();
        let descendant_exists = Path::new("/proc").join(child_pid.to_string()).exists();
        if exited && !descendant_exists {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "foreground scope did not terminate PID {launcher_pid} and descendant {child_pid}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn isolated_daemons_and_owner_restart_preserve_each_others_live_instances() {
    let first = GitFixture::new();
    let second = GitFixture::new();
    let mut first_daemon = ChildGuard::spawn(&first.socket, &first.workspaces, false);
    wait_for_socket(&mut first_daemon, &first.socket);
    let (mut first_foreground, first_probe) = start_foreground(&first, &first.repository, false);
    let first_client = runroom::HostClient::new(&first.socket);
    let first_record = first_client.list_instances(None, 100).unwrap().remove(0);

    let mut second_daemon = ChildGuard::spawn(&second.socket, &second.workspaces, false);
    wait_for_socket(&mut second_daemon, &second.socket);
    let (mut second_foreground, second_probe) =
        start_foreground(&second, &second.repository, false);
    let second_client = runroom::HostClient::new(&second.socket);
    let second_record = second_client.list_instances(None, 100).unwrap().remove(0);
    let first_backend =
        SystemdScopeBackend::connect(&first.root.join("state/instances.json"), &[]).unwrap();
    let second_backend =
        SystemdScopeBackend::connect(&second.root.join("state/instances.json"), &[]).unwrap();
    for (backend, foreign) in [
        (&first_backend, &second_probe),
        (&second_backend, &first_probe),
    ] {
        let process = ProcessId(
            NonZeroU32::new(u32::try_from(foreign["pid"].as_u64().unwrap()).unwrap()).unwrap(),
        );
        assert_eq!(backend.resolve_process(process).unwrap(), None);
    }
    assert!(matches!(
        second_backend.stop(
            &runroom::backend::ScopeHandle(first_record.scope_handle.clone()),
            StopMode::Force
        ),
        Err(runroom::backend::SystemdScopeError::ForeignScope(_))
    ));
    assert_eq!(
        first_client
            .get_instance(first_record.id.clone())
            .unwrap()
            .unwrap()
            .state,
        runroom::model::InstanceState::Running
    );
    first_daemon.0.as_mut().unwrap().kill().unwrap();
    let killed = first_daemon.0.take().unwrap().wait_with_output().unwrap();
    assert!(!killed.status.success());
    let mut restarted = ChildGuard::spawn(&first.socket, &first.workspaces, false);
    wait_for_socket(&mut restarted, &first.socket);
    assert_eq!(
        first_client
            .get_instance(first_record.id.clone())
            .unwrap()
            .unwrap()
            .state,
        runroom::model::InstanceState::Running
    );
    assert_eq!(
        second_client
            .get_instance(second_record.id.clone())
            .unwrap()
            .unwrap()
            .state,
        runroom::model::InstanceState::Running
    );
    first_client
        .stop_instance(first_record.id, StopMode::Force)
        .unwrap();
    second_client
        .stop_instance(second_record.id, StopMode::Force)
        .unwrap();
    assert!(!first_foreground.wait_for_exit().status.success());
    assert!(!second_foreground.wait_for_exit().status.success());
}

#[test]
fn alternate_socket_cannot_open_an_in_use_registry() {
    let fixture = GitFixture::new();
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, false);
    wait_for_socket(&mut daemon, &fixture.socket);
    runroom::HostClient::new(&fixture.socket).verify().unwrap();
    let alternate = fixture.root.join("other-runtime/control.sock");
    let mut duplicate = ChildGuard::spawn(&alternate, &fixture.workspaces, false);
    let output = duplicate.wait_for_exit();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("another daemon owns this instance registry")
    );
    assert!(!alternate.exists());
    runroom::HostClient::new(&fixture.socket).verify().unwrap();
}

#[test]
fn omitted_scalar_limits_reach_systemd_and_the_durable_registry() {
    let fixture = GitFixture::new();
    let config = fixture.config_home.join("runroom/config.toml");
    let mut contents = fs::read_to_string(&config).unwrap();
    contents.push_str(
        "\n[daemon.resource_ceiling]\nmemory_max_bytes = 268435456\ntasks_max = 64\ncpu_quota_basis_points = 10000\n",
    );
    fs::write(config, contents).unwrap();
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, false);
    wait_for_socket(&mut daemon, &fixture.socket);
    let (mut foreground, _) = start_foreground(&fixture, &fixture.repository, false);
    let client = runroom::HostClient::new(&fixture.socket);
    let record = client.list_instances(None, 100).unwrap().remove(0);
    assert_eq!(record.limits.memory_max_bytes, Some(268_435_456));
    assert_eq!(record.limits.tasks_max, Some(64));
    assert_eq!(record.limits.cpu_quota_basis_points, Some(10_000));
    let persisted: Value =
        serde_json::from_slice(&fs::read(fixture.root.join("state/instances.json")).unwrap())
            .unwrap();
    let limits = &persisted["instances"][0]["limits"];
    assert_eq!(limits["memory_max_bytes"], 268_435_456_u64);
    assert_eq!(limits["tasks_max"], 64_u64);
    assert_eq!(limits["cpu_quota_basis_points"], 10_000_u64);

    let connection = zbus::blocking::Connection::session().unwrap();
    let manager = zbus::blocking::Proxy::new(
        &connection,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .unwrap();
    let path: zbus::zvariant::OwnedObjectPath = manager
        .call("GetUnit", &(record.scope_handle.as_str(),))
        .unwrap();
    let scope = zbus::blocking::Proxy::new(
        &connection,
        "org.freedesktop.systemd1",
        path,
        "org.freedesktop.systemd1.Scope",
    )
    .unwrap();
    assert_eq!(scope.get_property::<u64>("MemoryMax").unwrap(), 268_435_456);
    assert_eq!(scope.get_property::<u64>("TasksMax").unwrap(), 64);
    assert_eq!(
        scope.get_property::<u64>("CPUQuotaPerSecUSec").unwrap(),
        1_000_000
    );
    client.stop_instance(record.id, StopMode::Force).unwrap();
    assert!(!foreground.wait_for_exit().status.success());
}

#[test]
fn verbose_primary_launch_preserves_native_arguments() {
    let fixture = GitFixture::new();
    let nested = fixture.repository.join("nested/path");
    fs::create_dir_all(&nested).expect("create nested directory");
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, true);
    wait_for_socket(&mut daemon, &fixture.socket);
    let arguments = ["space value", "--flag", "semi;literal"];

    let (launcher_pid, launcher) = run_probe(&fixture, &nested, None, true, &arguments);

    assert_output_succeeded("primary launcher", &launcher);
    let probe = probe_output(&launcher);
    assert_eq!(probe["pid"].as_u64(), Some(u64::from(launcher_pid)));
    assert_eq!(
        probe["cwd"].as_str(),
        Some(fixture.repository.to_str().expect("UTF-8 fixture path"))
    );
    assert_eq!(
        probe["arg_hex"],
        serde_json::json!([
            "73706163652076616c7565",
            "2d2d666c6167",
            "73656d693b6c69746572616c"
        ])
    );
    let stderr = String::from_utf8_lossy(&launcher.stderr);
    assert!(stderr.contains("workspace=\"primary\""));
    assert!(stderr.contains(&format!("workspace={}", fixture.repository.display())));
    assert!(stderr.contains("origin=Primary"));
    assert!(stderr.contains("launcher executing foreground command"));

    assert_output_succeeded("primary daemon", &daemon.wait_for_exit());
    assert!(!fixture.socket.exists(), "daemon should remove its socket");
}

#[test]
fn bubblewrap_exec_uses_sandbox_workspace_and_network_namespace() {
    let fixture = GitFixture::new();
    let config_path = fixture.config_home.join("runroom/config.toml");
    fs::write(
        &config_path,
        "runtime = 'bubblewrap'\n\n[launcher]\nprofile = 'sandbox'\n\n[launcher.profiles.sandbox]\nnetwork = 'none'\nbind_mounts = [\n  { source = '@workspace', destination = '/workspace', access = 'rw' },\n]\n",
    )
    .expect("write Bubblewrap profile");
    let host_network_namespace = fs::metadata("/proc/self/ns/net")
        .expect("inspect host network namespace")
        .ino();
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, true);
    wait_for_socket(&mut daemon, &fixture.socket);

    let (_, output) = run_probe(&fixture, &fixture.repository, None, false, &["space value"]);

    assert_output_succeeded("Bubblewrap launcher", &output);
    let probe = probe_output(&output);
    assert_eq!(probe["cwd"].as_str(), Some("/workspace"));
    assert_eq!(
        probe["arg_hex"],
        serde_json::json!(["73706163652076616c7565"])
    );
    assert_ne!(
        probe["netns"].as_u64(),
        Some(host_network_namespace),
        "Bubblewrap should create a network namespace"
    );
    assert_output_succeeded("Bubblewrap daemon", &daemon.wait_for_exit());
}

#[test]
fn default_profile_inherits_base_grants_and_overrides_mounts_and_environment() {
    let fixture = GitFixture::new();
    let inherited = fixture.root.join("inherited");
    let original = fixture.root.join("original");
    let replacement = fixture.root.join("replacement");
    let added = fixture.root.join("added");
    for directory in [&inherited, &original, &replacement, &added] {
        fs::create_dir(directory).expect("create profile mount source");
    }
    fs::write(inherited.join("guide"), "inherited read-only").unwrap();
    fs::write(original.join("guide"), "base destination").unwrap();
    fs::write(replacement.join("guide"), "child destination").unwrap();
    fs::write(added.join("guide"), "child addition").unwrap();
    let script = r"import errno, json, os, pathlib
inherited = pathlib.Path('/inherited/guide')
denied = False
try:
    inherited.write_text('forbidden')
except OSError as error:
    assert error.errno == errno.EROFS
    denied = True
pathlib.Path('/replaced/result').write_text('child write')
print(json.dumps({
    'cwd': os.getcwd(),
    'inherited': inherited.read_text(),
    'read_only_denied': denied,
    'replaced': pathlib.Path('/replaced/guide').read_text(),
    'added': pathlib.Path('/added/guide').read_text(),
    'base_host': os.getenv('RUNROOM_BASE_HOST'),
    'child_host': os.getenv('RUNROOM_CHILD_HOST'),
    'base_literal': os.getenv('RUNROOM_BASE_LITERAL'),
    'override': os.getenv('RUNROOM_OVERRIDE'),
    'path': os.getenv('PATH'),
}))
";
    let config = format!(
        r"runtime = 'bubblewrap'
[launcher.base]
command = {}
network = 'none'
environment = ['PATH', 'RUNROOM_BASE_HOST']
set_environment = {{ RUNROOM_BASE_LITERAL = 'base literal', RUNROOM_OVERRIDE = 'base value' }}
bind_mounts = [
  {{ source = '@workspace', destination = '/workspace', access = 'rw' }},
  {{ source = {:?}, destination = '/inherited', access = 'ro' }},
  {{ source = {:?}, destination = '/replaced', access = 'ro' }},
]
[launcher.profiles.default]
environment = ['RUNROOM_BASE_HOST', 'RUNROOM_CHILD_HOST']
set_environment = {{ RUNROOM_OVERRIDE = 'child value', PATH = '/profile/path' }}
bind_mounts = [
  {{ source = {:?}, destination = '/replaced', access = 'rw' }},
  {{ source = {:?}, destination = '/added', access = 'ro' }},
]
",
        serde_json::to_string(&shell_words::join([PYTHON, "-c", script])).unwrap(),
        inherited.to_str().unwrap(),
        original.to_str().unwrap(),
        replacement.to_str().unwrap(),
        added.to_str().unwrap(),
    );
    let config_path = fixture.config_home.join("runroom/config.toml");
    fs::write(&config_path, &config).expect("write inherited default profile");
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, true);
    wait_for_socket(&mut daemon, &fixture.socket);
    let output = isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .args(["launcher", "--socket"])
        .arg(&fixture.socket)
        .env("XDG_CONFIG_HOME", &fixture.config_home)
        .env("RUNROOM_BASE_HOST", "inherited host")
        .env("RUNROOM_CHILD_HOST", "child host")
        .env("RUNROOM_BASE_LITERAL", "host literal")
        .env("RUNROOM_OVERRIDE", "host override")
        .current_dir(&fixture.repository)
        .output()
        .expect("launch inherited default profile");
    assert_output_succeeded("inherited default launcher", &output);
    assert_eq!(
        probe_output(&output),
        serde_json::json!({
            "cwd": "/workspace",
            "inherited": "inherited read-only",
            "read_only_denied": true,
            "replaced": "child destination",
            "added": "child addition",
            "base_host": "inherited host",
            "child_host": "child host",
            "base_literal": "base literal",
            "override": "child value",
            "path": "/profile/path",
        })
    );
    assert_eq!(
        fs::read_to_string(replacement.join("result")).unwrap(),
        "child write"
    );
    assert!(!original.join("result").exists());
    assert_output_succeeded("inherited default daemon", &daemon.wait_for_exit());
}

#[test]
fn cli_cpu_override_replaces_the_inherited_default_selection() {
    let available = nix::sched::sched_getaffinity(nix::unistd::Pid::from_raw(0))
        .expect("read test CPU affinity");
    let cpus: Vec<_> = (0..nix::sched::CpuSet::count())
        .filter(|cpu| available.is_set(*cpu).expect("inspect available CPU"))
        .take(2)
        .collect();
    assert!(!cpus.is_empty(), "test needs an available CPU");
    let cpu_list = cpus
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let script = "import json,os; before=sorted(os.sched_getaffinity(0)); os.sched_setaffinity(0,set(range(1024))); print(json.dumps({'before':before,'after':sorted(os.sched_getaffinity(0))}))";
    for use_count in [true, false] {
        let fixture = GitFixture::new();
        let inherited_selection = if use_count {
            format!("cpu_cores = [{}]", cpus.last().unwrap())
        } else {
            "cpu_count = 1".to_owned()
        };
        fs::write(
            fixture.config_home.join("runroom/config.toml"),
            format!(
                "runtime = 'bubblewrap'\n[launcher.base]\nnetwork = 'none'\n{inherited_selection}\nbind_mounts = [{{ source = '@workspace', destination = '/workspace', access = 'rw' }}]\n[launcher.profiles.default]\n"
            ),
        )
        .expect("write inherited CPU selection");
        let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, true);
        wait_for_socket(&mut daemon, &fixture.socket);
        let mut command = isolated_command(env!("CARGO_BIN_EXE_runroom"));
        command
            .args(["launcher", "--socket"])
            .arg(&fixture.socket)
            .arg("--command")
            .arg(shell_words::join([PYTHON, "-c", script]))
            .env("XDG_CONFIG_HOME", &fixture.config_home)
            .current_dir(&fixture.repository);
        let expected = if use_count {
            command.args(["--cpu-count", "1"]);
            serde_json::json!([cpus[0]])
        } else {
            command.arg("--cpu-cores").arg(&cpu_list);
            serde_json::json!(cpus)
        };
        let output = command.output().expect("launch inherited CPU override");
        assert_output_succeeded("inherited CPU override launcher", &output);
        let observed = probe_output(&output);
        assert_eq!(observed["before"], expected, "count override={use_count}");
        assert_eq!(
            observed["after"], expected,
            "inherited CPU override allowed widening affinity"
        );
        assert_output_succeeded("inherited CPU override daemon", &daemon.wait_for_exit());
    }
}

#[test]
fn launch_mounts_enforce_read_only_and_write_through_explicit_destinations() {
    let fixture = GitFixture::new();
    let config_path = fixture.config_home.join("runroom/config.toml");
    let config = "runtime = 'bubblewrap'\n[launcher]\nprofile = 'sandbox'\n[launcher.profiles.sandbox]\nbind_mounts = [{ source = '@workspace', destination = '/workspace', access = 'rw' }]\n";
    fs::write(&config_path, config).unwrap();
    let docs = fixture.root.join("docs with spaces");
    let assets = fixture.root.join("assets");
    fs::create_dir(&docs).unwrap();
    fs::create_dir(&assets).unwrap();
    fs::write(docs.join("guide"), "host documentation").unwrap();
    let script = "import errno,pathlib\nfor path in ['/docs/guide', '/docs with spaces/guide']:\n assert pathlib.Path(path).read_text() == 'host documentation'\n try: pathlib.Path(path).write_text('changed')\n except OSError as e: assert e.errno == errno.EROFS\n else: raise AssertionError('read-only mount allowed writing')\npathlib.Path('/assets/result').write_text('sandbox write'); print('mount access verified')";
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, true);
    wait_for_socket(&mut daemon, &fixture.socket);
    let output = isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .args(["--no-worktree", "--here", "--socket"])
        .arg(&fixture.socket)
        .args(["--ro", "../docs with spaces"])
        .args([
            "-m",
            "../docs with spaces@/docs:ro",
            "--mount",
            "../assets@/assets:rw",
        ])
        .arg("--command")
        .arg(shell_words::join([PYTHON, "-c", script]))
        .env("XDG_CONFIG_HOME", &fixture.config_home)
        .current_dir(&fixture.repository)
        .output()
        .unwrap();
    assert_output_succeeded("launch mounts", &output);
    assert_eq!(
        fs::read_to_string(docs.join("guide")).unwrap(),
        "host documentation"
    );
    assert_eq!(
        fs::read_to_string(assets.join("result")).unwrap(),
        "sandbox write"
    );
    assert_eq!(fs::read_to_string(config_path).unwrap(), config);
    assert_output_succeeded("mount daemon", &daemon.wait_for_exit());
}

#[test]
fn cpu_restrictions_confine_foreground_and_descendants_even_after_affinity_reset() {
    let available = nix::sched::sched_getaffinity(nix::unistd::Pid::from_raw(0))
        .expect("read test CPU affinity");
    let cpus: Vec<_> = (0..nix::sched::CpuSet::count())
        .filter(|cpu| available.is_set(*cpu).expect("inspect available CPU"))
        .take(2)
        .collect();
    assert!(!cpus.is_empty(), "test needs an available CPU");
    let expected = serde_json::json!(cpus);
    let cpu_list = cpus
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let child_probe = "import json,os; os.sched_setaffinity(0, set(range(1024))); print(json.dumps(sorted(os.sched_getaffinity(0))))";
    let probe = format!(
        "import json,os,subprocess; before=sorted(os.sched_getaffinity(0)); os.sched_setaffinity(0,set(range(1024))); child=json.loads(subprocess.check_output(['/usr/bin/python3','-c',{}])); print(json.dumps({{'before':before,'after':sorted(os.sched_getaffinity(0)),'child':child}}))",
        serde_json::to_string(child_probe).unwrap()
    );
    for runtime in ["native", "bubblewrap"] {
        for use_count in [true, false] {
            let fixture = GitFixture::new();
            let mounts = if runtime == "bubblewrap" {
                "bind_mounts = [{ source = '@workspace', destination = '/workspace', access = 'rw' }]\n"
            } else {
                ""
            };
            fs::write(
                fixture.config_home.join("runroom/config.toml"),
                format!(
                    "runtime = '{runtime}'\n[launcher]\nprofile = 'probe'\n[launcher.profiles.probe]\nnetwork = 'host'\n{mounts}"
                ),
            ).expect("write affinity probe profile");
            let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, true);
            wait_for_socket(&mut daemon, &fixture.socket);
            let mut command = isolated_command(env!("CARGO_BIN_EXE_runroom"));
            command
                .args(["launcher", "--socket"])
                .arg(&fixture.socket)
                .arg("--command")
                .arg(shell_words::join([PYTHON, "-c", &probe]))
                .env("XDG_CONFIG_HOME", &fixture.config_home)
                .current_dir(&fixture.repository);
            if use_count {
                command.arg("--cpu-count").arg(cpus.len().to_string());
            } else {
                command.arg("--cpu-cores").arg(&cpu_list);
            }
            let output = command.output().expect("run CPU-confined launcher");
            assert_output_succeeded("CPU-confined launcher", &output);
            let observed = probe_output(&output);
            assert_eq!(observed["before"], expected, "{runtime}, count={use_count}");
            assert_eq!(observed["after"], expected, "foreground widened affinity");
            assert_eq!(observed["child"], expected, "descendant widened affinity");
            assert_output_succeeded("CPU confinement daemon", &daemon.wait_for_exit());
        }
    }
}

#[test]
fn no_worktree_foreground_uses_exact_directory_without_git_or_herdr_and_confines_files() {
    let fixture = GitFixture::new();
    let plain = fixture.root.join("plain");
    let nested = fixture.repository.join("nested");
    fs::create_dir_all(&plain).expect("create non-Git directory");
    fs::create_dir_all(&nested).expect("create Git subdirectory");
    let secret = fixture.root.join("outside-secret");
    fs::write(&secret, "outside\n").expect("write inaccessible sibling file");
    fs::write(
        fixture.config_home.join("runroom/config.toml"),
        format!(
            "runtime = 'bubblewrap'\n[launcher]\nprofile = 'pi'\nname = 'ignored-default-name'\n[launcher.profiles.pi]\nidentity = 'herdr'\nnetwork = 'none'\ncpu_count = 1\n[daemon]\nherdr_socket = '{}'\n",
            fixture.root.join("missing-herdr.sock").display()
        ),
    ).expect("write directory profile");
    let probe = format!(
        "import json,os,pathlib; pathlib.Path('inside.txt').write_text('inside'); print(json.dumps({{'cwd':os.getcwd(),'outside_visible':os.path.exists({:?}),'descriptor':os.path.exists('/runtime/launch.json'),'cpus':sorted(os.sched_getaffinity(0)),'cgroup':pathlib.Path('/proc/self/cgroup').read_text()}}))",
        secret.to_str().expect("UTF-8 fixture")
    );
    let available =
        nix::sched::sched_getaffinity(nix::unistd::Pid::from_raw(0)).expect("read available CPUs");
    let first_cpu = (0..nix::sched::CpuSet::count())
        .find(|cpu| available.is_set(*cpu).expect("inspect CPU"))
        .expect("available CPU");
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, false);
    wait_for_socket(&mut daemon, &fixture.socket);
    for directory in [&plain, &nested] {
        let mut command = isolated_command(env!("CARGO_BIN_EXE_runroom"));
        let output = command
            .args(["--no-worktree", "--here", "--socket"])
            .arg(&fixture.socket)
            .arg("--command")
            .arg(shell_words::join([PYTHON, "-c", &probe]))
            .env("XDG_CONFIG_HOME", &fixture.config_home)
            .current_dir(directory)
            .output()
            .expect("launch exact directory");
        assert_output_succeeded("foreground directory launch", &output);
        let observed = probe_output(&output);
        assert_eq!(observed["cwd"], "/workspace");
        assert_eq!(observed["outside_visible"], false);
        assert_eq!(observed["descriptor"], false);
        assert_eq!(observed["cpus"], serde_json::json!([first_cpu]));
        assert!(observed["cgroup"].as_str().unwrap().contains("/runroom-"));
        assert_eq!(
            fs::read_to_string(directory.join("inside.txt")).unwrap(),
            "inside"
        );
    }
    assert!(!fixture.repository.join("inside.txt").exists());
    assert!(
        !fixture.workspaces.exists(),
        "No-worktree launch created managed Git worktrees"
    );
}

#[test]
fn no_worktree_creates_a_default_session_tab_and_preserves_directory_cpu_and_mount_overrides() {
    let fixture = GitFixture::new();
    let home = fixture.root.join("isolated-home");
    let config_home = home.join(".config");
    let herdr_config = config_home.join("herdr/config.toml");
    let runroom_config = config_home.join("runroom/config.toml");
    fs::create_dir_all(herdr_config.parent().unwrap()).unwrap();
    fs::create_dir_all(runroom_config.parent().unwrap()).unwrap();
    fs::write(&herdr_config, "").unwrap();
    fs::write(
        &runroom_config,
        "runtime = 'bubblewrap'\n[launcher]\nprofile = 'development'\n[launcher.profiles.development]\ncommand = '/usr/bin/python3'\nnetwork = 'none'\ncpu_count = 2\n",
    ).unwrap();
    let directory = fixture.root.join("non Git directory");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("read-only grant"), "readable").unwrap();
    fs::create_dir(directory.join("writable grant")).unwrap();
    let herdr_socket = config_home.join("herdr/herdr.sock");
    let mut server = spawn_directory_herdr(&home, &config_home, &herdr_config, &directory);
    wait_for_socket(&mut server, &herdr_socket);
    let bootstrap = herdr_request(
        &herdr_socket,
        "workspace.create",
        &serde_json::json!({"cwd": directory, "label": "Directory test", "focus": true}),
    );
    let bootstrap_tab = bootstrap["tab"]["tab_id"].as_str().unwrap();
    let mut daemon = spawn_directory_daemon(&fixture, &home, &config_home, &herdr_socket);
    wait_for_socket(&mut daemon, &fixture.socket);
    let probe = "import os,json,pathlib; descriptor=json.loads(pathlib.Path('/runtime/launch.json').read_text()); readonly=pathlib.Path('/granted/read-only'); writable=pathlib.Path('/granted/writable/created'); writable.write_text('routed write'); denied=False\ntry:\n readonly.write_text('forbidden')\nexcept OSError:\n denied=True\np=pathlib.Path('result.tmp'); p.write_text(json.dumps({'cwd':os.getcwd(),'cpus':sorted(os.sched_getaffinity(0)),'workspace':descriptor['workspace'],'grant':readonly.read_text(),'read_only_denied':denied,'written':writable.read_text()})); p.replace('result.json')";
    let output = isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .args(["--no-worktree", "--socket"])
        .arg(&fixture.socket)
        .args(["--mount", "read-only grant@/granted/read-only:ro"])
        .args(["-m", "writable grant@/granted/writable:rw"])
        .args(["--cpu-count", "1", "-c"])
        .arg(shell_words::join([PYTHON, "-c", probe]))
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("HERDR_SESSION", "not-the-default-session")
        .env("HERDR_CONFIG_PATH", &herdr_config)
        .current_dir(&directory)
        .output()
        .unwrap();
    assert_output_succeeded("multiplexed directory launcher", &output);
    let deadline = Instant::now() + WAIT_LIMIT;
    while !directory.join("result.json").exists() {
        if Instant::now() >= deadline {
            let snapshot = herdr_request(&herdr_socket, "session.snapshot", &serde_json::json!({}));
            panic!("routed directory command did not complete; snapshot: {snapshot}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let observed: Value =
        serde_json::from_slice(&fs::read(directory.join("result.json")).unwrap()).unwrap();
    let available = nix::sched::sched_getaffinity(nix::unistd::Pid::from_raw(0)).unwrap();
    let first_cpu = (0..nix::sched::CpuSet::count())
        .find(|cpu| available.is_set(*cpu).unwrap())
        .unwrap();
    assert_eq!(observed["cwd"], "/workspace");
    assert_eq!(observed["cpus"], serde_json::json!([first_cpu]));
    assert_eq!(observed["workspace"]["kind"], "directory");
    assert_eq!(observed["grant"], "readable");
    assert_eq!(observed["read_only_denied"], true);
    assert_eq!(observed["written"], "routed write");
    assert_eq!(
        fs::read_to_string(directory.join("writable grant/created")).unwrap(),
        "routed write"
    );
    assert_eq!(
        observed["workspace"]["host_path"],
        directory.to_str().unwrap()
    );
    let records = runroom::HostClient::new(&fixture.socket)
        .list_instances(None, 100)
        .unwrap();
    let record = records.first().expect("registered directory instance");
    assert_eq!(
        record.workspace.selection,
        runroom::model::WorkspaceSelection::Here
    );
    assert_eq!(record.workspace.path, directory);
    assert_eq!(record.limits.cpu_count, Some(1));
    let context = record.herdr.as_ref().expect("routed pane identity");
    assert!(context.session_name.is_none());
    let pane = herdr_request(
        &herdr_socket,
        "pane.current",
        &serde_json::json!({"caller_pane_id": context.pane_id}),
    );
    assert_ne!(pane["pane"]["tab_id"].as_str().unwrap(), bootstrap_tab);
    assert_eq!(
        pane["pane"]["workspace_id"],
        bootstrap["workspace"]["workspace_id"]
    );
    assert!(
        !fixture.workspaces.exists(),
        "directory launch created Git worktrees"
    );
    stop_directory_herdr(&home, &config_home, &herdr_config, &mut server);
}

#[test]
fn here_no_worktree_preserves_existing_herdr_pane_and_reports_scoped_child_activity() {
    let fixture = GitFixture::new();
    let home = fixture.root.join("isolated-home");
    let config_home = home.join(".config");
    let herdr_config = config_home.join("herdr/config.toml");
    let runroom_config = config_home.join("runroom/config.toml");
    let directory = fixture.root.join("existing pane directory");
    fs::create_dir_all(&directory).unwrap();
    fs::create_dir_all(herdr_config.parent().unwrap()).unwrap();
    fs::create_dir_all(runroom_config.parent().unwrap()).unwrap();
    fs::write(&herdr_config, "").unwrap();
    fs::write(
        &runroom_config,
        format!(
            "runtime = 'bubblewrap'\n[launcher]\nprofile = 'reporter'\n[launcher.profiles.reporter]\nidentity = 'herdr'\nnetwork = 'none'\nbind_mounts = [{{ source = '@workspace', destination = '/workspace', access = 'rw' }}, {{ source = '{}', destination = '/runtime/runroom', access = 'rw' }}]\n",
            fixture.socket.parent().unwrap().display()
        ),
    ).unwrap();
    let herdr_socket = config_home.join("herdr/herdr.sock");
    let mut server = spawn_directory_herdr(&home, &config_home, &herdr_config, &directory);
    wait_for_socket(&mut server, &herdr_socket);
    let bootstrap = herdr_request(
        &herdr_socket,
        "workspace.create",
        &serde_json::json!({"cwd": directory, "label": "Same-pane reporting", "focus": true}),
    );
    let pane_id = bootstrap["root_pane"]["pane_id"]
        .as_str()
        .expect("bootstrap pane");
    let before = herdr_request(&herdr_socket, "session.snapshot", &serde_json::json!({}));
    let mut daemon = spawn_directory_daemon(&fixture, &home, &config_home, &herdr_socket);
    wait_for_socket(&mut daemon, &fixture.socket);
    wait_for_socket(
        &mut daemon,
        &fixture
            .socket
            .parent()
            .unwrap()
            .join("activity/status.sock"),
    );

    let probe = same_pane_activity_probe();
    let foreground_command = shell_words::join([PYTHON, "-c", &probe]);
    let launch_command = shell_words::join([
        env!("CARGO_BIN_EXE_runroom"),
        "--here",
        "--no-worktree",
        "--socket",
        fixture.socket.to_str().unwrap(),
        "--command",
        &foreground_command,
    ]);
    let command = format!(
        "{launch_command} >{} 2>&1",
        shell_words::quote(directory.join("launcher.log").to_str().unwrap())
    );
    herdr_request(
        &herdr_socket,
        "pane.send_input",
        &serde_json::json!({"pane_id": pane_id, "text": command, "keys": ["enter"]}),
    );
    let observed = await_pane_probe(&directory, "ready.json", &herdr_socket);

    let client = runroom::HostClient::new(&fixture.socket);
    let records = client.list_instances(None, 100).unwrap();
    assert_eq!(
        records.len(),
        1,
        "same-pane launch registered extra instances"
    );
    let record = &records[0];
    let _scope_cleanup = PaneScopeCleanup {
        socket: fixture.socket.clone(),
        instance: record.id.clone(),
    };
    assert_same_pane_attribution(&directory, &bootstrap, &observed, record);

    assert_scoped_pane_reports(
        &directory,
        &herdr_socket,
        &client,
        record,
        &observed,
        &before,
        &bootstrap,
    );
    fs::write(directory.join("finish"), "").unwrap();
    assert_eq!(
        await_pane_probe(&directory, "finished.json", &herdr_socket),
        true
    );
    assert!(
        !fixture.workspaces.exists(),
        "same-pane launch created Git worktrees"
    );
    stop_directory_herdr(&home, &config_home, &herdr_config, &mut server);
}

fn assert_same_pane_attribution(
    directory: &Path,
    bootstrap: &Value,
    observed: &Value,
    record: &runroom::model::InstanceRecord,
) {
    let pane_id = bootstrap["root_pane"]["pane_id"].as_str().unwrap();
    let workspace_id = bootstrap["workspace"]["workspace_id"].as_str().unwrap();
    assert_eq!(observed["cwd"], "/workspace");
    let descriptor = &observed["descriptor"];
    assert_eq!(descriptor["version"], 1);
    assert_eq!(descriptor["workspace"]["kind"], "directory");
    assert_eq!(
        descriptor["workspace"]["host_path"],
        directory.to_str().unwrap()
    );
    assert_eq!(descriptor["herdr"]["workspace_id"], workspace_id);
    assert_eq!(descriptor["herdr"]["pane_id"], pane_id);
    assert_eq!(descriptor["agent"]["id"], pane_id);
    assert_eq!(descriptor["instance_id"], record.id.0);
    assert_eq!(
        record.workspace.selection,
        runroom::model::WorkspaceSelection::Here
    );
    assert_eq!(record.workspace.path.as_path(), directory);
    assert_eq!(record.state, runroom::model::InstanceState::Running);
    let context = record
        .herdr
        .as_ref()
        .expect("same-pane registry attribution");
    assert_eq!(context.workspace_id.as_deref(), Some(workspace_id));
    assert_eq!(context.pane_id.as_deref(), Some(pane_id));
    assert!(context.session_name.is_none());
    let scope = observed["cgroup"].as_str().unwrap();
    assert!(
        scope.contains(&record.scope_handle),
        "scope attribution: {scope}"
    );
}

fn same_pane_activity_probe() -> String {
    // This subprocess, not the test process or foreground leader, opens the
    // daemon's real activity socket. Frames match src/process/daemon.rs.
    let reporter = r"import json,os,pathlib,socket,struct,sys
state = int(sys.argv[1])
message = sys.argv[2].encode('utf-8')
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
    stream.settimeout(5)
    stream.connect('/runtime/runroom/activity/status.sock')
    stream.sendall(b'RRA\0' + bytes([1, state]) + struct.pack('>H', len(message)) + message)
    ack = stream.recv(1)
    assert ack == b'\0', repr(ack)
print(json.dumps(dict(pid=os.getpid(), cgroup=pathlib.Path('/proc/self/cgroup').read_text(), ack=list(ack))))
";
    format!(
        r"import json,os,pathlib,subprocess,time
def publish(name, value):
    temporary = pathlib.Path(name + '.tmp')
    temporary.write_text(json.dumps(value))
    temporary.replace(name)
def await_file(name):
    deadline = time.monotonic() + 30
    while not pathlib.Path(name).exists():
        assert time.monotonic() < deadline, name
        time.sleep(0.01)
descriptor = json.loads(pathlib.Path('/runtime/launch.json').read_text())
publish('ready.json', dict(pid=os.getpid(), cwd=os.getcwd(), cgroup=pathlib.Path('/proc/self/cgroup').read_text(), descriptor=descriptor))
for index in range(3):
    request = 'request-' + str(index) + '.json'
    await_file(request)
    state, message = json.loads(pathlib.Path(request).read_text())
    result = json.loads(subprocess.check_output(['/usr/bin/python3', '-c', {}, str(state), message], timeout=10))
    publish('reported-' + str(index) + '.json', result)
await_file('finish')
publish('finished.json', True)
",
        serde_json::to_string(reporter).unwrap()
    )
}

fn assert_scoped_pane_reports(
    directory: &Path,
    herdr_socket: &Path,
    client: &runroom::HostClient,
    record: &runroom::model::InstanceRecord,
    observed: &Value,
    before: &Value,
    bootstrap: &Value,
) {
    let pane_id = bootstrap["root_pane"]["pane_id"].as_str().unwrap();
    let workspace_id = bootstrap["workspace"]["workspace_id"].as_str().unwrap();
    let tab_id = bootstrap["tab"]["tab_id"].as_str().unwrap();
    for (index, (wire_state, activity_state, state_name, message)) in [
        (
            0,
            runroom::model::ActivityState::Working,
            "working",
            "Working — scoped child",
        ),
        (
            1,
            runroom::model::ActivityState::Blocked,
            "blocked",
            "Waiting — scoped child",
        ),
        (
            2,
            runroom::model::ActivityState::Idle,
            "idle",
            "Ready — scoped child",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let request = directory.join(format!("request-{index}.json"));
        let temporary = directory.join(format!("request-{index}.tmp"));
        fs::write(
            &temporary,
            serde_json::to_vec(&serde_json::json!([wire_state, message])).unwrap(),
        )
        .unwrap();
        fs::rename(&temporary, &request).unwrap();
        let report = await_pane_probe(directory, &format!("reported-{index}.json"), herdr_socket);
        assert_eq!(report["ack"], serde_json::json!([0]));
        assert_ne!(
            report["pid"], observed["pid"],
            "leader sent the child report"
        );
        assert_eq!(
            report["cgroup"], observed["cgroup"],
            "reporter escaped its managed scope"
        );
        let current = client.list_instances(None, 100).unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].id, record.id);
        let activity = current[0]
            .activity
            .as_ref()
            .expect("registered binary activity");
        assert_eq!(activity.state, activity_state);
        assert_eq!(activity.message.as_deref(), Some(message));
        let pane = herdr_request(
            herdr_socket,
            "pane.current",
            &serde_json::json!({"caller_pane_id": pane_id}),
        );
        assert_eq!(pane["pane"]["tab_id"], tab_id);
        assert_eq!(pane["pane"]["workspace_id"], workspace_id);
        assert_eq!(
            pane["pane"]["agent"], record.profile,
            "Herdr must attribute activity to the selected runtime profile"
        );
        assert_pane_activity(herdr_socket, pane_id, state_name);
        let after = herdr_request(herdr_socket, "session.snapshot", &serde_json::json!({}));
        assert_same_tabs(before, &after);
    }
}

fn assert_same_tabs(before: &Value, after: &Value) {
    for (collection, id) in [
        ("workspaces", "workspace_id"),
        ("tabs", "tab_id"),
        ("panes", "pane_id"),
    ] {
        let identities = |snapshot: &Value| {
            let mut identities = snapshot["snapshot"][collection]
                .as_array()
                .expect("Herdr snapshot collection")
                .iter()
                .map(|item| item[id].as_str().expect("snapshot identity").to_owned())
                .collect::<Vec<_>>();
            identities.sort_unstable();
            identities
        };
        let expected = identities(before);
        assert!(!expected.is_empty(), "empty baseline {collection}");
        assert_eq!(
            identities(after),
            expected,
            "same-pane launch changed {collection}"
        );
    }
}

fn assert_pane_activity(socket: &Path, pane_id: &str, state: &str) {
    let pane = herdr_request(
        socket,
        "pane.current",
        &serde_json::json!({"caller_pane_id": pane_id}),
    );
    assert_eq!(
        pane["pane"]["agent_status"], state,
        "Herdr activity: {pane}"
    );
}

fn await_pane_probe(directory: &Path, filename: &str, socket: &Path) -> Value {
    let deadline = Instant::now() + WAIT_LIMIT;
    let path = directory.join(filename);
    loop {
        if let Ok(bytes) = fs::read(&path) {
            return serde_json::from_slice(&bytes).expect("atomic pane probe JSON");
        }
        assert!(
            Instant::now() < deadline,
            "pane probe {filename} did not complete; log: {}; snapshot: {}",
            fs::read_to_string(directory.join("launcher.log")).unwrap_or_default(),
            herdr_request(socket, "session.snapshot", &serde_json::json!({}))
        );
        thread::sleep(Duration::from_millis(10));
    }
}

struct PaneScopeCleanup {
    socket: PathBuf,
    instance: runroom::model::InstanceId,
}

impl Drop for PaneScopeCleanup {
    fn drop(&mut self) {
        let _ = runroom::HostClient::new(&self.socket)
            .stop_instance(self.instance.clone(), StopMode::Force);
    }
}

fn stop_directory_herdr(
    home: &Path,
    config_home: &Path,
    herdr_config: &Path,
    server: &mut ChildGuard,
) {
    let stopped = isolated_command("herdr")
        .args(["server", "stop"])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", config_home)
        .env("HERDR_CONFIG_PATH", herdr_config)
        .env_remove("HERDR_SESSION")
        .env_remove("HERDR_SOCKET_PATH")
        .output()
        .unwrap();
    assert_output_succeeded("isolated Herdr shutdown", &stopped);
    assert_output_succeeded("isolated Herdr server", &server.wait_for_exit());
}

fn spawn_directory_herdr(
    home: &Path,
    config_home: &Path,
    config: &Path,
    directory: &Path,
) -> ChildGuard {
    ChildGuard(Some(
        isolated_command("herdr")
            .arg("server")
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", config_home)
            .env("XDG_STATE_HOME", home.join(".local/state"))
            .env("HERDR_CONFIG_PATH", config)
            .env("SHELL", "/bin/bash")
            .env_remove("HERDR_SESSION")
            .env_remove("HERDR_SOCKET_PATH")
            .current_dir(directory)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start isolated Herdr server"),
    ))
}

fn spawn_directory_daemon(
    fixture: &GitFixture,
    home: &Path,
    config_home: &Path,
    herdr_socket: &Path,
) -> ChildGuard {
    ChildGuard(Some(
        isolated_command(env!("CARGO_BIN_EXE_runroom"))
            .args(["daemon", "--socket"])
            .arg(&fixture.socket)
            .arg("--workspace-root")
            .arg(&fixture.workspaces)
            .arg("--state-file")
            .arg(fixture.root.join("state/instances.json"))
            .arg("--herdr-socket")
            .arg(herdr_socket)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", config_home)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start directory routing daemon"),
    ))
}

fn herdr_request(socket: &Path, method: &str, params: &Value) -> Value {
    let mut stream = UnixStream::connect(socket).expect("connect isolated Herdr");
    stream.set_read_timeout(Some(WAIT_LIMIT)).unwrap();
    let request = serde_json::json!({"id": "directory-test", "method": method, "params": params});
    stream
        .write_all(serde_json::to_string(&request).unwrap().as_bytes())
        .unwrap();
    stream.write_all(b"\n").unwrap();
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    let response: Value = serde_json::from_str(&response).unwrap();
    assert!(
        response.get("error").is_none(),
        "Herdr request failed: {response}"
    );
    response["result"].clone()
}

#[test]
fn named_worktree_conflicts_with_no_worktree_but_allows_here() {
    let fixture = GitFixture::new();
    let rejected = isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .args([
            "--name",
            "docs",
            "--no-worktree",
            "--here",
            "--command",
            "/bin/true",
        ])
        .env("XDG_CONFIG_HOME", &fixture.config_home)
        .current_dir(&fixture.repository)
        .output()
        .expect("reject named exact-directory launch");
    assert_eq!(rejected.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(stderr.contains("--name"), "{stderr}");
    assert!(stderr.contains("--no-worktree"), "{stderr}");

    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, true);
    wait_for_socket(&mut daemon, &fixture.socket);
    let (_, allowed) = run_probe(&fixture, &fixture.repository, Some("docs"), false, &[]);
    assert_output_succeeded("named current-terminal launch", &allowed);
    assert!(
        Path::new(probe_output(&allowed)["cwd"].as_str().unwrap()).starts_with(&fixture.workspaces)
    );
    assert_output_succeeded("named current-terminal daemon", &daemon.wait_for_exit());
}

#[test]
fn repeated_named_launch_creates_then_reuses_one_worktree() {
    let fixture = GitFixture::new();
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, false);
    wait_for_socket(&mut daemon, &fixture.socket);

    let (_, first) = run_probe(&fixture, &fixture.repository, Some("docs"), true, &[]);
    assert_output_succeeded("first named launcher", &first);
    let first_stderr = String::from_utf8_lossy(&first.stderr);
    assert!(first_stderr.contains("origin=Created"));

    let (_, second) = run_probe(&fixture, &fixture.repository, Some("docs"), true, &[]);
    assert_output_succeeded("second named launcher", &second);
    let second_stderr = String::from_utf8_lossy(&second.stderr);
    assert!(second_stderr.contains("origin=Existing"));

    let first_path = PathBuf::from(
        probe_output(&first)["cwd"]
            .as_str()
            .expect("first probe cwd"),
    );
    let second_path = PathBuf::from(
        probe_output(&second)["cwd"]
            .as_str()
            .expect("second probe cwd"),
    );
    assert_eq!(first_path, second_path);
    assert!(first_path.starts_with(&fixture.workspaces));

    let listed = git(&fixture.repository, &["worktree", "list", "--porcelain"]);
    let listing = String::from_utf8(listed.stdout).expect("UTF-8 worktree listing");
    assert_eq!(listing.matches("branch refs/heads/docs").count(), 1);
    assert!(listing.contains(&format!("worktree {}", first_path.display())));
}

#[test]
fn workspace_commands_reject_active_retirement_then_retire_and_repair() {
    let fixture = GitFixture::new();
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, false);
    wait_for_socket(&mut daemon, &fixture.socket);

    let launcher = isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .args(["launcher", "--socket"])
        .arg(&fixture.socket)
        .args(["--name", "docs", "--command", "/usr/bin/sleep 30"])
        .env("XDG_CONFIG_HOME", &fixture.config_home)
        .current_dir(&fixture.repository)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start named workspace launcher");
    let mut foreground = ChildGuard(Some(launcher));
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let listed = git(&fixture.repository, &["worktree", "list", "--porcelain"]);
        if String::from_utf8_lossy(&listed.stdout).contains("branch refs/heads/docs") {
            break;
        }
        assert!(Instant::now() < deadline, "named worktree was not created");
        thread::sleep(Duration::from_millis(10));
    }

    let active_retirement = workspace_command(&fixture, &["retire", "docs"]);
    assert!(!active_retirement.status.success());
    assert!(
        String::from_utf8_lossy(&active_retirement.stderr).contains("workspace_active"),
        "unexpected active-retirement error: {}",
        String::from_utf8_lossy(&active_retirement.stderr)
    );

    foreground
        .0
        .as_mut()
        .expect("foreground launcher")
        .kill()
        .expect("kill foreground launcher");
    foreground
        .0
        .take()
        .expect("foreground launcher")
        .wait()
        .expect("wait for foreground launcher");

    let deadline = Instant::now() + WAIT_LIMIT;
    let retired = loop {
        let output = workspace_command(&fixture, &["retire", "docs"]);
        if output.status.success() {
            break output;
        }
        assert!(
            Instant::now() < deadline,
            "workspace remained active: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert!(String::from_utf8_lossy(&retired.stdout).contains("retired"));
    let listed = git(&fixture.repository, &["worktree", "list", "--porcelain"]);
    assert!(!String::from_utf8_lossy(&listed.stdout).contains("branch refs/heads/docs"));
    let branch = git(
        &fixture.repository,
        &["show-ref", "--verify", "refs/heads/docs"],
    );
    assert!(branch.status.success());

    let stale = fixture.root.join("stale-worktree");
    git(
        &fixture.repository,
        &[
            "worktree",
            "add",
            "--detach",
            stale.to_str().expect("UTF-8 stale path"),
        ],
    );
    fs::remove_dir_all(&stale).expect("remove stale worktree directory");
    let repaired = workspace_command(&fixture, &["repair"]);
    assert_output_succeeded("workspace repair", &repaired);
    assert!(String::from_utf8_lossy(&repaired.stdout).contains(&stale.display().to_string()));
}

#[test]
fn no_worktree_instances_at_worktree_root_and_below_block_retirement() {
    let fixture = GitFixture::new();
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, false);
    wait_for_socket(&mut daemon, &fixture.socket);
    let (_, output) = run_probe(&fixture, &fixture.repository, Some("docs"), false, &[]);
    assert_output_succeeded("create managed worktree", &output);
    let probe = probe_output(&output);
    let worktree = PathBuf::from(probe["cwd"].as_str().unwrap());
    let descendant = worktree.join("subdirectory");
    fs::create_dir(&descendant).unwrap();
    let client = runroom::HostClient::new(&fixture.socket);
    for directory in [&worktree, &descendant] {
        let (mut foreground, _) = start_foreground(&fixture, directory, true);
        let records = client.list_instances(None, 100).unwrap();
        let record = records
            .iter()
            .find(|record| {
                record.workspace.path == *directory
                    && record.workspace.selection == runroom::model::WorkspaceSelection::Here
                    && record.state == runroom::model::InstanceState::Running
            })
            .unwrap();
        let error = client
            .retire_workspace(
                fixture.repository.clone(),
                runroom::model::WorkspaceName("docs".to_owned()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("workspace_active"));
        assert!(worktree.exists());
        client
            .stop_instance(record.id.clone(), StopMode::Force)
            .unwrap();
        assert!(!foreground.wait_for_exit().status.success());
    }
    let (mut unrelated, _) = start_foreground(&fixture, &fixture.repository, true);
    let retired = client
        .retire_workspace(
            fixture.repository.clone(),
            runroom::model::WorkspaceName("docs".to_owned()),
        )
        .unwrap();
    assert_eq!(retired.path, worktree);
    assert!(!retired.path.exists());
    let record = client
        .list_instances(None, 100)
        .unwrap()
        .into_iter()
        .find(|record| {
            record.workspace.path == fixture.repository
                && record.state == runroom::model::InstanceState::Running
        })
        .unwrap();
    client.stop_instance(record.id, StopMode::Force).unwrap();
    assert!(!unrelated.wait_for_exit().status.success());
}

#[test]
fn daemon_and_launcher_share_mode_specific_toml() {
    let fixture = GitFixture::new();
    let config_home = fixture.root.join("config");
    let config_directory = config_home.join("runroom");
    fs::create_dir_all(&config_directory).expect("create config directory");
    let configured_command = probe_command(&[]);
    fs::write(
        config_directory.join("config.toml"),
        format!(
            "runtime = 'native'\nsocket = '{}'\n\n[launcher]\nname = 'docs'\nprofile = 'probe'\nverbose = true\n\n[launcher.profiles.probe]\ncommand = {}\nnetwork = 'host'\n\n[daemon]\nworkspace_root = '{}'\nverbose = false\n",
            fixture.socket.display(),
            serde_json::to_string(&configured_command).expect("serialize configured command"),
            fixture.workspaces.display()
        ),
    )
    .expect("write config");

    let mut daemon = ChildGuard::spawn_with_config(&config_home);
    wait_for_socket(&mut daemon, &fixture.socket);
    let launcher = isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .arg("launcher")
        .current_dir(&fixture.repository)
        .env("XDG_CONFIG_HOME", &config_home)
        .output()
        .expect("run configured launcher");

    assert_output_succeeded("configured launcher", &launcher);
    assert!(
        probe_output(&launcher)["cwd"]
            .as_str()
            .expect("configured probe cwd")
            .starts_with(fixture.workspaces.to_str().expect("UTF-8 fixture path"))
    );
    let stderr = String::from_utf8_lossy(&launcher.stderr);
    assert!(stderr.contains("workspace=\"docs\""));
    assert!(stderr.contains("origin=Created"));
    assert_output_succeeded("configured daemon", &daemon.wait_for_exit());
}

#[test]
fn launcher_requires_a_configured_or_overridden_command() {
    let root = unique_temporary_directory();
    let config_home = root.join("config");
    let config_path = config_home.join("runroom/config.toml");
    fs::create_dir_all(config_path.parent().expect("config parent"))
        .expect("create config directory");
    fs::write(
        &config_path,
        "[launcher]\nprofile = 'test'\n\n[launcher.profiles.test]\nnetwork = 'host'\n",
    )
    .expect("write config");
    let output = isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .args(["launcher", "--socket", "/unused/runroom.sock"])
        .env("XDG_CONFIG_HOME", &config_home)
        .output()
        .expect("run launcher without command");
    assert!(!output.status.success(), "missing command should fail");
    assert!(String::from_utf8_lossy(&output.stderr).contains(
        "launcher command is not configured for profile test; set its command or pass --command"
    ));
    fs::remove_dir_all(root).expect("remove temporary directory");
}

#[test]
fn command_override_wins_over_configured_default() {
    let fixture = GitFixture::new();
    let config_home = fixture.root.join("override-config");
    let config_directory = config_home.join("runroom");
    fs::create_dir_all(&config_directory).expect("create override config directory");
    fs::write(
        config_directory.join("config.toml"),
        format!(
            "socket = '{}'\n\n[launcher]\nprofile = 'test'\n\n[launcher.profiles.test]\ncommand = '/bin/false'\nnetwork = 'host'\n\n[daemon]\nworkspace_root = '{}'\n",
            fixture.socket.display(),
            fixture.workspaces.display()
        ),
    )
    .expect("write override config");
    let mut daemon = ChildGuard::spawn_with_config(&config_home);
    wait_for_socket(&mut daemon, &fixture.socket);

    let output = isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .args(["launcher", "--command", "/bin/true"])
        .current_dir(&fixture.repository)
        .env("XDG_CONFIG_HOME", &config_home)
        .output()
        .expect("run command override");

    assert_output_succeeded("command override", &output);
    assert_output_succeeded("override daemon", &daemon.wait_for_exit());
}

#[test]
fn private_network_setup_failure_never_executes_the_harness() {
    let fixture = GitFixture::new();
    fs::write(
        fixture.config_home.join("runroom/config.toml"),
        "runtime = 'bubblewrap'\n[launcher]\nprofile = 'private'\n[launcher.profiles.private]\nnetwork = 'private'\nbind_mounts = [{ source = '@workspace', destination = '/workspace', access = 'rw' }]\n",
    ).unwrap();
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, true);
    wait_for_socket(&mut daemon, &fixture.socket);
    let command = shell_words::join([
        PYTHON,
        "-c",
        "from pathlib import Path; Path('/workspace/unexpected-start').write_text('started')",
    ]);
    let output = isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .args(["--here", "--no-worktree", "--socket"])
        .arg(&fixture.socket)
        .args(["-c", &command])
        .env("XDG_CONFIG_HOME", &fixture.config_home)
        // Bubblewrap and the harness are absolute paths. Only helper lookup fails.
        .env("PATH", fixture.root.join("missing-helper"))
        .current_dir(&fixture.repository)
        .output()
        .expect("launch without network helper");
    assert!(
        !output.status.success(),
        "network setup unexpectedly succeeded"
    );
    assert_output_succeeded("private setup daemon", &daemon.wait_for_exit());
    let state_file = fixture.root.join("state/instances.json");
    let registry: Value = serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    let handle = runroom::backend::ScopeHandle(
        registry["instances"][0]["scope_handle"]
            .as_str()
            .unwrap()
            .to_owned(),
    );
    let backend = SystemdScopeBackend::connect(&state_file, &[]).unwrap();
    let deadline = Instant::now() + WAIT_LIMIT;
    while matches!(
        backend.inspect(&handle).unwrap(),
        ScopeState::Active | ScopeState::Starting | ScopeState::Stopping
    ) {
        assert!(
            Instant::now() < deadline,
            "failed startup left a live sandbox"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !fixture.repository.join("unexpected-start").exists(),
        "closing a failed startup gate executed the harness"
    );
}

#[test]
fn missing_foreground_executable_reports_exec_failure() {
    let fixture = GitFixture::new();
    let mut daemon = ChildGuard::spawn(&fixture.socket, &fixture.workspaces, true);
    wait_for_socket(&mut daemon, &fixture.socket);
    let output = isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .arg("launcher")
        .arg("--socket")
        .arg(&fixture.socket)
        .arg("-c")
        .arg("/definitely/missing/runroom-command")
        .env("XDG_CONFIG_HOME", &fixture.config_home)
        .current_dir(&fixture.repository)
        .output()
        .expect("run missing foreground executable");

    assert!(!output.status.success(), "missing executable should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot execute foreground command /definitely/missing/runroom-command")
    );
    assert!(stderr.contains("No such file or directory"));
    assert_output_succeeded("missing executable daemon", &daemon.wait_for_exit());
}

#[test]
fn invalid_toml_configuration_stops_before_role_startup() {
    let root = unique_temporary_directory();
    let config_home = root.join("config");
    let config_path = config_home.join("runroom/config.toml");
    fs::create_dir_all(config_path.parent().expect("config parent"))
        .expect("create config directory");
    fs::write(&config_path, "[daemon]\nname = 'docs'\n").expect("write invalid config");

    let output = isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .args(["daemon", "--socket", "/unused/runroom.sock"])
        .env("XDG_CONFIG_HOME", &config_home)
        .output()
        .expect("run with invalid config");

    assert!(!output.status.success(), "invalid config should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&format!("invalid {}", config_path.display())));
    assert!(stderr.contains("unknown field `name`"));
    fs::remove_dir_all(root).expect("remove temporary directory");
}

fn run_probe(
    fixture: &GitFixture,
    current_directory: &Path,
    name: Option<&str>,
    verbose: bool,
    arguments: &[&str],
) -> (u32, Output) {
    let mut command = isolated_command(env!("CARGO_BIN_EXE_runroom"));
    command
        .args(["launcher", "--here"])
        .arg("--socket")
        .arg(&fixture.socket)
        .current_dir(current_directory)
        .env("XDG_CONFIG_HOME", &fixture.config_home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if verbose {
        command.arg("--verbose");
    }
    if let Some(name) = name {
        command.arg("--name").arg(name);
    }
    let command_line = probe_command(arguments);
    if verbose {
        command.arg("--command");
    } else {
        command.arg("-c");
    }
    command.arg(command_line);
    let child = command.spawn().expect("start launcher");
    let launcher_pid = child.id();
    let output = child.wait_with_output().expect("collect launcher output");
    (launcher_pid, output)
}

fn probe_output(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid probe output: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn git(directory: &Path, arguments: &[&str]) -> Output {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("LC_ALL", "C")
        .output()
        .expect("execute Git fixture command");
    assert_output_succeeded("Git fixture command", &output);
    output
}

fn workspace_command(fixture: &GitFixture, arguments: &[&str]) -> Output {
    isolated_command(env!("CARGO_BIN_EXE_runroom"))
        .args(["workspace", "--socket"])
        .arg(&fixture.socket)
        .arg("--current-directory")
        .arg(&fixture.repository)
        .args(arguments)
        .env("XDG_CONFIG_HOME", &fixture.config_home)
        .output()
        .expect("run workspace command")
}

fn start_foreground(
    fixture: &GitFixture,
    directory: &Path,
    no_worktree: bool,
) -> (ChildGuard, Value) {
    let script = format!("{PROBE}; sys.stdout.flush(); import time; time.sleep(30)");
    let mut command = isolated_command(env!("CARGO_BIN_EXE_runroom"));
    command
        .args(["launcher", "--socket"])
        .arg(&fixture.socket)
        .args(["--here", "--command"])
        .arg(shell_words::join([PYTHON, "-c", &script]))
        .env("XDG_CONFIG_HOME", &fixture.config_home)
        .current_dir(directory)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if no_worktree {
        command.arg("--no-worktree");
    }
    let mut foreground = ChildGuard(Some(command.spawn().unwrap()));
    let stdout = foreground.0.as_mut().unwrap().stdout.take().unwrap();
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).unwrap();
    let probe = serde_json::from_str(&line).unwrap_or_else(|error| {
        let output = foreground.wait_for_exit();
        panic!(
            "foreground readiness failed: {error}; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (foreground, probe)
}

fn isolated_command(program: &str) -> Command {
    let mut command = Command::new(program);
    // Tests must not inherit attribution or routing from their host Herdr pane.
    for (name, _) in std::env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"HERDR_") {
            command.env_remove(name);
        }
    }
    command
}

fn unique_temporary_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("runroom-test-{}-{nonce}", std::process::id()))
}

fn wait_for_socket(daemon: &mut ChildGuard, socket_path: &Path) {
    let deadline = Instant::now() + WAIT_LIMIT;
    let socket = socket_path.to_str().expect("UTF-8 fixture socket");
    while Instant::now() < deadline {
        // A restart can leave a stale filesystem node. Check kernel listening
        // state without consuming the sole connection of a --once daemon.
        let listening = fs::read_to_string("/proc/net/unix")
            .expect("read Linux socket table")
            .lines()
            .any(|line| {
                let mut fields = line.split_whitespace();
                fields.nth(3) == Some("00010000") && fields.nth(3) == Some(socket)
            });
        if listening {
            return;
        }
        assert!(
            daemon
                .0
                .as_mut()
                .expect("daemon child")
                .try_wait()
                .expect("inspect daemon")
                .is_none(),
            "daemon exited before creating its socket"
        );
        thread::sleep(Duration::from_millis(10));
    }
    panic!("daemon did not create {}", socket_path.display());
}

fn assert_output_succeeded(role: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{role} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct GitFixture {
    root: PathBuf,
    repository: PathBuf,
    socket: PathBuf,
    workspaces: PathBuf,
    config_home: PathBuf,
}

impl GitFixture {
    fn new() -> Self {
        let root = unique_temporary_directory();
        let repository = root.join("project");
        fs::create_dir_all(&repository).expect("create Git repository");
        git(&repository, &["init", "--quiet", "--initial-branch=main"]);
        fs::write(repository.join("tracked.txt"), "fixture\n").expect("write fixture file");
        git(&repository, &["add", "tracked.txt"]);
        let commit = Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args([
                "-c",
                "user.name=Runroom Test",
                "-c",
                "user.email=runroom@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(["commit", "--quiet", "-m", "initial"])
            .output()
            .expect("commit fixture");
        assert_output_succeeded("Git fixture commit", &commit);
        let config_home = root.join("config");
        let config_path = config_home.join("runroom/config.toml");
        fs::create_dir_all(config_path.parent().expect("config parent"))
            .expect("create config directory");
        fs::write(
            &config_path,
            "[launcher]\nprofile = 'native'\n\n[launcher.profiles.native]\nnetwork = 'host'\n",
        )
        .expect("write native launcher profile");
        Self {
            socket: root.join("runtime/control.sock"),
            workspaces: root.join("workspaces"),
            config_home,
            root,
            repository,
        }
    }
}

impl Drop for GitFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove Git fixture");
    }
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn spawn(socket_path: &Path, workspace_root: &Path, once: bool) -> Self {
        let mut command = isolated_command(env!("CARGO_BIN_EXE_runroom"));
        command
            .arg("daemon")
            .arg("--socket")
            .arg(socket_path)
            .arg("--workspace-root")
            .arg(workspace_root)
            .arg("--state-file")
            .arg(
                workspace_root
                    .parent()
                    .expect("workspace root parent")
                    .join("state/instances.json"),
            )
            .env(
                "XDG_CONFIG_HOME",
                workspace_root
                    .parent()
                    .expect("workspace root parent")
                    .join("config"),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if once {
            command.arg("--once");
        }
        Self(Some(command.spawn().expect("start daemon")))
    }

    fn spawn_with_config(config_home: &Path) -> Self {
        let child = isolated_command(env!("CARGO_BIN_EXE_runroom"))
            .args(["daemon", "--once", "--state-file"])
            .arg(
                config_home
                    .parent()
                    .expect("config home parent")
                    .join("state/instances.json"),
            )
            .env("XDG_CONFIG_HOME", config_home)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start configured daemon");
        Self(Some(child))
    }

    fn wait_for_exit(&mut self) -> Output {
        let deadline = Instant::now() + WAIT_LIMIT;
        while Instant::now() < deadline {
            if self
                .0
                .as_mut()
                .expect("daemon child")
                .try_wait()
                .expect("inspect daemon")
                .is_some()
            {
                return self
                    .0
                    .take()
                    .expect("daemon child")
                    .wait_with_output()
                    .expect("collect daemon output");
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("daemon did not exit after one request");
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
