//! Runroom project environment resolution.

use std::collections::BTreeMap;
use std::env;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::model::ResolvedWorkspace;
use tracing::debug;

const MAX_ENV_FILE_BYTES: u64 = 64 * 1024;

pub const PROJECT_ENV_KEYS: [&str; 12] = [
    "RUNROOM_DATABASE_URL",
    "RUNROOM_MODEL_CACHE_DIR",
    "RUNROOM_POSTGRES_DB",
    "RUNROOM_POSTGRES_PASSWORD",
    "RUNROOM_POSTGRES_PORT",
    "RUNROOM_POSTGRES_USER",
    "RUNROOM_QDRANT_API_KEY",
    "RUNROOM_QDRANT_COLLECTION",
    "RUNROOM_QDRANT_GRPC_PORT",
    "RUNROOM_QDRANT_HTTP_PORT",
    "RUNROOM_QDRANT_URL",
    "RUNROOM_STATE_DIR",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectEnvironment {
    pub values: BTreeMap<String, String>,
    pub global_file: PathBuf,
    pub project_file: PathBuf,
    pub project_root: PathBuf,
}

impl ProjectEnvironment {
    /// Resolve bounded global/project environment layers for a selected workspace.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable HOME, invalid paths, unreadable/nonregular
    /// environment files, malformed values, or invalid derived service URLs.
    #[tracing::instrument(level = "debug", skip_all, name = "resolve_project_environment")]
    pub fn resolve(
        workspace: &ResolvedWorkspace,
        inherited: &BTreeMap<String, String>,
    ) -> io::Result<Self> {
        let home = env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| invalid("HOME is required to resolve the project environment"))?;
        Self::resolve_for_root(workspace.primary_checkout.clone(), &home, inherited)
    }

    /// Resolve environment layers using explicit project and home directories.
    ///
    /// # Errors
    ///
    /// Returns an error for relative paths, unreadable/nonregular or oversized
    /// environment files, malformed values, or invalid derived service URLs.
    #[tracing::instrument(level = "debug", skip_all, name = "resolve_project_environment_root")]
    pub fn resolve_for_root(
        project_root: PathBuf,
        home: &Path,
        inherited: &BTreeMap<String, String>,
    ) -> io::Result<Self> {
        if !project_root.is_absolute() || !home.is_absolute() {
            return Err(invalid("project root and HOME must be absolute"));
        }
        let global_file = home.join(".config/runroom/env");
        let project_file = project_root.join(".runroom.env");
        debug!(
            project_root = %project_root.display(),
            global_file = %global_file.display(),
            project_file = %project_file.display(),
            inherited_count = inherited.len(),
            "loading project environment layers"
        );
        let mut values = defaults(home);
        let default_count = values.len();
        let global_values = read_environment_file(&global_file)?;
        let global_count = global_values.len();
        values.extend(global_values);
        let project_values = read_environment_file(&project_file)?;
        let project_count = project_values.len();
        values.extend(project_values);
        let mut inherited_count = 0;
        for key in PROJECT_ENV_KEYS {
            if let Some(value) = inherited.get(key) {
                values.insert(key.to_owned(), value.clone());
                inherited_count += 1;
            }
        }
        derive_service_urls(&mut values)?;
        debug!(
            default_count,
            global_count,
            project_count,
            inherited_count,
            resolved_count = values.len(),
            "project environment resolved"
        );
        for key in [
            "RUNROOM_DATABASE_URL",
            "RUNROOM_QDRANT_COLLECTION",
            "RUNROOM_QDRANT_URL",
            "RUNROOM_STATE_DIR",
        ] {
            required(&values, key)?;
        }
        Ok(Self {
            values,
            global_file,
            project_file,
            project_root,
        })
    }
}

fn defaults(home: &Path) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "RUNROOM_MODEL_CACHE_DIR".to_owned(),
            home.join(".cache/runroom/transformers")
                .to_string_lossy()
                .into_owned(),
        ),
        ("RUNROOM_POSTGRES_DB".to_owned(), "runroom".to_owned()),
        (
            "RUNROOM_POSTGRES_PASSWORD".to_owned(),
            "runroom_local".to_owned(),
        ),
        ("RUNROOM_POSTGRES_PORT".to_owned(), "54329".to_owned()),
        ("RUNROOM_POSTGRES_USER".to_owned(), "runroom".to_owned()),
        (
            "RUNROOM_QDRANT_COLLECTION".to_owned(),
            "runroom_memories".to_owned(),
        ),
        ("RUNROOM_QDRANT_GRPC_PORT".to_owned(), "6434".to_owned()),
        ("RUNROOM_QDRANT_HTTP_PORT".to_owned(), "6433".to_owned()),
        (
            "RUNROOM_STATE_DIR".to_owned(),
            home.join(".local/state/runroom/workflow")
                .to_string_lossy()
                .into_owned(),
        ),
    ])
}

#[tracing::instrument(
    level = "debug",
    skip_all,
    name = "read_project_environment_file",
    fields(path = %path.display())
)]
fn read_environment_file(path: &Path) -> io::Result<BTreeMap<String, String>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            debug!(path = %path.display(), "project environment file not present");
            return Ok(BTreeMap::new());
        }
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "cannot open Runroom environment file {}: {error}",
                    path.display()
                ),
            ));
        }
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid(format!(
            "Runroom environment file must be a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_ENV_FILE_BYTES {
        return Err(invalid(format!(
            "Runroom environment file is too large: {}",
            path.display()
        )));
    }
    let mut contents = String::new();
    file.take(MAX_ENV_FILE_BYTES + 1)
        .read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_ENV_FILE_BYTES {
        return Err(invalid(format!(
            "Runroom environment file is too large: {}",
            path.display()
        )));
    }
    let parsed = parse_environment(&contents, path)?;
    debug!(
        path = %path.display(),
        variable_count = parsed.len(),
        "loaded project environment file"
    );
    Ok(parsed)
}

#[tracing::instrument(
    level = "debug",
    skip_all,
    name = "parse_project_environment",
    fields(source = %source.display())
)]
fn parse_environment(contents: &str, source: &Path) -> io::Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    for (index, raw_line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let assignment = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, raw_value)) = assignment.split_once('=') else {
            return Err(parse_error(source, line_number, "expected KEY=VALUE"));
        };
        if !PROJECT_ENV_KEYS.contains(&key) {
            return Err(parse_error(
                source,
                line_number,
                format!("unsupported Runroom variable {key}"),
            ));
        }
        let value = unquote(raw_value.trim(), source, line_number)?;
        if value.contains('\0') {
            return Err(parse_error(source, line_number, "value contains NUL"));
        }
        parsed.insert(key.to_owned(), value);
    }
    Ok(parsed)
}

fn unquote(value: &str, source: &Path, line_number: usize) -> io::Result<String> {
    let Some(quote) = value
        .chars()
        .next()
        .filter(|quote| matches!(quote, '\'' | '"'))
    else {
        return Ok(value.to_owned());
    };
    if value.len() < 2 || !value.ends_with(quote) {
        return Err(parse_error(
            source,
            line_number,
            "unterminated quoted value",
        ));
    }
    let inner = &value[1..value.len() - 1];
    if quote == '\'' {
        return Ok(inner.to_owned());
    }
    serde_json::from_str::<String>(value)
        .map_err(|_| parse_error(source, line_number, "invalid double-quoted value"))
}

#[tracing::instrument(level = "debug", skip_all, name = "derive_service_urls")]
fn derive_service_urls(values: &mut BTreeMap<String, String>) -> io::Result<()> {
    let database_derived = !values.contains_key("RUNROOM_DATABASE_URL");
    let qdrant_derived = !values.contains_key("RUNROOM_QDRANT_URL");
    if !values.contains_key("RUNROOM_DATABASE_URL") {
        let user = url_encode(required(values, "RUNROOM_POSTGRES_USER")?);
        let password = url_encode(required(values, "RUNROOM_POSTGRES_PASSWORD")?);
        let port = required(values, "RUNROOM_POSTGRES_PORT")?;
        let database = url_encode(required(values, "RUNROOM_POSTGRES_DB")?);
        values.insert(
            "RUNROOM_DATABASE_URL".to_owned(),
            format!("postgresql://{user}:{password}@127.0.0.1:{port}/{database}"),
        );
    }
    if !values.contains_key("RUNROOM_QDRANT_URL") {
        let port = required(values, "RUNROOM_QDRANT_HTTP_PORT")?;
        values.insert(
            "RUNROOM_QDRANT_URL".to_owned(),
            format!("http://127.0.0.1:{port}"),
        );
    }
    debug!(database_derived, qdrant_derived, "service URLs ready");
    Ok(())
}

fn required<'a>(values: &'a BTreeMap<String, String>, key: &str) -> io::Result<&'a str> {
    values
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid(format!("{key} must not be empty")))
}

fn url_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn parse_error(source: &Path, line_number: usize, message: impl std::fmt::Display) -> io::Error {
    invalid(format!("{}:{line_number}: {message}", source.display()))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::fs::{create_dir_all, remove_dir_all, write};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::model::{ProjectId, WorkspaceOrigin, WorkspaceSelection};

    fn temporary_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "runroom-environment-{}-{nonce}",
            std::process::id()
        ));
        create_dir_all(&path).expect("create temporary directory");
        path
    }

    #[test]
    fn fifo_environment_file_is_rejected_without_a_writer() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let root = temporary_directory();
        let path = root.join(".runroom.env");
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("create environment FIFO");
        let worker_path = path.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            sender
                .send(read_environment_file(&worker_path))
                .expect("send result");
        });
        let result = receiver.recv_timeout(Duration::from_secs(2));
        if matches!(result, Err(mpsc::RecvTimeoutError::Timeout)) {
            // Release a regressed blocking open before joining and cleaning up.
            let _writer = OpenOptions::new()
                .write(true)
                .custom_flags(nix::libc::O_NONBLOCK)
                .open(&path)
                .expect("release blocked FIFO reader");
            worker.join().expect("join blocked reader");
            remove_dir_all(root).expect("remove temporary directory");
            panic!("environment FIFO open blocked without a writer");
        }
        worker.join().expect("join environment reader");
        let error = result
            .expect("receive environment result")
            .expect_err("reject FIFO");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        remove_dir_all(root).expect("remove temporary directory");
    }

    #[test]
    fn precedence_and_derived_urls_are_stable() {
        let root = temporary_directory();
        let home = root.join("home");
        let project = root.join("project");
        create_dir_all(home.join(".config/runroom")).expect("create global config");
        create_dir_all(&project).expect("create project");
        write(
            home.join(".config/runroom/env"),
            "RUNROOM_POSTGRES_PORT=5000\n",
        )
        .expect("write global config");
        write(
            project.join(".runroom.env"),
            "RUNROOM_POSTGRES_PORT=5500\nRUNROOM_QDRANT_HTTP_PORT=7000\n",
        )
        .expect("write project config");
        let inherited = BTreeMap::from([("RUNROOM_POSTGRES_PORT".to_owned(), "6000".to_owned())]);

        let resolved = ProjectEnvironment::resolve_for_root(project, &home, &inherited)
            .expect("resolve environment");

        assert_eq!(resolved.values["RUNROOM_POSTGRES_PORT"], "6000");
        assert_eq!(
            resolved.values["RUNROOM_DATABASE_URL"],
            "postgresql://runroom:runroom_local@127.0.0.1:6000/runroom"
        );
        assert_eq!(
            resolved.values["RUNROOM_QDRANT_URL"],
            "http://127.0.0.1:7000"
        );
        remove_dir_all(root).expect("remove temporary directory");
    }

    #[test]
    fn named_workspace_uses_primary_project_config() {
        let root = temporary_directory();
        let primary = root.join("primary");
        let named = root.join("named");
        let common = primary.join(".git");
        create_dir_all(&common).expect("create common directory");
        create_dir_all(&named).expect("create named workspace");
        write(
            primary.join(".runroom.env"),
            "RUNROOM_QDRANT_COLLECTION=named-workspace-test\n",
        )
        .expect("write project environment");
        let workspace = ResolvedWorkspace {
            project: ProjectId("project".to_owned()),
            primary_checkout: primary.clone(),
            selection: WorkspaceSelection::default(),
            path: named,
            change_name: None,
            origin: WorkspaceOrigin::Existing,
            support_mounts: vec![crate::model::WorkspaceSupportMount {
                source: common.clone(),
                destination: common,
            }],
        };

        let resolved = ProjectEnvironment::resolve(&workspace, &BTreeMap::new())
            .expect("resolve named workspace environment");
        assert_eq!(resolved.project_root, primary);
        assert_eq!(
            resolved
                .values
                .get("RUNROOM_QDRANT_COLLECTION")
                .map(String::as_str),
            Some("named-workspace-test")
        );
        remove_dir_all(root).expect("remove temporary directory");
    }
}
