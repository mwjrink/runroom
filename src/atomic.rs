//! One-shot, repository-blind Pi worker launched inside a nested Bubblewrap namespace.

use std::collections::HashSet;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nix::fcntl::{FcntlArg, SealFlag, fcntl};
use nix::sys::memfd::{MFdFlags, memfd_create};
use serde::{Deserialize, Serialize};

const MAX_REQUEST_BYTES: u64 = 512 * 1024;
const MAX_CONTRACT_BYTES: usize = 128 * 1024;
const MAX_INSTRUCTION_BYTES: usize = 32 * 1024;
const MAX_TOTAL_RANGE_BYTES: usize = 256 * 1024;
const MAX_RANGES: usize = 64;
const MAX_ID_BYTES: usize = 128;
const BUBBLEWRAP: &str = "/usr/bin/bwrap";
const NODE: &str = "/usr/bin/node";
const SYSTEM_PROMPT: &str = "You are an atomic implementation worker. You have no tools and no repository access. Implement only the supplied body ranges from the immutable contract. Return exactly one JSON object with keys jobId, replacements, and issues. replacements is an array of {rangeId,lines}; lines is the complete replacement line array for that range. Include every range exactly once. Never emit Markdown fences. If work is incomplete, put a source comment using commentPrefix inside the affected replacement and repeat the issue in issues. Do not alter or invent signatures, imports, globals, types, or declarations.";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AtomicWorkerRequest {
    version: u8,
    job_id: String,
    model: String,
    contract: String,
    instruction: String,
    comment_prefix: String,
    ranges: Vec<AtomicWorkerRange>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AtomicWorkerRange {
    id: String,
    start: u32,
    end: u32,
    content_sha256: String,
    content: String,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn bounded_text(value: &str, maximum: usize, label: &str) -> io::Result<()> {
    if value.is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(invalid(format!("invalid atomic worker {label}")));
    }
    Ok(())
}

fn validate_request(request: &AtomicWorkerRequest) -> io::Result<()> {
    if request.version != 1 {
        return Err(invalid("unsupported atomic worker request version"));
    }
    bounded_text(&request.job_id, MAX_ID_BYTES, "job ID")?;
    bounded_text(&request.model, 255, "model")?;
    bounded_text(&request.contract, MAX_CONTRACT_BYTES, "contract")?;
    bounded_text(&request.instruction, MAX_INSTRUCTION_BYTES, "instruction")?;
    bounded_text(&request.comment_prefix, 8, "comment prefix")?;
    if request.ranges.is_empty() || request.ranges.len() > MAX_RANGES {
        return Err(invalid("invalid atomic worker range count"));
    }

    let mut ids = HashSet::with_capacity(request.ranges.len());
    let mut total = 0usize;
    let mut previous_end = 0u32;
    for range in &request.ranges {
        bounded_text(&range.id, MAX_ID_BYTES, "range ID")?;
        if !ids.insert(&range.id) {
            return Err(invalid("duplicate atomic worker range ID"));
        }
        if range.start == 0 || range.end < range.start || range.start <= previous_end {
            return Err(invalid(
                "atomic worker ranges must be sorted and non-overlapping",
            ));
        }
        if range.content_sha256.len() != 64
            || !range
                .content_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid("invalid atomic worker range hash"));
        }
        total = total
            .checked_add(range.content.len())
            .ok_or_else(|| invalid("atomic worker ranges exceed maximum size"))?;
        previous_end = range.end;
    }
    if total > MAX_TOTAL_RANGE_BYTES {
        return Err(invalid("atomic worker ranges exceed maximum size"));
    }
    Ok(())
}

fn load_request(path: &Path) -> io::Result<AtomicWorkerRequest> {
    if !path.is_absolute() {
        return Err(invalid("atomic worker request path must be absolute"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() > MAX_REQUEST_BYTES
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != nix::unistd::Uid::current().as_raw()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "atomic worker request must be a bounded private regular file",
        ));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| invalid("atomic worker request exceeds addressable memory"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_REQUEST_BYTES + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_REQUEST_BYTES {
        return Err(invalid("atomic worker request exceeds maximum size"));
    }
    let request: AtomicWorkerRequest = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("invalid atomic worker request: {error}")))?;
    validate_request(&request)?;
    Ok(request)
}

fn prompt_input(request: &AtomicWorkerRequest) -> io::Result<File> {
    let descriptor = memfd_create(
        "runroom-atomic-request.json",
        MFdFlags::MFD_ALLOW_SEALING | MFdFlags::MFD_CLOEXEC,
    )
    .map_err(io::Error::other)?;
    let mut file = File::from(descriptor);
    file.set_permissions(std::fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer(&mut file, request)
        .map_err(|error| invalid(format!("cannot encode atomic worker prompt: {error}")))?;
    fcntl(
        &file,
        FcntlArg::F_ADD_SEALS(
            SealFlag::F_SEAL_WRITE
                | SealFlag::F_SEAL_GROW
                | SealFlag::F_SEAL_SHRINK
                | SealFlag::F_SEAL_SEAL,
        ),
    )
    .map_err(io::Error::other)?;

    // Reopen our own immutable descriptor, not the caller's mutable request path.
    // Pi consumes non-TTY stdin as its initial prompt; no large argv or @file wrapper.
    OpenOptions::new()
        .read(true)
        .open(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn push_pair(arguments: &mut Vec<String>, flag: &str, value: impl AsRef<Path>) {
    arguments.push(flag.to_owned());
    arguments.push(value.as_ref().as_os_str().to_string_lossy().into_owned());
}

fn push_triplet(
    arguments: &mut Vec<String>,
    flag: &str,
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) {
    arguments.push(flag.to_owned());
    arguments.push(source.as_ref().as_os_str().to_string_lossy().into_owned());
    arguments.push(
        destination
            .as_ref()
            .as_os_str()
            .to_string_lossy()
            .into_owned(),
    );
}

fn add_directory(arguments: &mut Vec<String>, path: impl AsRef<Path>) {
    push_pair(arguments, "--dir", path);
}

fn atomic_arguments(request: &AtomicWorkerRequest, home: &Path) -> io::Result<Vec<String>> {
    let pi_package = home.join(".local/lib/node_modules/@earendil-works/pi-coding-agent");
    let pi_cli = pi_package.join("dist/cli.js");
    let global_modules = home.join(".local/lib/node_modules");
    let agent_dir = home.join(".pi/agent");
    let auth = agent_dir.join("auth.json");
    if !pi_cli.is_file() || !global_modules.is_dir() || !auth.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "atomic worker Pi runtime or authentication is unavailable",
        ));
    }

    let mut arguments = vec![
        "--unshare-user".to_owned(),
        "--unshare-ipc".to_owned(),
        "--unshare-pid".to_owned(),
        "--unshare-uts".to_owned(),
        "--die-with-parent".to_owned(),
        "--clearenv".to_owned(),
    ];
    push_triplet(&mut arguments, "--ro-bind", "/usr", "/usr");
    push_triplet(&mut arguments, "--ro-bind", "/etc", "/etc");
    push_triplet(&mut arguments, "--symlink", "usr/bin", "/bin");
    push_triplet(&mut arguments, "--symlink", "usr/bin", "/sbin");
    push_triplet(&mut arguments, "--symlink", "usr/lib", "/lib");
    push_triplet(&mut arguments, "--symlink", "usr/lib", "/lib64");
    push_pair(&mut arguments, "--proc", "/proc");
    push_pair(&mut arguments, "--dev", "/dev");
    push_pair(&mut arguments, "--tmpfs", "/tmp");
    push_pair(&mut arguments, "--tmpfs", "/run");
    push_pair(&mut arguments, "--tmpfs", "/var/tmp");
    for resolver in [
        "/run/systemd/resolve/stub-resolv.conf",
        "/run/systemd/resolve/resolv.conf",
    ] {
        push_triplet(&mut arguments, "--ro-bind-try", resolver, resolver);
    }

    add_directory(&mut arguments, home);
    add_directory(&mut arguments, home.join(".local"));
    add_directory(&mut arguments, home.join(".local/lib"));
    push_triplet(
        &mut arguments,
        "--ro-bind",
        &global_modules,
        &global_modules,
    );
    add_directory(&mut arguments, home.join(".pi"));
    add_directory(&mut arguments, &agent_dir);
    push_triplet(&mut arguments, "--ro-bind", &auth, &auth);
    let models_store = agent_dir.join("models-store.json");
    if models_store.is_file() {
        push_triplet(&mut arguments, "--ro-bind", &models_store, &models_store);
    }

    push_triplet(&mut arguments, "--setenv", "HOME", home);
    push_triplet(&mut arguments, "--setenv", "PATH", "/usr/bin");
    push_triplet(&mut arguments, "--setenv", "LANG", "C.UTF-8");
    push_pair(&mut arguments, "--chdir", "/tmp");
    arguments.push("--".to_owned());
    arguments.push(NODE.to_owned());
    arguments.push(pi_cli.to_string_lossy().into_owned());
    arguments.extend([
        "--print".to_owned(),
        "--no-session".to_owned(),
        "--no-extensions".to_owned(),
        "--no-skills".to_owned(),
        "--no-context-files".to_owned(),
        "--no-builtin-tools".to_owned(),
        "--thinking".to_owned(),
        "off".to_owned(),
        "--model".to_owned(),
        request.model.clone(),
        "--system-prompt".to_owned(),
        SYSTEM_PROMPT.to_owned(),
        // The validated JSON prompt is supplied through sealed, read-only stdin.
    ]);
    Ok(arguments)
}

/// Replace the current process with one repository-blind, one-turn Pi worker.
///
/// # Errors
///
/// Returns an error when the private request is malformed, required Pi runtime
/// files are unavailable, or Bubblewrap cannot replace the current process.
pub fn run_atomic_worker(request_path: &Path) -> io::Result<()> {
    let request = load_request(request_path)?;
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| invalid("HOME is required for atomic worker authentication"))?;
    let arguments = atomic_arguments(&request, &home)?;
    let input = prompt_input(&request)?;
    let error = Command::new(BUBBLEWRAP)
        .args(arguments)
        .stdin(Stdio::from(input))
        .exec();
    Err(io::Error::new(
        error.kind(),
        format!("cannot execute atomic worker Bubblewrap: {error}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct RequestFile(PathBuf);

    impl RequestFile {
        fn new(request: &AtomicWorkerRequest) -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let path = env::temp_dir().join(format!(
                "runroom-atomic-request-test-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .expect("create private request");
            serde_json::to_writer(&mut file, request).expect("write request");
            Self(path)
        }
    }

    impl Drop for RequestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn request() -> AtomicWorkerRequest {
        AtomicWorkerRequest {
            version: 1,
            job_id: "job-a".to_owned(),
            model: "openai-codex/gpt-5.6-sol".to_owned(),
            contract: "fn parse(input: &str) -> Result<Value, Error>;".to_owned(),
            instruction: "Implement the parser body.".to_owned(),
            comment_prefix: "//".to_owned(),
            ranges: vec![AtomicWorkerRange {
                id: "parse-body".to_owned(),
                start: 10,
                end: 12,
                content_sha256: "a".repeat(64),
                content: "    todo!()".to_owned(),
            }],
        }
    }

    #[test]
    fn validates_sorted_content_bound_ranges() {
        validate_request(&request()).expect("valid request");
        let mut invalid = request();
        invalid.ranges.push(AtomicWorkerRange {
            id: "earlier".to_owned(),
            start: 9,
            end: 9,
            content_sha256: "b".repeat(64),
            content: "x".to_owned(),
        });
        assert!(validate_request(&invalid).is_err());
    }

    #[test]
    fn maximum_escaped_request_keeps_validated_content_after_source_changes() {
        let mut expected = request();
        let escaped = "\n\r\t\\\"☃".repeat(8192);
        expected.contract = escaped.clone();
        expected
            .contract
            .push_str(&"c".repeat(MAX_CONTRACT_BYTES - escaped.len()));
        expected.instruction = "i".repeat(MAX_INSTRUCTION_BYTES);
        expected.ranges[0].content = escaped;
        let range_length = expected.ranges[0].content.len();
        expected.ranges[0]
            .content
            .push_str(&"r".repeat(MAX_TOTAL_RANGE_BYTES - range_length));

        let source = RequestFile::new(&expected);
        let validated = load_request(&source.0).expect("maximum escaped valid request");
        // A caller can replace the source after validation; it must never become the prompt.
        std::fs::write(&source.0, b"unvalidated replacement").expect("replace source");
        let mut input = prompt_input(&validated).expect("prepare immutable prompt");
        let actual: serde_json::Value =
            serde_json::from_reader(&mut input).expect("read complete prompt JSON");
        assert_eq!(
            actual,
            serde_json::to_value(&expected).expect("expected request JSON")
        );
    }

    #[test]
    fn prompt_is_read_only_and_cannot_be_mutated_through_another_descriptor() {
        let expected = request();
        let mut input = prompt_input(&expected).expect("prepare immutable prompt");
        assert!(input.write_all(b"tamper").is_err());
        assert!(input.set_len(0).is_err());

        // Even changing inode permissions cannot bypass the sealed snapshot.
        input
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .expect("change test snapshot mode");
        let mut writable = OpenOptions::new()
            .write(true)
            .open(format!("/proc/self/fd/{}", input.as_raw_fd()))
            .expect("reopen test snapshot");
        assert!(writable.write_all(b"tamper").is_err());
        assert!(writable.set_len(0).is_err());
        let actual: serde_json::Value =
            serde_json::from_reader(input).expect("read unchanged prompt JSON");
        assert_eq!(
            actual,
            serde_json::to_value(&expected).expect("expected request JSON")
        );
    }
}
