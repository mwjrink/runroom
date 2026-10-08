use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::io::{BufRead, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use crate::{LauncherArgs, decode_hex};

fn validate_config_hash(value: &str) -> Result<(), &'static str> {
    let Some(digest) = value.strip_prefix("v1:") else {
        return Err("configuration fingerprint must be v1:<64 lowercase hexadecimal digits>");
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("configuration fingerprint must be v1:<64 lowercase hexadecimal digits>");
    }
    Ok(())
}

pub(crate) fn confirm_config_policy(
    args: &LauncherArgs,
    current_hash: &str,
    input: &mut impl BufRead,
    output: &mut impl Write,
    interactive: bool,
) -> Result<(), Box<dyn Error>> {
    if let Some(saved) = &args.config_hash
        && let Err(error) = validate_config_hash(saved)
    {
        writeln!(output, "Invalid saved configuration fingerprint: {error}")?;
        print_recovery_command(args, output)?;
        return Err(error.into());
    }
    let live_continuation = args.resume.is_some() || args.continuation_token.is_some();
    if !(args.restored || live_continuation && args.config_hash.is_some()) {
        return Ok(());
    }
    if args.config_hash.as_deref() == Some(current_hash) {
        return Ok(());
    }
    if let Some(saved) = &args.config_hash {
        writeln!(
            output,
            "Warning: the saved launch configuration differs from the current configuration."
        )?;
        writeln!(
            output,
            "Saved fingerprint: {saved}\nCurrent fingerprint: {current_hash}"
        )?;
    } else {
        writeln!(
            output,
            "Warning: the saved launch configuration fingerprint is unavailable; its policy cannot be compared with the current configuration."
        )?;
        writeln!(output, "Current fingerprint: {current_hash}")?;
    }
    print_recovery_command(args, output)?;
    if !interactive {
        return Err("resume cancelled: configuration confirmation requires interactive stdin and stderr; review and run the command above instead".into());
    }
    write!(
        output,
        "Resume anyway or Cancel? [y/N] (y/yes = Resume anyway; anything else = Cancel): "
    )?;
    output.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    if answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err("resume cancelled".into())
    }
}

fn print_recovery_command(
    args: &LauncherArgs,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    writeln!(
        output,
        "Editable normal launch command (review it before running):"
    )?;
    writeln!(output, "{}", editable_launch_command(args)?)?;
    output.flush()?;
    Ok(())
}

fn shell_quote(word: &OsStr) -> String {
    if let Some(word) = word.to_str() {
        return shell_words::quote(word).into_owned();
    }
    // ANSI-C quoting preserves non-UTF-8 Unix path bytes in Bash and compatible shells.
    let mut quoted = String::from("$'");
    for byte in word.as_bytes() {
        write!(quoted, "\\x{byte:02x}").expect("writing to a string cannot fail");
    }
    quoted.push('\'');
    quoted
}

fn editable_launch_command(args: &LauncherArgs) -> Result<String, Box<dyn Error>> {
    let mut words = vec![OsString::from("runroom")];
    let mut option = |flag: &str, value: OsString| {
        if value.as_bytes().first() == Some(&b'-') {
            let mut combined = OsString::from(flag);
            combined.push("=");
            combined.push(value);
            words.push(combined);
        } else {
            words.push(OsString::from(flag));
            words.push(value);
        }
    };
    let decoded_socket;
    let socket = if let Some(encoded) = &args.socket_bytes {
        let bytes = decode_hex(encoded)?;
        if bytes.contains(&0) {
            return Err("control socket must not contain NUL".into());
        }
        decoded_socket = PathBuf::from(OsString::from_vec(bytes));
        Some(&decoded_socket)
    } else {
        args.socket.as_ref()
    };
    if let Some(socket) = socket {
        option("--socket", socket.as_os_str().to_owned());
    }
    if let Some(name) = &args.name {
        option("--name", name.as_str().into());
    }
    if let Some(profile) = &args.profile {
        option("--profile", profile.as_str().into());
    }
    if let Some(directory) = &args.workspace_directory {
        option("--workspace-directory", directory.as_str().into());
    }
    if let Some(network) = args.network {
        let network = match network {
            crate::config::NetworkFileMode::Host => "host",
            crate::config::NetworkFileMode::None => "none",
            crate::config::NetworkFileMode::Private => "private",
        };
        option("--network", network.into());
    }
    for forward in &args.publish {
        option(
            "--publish",
            format!("{}:{}", forward.host_port, forward.room_port).into(),
        );
    }
    if let Some(cores) = &args.cpu_cores {
        option(
            "--cpu-cores",
            cores
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
                .into(),
        );
    } else if let Some(count) = args.cpu_count {
        option("--cpu-count", count.to_string().into());
    }
    for source in &args.read_only {
        option("--read-only", source.as_os_str().to_owned());
    }
    for mount in &args.mounts {
        option("--mount", mount.as_str().into());
    }
    if let Some(command) = &args.command {
        // This is deliberately one opaque argument. Harness selectors and quoting are untouched.
        option("--command", command.as_str().into());
    }
    if args.here {
        words.push("--here".into());
    }
    if args.no_worktree {
        words.push("--no-worktree".into());
    }
    if args.verbose {
        words.push("--verbose".into());
    }
    Ok(words
        .iter()
        .map(|word| shell_quote(word))
        .collect::<Vec<_>>()
        .join(" "))
}

#[cfg(test)]
mod tests {
    use std::io::{self, BufRead, Cursor, Read};

    use super::*;
    use crate::Cli;
    use clap::Parser;

    const CURRENT: &str = "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SAVED: &str = "v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn restored(hash: Option<&str>) -> LauncherArgs {
        let mut arguments = vec![
            "runroom",
            "--here",
            "--no-worktree",
            "--command",
            "omp --resume 'opaque session' --flag=\"a'b\"",
        ];
        if let Some(hash) = hash {
            arguments.extend(["--config-hash", hash]);
        }
        let mut args = Cli::try_parse_from(arguments).unwrap().launcher;
        args.restored = true;
        args
    }

    struct NoInput;
    impl Read for NoInput {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("matching and noninteractive launches must not read input");
        }
    }
    impl BufRead for NoInput {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            panic!("matching and noninteractive launches must not read input");
        }
        fn consume(&mut self, _: usize) {
            panic!("must not consume input");
        }
    }

    #[test]
    fn matching_restore_and_new_launch_do_not_prompt_or_read() {
        for args in [restored(Some(CURRENT)), LauncherArgs::default()] {
            let mut output = Vec::new();
            confirm_config_policy(&args, CURRENT, &mut NoInput, &mut output, false).unwrap();
            assert_eq!(output, [] as [u8; 0]);
        }
    }

    #[test]
    fn mismatch_and_unknown_policy_require_interactive_confirmation() {
        for args in [restored(Some(SAVED)), restored(None)] {
            let mut output = Vec::new();
            let error = confirm_config_policy(&args, CURRENT, &mut NoInput, &mut output, false)
                .unwrap_err();
            assert!(error.to_string().contains("cancelled"));
            let output = String::from_utf8(output).unwrap();
            let command = output
                .lines()
                .find(|line| line.starts_with("runroom "))
                .unwrap();
            let decoded = shell_words::split(command).unwrap();
            let cli = Cli::try_parse_from(decoded).unwrap();
            assert_eq!(cli.launcher.command, args.command);
            assert!(cli.launcher.config_hash.is_none());
            assert!(!cli.launcher.restored);
            if args.config_hash.is_none() {
                assert!(output.contains("unavailable"));
            }
        }
    }

    #[test]
    fn only_explicit_yes_accepts_drift_or_unknown_policy() {
        for hash in [Some(SAVED), None] {
            let args = restored(hash);
            for answer in ["y\n", "yes\n", "YES\n", " y \n"] {
                let mut output = Vec::new();
                confirm_config_policy(&args, CURRENT, &mut Cursor::new(answer), &mut output, true)
                    .unwrap();
                let output = String::from_utf8(output).unwrap();
                assert!(output.find("runroom ").unwrap() < output.find("[y/N]").unwrap());
            }
            for answer in ["", "\n", "n\n", "cancel\n", "resume\n", "maybe\n"] {
                assert!(
                    confirm_config_policy(
                        &args,
                        CURRENT,
                        &mut Cursor::new(answer),
                        &mut Vec::new(),
                        true
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn live_handoff_checks_saved_stamp_but_unstamped_handoff_does_not_prompt() {
        let mut args = restored(Some(SAVED));
        args.restored = false;
        args.resume = Some("handoff".to_owned());
        assert!(
            confirm_config_policy(&args, CURRENT, &mut NoInput, &mut Vec::new(), false).is_err()
        );
        args.config_hash = None;
        confirm_config_policy(&args, CURRENT, &mut NoInput, &mut Vec::new(), false).unwrap();
    }

    #[test]
    fn editable_command_round_trips_custom_quoting_mounts_and_opaque_selectors() {
        let harness =
            "pi --session '/tmp/a b.jsonl' --resume --foo \"a'b\"; omp --continue $(unchanged)";
        let args = Cli::try_parse_from([
            "runroom",
            "--socket",
            "/tmp/control 'quoted'.sock",
            "--profile",
            "custom profile",
            "--workspace-directory",
            "original project",
            "--name",
            "workspace 'name'",
            "--here",
            "--network",
            "private",
            "--publish",
            "23001:3000",
            "--publish",
            "23002:8080",
            "--cpu-cores",
            "1,3",
            "--read-only",
            "relative path/it's-file",
            "--mount",
            "/host/a 'b'@/dest space:rw",
            "--command",
            harness,
            "--verbose",
            "--herdr-agent",
            "frozen-agent",
            "--config-hash",
            SAVED,
            "--resume",
            "handoff",
            "--continuation-token",
            "route",
        ])
        .unwrap()
        .launcher;
        let command = editable_launch_command(&args).unwrap();
        let decoded = shell_words::split(&command).unwrap();
        let normal = Cli::try_parse_from(decoded).unwrap().launcher;
        assert_eq!(normal.command.as_deref(), Some(harness));
        assert_eq!(normal.socket, args.socket);
        assert_eq!(normal.profile, args.profile);
        assert_eq!(normal.workspace_directory, args.workspace_directory);
        assert_eq!(normal.name, args.name);
        assert_eq!(normal.mounts, args.mounts);
        assert_eq!(normal.read_only, args.read_only);
        assert_eq!(normal.network, args.network);
        assert_eq!(normal.publish, args.publish);
        assert_eq!(normal.cpu_cores, args.cpu_cores);
        assert!(normal.here && normal.verbose);
        assert!(normal.resume.is_none() && normal.continuation_token.is_none());
        assert!(normal.restore_args.is_none() && normal.config_hash.is_none());
        assert!(normal.herdr_agent.is_none());
    }

    #[test]
    fn editable_command_preserves_leading_hyphens_and_empty_opaque_command() {
        for command in ["-opaque --resume", ""] {
            let args = LauncherArgs {
                profile: Some("-profile".to_owned()),
                name: Some("-workspace".to_owned()),
                socket: Some(PathBuf::from("-socket")),
                read_only: vec![PathBuf::from("-file")],
                mounts: vec!["-source@/destination:ro".to_owned()],
                command: Some(command.to_owned()),
                ..LauncherArgs::default()
            };
            let normal = Cli::try_parse_from(
                shell_words::split(&editable_launch_command(&args).unwrap()).unwrap(),
            )
            .unwrap()
            .launcher;
            assert_eq!(normal.profile, args.profile);
            assert_eq!(normal.name, args.name);
            assert_eq!(normal.socket, args.socket);
            assert_eq!(normal.read_only, args.read_only);
            assert_eq!(normal.mounts, args.mounts);
            assert_eq!(normal.command, args.command);
        }
    }

    #[test]
    fn accepted_policy_is_stamped_for_the_next_restore() {
        let file: crate::config::FileConfig = toml::from_str(
            "socket = '/control.sock'\n[launcher]\nprofile = 'coding'\n\
             [launcher.profiles.coding]\ncommand = 'omp --resume original'",
        )
        .unwrap();
        let effective = crate::config::EffectiveLauncherConfig::merge(
            None, None, None, None, None, false, &file,
        )
        .unwrap();
        let current = effective.fingerprint().unwrap();
        let mut args = restored(Some(SAVED));
        args.command = Some("omp --resume original".to_owned());
        confirm_config_policy(
            &args,
            &current,
            &mut Cursor::new("yes\n"),
            &mut Vec::new(),
            true,
        )
        .unwrap();
        let settings = effective.resolve(std::path::Path::new("/"), None).unwrap();
        let replay = crate::canonical_replay_arguments(&settings, &current).unwrap();
        let parsed = Cli::try_parse_from(
            std::iter::once("runroom").chain(replay.iter().map(String::as_str)),
        )
        .unwrap();
        assert_eq!(
            parsed.launcher.config_hash.as_deref(),
            Some(current.as_str())
        );
        let payload =
            serde_json::to_vec(&replay)
                .unwrap()
                .iter()
                .fold(String::new(), |mut payload, byte| {
                    write!(payload, "{byte:02x}").unwrap();
                    payload
                });
        let next = crate::resolve_restore_cli(
            Cli::try_parse_from(["runroom", "--restore-args", &payload]).unwrap(),
        )
        .unwrap();
        confirm_config_policy(
            &next.launcher,
            &current,
            &mut NoInput,
            &mut Vec::new(),
            false,
        )
        .unwrap();
    }

    #[test]
    fn recovery_decodes_byte_preserving_socket_to_a_normal_shell_argument() {
        let args = LauncherArgs {
            socket_bytes: Some("2f746d702fff".to_owned()),
            command: Some("omp --resume original".to_owned()),
            ..LauncherArgs::default()
        };
        let command = editable_launch_command(&args).unwrap();
        assert!(command.contains("--socket "));
        assert!(!command.contains("--socket-bytes"));
        assert!(command.contains("$'\\x2f\\x74\\x6d\\x70\\x2f\\xff'"));
    }

    #[test]
    fn malformed_fingerprints_are_clear_cli_errors() {
        for value in [
            "",
            "v1:",
            "v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "v1:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        ] {
            let args = restored(Some(value));
            let mut output = Vec::new();
            let error = confirm_config_policy(&args, CURRENT, &mut NoInput, &mut output, false)
                .unwrap_err();
            assert!(error.to_string().contains("configuration fingerprint"));
            let output = String::from_utf8(output).unwrap();
            let command = output
                .lines()
                .find(|line| line.starts_with("runroom "))
                .unwrap();
            let normal = Cli::try_parse_from(shell_words::split(command).unwrap()).unwrap();
            assert_eq!(normal.launcher.command, args.command);
            assert!(normal.launcher.config_hash.is_none());
        }
        assert!(validate_config_hash(CURRENT).is_ok());
    }
}
