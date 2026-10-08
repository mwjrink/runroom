# RunRoom

Run an app in a sandbox using bubblewrap and systemd to restrict files. This is little more than a command wrapper with a coordination daemon.

## Philosophy

In general, runroom is intended to be fairly transparent. Is not noticeably slower. It just wraps the harness (and agent within) without altering it. It just adds some guardrails without running a full container.

## Usecase

Run agents/harnesses in a directory and give them read only access to other files. Limit their cpu cores (I set mine to the last physical cores to keep core 0-3 for ui responsiveness) & memory.

## Shared base and default profiles

`[launcher.base]` supplies shared settings to every runnable profile. It is abstract: `--profile base` is rejected, and the base is not a launch target during verification. Inheritance is one level; profiles do not inherit from other profiles.

```toml
runtime = "bubblewrap"

[launcher.base]
network = "none"
environment = ["TERM", "COLORTERM"]
set_environment = { PATH = "/usr/local/bin:/usr/bin:/bin:/cargo/bin" }
bind_mounts = [
  { source = "@workspace", destination = "/workspace", access = "rw" },
  { source = "~/.cargo/bin", destination = "/cargo/bin", access = "ro" },
]

[launcher.profiles.default]
command = "/bin/bash"

[launcher.profiles.omp]
command = "omp"
bind_mounts = [{ executable = "omp", access = "ro" }]
```

Selection precedence is `--profile`, then `[launcher] profile`, then the runnable profile named `default`. The template selects Pi; the optional `default` profile opens Bash. Change `[launcher] profile` to select another default launch.

Profile entries override the base:

- Omitted scalars inherit; explicit values replace, including `false`.
- `environment` combines variable names across layers. `set_environment` merges by variable name, with the profile's value winning. Literal assignments take precedence over host passthrough of the same variable.
- `bind_mounts` merges by normalized destination; a profile mount replaces the base mount at the same destination, including its source, access mode, and `required` flag. Omitted path destinations use the expanded source path; executable mounts without a destination merge by executable name.
- `devices` merges by device path or class.
- Explicit `[]` or `{}` clears that inherited collection. Omitting a collection retains it.
- Specifying `cpu_cores` or `cpu_count` replaces the inherited CPU selection. Supplying both remains invalid; CLI CPU flags replace the effective selection.

The template shares policy, environment, common mounts, and devices in the base; pi and OMP add only their agent-specific settings. Existing configurations without a base continue to work.

### Sandbox PATH

`environment = ["PATH"]` copies the host PATH literally; it does not translate host mount paths. Only directories visible inside the sandbox can supply executables. Prefer a sandbox-specific `set_environment.PATH`, including `/cargo/bin` for the directory mount above. Executable mounts automatically prepend `/opt/runroom/bin`; ordinary directory mounts do not.

`set_environment` does not evaluate shell expressions: `PATH = "$PATH:/cargo/bin"` is a literal string, not an append operation. A profile assignment of PATH replaces the entire base PATH value, just like any other environment variable.

Mounting `~/.cargo/bin` exposes those files, not their external dependencies. Rustup-managed commands such as Cargo also need their Rust toolchain files; the binaries directory alone is insufficient.

## Configuration stages

Launcher policy and host-derived values are separate:

1. `EffectiveLauncherConfig::merge` combines the selected profile/base settings and CLI overrides. `with_launch_mounts` adds parsed CLI grant declarations. This stage validates configuration syntax and policy without reading host environment values, looking up executables, checking source files, or discovering devices. Environment names, literal assignments, symbolic `~`/`@workspace` paths, optional mounts, and device selectors remain declarations.
2. `EffectiveLauncherConfig::resolve` consumes that policy and produces `ResolvedLauncherConfig`: current host environment values, expanded/canonical mount sources, executable locations, concrete device grants, an absolute control socket, and canonical CLI mount arguments for replay.

The boundary is explicit in `src/main.rs::launcher_mode`, before `effective.resolve(...)`. Neither stage contacts the daemon or creates a workspace/scope. Workspace selection/support mounts and project-environment application remain in the existing later launch phases.

For example, `environment = ["PATH"]` is policy; today's host `PATH` value is resolution data. Changing that value does not change the effective configuration. A literal `set_environment.PATH` assignment is part of the effective policy.

Base/profile mount precedence is preserved when symbolic and absolute destinations resolve to the same host path. An optional overriding grant still suppresses its base grant when its source is absent. `verify --offline` performs both stages; it skips only the daemon handshake, not host validation.

### Resume configuration guard

New launches record a versioned SHA-256 fingerprint of the effective policy in their replay arguments. Restores compare it before host resolution or daemon/workspace operations. A matching fingerprint resumes without a prompt.

If the policy changed, Runroom warns and prints an editable normal `runroom --profile … --command '…' --here --no-worktree` command before offering **Resume anyway** or **Cancel**. Only `y` or `yes` proceeds; Enter, EOF, and other answers cancel. With non-interactive stdin or stderr, Runroom exits unsuccessfully after printing the command instead of waiting. Old replay arguments without a fingerprint also require confirmation. Runroom treats the entire harness command as opaque: it never interprets or removes harness resume selectors.

The hash covers runtime/network policy, mount and device declarations, mirrored environment names, literal assignments, project-environment/identity policy, resource limits, and the agent label. It excludes host-derived values, the harness command/session reference, routing flags, socket, workspace name, verbosity, and launch-only mount grants already frozen into replay arguments. CLI overrides are applied before hashing, so replayed overrides still take precedence over changed file defaults.

This detects policy changes, not changes to executables, mounted contents, discovered devices, or mirrored environment values. Accepting a mismatch uses the current configuration and records its fingerprint for subsequent restores; it does not restore a configuration snapshot.

`runroom --help` ends with only the selected existing configuration file location, or `Configuration: none`. Selection uses `$XDG_CONFIG_HOME/runroom/config.toml`, falling back to `$HOME/.config/runroom/config.toml` when `XDG_CONFIG_HOME` is unset or invalid; help does not parse the file.

## Launch-only mounts

```sh
runroom --ro ../docs
runroom --read-only="../docs"
runroom -m "../docs@/docs:ro" --mount "../assets@/assets:rw"
```

`--ro` is an alias for `--read-only`. Both mount the host source read-only at `/BASENAME` inside the sandbox. From `/home/max/project`, `--ro ../docs` resolves the host source `/home/max/docs` and mounts it at `/docs`; the project itself is at `/workspace`. Use `-m "../docs@/reference:ro"` to force another destination.

Sources resolve against the invoking host directory before any workspace or Herdr pane change; quoted `~` paths expand using the host home. Shorthand destinations use the supplied source basename, even when its symlink resolves to a differently named target. Sources without a basename require an explicit destination. Explicit destinations must be absolute (or home-relative with `~`), normalized, and outside protected runtime paths. Mount paths must be UTF-8; destinations cannot contain `@`.

Repeat flags for multiple grants; semicolon-separated lists are not supported. Up to 128 launch grants augment the selected profile without modifying the config. Duplicate destinations, including sources with the same basename, are errors; choose distinct explicit destinations instead. These flags require the Bubblewrap runtime and survive Herdr pane routing.

Read-only denies writes through that mount, not through another writable alias of the same host files. Grants apply only to the new sandbox and its descendants; they do not update already-running instances. Live-session mount updates are a [future enhancement](ENHANCEMENTS.md#live-session-mount-updates).

## Current pane and directory

`runroom --here` runs in the current shell/pane without creating a Herdr tab. Inside Herdr it retains the current pane identity and activity reporting; outside Herdr it runs locally.

`runroom --no-worktree` uses the exact invoking directory instead of selecting a Git workspace and also works outside Git. By itself it opens a tab in the default Herdr session. Combine `--here --no-worktree` to use the current directory in the current shell. `--no-multiplex` has been removed.

## Networking

Select networking in a launcher profile:

```toml
[launcher.profiles.omp]
network = "private"
```

`runroom --network host|none|private` overrides the selected profile for that launch, including Herdr pane routing and cold resume.

| Mode | Host interfaces/listeners visible | Internet and LAN access |
| --- | --- | --- |
| `host` | Yes | Host routing and firewall apply |
| `none` | No | No external connectivity |
| `private` | No | IPv4 forwarding through the host |

`private` requires Bubblewrap, `slirp4netns` on the launcher's host `PATH`, and a usable `/dev/net/tun`. Each launch gets a separate network namespace with `lo` and `tap0`. No host bridge, interface, forwarding sysctl, or firewall rules are created. This is visibility isolation, not a host/LAN access restriction: host-loopback services are reachable through the virtual gateway `10.0.2.2`, while sandbox `127.0.0.1` remains sandbox-local. Forwarding follows the helper's host routing/firewall/VPN policy; application-specific VPN exclusions still matter. IPv6 forwarding is not enabled.

The launcher owns Bubblewrap's startup gate. It starts slirp, waits for readiness, then authorizes and releases the harness; additional pre-start setup belongs before that release. A read-only launch confirmation prevents Bubblewrap's EOF-unblock behavior from executing the harness on setup failure. Setup is bounded to ten seconds, and missing/failed helpers never fall back to host networking. The launcher supervises both processes, preserves harness stdin and exit status, and stops the sandbox if its network helper exits.

Networking helpers live only for their launch; named shared networks are not supported. Strict public-internet-only `outbound` networking remains a [future enhancement](ENHANCEMENTS.md#strict-outbound-networking).

## Herdr activity and conversation resume

For identity-enabled Bubblewrap launches in Herdr, Runroom injects a read-only Pi or OMP companion extension and `/runtime/launch.json`. The companion reports root interactive session activity, questions, completion, failures, and the current conversation file through the restricted Runroom activity socket. OMP additionally reports approvals. Nested/non-interactive sessions do not claim the pane.

The profile must explicitly mount the daemon's activity directory read-only, for example `{ source = "/run/user/1000/runroom/activity", destination = "/runtime/runroom", access = "ro" }` when that is the daemon socket's sibling activity directory. Runroom derives the sandbox socket path from that grant; it does not expose the host Herdr control socket or modify host agent settings/extensions.

The injected extension has a stable, named canonical path so the agent can import it. Its sandbox-only parent directory is read-only; projected host extensions remain visible, and sibling settings/authentication/session directories retain their configured persistence. Herdr's agent label defaults to the foreground executable's basename: profile `coding` running `omp` reports `omp`, not `coding`. This trusted label comes from the daemon-owned launch record, never from an activity reporter. The profile remains Runroom policy metadata; the foreground executable determines whether conversation resume uses Pi or OMP.

On launch, Runroom records the resolved control socket, profile, reporting label, command, network mode, CPU selection, CLI mount grants, and verbosity. The authenticated companion supplies only the current session reference; the daemon builds a durable Herdr `resume_argv` from the saved launch arguments. Switching conversations updates that reference. Pi reopens it with `--session`; OMP uses `--resume=`.

After a Herdr restart or reboot, Herdr restores the pane's host working directory and executes `runroom --restore-args …`. This internal, shell-safe replay uses `--here --no-worktree`, so it re-enters the saved directory without creating another worktree or pane. Existing conversation selectors are replaced with the reported reference; other command arguments and launch overrides remain intact.

An optional `herdr_agent` overrides the full reporting label. It can be set in a profile or inherited from `launcher.base`; it does not change the command or selected profile:

```toml
[launcher.profiles.coding]
command = "omp"
# Optional; omit to report "omp" and preserve stock Herdr resume compatibility.
herdr_agent = "rr:omp"
```

**Warning:** unmodified Herdr can discard the custom resume command when it detects a recognized agent whose canonical label differs from `herdr_agent`. For example, `rr:omp` conflicts with detected `omp` and can break cold resume. Keep the command-based default for transparent integration; no Herdr patch is required. The saved replay still contains `--profile coding`, independently of the displayed agent label.

Requirements and limits:

- Launch Pi/OMP directly as the foreground command, with `identity = "herdr"`. Arbitrary shell wrappers do not provide exact conversation replay.
- Persist and remount the agent's session directory at the same sandbox path; session files must survive the reboot.
- Enable Herdr's `[session] resume_agents_on_restore = true` (its default). Runroom and its daemon must be available when Herdr restores.
- Profile configuration is reloaded, not snapshotted. Changing configuration between launch and resume is **undefined behavior**; keep the profile and grants stable.
- Herdr's custom resume command limit is 8192 bytes, including the encoded replay. Oversized reports are rejected, not truncated.

After upgrading this reporting bridge, restart the daemon and launch fresh sandboxes: restarting the daemon alone does not replace extensions already mounted inside running sandboxes. Already-open sessions without a recorded replay command are not retroactively resumable.

