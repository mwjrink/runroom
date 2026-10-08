# RunRoom

Run an app in a sandbox using bubblewrap and systemd to restrict files. This is little more than a command wrapper with a coordination daemon.

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

| Mode | Host interfaces/listeners visible | Internet and LAN access |
| --- | --- | --- |
| `host` | Yes | Host routing and firewall apply |
| `none` | No | No external connectivity |
| `private` | No | IPv4 forwarding through the host |

`private` requires Bubblewrap, `slirp4netns` on the launcher's host `PATH`, and a usable `/dev/net/tun`. Each launch gets a separate network namespace with `lo` and `tap0`. No host bridge, interface, forwarding sysctl, or firewall rules are created. This is visibility isolation, not a host/LAN access restriction: host-loopback services are reachable through the virtual gateway `10.0.2.2`, while sandbox `127.0.0.1` remains sandbox-local. Forwarding follows the helper's host routing/firewall/VPN policy; application-specific VPN exclusions still matter. IPv6 forwarding is not enabled.

The launcher owns Bubblewrap's startup gate. It starts slirp, waits for readiness, then authorizes and releases the harness; additional pre-start setup belongs before that release. A read-only launch confirmation prevents Bubblewrap's EOF-unblock behavior from executing the harness on setup failure. Setup is bounded to ten seconds, and missing/failed helpers never fall back to host networking. The launcher supervises both processes, preserves harness stdin and exit status, and stops the sandbox if its network helper exits.

Networking helpers live only for their launch; named shared networks are not supported. Strict public-internet-only `outbound` networking remains a [future enhancement](ENHANCEMENTS.md#strict-outbound-networking).

## OMP activity reporting

For identity-enabled Bubblewrap launches in Herdr, Runroom injects a read-only OMP companion extension and `/runtime/launch.json`. The companion reports UI session activity, approvals, questions, completion, and terminal failures through the restricted Runroom activity socket. Nested non-UI sessions do not report pane activity.

The profile must explicitly mount the daemon's activity directory read-only, for example `{ source = "~/.local/share/runroom/activity", destination = "/runtime/runroom", access = "ro" }` when that is the daemon socket's sibling activity directory. Runroom derives the sandbox socket path from that grant; it does not expose the host Herdr control socket or modify host OMP settings/extensions.

The injected extension has a stable, named canonical path so OMP can import it. Its sandbox-only parent directory is read-only; projected host extensions remain visible, and sibling OMP settings/authentication/session directories retain their configured persistence. Forwarded reports use the selected runtime profile as Herdr's agent label, taken from the daemon-owned instance record rather than supplied by the reporting process.

After upgrading this reporting bridge, launch a fresh sandbox: restarting the daemon alone does not replace extensions already mounted inside running sandboxes.

## Client/daemon compatibility

Client and daemon must have exactly the same full Cargo package version, including patch, prerelease, and build suffixes. This is the version printed by `runroom --version`. Rebuild/install both together and restart the daemon after upgrading.

## Daemon executable discovery

The user service searches `~/.local/bin` before `~/.cargo/bin`, then the standard system paths. Named Herdr sessions require a Herdr executable supporting `session list --json`. A daemon discovery failure includes the command's exit status and bounded stderr, so an older executable shadowing the current Herdr installation is visible.

`just update` reinstalls the Runroom binary; it does not replace the installed systemd unit. Existing services with the old search path need a drop-in via `systemctl --user edit runroom.service`:

```ini
[Service]
ExecSearchPath=%h/.local/bin:%h/.cargo/bin:/usr/local/bin:/usr/bin:/bin
```

Then run `systemctl --user daemon-reload` and `systemctl --user restart runroom.service`.
