# Enhancements

## Rotating CPU groups from a shared pool

Future enhancement: allow `cpu_cores` and `cpu_count` together to assign successive groups from the configured CPU pool to successive instances, wrapping around to the start as needed.

Example: `cpu_cores = [0, 1, 2, 3, 4, 5, 6, 7]` and `cpu_count = 2` would assign `[0, 1]`, then `[2, 3]`, then `[4, 5]`, then `[6, 7]`, then `[0, 1]` again. Reused groups remain shared; this does not reserve CPUs exclusively.

Before implementation, define pool ordering, allocation scope (profile or pool), concurrency-safe cursor updates, restart behavior, and handling of incomplete groups or unavailable CPUs.

Current behavior remains mutually exclusive: configure either `cpu_cores` or `cpu_count`. Supplying both is an error; a CLI selection replaces the profile's selection.

## Optional host Unix-user selection

Future enhancement: let a profile choose a real host Unix account for its contents and descendants.

The current backend attaches an existing launcher PID to a transient systemd user scope. Scopes do not spawn the command, and adding a `User=` property does not change its credentials. An unprivileged systemd user manager cannot switch to another host account.

Real per-instance switching needs an administrator-authorized system-service backend or another narrowly privileged launch mechanism. Before implementation, define the allowed target accounts, primary/supplementary groups, workspace and bind-mount permissions, environment/home handling, interactive terminal and exit-status behavior, and activity authentication across UIDs. Preserve CPU and other resource restrictions through that launch path.

Current behavior remains unprivileged: instances execute as the launching host user. No no-op Unix-user option is exposed.

References: [systemd.scope](https://www.freedesktop.org/software/systemd/man/latest/systemd.scope.html), [systemd.exec user identity](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#User=).
