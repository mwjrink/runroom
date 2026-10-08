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

## Live-session mount updates

Future enhancement: add or change bind mounts in an already-running sandbox without restarting its agent.

Launch-time `--ro` / `--read-only` and `-m` / `--mount` grants are supported, but affect only the new sandbox. Changing configuration or launching a second Bubblewrap process does not update an existing instance's mount namespace.

True live updates need an authenticated instance-targeted control operation and a narrowly authorized helper capable of modifying that instance's mount namespace. Before implementation, define namespace ownership and lifetime, source authorization, destination creation and collisions, read-only alias semantics, concurrency, and whether replacing or removing mounts is supported. Restarting the sandbox or exposing a mount only to a new child must not be presented as a live update.

## Strict outbound networking

Future enhancement: add `network = "outbound"` for public-internet access from an isolated network namespace while denying connections to host services, LAN/private networks, and link-local destinations. This is access isolation, not just hiding host interfaces and sockets.

Use an existing networking stack rather than implementing packet transport. Userspace forwarding alone, including slirp4netns with host-loopback access disabled, does not enforce the complete destination policy. Enforcement must remain outside the harness's authority: evaluate an administrator-authorized host firewall backend or a separately owned rootless guard namespace.

Before implementation, define IPv4/IPv6 policy, host-address and route changes, DNS forwarding and blocked DNS answers, namespace/helper ownership, startup readiness, crash/restart cleanup, and VPN/split-tunnel behavior. Fail closed without falling back to host networking. Verify public HTTPS succeeds while host/LAN access fails, including gateway and DNS bypass attempts.

## Sandboxing

Use as many as possible from bubblewrap:
User namespaces (CLONE_NEWUSER): This hides all but the current uid and gid from the sandbox. You can also change what the value of uid/gid should be in the sandbox.

IPC namespaces (CLONE_NEWIPC): The sandbox will get its own copy of all the different forms of IPCs, like SysV shared memory and semaphores.

PID namespaces (CLONE_NEWPID): The sandbox will not see any processes outside the sandbox. Additionally, bubblewrap will run a trivial pid1 inside your container to handle the requirements of reaping children in the sandbox. This avoids what is known now as the Docker pid 1 problem.

Network namespaces (CLONE_NEWNET): The sandbox will not see the network. Instead it will have its own network namespace with only a loopback device.

UTS namespace (CLONE_NEWUTS): The sandbox will have its own hostname.

Seccomp filters: You can pass in seccomp filters that limit which syscalls can be done in the sandbox. For more information, see Seccomp.
