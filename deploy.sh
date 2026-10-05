#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly MANIFEST="$SCRIPT_DIR/Cargo.toml"
readonly CONFIG_TEMPLATE="$SCRIPT_DIR/config.toml.in"
readonly SERVICE_TEMPLATE="$SCRIPT_DIR/runroom.service.in"
readonly MODE="${1:-install}"

fail() {
  printf 'runroom deploy: %s\n' "$*" >&2
  if [[ ${rollback_armed:-false} == true ]] && declare -F rollback_deployment >/dev/null; then
    rollback_deployment 1
  fi
  exit 1
}

usage() {
  printf 'Usage: %s {install|update|verify}\n' "${0##*/}" >&2
  exit 2
}

[[ $# -le 1 ]] || usage
case "$MODE" in
  install|update|verify) ;;
  *) usage ;;
esac

[[ ${EUID:-$(id -u)} -ne 0 ]] || fail "run as the target user, not root"
[[ -n ${HOME:-} && -d $HOME && $HOME == /* ]] || fail "HOME must name an existing absolute directory"
[[ $HOME =~ ^/[A-Za-z0-9._/+,:=-]+$ ]] || fail "HOME contains characters unsupported by the deployment templates"
[[ ${UID:-} =~ ^[0-9]+$ ]] || fail "UID is unavailable"

readonly USER_UID="$UID"
readonly RUNTIME_DIR="/run/user/$USER_UID"
readonly SOCKET_PATH="$RUNTIME_DIR/runroom/control.sock"
readonly ACTIVITY_SOCKET_PATH="$RUNTIME_DIR/runroom/activity/status.sock"
readonly BINARY_PATH="$HOME/.local/bin/runroom"
readonly LEGACY_BINARY_PATH="$HOME/.cargo/bin/runroom"
readonly CONFIG_PATH="$HOME/.config/runroom/config.toml"
readonly STATE_DIR="$HOME/.local/state/runroom"
readonly WORKFLOW_STATE_DIR="$STATE_DIR/workflow"
readonly CACHE_DIR="$HOME/.cache/runroom"
readonly SERVICE_PATH="$HOME/.config/systemd/user/runroom.service"

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

validate_rendered() {
  local path=$1
  local placeholder
  for placeholder in '@HOME@' '@UID@' '@RUNROOM_BINARY@'; do
    if grep -Fq -- "$placeholder" "$path"; then
      fail "unresolved placeholder $placeholder in $path"
    fi
  done
}

render_config() {
  local destination=$1
  local runroom_binary=$2
  local line
  : >"$destination"
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line//@HOME@/$HOME}
    line=${line//@UID@/$USER_UID}
    line=${line//@RUNROOM_BINARY@/$runroom_binary}
    printf '%s\n' "$line" >>"$destination"
  done <"$CONFIG_TEMPLATE"
  validate_rendered "$destination"
}

render_service() {
  local destination=$1
  local line
  : >"$destination"
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line//@RUNROOM_BINARY@/$BINARY_PATH}
    printf '%s\n' "$line" >>"$destination"
  done <"$SERVICE_TEMPLATE"
  validate_rendered "$destination"
}

validate_profile_contract() {
  local config=$1
  grep -Fqx -- '[launcher.profiles.pi]' "$config" || fail "$config does not define the pi profile"
  grep -Fqx -- '[launcher.profiles.omp]' "$config" || fail "$config does not define the omp profile"
  grep -Fqx -- 'project_environment = true' "$config" ||
    fail "$config does not enable native Runroom project environment resolution"
  if grep -Fq -- 'environment_provider' "$config"; then
    fail "$config still configures an external environment provider"
  fi
  grep -Fqx -- "  { source = \"$RUNTIME_DIR/runroom/activity\", destination = \"/runtime/runroom\", access = \"ro\" }," "$config" ||
    fail "$config does not isolate the Runroom activity socket from the control socket"
  if grep -Eq -- 'HERDR_SOCKET_PATH|DBUS_SESSION_BUS_ADDRESS|/herdr\.sock|/bin/herdr|/run/user/[0-9]+/bus' "$config"; then
    fail "$config grants a legacy Herdr or D-Bus capability"
  fi
}

validate_offline() {
  local binary=$1
  local config=$2
  "$binary" verify --config "$config" --offline
}

validate_live() {
  local binary=$1
  local config=$2
  validate_profile_contract "$config"
  validate_offline "$binary" "$config"
  "$binary" verify --config "$config"
}

atomic_install() {
  local source=$1
  local destination=$2
  local mode=$3
  local parent=${destination%/*}
  local pending
  mkdir -p -- "$parent"
  pending=$(mktemp -- "$parent/.runroom-install.XXXXXXXX")
  if ! install -m "$mode" -- "$source" "$pending"; then
    rm -f -- "$pending"
    return 1
  fi
  if ! mv -f -- "$pending" "$destination"; then
    rm -f -- "$pending"
    return 1
  fi
}

ensure_directory() {
  local path=$1
  if [[ -e $path || -L $path ]]; then
    [[ -d $path && ! -L $path ]] || fail "managed directory path is invalid: $path"
    return
  fi
  install -d -m 0700 -- "$path"
}

backup_managed() {
  local path=$1
  local backup=$2
  if [[ ! -e $path && ! -L $path ]]; then
    return 1
  fi
  [[ ! -e $backup && ! -L $backup ]] || fail "rollback path already exists: $backup"
  if [[ -L $path ]]; then
    ln -s -- "$(readlink -- "$path")" "$backup"
  else
    [[ -f $path ]] || fail "managed path is not a regular file: $path"
    ln -- "$path" "$backup"
  fi
}

restore_managed() {
  local path=$1
  local backup=$2
  local existed=$3
  if [[ $existed == true ]]; then
    if [[ -e $backup && -e $path && $backup -ef $path ]]; then
      rm -f -- "$backup"
    elif [[ -e $backup ]]; then
      mv -f -- "$backup" "$path"
    fi
  else
    rm -f -- "$path" "$backup"
  fi
}

rollback_deployment() {
  local status=${1:-1}
  rollback_armed=false
  trap - ERR HUP INT TERM
  set +e
  systemctl --user stop runroom.service
  restore_managed "$BINARY_PATH" "$BINARY_BACKUP" "${had_binary:-false}"
  restore_managed "$CONFIG_PATH" "$CONFIG_BACKUP" "${had_config:-false}"
  restore_managed "$SERVICE_PATH" "$SERVICE_BACKUP" "${had_service:-false}"
  systemctl --user daemon-reload
  systemctl --user reset-failed runroom.service
  if [[ ${service_was_enabled:-false} == true ]]; then
    systemctl --user enable runroom.service
  else
    systemctl --user disable runroom.service
  fi
  if [[ ${service_was_active:-false} == true ]]; then
    systemctl --user restart runroom.service
  else
    systemctl --user stop runroom.service
  fi
  printf 'runroom deploy: deployment failed; previous installation restored\n' >&2
  exit "$status"
}

wait_for_socket() {
  local attempt
  for ((attempt = 0; attempt < 100; attempt += 1)); do
    if [[ -S $SOCKET_PATH && -S $ACTIVITY_SOCKET_PATH ]] &&
      "$BINARY_PATH" verify --config "$CONFIG_PATH" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  fail "service did not become responsive at $SOCKET_PATH and $ACTIVITY_SOCKET_PATH"
}

for command in grep; do
  require_command "$command"
done

if [[ $MODE == verify ]]; then
  [[ -x $BINARY_PATH ]] || fail "installed binary not found: $BINARY_PATH"
  [[ -f $CONFIG_PATH ]] || fail "installed config not found: $CONFIG_PATH"
  [[ -d $WORKFLOW_STATE_DIR && ! -L $WORKFLOW_STATE_DIR ]] ||
    fail "installed workflow state root is missing or invalid: $WORKFLOW_STATE_DIR"
  [[ -d $CACHE_DIR && ! -L $CACHE_DIR ]] ||
    fail "installed cache root is missing or invalid: $CACHE_DIR"
  validate_live "$BINARY_PATH" "$CONFIG_PATH"
  printf 'Runroom verification succeeded for pi and omp profiles.\n'
  exit 0
fi

for command in cargo install ln mktemp mv readlink rm systemctl sleep; do
  require_command "$command"
done
ensure_directory "$RUNTIME_DIR/runroom"
ensure_directory "$RUNTIME_DIR/runroom/activity"
ensure_directory "$STATE_DIR"
ensure_directory "$WORKFLOW_STATE_DIR"
ensure_directory "$CACHE_DIR"
ensure_directory "$HOME/.local/share/runroom/workspaces"
[[ -f $MANIFEST && -f $CONFIG_TEMPLATE && -f $SERVICE_TEMPLATE ]] ||
  fail "deployment templates are incomplete"
if [[ -e $LEGACY_BINARY_PATH || -L $LEGACY_BINARY_PATH ]]; then
  [[ -f $LEGACY_BINARY_PATH && ! -L $LEGACY_BINARY_PATH ]] ||
    fail "legacy Runroom path is not a regular file: $LEGACY_BINARY_PATH"
fi
if [[ $MODE == update ]]; then
  [[ -x $BINARY_PATH && -f $CONFIG_PATH && -f $SERVICE_PATH ]] ||
    fail "update requires an existing installation; use install"
fi

stage=$(mktemp -d -- "${TMPDIR:-/tmp}/runroom-deploy.XXXXXXXX")
cleanup() {
  rm -rf -- "$stage"
}
trap cleanup EXIT

readonly CANDIDATE_TARGET="$stage/target"
readonly CANDIDATE_BINARY="$CANDIDATE_TARGET/release/runroom"
readonly CANDIDATE_CONFIG="$stage/config.toml"
readonly FINAL_CONFIG="$stage/config.final.toml"
readonly CANDIDATE_SERVICE="$stage/runroom.service"

CARGO_TARGET_DIR="$CANDIDATE_TARGET" cargo build --release --locked --manifest-path "$MANIFEST"
[[ -x $CANDIDATE_BINARY ]] || fail "locked build did not produce $CANDIDATE_BINARY"

render_config "$CANDIDATE_CONFIG" "$CANDIDATE_BINARY"
render_config "$FINAL_CONFIG" "$BINARY_PATH"
render_service "$CANDIDATE_SERVICE"
validate_profile_contract "$CANDIDATE_CONFIG"
validate_offline "$CANDIDATE_BINARY" "$CANDIDATE_CONFIG"

readonly BINARY_BACKUP="$BINARY_PATH.runroom-backup.$$"
readonly CONFIG_BACKUP="$CONFIG_PATH.runroom-backup.$$"
readonly SERVICE_BACKUP="$SERVICE_PATH.runroom-backup.$$"
for managed_path in "$BINARY_PATH" "$CONFIG_PATH" "$SERVICE_PATH"; do
  if [[ -e $managed_path || -L $managed_path ]]; then
    if [[ $managed_path == "$BINARY_PATH" && -L $managed_path ]]; then
      [[ $(readlink -- "$managed_path") == "$LEGACY_BINARY_PATH" && -x $managed_path ]] ||
        fail "installed Runroom symlink is not the recognized legacy deployment"
    else
      [[ -f $managed_path && ! -L $managed_path ]] ||
        fail "managed path is not a regular file: $managed_path"
    fi
  fi
done
for backup_path in "$BINARY_BACKUP" "$CONFIG_BACKUP" "$SERVICE_BACKUP"; do
  [[ ! -e $backup_path && ! -L $backup_path ]] ||
    fail "rollback path already exists: $backup_path"
done


service_was_enabled=false
service_was_active=false
if systemctl --user is-enabled --quiet runroom.service; then
  service_was_enabled=true
fi
if systemctl --user is-active --quiet runroom.service; then
  service_was_active=true
fi

had_binary=false
had_config=false
had_service=false
rollback_armed=true
trap 'rollback_deployment $?' ERR
trap 'rollback_deployment 129' HUP
trap 'rollback_deployment 130' INT
trap 'rollback_deployment 143' TERM

if [[ -e $BINARY_PATH || -L $BINARY_PATH ]]; then
  had_binary=true
  backup_managed "$BINARY_PATH" "$BINARY_BACKUP"
fi
if [[ -e $CONFIG_PATH || -L $CONFIG_PATH ]]; then
  had_config=true
  backup_managed "$CONFIG_PATH" "$CONFIG_BACKUP"
fi
if [[ -e $SERVICE_PATH || -L $SERVICE_PATH ]]; then
  had_service=true
  backup_managed "$SERVICE_PATH" "$SERVICE_BACKUP"
fi

atomic_install "$CANDIDATE_BINARY" "$BINARY_PATH" 0755
atomic_install "$FINAL_CONFIG" "$CONFIG_PATH" 0600
atomic_install "$CANDIDATE_SERVICE" "$SERVICE_PATH" 0644

systemctl --user daemon-reload
systemctl --user reset-failed runroom.service
systemctl --user enable runroom.service
systemctl --user restart runroom.service
wait_for_socket
validate_live "$BINARY_PATH" "$CONFIG_PATH"

rollback_armed=false
trap - ERR HUP INT TERM
rm -f -- "$BINARY_BACKUP" "$CONFIG_BACKUP" "$SERVICE_BACKUP"
rm -f -- "$LEGACY_BINARY_PATH"
printf 'Runroom %s succeeded; pi and omp profiles verified.\n' "$MODE"
