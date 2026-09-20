#!/usr/bin/env bash

# Signal-safe supervision for Docker operations whose caller owns a host flock
# or post-run evidence/topology cleanup. Docker closes unrelated inherited
# descriptors, so the lock-owning shell stays alive and binds lifecycle work to
# daemon-issued, full object IDs. Ordinary control-plane calls have a
# three-second bound; setup metadata, target-bound waits and attached
# run/build operations use their separately declared runtime envelopes.

_QCSD_DOCKER_API_TIMEOUT_SECONDS=3
# Evidence/setup `docker info` reads intentionally include client plugins.
# They are one-shot reads outside the terminal-signal control path.
_QCSD_DOCKER_METADATA_TIMEOUT_SECONDS=10
# BuildKit export can briefly saturate the daemon after the build process has
# finished. Only terminal build retirement gets this longer read-only proof;
# ordinary API calls and run/signal retirement keep their existing bounds.
_QCSD_DOCKER_BUILD_RETIREMENT_IDENTITY_TIMEOUT_SECONDS=10
# A read-only daemon-identity proof may be retried once when the first bounded
# observation is unavailable. Each attempt has its purpose-specific service
# bound. A returned mismatch is terminal and mutating
# Docker requests remain strictly one-shot.
_QCSD_DOCKER_DAEMON_IDENTITY_ATTEMPTS=2
# Handoff retirement is allowed one fresh read-only exact-presence proof after
# a transient unknown result.  Present and structurally ambiguous observations
# are terminal; neither is normalised into a retryable state at this boundary.
_QCSD_DOCKER_HANDOFF_ABSENCE_ATTEMPTS=2
_QCSD_DOCKER_GRACE_SECONDS=40
# Conservative interrupted delayed-create path at individual bounds: initial
# 6-second resolution, 12-second publication retry, 3-second signal, one
# 40-second graceful wait, 18-second post-client resolution, and 12 seconds for
# force-remove/absence proof total 91 seconds. The 120-second envelope leaves
# 29 seconds for local polling/reaping; acquisition-watch grants 135 seconds.
_QCSD_DOCKER_SUPERVISOR_SIGNAL_ENVELOPE_SECONDS=120
_QCSD_DOCKER_SUPERVISOR_LABEL_KEY="org.qcsd.supervisor.instance"
_QCSD_DOCKER_REAP_POLLS=10
_QCSD_DOCKER_REAP_DELAY_SECONDS=0.1
_QCSD_DOCKER_BUILD_GRACE_POLLS=100
_QCSD_DOCKER_BUILD_GRACE_DELAY_SECONDS=0.1
# Scope queries are local user-manager calls. Keeping each attempt to one
# second bounds both the pre-kill and post-kill two-snapshot proofs well inside
# the supervisor's 120-second terminal-signal envelope even when systemd is
# unresponsive.
_QCSD_DOCKER_SCOPE_API_TIMEOUT_SECONDS=1
_QCSD_DOCKER_SCOPE_SETTLE_POLLS=20
_QCSD_DOCKER_SCOPE_SETTLE_DELAY_SECONDS=0.05
_QCSD_DOCKER_LIFECYCLE_SCHEMA=1
_QCSD_DOCKER_LIFECYCLE_PARENT=/var/tmp
_QCSD_MAX_LIFECYCLE_OPERATIONS=7
# One historical source transition is admissible solely to retire terminal
# v57 HANDOFF ledgers that were written by the immediately preceding committed
# helper.  These pins identify the predecessor bytes, the commit that first
# carried them, the exact checkout that ran v57, and that checkout's helper
# blob.  They are deliberately not configurable: any future transition needs
# an independently reviewed, explicit successor rule.
_QCSD_DOCKER_V57_PREDECESSOR_SHA256=969f69faa531730f13204bbd0556a2d877b1cfd68d5594d80bff4caa05df6d8b
_QCSD_DOCKER_V57_PREDECESSOR_BLOB=958d3569aea861380abc4b7152ef29987602e2a8
_QCSD_DOCKER_V57_PREDECESSOR_COMMIT=d9683ccdfd9270da123dc2b008df5df4f60c0385
_QCSD_DOCKER_V57_CHECKOUT_COMMIT=b7811dab7124ffdde113fae111ef8bab4810ebba
_QCSD_DOCKER_V57_HELPER_PATH=tools/docker_signal_supervisor.sh
readonly _QCSD_DOCKER_V57_PREDECESSOR_SHA256 \
  _QCSD_DOCKER_V57_PREDECESSOR_BLOB \
  _QCSD_DOCKER_V57_PREDECESSOR_COMMIT \
  _QCSD_DOCKER_V57_CHECKOUT_COMMIT _QCSD_DOCKER_V57_HELPER_PATH

_qcsd_require_user_cgroup_manager() {
  command -v systemd-run >/dev/null 2>&1 &&
    command -v systemctl >/dev/null 2>&1 &&
    command -v timeout >/dev/null 2>&1 &&
    command -v setsid >/dev/null 2>&1 &&
    [[ "$(stat -fc '%T' /sys/fs/cgroup 2>/dev/null)" == "cgroup2fs" ]]
}

_qcsd_restore_signal_trap() {
  local saved="$1"
  local signal="$2"
  if [[ -n "${saved}" ]]; then
    eval "${saved}"
  else
    trap - "${signal}"
  fi
}

# Keep the asynchronously parsed trap action deliberately trivial. Bash 5.2
# can corrupt its recursive command-substitution parser when it dispatches any
# catchable trap while one simple command has multiple `$(...)` expansions
# (reported as an unterminated `)' in the trap).  The production supervisor
# therefore has a second invariant: while these traps are live, obtain each
# external value in its own assignment before combining or comparing values.
# The function body was parsed when this helper was sourced, and Bash's dynamic
# scoping lets it update the supervisor's local latch variables.
_qcsd_latch_requested_signal() {
  local signal_name="$1"
  local signal_status="$2"
  if [[ "${requested_status}" == "0" ]]; then
    requested_signal="${signal_name}"
    requested_status="${signal_status}"
  fi
}

# Legacy qcsd-lab recovery/build-transaction paths still use private children
# of /tmp.  Keep their shared-root validator until those callers migrate to
# the durable lifecycle namespace; Docker object ownership records themselves
# are never stored there.
_qcsd_secure_tmp_root() {
  local owner mode mode_value
  [[ ! -L /tmp && -d /tmp ]] || return 1
  owner="$(stat -Lc '%u' -- /tmp 2>/dev/null)" || return 1
  mode="$(stat -Lc '%a' -- /tmp 2>/dev/null)" || return 1
  [[ "${owner}" == "0" && "${mode}" =~ ^[0-7]{3,4}$ ]] || return 1
  mode_value=$((8#${mode}))
  if (( (mode_value & 0022) != 0 && (mode_value & 01000) == 0 )); then
    return 1
  fi
}

_qcsd_validate_lifecycle_root_contents() {
  local root="$1"
  local child name metadata owner mode links kind mode_value canonical root_metadata
  local nullglob_was_set=0 dotglob_was_set=0
  local -a children=()
  [[ ! -L "${root}" && -d "${root}" ]] || return 1
  canonical="$(realpath -m -- "${root}" 2>/dev/null)" || return 1
  [[ "${canonical}" == "${root}" && "${root%/*}" == "${_qcsd_lifecycle_base}" &&
      ( "${root##*/}" =~ ^(run|network|build|transaction)[.][0-9a-f]{32}$ ||
        "${root##*/}" =~ ^[.]retired[.](run|network|build|transaction)[.][0-9a-f]{32}$ ) ]] || return 1
  root_metadata="$(stat -Lc '%u:%a:%F' -- "${root}" 2>/dev/null)" || return 1
  [[ "${root_metadata}" == "${EUID}:700:directory" ]] || return 1
  shopt -q nullglob && nullglob_was_set=1
  shopt -q dotglob && dotglob_was_set=1
  shopt -s nullglob dotglob
  children=("${root}"/*)
  (( nullglob_was_set != 0 )) || shopt -u nullglob
  (( dotglob_was_set != 0 )) || shopt -u dotglob
  for child in "${children[@]}"; do
    name="${child##*/}"
    case "${name}" in
      SUPERVISION|SUPERVISION.next|RECOVERY|RECOVERY.next|HANDOFF|HANDOFF.next|\
      container.cid|run.status|run.status.next|build.status|build.status.next|stdout)
        [[ ! -L "${child}" && -f "${child}" ]] || return 1
        ;;
      BIRTH.lock|launcher.birth|launcher.birth.next)
        [[ ! -L "${child}" && -f "${child}" ]] || return 1
        ;;
      wait.pipe)
        [[ ! -L "${child}" && -p "${child}" ]] || return 1
        ;;
      *) return 1 ;;
    esac
    metadata="$(stat -Lc '%u:%a:%h:%F' -- "${child}" 2>/dev/null)" ||
      return 1
    IFS=: read -r owner mode links kind <<<"${metadata}"
    [[ "${owner}" == "${EUID}" && "${links}" == "1" &&
        "${mode}" =~ ^[0-7]{3,4}$ ]] || return 1
    mode_value=$((8#${mode}))
    (( (mode_value & 0022) == 0 )) || return 1
    if [[ "${name}" == "wait.pipe" ]]; then
      [[ "${kind}" == "fifo" ]] || return 1
    else
      [[ "${kind}" == "regular file" ||
          "${kind}" == "regular empty file" ]] || return 1
    fi
  done
}

_qcsd_secure_lifecycle_base() {
  local uid parent_metadata base_metadata entry entry_metadata canonical
  local expected_kind expected_mode entry_name operation_kind operation_token
  local nullglob_was_set=0 dotglob_was_set=0
  local -a entries=()
  local -A operation_kinds=()
  uid="${EUID}"
  [[ "${uid}" =~ ^(0|[1-9][0-9]*)$ ]] || return 1

  # Docker objects can outlive a distro or WSL restart, so ownership state
  # must not live in /tmp or XDG_RUNTIME_DIR.  The shared parent is accepted
  # only in its canonical, conventional configuration; the user-owned child
  # is always private and has one deterministic globally discoverable name.
  [[ "${_QCSD_DOCKER_LIFECYCLE_PARENT}" == "/var/tmp" &&
      ! -L /var/tmp && -d /var/tmp ]] || return 1
  canonical="$(readlink -f -- /var/tmp 2>/dev/null)" || return 1
  [[ "${canonical}" == "/var/tmp" ]] || return 1
  parent_metadata="$(stat -Lc '%u:%a:%F' -- /var/tmp 2>/dev/null)" || return 1
  [[ "${parent_metadata}" == "0:1777:directory" ]] || return 1

  _qcsd_lifecycle_base="/var/tmp/qcsd-docker-lifecycle-${uid}"
  if [[ ! -e "${_qcsd_lifecycle_base}" &&
        ! -L "${_qcsd_lifecycle_base}" ]]; then
    if ! (umask 077 && mkdir -m 700 -- "${_qcsd_lifecycle_base}"); then
      [[ -d "${_qcsd_lifecycle_base}" ]] || return 1
    fi
    sync -f /var/tmp || return 1
  fi
  [[ ! -L "${_qcsd_lifecycle_base}" &&
      -d "${_qcsd_lifecycle_base}" ]] || return 1
  canonical="$(readlink -f -- "${_qcsd_lifecycle_base}" 2>/dev/null)" || return 1
  [[ "${canonical}" == "${_qcsd_lifecycle_base}" ]] || return 1
  base_metadata="$(stat -Lc '%u:%a:%F' -- \
    "${_qcsd_lifecycle_base}" 2>/dev/null)" || return 1
  [[ "${base_metadata}" == "${uid}:700:directory" ]] || return 1

  # One malformed or unexpected root makes global admission fail closed.  Do
  # not inspect mutable children here: another admitted supervisor may be in
  # the middle of its atomic .next publication.  Recovery validates every
  # child after acquiring the lifecycle interlock.
  shopt -q nullglob && nullglob_was_set=1
  shopt -q dotglob && dotglob_was_set=1
  shopt -s nullglob dotglob
  entries=("${_qcsd_lifecycle_base}"/*)
  (( nullglob_was_set != 0 )) || shopt -u nullglob
  (( dotglob_was_set != 0 )) || shopt -u dotglob
  for entry in "${entries[@]}"; do
    entry_name="${entry##*/}"
    if [[ "${entry_name}" =~ ^(run|network|build|transaction)[.]([0-9a-f]{32})$ ]]; then
      operation_kind="${BASH_REMATCH[1]}"; operation_token="${BASH_REMATCH[2]}"
      [[ ! -L "${entry}" && -d "${entry}" ]] || return 1
      expected_kind=directory
      expected_mode=700
    elif [[ "${entry_name}" =~ ^[.]retired[.](run|network|build|transaction)[.]([0-9a-f]{32})$ ]]; then
      operation_kind="${BASH_REMATCH[1]}"; operation_token="${BASH_REMATCH[2]}"
      [[ ! -L "${entry}" && -d "${entry}" ]] || return 1
      expected_kind=directory
      expected_mode=700
    elif [[ "${entry_name}" =~ ^retirement[.](run|network|build|transaction)[.]([0-9a-f]{32})([.]next)?$ ]]; then
      operation_kind="${BASH_REMATCH[1]}"; operation_token="${BASH_REMATCH[2]}"
      [[ ! -L "${entry}" && -f "${entry}" ]] || return 1
      expected_kind="regular file"
      expected_mode=600
    else
      return 1
    fi
    [[ -z "${operation_kinds[${operation_token}]+x}" ||
        "${operation_kinds[${operation_token}]}" == "${operation_kind}" ]] || return 1
    operation_kinds["${operation_token}"]="${operation_kind}"
    canonical="$(readlink -f -- "${entry}" 2>/dev/null)" || return 1
    [[ "${canonical}" == "${entry}" ]] || return 1
    entry_metadata="$(stat -Lc '%u:%a:%F' -- "${entry}" 2>/dev/null)" || return 1
    if [[ "${expected_kind}" == "regular file" ]]; then
      [[ "${entry_metadata}" == "${uid}:${expected_mode}:regular file" ||
          "${entry_metadata}" == "${uid}:${expected_mode}:regular empty file" ]] || return 1
    else
      [[ "${entry_metadata}" == "${uid}:${expected_mode}:${expected_kind}" ]] || return 1
    fi
    [[ "${expected_kind}" != directory ]] ||
      _qcsd_validate_lifecycle_root_contents "${entry}" || return 1
  done
  (( ${#operation_kinds[@]} <= _QCSD_MAX_LIFECYCLE_OPERATIONS )) || return 1
}

_qcsd_lifecycle_lock_path() {
  local uid
  uid="${EUID}"
  [[ "${uid}" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  printf '/var/tmp/qcsd-docker-lifecycle-%s.lock\n' "${uid}"
}

_qcsd_create_lifecycle_root() {
  local kind="$1"
  local token="$2"
  local metadata canonical
  [[ "${kind}" =~ ^(run|network|build|transaction)$ &&
      "${token}" =~ ^[0-9a-f]{32}$ ]] || return 1
  _qcsd_secure_lifecycle_base || return 1
  _qcsd_lifecycle_root="${_qcsd_lifecycle_base}/${kind}.${token}"
  [[ ! -e "${_qcsd_lifecycle_root}" &&
      ! -L "${_qcsd_lifecycle_root}" ]] || return 1
  _qcsd_begin_lifecycle_root_creation "${kind}.${token}" || return 1
  if [[ ! -d "${_qcsd_lifecycle_root}" || -L "${_qcsd_lifecycle_root}" ||
      "$(stat -Lc '%d:%i:%u:%a:%F' -- "${_qcsd_lifecycle_root}")" != \
        "${_QCSD_CREATION_ROOT_DEVICE}:${_QCSD_CREATION_ROOT_INODE}:${EUID}:700:directory" ]]; then
    _qcsd_cancel_lifecycle_root_creation || true
    return 1
  fi
  canonical="$(readlink -f -- "${_qcsd_lifecycle_root}" 2>/dev/null)" || {
    _qcsd_cancel_lifecycle_root_creation || true; return 1;
  }
  metadata="$(stat -Lc '%u:%a:%F' -- \
    "${_qcsd_lifecycle_root}" 2>/dev/null)" || {
    _qcsd_cancel_lifecycle_root_creation || true; return 1;
  }
  if [[ "${canonical}" != "${_qcsd_lifecycle_root}" ||
        "${metadata}" != "${EUID}:700:directory" ]]; then
    _qcsd_cancel_lifecycle_root_creation || true
    return 1
  fi
  sync -f "${_qcsd_lifecycle_base}" || {
    _qcsd_cancel_lifecycle_root_creation || true; return 1;
  }
  _qcsd_lifecycle_root_created_hook "${_qcsd_lifecycle_root}" || {
    _qcsd_cancel_lifecycle_root_creation || true
    return 1
  }
}

_qcsd_lifecycle_root_created_hook() {
  # Test-only observation point.  Production deliberately does nothing.
  :
}

_qcsd_launcher_forked_hook() {
  # Test-only crash-injection point, before the child's identity is available.
  :
}

_qcsd_launcher_birth_bound_hook() {
  # Test-only crash-injection point after BIRTH is durable but before transfer.
  :
}

_qcsd_pre_mutation_release_hook() {
  # Test-only signal-injection point at the final mutation boundary.
  :
}

_qcsd_pre_cont_signal_hook() {
  # Test-only last-inch signal injection after process identity validation.
  :
}

_qcsd_capture_helper_source_identity() {
  local source_path source_metadata source_metadata_after mode mode_value
  [[ -z "${_QCSD_EXECUTED_HELPER_SOURCE_CAPTURED:-}" ]] || return 1
  source_path="${BASH_SOURCE[0]}"
  [[ -n "${source_path}" && "${source_path}" != *$'\n'* &&
      "${source_path}" != *$'\r'* && ! -L "${source_path}" &&
      -f "${source_path}" ]] || return 1
  _QCSD_EXECUTED_HELPER_SOURCE_PATH="$(readlink -f -- "${source_path}" 2>/dev/null)" ||
    return 1
  [[ -n "${_QCSD_EXECUTED_HELPER_SOURCE_PATH}" &&
      "${_QCSD_EXECUTED_HELPER_SOURCE_PATH}" != *$'\n'* &&
      "${_QCSD_EXECUTED_HELPER_SOURCE_PATH}" != *$'\r'* &&
      ! -L "${_QCSD_EXECUTED_HELPER_SOURCE_PATH}" &&
      -f "${_QCSD_EXECUTED_HELPER_SOURCE_PATH}" ]] || return 1
  source_metadata="$(stat -Lc '%d:%i:%s:%Y:%u:%a:%h:%F' -- \
    "${_QCSD_EXECUTED_HELPER_SOURCE_PATH}" 2>/dev/null)" || return 1
  IFS=: read -r _QCSD_EXECUTED_HELPER_SOURCE_DEVICE \
    _QCSD_EXECUTED_HELPER_SOURCE_INODE _QCSD_EXECUTED_HELPER_SOURCE_SIZE \
    _QCSD_EXECUTED_HELPER_SOURCE_MTIME _QCSD_EXECUTED_HELPER_SOURCE_OWNER \
    mode _QCSD_EXECUTED_HELPER_SOURCE_LINKS \
    _QCSD_EXECUTED_HELPER_SOURCE_KIND <<<"${source_metadata}"
  [[ "${_QCSD_EXECUTED_HELPER_SOURCE_OWNER}" == "${EUID}" &&
      "${_QCSD_EXECUTED_HELPER_SOURCE_LINKS}" == "1" &&
      "${_QCSD_EXECUTED_HELPER_SOURCE_KIND}" == "regular file" &&
      "${mode}" =~ ^[0-7]{3,4}$ ]] || return 1
  mode_value=$((8#${mode}))
  (( (mode_value & 0022) == 0 )) || return 1
  _QCSD_EXECUTED_HELPER_SOURCE_SHA256="$(sha256sum -- \
    "${_QCSD_EXECUTED_HELPER_SOURCE_PATH}" 2>/dev/null | awk '{print $1}')" || return 1
  [[ "${_QCSD_EXECUTED_HELPER_SOURCE_SHA256}" =~ ^[0-9a-f]{64}$ ]] || return 1
  source_metadata_after="$(stat -Lc '%d:%i:%s:%Y:%u:%a:%h:%F' -- \
    "${_QCSD_EXECUTED_HELPER_SOURCE_PATH}" 2>/dev/null)" || return 1
  [[ "${source_metadata_after}" == "${source_metadata}" ]] || return 1
  _QCSD_EXECUTED_HELPER_SOURCE_METADATA="${source_metadata}"
  _QCSD_EXECUTED_HELPER_SOURCE_CAPTURED=1
  readonly _QCSD_EXECUTED_HELPER_SOURCE_PATH \
    _QCSD_EXECUTED_HELPER_SOURCE_DEVICE _QCSD_EXECUTED_HELPER_SOURCE_INODE \
    _QCSD_EXECUTED_HELPER_SOURCE_SIZE _QCSD_EXECUTED_HELPER_SOURCE_MTIME \
    _QCSD_EXECUTED_HELPER_SOURCE_OWNER _QCSD_EXECUTED_HELPER_SOURCE_LINKS \
    _QCSD_EXECUTED_HELPER_SOURCE_KIND _QCSD_EXECUTED_HELPER_SOURCE_SHA256 \
    _QCSD_EXECUTED_HELPER_SOURCE_METADATA _QCSD_EXECUTED_HELPER_SOURCE_CAPTURED
}

_qcsd_revalidate_helper_source_identity() {
  local metadata digest
  [[ "${_QCSD_EXECUTED_HELPER_SOURCE_CAPTURED:-}" == "1" &&
      ! -L "${_QCSD_EXECUTED_HELPER_SOURCE_PATH}" &&
      -f "${_QCSD_EXECUTED_HELPER_SOURCE_PATH}" ]] || return 1
  metadata="$(stat -Lc '%d:%i:%s:%Y:%u:%a:%h:%F' -- \
    "${_QCSD_EXECUTED_HELPER_SOURCE_PATH}" 2>/dev/null)" || return 1
  [[ "${metadata}" == "${_QCSD_EXECUTED_HELPER_SOURCE_METADATA}" ]] || return 1
  digest="$(sha256sum -- "${_QCSD_EXECUTED_HELPER_SOURCE_PATH}" 2>/dev/null |
    awk '{print $1}')" || return 1
  [[ "${digest}" == "${_QCSD_EXECUTED_HELPER_SOURCE_SHA256}" ]] || return 1
  [[ "$(stat -Lc '%d:%i:%s:%Y:%u:%a:%h:%F' -- \
    "${_QCSD_EXECUTED_HELPER_SOURCE_PATH}" 2>/dev/null)" == "${metadata}" ]]
}

_qcsd_bind_helper_source_identity() {
  _qcsd_revalidate_helper_source_identity || return 1
  _qcsd_bound_source_path="${_QCSD_EXECUTED_HELPER_SOURCE_PATH}"
  _qcsd_bound_source_device="${_QCSD_EXECUTED_HELPER_SOURCE_DEVICE}"
  _qcsd_bound_source_inode="${_QCSD_EXECUTED_HELPER_SOURCE_INODE}"
  _qcsd_bound_source_size="${_QCSD_EXECUTED_HELPER_SOURCE_SIZE}"
  _qcsd_bound_source_mtime="${_QCSD_EXECUTED_HELPER_SOURCE_MTIME}"
  _qcsd_bound_source_owner="${_QCSD_EXECUTED_HELPER_SOURCE_OWNER}"
  _qcsd_bound_source_links="${_QCSD_EXECUTED_HELPER_SOURCE_LINKS}"
  _qcsd_bound_source_kind="${_QCSD_EXECUTED_HELPER_SOURCE_KIND}"
  _qcsd_bound_source_sha256="${_QCSD_EXECUTED_HELPER_SOURCE_SHA256}"
}

_qcsd_capture_helper_source_identity || return 1 2>/dev/null || exit 1

_qcsd_print_lifecycle_identity() {
  printf 'lifecycle_schema=%s\n' "${_QCSD_DOCKER_LIFECYCLE_SCHEMA}"
  printf 'lifecycle_state=%s\n' "${lifecycle_state}"
  printf 'lifecycle_root=%s\n' "${supervisor_root}"
  printf 'lifecycle_token=%s\n' "${token}"
  printf 'supervisor_source_path=%s\n' "${_qcsd_bound_source_path}"
  printf 'supervisor_source_sha256=%s\n' "${_qcsd_bound_source_sha256}"
  printf 'supervisor_source_device=%s\n' "${_qcsd_bound_source_device}"
  printf 'supervisor_source_inode=%s\n' "${_qcsd_bound_source_inode}"
}

_qcsd_verify_locked_regular_fd() {
  local fd="$1"
  local fd_path target metadata fd_metadata metadata_after owner mode links kind
  local mode_value
  [[ "${fd}" =~ ^[0-9]+$ ]] || return 1
  fd_path="/proc/${BASHPID}/fd/${fd}"
  [[ -L "${fd_path}" ]] || return 1
  target="$(readlink -f -- "${fd_path}" 2>/dev/null)" || return 1
  [[ -n "${target}" && "${target}" != *$'\n'* &&
      "${target}" != *$'\r'* && ! -L "${target}" &&
      -f "${target}" ]] || return 1
  fd_metadata="$(stat -Lc '%d:%i:%u:%a:%h:%F' -- "${fd_path}" 2>/dev/null)" ||
    return 1
  metadata="$(stat -Lc '%d:%i:%u:%a:%h:%F' -- "${target}" 2>/dev/null)" ||
    return 1
  [[ "${fd_metadata}" == "${metadata}" ]] || return 1
  IFS=: read -r _qcsd_bound_lock_device _qcsd_bound_lock_inode \
    owner mode links kind <<<"${metadata}"
  [[ "${owner}" == "${EUID}" && "${links}" == "1" &&
      "${mode}" == "600" && "${kind}" == "regular empty file" ]] || return 1
  # Opening /proc/.../fd/N creates an independent open-file description.  It
  # must be unable to acquire the same exclusive advisory lock.
  if flock -n "${fd_path}" true 2>/dev/null; then
    return 1
  fi
  metadata_after="$(stat -Lc '%d:%i:%u:%a:%h:%F' -- \
    "${fd_path}" 2>/dev/null)" || return 1
  [[ "${metadata_after}" == "${metadata}" ]] || return 1
  _qcsd_bound_lock_path="${target}"
}

_qcsd_supervisor_token() {
  local token
  token="$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d '[:space:]')" ||
    return 1
  [[ "${token}" =~ ^[0-9a-f]{32}$ ]] || return 1
  printf '%s\n' "${token}"
}

_qcsd_private_cid() {
  local cidfile="$1"
  local metadata owner mode links kind mode_value
  local -a lines=()
  if [[ -L "${cidfile}" || ! -f "${cidfile}" ]]; then
    return 1
  fi
  metadata="$(stat -Lc '%u:%a:%h:%F' -- "${cidfile}" 2>/dev/null)" || return 1
  IFS=: read -r owner mode links kind <<<"${metadata}"
  [[ "${owner}" == "${EUID}" && "${links}" == "1" &&
      "${kind}" == "regular file" && "${mode}" =~ ^[0-7]{3,4}$ ]] || return 1
  mode_value=$((8#${mode}))
  (( (mode_value & 0022) == 0 )) || return 1
  mapfile -t lines <"${cidfile}"
  if (( ${#lines[@]} != 1 )) ||
     [[ ! "${lines[0]}" =~ ^[0-9a-f]{64}$ ]]; then
    return 1
  fi
  printf '%s\n' "${lines[0]}"
}

_qcsd_private_exit_status() {
  local status_file="$1"
  local metadata status
  local -a lines=()
  [[ ! -L "${status_file}" && -f "${status_file}" ]] || return 1
  metadata="$(stat -Lc '%u:%a:%h:%F' -- "${status_file}" 2>/dev/null)" ||
    return 1
  [[ "${metadata}" == "${EUID}:600:1:regular file" ]] || return 1
  mapfile -t lines <"${status_file}"
  (( ${#lines[@]} == 1 )) || return 1
  status="${lines[0]}"
  [[ "${status}" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
  (( status <= 255 )) || return 1
  printf '%s\n' "${status}"
}

_qcsd_private_launcher_birth() {
  local birth_path="$1"
  local expected_root="$2"
  local expected_token="$3"
  local expected_kind="$4"
  local metadata size last_byte line key value grep_status
  local -a lines=()
  [[ ! -L "${birth_path}" && -f "${birth_path}" ]] || return 1
  metadata="$(stat -Lc '%u:%a:%h:%F' -- "${birth_path}" 2>/dev/null)" ||
    return 1
  [[ "${metadata}" == "${EUID}:600:1:regular file" ]] || return 1
  size="$(stat -Lc '%s' -- "${birth_path}" 2>/dev/null)" || return 1
  [[ "${size}" =~ ^[1-9][0-9]*$ ]] || return 1
  (( size <= 2048 )) || return 1
  last_byte="$(od -An -tu1 -j "$((size - 1))" -N1 -- \
    "${birth_path}" 2>/dev/null | tr -d '[:space:]')" || return 1
  [[ "${last_byte}" == "10" ]] || return 1
  if LC_ALL=C grep -q '[^ -~]' -- "${birth_path}"; then
    return 1
  else
    grep_status=$?
    (( grep_status == 1 )) || return 1
  fi
  mapfile -t lines <"${birth_path}" || return 1
  (( ${#lines[@]} == 8 )) || return 1
  [[ "${lines[0]}" == "birth_schema=1" &&
      "${lines[1]}" == "launcher_kind=${expected_kind}" &&
      "${lines[2]}" == "lifecycle_root=${expected_root}" &&
      "${lines[3]}" == "lifecycle_token=${expected_token}" ]] || return 1
  _qcsd_birth_pid="${lines[4]#launcher_pid=}"
  _qcsd_birth_start_time="${lines[5]#launcher_start_time=}"
  _qcsd_birth_session="${lines[6]#launcher_session=}"
  _qcsd_birth_process_group="${lines[7]#launcher_process_group=}"
  [[ "${lines[4]}" == "launcher_pid=${_qcsd_birth_pid}" &&
      "${lines[5]}" == "launcher_start_time=${_qcsd_birth_start_time}" &&
      "${lines[6]}" == "launcher_session=${_qcsd_birth_session}" &&
      "${lines[7]}" == "launcher_process_group=${_qcsd_birth_process_group}" &&
      "${_qcsd_birth_pid}" =~ ^[1-9][0-9]*$ &&
      "${_qcsd_birth_start_time}" =~ ^[1-9][0-9]*$ &&
      "${_qcsd_birth_session}" == "${_qcsd_birth_pid}" &&
      "${_qcsd_birth_process_group}" == "${_qcsd_birth_pid}" ]]
}

_qcsd_open_launcher_birth_lock() {
  local root="$1"
  local destination_name="$2"
  local path="${root}/BIRTH.lock" fd metadata fd_metadata
  [[ "${destination_name}" =~ ^[a-z_][a-z0-9_]*$ &&
      ! -e "${path}" && ! -L "${path}" ]] || return 1
  (umask 077 && : >"${path}") || return 1
  chmod 600 -- "${path}" || return 1
  exec {fd}<>"${path}" || return 1
  metadata="$(stat -Lc '%d:%i:%u:%a:%h:%F' -- "${path}" 2>/dev/null)" ||
    return 1
  fd_metadata="$(stat -Lc '%d:%i:%u:%a:%h:%F' -- \
    "/proc/${BASHPID}/fd/${fd}" 2>/dev/null)" || return 1
  [[ "${metadata}" == "${fd_metadata}" &&
      "${metadata}" == *":${EUID}:600:1:regular empty file" ]] || return 1
  flock -x "${fd}" || return 1
  printf -v "${destination_name}" '%s' "${fd}"
}

_qcsd_secure_supervision_file() {
  local path="$1"
  local metadata
  [[ ! -L "${path}" && -f "${path}" ]] || return 1
  chmod 600 -- "${path}" || return 1
  metadata="$(stat -Lc '%u:%a:%h' -- "${path}" 2>/dev/null)" || return 1
  [[ "${metadata}" == "${EUID}:600:1" ]]
}

_qcsd_publish_supervision_file() {
  local staged_path="$1"
  local published_path="$2"
  local root="${published_path%/*}" root_kind record_name="${published_path##*/}"
  local -A staged_values=()
  local -a staged_order=()
  _QCSD_PUBLISH_REPLACED=0
  _qcsd_secure_supervision_file "${staged_path}" || return 1
  root_kind="${root##*/}"; root_kind="${root_kind%%.*}"
  _qcsd_lifecycle_parse_record "${staged_path}" staged_values staged_order || return 1
  _qcsd_lifecycle_validate_record \
    "${root}" "${root_kind}" "${record_name}" staged_values || return 1
  sync -f "${staged_path}" || return 1
  mv -f -- "${staged_path}" "${published_path}" || return 1
  _QCSD_PUBLISH_REPLACED=1
  _qcsd_secure_supervision_file "${published_path}" || return 1
  _qcsd_lifecycle_parse_record "${published_path}" staged_values staged_order || return 1
  _qcsd_lifecycle_validate_record \
    "${root}" "${root_kind}" "${record_name}" staged_values || return 1
  sync -f "${published_path%/*}"
}

_qcsd_revalidate_release_record() {
  local root="$1" root_kind="$2" expected_sha="$3"
  local record="${root}/SUPERVISION" observed_sha
  local -A release_values=()
  local -a release_order=()
  _qcsd_validate_lifecycle_root_contents "${root}" || return 1
  _qcsd_lifecycle_parse_record "${record}" release_values release_order || return 1
  _qcsd_lifecycle_validate_record \
    "${root}" "${root_kind}" SUPERVISION release_values || return 1
  observed_sha="$(sha256sum -- "${record}" | awk '{print $1}')" || return 1
  [[ "${observed_sha}" == "${expected_sha}" ]]
}

# Name-based Bash references resolve through dynamic scope. Restrict caller
# destinations to a namespace that this helper never uses for locals, and
# require the exact mutable type before any Docker object can be created.
_qcsd_mutable_id_array() {
  local destination_name="$1"
  local declaration=""
  [[ "${destination_name}" =~ ^QCSD_DOCKER_IDS_[A-Z0-9_]+$ ]] || return 1
  declaration="$(declare -p "${destination_name}" 2>/dev/null)" || return 1
  [[ "${declaration}" == "declare -a ${destination_name}="* ]]
}

_qcsd_mutable_output_scalar() {
  local destination_name="$1"
  local declaration=""
  [[ "${destination_name}" =~ ^QCSD_DOCKER_OUTPUT_[A-Z0-9_]+$ ]] || return 1
  declaration="$(declare -p "${destination_name}" 2>/dev/null)" || return 1
  [[ "${declaration}" == "declare -- ${destination_name}="* ]]
}

_qcsd_docker_api() {
  _qcsd_docker_api_with_timeout "${_QCSD_DOCKER_API_TIMEOUT_SECONDS}" "$@"
}

_qcsd_docker_api_with_timeout() {
  local duration="$1"
  shift
  if ! _qcsd_revalidate_helper_source_identity; then
    echo "Docker API supervisor source identity changed" >&2
    return 125
  fi
  if [[ "$-" == *m* ]]; then
    echo "Docker API supervisor rejects shell monitor mode" >&2
    return 2
  fi
  if [[ -n "${_QCSD_DOCKER_PINNED_HOST:-}" &&
        "${1:-}" != "context" ]]; then
    _qcsd_pinned_docker_api_with_timeout "${duration}" "$@"
  else
    _qcsd_docker_api_raw_with_timeout "${duration}" "$@"
  fi
}

_qcsd_valid_pinned_docker_host() {
  local host="$1"
  local socket_path
  if [[ "${host}" == "npipe:////./pipe/dockerDesktopLinuxEngine" ]]; then
    return 0
  fi
  [[ "${host}" =~ ^unix:///[A-Za-z0-9_./-]+$ ]] || return 1
  socket_path="${host#unix://}"
  [[ "${socket_path}" == /* && "${socket_path}" != "/" &&
      "${socket_path}" != *"//"* && "${socket_path}" != *"/../"* &&
      "${socket_path}" != */.. && "${socket_path}" != *"/./"* &&
      "${socket_path}" != */. ]]
}

_qcsd_read_docker_daemon_id() {
  # Identity-only reads must not invoke `docker info` client/plugin discovery.
  # The pinned native wrapper performs this request only after authenticating
  # the ordinary API-service lease; the existing runtime bound still applies.
  (( $# == 1 )) || return 2
  _qcsd_valid_pinned_docker_host "$1" || return 125
  _qcsd_revalidate_helper_source_identity || return 125
  _qcsd_docker_api_service_with_timeout \
    "${_QCSD_DOCKER_API_TIMEOUT_SECONDS}" qcsd-native-docker-id "$1"
}

_qcsd_pinned_docker_api_with_timeout() {
  local duration="$1"
  shift
  if ! _qcsd_valid_pinned_docker_host \
       "${_QCSD_DOCKER_PINNED_HOST:-}" ||
     [[ ! "${_QCSD_DOCKER_PINNED_SERVER_ID:-}" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
    return 125
  fi
  if [[ "${1:-}" == "--context" ]]; then
    if (( $# < 3 )) || [[ "$2" != "${_QCSD_DOCKER_PINNED_CONTEXT:-}" ]]; then
      return 125
    fi
    shift 2
  fi
  # Fresh daemon equality and the original one-shot Docker operation remain
  # inside the same leased service. No identity is cached across requests.
  _qcsd_docker_api_service_with_timeout "${duration}" \
    qcsd-native-docker-exec "${_QCSD_DOCKER_PINNED_HOST}" \
    "${_QCSD_DOCKER_PINNED_SERVER_ID}" -- "$@"
}

_qcsd_docker_api_raw_with_timeout() {
  local duration="$1"
  shift
  if [[ "$-" == *m* ]]; then
    echo "Docker API supervisor rejects shell monitor mode" >&2
    return 2
  fi
  local -a docker_arguments=("$@")
  if [[ -n "${_QCSD_DOCKER_PINNED_HOST:-}" &&
        "${1:-}" != "context" ]]; then
    if ! _qcsd_valid_pinned_docker_host \
         "${_QCSD_DOCKER_PINNED_HOST}"; then
      return 125
    fi
    if [[ "${1:-}" == "--context" ]]; then
      if (( $# < 3 )) ||
         [[ "$2" != "${_QCSD_DOCKER_PINNED_CONTEXT:-}" ]]; then
        return 125
      fi
      shift 2
    fi
    docker_arguments=(--host "${_QCSD_DOCKER_PINNED_HOST}" "$@")
  fi
  if [[ "${docker_arguments[0]:-}" == "--host" ]]; then
    _qcsd_docker_api_service_with_timeout "${duration}" env \
      -u DOCKER_CONTEXT -u DOCKER_HOST -u DOCKER_TLS_VERIFY \
      -u DOCKER_CERT_PATH docker "${docker_arguments[@]}"
  else
    _qcsd_docker_api_service_with_timeout \
      "${duration}" docker "${docker_arguments[@]}"
  fi
}

# Container-supervision helpers inherit this function-local context through
# Bash dynamic scope. Outside a context-pinned run it is intentionally empty.
_qcsd_target_docker_api() {
  if [[ -n "${_qcsd_target_docker_context:-}" ]]; then
    _qcsd_docker_api --context "${_qcsd_target_docker_context}" "$@"
  else
    _qcsd_docker_api "$@"
  fi
}

_qcsd_target_docker_api_with_timeout() {
  local duration="$1"
  shift
  if [[ -n "${_qcsd_target_docker_context:-}" ]]; then
    _qcsd_docker_api_with_timeout "${duration}" \
      --context "${_qcsd_target_docker_context}" "$@"
  else
    _qcsd_docker_api_with_timeout "${duration}" "$@"
  fi
}

_qcsd_verify_pinned_docker_daemon() {
  local attempt status duration
  (( $# <= 1 )) || return 1
  case "${1-ordinary}" in
    ordinary) duration="${_QCSD_DOCKER_API_TIMEOUT_SECONDS}" ;;
    build-retirement)
      duration="${_QCSD_DOCKER_BUILD_RETIREMENT_IDENTITY_TIMEOUT_SECONDS}"
      ;;
    *) return 1 ;;
  esac
  if [[ ! "${_QCSD_DOCKER_PINNED_CONTEXT:-}" =~ ^[A-Za-z0-9_.-]+$ ]] ||
     ! _qcsd_valid_pinned_docker_host \
       "${_QCSD_DOCKER_PINNED_HOST:-}" ||
     [[ ! "${_QCSD_DOCKER_PINNED_SERVER_ID:-}" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
    return 1
  fi
  for (( attempt = 1;
         attempt <= _QCSD_DOCKER_DAEMON_IDENTITY_ATTEMPTS;
         attempt++ )); do
    # Keep daemon output inside the leased service.  In particular, do not
    # make command-substitution output from a very short transient service an
    # identity authority: systemd supervision can have completed correctly
    # even when that outer output boundary is unavailable.  systemd-run
    # --wait and the native holder preserve ExecMainStatus, so 42 is an exact
    # returned mismatch while 125 (or any other infrastructure failure) is
    # eligible for the one existing read-only retry.
    if _qcsd_docker_api_service_with_timeout \
        "${duration}" qcsd-native-docker-verify "${_QCSD_DOCKER_PINNED_HOST}" \
      "${_QCSD_DOCKER_PINNED_SERVER_ID}" >/dev/null 2>&1; then
      return 0
    else
      status=$?
    fi
    (( status == 42 )) && return 1
    # The native API-service boundary proves the failed service terminal
    # before returning, so a retry cannot overlap its predecessor.
  done
  return 1
}

_qcsd_verify_pinned_host_boot() {
  local observed_boot
  [[ "${_QCSD_DOCKER_PINNED_BOOT_ID:-}" =~ \
    ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
    return 1
  IFS= read -r observed_boot </proc/sys/kernel/random/boot_id || return 1
  [[ "${observed_boot}" == "${_QCSD_DOCKER_PINNED_BOOT_ID}" ]]
}

_qcsd_print_docker_binding() {
  printf 'docker_host=%s\n' "${_QCSD_DOCKER_PINNED_HOST:-unavailable}"
  printf 'docker_server_id=%s\n' \
    "${_QCSD_DOCKER_PINNED_SERVER_ID:-unavailable}"
  printf 'docker_request_revalidation=in-scope-immediately-before-mutation\n'
}

_qcsd_force_remove_target() {
  local cid="$1"
  target_force_attempted=1
  target_forced=1
  [[ "${target_force_api_outcome}" == accepted ]] ||
    target_force_api_outcome="unknown"
  if _qcsd_target_docker_api rm --force "${cid}" >/dev/null 2>&1; then
    target_force_api_outcome="accepted"
    return 0
  fi
  return 1
}

# Print present, absent, unknown, or ambiguous. Successful, canonical
# `container ls` output is the only absence proof. API failure is unknown;
# malformed, duplicate, or contradictory successful output is ambiguous.
_qcsd_docker_exact_id_presence_detailed() {
  local cid="$1"
  local output line
  local -a ids=()
  if ! output="$(_qcsd_target_docker_api container ls --all --no-trunc \
      --filter "id=${cid}" --format '{{.ID}}' 2>/dev/null)"; then
    printf 'unknown\n'
    return 0
  fi
  while IFS= read -r line; do
    [[ -z "${line}" ]] || ids+=("${line}")
  done <<<"${output}"
  if (( ${#ids[@]} == 0 )); then
    printf 'absent\n'
  elif (( ${#ids[@]} == 1 )) && [[ "${ids[0]}" == "${cid}" ]]; then
    printf 'present\n'
  else
    printf 'ambiguous\n'
  fi
}

# Preserve the historical tri-state contract for recovery and supervisor
# callers. Handoff retirement uses the detailed observation above because its
# bounded retry must never treat ambiguous successful output as API unknown.
_qcsd_docker_exact_id_presence() {
  local presence
  presence="$(_qcsd_docker_exact_id_presence_detailed "$1")" || {
    printf 'unknown\n'
    return 0
  }
  [[ "${presence}" != ambiguous ]] || presence=unknown
  printf '%s\n' "${presence}"
}

# Print running, stopped, absent, or unknown while also proving the private
# supervisor label. A detached launch is owned only in the running state.
_qcsd_docker_target_state() {
  local cid="$1"
  local token="$2"
  local presence output
  presence="$(_qcsd_docker_exact_id_presence "${cid}")"
  if [[ "${presence}" != "present" ]]; then
    printf '%s\n' "${presence}"
    return 0
  fi
  if ! output="$(_qcsd_target_docker_api container inspect --format \
      '{{.Id}}|{{index .Config.Labels "org.qcsd.supervisor.instance"}}|{{.State.Running}}' \
      "${cid}" 2>/dev/null)"; then
    printf 'unknown\n'
  elif [[ "${output}" == "${cid}|${token}|true" ]]; then
    printf 'running\n'
  elif [[ "${output}" == "${cid}|${token}|false" ]]; then
    printf 'stopped\n'
  else
    printf 'unknown\n'
  fi
}

# Set _qcsd_resolved_state/_qcsd_resolved_cid. The cidfile is authoritative
# when complete; the high-entropy label closes the daemon create/cidfile race.
_qcsd_resolve_docker_target() {
  local cidfile="$1"
  local token="$2"
  local cid output line
  local -a ids=()
  _qcsd_resolved_state="unknown"
  _qcsd_resolved_cid=""
  cid="$(_qcsd_private_cid "${cidfile}" 2>/dev/null)"
  if [[ -n "${cid}" ]]; then
    _qcsd_resolved_cid="${cid}"
    _qcsd_resolved_state="$(_qcsd_docker_target_state "${cid}" "${token}")"
    return 0
  fi
  if ! output="$(_qcsd_target_docker_api container ls --all --no-trunc \
      --filter "label=${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}=${token}" \
      --format '{{.ID}}' 2>/dev/null)"; then
    return 0
  fi
  while IFS= read -r line; do
    [[ -z "${line}" ]] || ids+=("${line}")
  done <<<"${output}"
  if (( ${#ids[@]} == 0 )); then
    _qcsd_resolved_state="absent"
  elif (( ${#ids[@]} == 1 )) && [[ "${ids[0]}" =~ ^[0-9a-f]{64}$ ]]; then
    _qcsd_resolved_cid="${ids[0]}"
    _qcsd_resolved_state="$(_qcsd_docker_target_state \
      "${_qcsd_resolved_cid}" "${token}")"
  fi
}

_qcsd_read_process_identity() {
  local pid="$1"
  local stat_line suffix
  local -a fields=()
  _qcsd_process_state=""
  _qcsd_process_parent=""
  _qcsd_process_group=""
  _qcsd_process_session=""
  _qcsd_process_start_time=""
  IFS= read -r stat_line 2>/dev/null <"/proc/${pid}/stat" || return 1
  suffix="${stat_line##*) }"
  read -r -a fields <<<"${suffix}"
  (( ${#fields[@]} > 19 )) || return 1
  [[ "${fields[0]}" =~ ^[A-Za-z]$ &&
      "${fields[1]}" =~ ^[0-9]+$ &&
      "${fields[2]}" =~ ^[0-9]+$ &&
      "${fields[3]}" =~ ^[0-9]+$ &&
      "${fields[19]}" =~ ^[0-9]+$ ]] || return 1
  _qcsd_process_state="${fields[0]}"
  _qcsd_process_parent="${fields[1]}"
  _qcsd_process_group="${fields[2]}"
  _qcsd_process_session="${fields[3]}"
  _qcsd_process_start_time="${fields[19]}"
}

_qcsd_bind_current_supervisor_identity() {
  _qcsd_bound_supervisor_pid="${BASHPID}"
  _qcsd_bound_supervisor_start_time=""
  _qcsd_bound_supervisor_session=""
  _qcsd_bound_supervisor_process_group=""
  _qcsd_read_process_identity "${_qcsd_bound_supervisor_pid}" || return 1
  [[ "${_qcsd_process_state}" != "Z" ]] || return 1
  _qcsd_bound_supervisor_start_time="${_qcsd_process_start_time}"
  _qcsd_bound_supervisor_session="${_qcsd_process_session}"
  _qcsd_bound_supervisor_process_group="${_qcsd_process_group}"
}

_qcsd_print_bound_supervisor_identity() {
  printf 'supervisor_pid=%s\n' "${supervisor_pid}"
  printf 'supervisor_start_time=%s\n' "${supervisor_start_time}"
  printf 'supervisor_session=%s\n' "${supervisor_session}"
  printf 'supervisor_process_group=%s\n' "${supervisor_process_group}"
}

_qcsd_job_is_running() {
  local wanted="$1"
  local wanted_start_time="$2"
  local wanted_session="$3"
  local wanted_group="$4"
  [[ -n "${wanted_start_time}" ]] || return 1
  _qcsd_read_process_identity "${wanted}" || return 1
  [[ "${_qcsd_process_state}" != "Z" &&
      "${_qcsd_process_start_time}" == "${wanted_start_time}" ]] || return 1
  [[ -z "${wanted_session}" ||
      "${_qcsd_process_session}" == "${wanted_session}" ]] || return 1
  [[ -z "${wanted_group}" ||
      "${_qcsd_process_group}" == "${wanted_group}" ]]
}

_qcsd_bound_process_is_gone() {
  local wanted="$1"
  local wanted_start_time="$2"
  local wanted_session="$3"
  local wanted_group="$4"
  # Absence, zombie state, or a different Linux birth identity proves that the
  # captured child cannot still execute. A failed /proc read while the PID path
  # remains visible is unknown, not absence.
  if ! _qcsd_read_process_identity "${wanted}"; then
    [[ ! -e "/proc/${wanted}" ]]
    return $?
  fi
  [[ "${_qcsd_process_state}" == "Z" ]] && return 0
  [[ -n "${wanted_start_time}" ]] || return 1
  [[ "${_qcsd_process_start_time}" != "${wanted_start_time}" ]] && return 0
  # A live process whose session or process group changed is not the bound
  # job, but it is emphatically not proven gone. Never turn that mismatch into
  # permission for a potentially blocking wait.
  return 1
}

_qcsd_wait_for_job_stop() {
  local job_pid="$1"
  local start_time="$2"
  local session="$3"
  local process_group="$4"
  local polls="$5"
  local delay="$6"
  local poll
  for (( poll = 0; poll < polls; poll++ )); do
    _qcsd_job_is_running \
      "${job_pid}" "${start_time}" "${session}" "${process_group}" || return 0
    sleep "${delay}" || true
  done
  ! _qcsd_job_is_running \
    "${job_pid}" "${start_time}" "${session}" "${process_group}"
}

_qcsd_process_group_has_live_members() {
  local wanted_session="$1"
  local wanted_group="$2"
  local stat_path member_pid scan unreadable=0
  [[ "${wanted_session}" =~ ^[1-9][0-9]*$ &&
      "${wanted_group}" =~ ^[1-9][0-9]*$ ]] || return 1
  # Require two empty snapshots. A member can fork after one /proc glob is
  # expanded and then exit before its own stat entry is read; the second scan
  # prevents that boundary from becoming a false quiescence proof.
  for scan in 1 2; do
    for stat_path in /proc/[0-9]*/stat; do
      [[ -e "${stat_path}" ]] || continue
      member_pid="${stat_path#/proc/}"
      member_pid="${member_pid%/stat}"
      if ! _qcsd_read_process_identity "${member_pid}"; then
        # A process can disappear between glob expansion and read; that is a
        # proven race-to-absence.  A still-visible stat path that cannot be
        # parsed is unknown and must conservatively prevent an empty-group
        # result.
        [[ -e "${stat_path}" ]] && unreadable=1
        continue
      fi
      if [[ "${_qcsd_process_state}" != "Z" &&
            "${_qcsd_process_session}" == "${wanted_session}" &&
            "${_qcsd_process_group}" == "${wanted_group}" ]]; then
        return 0
      fi
    done
    (( scan == 2 )) || sleep 0.01 || true
  done
  (( unreadable == 0 )) || return 0
  return 1
}

_qcsd_wait_for_process_group_stop() {
  local session="$1"
  local process_group="$2"
  local polls="$3"
  local delay="$4"
  local poll
  for (( poll = 0; poll < polls; poll++ )); do
    _qcsd_process_group_has_live_members "${session}" "${process_group}" ||
      return 0
    sleep "${delay}" || true
  done
  ! _qcsd_process_group_has_live_members "${session}" "${process_group}"
}

_qcsd_signal_bound_job() {
  local job_pid="$1"
  local start_time="$2"
  local session="$3"
  local process_group="$4"
  local requested="$5"
  # Bash offers no pidfd primitive. The child remains unreaped while this path
  # runs, and PID, Linux start time, process group, and session are revalidated
  # immediately before the builtin kill, with no external command in between.
  _qcsd_job_is_running \
    "${job_pid}" "${start_time}" "${session}" "${process_group}" || return 1
  [[ "${requested}" != CONT || "${_qcsd_process_state}" == T ]] || return 1
  [[ "${requested}" != "CONT" ]] || _qcsd_pre_cont_signal_hook
  if [[ "${requested}" == "CONT" ]] &&
     ! _qcsd_revalidate_helper_source_identity; then
    return 1
  fi
  # Source validation executes stat/hash helpers.  Rebind the exact stopped
  # child after that interruptible work so no external command separates the
  # final PID/start/session/group proof from the builtin signal operation.
  if [[ "${requested}" == "CONT" ]] &&
     ! _qcsd_job_is_running \
        "${job_pid}" "${start_time}" "${session}" "${process_group}"; then
    return 1
  fi
  [[ "${requested}" != CONT || "${_qcsd_process_state}" == T ]] || return 1
  if [[ "${requested}" == "CONT" && "${requested_status:-0}" != "0" ]]; then
    return 1
  fi
  kill -"${requested}" "${job_pid}" 2>/dev/null
}

_qcsd_signal_bound_process_group() {
  local job_pid="$1"
  local start_time="$2"
  local session="$3"
  local process_group="$4"
  local requested="$5"
  local required_state="${6:-}"
  [[ -z "${required_state}" || "${required_state}" == T ]] || return 1
  [[ "${session}" == "${job_pid}" && "${process_group}" == "${job_pid}" ]] ||
    return 1
  # A numeric SID/PGID can be recycled after the bound leader exits.  Never
  # authenticate a process group by numbers alone; orphan descendants are
  # owned and terminated through the uniquely bound systemd scope instead.
  _qcsd_job_is_running \
    "${job_pid}" "${start_time}" "${session}" "${process_group}" || return 1
  [[ -z "${required_state}" || "${_qcsd_process_state}" == "${required_state}" ]] ||
    return 1
  kill -"${requested}" -- "-${process_group}" 2>/dev/null
}

_qcsd_supervisor_tail_hook() {
  # Test-only override point. Production intentionally does no work here; the
  # signal-latching traps remain installed through all recovery bookkeeping.
  :
}

_qcsd_build_after_scope_signal_check_hook() {
  # Test-only boundary hook; production performs no work.
  :
}

_qcsd_build_wait_ready_hook() {
  # Test-only observation point after bound publication is fully durable.
  :
}

_qcsd_run_wait_ready_hook() {
  # Test-only observation point after run publication is fully durable.
  :
}

_qcsd_handoff_retire_after_absence_hook() {
  # Test-only boundary hook; production performs no work.
  :
}

_qcsd_retirement_boundary_hook() {
  # Test-only H0-H13 crash/signal injection. Production performs no work and
  # callers never consume hook output as authority.
  :
}

_qcsd_retirement_native_op() {
  local native_path="${_QCSD_LIFECYCLE_NATIVE_PATH:-}"
  [[ "${native_path}" == /* && -f "${native_path}" && ! -L "${native_path}" &&
      "$(sha256sum -- "${native_path}" | awk '{print $1}')" == \
        "${_QCSD_LIFECYCLE_NATIVE_SHA256:-}" ]] || return 1
  /usr/bin/python3 -I "${native_path}" --lease \
    "${_QCSD_LIFECYCLE_LEASE_SOCKET}" "${_QCSD_LIFECYCLE_LEASE_NONCE}" \
    "${_QCSD_LIFECYCLE_QCSD_PID}" "${_QCSD_LIFECYCLE_QCSD_START}" \
    "${_QCSD_LIFECYCLE_HELPER_SHA256}" "${_QCSD_LIFECYCLE_LOCK_DEVICE}" \
    "${_QCSD_LIFECYCLE_LOCK_INODE}" "$@"
}

_qcsd_begin_lifecycle_root_creation() {
  local root_name="$1" base_meta ready ready_extra
  [[ "${root_name}" =~ ^(run|network|build|transaction)[.][0-9a-f]{32}$ &&
      -z "${_QCSD_CREATION_HOLDER_PID:-}" ]] || return 1
  base_meta="$(stat -Lc '%d:%i' -- "${_qcsd_lifecycle_base}")" || return 1
  _qcsd_read_process_identity "${BASHPID}" || return 1
  [[ "${BASHPID}" == "${_QCSD_LIFECYCLE_QCSD_PID:-}" &&
      "${_qcsd_process_start_time}" == "${_QCSD_LIFECYCLE_QCSD_START:-}" &&
      "${_qcsd_process_session}" == "${BASHPID}" &&
      "${_qcsd_process_group}" == "${BASHPID}" ]] || return 1
  coproc QCSD_CREATION_HOLDER {
    exec /usr/bin/python3 -I "${_QCSD_LIFECYCLE_NATIVE_PATH}" --lease \
      "${_QCSD_LIFECYCLE_LEASE_SOCKET}" "${_QCSD_LIFECYCLE_LEASE_NONCE}" \
      "${_QCSD_LIFECYCLE_QCSD_PID}" "${_QCSD_LIFECYCLE_QCSD_START}" \
      "${_QCSD_LIFECYCLE_HELPER_SHA256}" "${_QCSD_LIFECYCLE_LOCK_DEVICE}" \
      "${_QCSD_LIFECYCLE_LOCK_INODE}" hold-creation \
      "${_qcsd_lifecycle_base}" "${EUID}" "${base_meta%%:*}" \
      "${base_meta##*:}" "${root_name}" "${_QCSD_LIFECYCLE_QCSD_PID}" \
      "${_qcsd_process_start_time}" "${_qcsd_process_session}" \
      "${_qcsd_process_group}"
  }
  _QCSD_CREATION_HOLDER_PID="${QCSD_CREATION_HOLDER_PID}"
  _QCSD_CREATION_HOLDER_READ_FD="${QCSD_CREATION_HOLDER[0]}"
  _QCSD_CREATION_HOLDER_WRITE_FD="${QCSD_CREATION_HOLDER[1]}"
  IFS=' ' read -r ready _QCSD_CREATION_ROOT_DEVICE \
    _QCSD_CREATION_ROOT_INODE ready_extra \
    <&"${_QCSD_CREATION_HOLDER_READ_FD}" || exit 125
  [[ "${ready}" == QCSD-CREATION-HOLD-READY-V1 && -z "${ready_extra}" &&
      "${_QCSD_CREATION_ROOT_DEVICE}" =~ ^[0-9]+$ &&
      "${_QCSD_CREATION_ROOT_INODE}" =~ ^[0-9]+$ ]] || exit 125
}

_qcsd_commit_lifecycle_root_creation() {
  local status extra acknowledgement
  [[ "${_QCSD_CREATION_HOLDER_PID:-}" =~ ^[1-9][0-9]*$ &&
      "${_QCSD_CREATION_HOLDER_WRITE_FD:-}" =~ ^[0-9]+$ ]] || exit 125
  printf 'QCSD-CREATION-HOLD-COMMIT-V1\n' >&"${_QCSD_CREATION_HOLDER_WRITE_FD}" || exit 125
  eval "exec ${_QCSD_CREATION_HOLDER_WRITE_FD}>&-" || exit 125
  IFS= read -r acknowledgement <&"${_QCSD_CREATION_HOLDER_READ_FD}" || exit 125
  [[ "${acknowledgement}" == QCSD-CREATION-HOLD-COMMITTED-V1 ]] || exit 125
  if IFS= read -r extra <&"${_QCSD_CREATION_HOLDER_READ_FD}"; then exit 125; fi
  wait "${_QCSD_CREATION_HOLDER_PID}" || status=$?
  status="${status:-0}"
  if [[ "${_QCSD_CREATION_HOLDER_READ_FD:-}" =~ ^[0-9]+$ ]]; then
    eval "exec ${_QCSD_CREATION_HOLDER_READ_FD}<&-" || exit 125
  fi
  unset _QCSD_CREATION_HOLDER_PID _QCSD_CREATION_HOLDER_READ_FD
  unset _QCSD_CREATION_HOLDER_WRITE_FD _QCSD_CREATION_ROOT_DEVICE
  unset _QCSD_CREATION_ROOT_INODE QCSD_CREATION_HOLDER_PID
  (( status == 0 )) || exit 125
  return 0
}

_qcsd_cancel_lifecycle_root_creation() {
  local status extra acknowledgement
  [[ "${_QCSD_CREATION_HOLDER_PID:-}" =~ ^[1-9][0-9]*$ &&
      "${_QCSD_CREATION_HOLDER_WRITE_FD:-}" =~ ^[0-9]+$ ]] || exit 125
  printf 'QCSD-CREATION-HOLD-CANCEL-V1\n' >&"${_QCSD_CREATION_HOLDER_WRITE_FD}" || exit 125
  eval "exec ${_QCSD_CREATION_HOLDER_WRITE_FD}>&-" || exit 125
  IFS= read -r acknowledgement <&"${_QCSD_CREATION_HOLDER_READ_FD}" || exit 125
  [[ "${acknowledgement}" == QCSD-CREATION-HOLD-CANCELLED-V1 ]] || exit 125
  if IFS= read -r extra <&"${_QCSD_CREATION_HOLDER_READ_FD}"; then exit 125; fi
  wait "${_QCSD_CREATION_HOLDER_PID}" || status=$?
  status="${status:-0}"
  if [[ "${_QCSD_CREATION_HOLDER_READ_FD:-}" =~ ^[0-9]+$ ]]; then
    eval "exec ${_QCSD_CREATION_HOLDER_READ_FD}<&-" || exit 125
  fi
  unset _QCSD_CREATION_HOLDER_PID _QCSD_CREATION_HOLDER_READ_FD
  unset _QCSD_CREATION_HOLDER_WRITE_FD _QCSD_CREATION_ROOT_DEVICE
  unset _QCSD_CREATION_ROOT_INODE QCSD_CREATION_HOLDER_PID
  (( status == 0 )) || exit 125
  return 0
}


_qcsd_build_ensure_scope_interrupt() {
  if (( build_scope_required != 0 && scope_signal_attempted == 0 )); then
    scope_signal_attempted=1
    scope_signal_outcome="unknown"
    if _qcsd_kill_user_scope "${build_scope_unit}" INT; then
      scope_signal_outcome="accepted"
    fi
  fi
}

_qcsd_record_cli_force_result() {
  local outcome="$1"
  if [[ "${outcome}" == accepted ]]; then
    cli_forced=1
    cli_force_outcome=accepted
  elif (( cli_forced == 0 )); then
    cli_force_outcome=unknown
  fi
}

_qcsd_valid_user_systemd_unit() {
  local unit="$1"
  [[ "${unit}" =~ ^qcsd-docker-(api-[0-9a-f]{32}[.]service|(run|build)-[0-9a-f]{32}[.]scope)$ ]]
}

_qcsd_query_user_scope() {
  local unit="$1"
  local output line key value
  local load_count=0 active_count=0 group_count=0
  _qcsd_scope_state="unknown"
  _qcsd_scope_control_group="unavailable"
  _qcsd_scope_load=""
  _qcsd_scope_active=""
  _qcsd_scope_group=""
  _qcsd_valid_user_systemd_unit "${unit}" || return 1
  output="$(
    setsid timeout --signal=KILL \
      "${_QCSD_DOCKER_SCOPE_API_TIMEOUT_SECONDS}s" \
      systemctl --user show "${unit}" --no-pager \
      --property=LoadState --property=ActiveState --property=ControlGroup
  )" || return 1
  while IFS= read -r line || [[ -n "${line}" ]]; do
    key="${line%%=*}"
    value="${line#*=}"
    case "${key}" in
      LoadState) load_count=$((load_count + 1)); _qcsd_scope_load="${value}" ;;
      ActiveState) active_count=$((active_count + 1)); _qcsd_scope_active="${value}" ;;
      ControlGroup) group_count=$((group_count + 1)); _qcsd_scope_group="${value}" ;;
    esac
  done <<<"${output}"
  if (( load_count != 1 || active_count != 1 || group_count != 1 )); then
    return 1
  fi
  if [[ "${_qcsd_scope_load}" == "not-found" &&
        "${_qcsd_scope_active}" == "inactive" &&
        -z "${_qcsd_scope_group}" ]]; then
    _qcsd_scope_state="absent"
    return 0
  fi
  if [[ "${_qcsd_scope_load}" != "loaded" ]]; then
    return 1
  fi
  case "${_qcsd_scope_active}" in
    active|activating|deactivating)
      [[ "${_qcsd_scope_group}" == /*/"${unit}" ]] || return 1
      _qcsd_scope_control_group="${_qcsd_scope_group}"
      _qcsd_scope_state="active"
      ;;
    inactive|failed)
      if [[ -n "${_qcsd_scope_group}" ]]; then
        [[ "${_qcsd_scope_group}" == /*/"${unit}" ]] || return 1
        _qcsd_scope_control_group="${_qcsd_scope_group}"
      fi
      _qcsd_scope_state="inactive"
      ;;
    *) return 1 ;;
  esac
}

# Observe the complete cgroup subtree bound by an exact systemd unit.  The
# kernel's populated flag covers nested cgroups while cgroup.procs independently
# proves that the directly bound group is empty.  Any malformed or unreadable
# procfs/cgroupfs state is unknown and therefore cannot authorise cleanup.
_qcsd_observe_user_scope_cgroup() {
  local unit="$1"
  local control_group="$2"
  local cgroup_root events_path procs_path line key value remainder pid
  local populated_count=0 populated_value=""
  local -a event_lines=() member_pids=()
  _qcsd_scope_cgroup_observation="unknown"
  _qcsd_valid_user_systemd_unit "${unit}" || return 1
  [[ "${control_group}" == /*/"${unit}" &&
      "${control_group}" =~ ^/[A-Za-z0-9_.@:/-]+$ &&
      "${control_group}" != *"//"* &&
      "${control_group}" != *"/../"* &&
      "${control_group}" != */.. &&
      "${control_group}" != *"/./"* &&
      "${control_group}" != */. ]] || return 1
  cgroup_root="/sys/fs/cgroup${control_group}"
  events_path="${cgroup_root}/cgroup.events"
  procs_path="${cgroup_root}/cgroup.procs"
  [[ ! -L "${cgroup_root}" && -d "${cgroup_root}" &&
      ! -L "${events_path}" && -f "${events_path}" &&
      ! -L "${procs_path}" && -f "${procs_path}" ]] || return 1
  mapfile -t event_lines <"${events_path}" || return 1
  mapfile -t member_pids <"${procs_path}" || return 1
  for line in "${event_lines[@]}"; do
    key=""
    value=""
    remainder=""
    read -r key value remainder <<<"${line}"
    if [[ "${key}" == "populated" ]]; then
      populated_count=$((populated_count + 1))
      [[ -z "${remainder}" && "${value}" =~ ^[01]$ ]] || return 1
      populated_value="${value}"
    fi
  done
  (( populated_count == 1 )) || return 1
  for pid in "${member_pids[@]}"; do
    [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || return 1
  done
  if [[ "${populated_value}" == "1" ]] || (( ${#member_pids[@]} != 0 )); then
    _qcsd_scope_cgroup_observation="nonempty"
  else
    _qcsd_scope_cgroup_observation="empty"
  fi
}

_qcsd_stop_user_scope() {
  local unit="$1"
  _qcsd_valid_user_systemd_unit "${unit}" || return 1
  setsid timeout --signal=KILL \
    "${_QCSD_DOCKER_SCOPE_API_TIMEOUT_SECONDS}s" \
    systemctl --user stop -- "${unit}" >/dev/null 2>&1
}

_qcsd_reset_failed_user_scope() {
  local unit="$1"
  _qcsd_valid_user_systemd_unit "${unit}" || return 1
  setsid timeout --signal=KILL \
    "${_QCSD_DOCKER_SCOPE_API_TIMEOUT_SECONDS}s" \
    systemctl --user reset-failed -- "${unit}" >/dev/null 2>&1
}

_qcsd_wait_user_scope_inactive() {
  local unit="$1"
  local poll empty_snapshots=0 bound_control_group="" observation="unknown"
  _qcsd_valid_user_systemd_unit "${unit}" || return 1
  for (( poll = 0; poll < _QCSD_DOCKER_SCOPE_SETTLE_POLLS; poll++ )); do
    observation="unknown"
    if _qcsd_query_user_scope "${unit}"; then
      case "${_qcsd_scope_state}" in
        absent)
          observation="empty"
          ;;
        inactive)
          if [[ "${_qcsd_scope_control_group}" == "unavailable" ]]; then
            observation="empty"
          elif [[ -z "${bound_control_group}" ||
                  "${bound_control_group}" == \
                    "${_qcsd_scope_control_group}" ]]; then
            bound_control_group="${_qcsd_scope_control_group}"
            if _qcsd_observe_user_scope_cgroup \
                "${unit}" "${bound_control_group}"; then
              observation="${_qcsd_scope_cgroup_observation}"
            fi
          fi
          ;;
        active)
          if [[ -z "${bound_control_group}" ||
                "${bound_control_group}" == \
                  "${_qcsd_scope_control_group}" ]]; then
            bound_control_group="${_qcsd_scope_control_group}"
            if _qcsd_observe_user_scope_cgroup \
                "${unit}" "${bound_control_group}"; then
              observation="${_qcsd_scope_cgroup_observation}"
            fi
          fi
          ;;
      esac
    fi
    if [[ "${observation}" == "empty" ]]; then
      empty_snapshots=$((empty_snapshots + 1))
      if (( empty_snapshots >= 2 )); then
        if [[ "${_qcsd_scope_state}" == "active" ]]; then
          # A killed systemd-run launcher can orphan an active scope after its
          # cgroup is already empty.  Stop the exact empty unit so it cannot be
          # mistaken for a live owner, then require a fresh two-observation
          # inactive/absent proof.
          _qcsd_stop_user_scope "${unit}" || {
            _qcsd_query_user_scope "${unit}" &&
              [[ "${_qcsd_scope_state}" == "inactive" ||
                 "${_qcsd_scope_state}" == "absent" ]] || return 1
          }
          empty_snapshots=0
          bound_control_group=""
        elif [[ "${_qcsd_scope_active}" == "failed" ]]; then
          _qcsd_reset_failed_user_scope "${unit}" || {
            _qcsd_query_user_scope "${unit}" &&
              [[ "${_qcsd_scope_state}" == "absent" ]] || return 1
          }
          empty_snapshots=0
          bound_control_group=""
        else
          return 0
        fi
      fi
    else
      empty_snapshots=0
    fi
    sleep "${_QCSD_DOCKER_SCOPE_SETTLE_DELAY_SECONDS}" || true
  done
  return 1
}

_qcsd_kill_user_scope() {
  local unit="$1"
  local requested="$2"
  _qcsd_valid_user_systemd_unit "${unit}" || return 1
  [[ "${requested}" == "INT" || "${requested}" == "KILL" ]] || return 1
  setsid timeout --signal=KILL \
    "${_QCSD_DOCKER_SCOPE_API_TIMEOUT_SECONDS}s" \
    systemctl --user kill --kill-whom=all --signal="${requested}" \
      "${unit}" >/dev/null 2>&1
}

# Execute one Docker client operation in a transient user service whose
# lifetime is the entire cgroup, not merely the direct CLI PID.  ExitType=cgroup
# means a daemonising/setsid descendant cannot turn a completed parent into a
# successful call, while RuntimeMaxSec and the outer client bound guarantee a
# finite return even when that descendant retains stdout or stderr.
_qcsd_docker_api_service_with_timeout() {
  local duration="$1"
  shift
  if [[ "$-" == *m* ]]; then
    echo "Docker API supervisor rejects shell monitor mode" >&2
    return 2
  fi
  if [[ ! "${duration}" =~ ^[1-9][0-9]*$ ]] ||
     (( $# == 0 )) || ! _qcsd_require_user_cgroup_manager; then
    echo "Docker API supervisor requires a positive timeout and user-systemd cgroup v2" >&2
    return 125
  fi
  local token unit base_meta api_status
  token="$(_qcsd_supervisor_token)"
  unit="qcsd-docker-api-${token}.service"
  if [[ ! "${unit}" =~ ^qcsd-docker-api-[0-9a-f]{32}[.]service$ ]] ||
     ! _qcsd_query_user_scope "${unit}" ||
     [[ "${_qcsd_scope_state}" != "absent" ]]; then
    echo "Docker API supervisor cannot reserve a unique user-systemd service" >&2
    return 125
  fi

  base_meta="$(stat -Lc '%d:%i' -- "${_qcsd_lifecycle_base}")" || return 125
  if _qcsd_retirement_native_op hold-api-service \
      "${_qcsd_lifecycle_base}" "${EUID}" "${base_meta%%:*}" \
      "${base_meta##*:}" "${unit}" "${duration}" \
      "${_QCSD_LIFECYCLE_QCSD_PID}" "${_QCSD_LIFECYCLE_QCSD_START}" \
      "${_QCSD_LIFECYCLE_QCSD_PID}" "${_QCSD_LIFECYCLE_QCSD_PID}" \
      "${_QCSD_LIFECYCLE_NATIVE_SHA256}" -- "$@"; then
    api_status=0
  else
    api_status=$?
  fi
  return "${api_status}"
}

_qcsd_registration_remove_id() {
  local registration_name="$1"
  local cid="$2"
  local -n registration_ref="${registration_name}"
  local -a retained=()
  local registered_cid
  for registered_cid in "${registration_ref[@]:-}"; do
    [[ "${registered_cid}" == "${cid}" ]] || retained+=("${registered_cid}")
  done
  registration_ref=("${retained[@]}")
  unset -n registration_ref
}

_qcsd_docker_exact_network_presence_detailed() {
  local network_id="$1"
  local output line
  local -a ids=()
  if ! output="$(_qcsd_target_docker_api network ls --no-trunc \
      --filter "id=${network_id}" --format '{{.ID}}' 2>/dev/null)"; then
    printf 'unknown\n'
    return 0
  fi
  while IFS= read -r line; do
    [[ -z "${line}" ]] || ids+=("${line}")
  done <<<"${output}"
  if (( ${#ids[@]} == 0 )); then
    printf 'absent\n'
  elif (( ${#ids[@]} == 1 )) && [[ "${ids[0]}" == "${network_id}" ]]; then
    printf 'present\n'
  else
    printf 'ambiguous\n'
  fi
}

_qcsd_docker_exact_network_presence() {
  local presence
  presence="$(_qcsd_docker_exact_network_presence_detailed "$1")" || {
    printf 'unknown\n'
    return 0
  }
  [[ "${presence}" != ambiguous ]] || presence=unknown
  printf '%s\n' "${presence}"
}

_qcsd_docker_network_state() {
  local network_id="$1"
  local token="$2"
  local presence output
  presence="$(_qcsd_docker_exact_network_presence "${network_id}")"
  if [[ "${presence}" != "present" ]]; then
    printf '%s\n' "${presence}"
    return 0
  fi
  if ! output="$(_qcsd_target_docker_api network inspect --format \
      '{{.Id}}|{{index .Labels "org.qcsd.supervisor.instance"}}' \
      "${network_id}" 2>/dev/null)"; then
    printf 'unknown\n'
  elif [[ "${output}" == "${network_id}|${token}" ]]; then
    printf 'present\n'
  else
    printf 'unknown\n'
  fi
}

_qcsd_resolve_docker_network() {
  local token="$1"
  local preferred_id="$2"
  local output line
  local -a ids=()
  _qcsd_resolved_network_state="unknown"
  _qcsd_resolved_network_id=""
  if [[ "${preferred_id}" =~ ^[0-9a-f]{64}$ ]]; then
    _qcsd_resolved_network_id="${preferred_id}"
    _qcsd_resolved_network_state="$(_qcsd_docker_network_state \
      "${preferred_id}" "${token}")"
    return 0
  fi
  if ! output="$(_qcsd_target_docker_api network ls --no-trunc \
      --filter "label=${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}=${token}" \
      --format '{{.ID}}' 2>/dev/null)"; then
    return 0
  fi
  while IFS= read -r line; do
    [[ -z "${line}" ]] || ids+=("${line}")
  done <<<"${output}"
  if (( ${#ids[@]} == 0 )); then
    _qcsd_resolved_network_state="absent"
  elif (( ${#ids[@]} == 1 )) && [[ "${ids[0]}" =~ ^[0-9a-f]{64}$ ]]; then
    _qcsd_resolved_network_id="${ids[0]}"
    _qcsd_resolved_network_state="$(_qcsd_docker_network_state \
      "${ids[0]}" "${token}")"
  fi
}

qcsd_create_docker_network() {
  local registration_name="$1"
  local _qcsd_target_docker_context="${DOCKER_CONTEXT:-}"
  shift
  if [[ "$-" == *m* ]]; then
    echo "Docker network supervisor rejects shell monitor mode" >&2
    return 2
  fi
  if (( $# < 4 )) ||
     [[ "$1" != "docker" || "$2" != "network" || "$3" != "create" ]]; then
    echo "Docker network supervisor requires an exact docker network create argv" >&2
    return 2
  fi
  if ! _qcsd_mutable_id_array "${registration_name}"; then
    echo "Docker network supervision requires an indexed cleanup array" >&2
    return 2
  fi
  if [[ ! "${_qcsd_target_docker_context}" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo "Docker network supervision requires a caller-pinned DOCKER_CONTEXT" >&2
    return 2
  fi
  if ! command -v setsid >/dev/null 2>&1 ||
     ! command -v timeout >/dev/null 2>&1 ||
     ! command -v od >/dev/null 2>&1 ||
     ! command -v readlink >/dev/null 2>&1 ||
     ! command -v sha256sum >/dev/null 2>&1 ||
     ! command -v stat >/dev/null 2>&1 ||
     ! command -v sync >/dev/null 2>&1 ||
     ! command -v mkfifo >/dev/null 2>&1; then
    echo "Docker network supervisor host primitives are unavailable" >&2
    return 1
  fi
  local argument previous=""
  for argument in "$@"; do
    if [[ "${argument}" == "--label-file" ||
          "${argument}" == --label-file=* ||
          "${argument}" == "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" ||
          "${argument}" == "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}="* ||
          "${argument}" == --label="${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" ||
          "${argument}" == --label="${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}="* ||
          "${argument}" == -l"${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" ||
          "${argument}" == -l"${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}="* ||
          "${argument}" == -l="${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" ||
          "${argument}" == -l="${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}="* ||
          "${argument}" =~ ^-[A-Za-z]*l=?org[.]qcsd[.]supervisor[.]instance(=|$) ]] ||
       { [[ "${previous}" == "--label" || "${previous}" == "-l" ||
             "${previous}" =~ ^-[A-Za-z]*l$ ]] &&
         [[ "${argument}" == "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" ||
             "${argument}" == "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}="* ]]; }; then
      echo "Docker network supervisor owns its private instance label" >&2
      return 2
    fi
    previous="${argument}"
  done
  if ! _qcsd_verify_pinned_docker_daemon ||
     ! _qcsd_verify_pinned_host_boot; then
    echo "Docker network supervisor cannot verify its pinned daemon identity" >&2
    return 1
  fi
  if [[ "${_qcsd_target_docker_context}" != \
        "${_QCSD_DOCKER_PINNED_CONTEXT}" ]]; then
    echo "Docker network supervisor context differs from its pinned host binding" >&2
    return 2
  fi
  if ! _qcsd_bind_helper_source_identity ||
     ! _qcsd_secure_lifecycle_base; then
    echo "Docker network supervisor cannot bind durable lifecycle state" >&2
    return 1
  fi

  local caller_had_errexit=0
  if [[ "$-" == *e* ]]; then
    caller_had_errexit=1
    set +e
  fi
  local network_boot_id=""
  IFS= read -r network_boot_id </proc/sys/kernel/random/boot_id ||
    network_boot_id=""
  if [[ ! "${network_boot_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "cannot bind the Docker network host boot identity" >&2
    (( caller_had_errexit )) && set -e
    return 1
  fi
  local saved_hup saved_int saved_quit saved_term
  local requested_signal="" requested_status=0
  saved_hup="$(trap -p HUP || true)"
  saved_int="$(trap -p INT || true)"
  saved_quit="$(trap -p QUIT || true)"
  saved_term="$(trap -p TERM || true)"
  trap '_qcsd_latch_requested_signal HUP 129' HUP
  trap '_qcsd_latch_requested_signal INT 130' INT
  trap '_qcsd_latch_requested_signal QUIT 131' QUIT
  trap '_qcsd_latch_requested_signal TERM 143' TERM
  local supervisor_pid supervisor_start_time supervisor_session
  local supervisor_process_group
  if ! _qcsd_bind_current_supervisor_identity; then
    echo "cannot bind the Docker network supervising shell identity" >&2
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  supervisor_pid="${_qcsd_bound_supervisor_pid}"
  supervisor_start_time="${_qcsd_bound_supervisor_start_time}"
  supervisor_session="${_qcsd_bound_supervisor_session}"
  supervisor_process_group="${_qcsd_bound_supervisor_process_group}"
  local supervisor_root token network_id="" network_state="unknown"
  local supervision_next recovery_next handoff_next request_argv_sha256
  local lifecycle_state="declared"
  token="$(_qcsd_supervisor_token)"
  if [[ -z "${token}" ]] ||
     ! _qcsd_create_lifecycle_root network "${token}"; then
    echo "cannot establish a private Docker network supervisor identity" >&2
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  supervisor_root="${_qcsd_lifecycle_root}"
  supervision_next="${supervisor_root}/SUPERVISION.next"
  recovery_next="${supervisor_root}/RECOVERY.next"
  handoff_next="${supervisor_root}/HANDOFF.next"
  request_argv_sha256="$(
    printf '%s\0' docker network create --label \
      "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}=${token}" "${@:4}" |
      sha256sum | awk '{print $1}'
  )"
  if [[ ! "${request_argv_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "cannot bind the Docker network request identity" >&2
    _qcsd_cancel_lifecycle_root_creation || true
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  if ! {
    printf 'object=network\n'
    _qcsd_print_lifecycle_identity
    _qcsd_print_bound_supervisor_identity
    printf 'network_id=unavailable\n'
    printf 'docker_context=%s\n' "${_qcsd_target_docker_context}"
    _qcsd_print_docker_binding
    printf 'docker_daemon_id=%s\n' \
      "${_QCSD_DOCKER_PINNED_SERVER_ID:-unavailable}"
    printf 'host_boot_id=%s\n' "${network_boot_id}"
    printf 'supervisor_label=%s=%s\n' \
      "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" "${token}"
    printf 'request_argv_sha256=%s\n' "${request_argv_sha256}"
    printf 'requested_signal=none\n'
    printf 'network_state=launching\n'
  } >"${supervision_next}"; then
    _qcsd_cancel_lifecycle_root_creation || return 1
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  _QCSD_PUBLISH_REPLACED=0
  if ! _qcsd_publish_supervision_file \
      "${supervision_next}" "${supervisor_root}/SUPERVISION"; then
    echo "cannot secure the Docker network supervisor identity" >&2
    if (( _QCSD_PUBLISH_REPLACED != 0 )); then
      _qcsd_commit_lifecycle_root_creation || true
    else
      _qcsd_cancel_lifecycle_root_creation || true
    fi
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi

  _qcsd_commit_lifecycle_root_creation || return 1

  local output="" create_status=0 cleanup_failure=0 teardown_unresolved=0
  local registered=0 poll launch_attempted=0
  if (( requested_status == 0 )); then
    lifecycle_state="request-authorised"
    {
      printf 'object=network\n'
      _qcsd_print_lifecycle_identity
      _qcsd_print_bound_supervisor_identity
      printf 'network_id=unavailable\n'
      printf 'docker_context=%s\n' "${_qcsd_target_docker_context}"
      _qcsd_print_docker_binding
      printf 'docker_daemon_id=%s\n' "${_QCSD_DOCKER_PINNED_SERVER_ID}"
      printf 'host_boot_id=%s\n' "${network_boot_id}"
      printf 'supervisor_label=%s=%s\n' \
        "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" "${token}"
      printf 'request_argv_sha256=%s\n' "${request_argv_sha256}"
      printf 'requested_signal=none\n'
      printf 'network_state=launching\n'
    } >"${supervision_next}"
    # Publication may fail after rename/fsync; its replacement outcome below
    # distinguishes a still-declared request from durable request authority.
    if ! _qcsd_publish_supervision_file \
        "${supervision_next}" "${supervisor_root}/SUPERVISION"; then
      (( _QCSD_PUBLISH_REPLACED == 0 )) || launch_attempted=1
      echo "cannot authorise the Docker network request durably" >&2
      create_status=1
      cleanup_failure=1
      network_state="absent"
    else
      launch_attempted=1
      release_record_sha="$(sha256sum -- "${supervisor_root}/SUPERVISION" | awk '{print $1}')" ||
        release_record_sha=""
      _qcsd_pre_mutation_release_hook network "${supervisor_root}"
      if [[ ! "${release_record_sha}" =~ ^[0-9a-f]{64}$ ]] ||
         ! _qcsd_revalidate_release_record \
           "${supervisor_root}" network "${release_record_sha}"; then
        create_status=1
        cleanup_failure=1
        teardown_unresolved=1
      elif (( requested_status != 0 )); then
        create_status="${requested_status}"
        teardown_unresolved=1
      else
        output="$(_qcsd_target_docker_api network create \
          --label "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}=${token}" "${@:4}")"
        create_status=$?
      fi
    fi
  else
    create_status="${requested_status}"
    network_state="absent"
  fi
  if [[ "${output}" =~ ^[0-9a-f]{64}$ ]]; then
    network_id="${output}"
  fi
  if (( launch_attempted != 0 )); then
    for (( poll = 0; poll < 3; poll++ )); do
      _qcsd_resolve_docker_network "${token}" "${network_id}"
      network_state="${_qcsd_resolved_network_state}"
      [[ -n "${_qcsd_resolved_network_id}" ]] &&
        network_id="${_qcsd_resolved_network_id}"
      [[ "${network_state}" == "present" ]] && break
      sleep 0.1 || true
    done
  fi

  if (( requested_status != 0 || create_status != 0 )); then
    if (( launch_attempted != 0 )) && [[ -z "${network_id}" ]]; then
      # A timed-out/interrupted client cannot prove the daemon abandoned the
      # create request merely because the private label is not visible yet.
      teardown_unresolved=1
    fi
    if [[ "${network_state}" == "present" ]]; then
      _qcsd_target_docker_api network rm "${network_id}" >/dev/null 2>&1 || true
      network_state="$(_qcsd_docker_exact_network_presence "${network_id}")"
    fi
    [[ "${network_state}" == "absent" ]] || teardown_unresolved=1
  elif [[ "${network_state}" != "present" || -z "${network_id}" ]]; then
    teardown_unresolved=1
  else
    lifecycle_state="bound"
    {
      printf 'object=network\n'
      _qcsd_print_lifecycle_identity
      _qcsd_print_bound_supervisor_identity
      printf 'network_id=%s\n' "${network_id}"
      printf 'docker_context=%s\n' "${_qcsd_target_docker_context}"
      _qcsd_print_docker_binding
      printf 'docker_daemon_id=%s\n' "${_QCSD_DOCKER_PINNED_SERVER_ID}"
      printf 'host_boot_id=%s\n' "${network_boot_id}"
      printf 'supervisor_label=%s=%s\n' \
        "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" "${token}"
      printf 'request_argv_sha256=%s\n' "${request_argv_sha256}"
      printf 'requested_signal=%s\n' "${requested_signal:-none}"
      printf 'network_state=present\n'
    } >"${supervision_next}"
    if ! _qcsd_publish_supervision_file \
        "${supervision_next}" "${supervisor_root}/SUPERVISION"; then
      echo "cannot bind the Docker network identity durably" >&2
      cleanup_failure=1
      teardown_unresolved=1
    else
      local -n registration="${registration_name}"
      for argument in "${registration[@]:-}"; do
        [[ "${argument}" != "${network_id}" ]] || cleanup_failure=1
      done
      if (( cleanup_failure == 0 )); then
        registration+=("${network_id}")
        registered=1
      fi
      unset -n registration
    fi
    if (( registered != 0 )); then
      lifecycle_state="handed-off"
      {
        printf 'object=network\n'
        _qcsd_print_lifecycle_identity
        _qcsd_print_bound_supervisor_identity
        printf 'network_id=%s\n' "${network_id}"
        printf 'docker_context=%s\n' "${_qcsd_target_docker_context}"
        _qcsd_print_docker_binding
        printf 'docker_daemon_id=%s\n' "${_QCSD_DOCKER_PINNED_SERVER_ID}"
        printf 'host_boot_id=%s\n' "${network_boot_id}"
        printf 'supervisor_label=%s=%s\n' \
          "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" "${token}"
        printf 'request_argv_sha256=%s\n' "${request_argv_sha256}"
        printf 'ownership=caller-cleanup-array\n'
        printf 'registration_name=%s\n' "${registration_name}"
        printf 'requested_signal=%s\n' "${requested_signal:-none}"
        printf 'network_state=present\n'
      } >"${handoff_next}"
      if ! _qcsd_publish_supervision_file \
          "${handoff_next}" "${supervisor_root}/HANDOFF"; then
        echo "cannot publish the Docker network ownership handoff" >&2
        cleanup_failure=1
        teardown_unresolved=1
      fi
    fi
  fi

  # Keep the latching traps live through bookkeeping. A late signal either is
  # drained here or is returned to the caller with the exact ID still present
  # in its cleanup array.
  _qcsd_supervisor_tail_hook
  if (( requested_status != 0 && registered != 0 )); then
    network_state="$(_qcsd_docker_network_state "${network_id}" "${token}")"
    if [[ "${network_state}" == "present" ]]; then
      _qcsd_target_docker_api network rm "${network_id}" >/dev/null 2>&1 || true
      network_state="$(_qcsd_docker_exact_network_presence "${network_id}")"
    fi
    if [[ "${network_state}" == "absent" ]]; then
      _qcsd_registration_remove_id "${registration_name}" "${network_id}"
      registered=0
    else
      teardown_unresolved=1
    fi
  fi

  if (( teardown_unresolved != 0 )); then
    lifecycle_state="unresolved"
    {
      printf 'object=network\n'
      _qcsd_print_lifecycle_identity
      _qcsd_print_bound_supervisor_identity
      printf 'network_id=%s\n' "${network_id:-unavailable}"
      printf 'docker_context=%s\n' "${_qcsd_target_docker_context}"
      _qcsd_print_docker_binding
      printf 'docker_daemon_id=%s\n' \
        "${_QCSD_DOCKER_PINNED_SERVER_ID:-unavailable}"
      printf 'host_boot_id=%s\n' "${network_boot_id}"
      printf 'supervisor_label=%s=%s\n' \
        "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" "${token}"
      printf 'request_argv_sha256=%s\n' "${request_argv_sha256}"
      printf 'requested_signal=%s\n' "${requested_signal:-none}"
      printf 'network_state=%s\n' "${network_state}"
      printf 'daemon_request_authorised=%s\n' "${launch_attempted}"
    } >"${recovery_next}"
    if _qcsd_publish_supervision_file \
        "${recovery_next}" "${supervisor_root}/RECOVERY"; then
      rm -f -- "${supervisor_root}/SUPERVISION" \
        "${supervisor_root}/HANDOFF"
    else
      echo "cannot secure the Docker network recovery record" >&2
      cleanup_failure=1
    fi
    echo "Docker network teardown is unresolved; preserving ${supervisor_root}" >&2
  elif (( registered != 0 )); then
    rm -f -- "${supervision_next}" "${recovery_next}" "${handoff_next}" \
      "${supervisor_root}/SUPERVISION" "${supervisor_root}/RECOVERY"
    if [[ ! -f "${supervisor_root}/HANDOFF" ]] ||
       ! sync -f "${supervisor_root}"; then
      echo "Docker network handoff ledger is not durable" >&2
      cleanup_failure=1
    fi
  else
    _qcsd_lifecycle_retire_completed_root "${supervisor_root}" || cleanup_failure=1
  fi
  _qcsd_restore_signal_trap "${saved_hup}" HUP
  _qcsd_restore_signal_trap "${saved_int}" INT
  _qcsd_restore_signal_trap "${saved_quit}" QUIT
  _qcsd_restore_signal_trap "${saved_term}" TERM

  local final_status="${create_status}"
  if (( requested_status != 0 )); then
    final_status="${requested_status}"
  elif (( create_status == 0 && (cleanup_failure != 0 || teardown_unresolved != 0) )); then
    final_status=1
  fi
  (( caller_had_errexit )) && set -e
  return "${final_status}"
}

_qcsd_run_docker_supervised() {
  local mode="$1"
  local registration_name="$2"
  local output_capture_name="$3"
  shift 3
  if [[ "${mode}" != "attached" && "${mode}" != "detached" ]]; then
    echo "Docker supervisor mode must be attached or detached" >&2
    return 2
  fi
  if [[ "$-" == *m* ]]; then
    echo "Docker supervisor rejects shell monitor mode" >&2
    return 2
  fi
  local run_option_offset=0
  local _qcsd_target_docker_context=""
  if (( $# >= 3 )) && [[ "$1" == "docker" && "$2" == "run" ]]; then
    run_option_offset=3
  elif (( $# >= 5 )) && [[ "$1" == "docker" && "$2" == "--context" &&
                            -n "$3" && "$4" == "run" ]]; then
    run_option_offset=5
    _qcsd_target_docker_context="$3"
  else
    echo "Docker supervisor requires an exact docker [--context NAME] run argv" >&2
    return 2
  fi
  if [[ "${mode}" == "detached" ]]; then
    if (( run_option_offset == 5 )); then
      echo "Detached Docker supervision requires the caller-pinned current context" >&2
      return 2
    fi
    if ! _qcsd_mutable_id_array "${registration_name}"; then
      echo "Detached Docker supervision requires an indexed cleanup array" >&2
      return 2
    fi
  fi
  if [[ -n "${output_capture_name}" ]] &&
     { [[ "${mode}" != "attached" ]] ||
       ! _qcsd_mutable_output_scalar "${output_capture_name}"; }; then
    echo "Docker stdout capture requires an existing safe caller variable" >&2
    return 2
  fi
  if ! command -v setsid >/dev/null 2>&1 ||
     ! command -v timeout >/dev/null 2>&1 ||
     ! command -v od >/dev/null 2>&1 ||
     ! command -v readlink >/dev/null 2>&1 ||
     ! command -v sha256sum >/dev/null 2>&1 ||
     ! command -v stat >/dev/null 2>&1 ||
     ! command -v sync >/dev/null 2>&1 ||
     ! _qcsd_require_user_cgroup_manager; then
    echo "Docker supervisor host primitives are unavailable" >&2
    return 1
  fi
  if [[ -z "${_qcsd_target_docker_context}" ]]; then
    _qcsd_target_docker_context="$(_qcsd_docker_api context show 2>/dev/null)"
  fi
  if [[ ! "${_qcsd_target_docker_context}" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo "Docker supervisor cannot pin one safe Docker context" >&2
    return 1
  fi
  if [[ -n "${_QCSD_DOCKER_PINNED_HOST:-}" &&
        "${_qcsd_target_docker_context}" != \
          "${_QCSD_DOCKER_PINNED_CONTEXT:-}" ]]; then
    echo "Docker supervisor context differs from its pinned host binding" >&2
    return 2
  fi
  local argument previous=""
  for argument in "$@"; do
    if [[ "${argument}" == "--rm" ||
          "${argument}" == --rm=* ||
          "${argument}" == "--detach" ||
          "${argument}" == --detach=* ||
          "${argument}" =~ ^-[^-]*d[^-]*$ ||
          "${argument}" == "--cidfile" ||
          "${argument}" == --cidfile=* ||
          "${argument}" == "--sig-proxy" ||
          "${argument}" == --sig-proxy=* ||
          "${argument}" == "--label-file" ||
          "${argument}" == --label-file=* ||
          "${argument}" == "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" ||
          "${argument}" == "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}="* ||
          "${argument}" == --label="${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" ||
          "${argument}" == --label="${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}="* ||
          "${argument}" == -l"${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" ||
          "${argument}" == -l"${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}="* ||
          "${argument}" == -l="${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" ||
          "${argument}" == -l="${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}="* ||
          "${argument}" =~ ^-[A-Za-z]*l=?org[.]qcsd[.]supervisor[.]instance(=|$) ]] ||
       { [[ "${previous}" == "--label" || "${previous}" == "-l" ||
             "${previous}" =~ ^-[A-Za-z]*l$ ]] &&
         [[ "${argument}" == "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" ||
             "${argument}" == "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}="* ]]; }; then
      echo "Docker supervisor owns lifecycle, cidfile, signal-proxy, and instance-label policy" >&2
      return 2
    fi
    previous="${argument}"
  done
  if [[ "${mode}" == "detached" ]]; then
    if [[ -z "${DOCKER_CONTEXT:-}" ||
          "${DOCKER_CONTEXT}" != "${_qcsd_target_docker_context}" ]]; then
      echo "Detached Docker supervision requires DOCKER_CONTEXT to remain pinned for cleanup" >&2
      return 2
    fi
  fi
  if ! _qcsd_verify_pinned_docker_daemon ||
     ! _qcsd_verify_pinned_host_boot; then
    echo "Docker supervisor cannot verify its pinned daemon identity" >&2
    return 1
  fi
  if ! _qcsd_bind_helper_source_identity ||
     ! _qcsd_secure_lifecycle_base; then
    echo "Docker supervisor cannot bind durable lifecycle state" >&2
    return 1
  fi

  local caller_had_errexit=0
  if [[ "$-" == *e* ]]; then
    caller_had_errexit=1
    set +e
  fi
  local saved_hup saved_int saved_quit saved_term
  local requested_signal="" requested_status=0
  saved_hup="$(trap -p HUP || true)"
  saved_int="$(trap -p INT || true)"
  saved_quit="$(trap -p QUIT || true)"
  saved_term="$(trap -p TERM || true)"
  trap '_qcsd_latch_requested_signal HUP 129' HUP
  trap '_qcsd_latch_requested_signal INT 130' INT
  trap '_qcsd_latch_requested_signal QUIT 131' QUIT
  trap '_qcsd_latch_requested_signal TERM 143' TERM
  local supervisor_pid supervisor_start_time supervisor_session
  local supervisor_process_group
  if ! _qcsd_bind_current_supervisor_identity; then
    echo "cannot bind the Docker run supervising shell identity" >&2
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  supervisor_pid="${_qcsd_bound_supervisor_pid}"
  supervisor_start_time="${_qcsd_bound_supervisor_start_time}"
  supervisor_session="${_qcsd_bound_supervisor_session}"
  supervisor_process_group="${_qcsd_bound_supervisor_process_group}"
  local supervisor_root cidfile token output_capture_path="" supervision_next
  local recovery_next handoff_next run_status_path run_status_next
  local run_argv_sha256 lifecycle_state="declared" daemon_request_authorised=0
  local run_scope_token run_scope_unit run_scope_control_group="unavailable"
  local run_scope_final_state="unavailable" run_scope_empty_proven=0
  local run_scope_leak_detected=0 run_scope_kill_attempted=0
  local run_scope_kill_outcome="not_attempted"
  local run_scope_checked=0
  local run_status_state="declared" run_status_matches=0
  local systemd_run_status="unavailable" docker_run_status="unavailable"
  local observed_run_status="" run_boot_id=""
  run_scope_token="$(_qcsd_supervisor_token)"
  token="${run_scope_token}"
  IFS= read -r run_boot_id </proc/sys/kernel/random/boot_id || run_boot_id=""
  run_scope_unit="qcsd-docker-run-${run_scope_token}.scope"
  if [[ ! "${run_boot_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ||
        ! "${run_scope_unit}" =~ ^qcsd-docker-run-[0-9a-f]{32}[.]scope$ ]] ||
     ! _qcsd_query_user_scope "${run_scope_unit}" ||
     [[ "${_qcsd_scope_state}" != "absent" ]]; then
    echo "Docker supervisor cannot reserve a unique user-systemd scope" >&2
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  if [[ -z "${token}" ]] ||
     ! _qcsd_create_lifecycle_root run "${token}"; then
    echo "cannot establish a private Docker supervisor identity" >&2
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  supervisor_root="${_qcsd_lifecycle_root}"
  cidfile="${supervisor_root}/container.cid"
  supervision_next="${supervisor_root}/SUPERVISION.next"
  recovery_next="${supervisor_root}/RECOVERY.next"
  handoff_next="${supervisor_root}/HANDOFF.next"
  run_status_path="${supervisor_root}/run.status"
  run_status_next="${run_status_path}.next"
  local wait_pipe="${supervisor_root}/wait.pipe"
  local wait_fd
  if ! mkfifo -m 600 -- "${wait_pipe}" ||
     ! exec {wait_fd}<>"${wait_pipe}"; then
    echo "cannot establish the private Docker wait channel" >&2
    _qcsd_cancel_lifecycle_root_creation || true
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  if [[ -n "${output_capture_name}" ]]; then
    output_capture_path="${supervisor_root}/stdout"
    : >"${output_capture_path}"
    if ! _qcsd_secure_supervision_file "${output_capture_path}"; then
      echo "cannot secure the Docker stdout capture" >&2
      exec {wait_fd}>&-
      _qcsd_cancel_lifecycle_root_creation || true
      _qcsd_restore_signal_trap "${saved_hup}" HUP
      _qcsd_restore_signal_trap "${saved_int}" INT
      _qcsd_restore_signal_trap "${saved_quit}" QUIT
      _qcsd_restore_signal_trap "${saved_term}" TERM
      (( caller_had_errexit )) && set -e
      return 1
    fi
  fi

  local -a command
  if [[ -n "${_QCSD_DOCKER_PINNED_HOST:-}" ]]; then
    command=(docker --host "${_QCSD_DOCKER_PINNED_HOST}")
  else
    command=(docker --context "${_qcsd_target_docker_context}")
  fi
  command+=(
    run --cidfile "${cidfile}" --sig-proxy=false
    --label "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}=${token}"
  )
  if [[ "${mode}" == "attached" ]]; then
    command+=(--rm)
  else
    command+=(--detach)
  fi
  command+=("${@:${run_option_offset}}")
  run_argv_sha256="$(printf '%s\0' "${command[@]}" |
    sha256sum | awk '{print $1}')"
  if [[ ! "${run_argv_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "cannot bind the Docker run request identity" >&2
    exec {wait_fd}>&-
    _qcsd_cancel_lifecycle_root_creation || true
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  if ! {
    printf 'object=docker-run-scope-launcher\n'
    printf 'process_identity_role=local-systemd-run-scope-launcher\n'
    _qcsd_print_lifecycle_identity
    _qcsd_print_bound_supervisor_identity
    printf 'mode=%s\n' "${mode}"
    printf 'scope_launcher_pid=unavailable\n'
    printf 'scope_launcher_start_time=unavailable\n'
    printf 'scope_launcher_session=unavailable\n'
    printf 'scope_launcher_process_group=unavailable\n'
    printf 'cli_pid=unavailable\n'
    printf 'cli_start_time=unavailable\n'
    printf 'cli_session=unavailable\n'
    printf 'cli_process_group=unavailable\n'
    printf 'container_id=unavailable\n'
    printf 'docker_context=%s\n' "${_qcsd_target_docker_context}"
    _qcsd_print_docker_binding
    printf 'docker_daemon_id=%s\n' \
      "${_QCSD_DOCKER_PINNED_SERVER_ID:-unavailable}"
    printf 'supervisor_label=%s=%s\n' \
      "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" "${token}"
    printf 'request_argv_sha256=%s\n' "${run_argv_sha256}"
    printf 'scope_required=1\n'
    printf 'scope_unit=%s\n' "${run_scope_unit}"
    printf 'scope_control_group=unavailable\n'
    printf 'scope_state=declared\n'
    printf 'host_boot_id=%s\n' "${run_boot_id}"
    printf 'status_file=%s\n' "${run_status_path}"
    printf 'status_file_state=declared\n'
    printf 'requested_signal=none\n'
    printf 'forwarded_target_signal=none\n'
    printf 'target_state=launching\n'
  } >"${supervision_next}"; then
    exec {wait_fd}>&-
    _qcsd_cancel_lifecycle_root_creation || return 1
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  _QCSD_PUBLISH_REPLACED=0
  if ! _qcsd_publish_supervision_file \
      "${supervision_next}" "${supervisor_root}/SUPERVISION"; then
    echo "cannot secure the Docker supervisor identity" >&2
    exec {wait_fd}>&-
    if (( _QCSD_PUBLISH_REPLACED != 0 )); then
      _qcsd_commit_lifecycle_root_creation || true
    else
      _qcsd_cancel_lifecycle_root_creation || true
    fi
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  _qcsd_commit_lifecycle_root_creation || return 1

  local cli_pid="" cli_start_time="" cli_session="" cli_process_group=""
  local durable_cli_pid=unavailable durable_cli_start_time=unavailable
  local durable_cli_session=unavailable durable_cli_process_group=unavailable
  local cli_status=0 cli_reaped=0
  local bound_cid="" target_state="unknown"
  local supervisor_failure=0 teardown_unresolved=0 cli_forced=0
  local target_forced=0 registered=0
  local cli_force_attempted=0 cli_force_outcome="not_attempted"
  local target_force_attempted=0 target_force_api_outcome="not_attempted"
  local interruption_handled=0 signal_attempted=0 signal_forwarded=0
  local poll wait_status second_wait_status
  local forced_without_bound_target=0 interrupted_without_bound_target=0
  local internal_abort=0 target_signal="" forwarded_target_signal="none"
  local signal_api_outcome="not_attempted"
  local interruption_reason="none"

  # A signal caught after the traps were installed but before daemon launch
  # must not create an object merely so that it can immediately be torn down.
  if (( requested_status != 0 )); then
    exec {wait_fd}>&-
    _qcsd_lifecycle_remove_root "${supervisor_root}" 0 recovered-stale 2>/dev/null || true
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return "${requested_status}"
  fi

  local launcher_birth_path="${supervisor_root}/launcher.birth"
  local launcher_birth_next="${launcher_birth_path}.next"
  local birth_lock_fd=""
  if ! _qcsd_open_launcher_birth_lock "${supervisor_root}" birth_lock_fd; then
    echo "cannot establish the Docker launcher birth interlock" >&2
    exec {wait_fd}>&-
    _qcsd_lifecycle_remove_root "${supervisor_root}" 0 recovered-stale 2>/dev/null || true
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi

  # Isolate the local systemd-run launcher and place the complete Docker CLI
  # tree in a unique mandatory scope.  The in-scope wrapper publishes the
  # actual Docker exit code atomically; the launcher's status is accepted only
  # when it matches that private channel.
  local -a docker_exec_command=() run_exec_command=()
  if [[ -n "${_QCSD_DOCKER_PINNED_HOST:-}" ]]; then
    docker_exec_command=(
      /usr/bin/env -u DOCKER_CONTEXT -u DOCKER_HOST -u DOCKER_TLS_VERIFY
      -u DOCKER_CERT_PATH --default-signal=HUP,INT,QUIT,TERM -- /bin/sh -c '
host=$1
expected=$2
shift 2
observed=$(docker --host "${host}" info --format "{{.ID}}") || {
  echo "Docker run daemon identity is unavailable at request boundary" >&2
  exit 125
}
[ "${observed}" = "${expected}" ] || {
  echo "Docker run daemon identity changed at request boundary" >&2
  exit 125
}
exec docker --host "${host}" "$@"
' qcsd-pinned-docker-run "${_QCSD_DOCKER_PINNED_HOST}" \
      "${_QCSD_DOCKER_PINNED_SERVER_ID}" "${command[@]:3}"
    )
  else
    docker_exec_command=(
      /usr/bin/env --default-signal=HUP,INT,QUIT,TERM -- "${command[@]}"
    )
  fi
  run_exec_command=(
    systemd-run --user --scope --collect --quiet --expand-environment=no
    --unit="${run_scope_unit}" --property=KillMode=control-group
    --property=TimeoutStopSec=10s -- /bin/bash -c '
status_path=$1
shift
"$@"
status=$?
case "${status}" in ""|*[!0-9]*) exit 125 ;; esac
(( status <= 255 )) || exit 125
umask 077
staged=${status_path}.next
printf "%s\n" "${status}" >"${staged}" || exit 125
chmod 600 -- "${staged}" || exit 125
sync -f "${staged}" || exit 125
mv -f -- "${staged}" "${status_path}" || exit 125
sync -f "${status_path%/*}" || exit 125
exit "${status}"
' qcsd-docker-run-status "${run_status_path}" "${docker_exec_command[@]}"
  )
  if [[ -n "${output_capture_path}" ]]; then
    setsid /bin/bash -c '
birth_path=$1
birth_fd=$2
root=$3
token=$4
kind=$5
shift 5
for fd_path in /proc/${BASHPID}/fd/*; do
  fd=${fd_path##*/}
  case "${fd}" in 0|1|2|"${birth_fd}") continue ;; *[!0-9]*|"") exit 125 ;; esac
  eval "exec ${fd}>&-"
done
stat_line=$(<"/proc/${BASHPID}/stat") || exit 125
stat_tail=${stat_line##*) }
read -r -a stat_fields <<<"${stat_tail}"
(( ${#stat_fields[@]} >= 20 )) || exit 125
start_time=${stat_fields[19]}
process_group=${stat_fields[2]}
session=${stat_fields[3]}
[[ "${process_group}" == "${BASHPID}" && "${session}" == "${BASHPID}" &&
    "${start_time}" =~ ^[1-9][0-9]*$ ]] || exit 125
umask 077
staged=${birth_path}.next
{
  printf "birth_schema=1\n"
  printf "launcher_kind=%s\n" "${kind}"
  printf "lifecycle_root=%s\n" "${root}"
  printf "lifecycle_token=%s\n" "${token}"
  printf "launcher_pid=%s\n" "${BASHPID}"
  printf "launcher_start_time=%s\n" "${start_time}"
  printf "launcher_session=%s\n" "${session}"
  printf "launcher_process_group=%s\n" "${process_group}"
} >"${staged}" || exit 125
chmod 600 -- "${staged}" && sync -f "${staged}" &&
  mv -f -- "${staged}" "${birth_path}" && sync -f "${root}" || exit 125
eval "exec ${birth_fd}>&-"
kill -STOP "${BASHPID}" || exit 125
exec "$@"
' qcsd-docker-run-scope-launcher \
      "${launcher_birth_path}" "${birth_lock_fd}" "${supervisor_root}" \
      "${token}" run \
      "${run_exec_command[@]}" >"${output_capture_path}" &
  else
    setsid /bin/bash -c '
birth_path=$1
birth_fd=$2
root=$3
token=$4
kind=$5
shift 5
for fd_path in /proc/${BASHPID}/fd/*; do
  fd=${fd_path##*/}
  case "${fd}" in 0|1|2|"${birth_fd}") continue ;; *[!0-9]*|"") exit 125 ;; esac
  eval "exec ${fd}>&-"
done
stat_line=$(<"/proc/${BASHPID}/stat") || exit 125
stat_tail=${stat_line##*) }
read -r -a stat_fields <<<"${stat_tail}"
(( ${#stat_fields[@]} >= 20 )) || exit 125
start_time=${stat_fields[19]}
process_group=${stat_fields[2]}
session=${stat_fields[3]}
[[ "${process_group}" == "${BASHPID}" && "${session}" == "${BASHPID}" &&
    "${start_time}" =~ ^[1-9][0-9]*$ ]] || exit 125
umask 077
staged=${birth_path}.next
{
  printf "birth_schema=1\n"
  printf "launcher_kind=%s\n" "${kind}"
  printf "lifecycle_root=%s\n" "${root}"
  printf "lifecycle_token=%s\n" "${token}"
  printf "launcher_pid=%s\n" "${BASHPID}"
  printf "launcher_start_time=%s\n" "${start_time}"
  printf "launcher_session=%s\n" "${session}"
  printf "launcher_process_group=%s\n" "${process_group}"
} >"${staged}" || exit 125
chmod 600 -- "${staged}" && sync -f "${staged}" &&
  mv -f -- "${staged}" "${birth_path}" && sync -f "${root}" || exit 125
eval "exec ${birth_fd}>&-"
kill -STOP "${BASHPID}" || exit 125
exec "$@"
' qcsd-docker-run-scope-launcher \
      "${launcher_birth_path}" "${birth_lock_fd}" "${supervisor_root}" \
      "${token}" run "${run_exec_command[@]}" &
  fi
  cli_pid=$!
  _qcsd_launcher_forked_hook run "${cli_pid}" "${supervisor_root}"
  for (( poll = 0; poll < 300; poll++ )); do
    if _qcsd_read_process_identity "${cli_pid}"; then
      [[ -n "${cli_start_time}" ]] || \
        cli_start_time="${_qcsd_process_start_time}"
      if [[ "${_qcsd_process_start_time}" == "${cli_start_time}" &&
            "${_qcsd_process_session}" == "${cli_pid}" &&
            "${_qcsd_process_group}" == "${cli_pid}" &&
            "${_qcsd_process_state}" == "T" ]] &&
         _qcsd_private_launcher_birth "${launcher_birth_path}" \
           "${supervisor_root}" "${token}" run &&
         [[ "${_qcsd_birth_pid}" == "${cli_pid}" &&
             "${_qcsd_birth_start_time}" == "${cli_start_time}" &&
             "${_qcsd_birth_session}" == "${cli_pid}" &&
             "${_qcsd_birth_process_group}" == "${cli_pid}" ]]; then
        cli_session="${_qcsd_process_session}"
        cli_process_group="${_qcsd_process_group}"
        break
      fi
    fi
    sleep 0.01 || true
  done
  if [[ -z "${cli_start_time}" || -z "${cli_session}" ||
        -z "${cli_process_group}" ]]; then
    echo "cannot bind the isolated Docker CLI birth identity" >&2
    supervisor_failure=1
    internal_abort=1
  else
    durable_cli_pid="${cli_pid}"
    durable_cli_start_time="${cli_start_time}"
    durable_cli_session="${cli_session}"
    durable_cli_process_group="${cli_process_group}"
  fi
  if (( internal_abort == 0 )); then
    _qcsd_launcher_birth_bound_hook run "${cli_pid}" "${supervisor_root}"
  fi
  if (( internal_abort == 0 )) &&
     ! _qcsd_revalidate_helper_source_identity; then
    echo "Docker run supervisor source changed before request authorisation" >&2
    supervisor_failure=1
    internal_abort=1
  fi
  if (( internal_abort == 0 )); then
    lifecycle_state="request-authorised"
    {
      printf 'object=docker-run-scope-launcher\n'
      printf 'process_identity_role=local-systemd-run-scope-launcher\n'
      _qcsd_print_lifecycle_identity
      _qcsd_print_bound_supervisor_identity
      printf 'mode=%s\n' "${mode}"
      printf 'scope_launcher_pid=%s\n' "${cli_pid}"
      printf 'scope_launcher_start_time=%s\n' "${cli_start_time}"
      printf 'scope_launcher_session=%s\n' "${cli_session}"
      printf 'scope_launcher_process_group=%s\n' "${cli_process_group}"
      printf 'cli_pid=%s\n' "${cli_pid}"
      printf 'cli_start_time=%s\n' "${cli_start_time}"
      printf 'cli_session=%s\n' "${cli_session}"
      printf 'cli_process_group=%s\n' "${cli_process_group}"
      printf 'container_id=unavailable\n'
      printf 'docker_context=%s\n' "${_qcsd_target_docker_context}"
      _qcsd_print_docker_binding
      printf 'docker_daemon_id=%s\n' "${_QCSD_DOCKER_PINNED_SERVER_ID}"
      printf 'supervisor_label=%s=%s\n' \
        "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" "${token}"
      printf 'request_argv_sha256=%s\n' "${run_argv_sha256}"
      printf 'scope_required=1\n'
      printf 'scope_unit=%s\n' "${run_scope_unit}"
      printf 'scope_control_group=unavailable\n'
      printf 'scope_state=declared\n'
      printf 'host_boot_id=%s\n' "${run_boot_id}"
      printf 'status_file=%s\n' "${run_status_path}"
      printf 'status_file_state=declared\n'
      printf 'requested_signal=%s\n' "${requested_signal:-none}"
      printf 'forwarded_target_signal=none\n'
      printf 'target_state=launching\n'
    } >"${supervision_next}"
    # A post-rename publication error is indistinguishable from a durable
    # request-authorised receipt after restart, so recovery must remain
    # conservative even when this call reports failure.
    if ! _qcsd_publish_supervision_file \
        "${supervision_next}" "${supervisor_root}/SUPERVISION"; then
      daemon_request_authorised="${_QCSD_PUBLISH_REPLACED}"
      echo "cannot authorise the Docker run request durably" >&2
      supervisor_failure=1
      internal_abort=1
    else
      daemon_request_authorised=1
    fi
  fi
  if (( requested_status != 0 )); then
    internal_abort=1
  fi
  # The final request-authorised receipt now contains the same exact birth
  # identity. Releasing this lock transfers crash recovery authority from the
  # child-published BIRTH receipt to SUPERVISION before the child can execute.
  exec {birth_lock_fd}>&-
  birth_lock_fd=""
  if (( internal_abort == 0 )); then
    rm -f -- "${launcher_birth_next}" "${launcher_birth_path}" \
      "${supervisor_root}/BIRTH.lock" || {
      echo "cannot retire the Docker launcher birth handoff" >&2
      supervisor_failure=1
      internal_abort=1
    }
    sync -f "${supervisor_root}" || {
      supervisor_failure=1
      internal_abort=1
    }
  fi
  release_record_sha="$(sha256sum -- "${supervisor_root}/SUPERVISION" | awk '{print $1}')" ||
    release_record_sha=""
  _qcsd_pre_mutation_release_hook run "${supervisor_root}"
  if [[ ! "${release_record_sha}" =~ ^[0-9a-f]{64}$ ]] ||
     ! _qcsd_revalidate_release_record \
       "${supervisor_root}" run "${release_record_sha}"; then
    supervisor_failure=1
    internal_abort=1
  fi
  if (( requested_status != 0 )); then
    internal_abort=1
  fi
  if (( internal_abort == 0 )) &&
     ! _qcsd_revalidate_helper_source_identity; then
    echo "Docker run supervisor source changed at launcher release" >&2
    supervisor_failure=1
    internal_abort=1
  fi
  if (( internal_abort == 0 )) &&
     ! _qcsd_signal_bound_job \
        "${cli_pid}" "${cli_start_time}" "${cli_session}" \
        "${cli_process_group}" CONT; then
    echo "cannot release the bound Docker CLI launcher" >&2
    supervisor_failure=1
    internal_abort=1
  fi
  if (( internal_abort == 0 )); then
    if _qcsd_query_user_scope "${run_scope_unit}"; then
      run_scope_final_state="${_qcsd_scope_state}"
      if [[ "${_qcsd_scope_control_group}" != "unavailable" ]]; then
        run_scope_control_group="${_qcsd_scope_control_group}"
      fi
    else
      echo "cannot bind the Docker run user-systemd scope identity" >&2
      supervisor_failure=1
      internal_abort=1
    fi
  fi
  if (( internal_abort == 0 )); then
    {
      printf 'object=docker-run-scope-launcher\n'
      printf 'process_identity_role=local-systemd-run-scope-launcher\n'
      _qcsd_print_lifecycle_identity
      _qcsd_print_bound_supervisor_identity
      printf 'mode=%s\n' "${mode}"
      printf 'scope_launcher_pid=%s\n' "${durable_cli_pid}"
      printf 'scope_launcher_start_time=%s\n' \
        "${durable_cli_start_time}"
      printf 'scope_launcher_session=%s\n' "${durable_cli_session}"
      printf 'scope_launcher_process_group=%s\n' \
        "${durable_cli_process_group}"
      printf 'cli_pid=%s\n' "${durable_cli_pid}"
      printf 'cli_start_time=%s\n' "${durable_cli_start_time}"
      printf 'cli_session=%s\n' "${durable_cli_session}"
      printf 'cli_process_group=%s\n' "${durable_cli_process_group}"
      printf 'container_id=unavailable\n'
      printf 'docker_context=%s\n' "${_qcsd_target_docker_context}"
      _qcsd_print_docker_binding
      printf 'docker_daemon_id=%s\n' \
        "${_QCSD_DOCKER_PINNED_SERVER_ID:-unavailable}"
      printf 'supervisor_label=%s=%s\n' \
        "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" "${token}"
      printf 'request_argv_sha256=%s\n' "${run_argv_sha256}"
      printf 'scope_required=1\n'
      printf 'scope_unit=%s\n' "${run_scope_unit}"
      printf 'scope_control_group=%s\n' "${run_scope_control_group}"
      printf 'scope_state=%s\n' "${run_scope_final_state}"
      printf 'host_boot_id=%s\n' "${run_boot_id}"
      printf 'status_file=%s\n' "${run_status_path}"
      printf 'status_file_state=awaiting-command-status\n'
      printf 'requested_signal=%s\n' "${requested_signal:-none}"
      printf 'forwarded_target_signal=none\n'
      printf 'target_state=launching\n'
    } >"${supervision_next}"
    if ! _qcsd_publish_supervision_file \
        "${supervision_next}" "${supervisor_root}/SUPERVISION"; then
      echo "cannot update the Docker supervisor process identity" >&2
      supervisor_failure=1
      internal_abort=1
    fi
  fi
  if (( internal_abort == 0 )); then
    _qcsd_run_wait_ready_hook
  fi
  # Poll the bound Linux process identity directly. `read -t` is a Bash
  # builtin on a private, never-readable FIFO: it creates no timer process and
  # bounds the narrow condition-to-wait signal race to one second rather than
  # a campaign run.
  while (( requested_status == 0 && internal_abort == 0 )) &&
        _qcsd_job_is_running \
          "${cli_pid}" "${cli_start_time}" "${cli_session}" \
          "${cli_process_group}"; do
    IFS= read -r -t 1 -u "${wait_fd}" _qcsd_wait_byte || true
  done
  wait_status="${requested_status}"
  (( internal_abort == 0 && requested_status == 0 )) && wait_status=0
  if (( internal_abort != 0 )); then
    cli_force_attempted=1
    if _qcsd_signal_bound_process_group \
        "${cli_pid}" "${cli_start_time}" "${cli_session}" \
        "${cli_process_group}" KILL ||
       _qcsd_signal_bound_job \
        "${cli_pid}" "${cli_start_time}" "" "" KILL; then
      _qcsd_record_cli_force_result accepted
    else
      # A failed session/group bind still leaves the unreaped child PID and
      # Linux birth time under this shell's control. Terminate that exact
      # process so it cannot retain the caller's pipes or flock indefinitely;
      # daemon-side state remains unresolved and is recovered by private label.
      _qcsd_record_cli_force_result unknown
    fi
    _qcsd_wait_for_job_stop \
      "${cli_pid}" "${cli_start_time}" "" "" \
      "${_QCSD_DOCKER_REAP_POLLS}" \
      "${_QCSD_DOCKER_REAP_DELAY_SECONDS}" || true
    if _qcsd_job_is_running \
         "${cli_pid}" "${cli_start_time}" "${cli_session}" \
         "${cli_process_group}" ||
       ! _qcsd_bound_process_is_gone \
         "${cli_pid}" "${cli_start_time}" "${cli_session}" \
         "${cli_process_group}"; then
      teardown_unresolved=1
    elif _qcsd_bound_process_is_gone \
        "${cli_pid}" "${cli_start_time}" "${cli_session}" \
        "${cli_process_group}"; then
      wait "${cli_pid}" 2>/dev/null
      second_wait_status=$?
      systemd_run_status="${second_wait_status}"
      cli_reaped=1
    else
      teardown_unresolved=1
    fi
    cli_status=1
  elif (( cli_reaped != 0 )); then
    :
  elif _qcsd_job_is_running \
      "${cli_pid}" "${cli_start_time}" "${cli_session}" \
      "${cli_process_group}"; then
    cli_status="${wait_status}"
  elif _qcsd_bound_process_is_gone \
      "${cli_pid}" "${cli_start_time}" "${cli_session}" \
      "${cli_process_group}"; then
    # A signal-interrupted wait may leave a completed child unreaped. A
    # second wait is immediate for a stopped job and yields its natural code.
    wait "${cli_pid}" 2>/dev/null
    second_wait_status=$?
    systemd_run_status="${second_wait_status}"
    cli_status="${second_wait_status}"
    cli_reaped=1
  else
    echo "Docker CLI liveness became unprovable before reap" >&2
    supervisor_failure=1
    internal_abort=1
    cli_status=1
  fi

  if (( cli_reaped != 0 )) &&
     [[ -n "${cli_session}" && -n "${cli_process_group}" ]] &&
     _qcsd_process_group_has_live_members \
       "${cli_session}" "${cli_process_group}"; then
    _qcsd_wait_for_process_group_stop "${cli_session}" "${cli_process_group}" \
      "${_QCSD_DOCKER_REAP_POLLS}" "${_QCSD_DOCKER_REAP_DELAY_SECONDS}" || true
    if _qcsd_process_group_has_live_members \
        "${cli_session}" "${cli_process_group}"; then
      echo "Docker CLI left a live process-group member" >&2
      supervisor_failure=1
      internal_abort=1
      teardown_unresolved=1
      cli_force_attempted=1
      if _qcsd_signal_bound_process_group "${cli_pid}" "${cli_start_time}" \
          "${cli_session}" "${cli_process_group}" KILL; then
        _qcsd_record_cli_force_result accepted
      else
        _qcsd_record_cli_force_result unknown
      fi
      _qcsd_wait_for_process_group_stop \
        "${cli_session}" "${cli_process_group}" \
        "${_QCSD_DOCKER_REAP_POLLS}" "${_QCSD_DOCKER_REAP_DELAY_SECONDS}" || true
    fi
  fi

  if (( cli_reaped != 0 )); then
    if observed_run_status="$(_qcsd_private_exit_status \
        "${run_status_path}")"; then
      docker_run_status="${observed_run_status}"
      run_status_state="valid"
      if [[ "${systemd_run_status}" =~ ^[0-9]+$ &&
            "${docker_run_status}" == "${systemd_run_status}" ]]; then
        run_status_matches=1
        cli_status="${docker_run_status}"
      else
        run_status_state="status-mismatch"
        if (( requested_status == 0 )); then
          supervisor_failure=1
          teardown_unresolved=1
          internal_abort=1
        fi
      fi
    elif [[ -e "${run_status_path}" || -L "${run_status_path}" ]]; then
      run_status_state="invalid"
      if (( requested_status == 0 )); then
        supervisor_failure=1
        teardown_unresolved=1
        internal_abort=1
      fi
    else
      run_status_state="missing"
      if (( requested_status == 0 )); then
        supervisor_failure=1
        teardown_unresolved=1
        internal_abort=1
      fi
    fi
    if _qcsd_wait_user_scope_inactive "${run_scope_unit}"; then
      run_scope_empty_proven=1
      run_scope_final_state="${_qcsd_scope_state}"
      run_scope_checked=1
    else
      run_scope_checked=1
      run_scope_leak_detected=1
      run_scope_kill_attempted=1
      run_scope_kill_outcome="unknown"
      supervisor_failure=1
      teardown_unresolved=1
      internal_abort=1
      if _qcsd_kill_user_scope "${run_scope_unit}" KILL; then
        run_scope_kill_outcome="accepted"
      fi
      if _qcsd_wait_user_scope_inactive "${run_scope_unit}"; then
        run_scope_empty_proven=1
        run_scope_final_state="${_qcsd_scope_state}"
      else
        run_scope_final_state="unknown"
      fi
    fi
  fi

  # Resolve once on the natural path. Any signal caught by the bounded API
  # call is handled by the single interruption path immediately afterwards.
  _qcsd_resolve_docker_target "${cidfile}" "${token}"
  target_state="${_qcsd_resolved_state}"
  bound_cid="${_qcsd_resolved_cid}"
  if [[ -n "${bound_cid}" ]]; then
    lifecycle_state="bound"
    {
      printf 'object=docker-run-scope-launcher\n'
      printf 'process_identity_role=local-systemd-run-scope-launcher\n'
      _qcsd_print_lifecycle_identity
      _qcsd_print_bound_supervisor_identity
      printf 'mode=%s\n' "${mode}"
      printf 'scope_launcher_pid=%s\n' "${durable_cli_pid}"
      printf 'scope_launcher_start_time=%s\n' "${durable_cli_start_time}"
      printf 'scope_launcher_session=%s\n' "${durable_cli_session}"
      printf 'scope_launcher_process_group=%s\n' \
        "${durable_cli_process_group}"
      printf 'cli_pid=%s\n' "${durable_cli_pid}"
      printf 'cli_start_time=%s\n' "${durable_cli_start_time}"
      printf 'cli_session=%s\n' "${durable_cli_session}"
      printf 'cli_process_group=%s\n' "${durable_cli_process_group}"
      printf 'container_id=%s\n' "${bound_cid}"
      printf 'docker_context=%s\n' "${_qcsd_target_docker_context}"
      _qcsd_print_docker_binding
      printf 'docker_daemon_id=%s\n' "${_QCSD_DOCKER_PINNED_SERVER_ID}"
      printf 'supervisor_label=%s=%s\n' \
        "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" "${token}"
      printf 'request_argv_sha256=%s\n' "${run_argv_sha256}"
      printf 'scope_required=1\n'
      printf 'scope_unit=%s\n' "${run_scope_unit}"
      printf 'scope_control_group=%s\n' "${run_scope_control_group}"
      printf 'scope_state=%s\n' "${run_scope_final_state}"
      printf 'host_boot_id=%s\n' "${run_boot_id}"
      printf 'status_file=%s\n' "${run_status_path}"
      printf 'status_file_state=%s\n' "${run_status_state}"
      printf 'requested_signal=%s\n' "${requested_signal:-none}"
      printf 'forwarded_target_signal=none\n'
      printf 'target_state=%s\n' "${target_state}"
    } >"${supervision_next}"
    if ! _qcsd_publish_supervision_file \
        "${supervision_next}" "${supervisor_root}/SUPERVISION"; then
      echo "cannot bind the Docker container identity durably" >&2
      supervisor_failure=1
      internal_abort=1
      teardown_unresolved=1
    fi
  fi

  if (( requested_status != 0 || internal_abort != 0 )); then
    interruption_handled=1
    if (( internal_abort != 0 && requested_status == 0 )); then
      interruption_reason="internal_abort"
      target_signal=TERM
    else
      interruption_reason="host_signal"
      target_signal="${requested_signal}"
    fi
    # The attached collection entrypoint ultimately execs Python. SIGINT maps
    # to KeyboardInterrupt and reaches capture/session finally cleanup; SIGTERM
    # does not. Preserve the conventional host-facing signal status while
    # forwarding SIGINT for every attached interruption. Detached services
    # retain their host signal.
    [[ "${mode}" == "attached" ]] && target_signal=INT

    # Persist the private recovery identity before any daemon operation. If the
    # watcher, daemon, or WSL instance dies during teardown, the label remains
    # available for an exact, auditable recovery attempt.
    lifecycle_state="unresolved"
    {
      printf 'object=docker-run-scope-launcher\n'
      printf 'process_identity_role=local-systemd-run-scope-launcher\n'
      _qcsd_print_lifecycle_identity
      _qcsd_print_bound_supervisor_identity
      printf 'mode=%s\n' "${mode}"
      printf 'scope_launcher_pid=%s\n' "${durable_cli_pid}"
      printf 'scope_launcher_start_time=%s\n' \
        "${durable_cli_start_time}"
      printf 'scope_launcher_session=%s\n' "${durable_cli_session}"
      printf 'scope_launcher_process_group=%s\n' \
        "${durable_cli_process_group}"
      printf 'cli_pid=%s\n' "${durable_cli_pid}"
      printf 'cli_start_time=%s\n' "${durable_cli_start_time}"
      printf 'cli_session=%s\n' "${durable_cli_session}"
      printf 'cli_process_group=%s\n' "${durable_cli_process_group}"
      printf 'container_id=%s\n' "${bound_cid:-unavailable}"
      printf 'docker_context=%s\n' "${_qcsd_target_docker_context}"
      _qcsd_print_docker_binding
      printf 'docker_daemon_id=%s\n' \
        "${_QCSD_DOCKER_PINNED_SERVER_ID:-unavailable}"
      printf 'supervisor_label=%s=%s\n' \
        "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" "${token}"
      printf 'request_argv_sha256=%s\n' "${run_argv_sha256}"
      printf 'scope_required=1\n'
      printf 'scope_unit=%s\n' "${run_scope_unit}"
      printf 'scope_control_group=%s\n' "${run_scope_control_group}"
      printf 'scope_state=%s\n' "${run_scope_final_state}"
      printf 'host_boot_id=%s\n' "${run_boot_id}"
      printf 'status_file=%s\n' "${run_status_path}"
      printf 'status_file_state=%s\n' "${run_status_state}"
      printf 'requested_signal=%s\n' "${requested_signal:-none}"
      printf 'interruption_reason=%s\n' "${interruption_reason}"
      printf 'planned_target_signal=%s\n' "${target_signal:-none}"
      printf 'target_signal_attempted=0\n'
      printf 'target_signal_api_outcome=not_attempted\n'
      printf 'forwarded_target_signal=none\n'
      printf 'target_state=%s\n' "${target_state}"
      printf 'daemon_request_authorised=%s\n' "${daemon_request_authorised}"
      printf 'phase=interrupted-before-daemon-teardown\n'
    } >"${recovery_next}"
    if ! _qcsd_publish_supervision_file \
        "${recovery_next}" "${supervisor_root}/RECOVERY"; then
      echo "cannot atomically publish the Docker recovery identity" >&2
      teardown_unresolved=1
    fi

    # Give an in-flight create a short bounded opportunity to publish either
    # its cidfile or private label before the CLI is forcibly stopped.
    for (( poll = 0; poll < 2 && ${#bound_cid} == 0; poll++ )); do
      sleep 0.1 || true
      _qcsd_resolve_docker_target "${cidfile}" "${token}"
      target_state="${_qcsd_resolved_state}"
      bound_cid="${_qcsd_resolved_cid}"
    done
    if [[ -z "${bound_cid}" ]]; then
      interrupted_without_bound_target=1
    fi
    if [[ -n "${bound_cid}" && "${target_state}" == "running" ]]; then
      signal_attempted=1
      signal_api_outcome="unknown"
      if _qcsd_target_docker_api kill --signal "${target_signal}" \
          "${bound_cid}" >/dev/null 2>&1; then
        signal_forwarded=1
        signal_api_outcome="accepted"
        forwarded_target_signal="${target_signal}"
      fi
    elif [[ "${target_state}" == "unknown" ]]; then
      teardown_unresolved=1
    fi

    # Grace begins after the one exact-target signal attempt, including when
    # the daemon client times out and acceptance is therefore uncertain.
    # `container wait` is target-bound and receives the dedicated 40-second
    # capture-cleanup allowance; every other daemon operation retains 3 seconds.
    if (( signal_attempted != 0 )) && [[ -n "${bound_cid}" ]]; then
      _qcsd_target_docker_api_with_timeout "${_QCSD_DOCKER_GRACE_SECONDS}" \
        container wait "${bound_cid}" >/dev/null 2>&1 || true
      _qcsd_resolve_docker_target "${cidfile}" "${token}"
      target_state="${_qcsd_resolved_state}"
      [[ -n "${_qcsd_resolved_cid}" ]] && bound_cid="${_qcsd_resolved_cid}"
    fi

    _qcsd_wait_for_job_stop \
      "${cli_pid}" "${cli_start_time}" "${cli_session}" \
      "${cli_process_group}" \
      "${_QCSD_DOCKER_REAP_POLLS}" "${_QCSD_DOCKER_REAP_DELAY_SECONDS}" || true
    if _qcsd_job_is_running \
         "${cli_pid}" "${cli_start_time}" "${cli_session}" \
         "${cli_process_group}" ||
       ! _qcsd_bound_process_is_gone \
         "${cli_pid}" "${cli_start_time}" "${cli_session}" \
         "${cli_process_group}"; then
      cli_force_attempted=1
      if [[ -z "${bound_cid}" ]]; then
        forced_without_bound_target=1
      fi
      if _qcsd_signal_bound_process_group \
          "${cli_pid}" "${cli_start_time}" "${cli_session}" \
          "${cli_process_group}" KILL ||
         _qcsd_signal_bound_job \
          "${cli_pid}" "${cli_start_time}" "" "" KILL; then
        _qcsd_record_cli_force_result accepted
      else
        _qcsd_record_cli_force_result unknown
      fi
      _qcsd_wait_for_job_stop \
        "${cli_pid}" "${cli_start_time}" "" "" \
        "${_QCSD_DOCKER_REAP_POLLS}" "${_QCSD_DOCKER_REAP_DELAY_SECONDS}" || true
    fi
    if _qcsd_bound_process_is_gone \
         "${cli_pid}" "${cli_start_time}" "${cli_session}" \
         "${cli_process_group}" && (( cli_reaped == 0 )); then
      wait "${cli_pid}" 2>/dev/null
      wait_status=$?
      systemd_run_status="${wait_status}"
      cli_status="${wait_status}"
      cli_reaped=1
    elif _qcsd_job_is_running \
        "${cli_pid}" "${cli_start_time}" "${cli_session}" \
        "${cli_process_group}"; then
      echo "Docker CLI remained after bounded exact-job termination" >&2
      teardown_unresolved=1
    elif (( cli_reaped == 0 )); then
      echo "Docker CLI termination state is unknown; refusing an unbounded wait" >&2
      teardown_unresolved=1
    fi

    # Re-query by the unguessable label after client death. Repeated absent
    # observations close the daemon-side delayed-create/cidfile race.
    for (( poll = 0; poll < 3; poll++ )); do
      _qcsd_resolve_docker_target "${cidfile}" "${token}"
      target_state="${_qcsd_resolved_state}"
      [[ -n "${_qcsd_resolved_cid}" ]] && bound_cid="${_qcsd_resolved_cid}"
      if [[ "${target_state}" == "running" && ${signal_attempted} -eq 0 ]]; then
        signal_attempted=1
        signal_api_outcome="unknown"
        if _qcsd_target_docker_api kill --signal "${target_signal}" \
            "${bound_cid}" >/dev/null 2>&1; then
          signal_forwarded=1
          signal_api_outcome="accepted"
          forwarded_target_signal="${target_signal}"
        fi
        _qcsd_target_docker_api_with_timeout "${_QCSD_DOCKER_GRACE_SECONDS}" \
          container wait "${bound_cid}" >/dev/null 2>&1 || true
        _qcsd_resolve_docker_target "${cidfile}" "${token}"
        target_state="${_qcsd_resolved_state}"
        [[ -n "${_qcsd_resolved_cid}" ]] && \
          bound_cid="${_qcsd_resolved_cid}"
      fi
      [[ "${target_state}" == "unknown" ]] && teardown_unresolved=1
      if [[ "${target_state}" == "running" ||
            "${target_state}" == "stopped" ]]; then
        break
      fi
      sleep 0.15 || true
    done
    if [[ "${target_state}" == "running" || "${target_state}" == "stopped" ]]; then
      _qcsd_force_remove_target "${bound_cid}" || true
      _qcsd_resolve_docker_target "${cidfile}" "${token}"
      target_state="${_qcsd_resolved_state}"
      [[ -n "${_qcsd_resolved_cid}" ]] && bound_cid="${_qcsd_resolved_cid}"
    fi
    if [[ "${target_state}" != "absent" ]]; then
      teardown_unresolved=1
    elif [[ -z "${bound_cid}" ]]; then
      # A killed/interrupted client without a bound CID can still race a daemon
      # create after our bounded label polls. Keep the nonce for recovery.
      teardown_unresolved=1
    fi
  fi

  if (( run_scope_checked == 0 )); then
    if (( cli_reaped != 0 )); then
      if observed_run_status="$(_qcsd_private_exit_status \
          "${run_status_path}")"; then
        docker_run_status="${observed_run_status}"
        run_status_state="valid"
        if [[ "${systemd_run_status}" =~ ^[0-9]+$ &&
              "${docker_run_status}" == "${systemd_run_status}" ]]; then
          run_status_matches=1
        else
          run_status_state="status-mismatch"
          if (( requested_status == 0 )); then
            supervisor_failure=1
            teardown_unresolved=1
          fi
        fi
      elif [[ -e "${run_status_path}" || -L "${run_status_path}" ]]; then
        run_status_state="invalid"
        if (( requested_status == 0 )); then
          supervisor_failure=1
          teardown_unresolved=1
        fi
      else
        run_status_state="missing"
        if (( requested_status == 0 )); then
          supervisor_failure=1
          teardown_unresolved=1
        fi
      fi
    else
      run_status_state="launcher-unreaped"
      supervisor_failure=1
      teardown_unresolved=1
    fi
    if _qcsd_wait_user_scope_inactive "${run_scope_unit}"; then
      run_scope_empty_proven=1
      run_scope_final_state="${_qcsd_scope_state}"
    else
      run_scope_leak_detected=1
      run_scope_kill_attempted=1
      run_scope_kill_outcome="unknown"
      supervisor_failure=1
      teardown_unresolved=1
      if _qcsd_kill_user_scope "${run_scope_unit}" KILL; then
        run_scope_kill_outcome="accepted"
      fi
      if _qcsd_wait_user_scope_inactive "${run_scope_unit}"; then
        run_scope_empty_proven=1
        run_scope_final_state="${_qcsd_scope_state}"
      else
        run_scope_final_state="unknown"
      fi
    fi
    run_scope_checked=1
  fi

  if (( requested_status == 0 && internal_abort == 0 )); then
    if [[ "${mode}" == "attached" ]]; then
      if [[ "${target_state}" == "running" || "${target_state}" == "stopped" ]]; then
        _qcsd_force_remove_target "${bound_cid}" || true
        _qcsd_resolve_docker_target "${cidfile}" "${token}"
        target_state="${_qcsd_resolved_state}"
      fi
      [[ "${target_state}" == "absent" ]] || teardown_unresolved=1
      if [[ -z "${bound_cid}" && ${cli_status} -eq 0 ]]; then
        echo "successful attached Docker run did not publish its private CID" >&2
        supervisor_failure=1
        teardown_unresolved=1
      elif [[ -z "${bound_cid}" && ${cli_status} -ne 0 ]]; then
        echo "failed attached Docker run has no bound CID; delayed create is unresolved" >&2
        teardown_unresolved=1
      fi
    elif (( cli_status != 0 )); then
      if [[ "${target_state}" == "running" || "${target_state}" == "stopped" ]]; then
        _qcsd_force_remove_target "${bound_cid}" || true
        _qcsd_resolve_docker_target "${cidfile}" "${token}"
        target_state="${_qcsd_resolved_state}"
      fi
      if [[ "${target_state}" != "absent" || -z "${bound_cid}" ]]; then
        teardown_unresolved=1
      fi
    elif [[ "${target_state}" == "stopped" && -n "${bound_cid}" ]]; then
      echo "successful detached Docker run exited before ownership handoff" >&2
      _qcsd_force_remove_target "${bound_cid}" || true
      _qcsd_resolve_docker_target "${cidfile}" "${token}"
      target_state="${_qcsd_resolved_state}"
      if [[ "${target_state}" == "absent" ]]; then
        supervisor_failure=1
      else
        teardown_unresolved=1
      fi
    elif [[ "${target_state}" == "absent" && -n "${bound_cid}" ]]; then
      echo "successful detached Docker run exited before ownership handoff" >&2
      supervisor_failure=1
    elif [[ -z "${bound_cid}" || "${target_state}" == "unknown" ]]; then
      echo "successful detached Docker run has no provably live bound container" >&2
      teardown_unresolved=1
    else
      local -n registration="${registration_name}"
      for argument in "${registration[@]:-}"; do
        if [[ "${argument}" == "${bound_cid}" ]]; then
          echo "detached Docker CID was already registered for cleanup" >&2
          supervisor_failure=1
          teardown_unresolved=1
        fi
      done
      if (( supervisor_failure == 0 )); then
        registration+=("${bound_cid}")
        registered=1
      fi
      unset -n registration
      if (( registered != 0 )); then
        lifecycle_state="handed-off"
        {
          printf 'object=docker-run-scope-launcher\n'
          printf 'process_identity_role=local-systemd-run-scope-launcher\n'
          _qcsd_print_lifecycle_identity
          _qcsd_print_bound_supervisor_identity
          printf 'mode=%s\n' "${mode}"
          printf 'scope_launcher_pid=%s\n' "${cli_pid}"
          printf 'scope_launcher_start_time=%s\n' \
            "${cli_start_time:-unavailable}"
          printf 'scope_launcher_session=%s\n' "${cli_session:-unavailable}"
          printf 'scope_launcher_process_group=%s\n' \
            "${cli_process_group:-unavailable}"
          printf 'cli_pid=%s\n' "${cli_pid}"
          printf 'cli_start_time=%s\n' "${cli_start_time:-unavailable}"
          printf 'cli_session=%s\n' "${cli_session:-unavailable}"
          printf 'cli_process_group=%s\n' "${cli_process_group:-unavailable}"
          printf 'container_id=%s\n' "${bound_cid}"
          printf 'docker_context=%s\n' "${_qcsd_target_docker_context}"
          _qcsd_print_docker_binding
          printf 'docker_daemon_id=%s\n' "${_QCSD_DOCKER_PINNED_SERVER_ID}"
          printf 'supervisor_label=%s=%s\n' \
            "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" "${token}"
          printf 'request_argv_sha256=%s\n' "${run_argv_sha256}"
          printf 'scope_required=1\n'
          printf 'scope_unit=%s\n' "${run_scope_unit}"
          printf 'scope_control_group=%s\n' "${run_scope_control_group}"
          printf 'scope_final_state=%s\n' "${run_scope_final_state}"
          printf 'scope_empty_proven=%s\n' "${run_scope_empty_proven}"
          printf 'host_boot_id=%s\n' "${run_boot_id}"
          printf 'status_file=%s\n' "${run_status_path}"
          printf 'status_file_state=%s\n' "${run_status_state}"
          printf 'status_file_matches=%s\n' "${run_status_matches}"
          printf 'docker_command_status=%s\n' "${docker_run_status}"
          printf 'systemd_run_status=%s\n' "${systemd_run_status}"
          printf 'ownership=caller-cleanup-array\n'
          printf 'registration_name=%s\n' "${registration_name}"
          printf 'requested_signal=%s\n' "${requested_signal:-none}"
          printf 'forwarded_target_signal=none\n'
          printf 'target_state=%s\n' "${target_state}"
        } >"${handoff_next}"
        if ! _qcsd_publish_supervision_file \
            "${handoff_next}" "${supervisor_root}/HANDOFF"; then
          echo "cannot publish the Docker container ownership handoff" >&2
          supervisor_failure=1
          teardown_unresolved=1
        fi
      fi
    fi
  fi

  # Keep latching HUP/INT/QUIT/TERM through FIFO and recovery bookkeeping.
  # This hook is
  # a no-op in production and lets tests inject the exact post-registration
  # boundary without timing sleeps.
  exec {wait_fd}>&-
  rm -f -- "${wait_pipe}"
  _qcsd_supervisor_tail_hook
  if (( requested_status != 0 && interruption_handled == 0 )); then
    interruption_handled=1
    interruption_reason="host_signal"
    target_signal="${requested_signal}"
    [[ "${mode}" == "attached" ]] && target_signal=INT
    if [[ -n "${bound_cid}" ]]; then
      target_state="$(_qcsd_docker_target_state "${bound_cid}" "${token}")"
    else
      _qcsd_resolve_docker_target "${cidfile}" "${token}"
      target_state="${_qcsd_resolved_state}"
      bound_cid="${_qcsd_resolved_cid}"
    fi
    if [[ -z "${bound_cid}" ]]; then
      interrupted_without_bound_target=1
    fi
    if [[ "${target_state}" == "running" ]]; then
      signal_attempted=1
      signal_api_outcome="unknown"
      if _qcsd_target_docker_api kill --signal "${target_signal}" \
          "${bound_cid}" >/dev/null 2>&1; then
        signal_forwarded=1
        signal_api_outcome="accepted"
        forwarded_target_signal="${target_signal}"
      fi
      _qcsd_target_docker_api_with_timeout "${_QCSD_DOCKER_GRACE_SECONDS}" \
        container wait "${bound_cid}" >/dev/null 2>&1 || true
      target_state="$(_qcsd_docker_target_state "${bound_cid}" "${token}")"
    fi
    if [[ "${target_state}" == "running" || "${target_state}" == "stopped" ]]; then
      _qcsd_force_remove_target "${bound_cid}" || true
      target_state="$(_qcsd_docker_target_state "${bound_cid}" "${token}")"
    fi
    [[ "${target_state}" == "absent" ]] || teardown_unresolved=1
    if (( registered != 0 )) && [[ "${target_state}" == "absent" ]]; then
      _qcsd_registration_remove_id "${registration_name}" "${bound_cid}"
      registered=0
    fi
  fi

  if [[ -n "${output_capture_name}" ]]; then
    local captured_output="" output_capture_metadata=""
    output_capture_metadata="$(
      stat -Lc '%u:%a:%h' -- "${output_capture_path}" 2>/dev/null
    )"
    if [[ -L "${output_capture_path}" || ! -f "${output_capture_path}" ||
          "${output_capture_metadata}" != "${EUID}:600:1" ]]; then
      echo "Docker stdout capture lost its private file identity" >&2
      supervisor_failure=1
    else
      captured_output="$(<"${output_capture_path}")"
      printf -v "${output_capture_name}" '%s' "${captured_output}"
    fi
    rm -f -- "${output_capture_path}"
  fi

  # Recovery is written before the caller's signal traps are restored. An
  # unresolved signal still returns its conventional shell status; the record
  # prevents an unknown daemon state from being mistaken for clean teardown.
  if (( teardown_unresolved != 0 )); then
    lifecycle_state="unresolved"
    {
      printf 'object=docker-run-scope-launcher\n'
      printf 'process_identity_role=local-systemd-run-scope-launcher\n'
      _qcsd_print_lifecycle_identity
      _qcsd_print_bound_supervisor_identity
      printf 'mode=%s\n' "${mode}"
      printf 'scope_launcher_pid=%s\n' "${durable_cli_pid}"
      printf 'scope_launcher_start_time=%s\n' \
        "${durable_cli_start_time}"
      printf 'scope_launcher_session=%s\n' "${durable_cli_session}"
      printf 'scope_launcher_process_group=%s\n' \
        "${durable_cli_process_group}"
      printf 'cli_pid=%s\n' "${durable_cli_pid}"
      printf 'cli_start_time=%s\n' "${durable_cli_start_time}"
      printf 'cli_session=%s\n' "${durable_cli_session}"
      printf 'cli_process_group=%s\n' "${durable_cli_process_group}"
      printf 'container_id=%s\n' "${bound_cid:-unavailable}"
      printf 'docker_context=%s\n' "${_qcsd_target_docker_context}"
      _qcsd_print_docker_binding
      printf 'docker_daemon_id=%s\n' \
        "${_QCSD_DOCKER_PINNED_SERVER_ID:-unavailable}"
      printf 'supervisor_label=%s=%s\n' \
        "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}" "${token}"
      printf 'request_argv_sha256=%s\n' "${run_argv_sha256}"
      printf 'daemon_request_authorised=%s\n' "${daemon_request_authorised}"
      printf 'scope_required=1\n'
      printf 'scope_unit=%s\n' "${run_scope_unit}"
      printf 'scope_control_group=%s\n' "${run_scope_control_group}"
      printf 'scope_final_state=%s\n' "${run_scope_final_state}"
      printf 'scope_leak_detected=%s\n' "${run_scope_leak_detected}"
      printf 'scope_kill_attempted=%s\n' "${run_scope_kill_attempted}"
      printf 'scope_kill_outcome=%s\n' "${run_scope_kill_outcome}"
      printf 'scope_empty_proven=%s\n' "${run_scope_empty_proven}"
      printf 'host_boot_id=%s\n' "${run_boot_id}"
      printf 'status_file=%s\n' "${run_status_path}"
      printf 'status_file_state=%s\n' "${run_status_state}"
      printf 'status_file_matches=%s\n' "${run_status_matches}"
      printf 'docker_command_status=%s\n' "${docker_run_status}"
      printf 'systemd_run_status=%s\n' "${systemd_run_status}"
      printf 'requested_signal=%s\n' "${requested_signal:-none}"
      printf 'interruption_reason=%s\n' "${interruption_reason}"
      printf 'planned_target_signal=%s\n' "${target_signal:-none}"
      printf 'target_signal_attempted=%s\n' "${signal_attempted}"
      printf 'target_signal_api_outcome=%s\n' "${signal_api_outcome}"
      printf 'forwarded_target_signal=%s\n' "${forwarded_target_signal}"
      printf 'target_state=%s\n' "${target_state}"
      printf 'forced_without_bound_target=%s\n' \
        "${forced_without_bound_target}"
      printf 'interrupted_without_bound_target=%s\n' \
        "${interrupted_without_bound_target}"
      printf 'docker_cli_forced=%s\n' "${cli_forced}"
      printf 'docker_cli_force_attempted=%s\n' "${cli_force_attempted}"
      printf 'docker_cli_force_outcome=%s\n' "${cli_force_outcome}"
      printf 'target_forced=%s\n' "${target_forced}"
      printf 'target_force_attempted=%s\n' "${target_force_attempted}"
      printf 'target_force_api_outcome=%s\n' "${target_force_api_outcome}"
    } >"${recovery_next}"
    if _qcsd_publish_supervision_file \
        "${recovery_next}" "${supervisor_root}/RECOVERY"; then
      rm -f -- "${supervisor_root}/SUPERVISION" \
        "${supervisor_root}/HANDOFF"
    else
      echo "cannot secure the final Docker recovery record" >&2
      supervisor_failure=1
    fi
    echo "Docker teardown is unresolved; preserving ${supervisor_root}" >&2
  elif (( registered != 0 )); then
    rm -f -- "${cidfile}" "${run_status_next}" "${run_status_path}" \
      "${supervision_next}" "${recovery_next}" "${handoff_next}" \
      "${supervisor_root}/SUPERVISION" "${supervisor_root}/RECOVERY"
    if [[ ! -f "${supervisor_root}/HANDOFF" ]] ||
       ! sync -f "${supervisor_root}"; then
      echo "Docker container handoff ledger is not durable" >&2
      supervisor_failure=1
    fi
  else
    if ! _qcsd_lifecycle_retire_completed_root "${supervisor_root}"; then
      echo "cannot remove the private Docker supervisor directory" >&2
      supervisor_failure=1
    fi
  fi

  # The latching traps stay live until the target is absent or exact-ID owned
  # by the caller and all local state is final. A later signal is therefore
  # either reflected in requested_status below or handled by the restored
  # caller trap; no process-substitution child can consume it.
  _qcsd_restore_signal_trap "${saved_hup}" HUP
  _qcsd_restore_signal_trap "${saved_int}" INT
  _qcsd_restore_signal_trap "${saved_quit}" QUIT
  _qcsd_restore_signal_trap "${saved_term}" TERM
  local final_status="${cli_status}"
  if (( requested_status != 0 )); then
    final_status="${requested_status}"
    if (( target_forced != 0 )); then
      echo "interrupted Docker container required exact-target forced removal" >&2
    fi
  elif (( cli_status == 0 && (teardown_unresolved != 0 || supervisor_failure != 0) )); then
    final_status=1
  fi
  (( caller_had_errexit )) && set -e
  return "${final_status}"
}

qcsd_run_docker_build() {
  if (( $# < 5 )) ||
     [[ "$1" != "docker" || "$2" != "--context" || -z "$3" ||
        "$4" != "build" ]]; then
    echo "Docker build supervisor requires docker --context NAME build argv" >&2
    return 2
  fi
  if [[ "$-" == *m* ]]; then
    echo "Docker build supervisor rejects shell monitor mode" >&2
    return 2
  fi
  local build_context="$3"
  if [[ ! "${build_context}" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo "Docker build supervisor requires one safe pinned context name" >&2
    return 2
  fi
  if [[ -n "${_QCSD_DOCKER_PINNED_HOST:-}" &&
        "${build_context}" != "${_QCSD_DOCKER_PINNED_CONTEXT:-}" ]]; then
    echo "Docker build context differs from its pinned host binding" >&2
    return 2
  fi
  if ! command -v setsid >/dev/null 2>&1 ||
     [[ ! -x /usr/bin/env ]] ||
     ! command -v flock >/dev/null 2>&1 ||
     ! command -v od >/dev/null 2>&1 ||
     ! command -v readlink >/dev/null 2>&1 ||
     ! command -v sha256sum >/dev/null 2>&1 ||
     ! command -v stat >/dev/null 2>&1 ||
     ! command -v sync >/dev/null 2>&1 ||
     ! command -v mkfifo >/dev/null 2>&1; then
    echo "Docker build supervisor host primitives are unavailable" >&2
    return 1
  fi

  local caller_had_errexit=0
  if [[ "$-" == *e* ]]; then
    caller_had_errexit=1
    set +e
  fi
  local supervisor_root wait_pipe wait_fd build_argv_sha256 working_directory
  local supervision_next recovery_next build_status_path build_status_next
  local build_daemon_id="${_QCSD_DOCKER_BUILD_DAEMON_ID:-}"
  local build_lock_fd="${_QCSD_DOCKER_BUILD_LOCK_FD:-}"
  local lifecycle_state="declared" token=""
  local build_scope_required=1 build_scope_token="" build_scope_unit="unavailable"
  local build_scope_control_group="unavailable" build_scope_final_state="unavailable"
  local scope_leak_detected=0 scope_kill_attempted=0 scope_kill_outcome="not_attempted"
  local scope_signal_attempted=0 scope_signal_outcome="not_attempted"
  local scope_empty_proven=0 build_boot_id=""
  local status_file_state="declared" status_file_matches=0
  local systemd_run_status="unavailable" docker_command_status="unavailable"
  local observed_command_status=""
  local -a build_command=("$@")
  if [[ -n "${_QCSD_DOCKER_PINNED_HOST:-}" ]]; then
    build_command=(
      docker --host "${_QCSD_DOCKER_PINNED_HOST}" build "${@:5}"
    )
  fi
  build_argv_sha256="$(
    printf '%s\0' "${build_command[@]}" | sha256sum | awk '{print $1}'
  )"
  working_directory="$(pwd -P)"
  IFS= read -r build_boot_id </proc/sys/kernel/random/boot_id || build_boot_id=""
  if [[ ! "${build_argv_sha256}" =~ ^[0-9a-f]{64}$ ||
        -z "${working_directory}" ||
        ! "${build_boot_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "cannot bind the Docker build command identity" >&2
    (( caller_had_errexit )) && set -e
    return 1
  fi
  if [[ ! "${build_daemon_id}" =~ ^[A-Za-z0-9_.:-]+$ ||
        "${build_daemon_id}" != "${_QCSD_DOCKER_PINNED_SERVER_ID:-}" ]]; then
    echo "cannot bind the Docker build daemon identity" >&2
    (( caller_had_errexit )) && set -e
    return 1
  fi
  if ! _qcsd_verify_locked_regular_fd "${build_lock_fd}"; then
    echo "cannot bind the Docker build host-lock descriptor" >&2
    (( caller_had_errexit )) && set -e
    return 1
  fi
  if ! _qcsd_verify_pinned_docker_daemon ||
     ! _qcsd_verify_pinned_host_boot; then
    echo "Docker build supervisor cannot verify its pinned daemon identity" >&2
    (( caller_had_errexit )) && set -e
    return 1
  fi
  if ! _qcsd_bind_helper_source_identity ||
     ! _qcsd_secure_lifecycle_base; then
    echo "Docker build supervisor cannot bind durable lifecycle state" >&2
    (( caller_had_errexit )) && set -e
    return 1
  fi
  if ! command -v systemd-run >/dev/null 2>&1 ||
     ! command -v systemctl >/dev/null 2>&1 ||
     [[ "$(stat -fc '%T' /sys/fs/cgroup 2>/dev/null)" != "cgroup2fs" ]]; then
    echo "Docker build supervisor requires a live user-systemd cgroup v2 scope" >&2
    (( caller_had_errexit )) && set -e
    return 1
  fi
  build_scope_token="$(_qcsd_supervisor_token)"
  token="${build_scope_token}"
  build_scope_unit="qcsd-docker-build-${build_scope_token}.scope"
  if [[ ! "${build_scope_unit}" =~ ^qcsd-docker-build-[0-9a-f]{32}[.]scope$ ]] ||
     ! _qcsd_query_user_scope "${build_scope_unit}" ||
     [[ "${_qcsd_scope_state}" != "absent" ]]; then
    echo "Docker build supervisor cannot reserve a unique user-systemd scope" >&2
    (( caller_had_errexit )) && set -e
    return 1
  fi
  local saved_hup saved_int saved_quit saved_term
  local requested_signal="" requested_status=0
  saved_hup="$(trap -p HUP || true)"
  saved_int="$(trap -p INT || true)"
  saved_quit="$(trap -p QUIT || true)"
  saved_term="$(trap -p TERM || true)"
  trap '_qcsd_latch_requested_signal HUP 129' HUP
  trap '_qcsd_latch_requested_signal INT 130' INT
  trap '_qcsd_latch_requested_signal QUIT 131' QUIT
  trap '_qcsd_latch_requested_signal TERM 143' TERM
  if [[ -z "${token}" ]] ||
     ! _qcsd_create_lifecycle_root build "${token}"; then
    echo "cannot establish a private Docker build supervisor identity" >&2
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  supervisor_root="${_qcsd_lifecycle_root}"
  wait_pipe="${supervisor_root}/wait.pipe"
  supervision_next="${supervisor_root}/SUPERVISION.next"
  recovery_next="${supervisor_root}/RECOVERY.next"
  build_status_path="${supervisor_root}/build.status"
  build_status_next="${build_status_path}.next"
  if ! mkfifo -m 600 -- "${wait_pipe}" ||
     ! exec {wait_fd}<>"${wait_pipe}"; then
    echo "cannot establish the private Docker build wait channel" >&2
    _qcsd_cancel_lifecycle_root_creation || true
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi

  if ! {
    printf 'object=docker-build-scope-launcher\n'
    printf 'process_identity_role=local-systemd-run-scope-launcher\n'
    _qcsd_print_lifecycle_identity
    printf 'scope_launcher_pid=unavailable\n'
    printf 'scope_launcher_start_time=unavailable\n'
    printf 'scope_launcher_session=unavailable\n'
    printf 'scope_launcher_process_group=unavailable\n'
    printf 'docker_context=%s\n' "${build_context}"
    _qcsd_print_docker_binding
    printf 'docker_daemon_id=%s\n' "${build_daemon_id}"
    printf 'build_lock_path=%s\n' "${_qcsd_bound_lock_path}"
    printf 'build_lock_device=%s\n' "${_qcsd_bound_lock_device}"
    printf 'build_lock_inode=%s\n' "${_qcsd_bound_lock_inode}"
    printf 'working_directory=%s\n' "${working_directory}"
    printf 'build_argv_sha256=%s\n' "${build_argv_sha256}"
    printf 'scope_required=%s\n' "${build_scope_required}"
    printf 'scope_unit=%s\n' "${build_scope_unit}"
    printf 'scope_control_group=unavailable\n'
    printf 'scope_state=declared\n'
    printf 'host_boot_id=%s\n' "${build_boot_id}"
    printf 'status_file=%s\n' "${build_status_path}"
    printf 'status_file_state=declared\n'
    printf 'requested_signal=none\n'
    printf 'forwarded_cli_signal=none\n'
    printf 'daemon_cancellation=unavailable-client-disconnect-only\n'
  } >"${supervision_next}"; then
    exec {wait_fd}>&-
    _qcsd_cancel_lifecycle_root_creation || return 1
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  _QCSD_PUBLISH_REPLACED=0
  if ! _qcsd_publish_supervision_file \
      "${supervision_next}" "${supervisor_root}/SUPERVISION"; then
    echo "cannot secure the Docker build supervisor identity" >&2
    exec {wait_fd}>&-
    if (( _QCSD_PUBLISH_REPLACED != 0 )); then
      _qcsd_commit_lifecycle_root_creation || true
    else
      _qcsd_cancel_lifecycle_root_creation || true
    fi
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi
  _qcsd_commit_lifecycle_root_creation || return 1
  if (( requested_status != 0 )); then
    exec {wait_fd}>&-
    _qcsd_lifecycle_remove_root "${supervisor_root}" 0 recovered-stale 2>/dev/null || true
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return "${requested_status}"
  fi

  local launcher_birth_path="${supervisor_root}/launcher.birth"
  local launcher_birth_next="${launcher_birth_path}.next"
  local birth_lock_fd=""
  if ! _qcsd_open_launcher_birth_lock "${supervisor_root}" birth_lock_fd; then
    echo "cannot establish the Docker build launcher birth interlock" >&2
    exec {wait_fd}>&-
    _qcsd_lifecycle_remove_root "${supervisor_root}" 0 recovered-stale 2>/dev/null || true
    _qcsd_restore_signal_trap "${saved_hup}" HUP
    _qcsd_restore_signal_trap "${saved_int}" INT
    _qcsd_restore_signal_trap "${saved_quit}" QUIT
    _qcsd_restore_signal_trap "${saved_term}" TERM
    (( caller_had_errexit )) && set -e
    return 1
  fi

  local cli_pid cli_start_time="" cli_session="" cli_process_group=""
  local durable_cli_pid=unavailable durable_cli_start_time=unavailable
  local durable_cli_session=unavailable durable_cli_process_group=unavailable
  local cli_status=0 cli_reaped=0 supervisor_failure=0 teardown_unresolved=0
  local internal_abort=0 cli_signal_attempted=0 cli_signal_forwarded=0
  local cli_signal_outcome="not_attempted"
  local cli_forced=0 cli_force_attempted=0 cli_force_outcome="not_attempted"
  local poll wait_status=0
  # Bash starts asynchronous children with SIGINT/SIGQUIT ignored, and an
  # exec'd shell cannot reset dispositions that were ignored on entry. GNU
  # env resets them before exec while setsid isolates the CLI from the caller's
  # process group; the supervisor's targeted SIGINT is therefore effective.
  local -a docker_exec_command=() build_exec_command=()
  if [[ -n "${_QCSD_DOCKER_PINNED_HOST:-}" ]]; then
    docker_exec_command=(
      /usr/bin/env -u DOCKER_CONTEXT -u DOCKER_HOST -u DOCKER_TLS_VERIFY
      -u DOCKER_CERT_PATH --default-signal=HUP,INT,QUIT,TERM -- /bin/sh -c '
host=$1
expected=$2
shift 2
observed=$(docker --host "${host}" info --format "{{.ID}}") || {
  echo "Docker build daemon identity is unavailable at request boundary" >&2
  exit 125
}
[ "${observed}" = "${expected}" ] || {
  echo "Docker build daemon identity changed at request boundary" >&2
  exit 125
}
exec docker --host "${host}" "$@"
' qcsd-pinned-docker-build "${_QCSD_DOCKER_PINNED_HOST}" \
      "${_QCSD_DOCKER_PINNED_SERVER_ID}" "${build_command[@]:3}"
    )
  else
    docker_exec_command=(
      /usr/bin/env --default-signal=HUP,INT,QUIT,TERM -- "${build_command[@]}"
    )
  fi
  build_exec_command=(
    systemd-run --user --scope --collect --quiet --expand-environment=no
    --unit="${build_scope_unit}" --property=KillMode=control-group
    --property=TimeoutStopSec=10s -- /bin/bash -c '
status_path=$1
shift
"$@"
status=$?
case "${status}" in ""|*[!0-9]*) exit 125 ;; esac
(( status <= 255 )) || exit 125
umask 077
staged=${status_path}.next
printf "%s\n" "${status}" >"${staged}" || exit 125
chmod 600 -- "${staged}" || exit 125
sync -f "${staged}" || exit 125
mv -f -- "${staged}" "${status_path}" || exit 125
sync -f "${status_path%/*}" || exit 125
exit "${status}"
' qcsd-docker-build-status "${build_status_path}" "${docker_exec_command[@]}"
  )
  setsid /bin/bash -c '
birth_path=$1
birth_fd=$2
root=$3
token=$4
kind=$5
shift 5
for fd_path in /proc/${BASHPID}/fd/*; do
  fd=${fd_path##*/}
  case "${fd}" in 0|1|2|"${birth_fd}") continue ;; *[!0-9]*|"") exit 125 ;; esac
  eval "exec ${fd}>&-"
done
stat_line=$(<"/proc/${BASHPID}/stat") || exit 125
stat_tail=${stat_line##*) }
read -r -a stat_fields <<<"${stat_tail}"
(( ${#stat_fields[@]} >= 20 )) || exit 125
start_time=${stat_fields[19]}
process_group=${stat_fields[2]}
session=${stat_fields[3]}
[[ "${process_group}" == "${BASHPID}" && "${session}" == "${BASHPID}" &&
    "${start_time}" =~ ^[1-9][0-9]*$ ]] || exit 125
umask 077
staged=${birth_path}.next
{
  printf "birth_schema=1\n"
  printf "launcher_kind=%s\n" "${kind}"
  printf "lifecycle_root=%s\n" "${root}"
  printf "lifecycle_token=%s\n" "${token}"
  printf "launcher_pid=%s\n" "${BASHPID}"
  printf "launcher_start_time=%s\n" "${start_time}"
  printf "launcher_session=%s\n" "${session}"
  printf "launcher_process_group=%s\n" "${process_group}"
} >"${staged}" || exit 125
chmod 600 -- "${staged}" && sync -f "${staged}" &&
  mv -f -- "${staged}" "${birth_path}" && sync -f "${root}" || exit 125
eval "exec ${birth_fd}>&-"
kill -STOP "${BASHPID}" || exit 125
exec "$@"
' qcsd-docker-build-cli \
    "${launcher_birth_path}" "${birth_lock_fd}" "${supervisor_root}" \
    "${token}" build "${build_exec_command[@]}" &
  cli_pid=$!
  _qcsd_launcher_forked_hook build "${cli_pid}" "${supervisor_root}"
  for (( poll = 0; poll < 300; poll++ )); do
    if _qcsd_read_process_identity "${cli_pid}"; then
      [[ -n "${cli_start_time}" ]] || cli_start_time="${_qcsd_process_start_time}"
      if [[ "${_qcsd_process_start_time}" == "${cli_start_time}" &&
            "${_qcsd_process_session}" == "${cli_pid}" &&
            "${_qcsd_process_group}" == "${cli_pid}" &&
            "${_qcsd_process_state}" == "T" ]] &&
         _qcsd_private_launcher_birth "${launcher_birth_path}" \
           "${supervisor_root}" "${token}" build &&
         [[ "${_qcsd_birth_pid}" == "${cli_pid}" &&
             "${_qcsd_birth_start_time}" == "${cli_start_time}" &&
             "${_qcsd_birth_session}" == "${cli_pid}" &&
             "${_qcsd_birth_process_group}" == "${cli_pid}" ]]; then
        cli_session="${_qcsd_process_session}"
        cli_process_group="${_qcsd_process_group}"
        break
      fi
    fi
    sleep 0.01 || true
  done
  if [[ -z "${cli_start_time}" || -z "${cli_session}" ||
        -z "${cli_process_group}" ]]; then
    echo "cannot bind the isolated Docker build CLI birth identity" >&2
    supervisor_failure=1
    internal_abort=1
  else
    durable_cli_pid="${cli_pid}"
    durable_cli_start_time="${cli_start_time}"
    durable_cli_session="${cli_session}"
    durable_cli_process_group="${cli_process_group}"
  fi
  if (( internal_abort == 0 )); then
    _qcsd_launcher_birth_bound_hook build "${cli_pid}" "${supervisor_root}"
  fi
  if (( internal_abort == 0 )) &&
     ! _qcsd_revalidate_helper_source_identity; then
    echo "Docker build supervisor source changed before request authorisation" >&2
    supervisor_failure=1
    internal_abort=1
  fi
  if (( internal_abort == 0 )); then
    lifecycle_state="request-authorised"
    {
      printf 'object=docker-build-scope-launcher\n'
      printf 'process_identity_role=local-systemd-run-scope-launcher\n'
      _qcsd_print_lifecycle_identity
      printf 'scope_launcher_pid=%s\n' "${cli_pid}"
      printf 'scope_launcher_start_time=%s\n' "${cli_start_time}"
      printf 'scope_launcher_session=%s\n' "${cli_session}"
      printf 'scope_launcher_process_group=%s\n' "${cli_process_group}"
      printf 'docker_context=%s\n' "${build_context}"
      _qcsd_print_docker_binding
      printf 'docker_daemon_id=%s\n' "${build_daemon_id}"
      printf 'build_lock_path=%s\n' "${_qcsd_bound_lock_path}"
      printf 'build_lock_device=%s\n' "${_qcsd_bound_lock_device}"
      printf 'build_lock_inode=%s\n' "${_qcsd_bound_lock_inode}"
      printf 'working_directory=%s\n' "${working_directory}"
      printf 'build_argv_sha256=%s\n' "${build_argv_sha256}"
      printf 'scope_required=%s\n' "${build_scope_required}"
      printf 'scope_unit=%s\n' "${build_scope_unit}"
      printf 'scope_control_group=unavailable\n'
      printf 'scope_state=declared\n'
      printf 'host_boot_id=%s\n' "${build_boot_id}"
      printf 'status_file=%s\n' "${build_status_path}"
      printf 'status_file_state=declared\n'
      printf 'requested_signal=%s\n' "${requested_signal:-none}"
      printf 'forwarded_cli_signal=none\n'
      printf 'daemon_cancellation=unavailable-client-disconnect-only\n'
    } >"${supervision_next}"
    if ! _qcsd_publish_supervision_file \
        "${supervision_next}" "${supervisor_root}/SUPERVISION"; then
      echo "cannot authorise the Docker build request durably" >&2
      supervisor_failure=1
      internal_abort=1
    fi
  fi
  if (( requested_status != 0 )); then
    internal_abort=1
  fi
  exec {birth_lock_fd}>&-
  birth_lock_fd=""
  if (( internal_abort == 0 )); then
    rm -f -- "${launcher_birth_next}" "${launcher_birth_path}" \
      "${supervisor_root}/BIRTH.lock" || {
      echo "cannot retire the Docker build launcher birth handoff" >&2
      supervisor_failure=1
      internal_abort=1
    }
    sync -f "${supervisor_root}" || {
      supervisor_failure=1
      internal_abort=1
    }
  fi
  release_record_sha="$(sha256sum -- "${supervisor_root}/SUPERVISION" | awk '{print $1}')" ||
    release_record_sha=""
  _qcsd_pre_mutation_release_hook build "${supervisor_root}"
  if [[ ! "${release_record_sha}" =~ ^[0-9a-f]{64}$ ]] ||
     ! _qcsd_revalidate_release_record \
       "${supervisor_root}" build "${release_record_sha}"; then
    supervisor_failure=1
    internal_abort=1
  fi
  if (( requested_status != 0 )); then
    internal_abort=1
  fi
  if (( internal_abort == 0 )) &&
     ! _qcsd_revalidate_helper_source_identity; then
    echo "Docker build supervisor source changed at launcher release" >&2
    supervisor_failure=1
    internal_abort=1
  fi
  if (( internal_abort == 0 )) &&
     ! _qcsd_signal_bound_job \
        "${cli_pid}" "${cli_start_time}" "${cli_session}" \
        "${cli_process_group}" CONT; then
    echo "cannot release the bound Docker build launcher" >&2
    supervisor_failure=1
    internal_abort=1
  fi
  if (( internal_abort == 0 && build_scope_required != 0 )); then
    if _qcsd_query_user_scope "${build_scope_unit}"; then
      build_scope_final_state="${_qcsd_scope_state}"
      if [[ "${_qcsd_scope_control_group}" != "unavailable" ]]; then
        build_scope_control_group="${_qcsd_scope_control_group}"
      fi
    else
      echo "cannot bind the Docker build user-systemd scope identity" >&2
      supervisor_failure=1
      internal_abort=1
    fi
  fi
  if (( internal_abort == 0 )); then
    lifecycle_state="bound"
    {
      printf 'object=docker-build-scope-launcher\n'
      printf 'process_identity_role=local-systemd-run-scope-launcher\n'
      _qcsd_print_lifecycle_identity
      printf 'scope_launcher_pid=%s\n' "${durable_cli_pid}"
      printf 'scope_launcher_start_time=%s\n' "${durable_cli_start_time}"
      printf 'scope_launcher_session=%s\n' "${durable_cli_session}"
      printf 'scope_launcher_process_group=%s\n' \
        "${durable_cli_process_group}"
      printf 'docker_context=%s\n' "${build_context}"
      _qcsd_print_docker_binding
      printf 'docker_daemon_id=%s\n' "${build_daemon_id}"
      printf 'build_lock_path=%s\n' "${_qcsd_bound_lock_path}"
      printf 'build_lock_device=%s\n' "${_qcsd_bound_lock_device}"
      printf 'build_lock_inode=%s\n' "${_qcsd_bound_lock_inode}"
      printf 'working_directory=%s\n' "${working_directory}"
      printf 'build_argv_sha256=%s\n' "${build_argv_sha256}"
      printf 'scope_required=%s\n' "${build_scope_required}"
      printf 'scope_unit=%s\n' "${build_scope_unit}"
      printf 'scope_control_group=%s\n' "${build_scope_control_group}"
      printf 'scope_state=%s\n' "${build_scope_final_state}"
      printf 'host_boot_id=%s\n' "${build_boot_id}"
      printf 'status_file=%s\n' "${build_status_path}"
      printf 'status_file_state=awaiting-command-status\n'
      printf 'requested_signal=%s\n' "${requested_signal:-none}"
      printf 'forwarded_cli_signal=none\n'
      printf 'daemon_cancellation=unavailable-client-disconnect-only\n'
    } >"${supervision_next}"
    if ! _qcsd_publish_supervision_file \
        "${supervision_next}" "${supervisor_root}/SUPERVISION"; then
      echo "cannot update the Docker build process identity" >&2
      supervisor_failure=1
      internal_abort=1
    fi
  fi

  if (( internal_abort == 0 )); then
    _qcsd_build_wait_ready_hook
  fi

  while (( requested_status == 0 && internal_abort == 0 )) &&
        _qcsd_job_is_running "${cli_pid}" "${cli_start_time}" \
          "${cli_session}" "${cli_process_group}"; do
    IFS= read -r -t 1 -u "${wait_fd}" _qcsd_build_wait_byte || true
  done
  if (( requested_status != 0 && build_scope_required != 0 )); then
    scope_signal_attempted=1
    scope_signal_outcome="unknown"
    if _qcsd_kill_user_scope "${build_scope_unit}" INT; then
      scope_signal_outcome="accepted"
    fi
  fi
  _qcsd_build_after_scope_signal_check_hook
  if (( internal_abort != 0 )); then
    if (( requested_status != 0 )) &&
       _qcsd_job_is_running "${cli_pid}" "${cli_start_time}" \
         "${cli_session}" "${cli_process_group}"; then
      _qcsd_build_ensure_scope_interrupt
      cli_signal_attempted=1
      cli_signal_outcome="unknown"
      if _qcsd_signal_bound_process_group "${cli_pid}" "${cli_start_time}" \
          "${cli_session}" "${cli_process_group}" INT; then
        cli_signal_forwarded=1
        cli_signal_outcome="accepted"
      fi
      _qcsd_wait_for_job_stop "${cli_pid}" "${cli_start_time}" \
        "${cli_session}" "${cli_process_group}" \
        "${_QCSD_DOCKER_BUILD_GRACE_POLLS}" \
        "${_QCSD_DOCKER_BUILD_GRACE_DELAY_SECONDS}" || true
    fi
    if _qcsd_job_is_running "${cli_pid}" "${cli_start_time}" \
        "${cli_session}" "${cli_process_group}"; then
      cli_force_attempted=1
      if _qcsd_signal_bound_process_group "${cli_pid}" "${cli_start_time}" \
          "${cli_session}" "${cli_process_group}" KILL ||
         _qcsd_signal_bound_job "${cli_pid}" "${cli_start_time}" "" "" KILL; then
        _qcsd_record_cli_force_result accepted
      else
        _qcsd_record_cli_force_result unknown
      fi
    fi
    cli_status=1
  elif (( requested_status != 0 )) &&
      _qcsd_job_is_running "${cli_pid}" "${cli_start_time}" \
      "${cli_session}" "${cli_process_group}"; then
    _qcsd_build_ensure_scope_interrupt
    cli_status="${requested_status}"
    cli_signal_attempted=1
    cli_signal_outcome="unknown"
    if _qcsd_signal_bound_process_group "${cli_pid}" "${cli_start_time}" \
        "${cli_session}" "${cli_process_group}" INT; then
      cli_signal_forwarded=1
      cli_signal_outcome="accepted"
    fi
    _qcsd_wait_for_job_stop "${cli_pid}" "${cli_start_time}" \
      "${cli_session}" "${cli_process_group}" \
      "${_QCSD_DOCKER_BUILD_GRACE_POLLS}" \
      "${_QCSD_DOCKER_BUILD_GRACE_DELAY_SECONDS}" || true
    if _qcsd_job_is_running "${cli_pid}" "${cli_start_time}" \
        "${cli_session}" "${cli_process_group}"; then
      cli_force_attempted=1
      if _qcsd_signal_bound_process_group "${cli_pid}" "${cli_start_time}" \
          "${cli_session}" "${cli_process_group}" KILL; then
        _qcsd_record_cli_force_result accepted
      else
        _qcsd_record_cli_force_result unknown
      fi
    fi
  fi

  if (( requested_status != 0 || internal_abort != 0 )); then
    # No interruption of the local client, including a cooperative SIGINT,
    # proves that BuildKit abandoned its solve or export. Preserve a taint
    # record and let the evidence-build preflight require explicit audit and a
    # daemon restart before another static-tag mutation.
    teardown_unresolved=1
  fi

  if (( cli_reaped == 0 )); then
    _qcsd_wait_for_job_stop "${cli_pid}" "${cli_start_time}" \
      "${cli_session}" "${cli_process_group}" \
      "${_QCSD_DOCKER_REAP_POLLS}" "${_QCSD_DOCKER_REAP_DELAY_SECONDS}" || true
    if _qcsd_bound_process_is_gone "${cli_pid}" "${cli_start_time}" \
        "${cli_session}" "${cli_process_group}"; then
      wait "${cli_pid}" 2>/dev/null
      wait_status=$?
      systemd_run_status="${wait_status}"
      if (( requested_status == 0 && internal_abort == 0 )); then
        cli_status="${wait_status}"
      fi
      cli_reaped=1
    else
      echo "Docker build CLI termination state is unresolved" >&2
      teardown_unresolved=1
      cli_force_attempted=1
      if _qcsd_signal_bound_process_group "${cli_pid}" "${cli_start_time}" \
          "${cli_session}" "${cli_process_group}" KILL ||
         _qcsd_signal_bound_job \
          "${cli_pid}" "${cli_start_time}" "" "" KILL; then
        _qcsd_record_cli_force_result accepted
      else
        _qcsd_record_cli_force_result unknown
      fi
      _qcsd_wait_for_job_stop "${cli_pid}" "${cli_start_time}" "" "" \
        "${_QCSD_DOCKER_REAP_POLLS}" "${_QCSD_DOCKER_REAP_DELAY_SECONDS}" || true
      if _qcsd_bound_process_is_gone \
          "${cli_pid}" "${cli_start_time}" "" ""; then
        wait "${cli_pid}" 2>/dev/null
        wait_status=$?
        systemd_run_status="${wait_status}"
        cli_reaped=1
      fi
    fi
  fi

  if (( cli_reaped != 0 )); then
    if observed_command_status="$(_qcsd_private_exit_status \
        "${build_status_path}")"; then
      docker_command_status="${observed_command_status}"
      status_file_state="valid"
      if [[ "${systemd_run_status}" =~ ^[0-9]+$ &&
            "${docker_command_status}" == "${systemd_run_status}" ]]; then
        status_file_matches=1
        cli_status="${docker_command_status}"
      else
        status_file_state="status-mismatch"
        supervisor_failure=1
        teardown_unresolved=1
      fi
    elif [[ -e "${build_status_path}" || -L "${build_status_path}" ]]; then
      status_file_state="invalid"
      supervisor_failure=1
      teardown_unresolved=1
    else
      status_file_state="missing"
      if (( requested_status == 0 && internal_abort == 0 )); then
        supervisor_failure=1
        teardown_unresolved=1
      fi
    fi
  else
    status_file_state="launcher-unreaped"
    supervisor_failure=1
    teardown_unresolved=1
  fi

  if (( build_scope_required != 0 )); then
    if _qcsd_wait_user_scope_inactive "${build_scope_unit}"; then
      scope_empty_proven=1
      build_scope_final_state="${_qcsd_scope_state}"
      if [[ "${_qcsd_scope_control_group}" != "unavailable" ]]; then
        build_scope_control_group="${_qcsd_scope_control_group}"
      fi
    else
      scope_leak_detected=1
      teardown_unresolved=1
      scope_kill_attempted=1
      scope_kill_outcome="unknown"
      if _qcsd_kill_user_scope "${build_scope_unit}" KILL; then
        scope_kill_outcome="accepted"
      fi
      if _qcsd_wait_user_scope_inactive "${build_scope_unit}"; then
        scope_empty_proven=1
        build_scope_final_state="${_qcsd_scope_state}"
      else
        build_scope_final_state="unknown"
      fi
    fi
  else
    scope_empty_proven=1
    build_scope_final_state="test-process-group-only"
  fi

  if [[ -n "${cli_session}" && -n "${cli_process_group}" ]] &&
     _qcsd_process_group_has_live_members \
       "${cli_session}" "${cli_process_group}"; then
    _qcsd_wait_for_process_group_stop "${cli_session}" "${cli_process_group}" \
      "${_QCSD_DOCKER_REAP_POLLS}" "${_QCSD_DOCKER_REAP_DELAY_SECONDS}" || true
    if _qcsd_process_group_has_live_members \
        "${cli_session}" "${cli_process_group}"; then
      echo "Docker build CLI left a live process-group member" >&2
      supervisor_failure=1
      teardown_unresolved=1
      cli_force_attempted=1
      if _qcsd_signal_bound_process_group "${cli_pid}" "${cli_start_time}" \
          "${cli_session}" "${cli_process_group}" KILL; then
        _qcsd_record_cli_force_result accepted
      else
        _qcsd_record_cli_force_result unknown
      fi
      _qcsd_wait_for_process_group_stop \
        "${cli_session}" "${cli_process_group}" \
        "${_QCSD_DOCKER_REAP_POLLS}" "${_QCSD_DOCKER_REAP_DELAY_SECONDS}" || true
      if _qcsd_process_group_has_live_members \
          "${cli_session}" "${cli_process_group}"; then
        echo "Docker build CLI process-group termination is unresolved" >&2
      fi
    fi
  fi

  # A non-zero local Docker CLI status cannot distinguish a daemon-terminal
  # build error from a disconnected/OOM-killed client whose BuildKit solve or
  # export may still be running. Fail closed for the static evidence tags.
  if (( cli_status != 0 )); then
    teardown_unresolved=1
  fi

  exec {wait_fd}>&-
  rm -f -- "${wait_pipe}"
  _qcsd_supervisor_tail_hook
  if (( requested_status != 0 || internal_abort != 0 )); then
    teardown_unresolved=1
  fi
  if (( teardown_unresolved == 0 )) &&
     ! rm -f -- "${build_status_next}" "${build_status_path}"; then
    echo "cannot remove the completed Docker build status channel" >&2
    supervisor_failure=1
    teardown_unresolved=1
  fi
  if (( teardown_unresolved != 0 )); then
    lifecycle_state="unresolved"
    {
      printf 'object=docker-build-scope-launcher\n'
      printf 'process_identity_role=local-systemd-run-scope-launcher\n'
      _qcsd_print_lifecycle_identity
      printf 'scope_launcher_pid=%s\n' "${durable_cli_pid}"
      printf 'scope_launcher_start_time=%s\n' "${durable_cli_start_time}"
      printf 'scope_launcher_session=%s\n' "${durable_cli_session}"
      printf 'scope_launcher_process_group=%s\n' \
        "${durable_cli_process_group}"
      printf 'docker_context=%s\n' "${build_context}"
      _qcsd_print_docker_binding
      printf 'docker_daemon_id=%s\n' "${build_daemon_id}"
      printf 'build_lock_path=%s\n' "${_qcsd_bound_lock_path}"
      printf 'build_lock_device=%s\n' "${_qcsd_bound_lock_device}"
      printf 'build_lock_inode=%s\n' "${_qcsd_bound_lock_inode}"
      printf 'working_directory=%s\n' "${working_directory}"
      printf 'build_argv_sha256=%s\n' "${build_argv_sha256}"
      printf 'scope_required=%s\n' "${build_scope_required}"
      printf 'scope_unit=%s\n' "${build_scope_unit}"
      printf 'scope_control_group=%s\n' "${build_scope_control_group}"
      printf 'scope_final_state=%s\n' "${build_scope_final_state}"
      printf 'scope_signal_attempted=%s\n' "${scope_signal_attempted}"
      printf 'scope_signal_outcome=%s\n' "${scope_signal_outcome}"
      printf 'scope_leak_detected=%s\n' "${scope_leak_detected}"
      printf 'scope_kill_attempted=%s\n' "${scope_kill_attempted}"
      printf 'scope_kill_outcome=%s\n' "${scope_kill_outcome}"
      printf 'scope_empty_proven=%s\n' "${scope_empty_proven}"
      printf 'host_boot_id=%s\n' "${build_boot_id}"
      printf 'status_file=%s\n' "${build_status_path}"
      printf 'status_file_state=%s\n' "${status_file_state}"
      printf 'status_file_matches=%s\n' "${status_file_matches}"
      printf 'docker_command_status=%s\n' "${docker_command_status}"
      printf 'systemd_run_status=%s\n' "${systemd_run_status}"
      printf 'requested_signal=%s\n' "${requested_signal:-none}"
      if (( cli_signal_forwarded != 0 )); then
        printf 'forwarded_cli_signal=INT\n'
      else
        printf 'forwarded_cli_signal=none\n'
      fi
      printf 'cli_signal_attempted=%s\n' "${cli_signal_attempted}"
      printf 'cli_signal_outcome=%s\n' "${cli_signal_outcome}"
      printf 'cli_forced=%s\n' "${cli_forced}"
      printf 'cli_force_attempted=%s\n' "${cli_force_attempted}"
      printf 'cli_force_outcome=%s\n' "${cli_force_outcome}"
      printf 'daemon_cancellation=unavailable-client-disconnect-only\n'
    } >"${recovery_next}"
    if _qcsd_publish_supervision_file \
        "${recovery_next}" "${supervisor_root}/RECOVERY"; then
      rm -f -- "${supervisor_root}/SUPERVISION"
    else
      echo "cannot publish the Docker build recovery record" >&2
      supervisor_failure=1
    fi
    echo "Docker build CLI teardown is unresolved; preserving ${supervisor_root}" >&2
  else
    _qcsd_lifecycle_retire_completed_root "${supervisor_root}" || supervisor_failure=1
  fi
  _qcsd_restore_signal_trap "${saved_hup}" HUP
  _qcsd_restore_signal_trap "${saved_int}" INT
  _qcsd_restore_signal_trap "${saved_quit}" QUIT
  _qcsd_restore_signal_trap "${saved_term}" TERM

  local final_status="${cli_status}"
  if (( requested_status != 0 )); then
    final_status="${requested_status}"
  elif (( cli_status == 0 && (supervisor_failure != 0 || teardown_unresolved != 0) )); then
    final_status=1
  fi
  (( caller_had_errexit )) && set -e
  return "${final_status}"
}

qcsd_run_attached_docker() {
  _qcsd_run_docker_supervised attached "" "" "$@"
}

qcsd_capture_attached_docker_output() {
  local output_capture_name="$1"
  shift
  _qcsd_run_docker_supervised attached "" "${output_capture_name}" "$@"
}

qcsd_run_detached_docker() {
  local registration_name="$1"
  shift
  _qcsd_run_docker_supervised detached "${registration_name}" "" "$@"
}

# Parse and recover the durable lifecycle namespace.  These functions are
# intentionally part of the sourced helper rather than the qcsd-lab launcher:
# the code that writes an ownership record is also the only code permitted to
# interpret it.  The launcher must hold the namespace's exclusive lifecycle
# lock while reconciling, and a shared or exclusive lock while retiring a
# normal handoff.
_qcsd_lifecycle_parse_record() {
  local record="$1"
  local values_name="$2"
  local order_name="$3"
  local -n values_ref="${values_name}"
  local -n order_ref="${order_name}"
  local metadata size last_byte line key value grep_status
  values_ref=()
  order_ref=()
  [[ ! -L "${record}" && -f "${record}" ]] || return 1
  metadata="$(stat -Lc '%u:%a:%h:%F' -- "${record}" 2>/dev/null)" || return 1
  [[ "${metadata}" == "${EUID}:600:1:regular file" ]] || return 1
  size="$(stat -Lc '%s' -- "${record}" 2>/dev/null)" || return 1
  [[ "${size}" =~ ^[1-9][0-9]*$ ]] || return 1
  (( size <= 32768 )) || return 1
  last_byte="$(
    od -An -tu1 -j "$((size - 1))" -N1 -- "${record}" 2>/dev/null |
      tr -d '[:space:]'
  )" || return 1
  [[ "${last_byte}" == "10" ]] || return 1
  if LC_ALL=C grep -q '[^ -~]' -- "${record}"; then
    return 1
  else
    grep_status=$?
    (( grep_status == 1 )) || return 1
  fi
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ "${line}" == *=* ]] || return 1
    key="${line%%=*}"
    value="${line#*=}"
    [[ "${key}" =~ ^[a-z][a-z0-9_]*$ && -n "${value}" ]] || return 1
    [[ ! -v "values_ref[${key}]" ]] || return 1
    case "${key}" in
      object|process_identity_role|lifecycle_schema|lifecycle_state|\
      lifecycle_root|lifecycle_token|supervisor_source_path|\
      supervisor_source_sha256|supervisor_source_device|\
      supervisor_source_inode|supervisor_pid|supervisor_start_time|\
      supervisor_session|supervisor_process_group|mode|scope_launcher_pid|\
      scope_launcher_start_time|scope_launcher_session|\
      scope_launcher_process_group|cli_pid|cli_start_time|cli_session|\
      cli_process_group|container_id|network_id|network_state|docker_context|docker_host|\
      docker_server_id|docker_request_revalidation|docker_daemon_id|\
      supervisor_label|request_argv_sha256|build_argv_sha256|scope_required|\
      scope_unit|scope_control_group|scope_state|scope_final_state|\
      scope_signal_attempted|scope_signal_outcome|scope_leak_detected|\
      scope_kill_attempted|scope_kill_outcome|scope_empty_proven|\
      host_boot_id|status_file|status_file_state|status_file_matches|\
      docker_command_status|systemd_run_status|ownership|registration_name|\
      requested_signal|interruption_reason|planned_target_signal|\
      target_signal_attempted|target_signal_api_outcome|\
      forwarded_target_signal|target_state|phase|forced_without_bound_target|\
      interrupted_without_bound_target|docker_cli_forced|\
      docker_cli_force_attempted|docker_cli_force_outcome|target_forced|\
      target_force_attempted|target_force_api_outcome|build_lock_path|\
      build_lock_device|build_lock_inode|working_directory|\
      forwarded_cli_signal|cli_signal_attempted|cli_signal_outcome|\
      cli_forced|cli_force_attempted|cli_force_outcome|daemon_cancellation|\
      daemon_request_authorised|cohort_version|receipt_path|transaction_state) ;;
      *) return 1 ;;
    esac
    values_ref["${key}"]="${value}"
    order_ref+=("${key}")
  done <"${record}"
  (( ${#order_ref[@]} > 0 ))
}

_qcsd_lifecycle_required_fields() {
  local values_name="$1"
  shift
  local -n values_ref="${values_name}"
  local field
  for field in "$@"; do
    [[ -v "values_ref[${field}]" && -n "${values_ref[${field}]}" ]] || return 1
  done
}

_qcsd_source_successor_git() {
  # Discard all ambient Git configuration and repository selectors.  The
  # fixed binary performs only read-only object/lineage queries below.
  /usr/bin/env -i XDG_CONFIG_HOME=/nonexistent \
    PATH=/usr/bin:/bin LC_ALL=C LANG=C GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git "$@"
}

_qcsd_source_successor_blob_sha256() {
  local checkout_root="$1" blob="$2" digest
  digest="$(
    set -o pipefail
    _qcsd_source_successor_git -C "${checkout_root}" cat-file blob \
      "${blob}" 2>/dev/null |
      /usr/bin/sha256sum
  )" || return 1
  digest="${digest%% *}"
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "${digest}"
}

_qcsd_lifecycle_v57_expected_handoff_sha256() {
  # Exact path/digest allowlist for the five terminal ledgers retained by the
  # rejected v57 shard.  A matching predecessor hash from any other campaign,
  # token, user namespace, or checkout remains invalid.
  case "$1" in
    /var/tmp/qcsd-docker-lifecycle-1000/run.0c59907e4fcfda3dfe6460d0ed90bc8d)
      printf '%s\n' ab8a743af5d96051dc8b5628109fea7498473c2cc7fda577254786cae399f16f ;;
    /var/tmp/qcsd-docker-lifecycle-1000/run.0f21acd1954d957587178aa473b2ae95)
      printf '%s\n' cd8db4c60847e8606a0d2587d7df2f0b3dd1b6f9051f0a94b1a32df6cd76ca8d ;;
    /var/tmp/qcsd-docker-lifecycle-1000/run.43135816b56120ed09bff4df82bbfe53)
      printf '%s\n' 91b1be07dfdab4453002e8b4792c918ad5375d72dc2ce6da8b5e8aee34817cd8 ;;
    /var/tmp/qcsd-docker-lifecycle-1000/network.d60e96839931a455660bb134c295c86e)
      printf '%s\n' f53c74e9963ca9ed97a6f0ce14d2a8c0ea20aa30b8ff95a64ee633e1b56a4d8f ;;
    /var/tmp/qcsd-docker-lifecycle-1000/network.fb0f174a425a544d329e8e1f6767bbbe)
      printf '%s\n' dee19badfac184a0a86f59e4e5143230d0d6c98d197027b43d0e807f86115761 ;;
    *) return 1 ;;
  esac
}

_qcsd_lifecycle_v57_handoff_allowlisted() {
  local values_name="$1" root expected record metadata_before metadata_after observed
  local device inode owner mode links size kind
  local -n values_ref="${values_name}"
  root="${values_ref[lifecycle_root]:-}"
  expected="$(_qcsd_lifecycle_v57_expected_handoff_sha256 "${root}")" || return 1
  record="${root}/HANDOFF"
  [[ ! -L "${record}" && -f "${record}" &&
      ! -e "${record}.next" && ! -L "${record}.next" ]] || return 1
  metadata_before="$(stat -Lc '%d:%i:%u:%a:%h:%s:%F' -- \
    "${record}" 2>/dev/null)" || return 1
  IFS=: read -r device inode owner mode links size kind <<<"${metadata_before}"
  [[ "${device}" =~ ^[0-9]+$ && "${inode}" =~ ^[0-9]+$ &&
      "${owner}" == "${EUID}" && "${mode}" == 600 && "${links}" == 1 &&
      "${size}" =~ ^[1-9][0-9]*$ && "${kind}" == "regular file" ]] || return 1
  observed="$(/usr/bin/sha256sum -- "${record}" 2>/dev/null |
    /usr/bin/awk '{print $1}')" || return 1
  metadata_after="$(stat -Lc '%d:%i:%u:%a:%h:%s:%F' -- \
    "${record}" 2>/dev/null)" || return 1
  [[ "${metadata_after}" == "${metadata_before}" &&
      "${observed}" == "${expected}" ]]
}

_qcsd_lifecycle_validate_v57_predecessor_checkout() {
  local tools_dir checkout_root canonical git_root git_dir
  local metadata owner mode kind mode_value head head_line predecessor_blob v57_blob
  local current_blob index_blob blob_kind commit_kind predecessor_digest current_digest
  local head_entry index_entry expected_head_entry expected_index_entry source_mode
  tools_dir="${_qcsd_bound_source_path%/*}"
  checkout_root="${tools_dir%/*}"
  [[ "${tools_dir##*/}" == tools &&
      "${_qcsd_bound_source_path}" == \
        "${checkout_root}/${_QCSD_DOCKER_V57_HELPER_PATH}" &&
      ! -L "${checkout_root}" && -d "${checkout_root}" ]] || return 1
  canonical="$(readlink -f -- "${checkout_root}" 2>/dev/null)" || return 1
  [[ "${canonical}" == "${checkout_root}" ]] || return 1
  metadata="$(stat -Lc '%u:%a:%F' -- "${checkout_root}" 2>/dev/null)" || return 1
  IFS=: read -r owner mode kind <<<"${metadata}"
  [[ "${owner}" == "${EUID}" && "${mode}" =~ ^[0-7]{3,4}$ &&
      "${kind}" == directory ]] || return 1
  mode_value=$((8#${mode}))
  (( (mode_value & 0022) == 0 )) || return 1

  git_root="$(_qcsd_source_successor_git -C "${checkout_root}" \
    rev-parse --show-toplevel 2>/dev/null)" || return 1
  [[ "${git_root}" == "${checkout_root}" ]] || return 1
  git_dir="$(_qcsd_source_successor_git -C "${checkout_root}" \
    rev-parse --absolute-git-dir 2>/dev/null)" || return 1
  [[ "${git_dir}" == /* && ! -L "${git_dir}" && -d "${git_dir}" ]] || return 1
  canonical="$(readlink -f -- "${git_dir}" 2>/dev/null)" || return 1
  [[ "${canonical}" == "${git_dir}" ]] || return 1
  metadata="$(stat -Lc '%u:%a:%F' -- "${git_dir}" 2>/dev/null)" || return 1
  IFS=: read -r owner mode kind <<<"${metadata}"
  [[ "${owner}" == "${EUID}" && "${mode}" =~ ^[0-7]{3,4}$ &&
      "${kind}" == directory ]] || return 1
  mode_value=$((8#${mode}))
  (( (mode_value & 0022) == 0 )) || return 1

  head="$(_qcsd_source_successor_git -C "${checkout_root}" \
    rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" || return 1
  commit_kind="$(_qcsd_source_successor_git -C "${checkout_root}" \
    cat-file -t "${_QCSD_DOCKER_V57_PREDECESSOR_COMMIT}" 2>/dev/null)" || return 1
  [[ "${commit_kind}" == commit ]] || return 1
  _qcsd_source_successor_git -C "${checkout_root}" merge-base --is-ancestor \
    "${_QCSD_DOCKER_V57_PREDECESSOR_COMMIT}" \
    "${_QCSD_DOCKER_V57_CHECKOUT_COMMIT}" \
    >/dev/null 2>&1 || return 1
  commit_kind="$(_qcsd_source_successor_git -C "${checkout_root}" \
    cat-file -t "${_QCSD_DOCKER_V57_CHECKOUT_COMMIT}" 2>/dev/null)" || return 1
  [[ "${commit_kind}" == commit ]] || return 1
  _qcsd_source_successor_git -C "${checkout_root}" merge-base --is-ancestor \
    "${_QCSD_DOCKER_V57_CHECKOUT_COMMIT}" "${head}" \
    >/dev/null 2>&1 || return 1
  head_line="$(_qcsd_source_successor_git -C "${checkout_root}" \
    rev-list --parents -n 1 "${head}" 2>/dev/null)" || return 1
  [[ "${head_line}" == \
      "${head} ${_QCSD_DOCKER_V57_CHECKOUT_COMMIT}" ]] || return 1
  predecessor_blob="$(_qcsd_source_successor_git -C "${checkout_root}" \
    rev-parse --verify \
      "${_QCSD_DOCKER_V57_PREDECESSOR_COMMIT}:${_QCSD_DOCKER_V57_HELPER_PATH}" \
      2>/dev/null)" || return 1
  v57_blob="$(_qcsd_source_successor_git -C "${checkout_root}" \
    rev-parse --verify \
      "${_QCSD_DOCKER_V57_CHECKOUT_COMMIT}:${_QCSD_DOCKER_V57_HELPER_PATH}" \
      2>/dev/null)" || return 1
  [[ "${predecessor_blob}" == "${_QCSD_DOCKER_V57_PREDECESSOR_BLOB}" &&
      "${v57_blob}" == "${_QCSD_DOCKER_V57_PREDECESSOR_BLOB}" ]] || return 1
  blob_kind="$(_qcsd_source_successor_git -C "${checkout_root}" cat-file -t \
    "${_QCSD_DOCKER_V57_PREDECESSOR_BLOB}" 2>/dev/null)" || return 1
  [[ "${blob_kind}" == blob ]] || return 1
  predecessor_digest="$(_qcsd_source_successor_blob_sha256 \
    "${checkout_root}" "${_QCSD_DOCKER_V57_PREDECESSOR_BLOB}")" || return 1
  [[ "${predecessor_digest}" == \
      "${_QCSD_DOCKER_V57_PREDECESSOR_SHA256}" ]] || return 1

  # The successor itself must be committed: HEAD must descend from the v57
  # checkout, and HEAD's helper bytes must be the exact immutable source this
  # shell captured.  A dirty, merely path-matching helper is never authority.
  current_blob="$(_qcsd_source_successor_git -C "${checkout_root}" \
    rev-parse --verify "HEAD:${_QCSD_DOCKER_V57_HELPER_PATH}" \
      2>/dev/null)" || return 1
  index_blob="$(_qcsd_source_successor_git -C "${checkout_root}" \
    rev-parse --verify ":${_QCSD_DOCKER_V57_HELPER_PATH}" \
      2>/dev/null)" || return 1
  [[ "${index_blob}" == "${current_blob}" ]] || return 1
  head_entry="$(_qcsd_source_successor_git -C "${checkout_root}" ls-tree \
    HEAD -- "${_QCSD_DOCKER_V57_HELPER_PATH}" 2>/dev/null)" || return 1
  index_entry="$(_qcsd_source_successor_git -C "${checkout_root}" ls-files \
    --stage -- "${_QCSD_DOCKER_V57_HELPER_PATH}" 2>/dev/null)" || return 1
  printf -v expected_head_entry '100644 blob %s\t%s' "${current_blob}" \
    "${_QCSD_DOCKER_V57_HELPER_PATH}"
  printf -v expected_index_entry '100644 %s 0\t%s' "${current_blob}" \
    "${_QCSD_DOCKER_V57_HELPER_PATH}"
  [[ "${head_entry}" == "${expected_head_entry}" &&
      "${index_entry}" == "${expected_index_entry}" ]] || return 1
  source_mode="$(stat -Lc %a -- "${_qcsd_bound_source_path}" 2>/dev/null)" ||
    return 1
  [[ "${source_mode}" =~ ^[0-7]{3,4}$ ]] || return 1
  mode_value=$((8#${source_mode}))
  (( (mode_value & 0111) == 0 )) || return 1
  blob_kind="$(_qcsd_source_successor_git -C "${checkout_root}" cat-file -t \
    "${current_blob}" 2>/dev/null)" || return 1
  [[ "${blob_kind}" == blob ]] || return 1
  current_digest="$(_qcsd_source_successor_blob_sha256 \
    "${checkout_root}" "${current_blob}")" || return 1
  [[ "${current_digest}" == "${_qcsd_bound_source_sha256}" ]]
}

_qcsd_lifecycle_source_successor_terminal_reproof() {
  local root_kind="$1" values_name="$2" presence
  local -n values_ref="${values_name}"
  local _qcsd_target_docker_context="${values_ref[docker_context]:-}"
  [[ "${values_ref[host_boot_id]:-}" == "${_QCSD_DOCKER_PINNED_BOOT_ID:-}" ]] ||
    return 1
  _qcsd_verify_pinned_host_boot || return 1
  _qcsd_verify_pinned_docker_daemon || return 1
  case "${root_kind}" in
    run)
      [[ "${values_ref[container_id]:-}" =~ ^[0-9a-f]{64}$ &&
          "${values_ref[scope_unit]:-}" =~ \
            ^qcsd-docker-run-[0-9a-f]{32}[.]scope$ &&
          "${values_ref[supervisor_label]:-}" == \
            "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}=${values_ref[lifecycle_token]:-}" &&
          "${values_ref[scope_launcher_pid]:-}" =~ ^[1-9][0-9]*$ &&
          "${values_ref[scope_launcher_start_time]:-}" =~ ^[1-9][0-9]*$ &&
          "${values_ref[scope_launcher_session]:-}" =~ ^[1-9][0-9]*$ &&
          "${values_ref[scope_launcher_process_group]:-}" =~ ^[1-9][0-9]*$ ]] ||
        return 1
      presence="$(_qcsd_docker_exact_id_presence_detailed \
        "${values_ref[container_id]:-}")" || return 1
      [[ "${presence}" == absent ]] || return 1
      _qcsd_resolve_docker_target "" "${values_ref[lifecycle_token]:-}"
      [[ "${_qcsd_resolved_state}" == absent &&
          -z "${_qcsd_resolved_cid}" ]] || return 1
      _qcsd_query_user_scope "${values_ref[scope_unit]:-}" || return 1
      [[ "${_qcsd_scope_state}" == absent ]] || return 1
      _qcsd_bound_process_is_gone "${values_ref[scope_launcher_pid]:-}" \
        "${values_ref[scope_launcher_start_time]:-}" \
        "${values_ref[scope_launcher_session]:-}" \
        "${values_ref[scope_launcher_process_group]:-}" || return 1
      ;;
    network)
      [[ "${values_ref[network_id]:-}" =~ ^[0-9a-f]{64}$ &&
          "${values_ref[supervisor_label]:-}" == \
            "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}=${values_ref[lifecycle_token]:-}" ]] ||
        return 1
      presence="$(_qcsd_docker_exact_network_presence_detailed \
        "${values_ref[network_id]:-}")" || return 1
      [[ "${presence}" == absent ]] || return 1
      _qcsd_resolve_docker_network "${values_ref[lifecycle_token]:-}" ""
      [[ "${_qcsd_resolved_network_state}" == absent &&
          -z "${_qcsd_resolved_network_id}" ]] || return 1
      ;;
    *) return 1 ;;
  esac
  [[ "${values_ref[supervisor_pid]:-}" =~ ^[1-9][0-9]*$ &&
      "${values_ref[supervisor_start_time]:-}" =~ ^[1-9][0-9]*$ &&
      "${values_ref[supervisor_session]:-}" =~ ^[1-9][0-9]*$ &&
      "${values_ref[supervisor_process_group]:-}" =~ ^[1-9][0-9]*$ ]] ||
    return 1
  _qcsd_bound_process_is_gone "${values_ref[supervisor_pid]:-}" \
    "${values_ref[supervisor_start_time]:-}" \
    "${values_ref[supervisor_session]:-}" \
    "${values_ref[supervisor_process_group]:-}"
}

_qcsd_lifecycle_is_v57_source_successor() {
  local root_kind="$1" record_name="$2" values_name="$3"
  local -n values_ref="${values_name}"
  [[ "${root_kind}" =~ ^(run|network)$ && "${record_name}" == HANDOFF &&
      "${values_ref[lifecycle_state]:-}" == handed-off &&
      "${values_ref[supervisor_source_sha256]:-}" == \
        "${_QCSD_DOCKER_V57_PREDECESSOR_SHA256}" &&
      "${_qcsd_bound_source_sha256:-}" != \
        "${_QCSD_DOCKER_V57_PREDECESSOR_SHA256}" ]]
}

_qcsd_lifecycle_validate_source_identity() {
  local root_kind="$1" record_name="$2" values_name="$3"
  local -n values_ref="${values_name}"
  _qcsd_bind_helper_source_identity || return 1
  [[ "${values_ref[supervisor_source_path]}" == "${_qcsd_bound_source_path}" &&
      "${values_ref[supervisor_source_device]}" == "${_qcsd_bound_source_device}" &&
      "${values_ref[supervisor_source_inode]}" == "${_qcsd_bound_source_inode}" ]] ||
    return 1
  if [[ "${values_ref[supervisor_source_sha256]}" == \
        "${_qcsd_bound_source_sha256}" ]]; then
    return 0
  fi
  # A source mismatch normally remains terminal.  The sole exception is an
  # immutable v57 run/network HANDOFF from the exact predecessor checkout,
  # and even that receipt is admitted only after fresh, read-only proof that
  # its exact object, private label, launcher, and (for a run) scope are gone.
  _qcsd_lifecycle_is_v57_source_successor \
    "${root_kind}" "${record_name}" "${values_name}" || return 1
  _qcsd_lifecycle_v57_handoff_allowlisted "${values_name}" || return 1
  _qcsd_lifecycle_validate_v57_predecessor_checkout || return 1
  _qcsd_lifecycle_source_successor_terminal_reproof \
    "${root_kind}" "${values_name}"
}

_qcsd_lifecycle_validate_supervisor_tuple() {
  local values_name="$1"
  local -n values_ref="${values_name}"
  [[ "${values_ref[supervisor_pid]}" =~ ^[1-9][0-9]*$ &&
      "${values_ref[supervisor_start_time]}" =~ ^[1-9][0-9]*$ &&
      "${values_ref[supervisor_session]}" =~ ^[1-9][0-9]*$ &&
      "${values_ref[supervisor_process_group]}" =~ ^[1-9][0-9]*$ ]]
}

_qcsd_lifecycle_validate_scope_tuple() {
  local values_name="$1"
  local include_cli="$2"
  local -n values_ref="${values_name}"
  local pid="${values_ref[scope_launcher_pid]}"
  if [[ "${pid}" == "unavailable" ]]; then
    [[ "${values_ref[scope_launcher_start_time]}" == "unavailable" &&
        "${values_ref[scope_launcher_session]}" == "unavailable" &&
        "${values_ref[scope_launcher_process_group]}" == "unavailable" ]] ||
      return 1
    if (( include_cli != 0 )); then
      [[ "${values_ref[cli_pid]}" == "unavailable" &&
          "${values_ref[cli_start_time]}" == "unavailable" &&
          "${values_ref[cli_session]}" == "unavailable" &&
          "${values_ref[cli_process_group]}" == "unavailable" ]] || return 1
    fi
    return 0
  fi
  [[ "${pid}" =~ ^[1-9][0-9]*$ &&
      "${values_ref[scope_launcher_start_time]}" =~ ^[1-9][0-9]*$ &&
      "${values_ref[scope_launcher_session]}" == "${pid}" &&
      "${values_ref[scope_launcher_process_group]}" == "${pid}" ]] || return 1
  if (( include_cli != 0 )); then
    [[ "${values_ref[cli_pid]}" == "${pid}" &&
        "${values_ref[cli_start_time]}" == \
          "${values_ref[scope_launcher_start_time]}" &&
        "${values_ref[cli_session]}" == "${pid}" &&
        "${values_ref[cli_process_group]}" == "${pid}" ]] || return 1
  fi
}

_qcsd_lifecycle_validate_observed_scope_binding() {
  local state="$1" control_group="$2"
  case "${state}" in
    active) [[ "${control_group}" != unavailable ]] ;;
    inactive) return 0 ;;
    absent) [[ "${control_group}" == unavailable ]] ;;
    *) return 1 ;;
  esac
}

_qcsd_lifecycle_validate_exact_keys() {
  local kind="$1" record="$2" state="$3" values_name="$4" spec field
  local -n values_ref="${values_name}"
  local -A expected=()
  spec='object lifecycle_schema lifecycle_state lifecycle_root lifecycle_token
supervisor_source_path supervisor_source_sha256 supervisor_source_device
supervisor_source_inode docker_context docker_host docker_server_id
docker_request_revalidation docker_daemon_id host_boot_id'
  case "${kind}" in
    network)
      spec+=' supervisor_pid supervisor_start_time supervisor_session
supervisor_process_group network_id supervisor_label request_argv_sha256
requested_signal network_state'
      [[ "${record}" != HANDOFF ]] || spec+=' ownership registration_name'
      [[ "${record}" != RECOVERY ]] || spec+=' daemon_request_authorised'
      ;;
    run)
      spec+=' process_identity_role supervisor_pid supervisor_start_time
supervisor_session supervisor_process_group mode scope_launcher_pid
scope_launcher_start_time scope_launcher_session scope_launcher_process_group
cli_pid cli_start_time cli_session cli_process_group container_id
supervisor_label request_argv_sha256 scope_required scope_unit
scope_control_group status_file status_file_state requested_signal
forwarded_target_signal target_state'
      if [[ "${record}" == SUPERVISION ]]; then
        spec+=' scope_state'
      elif [[ "${record}" == HANDOFF ]]; then
        spec+=' scope_final_state scope_empty_proven status_file_matches
docker_command_status systemd_run_status ownership registration_name'
      elif [[ -v 'values_ref[phase]' ]]; then
        spec+=' scope_state daemon_request_authorised interruption_reason
planned_target_signal target_signal_attempted target_signal_api_outcome phase'
      else
        spec+=' daemon_request_authorised scope_final_state scope_leak_detected
scope_kill_attempted scope_kill_outcome scope_empty_proven status_file_matches
docker_command_status systemd_run_status interruption_reason
planned_target_signal target_signal_attempted target_signal_api_outcome
forced_without_bound_target interrupted_without_bound_target docker_cli_forced
docker_cli_force_attempted docker_cli_force_outcome target_forced
target_force_attempted target_force_api_outcome'
      fi
      ;;
    build)
      spec+=' process_identity_role scope_launcher_pid
scope_launcher_start_time scope_launcher_session scope_launcher_process_group
build_lock_path build_lock_device build_lock_inode working_directory
build_argv_sha256 scope_required scope_unit scope_control_group status_file
status_file_state requested_signal forwarded_cli_signal daemon_cancellation'
      if [[ "${record}" == SUPERVISION ]]; then
        spec+=' scope_state'
      else
        spec+=' scope_final_state scope_signal_attempted scope_signal_outcome
scope_leak_detected scope_kill_attempted scope_kill_outcome scope_empty_proven
status_file_matches docker_command_status systemd_run_status
cli_signal_attempted cli_signal_outcome cli_forced cli_force_attempted
cli_force_outcome'
      fi
      ;;
    transaction)
      spec+=' working_directory cohort_version receipt_path transaction_state'
      ;;
    *) return 1 ;;
  esac
  for field in ${spec}; do expected["${field}"]=1; done
  (( ${#expected[@]} == ${#values_ref[@]} )) || return 1
  for field in "${!values_ref[@]}"; do
    [[ -v 'expected['"${field}"']' ]] || return 1
  done
}

_qcsd_lifecycle_validate_record() {
  local root="$1"
  local root_kind="$2"
  local record_name="$3"
  local values_name="$4"
  local -n values_ref="${values_name}"
  local token="${root##*.}" state expected_object control_group canonical
  local lock_metadata field
  _qcsd_lifecycle_required_fields "${values_name}" \
    object lifecycle_schema lifecycle_state lifecycle_root lifecycle_token \
    supervisor_source_path supervisor_source_sha256 supervisor_source_device \
    supervisor_source_inode docker_context docker_host docker_server_id \
    docker_request_revalidation docker_daemon_id host_boot_id || return 1
  [[ "${values_ref[lifecycle_schema]}" == \
        "${_QCSD_DOCKER_LIFECYCLE_SCHEMA}" &&
      "${values_ref[lifecycle_root]}" == "${root}" &&
      "${values_ref[lifecycle_token]}" == "${token}" &&
      "${values_ref[docker_context]}" == \
        "${_QCSD_DOCKER_PINNED_CONTEXT:-}" &&
      "${values_ref[docker_host]}" == "${_QCSD_DOCKER_PINNED_HOST:-}" &&
      "${values_ref[docker_server_id]}" == \
        "${_QCSD_DOCKER_PINNED_SERVER_ID:-}" &&
      "${values_ref[docker_daemon_id]}" == \
        "${_QCSD_DOCKER_PINNED_SERVER_ID:-}" &&
      "${values_ref[docker_request_revalidation]}" == \
        "in-scope-immediately-before-mutation" &&
      "${values_ref[host_boot_id]}" =~ \
        ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
    return 1
  _qcsd_lifecycle_validate_source_identity \
    "${root_kind}" "${record_name}" "${values_name}" || return 1
  state="${values_ref[lifecycle_state]}"
  case "${root_kind}:${record_name}:${state}" in
    run:SUPERVISION:declared|run:SUPERVISION:request-authorised|\
    run:SUPERVISION:bound|run:HANDOFF:handed-off|run:RECOVERY:unresolved|\
    network:SUPERVISION:declared|network:SUPERVISION:request-authorised|\
    network:SUPERVISION:bound|network:HANDOFF:handed-off|\
    network:RECOVERY:unresolved|build:SUPERVISION:declared|\
    build:SUPERVISION:request-authorised|build:SUPERVISION:bound|\
    build:RECOVERY:unresolved|transaction:SUPERVISION:request-authorised) ;;
    *) return 1 ;;
  esac
  case "${root_kind}" in
    run) expected_object=docker-run-scope-launcher ;;
    network) expected_object=network ;;
    build) expected_object=docker-build-scope-launcher ;;
    transaction) expected_object=docker-build-transaction ;;
    *) return 1 ;;
  esac
  if [[ "${record_name}" == "RECOVERY" &&
        ( "${root_kind}" == "run" || "${root_kind}" == "network" ) ]]; then
    _qcsd_lifecycle_required_fields "${values_name}" \
      daemon_request_authorised || return 1
    [[ "${values_ref[daemon_request_authorised]}" =~ ^[01]$ ]] || return 1
  fi
  case "${root_kind}:${record_name}:${state}" in
    network:SUPERVISION:declared|network:SUPERVISION:request-authorised)
      [[ "${values_ref[network_id]}" == unavailable &&
          "${values_ref[network_state]}" == launching &&
          "${values_ref[requested_signal]}" == none ]] || return 1 ;;
    network:SUPERVISION:bound|network:HANDOFF:handed-off)
      [[ "${values_ref[network_id]}" =~ ^[0-9a-f]{64}$ &&
          "${values_ref[network_state]}" == present ]] || return 1 ;;
    network:RECOVERY:unresolved)
      [[ "${values_ref[daemon_request_authorised]}" == 1 &&
            ( ( "${values_ref[network_id]}" == unavailable &&
              "${values_ref[network_state]}" =~ ^(absent|unknown)$ ) ||
              ( "${values_ref[network_id]}" =~ ^[0-9a-f]{64}$ &&
                "${values_ref[network_state]}" =~ ^(present|absent|unknown)$ ) ) ]] ||
        return 1 ;;
    run:SUPERVISION:declared)
      [[ "${values_ref[scope_launcher_pid]}" == unavailable &&
          "${values_ref[container_id]}" == unavailable &&
          "${values_ref[scope_state]}" == declared &&
          "${values_ref[scope_control_group]}" == unavailable &&
          "${values_ref[status_file_state]}" == declared &&
          "${values_ref[requested_signal]}" == none &&
          "${values_ref[forwarded_target_signal]}" == none &&
          "${values_ref[target_state]}" == launching ]] || return 1 ;;
    run:SUPERVISION:bound)
      [[ "${values_ref[scope_launcher_pid]}" =~ ^[1-9][0-9]*$ &&
          "${values_ref[container_id]}" =~ ^[0-9a-f]{64}$ &&
          "${values_ref[target_state]}" != launching &&
          "${values_ref[scope_state]}" =~ ^(unavailable|active|inactive|absent|unknown)$ &&
          "${values_ref[status_file_state]}" =~ \
            ^(declared|valid|status-mismatch|invalid|missing)$ &&
          ( "${values_ref[scope_state]}" != unavailable ||
            "${values_ref[scope_control_group]}" == unavailable ) &&
          ( "${values_ref[scope_state]}" != active ||
            "${values_ref[scope_control_group]}" != unavailable ) ]] || return 1 ;;
    run:SUPERVISION:request-authorised)
      [[ "${values_ref[scope_launcher_pid]}" =~ ^[1-9][0-9]*$ &&
          "${values_ref[container_id]}" == unavailable &&
          "${values_ref[target_state]}" == launching &&
          ( ( "${values_ref[scope_state]}" == declared &&
              "${values_ref[scope_control_group]}" == unavailable &&
              "${values_ref[status_file_state]}" == declared ) ||
            ( "${values_ref[scope_state]}" =~ ^(active|inactive|absent)$ &&
              "${values_ref[status_file_state]}" == awaiting-command-status ) ) ]] ||
        return 1 ;;
    run:HANDOFF:handed-off)
      [[ "${values_ref[mode]}" == detached &&
          "${values_ref[scope_launcher_pid]}" =~ ^[1-9][0-9]*$ &&
          "${values_ref[container_id]}" =~ ^[0-9a-f]{64}$ &&
          "${values_ref[target_state]}" == running &&
          "${values_ref[scope_final_state]}" =~ ^(inactive|absent)$ &&
          "${values_ref[scope_empty_proven]}" == 1 &&
          "${values_ref[status_file_state]}" == valid &&
          "${values_ref[status_file_matches]}" == 1 &&
          "${values_ref[docker_command_status]}" == 0 &&
          "${values_ref[systemd_run_status]}" == 0 &&
          "${values_ref[forwarded_target_signal]}" == none ]] || return 1 ;;
    build:SUPERVISION:declared)
      [[ "${values_ref[scope_launcher_pid]}" == unavailable &&
          "${values_ref[scope_state]}" == declared &&
          "${values_ref[scope_control_group]}" == unavailable &&
          "${values_ref[status_file_state]}" == declared &&
          "${values_ref[requested_signal]}" == none &&
          "${values_ref[forwarded_cli_signal]}" == none ]] || return 1 ;;
    build:SUPERVISION:request-authorised|build:SUPERVISION:bound)
      [[ "${values_ref[scope_launcher_pid]}" =~ ^[1-9][0-9]*$ ]] || return 1
      if [[ "${state}" == request-authorised ]]; then
        [[ "${values_ref[scope_state]}" == declared &&
            "${values_ref[scope_control_group]}" == unavailable &&
            "${values_ref[status_file_state]}" == declared ]] || return 1
      else
        [[ "${values_ref[scope_state]}" =~ ^(active|inactive|absent)$ &&
            "${values_ref[status_file_state]}" == awaiting-command-status ]] ||
          return 1
      fi ;;
  esac
  if [[ ( "${root_kind}:${record_name}:${state}" == \
          run:SUPERVISION:request-authorised ||
          "${root_kind}:${record_name}:${state}" == build:SUPERVISION:bound ) &&
        "${values_ref[scope_state]}" != declared ]]; then
    _qcsd_lifecycle_validate_observed_scope_binding \
      "${values_ref[scope_state]}" "${values_ref[scope_control_group]}" || return 1
  fi
  if [[ "${record_name}" == SUPERVISION ]]; then
    [[ ! -v 'values_ref[forwarded_target_signal]' ||
        "${values_ref[forwarded_target_signal]}" == none ]] || return 1
    [[ ! -v 'values_ref[forwarded_cli_signal]' ||
        "${values_ref[forwarded_cli_signal]}" == none ]] || return 1
  fi
  if [[ -v 'values_ref[status_file_state]' ]]; then
    [[ "${values_ref[status_file_state]}" =~ \
      ^(declared|awaiting-command-status|valid|status-mismatch|invalid|missing|launcher-unreaped)$ ]] ||
      return 1
  fi
  [[ "${values_ref[object]}" == "${expected_object}" ]] || return 1
  _qcsd_lifecycle_validate_exact_keys \
    "${root_kind}" "${record_name}" "${state}" "${values_name}" || return 1

  # The parser's key vocabulary is intentionally a union, but a receipt may
  # contain only fields belonging to its object kind.  This prevents a known
  # field from another schema being smuggled through as unaudited surplus.
  for field in "${!values_ref[@]}"; do
    case "${field}" in
      object|lifecycle_schema|lifecycle_state|lifecycle_root|lifecycle_token|\
      supervisor_source_path|supervisor_source_sha256|supervisor_source_device|\
      supervisor_source_inode|docker_context|docker_host|docker_server_id|\
      docker_request_revalidation|docker_daemon_id|host_boot_id) continue ;;
    esac
    case "${root_kind}:${field}" in
      run:process_identity_role|run:supervisor_pid|run:supervisor_start_time|\
      run:supervisor_session|run:supervisor_process_group|run:mode|\
      run:scope_launcher_pid|run:scope_launcher_start_time|\
      run:scope_launcher_session|run:scope_launcher_process_group|run:cli_pid|\
      run:cli_start_time|run:cli_session|run:cli_process_group|run:container_id|\
      run:supervisor_label|run:request_argv_sha256|run:scope_required|\
      run:scope_unit|run:scope_control_group|run:scope_state|\
      run:scope_final_state|run:scope_signal_attempted|run:scope_signal_outcome|\
      run:scope_leak_detected|run:scope_kill_attempted|run:scope_kill_outcome|\
      run:scope_empty_proven|run:status_file|run:status_file_state|\
      run:status_file_matches|run:docker_command_status|run:systemd_run_status|\
      run:ownership|run:registration_name|run:requested_signal|\
      run:interruption_reason|run:planned_target_signal|\
      run:target_signal_attempted|run:target_signal_api_outcome|\
      run:forwarded_target_signal|run:target_state|run:phase|\
      run:forced_without_bound_target|run:interrupted_without_bound_target|\
      run:docker_cli_forced|run:docker_cli_force_attempted|\
      run:docker_cli_force_outcome|run:target_forced|\
      run:target_force_attempted|run:target_force_api_outcome|\
      run:daemon_request_authorised) continue ;;
      network:supervisor_pid|network:supervisor_start_time|\
      network:supervisor_session|network:supervisor_process_group|\
      network:network_id|network:network_state|network:supervisor_label|\
      network:request_argv_sha256|network:ownership|network:registration_name|\
      network:requested_signal|network:daemon_request_authorised) continue ;;
      build:process_identity_role|build:supervisor_pid|\
      build:supervisor_start_time|build:supervisor_session|\
      build:supervisor_process_group|build:scope_launcher_pid|\
      build:scope_launcher_start_time|build:scope_launcher_session|\
      build:scope_launcher_process_group|build:build_argv_sha256|\
      build:scope_required|build:scope_unit|build:scope_control_group|\
      build:scope_state|build:scope_final_state|build:scope_signal_attempted|\
      build:scope_signal_outcome|build:scope_leak_detected|\
      build:scope_kill_attempted|build:scope_kill_outcome|\
      build:scope_empty_proven|build:status_file|build:status_file_state|\
      build:status_file_matches|build:docker_command_status|\
      build:systemd_run_status|build:requested_signal|\
      build:forwarded_cli_signal|build:cli_signal_attempted|\
      build:cli_signal_outcome|build:cli_forced|build:cli_force_attempted|\
      build:cli_force_outcome|build:daemon_cancellation|build:build_lock_path|\
      build:build_lock_device|build:build_lock_inode|build:working_directory) continue ;;
      transaction:working_directory|transaction:cohort_version|\
      transaction:receipt_path|transaction:transaction_state) continue ;;
      *) return 1 ;;
    esac
  done

  case "${root_kind}" in
    run|network)
      _qcsd_lifecycle_required_fields "${values_name}" \
        supervisor_pid supervisor_start_time supervisor_session \
        supervisor_process_group supervisor_label request_argv_sha256 || return 1
      _qcsd_lifecycle_validate_supervisor_tuple "${values_name}" || return 1
      [[ "${values_ref[supervisor_label]}" == \
            "${_QCSD_DOCKER_SUPERVISOR_LABEL_KEY}=${token}" &&
          "${values_ref[request_argv_sha256]}" =~ ^[0-9a-f]{64}$ ]] || return 1
      ;;
  esac
  case "${root_kind}" in
    network)
      _qcsd_lifecycle_required_fields "${values_name}" \
        network_id requested_signal network_state || return 1
      [[ "${values_ref[network_id]}" =~ ^(unavailable|[0-9a-f]{64})$ &&
          "${values_ref[requested_signal]}" =~ ^(none|HUP|INT|QUIT|TERM)$ &&
          "${values_ref[network_state]}" =~ ^(launching|present|absent|unknown)$ ]] ||
        return 1
      ;;
    run)
      _qcsd_lifecycle_required_fields "${values_name}" \
        process_identity_role mode scope_launcher_pid scope_launcher_start_time \
        scope_launcher_session scope_launcher_process_group cli_pid \
        cli_start_time cli_session cli_process_group container_id scope_required \
        scope_unit scope_control_group status_file status_file_state \
        requested_signal target_state || return 1
      [[ "${values_ref[process_identity_role]}" == \
            "local-systemd-run-scope-launcher" &&
          "${values_ref[mode]}" =~ ^(attached|detached)$ &&
          "${values_ref[container_id]}" =~ ^(unavailable|[0-9a-f]{64})$ &&
          "${values_ref[scope_required]}" == "1" &&
          "${values_ref[scope_unit]}" == \
            "qcsd-docker-run-${token}.scope" &&
          "${values_ref[status_file]}" == "${root}/run.status" &&
          "${values_ref[requested_signal]}" =~ ^(none|HUP|INT|QUIT|TERM)$ &&
          "${values_ref[target_state]}" =~ \
            ^(launching|running|stopped|absent|unknown)$ ]] || return 1
      _qcsd_lifecycle_validate_scope_tuple "${values_name}" 1 || return 1
      control_group="${values_ref[scope_control_group]}"
      if [[ "${control_group}" != "unavailable" ]]; then
        canonical="$(realpath -m -- "${control_group}" 2>/dev/null)" || return 1
        [[ "${canonical}" == "${control_group}" &&
            "${control_group}" == */"${values_ref[scope_unit]}" &&
            "${control_group}" =~ ^/[A-Za-z0-9_.@:/-]+$ ]] || return 1
      fi
      ;;
    build)
      _qcsd_lifecycle_required_fields "${values_name}" \
        process_identity_role scope_launcher_pid scope_launcher_start_time \
        scope_launcher_session scope_launcher_process_group build_lock_path \
        build_lock_device build_lock_inode working_directory build_argv_sha256 \
        scope_required scope_unit scope_control_group status_file \
        status_file_state requested_signal forwarded_cli_signal \
        daemon_cancellation || return 1
      [[ "${values_ref[process_identity_role]}" == \
            "local-systemd-run-scope-launcher" &&
          "${values_ref[build_argv_sha256]}" =~ ^[0-9a-f]{64}$ &&
          "${values_ref[build_lock_device]}" =~ ^[0-9]+$ &&
          "${values_ref[build_lock_inode]}" =~ ^[1-9][0-9]*$ &&
          "${values_ref[working_directory]}" == /* &&
          "${values_ref[working_directory]}" != "/" &&
          "${values_ref[scope_required]}" == "1" &&
          "${values_ref[scope_unit]}" == \
            "qcsd-docker-build-${token}.scope" &&
          "${values_ref[status_file]}" == "${root}/build.status" &&
          "${values_ref[requested_signal]}" =~ ^(none|HUP|INT|QUIT|TERM)$ &&
          "${values_ref[forwarded_cli_signal]}" =~ ^(none|INT)$ &&
          "${values_ref[daemon_cancellation]}" == \
            "unavailable-client-disconnect-only" ]] || return 1
      canonical="$(realpath -m -- \
        "${values_ref[working_directory]}" 2>/dev/null)" || return 1
      [[ "${canonical}" == "${values_ref[working_directory]}" ]] || return 1
      [[ ! -L "${values_ref[build_lock_path]}" &&
          -f "${values_ref[build_lock_path]}" ]] || return 1
      lock_metadata="$(stat -Lc '%d:%i:%u:%a:%h:%F' -- \
        "${values_ref[build_lock_path]}" 2>/dev/null)" || return 1
      [[ "${lock_metadata}" == \
        "${values_ref[build_lock_device]}:${values_ref[build_lock_inode]}:${EUID}:600:1:regular empty file" ]] ||
        return 1
      _qcsd_lifecycle_validate_scope_tuple "${values_name}" 0 || return 1
      control_group="${values_ref[scope_control_group]}"
      if [[ "${control_group}" != "unavailable" ]]; then
        canonical="$(realpath -m -- "${control_group}" 2>/dev/null)" || return 1
        [[ "${canonical}" == "${control_group}" &&
            "${control_group}" == */"${values_ref[scope_unit]}" &&
            "${control_group}" =~ ^/[A-Za-z0-9_.@:/-]+$ ]] || return 1
      fi
      ;;
    transaction)
      _qcsd_lifecycle_required_fields "${values_name}" \
        working_directory cohort_version receipt_path transaction_state || return 1
      [[ "${values_ref[cohort_version]}" =~ ^[1-9][0-9]*$ &&
          "${values_ref[working_directory]}" == /* &&
          "${values_ref[working_directory]}" != "/" &&
          "${values_ref[receipt_path]}" == /* &&
          "${values_ref[receipt_path]}" != "/" &&
          "${values_ref[transaction_state]}" == \
            "uncommitted-static-tag-mutation" ]] || return 1
      ;;
  esac
  if [[ "${record_name}" == "HANDOFF" ]]; then
    _qcsd_lifecycle_required_fields "${values_name}" \
      ownership registration_name || return 1
    [[ "${values_ref[ownership]}" == "caller-cleanup-array" &&
        "${values_ref[registration_name]}" =~ \
          ^QCSD_DOCKER_IDS_[A-Z0-9_]+$ ]] || return 1
    if [[ "${root_kind}" == "run" ]]; then
      [[ "${values_ref[mode]}" == "detached" &&
          "${values_ref[container_id]}" =~ ^[0-9a-f]{64}$ ]] || return 1
    else
      [[ "${root_kind}" == "network" &&
          "${values_ref[network_id]}" =~ ^[0-9a-f]{64}$ ]] || return 1
    fi
  fi
  for field in scope_signal_attempted scope_leak_detected scope_kill_attempted \
      scope_empty_proven status_file_matches target_signal_attempted \
      forced_without_bound_target interrupted_without_bound_target \
      docker_cli_forced docker_cli_force_attempted target_forced \
      target_force_attempted cli_signal_attempted cli_forced \
      cli_force_attempted daemon_request_authorised; do
    [[ ! -v "values_ref[${field}]" ||
        "${values_ref[${field}]}" =~ ^[01]$ ]] || return 1
  done
  for field in scope_signal_outcome scope_kill_outcome \
      target_signal_api_outcome docker_cli_force_outcome \
      target_force_api_outcome cli_signal_outcome cli_force_outcome; do
    [[ ! -v "values_ref[${field}]" ||
        "${values_ref[${field}]}" =~ ^(not_attempted|accepted|unknown)$ ]] || return 1
  done
  if [[ -v 'values_ref[phase]' ]]; then
    [[ "${values_ref[phase]}" == "interrupted-before-daemon-teardown" ]] ||
      return 1
  fi
  if [[ "${record_name}" == "RECOVERY" &&
        "${values_ref[daemon_request_authorised]:-1}" == "0" ]]; then
    if [[ "${root_kind}" == "run" ]]; then
      [[ "${values_ref[container_id]}" == "unavailable" ]] || return 1
      if [[ -v 'values_ref[phase]' ]]; then
        [[ "${values_ref[status_file_state]}" =~ ^(declared|missing)$ ]] || return 1
      else
        [[ "${values_ref[status_file_state]}" =~ ^(missing|launcher-unreaped)$ &&
            "${values_ref[interruption_reason]}" != none &&
            "${values_ref[interrupted_without_bound_target]}" == 1 &&
            "${values_ref[target_state]}" =~ ^(absent|unknown)$ &&
            "${values_ref[target_signal_attempted]}" == 0 &&
            "${values_ref[target_force_attempted]}" == 0 ]] || return 1
      fi
    elif [[ "${root_kind}" == "network" ]]; then
      [[ "${values_ref[network_id]}" == "unavailable" ]] || return 1
    fi
  fi
  if [[ "${record_name}" == RECOVERY && ! -v 'values_ref[phase]' &&
        -v 'values_ref[status_file_matches]' ]]; then
    case "${values_ref[status_file_state]}" in
      valid)
        [[ "${values_ref[status_file_matches]}" == 1 &&
            "${values_ref[docker_command_status]}" =~ ^(0|[1-9][0-9]{0,2})$ &&
            "${values_ref[systemd_run_status]}" == \
              "${values_ref[docker_command_status]}" ]] || return 1
        (( values_ref[docker_command_status] <= 255 )) || return 1 ;;
      status-mismatch)
        [[ "${values_ref[status_file_matches]}" == 0 &&
            "${values_ref[docker_command_status]}" =~ ^(0|[1-9][0-9]{0,2})$ &&
            "${values_ref[systemd_run_status]}" =~ ^(0|[1-9][0-9]{0,2})$ &&
            "${values_ref[systemd_run_status]}" != \
              "${values_ref[docker_command_status]}" ]] || return 1
        (( values_ref[docker_command_status] <= 255 &&
           values_ref[systemd_run_status] <= 255 )) || return 1 ;;
      invalid|missing)
        [[ "${values_ref[status_file_matches]}" == 0 &&
            "${values_ref[docker_command_status]}" == unavailable &&
            "${values_ref[systemd_run_status]}" =~ ^(0|[1-9][0-9]{0,2})$ ]] ||
          return 1
        (( values_ref[systemd_run_status] <= 255 )) || return 1 ;;
      launcher-unreaped)
        [[ "${values_ref[status_file_matches]}" == 0 &&
            "${values_ref[docker_command_status]}" == unavailable &&
            "${values_ref[systemd_run_status]}" == unavailable ]] || return 1 ;;
      *) return 1 ;;
    esac
  fi
  if [[ "${record_name}" == RECOVERY &&
        -v 'values_ref[scope_empty_proven]' ]]; then
    if [[ "${values_ref[scope_empty_proven]}" == 1 ]]; then
      [[ "${values_ref[scope_final_state]}" =~ ^(inactive|absent)$ ]] || return 1
    else
      [[ "${values_ref[scope_final_state]}" == unknown &&
          "${values_ref[scope_leak_detected]}" == 1 ]] || return 1
    fi
    if [[ "${values_ref[scope_leak_detected]}" == 0 ]]; then
      [[ "${values_ref[scope_kill_attempted]}" == 0 &&
          "${values_ref[scope_kill_outcome]}" == not_attempted ]] || return 1
    else
      [[ "${values_ref[scope_kill_attempted]}" == 1 &&
          "${values_ref[scope_kill_outcome]}" =~ ^(accepted|unknown)$ ]] || return 1
    fi
  fi
  local attempted_key outcome_key pair
  for pair in scope_signal_attempted:scope_signal_outcome \
      target_signal_attempted:target_signal_api_outcome \
      docker_cli_force_attempted:docker_cli_force_outcome \
      target_force_attempted:target_force_api_outcome \
      cli_signal_attempted:cli_signal_outcome \
      cli_force_attempted:cli_force_outcome; do
    attempted_key="${pair%%:*}"
    outcome_key="${pair#*:}"
    [[ -v "values_ref[${attempted_key}]" ]] || continue
    if [[ "${values_ref[${attempted_key}]}" == 0 ]]; then
      [[ "${values_ref[${outcome_key}]}" == not_attempted ]] || return 1
    else
      [[ "${values_ref[${outcome_key}]}" =~ ^(accepted|unknown)$ ]] || return 1
    fi
  done
  for pair in docker_cli_forced:docker_cli_force cli_forced:cli_force; do
    field="${pair%%:*}"
    outcome_key="${pair#*:}"
    [[ ! -v "values_ref[${field}]" || "${values_ref[${field}]}" == 0 ||
        ( "${values_ref[${outcome_key}_attempted]}" == 1 &&
          "${values_ref[${outcome_key}_outcome]}" == accepted ) ]] || return 1
  done
  if [[ -v 'values_ref[target_forced]' &&
        "${values_ref[target_forced]}" == 1 ]]; then
    [[ "${values_ref[target_force_attempted]}" == 1 &&
        "${values_ref[target_force_api_outcome]}" =~ ^(accepted|unknown)$ ]] ||
      return 1
  fi
  if [[ "${root_kind}" == run && "${record_name}" == RECOVERY ]]; then
    [[ "${values_ref[target_state]}" != launching ]] || return 1
    if [[ "${values_ref[container_id]}" == unavailable ]]; then
      [[ "${values_ref[target_state]}" =~ ^(absent|unknown)$ ]] || return 1
    fi
    if [[ -v 'values_ref[phase]' ]]; then
      [[ "${values_ref[scope_state]}" =~ \
          ^(unavailable|active|inactive|absent|unknown)$ &&
          ( "${values_ref[scope_state]}" != active ||
            "${values_ref[scope_control_group]}" != unavailable ) ]] || return 1
    fi
    # requested_signal is a lifetime latch and can change after the teardown
    # reason/target snapshot.  Therefore a late host signal may coexist with
    # an earlier none or internal-abort reason; it must not retroactively alter
    # the already attempted target action recorded below.
    case "${values_ref[interruption_reason]}" in
      none)
        [[ "${values_ref[planned_target_signal]}" == none ]] || return 1 ;;
      internal_abort)
        if [[ "${values_ref[mode]}" == attached ]]; then
          [[ "${values_ref[planned_target_signal]}" == INT ]] || return 1
        else
          [[ "${values_ref[planned_target_signal]}" == TERM ]] || return 1
        fi ;;
      host_signal)
        [[ "${values_ref[requested_signal]}" != none ]] || return 1
        if [[ "${values_ref[mode]}" == attached ]]; then
          [[ "${values_ref[planned_target_signal]}" == INT ]] || return 1
        else
          [[ "${values_ref[planned_target_signal]}" == \
              "${values_ref[requested_signal]}" ]] || return 1
        fi ;;
      *) return 1 ;;
    esac
    if [[ -v 'values_ref[phase]' ]]; then
      [[ "${values_ref[interruption_reason]}" != none &&
          "${values_ref[target_signal_attempted]}" == 0 &&
          "${values_ref[target_signal_api_outcome]}" == not_attempted &&
          "${values_ref[forwarded_target_signal]}" == none ]] || return 1
    else
      case "${values_ref[target_signal_attempted]}:${values_ref[target_signal_api_outcome]}:${values_ref[forwarded_target_signal]}" in
        0:not_attempted:none|1:unknown:none) ;;
        1:accepted:*)
          [[ "${values_ref[forwarded_target_signal]}" == \
              "${values_ref[planned_target_signal]}" ]] || return 1 ;;
        *) return 1 ;;
      esac
      if [[ "${values_ref[interruption_reason]}" == none ]]; then
        [[ "${values_ref[target_signal_attempted]}" == 0 &&
            "${values_ref[target_signal_api_outcome]}" == not_attempted &&
            "${values_ref[forwarded_target_signal]}" == none ]] || return 1
      fi
      case "${values_ref[target_force_attempted]}:${values_ref[target_forced]}:${values_ref[target_force_api_outcome]}" in
        0:0:not_attempted|1:1:accepted|1:1:unknown) ;;
        *) return 1 ;;
      esac
      if [[ "${values_ref[target_signal_attempted]}" == 1 ||
            "${values_ref[target_force_attempted]}" == 1 ]]; then
        [[ "${values_ref[container_id]}" =~ ^[0-9a-f]{64}$ ]] || return 1
      fi
      case "${values_ref[docker_cli_force_attempted]}:${values_ref[docker_cli_forced]}:${values_ref[docker_cli_force_outcome]}" in
        0:0:not_attempted|1:0:unknown|1:1:accepted) ;;
        *) return 1 ;;
      esac
      if [[ "${values_ref[interrupted_without_bound_target]}" == 1 ]]; then
        [[ "${values_ref[interruption_reason]}" != none ]] || return 1
      fi
      if [[ "${values_ref[container_id]}" == unavailable &&
            "${values_ref[interruption_reason]}" != none ]]; then
        [[ "${values_ref[interrupted_without_bound_target]}" == 1 ]] || return 1
      fi
      if [[ "${values_ref[forced_without_bound_target]}" == 1 ]]; then
        [[ "${values_ref[interrupted_without_bound_target]}" == 1 &&
            "${values_ref[docker_cli_force_attempted]}" == 1 &&
            "${values_ref[interruption_reason]}" != none ]] || return 1
      fi
    fi
  fi
  if [[ "${root_kind}" == build && "${record_name}" == RECOVERY ]]; then
    case "${values_ref[scope_signal_attempted]}:${values_ref[scope_signal_outcome]}" in
      0:not_attempted) ;;
      1:accepted|1:unknown)
        [[ "${values_ref[requested_signal]}" != none ]] || return 1 ;;
      *) return 1 ;;
    esac
    case "${values_ref[cli_signal_attempted]}:${values_ref[cli_signal_outcome]}:${values_ref[forwarded_cli_signal]}" in
      0:not_attempted:none|1:unknown:none|1:accepted:INT) ;;
      *) return 1 ;;
    esac
    if [[ "${values_ref[cli_signal_attempted]}" == 1 ]]; then
      [[ "${values_ref[requested_signal]}" != none &&
          "${values_ref[scope_signal_attempted]}" == 1 ]] || return 1
    fi
    case "${values_ref[cli_force_attempted]}:${values_ref[cli_forced]}:${values_ref[cli_force_outcome]}" in
      0:0:not_attempted|1:0:unknown|1:1:accepted) ;;
      *) return 1 ;;
    esac
  fi
  if [[ -v 'values_ref[forwarded_target_signal]' &&
        "${values_ref[forwarded_target_signal]}" != none ]]; then
    [[ "${values_ref[target_signal_attempted]}" == 1 &&
        "${values_ref[target_signal_api_outcome]}" == accepted &&
        "${values_ref[forwarded_target_signal]}" == \
          "${values_ref[planned_target_signal]}" ]] || return 1
  fi
  if [[ -v 'values_ref[forwarded_cli_signal]' &&
        "${values_ref[forwarded_cli_signal]}" != none ]]; then
    [[ "${values_ref[cli_signal_attempted]}" == 1 &&
        "${values_ref[cli_signal_outcome]}" == accepted &&
        "${values_ref[forwarded_cli_signal]}" == INT ]] || return 1
  fi
}

_qcsd_lifecycle_records_match() {
  local first_name="$1"
  local second_name="$2"
  local -n first_ref="${first_name}"
  local -n second_ref="${second_name}"
  local field
  for field in object lifecycle_schema lifecycle_root lifecycle_token \
      supervisor_source_path supervisor_source_sha256 supervisor_source_device \
      supervisor_source_inode docker_context docker_host docker_server_id \
      docker_request_revalidation docker_daemon_id host_boot_id; do
    [[ "${first_ref[${field}]}" == "${second_ref[${field}]}" ]] || return 1
  done
  for field in supervisor_pid supervisor_start_time supervisor_session \
      supervisor_process_group process_identity_role mode supervisor_label \
      request_argv_sha256 build_argv_sha256 scope_required scope_unit \
      status_file build_lock_path build_lock_device build_lock_inode \
      working_directory daemon_cancellation; do
    if [[ -v "first_ref[${field}]" && -v "second_ref[${field}]" ]]; then
      [[ "${first_ref[${field}]}" == "${second_ref[${field}]}" ]] || return 1
    fi
  done
  for field in container_id network_id; do
    if [[ -v "first_ref[${field}]" && -v "second_ref[${field}]" ]]; then
      if [[ "${first_ref[${field}]}" != "unavailable" ]]; then
        [[ "${second_ref[${field}]}" == "${first_ref[${field}]}" ]] || return 1
      fi
    fi
  done
  for field in scope_launcher_pid scope_launcher_start_time \
      scope_launcher_session scope_launcher_process_group cli_pid cli_start_time \
      cli_session cli_process_group scope_control_group; do
    if [[ -v "first_ref[${field}]" && -v "second_ref[${field}]" ]]; then
      if [[ "${first_ref[${field}]}" == "unavailable" ]]; then
        : # One-way binding from unavailable to an exact durable identity.
      else
        [[ "${second_ref[${field}]}" == "${first_ref[${field}]}" ]] || return 1
      fi
    fi
  done
  if [[ -v 'second_ref[daemon_request_authorised]' ]]; then
    case "${first_ref[lifecycle_state]}" in
      declared) [[ "${second_ref[daemon_request_authorised]}" == 0 ]] || return 1 ;;
      request-authorised|bound|handed-off)
        [[ "${second_ref[daemon_request_authorised]}" == 1 ]] || return 1 ;;
    esac
  fi
  if [[ -v 'first_ref[requested_signal]' &&
        -v 'second_ref[requested_signal]' &&
        "${first_ref[requested_signal]}" != none ]]; then
    [[ "${second_ref[requested_signal]}" == \
      "${first_ref[requested_signal]}" ]] || return 1
  fi
}

_qcsd_lifecycle_apply_launcher_birth() {
  local root="$1"
  local root_kind="$2"
  local values_name="$3"
  local -n values_ref="${values_name}"
  local lock_path="${root}/BIRTH.lock" birth_path="${root}/launcher.birth"
  local lock_fd lock_metadata fd_metadata
  if [[ ! -e "${lock_path}" && ! -L "${lock_path}" &&
        ! -e "${birth_path}" && ! -L "${birth_path}" ]]; then
    return 0
  fi
  [[ "${root_kind}" == "run" || "${root_kind}" == "build" ]] || return 1
  [[ ! -L "${lock_path}" && -f "${lock_path}" ]] || return 1
  lock_metadata="$(stat -Lc '%d:%i:%u:%a:%h:%F' -- \
    "${lock_path}" 2>/dev/null)" || return 1
  [[ "${lock_metadata}" == *":${EUID}:600:1:regular empty file" ]] || return 1
  exec {lock_fd}<>"${lock_path}" || return 1
  fd_metadata="$(stat -Lc '%d:%i:%u:%a:%h:%F' -- \
    "/proc/${BASHPID}/fd/${lock_fd}" 2>/dev/null)" || {
    exec {lock_fd}>&-
    return 1
  }
  if [[ "${fd_metadata}" != "${lock_metadata}" ]] ||
     ! flock -w "${_QCSD_DOCKER_BIRTH_LOCK_WAIT_SECONDS:-3}" \
        "${lock_fd}"; then
    exec {lock_fd}>&-
    return 1
  fi
  if [[ ! -e "${birth_path}" && ! -L "${birth_path}" ]]; then
    exec {lock_fd}>&-
    return 0
  fi
  if ! _qcsd_private_launcher_birth "${birth_path}" "${root}" \
      "${values_ref[lifecycle_token]}" "${root_kind}"; then
    exec {lock_fd}>&-
    return 1
  fi
  exec {lock_fd}>&-
  if [[ "${values_ref[scope_launcher_pid]}" == "unavailable" ]]; then
    if [[ "${values_ref[lifecycle_state]}" == unresolved ]]; then
      [[ "${root_kind}" == build ||
          ( "${root_kind}" == run &&
            "${values_ref[daemon_request_authorised]}" == 0 ) ]] || return 1
    else
      [[ "${values_ref[lifecycle_state]}" == declared ]] || return 1
    fi
    values_ref[scope_launcher_pid]="${_qcsd_birth_pid}"
    values_ref[scope_launcher_start_time]="${_qcsd_birth_start_time}"
    values_ref[scope_launcher_session]="${_qcsd_birth_session}"
    values_ref[scope_launcher_process_group]="${_qcsd_birth_process_group}"
    if [[ "${root_kind}" == "run" ]]; then
      values_ref[cli_pid]="${_qcsd_birth_pid}"
      values_ref[cli_start_time]="${_qcsd_birth_start_time}"
      values_ref[cli_session]="${_qcsd_birth_session}"
      values_ref[cli_process_group]="${_qcsd_birth_process_group}"
    fi
  else
    [[ "${values_ref[scope_launcher_pid]}" == "${_qcsd_birth_pid}" &&
        "${values_ref[scope_launcher_start_time]}" == \
          "${_qcsd_birth_start_time}" &&
        "${values_ref[scope_launcher_session]}" == "${_qcsd_birth_session}" &&
        "${values_ref[scope_launcher_process_group]}" == \
          "${_qcsd_birth_process_group}" ]] || return 1
  fi
}

_qcsd_lifecycle_validate_root() {
  local root="$1"
  local root_kind="$2"
  local record record_name selected_name="" selected_record="" child child_name
  local -A supervision_values=() recovery_values=() handoff_values=()
  local -a supervision_order=() recovery_order=() handoff_order=()
  _qcsd_validate_lifecycle_root_contents "${root}" || return 1
  # The low-level metadata validator recognises the union of private files;
  # reject cross-kind smuggling before parsing or mutating any root.
  for child in "${root}"/*; do
    [[ -e "${child}" || -L "${child}" ]] || continue
    child_name="${child##*/}"
    case "${root_kind}:${child_name}" in
      run:SUPERVISION|run:SUPERVISION.next|run:RECOVERY|run:RECOVERY.next|\
      run:HANDOFF|run:HANDOFF.next|run:container.cid|run:run.status|\
      run:run.status.next|run:BIRTH.lock|run:launcher.birth|\
      run:launcher.birth.next|run:stdout|run:wait.pipe|\
      build:SUPERVISION|build:SUPERVISION.next|build:RECOVERY|\
      build:RECOVERY.next|build:build.status|build:build.status.next|\
      build:BIRTH.lock|build:launcher.birth|build:launcher.birth.next|\
      build:wait.pipe|network:SUPERVISION|network:SUPERVISION.next|\
      network:RECOVERY|network:RECOVERY.next|network:HANDOFF|\
      network:HANDOFF.next|transaction:SUPERVISION|\
      transaction:SUPERVISION.next) ;;
      *) return 1 ;;
    esac
  done
  for record_name in SUPERVISION RECOVERY HANDOFF; do
    record="${root}/${record_name}"
    if [[ -e "${record}" || -L "${record}" ]]; then
      case "${record_name}" in
        SUPERVISION) selected_name=supervision_values; selected_record="${record}" ;;
        RECOVERY) selected_name=recovery_values; selected_record="${record}" ;;
        HANDOFF) selected_name=handoff_values; selected_record="${record}" ;;
      esac
      _qcsd_lifecycle_parse_record "${record}" "${selected_name}" \
        "${record_name,,}_order" || return 1
      _qcsd_lifecycle_validate_record "${root}" "${root_kind}" \
        "${record_name}" "${selected_name}" || return 1
    fi
  done
  declare -g _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED=0
  if [[ -z "${selected_record}" ]]; then
    # The root directory is fsynced before the first receipt is published.
    # A host kill in that narrow interval can therefore leave an empty root,
    # a private FIFO/stdout file, or an incomplete initial SUPERVISION.next.
    # The daemon request is gated on the final SUPERVISION publication, so an
    # exclusively admitted launcher may retire precisely these known
    # pre-request shapes without guessing about Docker ownership.
    for child in "${root}"/*; do
      [[ -e "${child}" || -L "${child}" ]] || continue
      child_name="${child##*/}"
      case "${root_kind}:${child_name}" in
        run:SUPERVISION.next|run:wait.pipe|run:stdout|\
        network:SUPERVISION.next|\
        build:SUPERVISION.next|build:wait.pipe|\
        transaction:SUPERVISION.next) ;;
        *) return 1 ;;
      esac
    done
    declare -gA _QCSD_LIFECYCLE_SELECTED_VALUES=()
    _QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_token]="${root##*.}"
    _QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]="declared"
    _QCSD_LIFECYCLE_SELECTED_RECORD="unpublished"
    _QCSD_LIFECYCLE_SELECTED_KIND="${root_kind}"
    _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED=1
    return 0
  fi
  # Once a final receipt exists, an adjacent staged update may contain a
  # newer process/object identity.  Without its publisher's live birth lock
  # there is no sound way to decide whether to promote or discard it, so keep
  # the complete root untouched for explicit audit rather than recovering
  # from an older receipt and losing possible ownership.
  for record in "${root}/SUPERVISION.next" "${root}/RECOVERY.next" \
      "${root}/HANDOFF.next" "${root}/run.status.next" \
      "${root}/build.status.next"; do
    [[ ! -e "${record}" && ! -L "${record}" ]] || return 1
  done
  if (( ${#supervision_values[@]} && ${#recovery_values[@]} )); then
    _qcsd_lifecycle_records_match supervision_values recovery_values || return 1
  fi
  if (( ${#supervision_values[@]} && ${#handoff_values[@]} )); then
    [[ "${supervision_values[lifecycle_state]}" == bound ]] || return 1
    _qcsd_lifecycle_records_match supervision_values handoff_values || return 1
  fi
  if (( ${#recovery_values[@]} && ${#handoff_values[@]} )); then
    [[ ! -v 'recovery_values[phase]' ]] || return 1
    _qcsd_lifecycle_records_match handoff_values recovery_values || return 1
  fi
  if (( ${#recovery_values[@]} )); then
    selected_name=recovery_values
    selected_record="${root}/RECOVERY"
  elif (( ${#handoff_values[@]} )); then
    selected_name=handoff_values
    selected_record="${root}/HANDOFF"
  else
    selected_name=supervision_values
    selected_record="${root}/SUPERVISION"
  fi
  declare -gA _QCSD_LIFECYCLE_SELECTED_VALUES=()
  local -n selected_ref="${selected_name}"
  local selected_key
  for selected_key in "${!selected_ref[@]}"; do
    _QCSD_LIFECYCLE_SELECTED_VALUES["${selected_key}"]="${selected_ref[${selected_key}]}"
  done
  if [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}" == declared ]]; then
    if [[ "${root_kind}" == run &&
          ( -e "${root}/run.status" || -L "${root}/run.status" ) ]]; then
      return 1
    elif [[ "${root_kind}" == build &&
            ( -e "${root}/build.status" || -L "${root}/build.status" ) ]]; then
      return 1
    fi
  fi
  if [[ "${root_kind}" == run &&
        ( -e "${root}/container.cid" || -L "${root}/container.cid" ) ]]; then
    local validated_cidfile_id
    validated_cidfile_id="$(_qcsd_private_cid "${root}/container.cid")" || return 1
    [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}" != declared ]] ||
      return 1
    if [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}" == unresolved &&
          "${_QCSD_LIFECYCLE_SELECTED_VALUES[daemon_request_authorised]}" == 0 ]]; then
      return 1
    fi
    if [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[container_id]}" == unavailable ]]; then
      _QCSD_LIFECYCLE_SELECTED_VALUES[container_id]="${validated_cidfile_id}"
    else
      [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[container_id]}" == \
          "${validated_cidfile_id}" ]] || return 1
    fi
  fi
  # Before request authority exists, neither launcher can have produced a
  # terminal status.  Capture-mode stdout is created empty before the birth
  # stop and must likewise remain empty until the launcher is released.
  if [[ ( "${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}" == declared ||
          ( "${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}" == unresolved &&
            "${_QCSD_LIFECYCLE_SELECTED_VALUES[daemon_request_authorised]:-1}" == 0 ) ) ]]; then
    if [[ "${root_kind}" == run ]]; then
      [[ ! -e "${root}/run.status" && ! -L "${root}/run.status" ]] || return 1
      if [[ -e "${root}/stdout" || -L "${root}/stdout" ]]; then
        [[ ! -L "${root}/stdout" && -f "${root}/stdout" &&
            ! -s "${root}/stdout" ]] || return 1
      fi
    elif [[ "${root_kind}" == build ]]; then
      [[ ! -e "${root}/build.status" && ! -L "${root}/build.status" ]] || return 1
    fi
  fi
  if [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}" == unresolved &&
        -v '_QCSD_LIFECYCLE_SELECTED_VALUES[scope_final_state]' &&
        -v '_QCSD_LIFECYCLE_SELECTED_VALUES[status_file_state]' ]]; then
    local status_path="${_QCSD_LIFECYCLE_SELECTED_VALUES[status_file]}"
    local observed_status
    case "${_QCSD_LIFECYCLE_SELECTED_VALUES[status_file_state]}" in
      valid|status-mismatch)
        observed_status="$(_qcsd_private_exit_status "${status_path}")" || return 1
        [[ "${observed_status}" == \
          "${_QCSD_LIFECYCLE_SELECTED_VALUES[docker_command_status]}" ]] || return 1 ;;
      invalid)
        [[ -e "${status_path}" && ! -L "${status_path}" ]] || return 1
        ! _qcsd_private_exit_status "${status_path}" >/dev/null 2>&1 || return 1 ;;
      missing)
        [[ ! -e "${status_path}" && ! -L "${status_path}" ]] || return 1 ;;
      launcher-unreaped) ;;
      *) return 1 ;;
    esac
  fi
  _qcsd_lifecycle_apply_launcher_birth "${root}" "${root_kind}" \
    _QCSD_LIFECYCLE_SELECTED_VALUES || return 1
  [[ ! -e "${root}/launcher.birth.next" &&
      ! -L "${root}/launcher.birth.next" ]] || return 1
  _QCSD_LIFECYCLE_SELECTED_RECORD="${selected_record}"
  _QCSD_LIFECYCLE_SELECTED_KIND="${root_kind}"
}

_qcsd_lifecycle_preauthorisation_contradiction() {
  local root_kind="$1" values_name="$2" current_boot="$3"
  local -n values_ref="${values_name}"
  local pid="${values_ref[scope_launcher_pid]:-unavailable}"
  [[ "${values_ref[lifecycle_state]}" == declared ||
      ( "${values_ref[lifecycle_state]}" == unresolved &&
        "${values_ref[daemon_request_authorised]:-1}" == 0 ) ]] || return 1
  [[ "${values_ref[host_boot_id]}" == "${current_boot}" &&
      "${pid}" != unavailable ]] || return 1
  # A same-boot durable birth proves the precise child, but only a still-live
  # stopped child proves that CONT/exec never occurred.  Gone, zombie,
  # identity-mismatched, or non-stopped states are ambiguous execution and
  # must be contained where possible while the ledger remains quarantined.
  if _qcsd_read_process_identity "${pid}" &&
     [[ "${_qcsd_process_start_time}" == "${values_ref[scope_launcher_start_time]}" &&
        "${_qcsd_process_session}" == "${values_ref[scope_launcher_session]}" &&
        "${_qcsd_process_group}" == "${values_ref[scope_launcher_process_group]}" &&
        "${_qcsd_process_state}" == T ]]; then
    return 1
  fi
  return 0
}

_qcsd_lifecycle_preauthorisation_object_absent() {
  local root_kind="$1" values_name="$2"
  local -n values_ref="${values_name}"
  local _qcsd_target_docker_context="${values_ref[docker_context]}"
  [[ "${values_ref[lifecycle_state]}" == declared ||
      ( "${values_ref[lifecycle_state]}" == unresolved &&
        "${values_ref[daemon_request_authorised]:-1}" == 0 ) ]] || return 0
  case "${root_kind}" in
    run)
      _qcsd_resolve_docker_target "" "${values_ref[lifecycle_token]}"
      [[ "${_qcsd_resolved_state}" == absent ]] ;;
    network)
      _qcsd_resolve_docker_network "${values_ref[lifecycle_token]}" ""
      [[ "${_qcsd_resolved_network_state}" == absent ]] ;;
    build) return 0 ;;
    *) return 1 ;;
  esac
}

_qcsd_lifecycle_require_stale_supervisor() {
  local values_name="$1"
  local current_boot="$2"
  local -n values_ref="${values_name}"
  [[ "${values_ref[host_boot_id]}" == "${current_boot}" ]] || return 0
  [[ -v 'values_ref[supervisor_pid]' ]] || return 0
  if _qcsd_job_is_running \
      "${values_ref[supervisor_pid]}" "${values_ref[supervisor_start_time]}" \
      "${values_ref[supervisor_session]}" \
      "${values_ref[supervisor_process_group]}"; then
    return 1
  fi
  _qcsd_bound_process_is_gone \
    "${values_ref[supervisor_pid]}" "${values_ref[supervisor_start_time]}" \
    "${values_ref[supervisor_session]}" \
    "${values_ref[supervisor_process_group]}"
}

_qcsd_lifecycle_stop_stale_scope() {
  local values_name="$1"
  local current_boot="$2"
  local require_preauthorised_stop="${3:-0}"
  local -n values_ref="${values_name}"
  local pid="${values_ref[scope_launcher_pid]}"
  local preauthorised_exact_kill=0
  declare -g _QCSD_PREAUTH_CONTRADICTION_AT_CONTAINMENT=0
  [[ "${values_ref[host_boot_id]}" == "${current_boot}" ]] || return 0
  if [[ "${require_preauthorised_stop}" == 1 && "${pid}" != unavailable ]]; then
    if ! _qcsd_job_is_running "${pid}" \
        "${values_ref[scope_launcher_start_time]}" \
        "${values_ref[scope_launcher_session]}" \
        "${values_ref[scope_launcher_process_group]}" ||
       [[ "${_qcsd_process_state}" != T ]]; then
      _QCSD_PREAUTH_CONTRADICTION_AT_CONTAINMENT=1
    fi
  fi
  if [[ "${pid}" != "unavailable" ]] &&
     _qcsd_job_is_running "${pid}" \
       "${values_ref[scope_launcher_start_time]}" \
       "${values_ref[scope_launcher_session]}" \
       "${values_ref[scope_launcher_process_group]}"; then
    [[ "$(stat -Lc '%u' -- "/proc/${pid}" 2>/dev/null)" == "${EUID}" ]] ||
      return 1
    local required_state=""
    [[ "${require_preauthorised_stop}" != 1 ]] || required_state=T
    if ! _qcsd_signal_bound_process_group "${pid}" \
      "${values_ref[scope_launcher_start_time]}" \
      "${values_ref[scope_launcher_session]}" \
      "${values_ref[scope_launcher_process_group]}" KILL "${required_state}"; then
      if [[ "${require_preauthorised_stop}" == 1 ]]; then
        _QCSD_PREAUTH_CONTRADICTION_AT_CONTAINMENT=1
        # The exact child no longer proves the pre-CONT stopped state.  Do
        # not authorise a numeric process-group signal, but still contain the
        # uniquely named mandatory scope before preserving the ledger.
        _qcsd_kill_user_scope "${values_ref[scope_unit]}" KILL || true
        _qcsd_wait_user_scope_inactive "${values_ref[scope_unit]}" || return 1
      fi
    elif [[ "${require_preauthorised_stop}" == 1 ]]; then
      preauthorised_exact_kill=1
    fi
    _qcsd_wait_for_job_stop "${pid}" \
      "${values_ref[scope_launcher_start_time]}" \
      "${values_ref[scope_launcher_session]}" \
      "${values_ref[scope_launcher_process_group]}" \
      "${_QCSD_DOCKER_REAP_POLLS}" "${_QCSD_DOCKER_REAP_DELAY_SECONDS}" || true
  fi
  if [[ "${require_preauthorised_stop}" == 1 && "${pid}" != unavailable &&
        "${preauthorised_exact_kill}" == 0 ]]; then
    _QCSD_PREAUTH_CONTRADICTION_AT_CONTAINMENT=1
  fi
  if [[ "${require_preauthorised_stop}" == 1 &&
        "${_QCSD_PREAUTH_CONTRADICTION_AT_CONTAINMENT}" == 1 ]]; then
    _qcsd_kill_user_scope "${values_ref[scope_unit]}" KILL || true
    _qcsd_wait_user_scope_inactive "${values_ref[scope_unit]}" || return 1
  fi
  if [[ "${pid}" != "unavailable" ]] &&
     ! _qcsd_bound_process_is_gone "${pid}" \
       "${values_ref[scope_launcher_start_time]}" \
       "${values_ref[scope_launcher_session]}" \
       "${values_ref[scope_launcher_process_group]}"; then
    return 1
  fi
  if ! _qcsd_wait_user_scope_inactive "${values_ref[scope_unit]}"; then
    _qcsd_kill_user_scope "${values_ref[scope_unit]}" KILL || true
    _qcsd_wait_user_scope_inactive "${values_ref[scope_unit]}" || return 1
  fi
}

_qcsd_retirement_authority_path() {
  local root="$1" name="${root##*/}"
  [[ "${name}" =~ ^(run|network|build|transaction)\.([0-9a-f]{32})$ ]] || return 1
  printf '%s/retirement.%s.%s\n' "${root%/*}" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}

_qcsd_retirement_authority_binding() {
  local authority="$1" metadata
  [[ -f "${authority}" && ! -L "${authority}" ]] || return 1
  metadata="$(stat -Lc '%d:%i:%u:%a:%h:%s:%F' -- "${authority}")" || return 1
  IFS=: read -r _QCSD_RETIRE_AUTH_DEV _QCSD_RETIRE_AUTH_INO \
    _QCSD_RETIRE_AUTH_UID _QCSD_RETIRE_AUTH_MODE _QCSD_RETIRE_AUTH_LINKS \
    _QCSD_RETIRE_AUTH_SIZE _QCSD_RETIRE_AUTH_TYPE <<<"${metadata}"
  [[ "${_QCSD_RETIRE_AUTH_UID}" == "${EUID}" &&
      "${_QCSD_RETIRE_AUTH_MODE}" == 600 && "${_QCSD_RETIRE_AUTH_LINKS}" == 1 &&
      "${_QCSD_RETIRE_AUTH_TYPE}" == "regular file" ]] || return 1
  _QCSD_RETIRE_AUTH_SHA="$(sha256sum -- "${authority}" | awk '{print $1}')" || return 1
  [[ "${_QCSD_RETIRE_AUTH_SHA}" =~ ^[0-9a-f]{64}$ ]]
}

_qcsd_retirement_native_authenticated() {
  local action="$1" authority="$2"
  shift 2
  local base="${authority%/*}" base_meta
  _qcsd_retirement_authority_binding "${authority}" || return 1
  base_meta="$(stat -Lc '%d:%i' -- "${base}")" || return 1
  _qcsd_retirement_boundary_hook H14 "${action}" "${authority}"
  _qcsd_retirement_native_op "${action}" "${base}" "${EUID}" \
    "${base_meta%%:*}" "${base_meta##*:}" --authority "${authority##*/}" \
    "${_QCSD_RETIRE_AUTH_DEV}" "${_QCSD_RETIRE_AUTH_INO}" \
    "${_QCSD_RETIRE_AUTH_SIZE}" "${_QCSD_RETIRE_AUTH_SHA}" "$@" || return 1
  _qcsd_retirement_boundary_hook H15 "${action}" "${authority}"
}

_qcsd_retirement_prepare_authority() {
  local root="$1" reason="$2" allow_staged="$3"
  local authority="$4" kind token root_meta root_manifest entry name metadata digest
  local record_name=unavailable record_hash=unavailable record_state=unavailable
  local object_id=unavailable supervisor_label=unavailable scope_unit=unavailable
  local registration_name=unavailable
  local launcher_pid=unavailable launcher_start=unavailable
  local launcher_session=unavailable launcher_group=unavailable
  local transaction_receipt=unavailable transaction_receipt_dev=unavailable
  local transaction_receipt_ino=unavailable transaction_receipt_sha=unavailable
  local base_identity guardian_path guardian_meta guardian_sha qcsd_path qcsd_meta qcsd_sha
  local helper_path helper_meta helper_sha native_path native_meta native_sha
  local lock_path lock_parent_identity
  local docker_config_name docker_config_boot docker_config_metadata
  local docker_config_first_entry
  local source_name source_path_name source_path
  local guardian_dev guardian_ino qcsd_dev qcsd_ino helper_dev helper_ino
  local native_dev native_ino ignored
  kind="${root##*/}"; token="${kind#*.}"; kind="${kind%%.*}"
  [[ "${kind}" =~ ^(run|network|build|transaction)$ && "${token}" =~ ^[0-9a-f]{32}$ &&
      "${reason}" =~ ^(recovered-stale|handoff-retired|transaction-committed|unpublished)$ &&
      "${allow_staged}" =~ ^[01]$ ]] || return 1
  _qcsd_validate_lifecycle_root_contents "${root}" || return 1
  base_identity="$(stat -Lc '%d:%i:%u:%a:%F' -- "${root%/*}")" || return 1
  guardian_path="${_QCSD_LIFECYCLE_GUARD_SOURCE_PATH:-}"
  qcsd_path="${_QCSD_LIFECYCLE_QCSD_SOURCE_PATH:-}"
  helper_path="${_QCSD_LIFECYCLE_HELPER_SOURCE_PATH:-}"
  native_path="${_QCSD_LIFECYCLE_NATIVE_PATH:-}"
  lock_path="${_QCSD_LIFECYCLE_LOCK_PATH:-}"
  [[ "${lock_path}" == /* && -f "${lock_path}" && ! -L "${lock_path}" ]] || return 1
  lock_parent_identity="$(stat -Lc '%d:%i' -- "${lock_path%/*}")" || return 1
  [[ "${lock_parent_identity}" == "${_QCSD_LIFECYCLE_LOCK_PARENT_DEVICE}:${_QCSD_LIFECYCLE_LOCK_PARENT_INODE}" &&
      "$(stat -Lc '%d:%i' -- "${lock_path}")" == "${_QCSD_LIFECYCLE_LOCK_DEVICE}:${_QCSD_LIFECYCLE_LOCK_INODE}" ]] || return 1
  docker_config_name="${_QCSD_LIFECYCLE_DOCKER_CONFIG_PATH##*/}"
  docker_config_boot="${_QCSD_LIFECYCLE_BOOT_ID//-/}"
  [[ "${docker_config_name}" =~ ^[.]qcsd-docker-config-${EUID}[.]v2[.]([0-9a-f]{32})[.]([1-9][0-9]*)[.][0-9a-f]{64}$ ]] || return 1
  [[ "${BASH_REMATCH[1]}" == "${docker_config_boot}" &&
      "${BASH_REMATCH[2]}" == "${_QCSD_LIFECYCLE_GUARD_START}" ]] || return 1
  [[ "${_QCSD_LIFECYCLE_LOCK_DEVICE:-}" =~ ^[0-9]+$ &&
      "${_QCSD_LIFECYCLE_LOCK_INODE:-}" =~ ^[0-9]+$ &&
      "${_QCSD_LIFECYCLE_HELPER_SHA256:-}" =~ ^[0-9a-f]{64}$ &&
      "${_QCSD_LIFECYCLE_DOCKER_CONFIG_PATH%/*}" == "${lock_path%/*}" &&
      "${_QCSD_LIFECYCLE_DOCKER_CONFIG_DEVICE:-}" =~ ^[0-9]+$ &&
      "${_QCSD_LIFECYCLE_DOCKER_CONFIG_INODE:-}" =~ ^[0-9]+$ &&
      -d "${_QCSD_LIFECYCLE_DOCKER_CONFIG_PATH}" &&
      ! -L "${_QCSD_LIFECYCLE_DOCKER_CONFIG_PATH}" &&
      "${_QCSD_EXECUTED_HELPER_SOURCE_SHA256:-}" == "${_QCSD_LIFECYCLE_HELPER_SHA256}" &&
      "${_QCSD_DOCKER_PINNED_CONTEXT:-}" =~ ^[A-Za-z0-9_.-]+$ &&
      "${_QCSD_DOCKER_PINNED_CONTEXT}" != unavailable &&
      "${_QCSD_DOCKER_PINNED_HOST:-}" =~ ^(unix:///var/run/docker[.]sock|npipe:////[.]/pipe/dockerDesktopLinuxEngine)$ &&
      "${_QCSD_DOCKER_PINNED_SERVER_ID:-}" =~ ^[A-Za-z0-9_.:-]+$ &&
      "${_QCSD_DOCKER_PINNED_SERVER_ID}" != unavailable &&
      "${_QCSD_DOCKER_PINNED_BOOT_ID:-}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  docker_config_metadata="$(stat -Lc '%d:%i:%u:%a:%h:%F' -- \
    "${_QCSD_LIFECYCLE_DOCKER_CONFIG_PATH}")" || return 1
  docker_config_first_entry="$(find -H \
    "${_QCSD_LIFECYCLE_DOCKER_CONFIG_PATH}" \
    -mindepth 1 -maxdepth 1 -print -quit)" || true
  [[ "${docker_config_metadata}" == \
        "${_QCSD_LIFECYCLE_DOCKER_CONFIG_DEVICE}:${_QCSD_LIFECYCLE_DOCKER_CONFIG_INODE}:${EUID}:500:2:directory" &&
      -z "${docker_config_first_entry}" ]] || return 1
  for source_name in guardian qcsd helper native; do
    source_path_name="${source_name}_path"; source_path="${!source_path_name}"
    [[ "${source_path}" == /* && -f "${source_path}" && ! -L "${source_path}" ]] || return 1
    printf -v "${source_name}_meta" '%s' "$(stat -Lc '%d:%i:%u:%a:%h:%s:%F' -- "${source_path}")" || return 1
    printf -v "${source_name}_sha" '%s' "$(sha256sum -- "${source_path}" | awk '{print $1}')" || return 1
  done
  IFS=: read -r guardian_dev guardian_ino ignored <<<"${guardian_meta}"
  IFS=: read -r qcsd_dev qcsd_ino ignored <<<"${qcsd_meta}"
  IFS=: read -r helper_dev helper_ino ignored <<<"${helper_meta}"
  IFS=: read -r native_dev native_ino ignored <<<"${native_meta}"
  [[ "${guardian_dev}" == "${_QCSD_LIFECYCLE_GUARD_SOURCE_DEVICE}" &&
      "${guardian_ino}" == "${_QCSD_LIFECYCLE_GUARD_SOURCE_INODE}" &&
      "${guardian_sha}" == "${_QCSD_LIFECYCLE_GUARD_SOURCE_SHA256}" &&
      "${qcsd_dev}" == "${_QCSD_LIFECYCLE_QCSD_SOURCE_DEVICE}" &&
      "${qcsd_ino}" == "${_QCSD_LIFECYCLE_QCSD_SOURCE_INODE}" &&
      "${qcsd_sha}" == "${_QCSD_LIFECYCLE_QCSD_SOURCE_SHA256}" &&
      "${helper_dev}" == "${_QCSD_LIFECYCLE_HELPER_SOURCE_DEVICE}" &&
      "${helper_ino}" == "${_QCSD_LIFECYCLE_HELPER_SOURCE_INODE}" &&
      "${helper_sha}" == "${_QCSD_LIFECYCLE_HELPER_SHA256}" &&
      "${native_dev}" == "${_QCSD_LIFECYCLE_NATIVE_SOURCE_DEVICE}" &&
      "${native_ino}" == "${_QCSD_LIFECYCLE_NATIVE_SOURCE_INODE}" &&
      "${native_sha}" == "${_QCSD_LIFECYCLE_NATIVE_SHA256}" ]] || return 1
  if [[ "${allow_staged}" == 0 ]]; then
    for entry in "${root}"/*.next; do
      [[ ! -e "${entry}" && ! -L "${entry}" ]] || return 1
    done
  fi
  {
    _qcsd_lifecycle_validate_root "${root}" "${kind}" || return 1
    if [[ "${reason}" == unpublished ]]; then
      (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED != 0 )) || return 1
    else
      (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED == 0 )) || return 1
      record_name="${_QCSD_LIFECYCLE_SELECTED_RECORD##*/}"
      record_hash="$(sha256sum -- "${_QCSD_LIFECYCLE_SELECTED_RECORD}" | awk '{print $1}')" || return 1
      record_state="${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}"
      [[ "${reason}" != handoff-retired || "${record_state}" == handed-off ]] || return 1
      supervisor_label="${_QCSD_LIFECYCLE_SELECTED_VALUES[supervisor_label]:-unavailable}"
      scope_unit="${_QCSD_LIFECYCLE_SELECTED_VALUES[scope_unit]:-unavailable}"
      registration_name="${_QCSD_LIFECYCLE_SELECTED_VALUES[registration_name]:-unavailable}"
      # The new authority belongs to this boot. Never rebind a historical
      # launcher tuple to it: PID/start ticks are meaningful only within one
      # boot. The original record and its hash retain the historical tuple.
      if [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[host_boot_id]}" == \
            "${_QCSD_DOCKER_PINNED_BOOT_ID}" ]]; then
        launcher_pid="${_QCSD_LIFECYCLE_SELECTED_VALUES[scope_launcher_pid]:-unavailable}"
        launcher_start="${_QCSD_LIFECYCLE_SELECTED_VALUES[scope_launcher_start_time]:-unavailable}"
        launcher_session="${_QCSD_LIFECYCLE_SELECTED_VALUES[scope_launcher_session]:-unavailable}"
        launcher_group="${_QCSD_LIFECYCLE_SELECTED_VALUES[scope_launcher_process_group]:-unavailable}"
      fi
      if [[ "${kind}" == run ]]; then
        object_id="${_QCSD_LIFECYCLE_SELECTED_VALUES[container_id]}"
      elif [[ "${kind}" == network ]]; then
        object_id="${_QCSD_LIFECYCLE_SELECTED_VALUES[network_id]}"
      elif [[ "${kind}" == transaction ]]; then
        transaction_receipt="${_QCSD_LIFECYCLE_SELECTED_VALUES[receipt_path]}"
        [[ "${transaction_receipt}" == /* && -f "${transaction_receipt}" &&
            ! -L "${transaction_receipt}" ]] || return 1
        IFS=: read -r transaction_receipt_dev transaction_receipt_ino <<<"$(
          stat -Lc '%d:%i' -- "${transaction_receipt}")" || return 1
        transaction_receipt_sha="$(sha256sum -- "${transaction_receipt}" | awk '{print $1}')" || return 1
      fi
    fi
  }
  root_meta="$(stat -Lc '%d:%i:%u:%a:%h:%F' -- "${root}")" || return 1
  root_manifest="$(_qcsd_lifecycle_root_manifest_sha256 "${root}")" || return 1
  {
    printf 'retirement_schema=1\nkind=%s\ntoken=%s\nactive_name=%s\nretired_name=.retired.%s.%s\n' \
      "${kind}" "${token}" "${root##*/}" "${kind}" "${token}"
    printf 'root_identity=%s\nroot_manifest_sha256=%s\nreason=%s\nallow_staged=%s\n' \
      "${root_meta}" "${root_manifest}" "${reason}" "${allow_staged}"
    printf 'base_identity=%s\n' "${base_identity}"
    printf 'record_name=%s\nrecord_sha256=%s\nrecord_state=%s\nobject_id=%s\n' \
      "${record_name}" "${record_hash}" "${record_state}" "${object_id}"
    printf 'supervisor_label=%s\nscope_unit=%s\ndocker_context=%s\ndocker_host=%s\ndocker_config_path=%s\ndocker_config_device=%s\ndocker_config_inode=%s\nbuildx_config_path=%s\nbuildx_config_device=%s\nbuildx_config_inode=%s\n' \
      "${supervisor_label}" "${scope_unit}" "${_QCSD_DOCKER_PINNED_CONTEXT:-unavailable}" \
      "${_QCSD_DOCKER_PINNED_HOST:-unavailable}" \
      current-guardian current-guardian current-guardian \
      current-guardian current-guardian current-guardian
    printf 'docker_server_id=%s\nhost_boot_id=%s\nhelper_source_sha256=%s\nlock_device=%s\nlock_inode=%s\nlock_path=%s\nlock_parent_identity=%s\n' \
      "${_QCSD_DOCKER_PINNED_SERVER_ID:-unavailable}" "${_QCSD_DOCKER_PINNED_BOOT_ID:-unavailable}" \
      "${_QCSD_EXECUTED_HELPER_SOURCE_SHA256:-unavailable}" \
      "${_QCSD_LIFECYCLE_LOCK_DEVICE:-unavailable}" "${_QCSD_LIFECYCLE_LOCK_INODE:-unavailable}" \
      "${lock_path}" "${lock_parent_identity}"
    printf 'registration_name=%s\n' "${registration_name}"
    printf 'transaction_receipt=%s\ntransaction_receipt_device=%s\ntransaction_receipt_inode=%s\ntransaction_receipt_sha256=%s\n' \
      "${transaction_receipt}" "${transaction_receipt_dev}" \
      "${transaction_receipt_ino}" "${transaction_receipt_sha}"
    printf 'guardian_source_path=%s\nguardian_source_identity=%s\nguardian_source_sha256=%s\n' \
      "${guardian_path}" "${guardian_meta}" "${guardian_sha}"
    printf 'qcsd_source_path=%s\nqcsd_source_identity=%s\nqcsd_source_sha256=%s\n' \
      "${qcsd_path}" "${qcsd_meta}" "${qcsd_sha}"
    printf 'helper_source_path=%s\nhelper_source_identity=%s\nhelper_source_sha256_full=%s\n' \
      "${helper_path}" "${helper_meta}" "${helper_sha}"
    printf 'native_source_path=%s\nnative_source_identity=%s\nnative_source_sha256=%s\n' \
      "${native_path}" "${native_meta}" "${native_sha}"
    printf 'launcher_pid=%s\nlauncher_start_time=%s\nlauncher_session=%s\nlauncher_process_group=%s\n' \
      "${launcher_pid}" "${launcher_start}" "${launcher_session}" "${launcher_group}"
    for entry in "${root}"/*; do
      [[ -e "${entry}" || -L "${entry}" ]] || continue
      name="${entry##*/}"
      [[ "${name}" != *$'\t'* && "${name}" != *$'\n'* ]] || return 1
      metadata="$(stat -Lc '%d:%i:%u:%a:%h:%s:%F' -- "${entry}")" || return 1
      if [[ -f "${entry}" && ! -L "${entry}" ]]; then
        digest="$(sha256sum -- "${entry}" | awk '{print $1}')" || return 1
      elif [[ -p "${entry}" && ! -L "${entry}" ]]; then
        digest=fifo
      else
        return 1
      fi
      printf 'child\t%s\t%s\t%s\n' "${name}" "${metadata}" "${digest}"
    done
  }
  local observed_root_metadata observed_root_manifest
  observed_root_metadata="$(stat -Lc '%d:%i:%u:%a:%h:%F' -- "${root}")" ||
    return 1
  observed_root_manifest="$(_qcsd_lifecycle_root_manifest_sha256 "${root}")" ||
    return 1
  [[ "${observed_root_metadata}" == "${root_meta}" &&
      "${observed_root_manifest}" == "${root_manifest}" ]]
}

_qcsd_retirement_parse_authority() {
  local authority="$1" line key value child_count=0 scalar_index
  local source_name source_path_key source_identity_key source_hash_key
  local -a lines=()
  local -a scalar_keys=(kind token active_name retired_name root_identity
    root_manifest_sha256 reason allow_staged base_identity record_name record_sha256 record_state
    object_id supervisor_label scope_unit docker_context docker_host docker_config_path
    docker_config_device docker_config_inode buildx_config_path buildx_config_device
    buildx_config_inode docker_server_id
    host_boot_id helper_source_sha256 lock_device lock_inode lock_path
    lock_parent_identity registration_name
    transaction_receipt transaction_receipt_device transaction_receipt_inode
    transaction_receipt_sha256 guardian_source_path guardian_source_identity
    guardian_source_sha256 qcsd_source_path qcsd_source_identity qcsd_source_sha256
    helper_source_path helper_source_identity helper_source_sha256_full
    native_source_path native_source_identity native_source_sha256 launcher_pid
    launcher_start_time launcher_session launcher_process_group)
  local -A seen_children=()
  _qcsd_retirement_authority_binding "${authority}" || return 1
  mapfile -t lines <"${authority}" || return 1
  (( ${#lines[@]} >= 9 )) || return 1
  [[ "${lines[0]}" == retirement_schema=1 ]] || return 1
  (( ${#lines[@]} >= 1 + ${#scalar_keys[@]} )) || return 1
  for (( scalar_index = 0; scalar_index < ${#scalar_keys[@]}; scalar_index++ )); do
    [[ "${lines[scalar_index + 1]%%=*}" == "${scalar_keys[scalar_index]}" ]] || return 1
  done
  for (( scalar_index = 1 + ${#scalar_keys[@]}; scalar_index < ${#lines[@]}; scalar_index++ )); do
    [[ "${lines[scalar_index]}" == child$'\t'* ]] || return 1
  done
  declare -gA _QCSD_RETIRE_VALUES=()
  declare -ga _QCSD_RETIRE_CHILDREN=()
  for line in "${lines[@]:1}"; do
    if [[ "${line}" == child$'\t'* ]]; then
      IFS=$'\t' read -r _ child_name child_metadata child_digest child_extra <<<"${line}"
      [[ -z "${child_extra}" && "${child_name}" =~ ^[A-Za-z0-9_.-]+$ &&
          "${child_name}" != . && "${child_name}" != .. &&
          "${child_metadata}" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}:[1-9][0-9]*:[0-9]+:(regular\ file|regular\ empty\ file|fifo)$ &&
          ( "${child_digest}" == fifo || "${child_digest}" =~ ^[0-9a-f]{64}$ ) &&
          -z "${seen_children[${child_name}]+x}" ]] || return 1
      [[ ( "${child_metadata}" == *":fifo" && "${child_digest}" == fifo ) ||
          ( ( "${child_metadata}" == *":regular file" ||
              "${child_metadata}" == *":regular empty file" ) &&
            "${child_digest}" != fifo ) ]] || return 1
      seen_children["${child_name}"]=1
      _QCSD_RETIRE_CHILDREN+=("${line}"); child_count=$((child_count + 1)); continue
    fi
    [[ "${line}" == *=* ]] || return 1
    key="${line%%=*}"; value="${line#*=}"
    [[ -z "${_QCSD_RETIRE_VALUES[${key}]+x}" ]] || return 1
    _QCSD_RETIRE_VALUES["${key}"]="${value}"
  done
  (( ${#_QCSD_RETIRE_VALUES[@]} == 51 )) || return 1
  [[ "${_QCSD_RETIRE_VALUES[kind]:-}" =~ ^(run|network|build|transaction)$ &&
      "${_QCSD_RETIRE_VALUES[token]:-}" =~ ^[0-9a-f]{32}$ &&
      "${_QCSD_RETIRE_VALUES[active_name]:-}" == "${_QCSD_RETIRE_VALUES[kind]}.${_QCSD_RETIRE_VALUES[token]}" &&
      "${_QCSD_RETIRE_VALUES[retired_name]:-}" == ".retired.${_QCSD_RETIRE_VALUES[kind]}.${_QCSD_RETIRE_VALUES[token]}" &&
      "${_QCSD_RETIRE_VALUES[root_identity]:-}" =~ ^[0-9]+:[0-9]+:[0-9]+:700:(2|[3-9]|[1-9][0-9]+):directory$ &&
      "${_QCSD_RETIRE_VALUES[root_manifest_sha256]:-}" =~ ^[0-9a-f]{64}$ &&
      "${_QCSD_RETIRE_VALUES[base_identity]:-}" =~ ^[0-9]+:[0-9]+:[0-9]+:700:directory$ &&
      "${_QCSD_RETIRE_VALUES[reason]:-}" =~ ^(recovered-stale|handoff-retired|transaction-committed|unpublished)$ &&
      "${_QCSD_RETIRE_VALUES[allow_staged]:-}" =~ ^[01]$ &&
      "${_QCSD_RETIRE_VALUES[record_name]:-}" =~ ^(unavailable|SUPERVISION|RECOVERY|HANDOFF)$ &&
      "${_QCSD_RETIRE_VALUES[record_sha256]:-}" =~ ^(unavailable|[0-9a-f]{64})$ &&
      "${_QCSD_RETIRE_VALUES[record_state]:-}" =~ ^(unavailable|declared|request-authorised|bound|handed-off|unresolved)$ &&
      "${_QCSD_RETIRE_VALUES[object_id]:-}" =~ ^(unavailable|[0-9a-f]{64})$ &&
      "${_QCSD_RETIRE_VALUES[supervisor_label]:-}" =~ ^(unavailable|org[.]qcsd[.]supervisor[.]instance=[0-9a-f]{32})$ &&
      "${_QCSD_RETIRE_VALUES[scope_unit]:-}" =~ ^(unavailable|qcsd-docker-(run|build)-[0-9a-f]{32}[.]scope)$ &&
      "${_QCSD_RETIRE_VALUES[docker_context]:-}" =~ ^[A-Za-z0-9_.-]+$ &&
      "${_QCSD_RETIRE_VALUES[docker_context]}" != unavailable &&
      "${_QCSD_RETIRE_VALUES[docker_host]:-}" =~ ^(unix:///var/run/docker[.]sock|npipe:////[.]/pipe/dockerDesktopLinuxEngine)$ &&
      "${_QCSD_RETIRE_VALUES[docker_config_path]:-}" == current-guardian &&
      "${_QCSD_RETIRE_VALUES[docker_config_device]:-}" == current-guardian &&
      "${_QCSD_RETIRE_VALUES[docker_config_inode]:-}" == current-guardian &&
      "${_QCSD_RETIRE_VALUES[buildx_config_path]:-}" == current-guardian &&
      "${_QCSD_RETIRE_VALUES[buildx_config_device]:-}" == current-guardian &&
      "${_QCSD_RETIRE_VALUES[buildx_config_inode]:-}" == current-guardian &&
      "${_QCSD_RETIRE_VALUES[docker_server_id]:-}" =~ ^[A-Za-z0-9_.:-]+$ &&
      "${_QCSD_RETIRE_VALUES[docker_server_id]}" != unavailable &&
      "${_QCSD_RETIRE_VALUES[host_boot_id]:-}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ &&
      "${_QCSD_RETIRE_VALUES[helper_source_sha256]:-}" =~ ^[0-9a-f]{64}$ &&
      "${_QCSD_RETIRE_VALUES[lock_device]:-}" =~ ^[0-9]+$ &&
      "${_QCSD_RETIRE_VALUES[lock_inode]:-}" =~ ^[0-9]+$ &&
      "${_QCSD_RETIRE_VALUES[lock_path]:-}" == /* &&
      "${_QCSD_RETIRE_VALUES[lock_parent_identity]:-}" =~ ^[0-9]+:[0-9]+$ &&
      "${_QCSD_RETIRE_VALUES[registration_name]:-}" =~ ^(unavailable|QCSD_DOCKER_IDS_[A-Z0-9_]+)$ &&
      "${_QCSD_RETIRE_VALUES[transaction_receipt_device]:-}" =~ ^(unavailable|[0-9]+)$ &&
      "${_QCSD_RETIRE_VALUES[transaction_receipt_inode]:-}" =~ ^(unavailable|[0-9]+)$ &&
      "${_QCSD_RETIRE_VALUES[transaction_receipt_sha256]:-}" =~ ^(unavailable|[0-9a-f]{64})$ &&
      "${_QCSD_RETIRE_VALUES[guardian_source_sha256]:-}" =~ ^(unavailable|[0-9a-f]{64})$ &&
      "${_QCSD_RETIRE_VALUES[qcsd_source_sha256]:-}" =~ ^(unavailable|[0-9a-f]{64})$ &&
      "${_QCSD_RETIRE_VALUES[helper_source_sha256_full]:-}" =~ ^(unavailable|[0-9a-f]{64})$ &&
      "${_QCSD_RETIRE_VALUES[native_source_sha256]:-}" =~ ^(unavailable|[0-9a-f]{64})$ &&
      "${_QCSD_RETIRE_VALUES[launcher_pid]:-}" =~ ^(unavailable|[1-9][0-9]*)$ &&
      "${_QCSD_RETIRE_VALUES[launcher_start_time]:-}" =~ ^(unavailable|[1-9][0-9]*)$ &&
      "${_QCSD_RETIRE_VALUES[launcher_session]:-}" =~ ^(unavailable|[1-9][0-9]*)$ &&
      "${_QCSD_RETIRE_VALUES[launcher_process_group]:-}" =~ ^(unavailable|[1-9][0-9]*)$ ]] || return 1
  if [[ "${_QCSD_RETIRE_VALUES[launcher_pid]}" == unavailable ]]; then
    [[ "${_QCSD_RETIRE_VALUES[launcher_start_time]}" == unavailable &&
        "${_QCSD_RETIRE_VALUES[launcher_session]}" == unavailable &&
        "${_QCSD_RETIRE_VALUES[launcher_process_group]}" == unavailable ]] || return 1
  else
    [[ "${_QCSD_RETIRE_VALUES[launcher_session]}" == "${_QCSD_RETIRE_VALUES[launcher_pid]}" &&
        "${_QCSD_RETIRE_VALUES[launcher_process_group]}" == "${_QCSD_RETIRE_VALUES[launcher_pid]}" ]] || return 1
  fi
  for source_name in guardian qcsd helper native; do
    source_path_key="${source_name}_source_path"
    source_identity_key="${source_name}_source_identity"
    [[ "${source_name}" != helper ]] || source_hash_key=helper_source_sha256_full
    [[ "${source_name}" == helper ]] || source_hash_key="${source_name}_source_sha256"
    [[ "${_QCSD_RETIRE_VALUES[${source_path_key}]}" == /* &&
        "${_QCSD_RETIRE_VALUES[${source_identity_key}]}" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}:1:[0-9]+:(regular\ file|regular\ empty\ file)$ &&
        "${_QCSD_RETIRE_VALUES[${source_hash_key}]}" =~ ^[0-9a-f]{64}$ ]] || return 1
  done
  case "${_QCSD_RETIRE_VALUES[reason]}" in
    unpublished)
      [[ "${_QCSD_RETIRE_VALUES[record_name]}" == unavailable &&
          "${_QCSD_RETIRE_VALUES[record_sha256]}" == unavailable &&
          "${_QCSD_RETIRE_VALUES[record_state]}" == unavailable &&
          "${_QCSD_RETIRE_VALUES[allow_staged]}" == 1 ]] || return 1
      ;;
    handoff-retired)
      [[ "${_QCSD_RETIRE_VALUES[kind]}" =~ ^(run|network)$ &&
          "${_QCSD_RETIRE_VALUES[record_name]}" == HANDOFF &&
          "${_QCSD_RETIRE_VALUES[record_state]}" == handed-off &&
          "${_QCSD_RETIRE_VALUES[record_sha256]}" != unavailable &&
          "${_QCSD_RETIRE_VALUES[object_id]}" != unavailable &&
          "${_QCSD_RETIRE_VALUES[registration_name]}" != unavailable &&
          "${_QCSD_RETIRE_VALUES[allow_staged]}" == 0 ]] || return 1
      ;;
    recovered-stale)
      [[ "${_QCSD_RETIRE_VALUES[record_name]}" =~ ^(SUPERVISION|RECOVERY)$ &&
          "${_QCSD_RETIRE_VALUES[record_sha256]}" != unavailable &&
          "${_QCSD_RETIRE_VALUES[record_state]}" != unavailable &&
          "${_QCSD_RETIRE_VALUES[allow_staged]}" == 0 ]] || return 1
      ;;
    transaction-committed)
      [[ "${_QCSD_RETIRE_VALUES[kind]}" == transaction &&
          "${_QCSD_RETIRE_VALUES[record_name]}" == SUPERVISION &&
          "${_QCSD_RETIRE_VALUES[record_state]}" == request-authorised &&
          "${_QCSD_RETIRE_VALUES[transaction_receipt]}" == /* &&
          "${_QCSD_RETIRE_VALUES[transaction_receipt_sha256]}" != unavailable ]] || return 1
      ;;
  esac
  [[ "${authority##*/}" == "retirement.${_QCSD_RETIRE_VALUES[kind]}.${_QCSD_RETIRE_VALUES[token]}" ||
      "${authority##*/}" == "retirement.${_QCSD_RETIRE_VALUES[kind]}.${_QCSD_RETIRE_VALUES[token]}.next" ]]
}

_qcsd_validate_retirement_phase() {
  local authority="$1" active retired root_identity root_dev root_ino line
  local child name metadata digest child_dev child_ino child_uid child_mode
  local child_links child_size child_type found
  local -A expected=()
  local -a retired_children=()
  local nullglob_was_set=0 dotglob_was_set=0
  local survivor_started=0
  _qcsd_retirement_parse_authority "${authority}" || return 1
  active="${authority%/*}/${_QCSD_RETIRE_VALUES[active_name]}"
  retired="${authority%/*}/${_QCSD_RETIRE_VALUES[retired_name]}"
  [[ ! -e "${authority}.next" && ! -L "${authority}.next" ]] || return 1
  [[ ! ( -e "${active}" && -e "${retired}" ) ]] || return 1
  root_identity="${_QCSD_RETIRE_VALUES[root_identity]}"
  root_dev="${root_identity%%:*}"; root_identity="${root_identity#*:}"
  root_ino="${root_identity%%:*}"
  if [[ -e "${active}" || -L "${active}" ]]; then
    [[ -d "${active}" && ! -L "${active}" &&
        "$(_qcsd_lifecycle_root_manifest_sha256 "${active}")" == \
          "${_QCSD_RETIRE_VALUES[root_manifest_sha256]}" ]] || return 1
  fi
  for line in "${_QCSD_RETIRE_CHILDREN[@]}"; do
    IFS=$'\t' read -r _ name metadata digest <<<"${line}"
    expected["${name}"]="${metadata}"$'\t'"${digest}"
  done
  if [[ -e "${retired}" || -L "${retired}" ]]; then
    [[ -d "${retired}" && ! -L "${retired}" ]] || return 1
    [[ "$(stat -Lc '%d:%i:%u:%a:%h:%F' -- "${retired}")" == \
        "${_QCSD_RETIRE_VALUES[root_identity]}" ]] || return 1
    shopt -q nullglob && nullglob_was_set=1
    shopt -q dotglob && dotglob_was_set=1
    shopt -s nullglob dotglob
    retired_children=("${retired}"/*)
    (( nullglob_was_set != 0 )) || shopt -u nullglob
    (( dotglob_was_set != 0 )) || shopt -u dotglob
    for child in "${retired_children[@]}"; do
      [[ -e "${child}" || -L "${child}" ]] || continue
      name="${child##*/}"; [[ -n "${expected[${name}]+x}" ]] || return 1
      IFS=$'\t' read -r metadata digest <<<"${expected[${name}]}"
      [[ "$(stat -Lc '%d:%i:%u:%a:%h:%s:%F' -- "${child}")" == "${metadata}" ]] || return 1
      if [[ "${digest}" == fifo ]]; then
        [[ -p "${child}" && ! -L "${child}" ]] || return 1
      else
        [[ -f "${child}" && ! -L "${child}" &&
            "$(sha256sum -- "${child}" | awk '{print $1}')" == "${digest}" ]] || return 1
      fi
    done
    # Deletion is canonical authority order.  A restart may observe only an
    # exact suffix; an arbitrary hole is not evidence of our prior progress.
    for line in "${_QCSD_RETIRE_CHILDREN[@]}"; do
      IFS=$'\t' read -r _ name metadata digest <<<"${line}"
      if [[ -e "${retired}/${name}" || -L "${retired}/${name}" ]]; then
        survivor_started=1
      elif (( survivor_started != 0 )); then
        return 1
      fi
    done
  fi
}

_qcsd_retirement_terminal_reproof() {
  local values_name="$1" presence receipt_meta source_name path_key identity_key hash_key
  local identity_purpose=ordinary
  local lifecycle_base_metadata lock_metadata lock_parent_metadata
  local docker_config_metadata docker_config_first_entry
  local buildx_config_metadata buildx_config_links source_metadata source_digest
  local -n values_ref="${values_name}"
  lifecycle_base_metadata="$(stat -Lc '%d:%i:%u:%a:%F' -- \
    "${_qcsd_lifecycle_base}")" || return 1
  [[ "${lifecycle_base_metadata}" == \
      "${values_ref[base_identity]}" ]] || return 1
  [[ -f "${values_ref[lock_path]}" && ! -L "${values_ref[lock_path]}" ]] ||
    return 1
  lock_metadata="$(stat -Lc '%d:%i' -- "${values_ref[lock_path]}")" || return 1
  lock_parent_metadata="$(stat -Lc '%d:%i' -- \
    "${values_ref[lock_path]%/*}")" || return 1
  [[ "${lock_metadata}" == \
        "${values_ref[lock_device]}:${values_ref[lock_inode]}" &&
      "${lock_parent_metadata}" == \
        "${values_ref[lock_parent_identity]}" &&
      "${values_ref[lock_path]}" == "${_QCSD_LIFECYCLE_LOCK_PATH:-}" &&
      "${values_ref[lock_parent_identity]}" == \
        "${_QCSD_LIFECYCLE_LOCK_PARENT_DEVICE:-}:${_QCSD_LIFECYCLE_LOCK_PARENT_INODE:-}" &&
      "${values_ref[lock_device]}:${values_ref[lock_inode]}" == \
        "${_QCSD_LIFECYCLE_LOCK_DEVICE:-}:${_QCSD_LIFECYCLE_LOCK_INODE:-}" ]] || return 1
  [[ "${values_ref[docker_config_path]}:${values_ref[docker_config_device]}:${values_ref[docker_config_inode]}" == \
      current-guardian:current-guardian:current-guardian &&
      -d "${_QCSD_LIFECYCLE_DOCKER_CONFIG_PATH:-}" &&
      ! -L "${_QCSD_LIFECYCLE_DOCKER_CONFIG_PATH:-}" ]] || return 1
  docker_config_metadata="$(stat -Lc '%d:%i:%u:%a:%h:%F' -- \
    "${_QCSD_LIFECYCLE_DOCKER_CONFIG_PATH}")" || return 1
  docker_config_first_entry="$(find -H \
    "${_QCSD_LIFECYCLE_DOCKER_CONFIG_PATH}" \
    -mindepth 1 -maxdepth 1 -print -quit)" || true
  [[ "${docker_config_metadata}" == \
        "${_QCSD_LIFECYCLE_DOCKER_CONFIG_DEVICE}:${_QCSD_LIFECYCLE_DOCKER_CONFIG_INODE}:${EUID}:500:2:directory" &&
      -z "${docker_config_first_entry}" ]] || return 1
  [[ "${values_ref[buildx_config_path]}:${values_ref[buildx_config_device]}:${values_ref[buildx_config_inode]}" == \
      current-guardian:current-guardian:current-guardian &&
      -d "${_QCSD_LIFECYCLE_BUILDX_CONFIG_PATH:-}" &&
      ! -L "${_QCSD_LIFECYCLE_BUILDX_CONFIG_PATH}" ]] || return 1
  buildx_config_metadata="$(stat -Lc '%d:%i:%u:%a:%h:%F' -- \
    "${_QCSD_LIFECYCLE_BUILDX_CONFIG_PATH}")" || return 1
  buildx_config_links="$(stat -Lc %h -- \
    "${_QCSD_LIFECYCLE_BUILDX_CONFIG_PATH}")" || return 1
  [[ "${buildx_config_metadata}" == \
        "${_QCSD_LIFECYCLE_BUILDX_CONFIG_DEVICE}:${_QCSD_LIFECYCLE_BUILDX_CONFIG_INODE}:${EUID}:700:"*":directory" &&
      "${buildx_config_links}" =~ ^([2-9]|[1-9][0-9]+)$ ]] || return 1
  for source_name in guardian qcsd helper native; do
    path_key="${source_name}_source_path"
    identity_key="${source_name}_source_identity"
    [[ "${source_name}" != helper ]] || hash_key=helper_source_sha256_full
    [[ "${source_name}" == helper ]] || hash_key="${source_name}_source_sha256"
    [[ "${values_ref[${path_key}]}" == unavailable ]] && continue
    [[ -f "${values_ref[${path_key}]}" &&
        ! -L "${values_ref[${path_key}]}" ]] || return 1
    source_metadata="$(stat -Lc '%d:%i:%u:%a:%h:%s:%F' -- \
      "${values_ref[${path_key}]}")" || return 1
    source_digest="$(sha256sum -- "${values_ref[${path_key}]}" | \
      awk '{print $1}')" || return 1
    [[ "${source_metadata}" == \
          "${values_ref[${identity_key}]}" &&
        "${source_digest}" == \
          "${values_ref[${hash_key}]}" ]] || return 1
  done
  if [[ "${values_ref[helper_source_sha256]}" != unavailable ]]; then
    _qcsd_revalidate_helper_source_identity || return 1
    [[ "${_QCSD_EXECUTED_HELPER_SOURCE_SHA256}" == \
        "${values_ref[helper_source_sha256]}" ]] || return 1
  fi
  if [[ "${values_ref[host_boot_id]}" != unavailable ]]; then
    _qcsd_verify_pinned_host_boot || return 1
    if [[ "${values_ref[kind]}" == build ]]; then
      identity_purpose=build-retirement
    fi
    if ! _qcsd_verify_pinned_docker_daemon "${identity_purpose}"; then
      echo "Docker lifecycle retirement refused because daemon identity could not be verified" >&2
      return 1
    fi
    # A durable authority may outlive its host boot. Current boot stability,
    # source/lock bindings and the same daemon remain mandatory; the old boot
    # only determines whether its launcher tuple can still name a process.
    [[ "${values_ref[docker_context]}" == "${_QCSD_DOCKER_PINNED_CONTEXT}" &&
        "${values_ref[docker_host]}" == "${_QCSD_DOCKER_PINNED_HOST}" &&
        "${values_ref[docker_server_id]}" == "${_QCSD_DOCKER_PINNED_SERVER_ID}" ]] || return 1
  fi
  if [[ "${values_ref[kind]}" == run ]]; then
    if [[ "${values_ref[object_id]}" != unavailable ]]; then
      presence="$(_qcsd_docker_exact_id_presence "${values_ref[object_id]}")"
      [[ "${presence}" == absent ]] || return 1
    fi
    _qcsd_resolve_docker_target "" "${values_ref[token]}"
    [[ "${_qcsd_resolved_state}" == absent ]] || return 1
  elif [[ "${values_ref[kind]}" == network ]]; then
    if [[ "${values_ref[object_id]}" != unavailable ]]; then
      presence="$(_qcsd_docker_exact_network_presence "${values_ref[object_id]}")"
      [[ "${presence}" == absent ]] || return 1
    fi
    _qcsd_resolve_docker_network "${values_ref[token]}" ""
    [[ "${_qcsd_resolved_network_state}" == absent ]] || return 1
  fi
  if [[ "${values_ref[scope_unit]}" != unavailable ]]; then
    _qcsd_query_user_scope "${values_ref[scope_unit]}" || return 1
    [[ "${_qcsd_scope_state}" == absent ]] || return 1
  fi
  if [[ "${values_ref[launcher_pid]}" != unavailable &&
        "${values_ref[host_boot_id]}" == "${_QCSD_DOCKER_PINNED_BOOT_ID}" ]]; then
    _qcsd_bound_process_is_gone "${values_ref[launcher_pid]}" \
      "${values_ref[launcher_start_time]}" "${values_ref[launcher_session]}" \
      "${values_ref[launcher_process_group]}" || return 1
  fi
  if [[ "${values_ref[kind]}" == transaction ]]; then
    [[ "${values_ref[reason]}" == unpublished ]] && return 0
    [[ "${values_ref[reason]}" == transaction-committed &&
        -f "${values_ref[transaction_receipt]}" &&
        ! -L "${values_ref[transaction_receipt]}" ]] || return 1
    receipt_meta="$(stat -Lc '%d:%i' -- "${values_ref[transaction_receipt]}")" || return 1
    [[ "${receipt_meta}" == "${values_ref[transaction_receipt_device]}:${values_ref[transaction_receipt_inode]}" &&
        "$(sha256sum -- "${values_ref[transaction_receipt]}" | awk '{print $1}')" == \
          "${values_ref[transaction_receipt_sha256]}" ]] || return 1
  fi
}

_qcsd_resume_retirement() {
  local authority="$1" active retired root_dev root_ino root_identity line
  local child name expected_name metadata digest current count=0 found
  local authority_parent_metadata
  local -a retired_children=()
  local nullglob_was_set=0 dotglob_was_set=0
  _qcsd_validate_retirement_phase "${authority}" || return 1
  active="${authority%/*}/${_QCSD_RETIRE_VALUES[active_name]}"
  retired="${authority%/*}/${_QCSD_RETIRE_VALUES[retired_name]}"
  root_identity="${_QCSD_RETIRE_VALUES[root_identity]}"
  root_dev="${root_identity%%:*}"; current="${root_identity#*:}"; root_ino="${current%%:*}"
  [[ ! -e "${authority}.next" && ! -L "${authority}.next" ]] || return 1
  [[ ! ( -e "${active}" && -e "${retired}" ) ]] || return 1
  _qcsd_retirement_boundary_hook H4 "${authority}"
  if [[ -d "${active}" && ! -L "${active}" ]]; then
    [[ "$(_qcsd_lifecycle_root_manifest_sha256 "${active}")" == \
        "${_QCSD_RETIRE_VALUES[root_manifest_sha256]}" ]] || return 1
    _qcsd_retirement_terminal_reproof _QCSD_RETIRE_VALUES || return 1
    _qcsd_retirement_boundary_hook H5 "${authority}"
    _qcsd_retirement_native_authenticated rename-root "${authority}" \
      "${active##*/}" "${retired##*/}" "${root_dev}" "${root_ino}" || return 1
    _qcsd_retirement_boundary_hook H6 "${authority}"
  elif [[ -e "${active}" || -L "${active}" ]]; then
    return 1
  fi
  _qcsd_retirement_boundary_hook H7 "${authority}"
  _qcsd_retirement_terminal_reproof _QCSD_RETIRE_VALUES || return 1
  if [[ -d "${retired}" && ! -L "${retired}" ]]; then
    shopt -q nullglob && nullglob_was_set=1
    shopt -q dotglob && dotglob_was_set=1
    shopt -s nullglob dotglob
    retired_children=("${retired}"/*)
    (( nullglob_was_set != 0 )) || shopt -u nullglob
    (( dotglob_was_set != 0 )) || shopt -u dotglob
    # Revalidate the entire survivor set, including hidden entries, before the
    # first unlink.  This second pass closes the hook/TOCTOU boundary after H7.
    for child in "${retired_children[@]}"; do
      name="${child##*/}"
      found=0
      for line in "${_QCSD_RETIRE_CHILDREN[@]}"; do
        IFS=$'\t' read -r _ expected_name metadata digest <<<"${line}"
        [[ "${expected_name}" != "${name}" ]] || { found=1; break; }
      done
      (( found != 0 )) || return 1
      [[ "$(stat -Lc '%d:%i:%u:%a:%h:%s:%F' -- "${child}")" == "${metadata}" ]] || return 1
      if [[ "${digest}" == fifo ]]; then
        [[ -p "${child}" && ! -L "${child}" ]] || return 1
      else
        [[ -f "${child}" && ! -L "${child}" &&
            "$(sha256sum -- "${child}" | awk '{print $1}')" == "${digest}" ]] || return 1
      fi
    done
    # The complete survivor subset was authenticated above before any unlink.
    for line in "${_QCSD_RETIRE_CHILDREN[@]}"; do
      IFS=$'\t' read -r _ name metadata digest <<<"${line}"
      child="${retired}/${name}"
      [[ -e "${child}" || -L "${child}" ]] || continue
      IFS=: read -r child_dev child_ino child_uid child_mode child_links child_size child_type <<<"${metadata}"
      [[ "${child_uid}" == "${EUID}" &&
          "${child_type}" =~ ^(regular\ file|regular\ empty\ file|fifo)$ ]] || return 1
      _qcsd_retirement_boundary_hook H8 "${authority}" "${name}" "${count}"
      _qcsd_retirement_native_authenticated unlink "${authority}" \
        "${retired##*/}" "${name}" "${root_dev}" "${root_ino}" \
        "${child_dev}" "${child_ino}" "${child_mode}" "${child_links}" \
        "${child_size}" "${digest}" || return 1
      _qcsd_retirement_boundary_hook H9 "${authority}" "${name}" "${count}"
      count=$((count + 1))
    done
    # No authority-unknown survivor may be removed.
    shopt -q nullglob && nullglob_was_set=1
    shopt -q dotglob && dotglob_was_set=1
    shopt -s nullglob dotglob
    retired_children=("${retired}"/*)
    (( nullglob_was_set != 0 )) || shopt -u nullglob
    (( dotglob_was_set != 0 )) || shopt -u dotglob
    for child in "${retired_children[@]}"; do
      [[ ! -e "${child}" && ! -L "${child}" ]] || return 1
    done
    _qcsd_retirement_boundary_hook H10 "${authority}"
    _qcsd_retirement_native_authenticated rmdir "${authority}" \
      "${retired##*/}" "${root_dev}" "${root_ino}" || return 1
    _qcsd_retirement_boundary_hook H11 "${authority}"
  elif [[ -e "${retired}" || -L "${retired}" ]]; then
    return 1
  fi
  # Neither directory is a legitimate post-rmdir restart phase.
  _qcsd_retirement_terminal_reproof _QCSD_RETIRE_VALUES || return 1
  _qcsd_retirement_authority_binding "${authority}" || return 1
  _qcsd_retirement_boundary_hook H12 "${authority}"
  authority_parent_metadata="$(stat -Lc '%d:%i' -- "${authority%/*}")" ||
    return 1
  _qcsd_retirement_native_op unlink-authority "${authority%/*}" "${EUID}" \
    "${authority_parent_metadata%%:*}" "${authority_parent_metadata##*:}" \
    "${authority##*/}" "${_QCSD_RETIRE_AUTH_DEV}" "${_QCSD_RETIRE_AUTH_INO}" \
    "${_QCSD_RETIRE_AUTH_SIZE}" "${_QCSD_RETIRE_AUTH_SHA}" || return 1
  _qcsd_retirement_boundary_hook H13 "${authority}"
}

_qcsd_lifecycle_remove_root() {
  local root="$1" allow_staged="${2:-0}" reason="${3:-}"
  [[ -n "${reason}" ]] || return 1
  local authority staged base_meta payload
  _qcsd_retirement_boundary_hook H0 "${root}"
  authority="$(_qcsd_retirement_authority_path "${root}")" || return 1
  staged="${authority}.next"
  [[ ! -e "${authority}" && ! -L "${authority}" &&
      ! -e "${staged}" && ! -L "${staged}" ]] || return 1
  payload="$(_qcsd_retirement_prepare_authority \
    "${root}" "${reason}" "${allow_staged}" "${authority}")" || return 1
  _qcsd_retirement_boundary_hook H1 "${root}" "${authority}"
  base_meta="$(stat -Lc '%d:%i' -- "${root%/*}")" || return 1
  _qcsd_retirement_boundary_hook H2 "${root}" "${authority}"
  _qcsd_retirement_native_op publish "${root%/*}" "${EUID}" \
    "${base_meta%%:*}" "${base_meta##*:}" "${staged##*/}" "${authority##*/}" \
    <<<"${payload}" || return 1
  _qcsd_retirement_boundary_hook H3 "${root}" "${authority}"
  _qcsd_resume_retirement "${authority}"
}

_qcsd_lifecycle_retire_completed_root() {
  local root="$1"
  if [[ -f "${root}/HANDOFF" && ! -L "${root}/HANDOFF" ]]; then
    _qcsd_lifecycle_remove_root "${root}" 0 handoff-retired
  elif { [[ -f "${root}/RECOVERY" && ! -L "${root}/RECOVERY" ]] ||
         [[ -f "${root}/SUPERVISION" && ! -L "${root}/SUPERVISION" ]]; }; then
    _qcsd_lifecycle_remove_root "${root}" 0 recovered-stale
  else
    _qcsd_lifecycle_remove_root "${root}" 1 unpublished
  fi
}

_qcsd_lifecycle_root_manifest_sha256() {
  local root="$1" entry name metadata digest root_metadata
  _qcsd_validate_lifecycle_root_contents "${root}" || return 1
  root_metadata="$(stat -Lc '%d:%i:%u:%a:%F' -- "${root}" 2>/dev/null)" || return 1
  {
    printf '.\t%s\tdirectory\n' "${root_metadata}"
    for entry in "${root}"/*; do
      [[ -e "${entry}" || -L "${entry}" ]] || continue
      name="${entry##*/}"
      metadata="$(stat -Lc '%d:%i:%u:%a:%h:%s:%F' -- "${entry}" 2>/dev/null)" ||
        return 1
      if [[ -f "${entry}" && ! -L "${entry}" ]]; then
        digest="$(sha256sum -- "${entry}" | awk '{print $1}')" || return 1
      else
        digest=non-regular
      fi
      printf '%s\t%s\t%s\n' "${name}" "${metadata}" "${digest}"
    done
  } | sha256sum | awk '{print $1}'
}

_qcsd_lifecycle_remove_unchanged_root() {
  local root="$1" root_kind="$2" expected_record="$3" expected_sha="$4"
  local expected_manifest="$5" observed_sha observed_manifest
  _qcsd_lifecycle_validate_root "${root}" "${root_kind}" || return 1
  if [[ -z "${expected_record}" ]]; then
    (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED != 0 )) || return 1
  else
    (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED == 0 )) || return 1
    [[ "${_QCSD_LIFECYCLE_SELECTED_RECORD}" == "${expected_record}" ]] || return 1
    observed_sha="$(sha256sum -- "${expected_record}" | awk '{print $1}')" || return 1
    [[ "${observed_sha}" == "${expected_sha}" ]] || return 1
  fi
  observed_manifest="$(_qcsd_lifecycle_root_manifest_sha256 "${root}")" || return 1
  [[ "${observed_manifest}" == "${expected_manifest}" ]] || return 1
  _qcsd_revalidate_helper_source_identity || return 1
  if [[ -z "${expected_record}" ]]; then
    _qcsd_lifecycle_remove_root "${root}" 1 unpublished
  elif [[ "${expected_record##*/}" == HANDOFF ]]; then
    _qcsd_lifecycle_remove_root "${root}" 0 handoff-retired
  else
    _qcsd_lifecycle_remove_root "${root}" 0 recovered-stale
  fi
}

_qcsd_lifecycle_revalidate_snapshot() {
  local root="$1" root_kind="$2" expected_record="$3" expected_sha="$4"
  local expected_manifest="$5" observed_sha observed_manifest
  _qcsd_lifecycle_validate_root "${root}" "${root_kind}" || return 1
  [[ "${_QCSD_LIFECYCLE_SELECTED_RECORD}" == "${expected_record}" ]] || return 1
  observed_sha="$(sha256sum -- "${expected_record}" | awk '{print $1}')" || return 1
  [[ "${observed_sha}" == "${expected_sha}" ]] || return 1
  observed_manifest="$(_qcsd_lifecycle_root_manifest_sha256 "${root}")" || return 1
  [[ "${observed_manifest}" == "${expected_manifest}" ]]
}

_qcsd_lifecycle_settle_recovery_batch() {
  case "${1:-}" in
    run) sleep "${_QCSD_DOCKER_STALE_RUN_SETTLE_SECONDS:-5}" ;;
    network) sleep "${_QCSD_DOCKER_STALE_NETWORK_SETTLE_SECONDS:-5}" ;;
    *) return 1 ;;
  esac
}

_qcsd_lifecycle_reprove_recovery_boundary() {
  local root_kind="$1" values_name="$2" current_boot="$3"
  local -n values_ref="${values_name}"
  local pid
  _qcsd_lifecycle_require_stale_supervisor "${values_name}" "${current_boot}" ||
    return 1
  case "${root_kind}" in
    run)
      pid="${values_ref[scope_launcher_pid]}"
      if [[ "${pid}" != unavailable &&
            "${values_ref[host_boot_id]}" == "${current_boot}" ]]; then
        _qcsd_bound_process_is_gone "${pid}" \
          "${values_ref[scope_launcher_start_time]}" \
          "${values_ref[scope_launcher_session]}" \
          "${values_ref[scope_launcher_process_group]}" || return 1
      fi
      _qcsd_wait_user_scope_inactive "${values_ref[scope_unit]}"
      ;;
    network) return 0 ;;
    *) return 1 ;;
  esac
}

_qcsd_lifecycle_recover_container() {
  local root="$1"
  local values_name="$2"
  local batch_settled="${3:-0}"
  local -n values_ref="${values_name}"
  local token="${values_ref[lifecycle_token]}" recorded_id="${values_ref[container_id]}"
  local cidfile_id="" resolved_id="" resolved_state presence snapshot
  local _qcsd_target_docker_context="${values_ref[docker_context]}"
  [[ "${batch_settled}" =~ ^[01]$ ]] || return 1
  if [[ "${batch_settled}" == 0 &&
        ( "${values_ref[lifecycle_state]}" == request-authorised ||
          "${values_ref[daemon_request_authorised]:-0}" == 1 ) ]]; then
    _qcsd_lifecycle_settle_recovery_batch run || return 1
  fi
  if [[ -e "${root}/container.cid" || -L "${root}/container.cid" ]]; then
    cidfile_id="$(_qcsd_private_cid "${root}/container.cid")" || return 1
    if [[ "${recorded_id}" == "unavailable" ]]; then
      recorded_id="${cidfile_id}"
    elif [[ "${recorded_id}" != "${cidfile_id}" ]]; then
      return 1
    fi
  fi
  _qcsd_resolve_docker_target "" "${token}"
  resolved_state="${_qcsd_resolved_state}"
  resolved_id="${_qcsd_resolved_cid}"
  [[ "${resolved_state}" != "unknown" ]] || return 1
  if [[ ( "${values_ref[lifecycle_state]}" == request-authorised ||
          "${values_ref[daemon_request_authorised]:-0}" == 1 ) &&
        "${recorded_id}" == unavailable && "${resolved_state}" == absent ]]; then
    return 1
  fi
  if [[ ( "${values_ref[lifecycle_state]}" == declared ||
          "${values_ref[daemon_request_authorised]:-1}" == 0 ) &&
        "${resolved_state}" != "absent" ]]; then
    return 1
  fi
  if [[ -n "${resolved_id}" ]]; then
    [[ "${recorded_id}" == "unavailable" ||
        "${recorded_id}" == "${resolved_id}" ]] || return 1
    recorded_id="${resolved_id}"
    _qcsd_target_docker_api rm --force "${resolved_id}" >/dev/null 2>&1 || true
  elif [[ "${recorded_id}" != "unavailable" ]]; then
    presence="$(_qcsd_docker_exact_id_presence "${recorded_id}")"
    [[ "${presence}" == "absent" ]] || return 1
  fi
  for snapshot in 1 2; do
    _qcsd_resolve_docker_target "" "${token}"
    [[ "${_qcsd_resolved_state}" == "absent" ]] || return 1
    if [[ "${recorded_id}" != "unavailable" ]]; then
      presence="$(_qcsd_docker_exact_id_presence "${recorded_id}")"
      [[ "${presence}" == "absent" ]] || return 1
    fi
    (( snapshot == 2 )) || sleep 0.1
  done
}

_qcsd_lifecycle_recover_network() {
  local values_name="$1"
  local batch_settled="${2:-0}"
  local -n values_ref="${values_name}"
  local token="${values_ref[lifecycle_token]}" recorded_id="${values_ref[network_id]}"
  local resolved_id resolved_state presence snapshot
  local _qcsd_target_docker_context="${values_ref[docker_context]}"
  [[ "${batch_settled}" =~ ^[01]$ ]] || return 1
  if [[ "${batch_settled}" == 0 &&
        ( "${values_ref[lifecycle_state]}" == request-authorised ||
          "${values_ref[daemon_request_authorised]:-0}" == 1 ) ]]; then
    _qcsd_lifecycle_settle_recovery_batch network || return 1
  fi
  _qcsd_resolve_docker_network "${token}" ""
  resolved_state="${_qcsd_resolved_network_state}"
  resolved_id="${_qcsd_resolved_network_id}"
  [[ "${resolved_state}" != "unknown" ]] || return 1
  if [[ ( "${values_ref[lifecycle_state]}" == request-authorised ||
          "${values_ref[daemon_request_authorised]:-0}" == 1 ) &&
        "${recorded_id}" == unavailable && "${resolved_state}" == absent ]]; then
    return 1
  fi
  if [[ ( "${values_ref[lifecycle_state]}" == declared ||
          "${values_ref[daemon_request_authorised]:-1}" == 0 ) &&
        "${resolved_state}" != "absent" ]]; then
    return 1
  fi
  if [[ -n "${resolved_id}" ]]; then
    [[ "${recorded_id}" == "unavailable" ||
        "${recorded_id}" == "${resolved_id}" ]] || return 1
    recorded_id="${resolved_id}"
    _qcsd_target_docker_api network rm "${resolved_id}" >/dev/null 2>&1 || true
  elif [[ "${recorded_id}" != "unavailable" ]]; then
    presence="$(_qcsd_docker_exact_network_presence "${recorded_id}")"
    [[ "${presence}" == "absent" ]] || return 1
  fi
  for snapshot in 1 2; do
    _qcsd_resolve_docker_network "${token}" ""
    [[ "${_qcsd_resolved_network_state}" == "absent" ]] || return 1
    if [[ "${recorded_id}" != "unavailable" ]]; then
      presence="$(_qcsd_docker_exact_network_presence "${recorded_id}")"
      [[ "${presence}" == "absent" ]] || return 1
    fi
    (( snapshot == 2 )) || sleep 0.1
  done
}

qcsd_reconcile_docker_lifecycle() {
  local requested_action="${1:-recover}"
  local current_boot root root_kind recovery_kind index blocked_root=""
  local selected_record_snapshot selected_sha_snapshot manifest_snapshot
  local preauth_stop=0 run_settle_required=0 network_settle_required=0
  local nullglob_was_set=0 dotglob_was_set=0
  local -a roots=() kinds=() authorities=() staged_authorities=()
  local -a active_candidates=() retired_candidates=()
  local -a recovery_record_snapshots=() recovery_sha_snapshots=()
  local -a recovery_manifest_snapshots=() run_contained=() network_preflighted=()
  local -A seen_tokens=() seen_labels=() seen_ids=() seen_scopes=() seen_launchers=()
  local -A retiring_active=() retiring_retired=()
  local launcher_key object_key
  [[ "${requested_action}" == "validate" ||
      "${requested_action}" == "recover" ]] || return 2
  _qcsd_verify_pinned_docker_daemon || return 1
  _qcsd_verify_pinned_host_boot || return 1
  _qcsd_secure_lifecycle_base || return 1
  IFS= read -r current_boot </proc/sys/kernel/random/boot_id || return 1
  [[ "${current_boot}" =~ \
    ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  shopt -q nullglob && nullglob_was_set=1
  shopt -q dotglob && dotglob_was_set=1
  shopt -s nullglob dotglob
  active_candidates=("${_qcsd_lifecycle_base}"/{run,network,build,transaction}.*)
  for root in "${_qcsd_lifecycle_base}"/retirement.{run,network,build,transaction}.*; do
    if [[ "${root}" == *.next ]]; then
      staged_authorities+=("${root}")
    else
      authorities+=("${root}")
    fi
  done
  retired_candidates=("${_qcsd_lifecycle_base}"/.retired.{run,network,build,transaction}.*)
  (( nullglob_was_set != 0 )) || shopt -u nullglob
  (( dotglob_was_set != 0 )) || shopt -u dotglob
  for root in "${_qcsd_lifecycle_base}"/* "${_qcsd_lifecycle_base}"/.*; do
    [[ -e "${root}" || -L "${root}" ]] || continue
    case "${root##*/}" in
      .|..) continue ;;
      run.*|network.*|build.*|transaction.*|retirement.run.*|retirement.network.*|retirement.build.*|retirement.transaction.*|.retired.run.*|.retired.network.*|.retired.build.*|.retired.transaction.*) ;;
      *) echo "Docker lifecycle admission found malformed state: ${root}" >&2; return 1 ;;
    esac
  done
  for root in "${staged_authorities[@]}"; do
    _qcsd_retirement_parse_authority "${root}" || return 1
    [[ ! -e "${root%.next}" && ! -L "${root%.next}" &&
        -d "${_qcsd_lifecycle_base}/${_QCSD_RETIRE_VALUES[active_name]}" &&
        "$(_qcsd_lifecycle_root_manifest_sha256 \
          "${_qcsd_lifecycle_base}/${_QCSD_RETIRE_VALUES[active_name]}")" == \
          "${_QCSD_RETIRE_VALUES[root_manifest_sha256]}" ]] || return 1
    _qcsd_retirement_terminal_reproof _QCSD_RETIRE_VALUES || return 1
    [[ -z "${retiring_active[${_QCSD_RETIRE_VALUES[active_name]}]+x}" ]] || return 1
    retiring_active["${_QCSD_RETIRE_VALUES[active_name]}"]="${root}"
    [[ -z "${seen_tokens[${_QCSD_RETIRE_VALUES[token]}]+x}" ]] || return 1
    seen_tokens["${_QCSD_RETIRE_VALUES[token]}"]="${root}"
    if [[ "${_QCSD_RETIRE_VALUES[supervisor_label]}" != unavailable ]]; then
      [[ -z "${seen_labels[${_QCSD_RETIRE_VALUES[supervisor_label]}]+x}" ]] || return 1
      seen_labels["${_QCSD_RETIRE_VALUES[supervisor_label]}"]="${root}"
    fi
    if [[ "${_QCSD_RETIRE_VALUES[scope_unit]}" != unavailable ]]; then
      [[ -z "${seen_scopes[${_QCSD_RETIRE_VALUES[scope_unit]}]+x}" ]] || return 1
      seen_scopes["${_QCSD_RETIRE_VALUES[scope_unit]}"]="${root}"
    fi
    if [[ "${_QCSD_RETIRE_VALUES[launcher_pid]}" != unavailable ]]; then
      launcher_key="${_QCSD_RETIRE_VALUES[host_boot_id]}:${_QCSD_RETIRE_VALUES[launcher_pid]}:${_QCSD_RETIRE_VALUES[launcher_start_time]}:${_QCSD_RETIRE_VALUES[launcher_session]}:${_QCSD_RETIRE_VALUES[launcher_process_group]}"
      [[ -z "${seen_launchers[${launcher_key}]+x}" ]] || return 1
      seen_launchers["${launcher_key}"]="${root}"
    fi
    if [[ "${_QCSD_RETIRE_VALUES[object_id]}" != unavailable ]]; then
      [[ "${_QCSD_RETIRE_VALUES[kind]}" == run ]] && object_key=container || object_key=network
      object_key="${object_key}:${_QCSD_RETIRE_VALUES[object_id]}"
      [[ -z "${seen_ids[${object_key}]+x}" ]] || return 1
      seen_ids["${object_key}"]="${root}"
    fi
  done
  for root in "${authorities[@]}"; do
    _qcsd_validate_retirement_phase "${root}" || {
      echo "Docker lifecycle admission found malformed retirement authority: ${root}" >&2
      return 1
    }
    _qcsd_retirement_terminal_reproof _QCSD_RETIRE_VALUES || return 1
    [[ -z "${seen_tokens[${_QCSD_RETIRE_VALUES[token]}]+x}" ]] || return 1
    seen_tokens["${_QCSD_RETIRE_VALUES[token]}"]="${root}"
    if [[ "${_QCSD_RETIRE_VALUES[supervisor_label]}" != unavailable ]]; then
      [[ -z "${seen_labels[${_QCSD_RETIRE_VALUES[supervisor_label]}]+x}" ]] || return 1
      seen_labels["${_QCSD_RETIRE_VALUES[supervisor_label]}"]="${root}"
    fi
    if [[ "${_QCSD_RETIRE_VALUES[scope_unit]}" != unavailable ]]; then
      [[ -z "${seen_scopes[${_QCSD_RETIRE_VALUES[scope_unit]}]+x}" ]] || return 1
      seen_scopes["${_QCSD_RETIRE_VALUES[scope_unit]}"]="${root}"
    fi
    if [[ "${_QCSD_RETIRE_VALUES[object_id]}" != unavailable ]]; then
      if [[ "${_QCSD_RETIRE_VALUES[kind]}" == run ]]; then
        object_key="container:${_QCSD_RETIRE_VALUES[object_id]}"
      else
        object_key="network:${_QCSD_RETIRE_VALUES[object_id]}"
      fi
      [[ -z "${seen_ids[${object_key}]+x}" ]] || return 1
      seen_ids["${object_key}"]="${root}"
    fi
    if [[ "${_QCSD_RETIRE_VALUES[launcher_pid]}" != unavailable ]]; then
      launcher_key="${_QCSD_RETIRE_VALUES[host_boot_id]}:${_QCSD_RETIRE_VALUES[launcher_pid]}:${_QCSD_RETIRE_VALUES[launcher_start_time]}:${_QCSD_RETIRE_VALUES[launcher_session]}:${_QCSD_RETIRE_VALUES[launcher_process_group]}"
      [[ -z "${seen_launchers[${launcher_key}]+x}" ]] || return 1
      seen_launchers["${launcher_key}"]="${root}"
    fi
    retiring_active["${_QCSD_RETIRE_VALUES[active_name]}"]="${root}"
    retiring_retired["${_QCSD_RETIRE_VALUES[retired_name]}"]="${root}"
  done
  for root in "${retired_candidates[@]}"; do
    [[ -n "${retiring_retired[${root##*/}]+x}" ]] || {
      echo "Docker lifecycle admission found an unauthorised retired root: ${root}" >&2
      return 1
    }
  done
  for root in "${active_candidates[@]}"; do
    [[ -z "${retiring_active[${root##*/}]+x}" ]] || continue
    roots+=("${root}")
  done
  for root in "${roots[@]}"; do
    root_kind="${root##*/}"
    root_kind="${root_kind%%.*}"
    _qcsd_lifecycle_validate_root "${root}" "${root_kind}" || {
      echo "Docker lifecycle admission found malformed state: ${root}" >&2
      return 1
    }
    if (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED == 0 )); then
      _qcsd_lifecycle_require_stale_supervisor \
        _QCSD_LIFECYCLE_SELECTED_VALUES "${current_boot}" || {
        echo "Docker lifecycle admission found an active supervisor: ${root}" >&2
        return 1
      }
    fi
    [[ -z "${seen_tokens[${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_token]}]+x}" ]] ||
      return 1
    seen_tokens["${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_token]}"]="${root}"
    if (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED == 0 )) &&
       [[ -v '_QCSD_LIFECYCLE_SELECTED_VALUES[supervisor_label]' ]]; then
      [[ -z "${seen_labels[${_QCSD_LIFECYCLE_SELECTED_VALUES[supervisor_label]}]+x}" ]] ||
        return 1
      seen_labels["${_QCSD_LIFECYCLE_SELECTED_VALUES[supervisor_label]}"]="${root}"
    fi
    if (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED == 0 )) &&
       [[ -v '_QCSD_LIFECYCLE_SELECTED_VALUES[scope_unit]' ]]; then
      [[ -z "${seen_scopes[${_QCSD_LIFECYCLE_SELECTED_VALUES[scope_unit]}]+x}" ]] ||
        return 1
      seen_scopes["${_QCSD_LIFECYCLE_SELECTED_VALUES[scope_unit]}"]="${root}"
      if [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[scope_launcher_pid]}" != unavailable ]]; then
        launcher_key="${_QCSD_LIFECYCLE_SELECTED_VALUES[host_boot_id]}:${_QCSD_LIFECYCLE_SELECTED_VALUES[scope_launcher_pid]}:${_QCSD_LIFECYCLE_SELECTED_VALUES[scope_launcher_start_time]}:${_QCSD_LIFECYCLE_SELECTED_VALUES[scope_launcher_session]}:${_QCSD_LIFECYCLE_SELECTED_VALUES[scope_launcher_process_group]}"
        [[ -z "${seen_launchers[${launcher_key}]+x}" ]] || return 1
        seen_launchers["${launcher_key}"]="${root}"
      fi
    fi
    if (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED == 0 )) &&
       [[ "${root_kind}" == "run" &&
          "${_QCSD_LIFECYCLE_SELECTED_VALUES[container_id]}" != "unavailable" ]]; then
      [[ -z "${seen_ids[container:${_QCSD_LIFECYCLE_SELECTED_VALUES[container_id]}]+x}" ]] ||
        return 1
      seen_ids["container:${_QCSD_LIFECYCLE_SELECTED_VALUES[container_id]}"]="${root}"
    elif (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED == 0 )) &&
         [[ "${root_kind}" == "network" &&
            "${_QCSD_LIFECYCLE_SELECTED_VALUES[network_id]}" != "unavailable" ]]; then
      [[ -z "${seen_ids[network:${_QCSD_LIFECYCLE_SELECTED_VALUES[network_id]}]+x}" ]] ||
        return 1
      seen_ids["network:${_QCSD_LIFECYCLE_SELECTED_VALUES[network_id]}"]="${root}"
    fi
    kinds+=("${root_kind}")
    if (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED == 0 )); then
      _qcsd_lifecycle_preauthorisation_object_absent \
        "${root_kind}" _QCSD_LIFECYCLE_SELECTED_VALUES || {
        blocked_root="${root}"
      }
      if _qcsd_lifecycle_preauthorisation_contradiction \
          "${root_kind}" _QCSD_LIFECYCLE_SELECTED_VALUES "${current_boot}"; then
        blocked_root="${root}"
      fi
    fi
    if (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED == 0 )) &&
       [[ "${root_kind}" == "transaction" ||
          ( "${root_kind}" == "build" &&
            "${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}" != "declared" ) ]]; then
      blocked_root="${root}"
    fi
  done
  # A build transaction remains a hard admission block, but it must not leave
  # an exactly identified pre-exec launcher stopped indefinitely.  After the
  # complete set validates, terminate/prove only local build scopes; retain
  # every durable build/transaction receipt and perform no Docker mutation.
  if [[ -n "${blocked_root}" ]]; then
    for (( index = 0; index < ${#roots[@]}; index++ )); do
      [[ "${kinds[index]}" == "build" || "${kinds[index]}" == "run" ]] || continue
      root="${roots[index]}"
      _qcsd_lifecycle_validate_root "${root}" "${kinds[index]}" || return 1
      if (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED == 0 )) &&
         ! _qcsd_lifecycle_is_v57_source_successor "${kinds[index]}" \
             "${_QCSD_LIFECYCLE_SELECTED_RECORD##*/}" \
             _QCSD_LIFECYCLE_SELECTED_VALUES; then
        # Even when another root blocks global admission, a predecessor
        # HANDOFF remains ledger-only and never enters scope-control code.
        _qcsd_lifecycle_stop_stale_scope \
          _QCSD_LIFECYCLE_SELECTED_VALUES "${current_boot}" 1 || return 1
      fi
    done
  fi
  if [[ -n "${blocked_root}" ]]; then
    echo "Docker lifecycle admission is blocked by unresolved build state or contradictory pre-authorisation evidence: ${blocked_root}" >&2
    return 1
  fi
  [[ "${requested_action}" == "recover" ]] || return 0
  for root in "${staged_authorities[@]}"; do
    local staged_base_meta staged_meta staged_tail staged_dev staged_ino staged_size
    local staged_sha final_authority active_name
    local active_root root_identity root_dev root_ino
    _qcsd_retirement_parse_authority "${root}" || return 1
    staged_base_meta="$(stat -Lc '%d:%i' -- "${_qcsd_lifecycle_base}")" || return 1
    staged_meta="$(stat -Lc '%d:%i:%s' -- "${root}")" || return 1
    staged_dev="${staged_meta%%:*}"; staged_tail="${staged_meta#*:}"
    staged_ino="${staged_tail%%:*}"; staged_size="${staged_tail##*:}"
    staged_sha="$(sha256sum -- "${root}" | awk '{print $1}')" || return 1
    [[ "${staged_sha}" =~ ^[0-9a-f]{64}$ ]] || return 1
    final_authority="${root%.next}"
    active_name="${_QCSD_RETIRE_VALUES[active_name]}"
    active_root="${_qcsd_lifecycle_base}/${active_name}"
    root_identity="${_QCSD_RETIRE_VALUES[root_identity]}"
    root_dev="${root_identity%%:*}"; root_identity="${root_identity#*:}"
    root_ino="${root_identity%%:*}"
    [[ -d "${active_root}" && ! -L "${active_root}" &&
        "$(_qcsd_lifecycle_root_manifest_sha256 "${active_root}")" == "${_QCSD_RETIRE_VALUES[root_manifest_sha256]}" ]] || return 1
    _qcsd_retirement_native_op promote-authority \
      "${_qcsd_lifecycle_base}" "${EUID}" \
      "${staged_base_meta%%:*}" "${staged_base_meta##*:}" "${root##*/}" \
      "${final_authority##*/}" "${staged_dev}" "${staged_ino}" \
      "${staged_size}" "${staged_sha}" "${active_name}" \
      "${root_dev}" "${root_ino}" \
      "${_QCSD_RETIRE_VALUES[root_manifest_sha256]}" || return 1
    authorities+=("${final_authority}")
  done
  # Final authorities were all admitted above. Resume them before ordinary
  # stale roots; each native step reauthenticates the authority and target.
  for root in "${authorities[@]}"; do
    _qcsd_resume_retirement "${root}" || return 1
  done
  # A daemon request can outlive the launcher that issued it.  Contain every
  # ordinary published run first, pin its exact receipt/root snapshot through
  # containment, and only then start one shared delayed-create settle window.
  # Unpublished roots have no authorised request, while the allowlisted v57
  # successor path is deliberately ledger-only and never controls a scope.
  for (( index = 0; index < ${#roots[@]}; index++ )); do
    [[ "${kinds[index]}" == run ]] || continue
    root="${roots[index]}"
    _qcsd_lifecycle_validate_root "${root}" run || return 1
    (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED == 0 )) || continue
    if _qcsd_lifecycle_is_v57_source_successor run \
        "${_QCSD_LIFECYCLE_SELECTED_RECORD##*/}" \
        _QCSD_LIFECYCLE_SELECTED_VALUES; then
      continue
    fi
    selected_record_snapshot="${_QCSD_LIFECYCLE_SELECTED_RECORD}"
    selected_sha_snapshot="$(sha256sum -- "${selected_record_snapshot}" | awk '{print $1}')" ||
      return 1
    manifest_snapshot="$(_qcsd_lifecycle_root_manifest_sha256 "${root}")" || return 1
    preauth_stop=0
    if [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}" == declared ||
          ( "${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}" == unresolved &&
            "${_QCSD_LIFECYCLE_SELECTED_VALUES[daemon_request_authorised]:-1}" == 0 ) ]]; then
      preauth_stop=1
    fi
    _qcsd_lifecycle_stop_stale_scope \
      _QCSD_LIFECYCLE_SELECTED_VALUES "${current_boot}" "${preauth_stop}" || return 1
    (( _QCSD_PREAUTH_CONTRADICTION_AT_CONTAINMENT == 0 )) || return 1
    _qcsd_lifecycle_revalidate_snapshot "${root}" run \
      "${selected_record_snapshot}" "${selected_sha_snapshot}" \
      "${manifest_snapshot}" || return 1
    run_contained[index]=1
    recovery_record_snapshots[index]="${selected_record_snapshot}"
    recovery_sha_snapshots[index]="${selected_sha_snapshot}"
    recovery_manifest_snapshots[index]="${manifest_snapshot}"
    if [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}" == request-authorised ||
          "${_QCSD_LIFECYCLE_SELECTED_VALUES[daemon_request_authorised]:-0}" == 1 ]]; then
      run_settle_required=1
    fi
  done
  if (( run_settle_required != 0 )); then
    _qcsd_lifecycle_settle_recovery_batch run || return 1
  fi
  # Container scopes own the network attachments.  Validation above is a
  # complete fail-closed pass; mutation below is deliberately dependency
  # ordered so network removal cannot precede recovery of an attached run.
  for recovery_kind in run build transaction network; do
    if [[ "${recovery_kind}" == network ]]; then
      network_settle_required=0
      # Pin every ordinary published network before the shared wait, then
      # revalidate the same snapshot immediately before its Docker mutation.
      for (( index = 0; index < ${#roots[@]}; index++ )); do
        [[ "${kinds[index]}" == network ]] || continue
        root="${roots[index]}"
        _qcsd_lifecycle_validate_root "${root}" network || return 1
        (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED == 0 )) || continue
        if _qcsd_lifecycle_is_v57_source_successor network \
            "${_QCSD_LIFECYCLE_SELECTED_RECORD##*/}" \
            _QCSD_LIFECYCLE_SELECTED_VALUES; then
          continue
        fi
        selected_record_snapshot="${_QCSD_LIFECYCLE_SELECTED_RECORD}"
        selected_sha_snapshot="$(sha256sum -- "${selected_record_snapshot}" | awk '{print $1}')" ||
          return 1
        manifest_snapshot="$(_qcsd_lifecycle_root_manifest_sha256 "${root}")" || return 1
        _qcsd_lifecycle_revalidate_snapshot "${root}" network \
          "${selected_record_snapshot}" "${selected_sha_snapshot}" \
          "${manifest_snapshot}" || return 1
        network_preflighted[index]=1
        recovery_record_snapshots[index]="${selected_record_snapshot}"
        recovery_sha_snapshots[index]="${selected_sha_snapshot}"
        recovery_manifest_snapshots[index]="${manifest_snapshot}"
        if [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}" == request-authorised ||
              "${_QCSD_LIFECYCLE_SELECTED_VALUES[daemon_request_authorised]:-0}" == 1 ]]; then
          network_settle_required=1
        fi
      done
      if (( network_settle_required != 0 )); then
        _qcsd_lifecycle_settle_recovery_batch network || return 1
      fi
    fi
    for (( index = 0; index < ${#roots[@]}; index++ )); do
      root="${roots[index]}"
      root_kind="${kinds[index]}"
      [[ "${root_kind}" == "${recovery_kind}" ]] || continue
      if [[ ( "${root_kind}" == run && "${run_contained[$index]:-0}" == 1 ) ||
            ( "${root_kind}" == network && "${network_preflighted[$index]:-0}" == 1 ) ]]; then
        selected_record_snapshot="${recovery_record_snapshots[index]}"
        selected_sha_snapshot="${recovery_sha_snapshots[index]}"
        manifest_snapshot="${recovery_manifest_snapshots[index]}"
        _qcsd_lifecycle_revalidate_snapshot "${root}" "${root_kind}" \
          "${selected_record_snapshot}" "${selected_sha_snapshot}" \
          "${manifest_snapshot}" || return 1
      else
        _qcsd_lifecycle_validate_root "${root}" "${root_kind}" || return 1
        selected_record_snapshot=""
        selected_sha_snapshot=""
        manifest_snapshot="$(_qcsd_lifecycle_root_manifest_sha256 "${root}")" || return 1
        if (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED == 0 )); then
          selected_record_snapshot="${_QCSD_LIFECYCLE_SELECTED_RECORD}"
          selected_sha_snapshot="$(sha256sum -- "${selected_record_snapshot}" | awk '{print $1}')" ||
            return 1
        fi
      fi
      if (( _QCSD_LIFECYCLE_SELECTED_UNPUBLISHED != 0 )); then
        _qcsd_lifecycle_remove_unchanged_root \
          "${root}" "${root_kind}" "" "" "${manifest_snapshot}" || return 1
        echo "Recovered unpublished Docker ${root_kind} lifecycle state: ${root}" >&2
        continue
      fi
      case "${root_kind}" in
        run)
          if _qcsd_lifecycle_is_v57_source_successor "${root_kind}" \
              "${_QCSD_LIFECYCLE_SELECTED_RECORD##*/}" \
              _QCSD_LIFECYCLE_SELECTED_VALUES; then
            # The exceptional successor path is ledger-only. It may retire a
            # now-ownerless HANDOFF after fresh absence proofs, but it must
            # never stop a scope or issue Docker kill/rm requests.
            _qcsd_lifecycle_revalidate_snapshot "${root}" "${root_kind}" \
              "${selected_record_snapshot}" "${selected_sha_snapshot}" \
              "${manifest_snapshot}" || return 1
          else
            (( ${run_contained[$index]:-0} == 1 )) || return 1
            _qcsd_lifecycle_reprove_recovery_boundary run \
              _QCSD_LIFECYCLE_SELECTED_VALUES "${current_boot}" || return 1
            _qcsd_lifecycle_recover_container \
              "${root}" _QCSD_LIFECYCLE_SELECTED_VALUES 1 || return 1
          fi
          ;;
        network)
          _qcsd_lifecycle_revalidate_snapshot "${root}" "${root_kind}" \
            "${selected_record_snapshot}" "${selected_sha_snapshot}" \
            "${manifest_snapshot}" || return 1
          if ! _qcsd_lifecycle_is_v57_source_successor "${root_kind}" \
              "${_QCSD_LIFECYCLE_SELECTED_RECORD##*/}" \
              _QCSD_LIFECYCLE_SELECTED_VALUES; then
            (( ${network_preflighted[$index]:-0} == 1 )) || return 1
            _qcsd_lifecycle_reprove_recovery_boundary network \
              _QCSD_LIFECYCLE_SELECTED_VALUES "${current_boot}" || return 1
            _qcsd_lifecycle_recover_network \
              _QCSD_LIFECYCLE_SELECTED_VALUES 1 || return 1
          fi
          ;;
        build)
          [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}" == "declared" ]] ||
            return 1
          _qcsd_lifecycle_stop_stale_scope \
            _QCSD_LIFECYCLE_SELECTED_VALUES "${current_boot}" 1 || return 1
          (( _QCSD_PREAUTH_CONTRADICTION_AT_CONTAINMENT == 0 )) || return 1
          ;;
        transaction)
          # A published transaction was rejected before any recovery mutation.
          return 1
          ;;
        *) return 1 ;;
      esac
      _qcsd_lifecycle_remove_unchanged_root \
        "${root}" "${root_kind}" "${selected_record_snapshot}" \
        "${selected_sha_snapshot}" "${manifest_snapshot}" || return 1
      echo "Recovered durable Docker ${root_kind} lifecycle state: ${root}" >&2
    done
  done
}

_qcsd_handoff_retirement_error() {
  local stage="${1:-unknown}" detail="${2:-unspecified failure}"
  printf 'Docker handoff retirement failed at %s: %s\n' \
    "${stage}" "${detail}" >&2
  return 1
}

_qcsd_select_handoff_retirement_authority() {
  local root_kind="$1" object_id="$2" registration_name="$3"
  local output_name="$4" authority_path match_count=0
  local nullglob_was_set=0
  local -a authorities=()
  local -n output_ref="${output_name}"
  output_ref=""
  shopt -q nullglob && nullglob_was_set=1
  shopt -s nullglob
  authorities=("${_qcsd_lifecycle_base}/retirement.${root_kind}."*)
  (( nullglob_was_set != 0 )) || shopt -u nullglob
  for authority_path in "${authorities[@]}"; do
    [[ "${authority_path}" != *.next ]] || continue
    _qcsd_validate_retirement_phase "${authority_path}" || return 1
    if [[ "${_QCSD_RETIRE_VALUES[kind]}" == "${root_kind}" &&
          "${_QCSD_RETIRE_VALUES[reason]}" == handoff-retired &&
          "${_QCSD_RETIRE_VALUES[object_id]}" == "${object_id}" &&
          "${_QCSD_RETIRE_VALUES[registration_name]}" == "${registration_name}" ]]; then
      output_ref="${authority_path}"
      match_count=$((match_count + 1))
    fi
  done
  (( match_count <= 1 ))
}

qcsd_retire_docker_handoff() {
  local root_kind="${1:-}"
  local object_id="${2:-}"
  local registration_name="${3:-}"
  local root authority="" candidate="" candidate_count=0 presence
  local candidate_sha="" observed_sha
  local candidate_manifest="" observed_manifest entry attempt
  local nullglob_was_set=0
  local -a roots=()
  if [[ ! "${root_kind}" =~ ^(run|network)$ ||
        ! "${object_id}" =~ ^[0-9a-f]{64}$ ||
        ! "${registration_name}" =~ ^QCSD_DOCKER_IDS_[A-Z0-9_]+$ ]]; then
    _qcsd_handoff_retirement_error request-validation \
      "invalid kind, object ID, or registration name"
    return 1
  fi
  if ! _qcsd_verify_pinned_docker_daemon; then
    _qcsd_handoff_retirement_error daemon-identity \
      "pinned Docker daemon could not be revalidated"
    return 1
  fi
  if ! _qcsd_verify_pinned_host_boot; then
    _qcsd_handoff_retirement_error host-boot \
      "pinned host boot could not be revalidated"
    return 1
  fi
  if ! _qcsd_secure_lifecycle_base; then
    _qcsd_handoff_retirement_error lifecycle-base \
      "durable lifecycle base validation failed"
    return 1
  fi
  # Publication proves that exact HANDOFF selection already succeeded. Resume
  # it before looking for an active root, which may already have been renamed.
  if ! _qcsd_select_handoff_retirement_authority \
      "${root_kind}" "${object_id}" "${registration_name}" authority; then
    _qcsd_handoff_retirement_error authority-selection \
      "invalid or non-unique durable ${root_kind} retirement authority"
    return 1
  fi
  if [[ -n "${authority}" ]]; then
    if ! _qcsd_resume_retirement "${authority}"; then
      _qcsd_handoff_retirement_error durable-authority-continuation \
        "authenticated retirement did not complete; retained ${authority}"
      return 1
    fi
    return 0
  fi
  shopt -q nullglob && nullglob_was_set=1
  shopt -s nullglob
  roots=("${_qcsd_lifecycle_base}/${root_kind}."*)
  (( nullglob_was_set != 0 )) || shopt -u nullglob
  for root in "${roots[@]}"; do
    [[ -f "${root}/HANDOFF" && ! -L "${root}/HANDOFF" ]] || continue
    if ! _qcsd_lifecycle_validate_root "${root}" "${root_kind}"; then
      _qcsd_handoff_retirement_error root-validation \
        "invalid ${root_kind} lifecycle root ${root}"
      return 1
    fi
    [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[lifecycle_state]}" == "handed-off" ]] ||
      continue
    if [[ "${_QCSD_LIFECYCLE_SELECTED_VALUES[registration_name]}" == \
          "${registration_name}" ]] &&
       { [[ "${root_kind}" == "run" &&
             "${_QCSD_LIFECYCLE_SELECTED_VALUES[container_id]}" == "${object_id}" ]] ||
         [[ "${root_kind}" == "network" &&
             "${_QCSD_LIFECYCLE_SELECTED_VALUES[network_id]}" == "${object_id}" ]]; }; then
      candidate="${root}"
      if ! candidate_sha="$(sha256sum -- "${root}/HANDOFF" | awk '{print $1}')"; then
        _qcsd_handoff_retirement_error candidate-record-digest \
          "could not hash ${root}/HANDOFF"
        return 1
      fi
      if ! candidate_manifest="$(_qcsd_lifecycle_root_manifest_sha256 "${root}")"; then
        _qcsd_handoff_retirement_error candidate-manifest \
          "could not bind lifecycle manifest for ${root}"
        return 1
      fi
      candidate_count=$((candidate_count + 1))
    fi
  done
  if (( candidate_count != 1 )); then
    _qcsd_handoff_retirement_error candidate-selection \
      "expected one exact ${root_kind} HANDOFF for ${registration_name}; found ${candidate_count}"
    return 1
  fi
  for (( attempt = 1;
         attempt <= _QCSD_DOCKER_HANDOFF_ABSENCE_ATTEMPTS;
         attempt++ )); do
    if [[ "${root_kind}" == "run" ]]; then
      presence="$(_qcsd_docker_exact_id_presence_detailed "${object_id}")"
    else
      presence="$(_qcsd_docker_exact_network_presence_detailed "${object_id}")"
    fi
    case "${presence}" in
      absent)
        break
        ;;
      present|ambiguous)
        _qcsd_handoff_retirement_error absence-proof \
          "exact ${root_kind} presence is ${presence}; retained ${candidate}"
        return 1
        ;;
      unknown)
        if (( attempt == _QCSD_DOCKER_HANDOFF_ABSENCE_ATTEMPTS )); then
          _qcsd_handoff_retirement_error absence-proof \
            "exact ${root_kind} presence remained unknown after ${attempt} attempts; retained ${candidate}"
          return 1
        fi
        printf 'Docker handoff retirement retrying absence-proof after exact %s presence was unknown (attempt %d/%d): %s\n' \
          "${root_kind}" "${attempt}" \
          "${_QCSD_DOCKER_HANDOFF_ABSENCE_ATTEMPTS}" "${candidate}" >&2
        if ! _qcsd_verify_pinned_docker_daemon; then
          _qcsd_handoff_retirement_error absence-retry-daemon-identity \
            "pinned Docker daemon could not be revalidated after unknown presence"
          return 1
        fi
        if ! _qcsd_verify_pinned_host_boot; then
          _qcsd_handoff_retirement_error absence-retry-host-boot \
            "pinned host boot could not be revalidated after unknown presence"
          return 1
        fi
        ;;
      *)
        _qcsd_handoff_retirement_error absence-proof \
          "invalid exact ${root_kind} presence result; retained ${candidate}"
        return 1
        ;;
    esac
  done
  if [[ "${presence}" != absent ]]; then
    _qcsd_handoff_retirement_error absence-proof \
      "exact ${root_kind} absence was not established; retained ${candidate}"
    return 1
  fi
  if ! _qcsd_handoff_retire_after_absence_hook \
      "${candidate}" "${root_kind}" "${object_id}" "${registration_name}"; then
    _qcsd_handoff_retirement_error post-absence-hook \
      "post-proof retirement boundary failed; retained ${candidate}"
    return 1
  fi
  if ! _qcsd_validate_lifecycle_root_contents "${candidate}"; then
    _qcsd_handoff_retirement_error root-contents-revalidation \
      "lifecycle root changed after absence proof; retained ${candidate}"
    return 1
  fi
  for entry in "${candidate}"/*.next; do
    if [[ -e "${entry}" || -L "${entry}" ]]; then
      _qcsd_handoff_retirement_error staged-record-check \
        "staged lifecycle entry appeared after absence proof; retained ${candidate}"
      return 1
    fi
  done
  if ! observed_sha="$(sha256sum -- "${candidate}/HANDOFF" | awk '{print $1}')" ||
     [[ "${observed_sha}" != "${candidate_sha}" ]]; then
    _qcsd_handoff_retirement_error record-digest-revalidation \
      "HANDOFF digest changed after absence proof; retained ${candidate}"
    return 1
  fi
  if ! observed_manifest="$(_qcsd_lifecycle_root_manifest_sha256 "${candidate}")" ||
     [[ "${observed_manifest}" != "${candidate_manifest}" ]]; then
    _qcsd_handoff_retirement_error manifest-revalidation \
      "lifecycle manifest changed after absence proof; retained ${candidate}"
    return 1
  fi
  if ! _qcsd_revalidate_helper_source_identity; then
    _qcsd_handoff_retirement_error helper-source-revalidation \
      "executed helper source identity changed; retained ${candidate}"
    return 1
  fi
  if ! _qcsd_lifecycle_remove_root "${candidate}" 0 handoff-retired; then
    _qcsd_handoff_retirement_error durable-root-removal \
      "authenticated retirement did not complete; retained durable state for ${candidate}"
    return 1
  fi
}
