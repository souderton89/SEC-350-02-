#!/bin/vbash
# vyos-dynamic-menu.sh
# Dynamic CRUD menu for Firewall (ipv4 rulesets) + NAT + Interfaces + System (users + hostname)
# Scans live config each time. No hardcoded rules.
#
# SAFETY GOALS:
# - "ADD" must NOT overwrite existing items.
#   * Add DNAT: blocks rule number if it already exists.
#   * Add Firewall rule: blocks rule number if it already exists in that ruleset.
#   * Add Zone binding: blocks if binding already exists (TO<-FROM already has a ruleset).
# - User is ALWAYS shown what exists + the next suggested free rule number.
# - Updates/changes to existing rules/bindings must be done via Update/Delete menus (not Add).
#
# USER FRIENDLY:
# - Every submenu repeats detected items.
# - Every prompt explains WHAT you are selecting.
# - If a list is empty, you get a clear error (no blind "Select:").
# - Uses grep -F (no regex from user input).
# - Preview before delete/update.
#
# PORTABILITY FIX:
# - Does NOT rely on "mapfile/readarray". Uses a portable loader (works across VyOS variations).
# - Forces ALL UI output/input through /dev/tty so menus never “disappear” on some VyOS builds.
#
# CONFIG SESSION FIX (IMPORTANT):
# - Uses cli-shell-api sessions + my_* commands (modern + stable).
#   Flow: getSessionEnv -> setupSession -> my_set/my_delete/my_commit -> teardownSession
#   This avoids "without config session" and avoids broken legacy save script paths.

TTY="/dev/tty"

# Force script to run in vyattacfg group (fixes config session / permission weirdness)
# FIX: preserve arguments safely (handles spaces/special chars)
if [ "$(id -gn 2>/dev/null)" != "vyattacfg" ]; then
  SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"

  # Build a safely-quoted argument string for sg -c (bash-style quoting)
  ARGS=""
  for a in "$@"; do
    ARGS="$ARGS $(printf "%q" "$a")"
  done

  # Quote the script path too
  exec sg vyattacfg -c "/bin/vbash $(printf "%q" "$SCRIPT_PATH")$ARGS"
fi

source /opt/vyatta/etc/functions/script-template

# -----------------------------
# TTY-safe IO (PORTABILITY FIX)
# -----------------------------
tprint() { printf "%s\n" "$*" >"$TTY"; }
tprintf() { printf "$@" >"$TTY"; }

# -----------------------------
# FIX: prevent VyOS completion crash in scripts
# -----------------------------
disable_completion_env() {
  unset COMP_LINE COMP_POINT COMP_TYPE COMP_KEY COMP_WORDBREAKS 2>/dev/null || true
  unset COMP_WORDS COMP_CWORD 2>/dev/null || true
}

tread() {
  local __var="$1"; shift
  local __prompt="${1:-}"
  local __val=""

  disable_completion_env

  if [ -n "$__prompt" ]; then
    read -r -p "$__prompt" __val <"$TTY"
  else
    read -r __val <"$TTY"
  fi
  printf -v "$__var" "%s" "$__val"
}

tread_secret() {
  # Like tread, but hides input (password)
  local __var="$1"; shift
  local __prompt="${1:-Password: }"
  local __val=""

  disable_completion_env

  # -s hides, -r raw, -p prompt
  read -r -s -p "$__prompt" __val <"$TTY"
  printf "\n" >"$TTY"
  printf -v "$__var" "%s" "$__val"
}

pause() { tprint ""; local _; tread _ "Press Enter to continue..."; }

strip_quotes() {
  local s="$1"
  s="${s#\'}"
  s="${s%\'}"
  echo "$s"
}

join_lines() { tr '\n' ' ' | sed 's/[[:space:]]*$//'; }

load_array() {
  local __name="$1"; shift
  local line=""
  eval "$__name=()"
  while IFS= read -r line; do
    [ -n "$line" ] && eval "$__name+=(\"\$line\")"
  done < <("$@")
}

# -----------------------------
# Input validation (NO OPEN-ENDED INPUT)
# -----------------------------
is_valid_username() {
  # Linux-ish, safe for VyOS CLI tokens.
  # starts with letter/_ then letters/numbers/_/.- ; length 1-32
  echo "$1" | grep -Eq '^[A-Za-z_][A-Za-z0-9_.-]{0,31}$'
}
is_valid_hostname() {
  # RFC-ish, no underscores; 1-253; labels 1-63; no leading/trailing '-'
  local hn="$1"
  [ -z "$hn" ] && return 1
  [ "${#hn}" -gt 253 ] && return 1
  echo "$hn" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
}
is_valid_ipv4() {
  local ip="$1"
  echo "$ip" | awk -F. '
    NF!=4{exit 1}
    {for(i=1;i<=4;i++){ if($i!~/^[0-9]+$/) exit 1; if($i<0||$i>255) exit 1}}
    END{exit 0}'
}
is_valid_cidr4() {
  local cidr="$1"
  echo "$cidr" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$' || return 1
  local ip="${cidr%/*}"
  is_valid_ipv4 "$ip"
}
is_valid_port_or_range() {
  # 1-65535 or 1-65535-1-65535
  local p="$1"
  echo "$p" | grep -Eq '^[0-9]{1,5}(-[0-9]{1,5})?$' || return 1
  local a="${p%%-*}"
  local b=""
  [ "$a" -ge 1 ] 2>/dev/null || return 1
  [ "$a" -le 65535 ] 2>/dev/null || return 1
  if echo "$p" | grep -q -- '-'; then
    b="${p#*-}"
    [ "$b" -ge 1 ] 2>/dev/null || return 1
    [ "$b" -le 65535 ] 2>/dev/null || return 1
    [ "$a" -le "$b" ] 2>/dev/null || return 1
  fi
  return 0
}
is_safe_ruleset_name() {
  # Avoid breaking grep/awk and CLI tokens. Allow letters, numbers, underscore, dash, dot.
  echo "$1" | grep -Eq '^[A-Za-z0-9_.-]{1,64}$'
}
is_safe_iface_name() {
  # eth0, eth1, bond0, etc. (simple)
  echo "$1" | grep -Eq '^[A-Za-z0-9_.:-]{1,32}$'
}
is_safe_free_text() {
  # For description/full-name: block control chars, pipes, backticks.
  # Allow spaces, typical punctuation.
  printf "%s" "$1" | grep -Eq '^[[:print:]]{1,128}$' && ! printf "%s" "$1" | grep -Eq '[`|]'
}
reject_if_unsafe_commandline() {
  # Blocks shell metacharacters and quoting that our simple splitter can't safely preserve.
  # This makes "raw mode" non-open-ended.
  local s="$1"
  printf "%s" "$s" | grep -Eq '[;&|`$<>()\\]' && return 0
  printf "%s" "$s" | grep -Eq '[\r\n\t]' && return 0
  # FIX: safe quote detection without breaking shell quoting
  printf "%s" "$s" | grep -Eq "[\"']" && return 0
  return 1
}

# ============================================================
# API SESSION (FIXES: save script not found, remove-user crash)
# ============================================================
API_ACTIVE=0
MY_SET=""
MY_DELETE=""
MY_COMMIT=""
SAVE_BIN=""
SAVE_CANDIDATES=()

api_detect_bins() {
  local SBIN="/opt/vyatta/sbin"

  MY_SET="$SBIN/my_set"
  MY_DELETE="$SBIN/my_delete"
  MY_COMMIT="$SBIN/my_commit"

  # SAVE varies by build. Auto-detect common candidates.
  SAVE_CANDIDATES=(
    "$SBIN/vyos-config-save"
    "$SBIN/vyatta-save-config"
    "$SBIN/vyos-save-config"
    "$SBIN/vyos-save-config.py"
    "/usr/libexec/vyos/vyos-config-save"
    "/usr/libexec/vyos/vyos-save-config"
    "/usr/libexec/vyos/vyos-save-config.py"
    "/usr/lib/vyos/vyos-config-save"
    "/usr/lib/vyos/vyos-save-config.py"
  )

  SAVE_BIN=""
  local c
  for c in "${SAVE_CANDIDATES[@]}"; do
    if [ -x "$c" ]; then
      SAVE_BIN="$c"
      break
    fi
  done
}

api_begin() {
  disable_completion_env
  api_detect_bins

  # Must have cli-shell-api + my_* tools
  if ! command -v cli-shell-api >/dev/null 2>&1; then
    tprint ""
    tprint "ERROR: cli-shell-api not found. Cannot open API config session."
    pause
    return 1
  fi
  if [ ! -x "$MY_SET" ] || [ ! -x "$MY_DELETE" ] || [ ! -x "$MY_COMMIT" ]; then
    tprint ""
    tprint "ERROR: my_* commands not found in /opt/vyatta/sbin."
    tprint "Expected:"
    tprint "  /opt/vyatta/sbin/my_set"
    tprint "  /opt/vyatta/sbin/my_delete"
    tprint "  /opt/vyatta/sbin/my_commit"
    pause
    return 1
  fi

  # Build session environment for THIS process
  local session_env=""
  session_env="$(cli-shell-api getSessionEnv "$PPID" 2>/dev/null || true)"
  if [ -z "$session_env" ]; then
    session_env="$(cli-shell-api getSessionEnv "$$" 2>/dev/null || true)"
  fi
  if [ -z "$session_env" ]; then
    tprint ""
    tprint "ERROR: could not get session env (cli-shell-api getSessionEnv)."
    pause
    return 1
  fi
  eval "$session_env"

  # Start session
  if ! cli-shell-api setupSession <"$TTY" >"$TTY" 2>&1; then
    tprint ""
    tprint "ERROR: could not setupSession."
    pause
    return 1
  fi

  # Confirm session is active
  cli-shell-api inSession >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    tprint ""
    tprint "ERROR: API session is not active (inSession failed)."
    cli-shell-api teardownSession >/dev/null 2>&1 || true
    pause
    return 1
  fi

  API_ACTIVE=1
  return 0
}

api_end() {
  disable_completion_env
  if [ "$API_ACTIVE" -eq 1 ]; then
    cli-shell-api teardownSession <"$TTY" >"$TTY" 2>&1 || true
  fi
  API_ACTIVE=0
}

# -----------------------------
# SAFE WRAPPERS (DO NOT OVERRIDE set/delete/commit/save)
# -----------------------------
cfg_set() {
  [ "$API_ACTIVE" -eq 1 ] || { tprint "ERROR: no API session (cfg_set)"; return 1; }
  "$MY_SET" "$@"
}
cfg_delete() {
  [ "$API_ACTIVE" -eq 1 ] || { tprint "ERROR: no API session (cfg_delete)"; return 1; }
  "$MY_DELETE" "$@"
}
cfg_commit() {
  [ "$API_ACTIVE" -eq 1 ] || { tprint "ERROR: no API session (cfg_commit)"; return 1; }
  "$MY_COMMIT"
}
cfg_save() {
  [ "$API_ACTIVE" -eq 1 ] || { tprint "ERROR: no API session (cfg_save)"; return 1; }
  if [ -n "${SAVE_BIN:-}" ] && [ -x "$SAVE_BIN" ]; then
    "$SAVE_BIN"
    return $?
  fi
  tprint ""
  tprint "ERROR: could not find a working save binary on this VyOS build."
  tprint "Your changes ARE committed but not saved."
  tprint "Run this and paste output:"
  tprint "  ls -l /opt/vyatta/sbin | grep -i save"
  return 1
}

# Keep names for your existing logic
cfg_begin() { api_begin; }
cfg_end() { api_end; }

# --- EXTRA SAFETY (recommended): always tear down session on exit ---
trap 'cfg_end >/dev/null 2>&1 || true' EXIT

# ---- ACCESS CHECKS (prevents blank menus) ----
get_cfg_cmds() {
  run show configuration commands 2>&1
}

die_no_access_if_needed() {
  local out
  out="$(get_cfg_cmds || true)"

  if echo "$out" | grep -qiE "not assigned to any operator group|permission denied|authorization|not authorized|internal error"; then
    tprint ""
    tprint "ERROR: This user does not have permission to read the live config."
    tprint "The script needs: 'show configuration commands'."
    tprint ""
    tprint "Fix:"
    tprint "  - Run as a VyOS admin user, OR"
    tprint "  - Fix this user's operator/admin permissions."
    tprint ""
    tprint "What VyOS returned:"
    tprint "----------------------------------------"
    tprint "$out"
    tprint "----------------------------------------"
    tprint ""
    exit 1
  fi

  if [ -z "$out" ]; then
    tprint ""
    tprint "ERROR: 'show configuration commands' returned NOTHING."
    tprint "This usually means permission problems or a broken CLI session."
    tprint ""
    exit 1
  fi
}

show_detected_summary() {
  local ifs rulesets nd ns zones
  ifs="$(scan_eth_ifaces | join_lines)"
  rulesets="$(scan_firewall_rulesets | join_lines)"
  zones="$(scan_fw_zones | join_lines)"
  nd="$(scan_nat_dest_rules | join_lines)"
  ns="$(scan_nat_source_rules | join_lines)"

  tprint "Detected right now:"
  tprint "  Interfaces: ${ifs:-NONE}"
  tprint "  FW rulesets: ${rulesets:-NONE}"
  tprint "  FW zones: ${zones:-NONE}"
  tprint "  NAT dest rules: ${nd:-NONE}"
  tprint "  NAT source rules: ${ns:-NONE}"
  tprint ""
}

SELECTED=""

select_from_list() {
  local title="$1"; shift
  local arr=("$@")
  local i choice

  tprint ""
  tprint "=== $title ==="

  if [ "${#arr[@]}" -eq 0 ]; then
    tprint "(none found)"
    return 1
  fi

  for i in "${!arr[@]}"; do
    tprintf "%2d) %s\n" "$((i+1))" "${arr[$i]}"
  done
  tprint " 0) Cancel"
  tprint ""

  tread choice "Select option #: "
  if [ -z "$choice" ] || ! echo "$choice" | grep -Eq '^[0-9]+$'; then
    tprint "Invalid."
    return 1
  fi
  if [ "$choice" -eq 0 ]; then
    return 1
  fi
  if [ "$choice" -lt 1 ] || [ "$choice" -gt "${#arr[@]}" ]; then
    tprint "Invalid."
    return 1
  fi

  SELECTED="${arr[$((choice-1))]}"
  return 0
}

# -----------------------------
# NEW: numbered vertical choice lists w/ default + Enter support
# -----------------------------
select_from_list_default() {
  local title="$1"; shift
  local def="$1"; shift
  local arr=("$@")
  local i choice def_idx=""

  tprint ""
  tprint "=== $title ==="

  if [ "${#arr[@]}" -eq 0 ]; then
    tprint "(none found)"
    return 1
  fi

  for i in "${!arr[@]}"; do
    if [ -n "$def" ] && [ "${arr[$i]}" = "$def" ]; then
      tprintf "%2d) %s  (default)\n" "$((i+1))" "${arr[$i]}"
      def_idx="$((i+1))"
    else
      tprintf "%2d) %s\n" "$((i+1))" "${arr[$i]}"
    fi
  done
  tprint " 0) Cancel"
  tprint ""

  if [ -n "$def_idx" ]; then
    tread choice "Select option # [${def_idx}]: "
    choice="${choice:-$def_idx}"
  else
    tread choice "Select option #: "
  fi

  if [ -z "$choice" ] || ! echo "$choice" | grep -Eq '^[0-9]+$'; then
    tprint "Invalid."
    return 1
  fi
  if [ "$choice" -eq 0 ]; then
    return 1
  fi
  if [ "$choice" -lt 1 ] || [ "$choice" -gt "${#arr[@]}" ]; then
    tprint "Invalid."
    return 1
  fi

  SELECTED="${arr[$((choice-1))]}"
  return 0
}

choose_fw_action() {
  local def="${1:-accept}"
  if select_from_list_default "Action (what to do with matched traffic)" "$def" "accept" "drop" "reject"; then
    echo "$SELECTED"
    return 0
  fi
  return 1
}

choose_fw_protocol() {
  local def="${1:-tcp}"
  if select_from_list_default "Protocol (what traffic type to match)" "$def" "tcp" "udp" "icmp" "any"; then
    echo "$SELECTED"
    return 0
  fi
  return 1
}

choose_nat_type() {
  local def="${1:-destination}"
  tprint ""
  tprint "NAT type help:"
  tprint "  destination = DNAT / port forwarding"
  tprint "  source      = SNAT / masquerade"
  if select_from_list_default "Select NAT type" "$def" "destination" "source"; then
    echo "$SELECTED"
    return 0
  fi
  return 1
}

choose_tcp_udp() {
  local def="${1:-tcp}"
  if select_from_list_default "Protocol (tcp/udp)" "$def" "tcp" "udp"; then
    echo "$SELECTED"
    return 0
  fi
  return 1
}

choose_yes_no() {
  # Args: prompt, default(y/n)
  local prompt="$1"
  local def="${2:-n}"
  local def_label="No"
  { [ "$def" = "y" ] || [ "$def" = "Y" ]; } && def_label="Yes"

  if select_from_list_default "$prompt" "$def_label" "Yes" "No"; then
    case "$SELECTED" in
      Yes) echo "y" ;;
      No)  echo "n" ;;
    esac
    return 0
  fi
  return 1
}

ask() {
  local prompt="$1"
  local def="${2:-}"
  local val=""
  if [ -n "$def" ]; then
    tread val "$prompt [$def]: "
    echo "${val:-$def}"
  else
    tread val "$prompt: "
    echo "$val"
  fi
}

confirm_commit_save() {
  local yn
  yn="$(choose_yes_no "Commit + Save now?" "y" || true)"
  [ "${yn:-n}" = "y" ]
}

cfg_apply() {
  if confirm_commit_save; then
    disable_completion_env

    local out rc
    out="$(cfg_commit 2>&1)"
    rc=$?

    printf "%s\n" "$out" >"$TTY"

    if echo "$out" | grep -qi "No configuration changes to commit"; then
      tprint ""
      tprint "NOTE: Nothing changed, so nothing to commit."
      cfg_end
      pause
      return 0
    fi

    if [ $rc -ne 0 ]; then
      tprint ""
      tprint "ERROR: commit failed. Nothing was applied."
      cfg_end
      pause
      return 1
    fi

    disable_completion_env
    if ! cfg_save <"$TTY" >"$TTY" 2>&1; then
      tprint ""
      tprint "ERROR: save failed. Changes may be applied but not saved."
      cfg_end
      pause
      return 1
    fi

    tprint "DONE: committed + saved."
    cfg_end
  else
    tprint "Not committed. (No changes saved.)"
    cfg_end
  fi
  pause
  return 0
}

# ---- SAFETY HELPERS ----
is_number_in_list() {
  local needle="$1"; shift
  local x
  for x in "$@"; do
    [ "$x" = "$needle" ] && return 0
  done
  return 1
}

next_free_rule_number() {
  local used=("$@")
  local n=10
  while is_number_in_list "$n" "${used[@]}"; do
    n=$((n+10))
  done
  echo "$n"
}

require_numeric() { echo "$1" | grep -Eq '^[0-9]+$'; }

require_nonempty_list_or_return() {
  local label="$1"; shift
  local arr=("$@")
  if [ "${#arr[@]}" -eq 0 ]; then
    tprint ""
    tprint "ERROR: Nothing available for: $label"
    tprint "Possible reasons:"
    tprint "  - The config has none, OR"
    tprint "  - Permission problem (cannot read config)."
    tprint ""
    pause
    return 1
  fi
  return 0
}

# -----------------------------
# Scan functions (dynamic)
# -----------------------------
scan_firewall_rulesets() {
  get_cfg_cmds \
    | grep -F "set firewall ipv4 name " \
    | awk '{print $5}' \
    | sort -u \
    | while read -r n; do strip_quotes "$n"; done
}

scan_firewall_rule_numbers_quoted() {
  local rs="$1"
  get_cfg_cmds \
    | grep -F "set firewall ipv4 name '$rs' rule " \
    | awk '{print $7}' \
    | sort -u
}

scan_firewall_rule_numbers_unquoted() {
  local rs="$1"
  get_cfg_cmds \
    | grep -F "set firewall ipv4 name $rs rule " \
    | awk '{print $7}' \
    | sort -u
}

scan_firewall_rule_numbers() {
  local rs="$1"
  local a=() b=() merged=()
  load_array a scan_firewall_rule_numbers_quoted "$rs"
  load_array b scan_firewall_rule_numbers_unquoted "$rs"
  merged=("${a[@]}" "${b[@]}")
  if [ "${#merged[@]}" -gt 0 ]; then
    printf "%s\n" "${merged[@]}" | sed '/^$/d' | sort -u
  fi
}

scan_nat_dest_rules() {
  get_cfg_cmds \
    | grep -F "set nat destination rule " \
    | awk '{print $5}' \
    | sort -u
}

scan_nat_source_rules() {
  get_cfg_cmds \
    | grep -F "set nat source rule " \
    | awk '{print $5}' \
    | sort -u
}

scan_eth_ifaces() {
  get_cfg_cmds \
    | grep -F "set interfaces ethernet " \
    | awk '{print $4}' \
    | sort -u
}

scan_fw_zones() {
  get_cfg_cmds \
    | grep -F "set firewall zone " \
    | awk '{print $4}' \
    | sort -u
}

scan_zone_bindings() {
  get_cfg_cmds \
    | grep -F "set firewall zone " \
    | grep -F " from " \
    | grep -F " firewall name " \
    | awk '{print $4 "|" $6 "|" $9}' \
    | while IFS='|' read -r to from rs; do
        to="$(strip_quotes "$to")"
        from="$(strip_quotes "$from")"
        rs="$(strip_quotes "$rs")"
        echo "$to|$from|$rs"
      done \
    | sort -u
}

binding_exists() {
  local to="$1" from="$2"
  scan_zone_bindings | grep -F -q "${to}|${from}|"
}

binding_get_ruleset() {
  local to="$1" from="$2"
  scan_zone_bindings \
    | grep -F "${to}|${from}|" \
    | head -n 1 \
    | awk -F'|' '{print $3}'
}

# -----------------------------
# System: User + Hostname management
# -----------------------------
scan_login_users() {
  get_cfg_cmds \
    | grep -F "set system login user " \
    | awk '{print $5}' \
    | sort -u \
    | while read -r u; do strip_quotes "$u"; done
}

get_current_username() { (id -un 2>/dev/null || true) | tr -d '\n'; }

get_current_hostname() {
  local hn
  hn="$(run show configuration commands 2>/dev/null | grep -F "set system host-name " | head -n 1 | awk '{print $4}' || true)"
  hn="$(strip_quotes "$hn")"
  if [ -n "$hn" ]; then
    echo "$hn"
  else
    (hostname 2>/dev/null || true)
  fi
}

user_add_menu() {
  local u pw fn
  local existing=() exists_yn

  tprint ""
  tprint "You selected: ADD user"
  tprint "This will create: system login user <username> + password"
  tprint ""

  u="$(ask "Username (example: admin2)" "")"
  [ -z "$u" ] && return 0

  if ! is_valid_username "$u"; then
    tprint ""
    tprint "ERROR: Invalid username."
    tprint "Allowed: letters/numbers/_/./- (must start with letter or _), max 32 chars."
    pause
    return 0
  fi

  load_array existing scan_login_users
  if is_number_in_list "$u" "${existing[@]}"; then
    tprint ""
    tprint "ERROR: User already exists in config: $u"
    tprint "ADD will NOT overwrite existing users."
    tprint "Use REMOVE and then ADD if you really want to replace it."
    pause
    return 0
  fi

  fn="$(ask "Full name (optional)" "")"
  if [ -n "$fn" ] && ! is_safe_free_text "$fn"; then
    tprint ""
    tprint "ERROR: Full name has unsupported characters."
    pause
    return 0
  fi

  tread_secret pw "Password (input hidden): "
  if [ -z "$pw" ]; then
    tprint "Password required."
    pause
    return 0
  fi

  tprint ""
  tprint "SUMMARY:"
  tprint "  username: $u"
  [ -n "$fn" ] && tprint "  full-name: $fn"
  tprint "  password: (set)"
  tprint ""
  exists_yn="$(choose_yes_no "Proceed to create this user?" "y" || echo "n")"
  [ "$exists_yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  [ -n "$fn" ] && cfg_set system login user "$u" full-name "$fn"
  cfg_set system login user "$u" authentication plaintext-password "$pw"
  cfg_apply
}

user_remove_menu() {
  local users=() current target
  load_array users scan_login_users

  tprint ""
  tprint "You selected: REMOVE user"
  tprint "This will delete: system login user <username>"
  tprint ""

  require_nonempty_list_or_return "Configured login users" "${users[@]}" || return 0

  current="$(get_current_username)"
  [ -n "$current" ] && tprint "Current logged-in user: $current"

  if select_from_list "Select user to REMOVE" "${users[@]}"; then
    target="$SELECTED"
  else
    return 0
  fi

  if [ -n "$current" ] && [ "$target" = "$current" ]; then
    tprint ""
    tprint "ERROR: You cannot remove the user you are currently logged in as ($current)."
    tprint "Log in as a different admin user first, then remove this user."
    pause
    return 0
  fi

  tprint ""
  tprint "You are about to REMOVE user: $target"
  tprint "--------------------------------------------------------"
  (get_cfg_cmds | grep -F "set system login user '$target' " || true) >"$TTY"
  (get_cfg_cmds | grep -F "set system login user $target " || true) >>"$TTY"
  tprint "--------------------------------------------------------"
  tprint ""

  local yn
  yn="$(choose_yes_no "Proceed with delete?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_delete system login user "$target"
  cfg_apply
}

users_menu() {
  while true; do
    tprint ""
    tprint "===================="
    tprint " User Management Menu"
    tprint "===================="
    tprint "Users detected (from config):"
    local ulist=""
    ulist="$(scan_login_users | join_lines)"
    tprint "  ${ulist:-NONE}"
    tprint ""
    tprint "1) Add user"
    tprint "2) Remove user"
    tprint "3) Back"
    local c
    tread c "Select menu option #: "
    case "$c" in
      1) user_add_menu ;;
      2) user_remove_menu ;;
      3) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

hostname_menu() {
  local cur newhn yn
  tprint ""
  tprint "===================="
  tprint " Hostname Menu"
  tprint "===================="
  cur="$(get_current_hostname)"
  tprint "Current hostname: ${cur:-UNKNOWN}"
  tprint ""

  newhn="$(ask "New hostname (example: vyos-edge01)" "")"
  [ -z "$newhn" ] && return 0

  if ! is_valid_hostname "$newhn"; then
    tprint ""
    tprint "ERROR: Invalid hostname."
    tprint "Use letters/numbers and dashes; labels separated by dots; no underscores."
    pause
    return 0
  fi

  tprint ""
  tprint "You are setting system host-name to: $newhn"
  tprint ""
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set system host-name "$newhn"
  cfg_apply
}

system_menu() {
  while true; do
    tprint ""
    tprint "=================="
    tprint " System Menu"
    tprint "=================="
    tprint "1) User management (add/remove)"
    tprint "2) Change system hostname"
    tprint "3) Back"
    local c
    tread c "Select menu option #: "
    case "$c" in
      1) users_menu ;;
      2) hostname_menu ;;
      3) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# -----------------------------
# Firewall CRUD (rulesets + rules)
# -----------------------------
fw_choose_ruleset_existing_only() {
  local arr=()
  load_array arr scan_firewall_rulesets

  tprint ""
  tprint "You are selecting a FIREWALL RULESET (existing)."
  tprint "Examples: DMZ-to-LAN, WAN-to-DMZ, LAN-to-WAN"
  tprint ""

  require_nonempty_list_or_return "Firewall rulesets" "${arr[@]}" || return 1

  if select_from_list "Select WHICH ruleset to use" "${arr[@]}"; then
    echo "$SELECTED"
    return 0
  fi
  return 1
}

fw_choose_ruleset_or_new() {
  local arr=()
  load_array arr scan_firewall_rulesets

  tprint ""
  tprint "You are selecting a FIREWALL RULESET."
  tprint "Examples: DMZ-to-LAN, WAN-to-DMZ, LAN-to-WAN"
  tprint ""

  if [ "${#arr[@]}" -gt 0 ]; then
    if select_from_list "Select a ruleset to use" "${arr[@]}"; then
      echo "$SELECTED"
      return 0
    fi
  else
    tprint "No rulesets detected."
  fi

  tprint ""
  tprint "No selection made. Type a ruleset name to create/use."
  local rs
  rs="$(ask "Ruleset name (example: DMZ-to-LAN)" "")"
  [ -z "$rs" ] && return 1

  if ! is_safe_ruleset_name "$rs"; then
    tprint ""
    tprint "ERROR: Invalid ruleset name."
    tprint "Allowed: letters/numbers/_/./- (max 64)."
    pause
    return 1
  fi

  echo "$rs"
}

fw_choose_rule_number_existing() {
  local rs="$1"
  local arr=()
  load_array arr scan_firewall_rule_numbers "$rs"

  tprint ""
  tprint "You are selecting an EXISTING RULE NUMBER in: $rs"
  tprint ""

  require_nonempty_list_or_return "Firewall rules inside ruleset '$rs'" "${arr[@]}" || return 1

  if select_from_list "Select existing rule number" "${arr[@]}"; then
    echo "$SELECTED"
    return 0
  fi
  return 1
}

fw_choose_rule_number_new_only() {
  local rs="$1"
  local used=() suggested n
  load_array used scan_firewall_rule_numbers "$rs"

  tprint ""
  tprint "ADD MODE (SAFE): You are selecting a NEW RULE NUMBER in: $rs"
  tprint "Add will NOT overwrite existing numbers."
  tprint ""

  suggested="$(next_free_rule_number "${used[@]}")"
  tprint "Existing rule numbers: ${used[*]:-(none)}"
  tprint "Suggested next free rule number: $suggested"
  tprint ""

  while true; do
    n="$(ask "Rule number (new only)" "$suggested")"
    [ -z "$n" ] && tprint "Rule number required." && continue
    if ! require_numeric "$n"; then
      tprint "ERROR: must be a number (example: 10)."
      continue
    fi
    if is_number_in_list "$n" "${used[@]}"; then
      tprint "ERROR: rule $n already exists in $rs."
      tprint "Use Update/Delete to change existing rules."
      continue
    fi
    break
  done
  echo "$n"
}

fw_preview_rule() {
  local rs="$1" n="$2"
  tprint ""
  tprint "Current config lines for: firewall ipv4 name '$rs' rule $n"
  tprint "--------------------------------------------------------"
  (get_cfg_cmds | grep -F "set firewall ipv4 name '$rs' rule $n " || true) >"$TTY"
  (get_cfg_cmds | grep -F "set firewall ipv4 name $rs rule $n " || true) >>"$TTY"
  tprint "--------------------------------------------------------"
  tprint ""
}

fw_list_ruleset() {
  local rs
  tprint ""
  tprint "You selected: List ruleset"
  tprint "Next: choose WHICH ruleset to view."
  tprint ""

  rs="$(fw_choose_ruleset_existing_only)" || return 0

  tprint ""
  tprint "Showing commands for ruleset: $rs"
  tprint "--------------------------------------------------------"
  (get_cfg_cmds | grep -F "set firewall ipv4 name '$rs' " || true) >"$TTY"
  (get_cfg_cmds | grep -F "set firewall ipv4 name $rs " || true) >>"$TTY"
  tprint "--------------------------------------------------------"
  pause
}

fw_add_rule_guided_safe() {
  local rs n action proto desc saddr daddr sport dport state_est state_rel state_new
  local yn

  tprint ""
  tprint "You selected: ADD rule (SAFE - new only)"
  tprint "Next steps:"
  tprint "  1) Select a ruleset"
  tprint "  2) Select a NEW rule number (script suggests next free)"
  tprint "  3) Enter fields"
  tprint ""

  rs="$(fw_choose_ruleset_or_new)" || return 0
  n="$(fw_choose_rule_number_new_only "$rs")" || return 0

  tprint ""
  tprint "Now creating NEW rule: firewall ipv4 name '$rs' rule $n"
  tprint "Leave optional fields blank to skip."
  tprint ""

  action="$(choose_fw_action "accept")" || return 0
  proto="$(choose_fw_protocol "tcp")" || return 0

  desc="$(ask "Description (optional)" "")"
  [ -n "$desc" ] && ! is_safe_free_text "$desc" && { tprint "ERROR: Description has unsupported characters."; pause; return 0; }

  saddr="$(ask "Source address (optional) (example: 172.16.50.0/29)" "")"
  if [ -n "$saddr" ] && ! is_valid_cidr4 "$saddr" && ! is_valid_ipv4 "$saddr"; then
    tprint "ERROR: Source address must be IPv4 or IPv4/CIDR."
    pause
    return 0
  fi

  daddr="$(ask "Destination address (optional) (example: 172.16.200.10)" "")"
  if [ -n "$daddr" ] && ! is_valid_cidr4 "$daddr" && ! is_valid_ipv4 "$daddr"; then
    tprint "ERROR: Destination address must be IPv4 or IPv4/CIDR."
    pause
    return 0
  fi

  sport="$(ask "Source port (optional) (example: 443 or 1514-1515)" "")"
  if [ -n "$sport" ] && ! is_valid_port_or_range "$sport"; then
    tprint "ERROR: Source port must be 1-65535 or range like 1000-2000."
    pause
    return 0
  fi

  dport="$(ask "Destination port (optional) (example: 22 or 1514-1515)" "")"
  if [ -n "$dport" ] && ! is_valid_port_or_range "$dport"; then
    tprint "ERROR: Destination port must be 1-65535 or range like 1000-2000."
    pause
    return 0
  fi

  state_est="$(choose_yes_no "Match ESTABLISHED state?" "n" || echo "n")"
  state_rel="$(choose_yes_no "Match RELATED state?" "n" || echo "n")"
  state_new="$(choose_yes_no "Match NEW state?" "n" || echo "n")"

  tprint ""
  tprint "SUMMARY:"
  tprint "  ruleset: $rs"
  tprint "  rule: $n"
  tprint "  action: $action"
  [ -n "$proto" ] && tprint "  protocol: $proto"
  [ -n "$saddr" ] && tprint "  source address: $saddr"
  [ -n "$sport" ] && tprint "  source port: $sport"
  [ -n "$daddr" ] && tprint "  destination address: $daddr"
  [ -n "$dport" ] && tprint "  destination port: $dport"
  [ -n "$desc" ] && tprint "  description: $desc"
  tprint ""
  yn="$(choose_yes_no "Proceed to create this rule?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set firewall ipv4 name "$rs" rule "$n" action "$action"
  [ -n "$desc" ] && cfg_set firewall ipv4 name "$rs" rule "$n" description "$desc"

  if [ -n "$proto" ] && [ "$proto" != "any" ]; then
    cfg_set firewall ipv4 name "$rs" rule "$n" protocol "$proto"
  fi

  [ -n "$saddr" ] && cfg_set firewall ipv4 name "$rs" rule "$n" source address "$saddr"
  [ -n "$daddr" ] && cfg_set firewall ipv4 name "$rs" rule "$n" destination address "$daddr"
  [ -n "$sport" ] && cfg_set firewall ipv4 name "$rs" rule "$n" source port "$sport"
  [ -n "$dport" ] && cfg_set firewall ipv4 name "$rs" rule "$n" destination port "$dport"

  { [ "$state_est" = "y" ] || [ "$state_est" = "Y" ]; } && cfg_set firewall ipv4 name "$rs" rule "$n" state established
  { [ "$state_rel" = "y" ] || [ "$state_rel" = "Y" ]; } && cfg_set firewall ipv4 name "$rs" rule "$n" state related
  { [ "$state_new" = "y" ] || [ "$state_new" = "Y" ]; } && cfg_set firewall ipv4 name "$rs" rule "$n" state new

  cfg_apply
}

# -----------------------------
# FIX: Remove open-ended "Field path" updates.
# Now: strict list of supported fields only.
# -----------------------------
fw_update_single_field() {
  local rs n field val yn
  local fields=("action" "description" "protocol" "source address" "source port" "destination address" "destination port" "state established" "state related" "state new" "back")

  tprint ""
  tprint "You selected: Update ONE field (existing rule)"
  tprint "Next steps:"
  tprint "  1) Select a ruleset"
  tprint "  2) Select an EXISTING rule number"
  tprint "  3) Select the field to change (from a safe list)"
  tprint ""

  rs="$(fw_choose_ruleset_existing_only)" || return 0
  n="$(fw_choose_rule_number_existing "$rs")" || return 0
  fw_preview_rule "$rs" "$n"

  if ! select_from_list "Select field to update (safe list)" "${fields[@]}"; then
    return 0
  fi
  field="$SELECTED"
  [ "$field" = "back" ] && return 0

  case "$field" in
    action)
      val="$(choose_fw_action "accept")" || return 0
      cfg_begin || return 0
      cfg_set firewall ipv4 name "$rs" rule "$n" action "$val"
      cfg_apply
      ;;
    protocol)
      val="$(choose_fw_protocol "tcp")" || return 0
      cfg_begin || return 0
      if [ "$val" = "any" ]; then
        cfg_delete firewall ipv4 name "$rs" rule "$n" protocol
      else
        cfg_set firewall ipv4 name "$rs" rule "$n" protocol "$val"
      fi
      cfg_apply
      ;;
    description)
      tprint ""
      tprint "Leave blank to DELETE the description."
      val="$(ask "New description" "")"
      if [ -n "$val" ] && ! is_safe_free_text "$val"; then
        tprint "ERROR: Description has unsupported characters."
        pause
        return 0
      fi
      cfg_begin || return 0
      if [ -z "$val" ]; then
        cfg_delete firewall ipv4 name "$rs" rule "$n" description
      else
        cfg_set firewall ipv4 name "$rs" rule "$n" description "$val"
      fi
      cfg_apply
      ;;
    "source address"|"destination address")
      tprint ""
      tprint "Leave blank to DELETE the address match."
      val="$(ask "New IPv4 or IPv4/CIDR" "")"
      if [ -n "$val" ] && ! is_valid_ipv4 "$val" && ! is_valid_cidr4 "$val"; then
        tprint "ERROR: Must be IPv4 or IPv4/CIDR."
        pause
        return 0
      fi
      cfg_begin || return 0
      if [ -z "$val" ]; then
        if [ "$field" = "source address" ]; then
          cfg_delete firewall ipv4 name "$rs" rule "$n" source address
        else
          cfg_delete firewall ipv4 name "$rs" rule "$n" destination address
        fi
      else
        if [ "$field" = "source address" ]; then
          cfg_set firewall ipv4 name "$rs" rule "$n" source address "$val"
        else
          cfg_set firewall ipv4 name "$rs" rule "$n" destination address "$val"
        fi
      fi
      cfg_apply
      ;;
    "source port"|"destination port")
      tprint ""
      tprint "Leave blank to DELETE the port match."
      val="$(ask "New port or range (example: 22 or 1514-1515)" "")"
      if [ -n "$val" ] && ! is_valid_port_or_range "$val"; then
        tprint "ERROR: Must be 1-65535 or range like 1000-2000."
        pause
        return 0
      fi
      cfg_begin || return 0
      if [ -z "$val" ]; then
        if [ "$field" = "source port" ]; then
          cfg_delete firewall ipv4 name "$rs" rule "$n" source port
        else
          cfg_delete firewall ipv4 name "$rs" rule "$n" destination port
        fi
      else
        if [ "$field" = "source port" ]; then
          cfg_set firewall ipv4 name "$rs" rule "$n" source port "$val"
        else
          cfg_set firewall ipv4 name "$rs" rule "$n" destination port "$val"
        fi
      fi
      cfg_apply
      ;;
    "state established"|"state related"|"state new")
      yn="$(choose_yes_no "Set this state match ON?" "y" || echo "n")"
      cfg_begin || return 0
      if [ "$yn" = "y" ]; then
        case "$field" in
          "state established") cfg_set firewall ipv4 name "$rs" rule "$n" state established ;;
          "state related")     cfg_set firewall ipv4 name "$rs" rule "$n" state related ;;
          "state new")         cfg_set firewall ipv4 name "$rs" rule "$n" state new ;;
        esac
      else
        case "$field" in
          "state established") cfg_delete firewall ipv4 name "$rs" rule "$n" state established ;;
          "state related")     cfg_delete firewall ipv4 name "$rs" rule "$n" state related ;;
          "state new")         cfg_delete firewall ipv4 name "$rs" rule "$n" state new ;;
        esac
      fi
      cfg_apply
      ;;
    *)
      tprint "Invalid."
      pause
      ;;
  esac
}

fw_delete_rule() {
  local rs n yn

  tprint ""
  tprint "You selected: Delete existing rule"
  tprint "Next steps:"
  tprint "  1) Select a ruleset"
  tprint "  2) Select an EXISTING rule number to delete"
  tprint ""

  rs="$(fw_choose_ruleset_existing_only)" || return 0
  n="$(fw_choose_rule_number_existing "$rs")" || return 0
  fw_preview_rule "$rs" "$n"

  yn="$(choose_yes_no "Proceed with delete?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_delete firewall ipv4 name "$rs" rule "$n"
  cfg_apply
}

# -----------------------------
# Zone-based firewall bindings (A)
# -----------------------------
zone_choose_existing() {
  local zones=()
  load_array zones scan_fw_zones

  tprint ""
  tprint "You are selecting a FIREWALL ZONE (existing)."
  tprint "Examples: LAN, WAN, DMZ, MGMT"
  tprint ""

  require_nonempty_list_or_return "Firewall zones" "${zones[@]}" || return 1

  if select_from_list "Select a zone" "${zones[@]}"; then
    echo "$SELECTED"
    return 0
  fi
  return 1
}

zone_binding_preview() {
  local to="$1" from="$2"
  tprint ""
  tprint "Binding preview: TO='$to' <- FROM='$from'"
  tprint "--------------------------------------------------------"
  (get_cfg_cmds | grep -F "set firewall zone $to from $from firewall name " || true) >"$TTY"
  tprint "--------------------------------------------------------"
  tprint ""
}

zone_list_bindings() {
  tprint ""
  tprint "You selected: List zone bindings"
  tprint "Current zone bindings (TO <- FROM = RULESET):"
  tprint ""

  local b=()
  load_array b scan_zone_bindings
  if [ "${#b[@]}" -eq 0 ]; then
    tprint "(none found)"
    pause
    return 0
  fi

  printf "%s\n" "${b[@]}" | awk -F'|' '{printf "  %s <- %s   =   %s\n",$1,$2,$3}' >"$TTY"
  pause
}

zone_add_binding_safe() {
  local to from ruleset existing_rs yn

  tprint ""
  tprint "You selected: ADD zone binding (SAFE - will not overwrite)"
  tprint "This attaches a ruleset to a zone direction:"
  tprint "  TO-ZONE  <-  FROM-ZONE"
  tprint ""

  to="$(zone_choose_existing)" || return 0
  from="$(zone_choose_existing)" || return 0

  if [ "$to" = "$from" ]; then
    tprint ""
    tprint "ERROR: TO and FROM cannot be the same zone."
    pause
    return 0
  fi

  if binding_exists "$to" "$from"; then
    existing_rs="$(binding_get_ruleset "$to" "$from")"
    tprint ""
    tprint "ERROR: Binding already exists:"
    tprint "  $to <- $from  =  ${existing_rs:-UNKNOWN}"
    tprint ""
    tprint "Add mode will NOT overwrite."
    tprint "Use Update/Delete in Zone Bindings menu."
    pause
    return 0
  fi

  ruleset="$(fw_choose_ruleset_existing_only)" || return 0

  tprint ""
  tprint "SUMMARY (new zone binding):"
  tprint "  TO:      $to"
  tprint "  FROM:    $from"
  tprint "  RULESET: $ruleset"
  tprint ""
  yn="$(choose_yes_no "Proceed to create this binding?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set firewall zone "$to" from "$from" firewall name "$ruleset"
  cfg_apply
}

zone_update_binding_existing() {
  local to from ruleset existing_rs yn

  tprint ""
  tprint "You selected: UPDATE zone binding (existing only)"
  tprint "This changes which ruleset is attached to:"
  tprint "  TO-ZONE <- FROM-ZONE"
  tprint ""

  to="$(zone_choose_existing)" || return 0
  from="$(zone_choose_existing)" || return 0

  if ! binding_exists "$to" "$from"; then
    tprint ""
    tprint "ERROR: No existing binding for:"
    tprint "  $to <- $from"
    tprint ""
    tprint "Use ADD if you want to create it."
    pause
    return 0
  fi

  existing_rs="$(binding_get_ruleset "$to" "$from")"
  tprint ""
  tprint "Current ruleset for $to <- $from : ${existing_rs:-UNKNOWN}"
  zone_binding_preview "$to" "$from"

  ruleset="$(fw_choose_ruleset_existing_only)" || return 0

  tprint ""
  tprint "SUMMARY (update binding):"
  tprint "  TO:      $to"
  tprint "  FROM:    $from"
  tprint "  OLD:     ${existing_rs:-UNKNOWN}"
  tprint "  NEW:     $ruleset"
  tprint ""
  yn="$(choose_yes_no "Proceed with update?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set firewall zone "$to" from "$from" firewall name "$ruleset"
  cfg_apply
}

zone_delete_binding_existing() {
  local to from existing_rs yn

  tprint ""
  tprint "You selected: DELETE zone binding (existing only)"
  tprint ""

  to="$(zone_choose_existing)" || return 0
  from="$(zone_choose_existing)" || return 0

  if ! binding_exists "$to" "$from"; then
    tprint ""
    tprint "ERROR: No existing binding for:"
    tprint "  $to <- $from"
    pause
    return 0
  fi

  existing_rs="$(binding_get_ruleset "$to" "$from")"
  tprint ""
  tprint "You are deleting:"
  tprint "  $to <- $from  =  ${existing_rs:-UNKNOWN}"
  zone_binding_preview "$to" "$from"

  yn="$(choose_yes_no "Proceed with delete?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_delete firewall zone "$to" from "$from" firewall name
  cfg_apply
}

zone_bindings_menu() {
  while true; do
    tprint ""
    tprint "=============================="
    tprint " Zone Firewall Bindings (A)"
    tprint "=============================="
    show_detected_summary
    tprint "What this does:"
    tprint "  Attach a ruleset to: TO-ZONE <- FROM-ZONE"
    tprint ""
    tprint "SAFE RULES:"
    tprint "  - ADD will NOT overwrite existing bindings."
    tprint "  - Update/Delete only work on EXISTING bindings."
    tprint ""
    tprint "1) List bindings (TO <- FROM = RULESET)"
    tprint "2) ADD binding (SAFE - new only)"
    tprint "3) UPDATE binding (existing only)"
    tprint "4) DELETE binding (existing only)"
    tprint "5) Back"
    local c
    tread c "Select menu option #: "
    case "$c" in
      1) zone_list_bindings ;;
      2) zone_add_binding_safe ;;
      3) zone_update_binding_existing ;;
      4) zone_delete_binding_existing ;;
      5) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

firewall_menu() {
  while true; do
    tprint ""
    tprint "========================"
    tprint " Firewall Menu (Dynamic)"
    tprint "========================"
    show_detected_summary
    tprint "SAFE RULES:"
    tprint "  - ADD will NOT overwrite existing rule numbers."
    tprint "  - Update/Delete only work on EXISTING rules."
    tprint ""
    tprint "1) List ruleset (show commands)"
    tprint "2) ADD rule (SAFE - new only)"
    tprint "3) Update ONE field in an existing rule (SAFE list)"
    tprint "4) Delete existing rule"
    tprint "5) Zone bindings (A: zone-based attach rulesets)"
    tprint "6) Back"
    local c
    tread c "Select menu option #: "
    case "$c" in
      1) fw_list_ruleset ;;
      2) fw_add_rule_guided_safe ;;
      3) fw_update_single_field ;;
      4) fw_delete_rule ;;
      5) zone_bindings_menu ;;
      6) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# -----------------------------
# NAT CRUD
# -----------------------------
nat_list() {
  tprint ""
  tprint "You selected: List NAT"
  tprint "Showing NAT commands (current config):"
  tprint ""
  (get_cfg_cmds | grep -F "set nat " || true) >"$TTY"
  pause
}

nat_choose_type() {
  local t
  t="$(choose_nat_type "destination" || true)"
  case "$t" in
    destination|source) echo "$t" ;;
    *) echo "" ;;
  esac
}

nat_choose_rule_number_existing() {
  local type="$1"
  local arr=()

  if [ "$type" = "destination" ]; then
    load_array arr scan_nat_dest_rules
  else
    load_array arr scan_nat_source_rules
  fi

  tprint ""
  tprint "You are selecting an EXISTING NAT RULE NUMBER (type: $type)"
  tprint ""

  require_nonempty_list_or_return "NAT $type rules" "${arr[@]}" || return 1

  if select_from_list "Select existing NAT rule number" "${arr[@]}"; then
    echo "$SELECTED"
    return 0
  fi
  return 1
}

nat_preview_rule() {
  local type="$1" n="$2"
  tprint ""
  tprint "Current config lines for: nat $type rule $n"
  tprint "--------------------------------------------------------"
  (get_cfg_cmds | grep -F "set nat $type rule $n " || true) >"$TTY"
  tprint "--------------------------------------------------------"
  tprint ""
}

nat_add_dnat_guided() {
  local n desc inif proto dport taddr tport
  local used=() suggested
  local ifs=()
  local yn

  tprint ""
  tprint "You selected: Add DNAT rule (SAFE - new only)"
  tprint "Next steps:"
  tprint "  1) Choose a NEW rule number (script suggests next free)"
  tprint "  2) Pick inbound interface"
  tprint "  3) Enter ports + translation"
  tprint ""

  load_array used scan_nat_dest_rules

  suggested="$(next_free_rule_number "${used[@]}")"
  tprint "Existing DNAT rule numbers: ${used[*]:-(none)}"
  tprint "Suggested next free rule number: $suggested"
  tprint ""

  while true; do
    n="$(ask "DNAT rule number (new only)" "$suggested")"
    [ -z "$n" ] && tprint "Rule number required." && continue
    if ! require_numeric "$n"; then
      tprint "ERROR: must be a number (example: 10)."
      continue
    fi
    if is_number_in_list "$n" "${used[@]}"; then
      tprint "ERROR: rule $n already exists. Add mode will NOT overwrite."
      tprint "Use Update/Delete to change existing rules."
      continue
    fi
    break
  done

  desc="$(ask "Description (example: HTTP -> DMZ)" "DNAT")"
  [ -n "$desc" ] && ! is_safe_free_text "$desc" && { tprint "ERROR: Description has unsupported characters."; pause; return 0; }

  load_array ifs scan_eth_ifaces
  require_nonempty_list_or_return "Ethernet interfaces (for inbound)" "${ifs[@]}" || return 0

  if select_from_list "Select inbound interface (usually WAN like eth0)" "${ifs[@]}"; then
    inif="$SELECTED"
  else
    return 0
  fi

  proto="$(choose_tcp_udp "tcp")" || return 0

  dport="$(ask "Public port (example: 80)" "80")"
  if ! is_valid_port_or_range "$dport"; then
    tprint "ERROR: Public port must be 1-65535 (or range)."
    pause
    return 0
  fi

  taddr="$(ask "Inside IP (example: 172.16.50.3)" "172.16.50.3")"
  if ! is_valid_ipv4 "$taddr"; then
    tprint "ERROR: Inside IP must be valid IPv4."
    pause
    return 0
  fi

  tport="$(ask "Inside port (example: 80)" "80")"
  if ! is_valid_port_or_range "$tport"; then
    tprint "ERROR: Inside port must be 1-65535 (or range)."
    pause
    return 0
  fi

  tprint ""
  tprint "SUMMARY (DNAT rule $n):"
  tprint "  description: $desc"
  tprint "  inbound-interface: $inif"
  tprint "  protocol: $proto"
  tprint "  public port: $dport"
  tprint "  translation: $taddr:$tport"
  tprint ""
  yn="$(choose_yes_no "Proceed to create this DNAT rule?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set nat destination rule "$n" description "$desc"
  cfg_set nat destination rule "$n" inbound-interface name "$inif"
  cfg_set nat destination rule "$n" protocol "$proto"
  cfg_set nat destination rule "$n" destination port "$dport"
  cfg_set nat destination rule "$n" translation address "$taddr"
  cfg_set nat destination rule "$n" translation port "$tport"
  cfg_apply
}

# -----------------------------
# FIX: Remove open-ended NAT "Field path" updates.
# Now: strict list of supported fields only.
# -----------------------------
nat_update_single_field() {
  local type n field val yn
  local fields=("description" "protocol" "destination port" "inbound-interface name" "outbound-interface name" "source address" "translation address" "translation port" "back")

  tprint ""
  tprint "You selected: Update ONE field in an existing NAT rule"
  tprint ""

  type="$(nat_choose_type)"
  [ -z "$type" ] && return 0
  n="$(nat_choose_rule_number_existing "$type")" || return 0

  nat_preview_rule "$type" "$n"

  if ! select_from_list "Select field to update (safe list)" "${fields[@]}"; then
    return 0
  fi
  field="$SELECTED"
  [ "$field" = "back" ] && return 0

  case "$field" in
    description)
      tprint ""
      tprint "Leave blank to DELETE the description."
      val="$(ask "New description" "")"
      if [ -n "$val" ] && ! is_safe_free_text "$val"; then
        tprint "ERROR: Description has unsupported characters."
        pause
        return 0
      fi
      cfg_begin || return 0
      if [ -z "$val" ]; then
        cfg_delete nat "$type" rule "$n" description
      else
        cfg_set nat "$type" rule "$n" description "$val"
      fi
      cfg_apply
      ;;
    protocol)
      val="$(choose_fw_protocol "tcp")" || return 0
      cfg_begin || return 0
      if [ "$val" = "any" ]; then
        cfg_delete nat "$type" rule "$n" protocol
      else
        cfg_set nat "$type" rule "$n" protocol "$val"
      fi
      cfg_apply
      ;;
    "destination port"|"translation port")
      tprint ""
      tprint "Leave blank to DELETE."
      val="$(ask "New port or range (example: 80 or 1000-2000)" "")"
      if [ -n "$val" ] && ! is_valid_port_or_range "$val"; then
        tprint "ERROR: Must be 1-65535 or range like 1000-2000."
        pause
        return 0
      fi
      cfg_begin || return 0
      if [ -z "$val" ]; then
        if [ "$field" = "destination port" ]; then
          cfg_delete nat "$type" rule "$n" destination port
        else
          cfg_delete nat "$type" rule "$n" translation port
        fi
      else
        if [ "$field" = "destination port" ]; then
          cfg_set nat "$type" rule "$n" destination port "$val"
        else
          cfg_set nat "$type" rule "$n" translation port "$val"
        fi
      fi
      cfg_apply
      ;;
    "translation address"|"source address")
      tprint ""
      tprint "Leave blank to DELETE."
      val="$(ask "New IPv4 or IPv4/CIDR" "")"
      if [ -n "$val" ] && ! is_valid_ipv4 "$val" && ! is_valid_cidr4 "$val"; then
        tprint "ERROR: Must be IPv4 or IPv4/CIDR."
        pause
        return 0
      fi
      cfg_begin || return 0
      if [ -z "$val" ]; then
        if [ "$field" = "translation address" ]; then
          cfg_delete nat "$type" rule "$n" translation address
        else
          cfg_delete nat "$type" rule "$n" source address
        fi
      else
        if [ "$field" = "translation address" ]; then
          cfg_set nat "$type" rule "$n" translation address "$val"
        else
          cfg_set nat "$type" rule "$n" source address "$val"
        fi
      fi
      cfg_apply
      ;;
    "inbound-interface name"|"outbound-interface name")
      tprint ""
      tprint "Leave blank to DELETE."
      val="$(ask "Interface name (example: eth0)" "")"
      if [ -n "$val" ] && ! is_safe_iface_name "$val"; then
        tprint "ERROR: Invalid interface name."
        pause
        return 0
      fi
      cfg_begin || return 0
      if [ -z "$val" ]; then
        if [ "$field" = "inbound-interface name" ]; then
          cfg_delete nat "$type" rule "$n" inbound-interface name
        else
          cfg_delete nat "$type" rule "$n" outbound-interface name
        fi
      else
        if [ "$field" = "inbound-interface name" ]; then
          cfg_set nat "$type" rule "$n" inbound-interface name "$val"
        else
          cfg_set nat "$type" rule "$n" outbound-interface name "$val"
        fi
      fi
      cfg_apply
      ;;
    *)
      tprint "Invalid."
      pause
      ;;
  esac
}

nat_delete_rule() {
  local type n yn

  tprint ""
  tprint "You selected: Delete existing NAT rule"
  tprint ""

  type="$(nat_choose_type)"
  [ -z "$type" ] && return 0
  n="$(nat_choose_rule_number_existing "$type")" || return 0

  nat_preview_rule "$type" "$n"
  yn="$(choose_yes_no "Proceed with delete?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_delete nat "$type" rule "$n"
  cfg_apply
}

nat_menu() {
  while true; do
    tprint ""
    tprint "=================="
    tprint " NAT Menu (Dynamic)"
    tprint "=================="
    show_detected_summary
    tprint "SAFE RULES:"
    tprint "  - ADD DNAT will NOT overwrite existing rule numbers."
    tprint "  - Update/Delete only work on EXISTING rules."
    tprint ""
    tprint "1) List NAT (show commands)"
    tprint "2) Add DNAT rule (SAFE - new only)"
    tprint "3) Update ONE field in an existing NAT rule (SAFE list)"
    tprint "4) Delete existing NAT rule"
    tprint "5) Back"
    local c
    tread c "Select menu option #: "
    case "$c" in
      1) nat_list ;;
      2) nat_add_dnat_guided ;;
      3) nat_update_single_field ;;
      4) nat_delete_rule ;;
      5) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# -----------------------------
# Interfaces
# -----------------------------
iface_set_ip() {
  local ifs=() iface ip desc yn

  load_array ifs scan_eth_ifaces

  tprint ""
  tprint "You selected: Set interface IP + description"
  tprint "Next steps:"
  tprint "  1) Choose an interface"
  tprint "  2) Enter a CIDR address"
  tprint "  3) Optional description"
  tprint ""

  require_nonempty_list_or_return "Ethernet interfaces" "${ifs[@]}" || return 0

  if select_from_list "Select interface to configure" "${ifs[@]}"; then
    iface="$SELECTED"
  else
    return 0
  fi

  ip="$(ask "New address (CIDR) (example: 172.16.50.2/29)" "")"
  [ -z "$ip" ] && return 0
  if ! is_valid_cidr4 "$ip"; then
    tprint "ERROR: Address must be IPv4/CIDR like 192.168.1.1/24."
    pause
    return 0
  fi

  desc="$(ask "Description (optional) (example: Hamed-DMZ)" "")"
  if [ -n "$desc" ] && ! is_safe_free_text "$desc"; then
    tprint "ERROR: Description has unsupported characters."
    pause
    return 0
  fi

  tprint ""
  tprint "SUMMARY:"
  tprint "  interface: $iface"
  tprint "  address: $ip"
  [ -n "$desc" ] && tprint "  description: $desc"
  tprint ""
  yn="$(choose_yes_no "Proceed with interface update?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set interfaces ethernet "$iface" address "$ip"
  [ -n "$desc" ] && cfg_set interfaces ethernet "$iface" description "$desc"
  cfg_apply
}

iface_show() {
  tprint ""
  tprint "You selected: Show interfaces"
  tprint ""
  run show interfaces >"$TTY"
  tprint ""
  pause
}

iface_menu() {
  while true; do
    tprint ""
    tprint "========================"
    tprint " Interfaces Menu (Dynamic)"
    tprint "========================"
    show_detected_summary
    tprint "1) Set interface IP + description"
    tprint "2) Show interfaces"
    tprint "3) Back"
    local c
    tread c "Select menu option #: "
    case "$c" in
      1) iface_set_ip ;;
      2) iface_show ;;
      3) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# DNS Forwarding (FIXED per your screenshots)
# ============================================================
scan_dns_allow_from() {
  get_cfg_cmds \
    | grep -F "set service dns forwarding allow-from " \
    | awk '{print $6}' \
    | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

scan_dns_listen_address() {
  get_cfg_cmds \
    | grep -F "set service dns forwarding listen-address " \
    | awk '{print $6}' \
    | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

dns_system_is_enabled() {
  if get_cfg_cmds | grep -F -q "set service dns forwarding system"; then
    return 0
  fi
  return 1
}

dns_show_current() {
  local af la sys
  af="$(scan_dns_allow_from | join_lines)"
  la="$(scan_dns_listen_address | join_lines)"
  if dns_system_is_enabled; then
    sys="ENABLED"
  else
    sys="DISABLED"
  fi

  tprint ""
  tprint "DNS Forwarding status:"
  tprint "  allow-from:     ${af:-NONE}"
  tprint "  listen-address: ${la:-NONE}"
  tprint "  system:         $sys"
  tprint ""
}

dns_list_config() {
  tprint ""
  tprint "You selected: List DNS forwarding config"
  tprint ""
  dns_show_current
  tprint "Commands:"
  tprint "--------------------------------------------------------"
  (get_cfg_cmds | grep -F "set service dns forwarding " || true) >"$TTY"
  tprint "--------------------------------------------------------"
  pause
}

dns_add_allow_from_safe() {
  local current_af=() current_la=()
  local new_af la_needed yn

  load_array current_af scan_dns_allow_from
  load_array current_la scan_dns_listen_address

  tprint ""
  tprint "ADD allow-from (SAFE - will not duplicate)"
  tprint "Current allow-from entries:"
  tprint "  ${current_af[*]:-(none)}"
  tprint ""

  new_af="$(ask "New allow-from subnet (CIDR) (example: 10.0.66.0/28)" "")"
  [ -z "$new_af" ] && return 0
  if ! is_valid_cidr4 "$new_af"; then
    tprint "ERROR: allow-from must be IPv4/CIDR like 10.0.0.0/24."
    pause
    return 0
  fi

  if is_number_in_list "$new_af" "${current_af[@]}"; then
    tprint ""
    tprint "ERROR: allow-from already exists: $new_af"
    pause
    return 0
  fi

  if [ "${#current_la[@]}" -eq 0 ]; then
    tprint ""
    tprint "IMPORTANT:"
    tprint "  DNS forwarding commit will FAIL unless BOTH exist:"
    tprint "    - allow-from"
    tprint "    - listen-address"
    tprint ""
    tprint "Right now listen-address is missing, so we must add it now."
    tprint ""
    la_needed="$(ask "Listen-address IP to add now (example: 10.0.66.2)" "")"
    [ -z "$la_needed" ] && return 0
    if ! is_valid_ipv4 "$la_needed"; then
      tprint "ERROR: listen-address must be valid IPv4."
      pause
      return 0
    fi
  fi

  tprint ""
  tprint "SUMMARY:"
  tprint "  add allow-from: $new_af"
  [ -n "${la_needed:-}" ] && tprint "  add listen-address (required): $la_needed"
  tprint ""
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set service dns forwarding allow-from "$new_af"
  [ -n "${la_needed:-}" ] && cfg_set service dns forwarding listen-address "$la_needed"
  cfg_apply
}

dns_delete_allow_from_existing() {
  local current_af=() current_la=() target
  local la_count af_count yn

  load_array current_af scan_dns_allow_from
  load_array current_la scan_dns_listen_address

  tprint ""
  tprint "DELETE allow-from (existing)"
  tprint ""

  require_nonempty_list_or_return "DNS allow-from entries" "${current_af[@]}" || return 0

  if select_from_list "Select allow-from to DELETE" "${current_af[@]}"; then
    target="$SELECTED"
  else
    return 0
  fi

  af_count="${#current_af[@]}"
  la_count="${#current_la[@]}"

  if [ "$af_count" -le 1 ] && { [ "$la_count" -ge 1 ] || dns_system_is_enabled; }; then
    tprint ""
    tprint "BLOCKED (prevents commit failure):"
    tprint "  You cannot delete the LAST allow-from while listen-address exists"
    tprint "  or while DNS system forwarding is enabled."
    tprint ""
    tprint "Fix options:"
    tprint "  - Add another allow-from first, OR"
    tprint "  - Delete ALL listen-address entries first, AND disable system if enabled."
    pause
    return 0
  fi

  yn="$(choose_yes_no "Delete allow-from: $target ?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_delete service dns forwarding allow-from "$target"
  cfg_apply
}

dns_add_listen_address_safe() {
  local current_af=() current_la=()
  local new_la af_needed yn

  load_array current_af scan_dns_allow_from
  load_array current_la scan_dns_listen_address

  tprint ""
  tprint "ADD listen-address (SAFE - will not duplicate)"
  tprint "Current listen-address entries:"
  tprint "  ${current_la[*]:-(none)}"
  tprint ""

  new_la="$(ask "New listen-address IP (example: 10.0.66.2)" "")"
  [ -z "$new_la" ] && return 0
  if ! is_valid_ipv4 "$new_la"; then
    tprint "ERROR: listen-address must be valid IPv4."
    pause
    return 0
  fi

  if is_number_in_list "$new_la" "${current_la[@]}"; then
    tprint ""
    tprint "ERROR: listen-address already exists: $new_la"
    pause
    return 0
  fi

  if [ "${#current_af[@]}" -eq 0 ]; then
    tprint ""
    tprint "IMPORTANT:"
    tprint "  DNS forwarding commit will FAIL unless BOTH exist:"
    tprint "    - allow-from"
    tprint "    - listen-address"
    tprint ""
    tprint "Right now allow-from is missing, so we must add it now."
    tprint ""
    af_needed="$(ask "Allow-from subnet (CIDR) to add now (example: 10.0.66.0/28)" "")"
    [ -z "$af_needed" ] && return 0
    if ! is_valid_cidr4 "$af_needed"; then
      tprint "ERROR: allow-from must be IPv4/CIDR."
      pause
      return 0
    fi
  fi

  tprint ""
  tprint "SUMMARY:"
  tprint "  add listen-address: $new_la"
  [ -n "${af_needed:-}" ] && tprint "  add allow-from (required): $af_needed"
  tprint ""
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set service dns forwarding listen-address "$new_la"
  [ -n "${af_needed:-}" ] && cfg_set service dns forwarding allow-from "$af_needed"
  cfg_apply
}

dns_delete_listen_address_existing() {
  local current_af=() current_la=() target
  local la_count af_count yn

  load_array current_af scan_dns_allow_from
  load_array current_la scan_dns_listen_address

  tprint ""
  tprint "DELETE listen-address (existing)"
  tprint ""

  require_nonempty_list_or_return "DNS listen-address entries" "${current_la[@]}" || return 0

  if select_from_list "Select listen-address to DELETE" "${current_la[@]}"; then
    target="$SELECTED"
  else
    return 0
  fi

  af_count="${#current_af[@]}"
  la_count="${#current_la[@]}"

  if [ "$la_count" -le 1 ] && { [ "$af_count" -ge 1 ] || dns_system_is_enabled; }; then
    tprint ""
    tprint "BLOCKED (prevents commit failure):"
    tprint "  You cannot delete the LAST listen-address while allow-from exists"
    tprint "  or while DNS system forwarding is enabled."
    tprint ""
    tprint "Fix options:"
    tprint "  - Add another listen-address first, OR"
    tprint "  - Delete ALL allow-from entries first, AND disable system if enabled."
    pause
    return 0
  fi

  yn="$(choose_yes_no "Delete listen-address: $target ?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_delete service dns forwarding listen-address "$target"
  cfg_apply
}

dns_system_forwarding_toggle() {
  local current_af=() current_la=()
  local yn

  load_array current_af scan_dns_allow_from
  load_array current_la scan_dns_listen_address

  tprint ""
  if dns_system_is_enabled; then
    tprint "DNS system forwarding is currently: ENABLED"
  else
    tprint "DNS system forwarding is currently: DISABLED"
  fi
  tprint "This controls: set service dns forwarding system"
  tprint ""

  if dns_system_is_enabled; then
    yn="$(choose_yes_no "Disable DNS system forwarding now?" "y" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

    cfg_begin || return 0
    cfg_delete service dns forwarding system
    cfg_apply
    return 0
  fi

  if [ "${#current_la[@]}" -eq 0 ] || [ "${#current_af[@]}" -eq 0 ]; then
    tprint ""
    tprint "CANNOT ENABLE (would fail commit):"
    [ "${#current_la[@]}" -eq 0 ] && tprint "  - Missing listen-address"
    [ "${#current_af[@]}" -eq 0 ] && tprint "  - Missing allow-from"
    tprint ""
    pause
    return 0
  fi

  yn="$(choose_yes_no "Enable DNS system forwarding now?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set service dns forwarding system
  cfg_apply
}

dns_forwarding_menu() {
  while true; do
    tprint ""
    tprint "=============================="
    tprint " DNS Forwarding Submenu"
    tprint "=============================="
    dns_show_current
    tprint "1) List DNS forwarding config"
    tprint "2) Add allow-from (SAFE)"
    tprint "3) Delete allow-from (existing)"
    tprint "4) Add listen-address (SAFE)"
    tprint "5) Delete listen-address (existing)"
    tprint "6) DNS system forwarding (enable/disable)"
    tprint "7) Back"
    local c
    tread c "Select menu option #: "
    case "$c" in
      1) dns_list_config ;;
      2) dns_add_allow_from_safe ;;
      3) dns_delete_allow_from_existing ;;
      4) dns_add_listen_address_safe ;;
      5) dns_delete_listen_address_existing ;;
      6) dns_system_forwarding_toggle ;;
      7) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# RIP Submenu (separate from DNS as requested)
# ============================================================
scan_rip_interfaces() {
  get_cfg_cmds \
    | grep -F "set protocols rip interface " \
    | awk '{print $5}' \
    | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

scan_rip_networks() {
  get_cfg_cmds \
    | grep -F "set protocols rip network " \
    | awk '{print $5}' \
    | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

rip_list_config() {
  tprint ""
  tprint "You selected: List RIP config"
  tprint ""
  tprint "Interfaces: $(scan_rip_interfaces | join_lines)"
  tprint "Networks:   $(scan_rip_networks | join_lines)"
  tprint ""
  tprint "Commands:"
  tprint "--------------------------------------------------------"
  (get_cfg_cmds | grep -F "set protocols rip " || true) >"$TTY"
  tprint "--------------------------------------------------------"
  pause
}

rip_add_interface_safe() {
  local current=() ifs=() iface yn
  load_array current scan_rip_interfaces
  load_array ifs scan_eth_ifaces

  tprint ""
  tprint "ADD RIP interface (SAFE - will not duplicate)"
  tprint "Current RIP interfaces: ${current[*]:-(none)}"
  tprint ""

  if [ "${#ifs[@]}" -gt 0 ]; then
    if select_from_list "Select interface (detected ethernet)" "${ifs[@]}"; then
      iface="$SELECTED"
    else
      iface="$(ask "Interface name (example: eth0)" "")"
    fi
  else
    iface="$(ask "Interface name (example: eth0)" "")"
  fi
  [ -z "$iface" ] && return 0
  if ! is_safe_iface_name "$iface"; then
    tprint "ERROR: Invalid interface name."
    pause
    return 0
  fi

  if is_number_in_list "$iface" "${current[@]}"; then
    tprint ""
    tprint "ERROR: RIP interface already exists: $iface"
    pause
    return 0
  fi

  tprint ""
  tprint "SUMMARY:"
  tprint "  add RIP interface: $iface"
  tprint ""
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set protocols rip interface "$iface"
  cfg_apply
}

rip_delete_interface_existing() {
  local current=() target yn
  load_array current scan_rip_interfaces

  tprint ""
  tprint "DELETE RIP interface (existing)"
  tprint ""

  require_nonempty_list_or_return "RIP interfaces" "${current[@]}" || return 0

  if select_from_list "Select RIP interface to DELETE" "${current[@]}"; then
    target="$SELECTED"
  else
    return 0
  fi

  yn="$(choose_yes_no "Delete RIP interface: $target ?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_delete protocols rip interface "$target"
  cfg_apply
}

rip_add_network_safe() {
  local current=() net yn
  load_array current scan_rip_networks

  tprint ""
  tprint "ADD RIP network (SAFE - will not duplicate)"
  tprint "Current RIP networks: ${current[*]:-(none)}"
  tprint ""

  net="$(ask "Network to advertise (CIDR) (example: 10.0.66.0/28)" "")"
  [ -z "$net" ] && return 0
  if ! is_valid_cidr4 "$net"; then
    tprint "ERROR: RIP network must be IPv4/CIDR."
    pause
    return 0
  fi

  if is_number_in_list "$net" "${current[@]}"; then
    tprint ""
    tprint "ERROR: RIP network already exists: $net"
    pause
    return 0
  fi

  yn="$(choose_yes_no "Add RIP network: $net ?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set protocols rip network "$net"
  cfg_apply
}

rip_delete_network_existing() {
  local current=() target yn
  load_array current scan_rip_networks

  tprint ""
  tprint "DELETE RIP network (existing)"
  tprint ""

  require_nonempty_list_or_return "RIP networks" "${current[@]}" || return 0

  if select_from_list "Select RIP network to DELETE" "${current[@]}"; then
    target="$SELECTED"
  else
    return 0
  fi

  yn="$(choose_yes_no "Delete RIP network: $target ?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_delete protocols rip network "$target"
  cfg_apply
}

rip_menu() {
  while true; do
    tprint ""
    tprint "=============================="
    tprint " RIP Submenu"
    tprint "=============================="
    tprint "Current:"
    tprint "  interfaces: $(scan_rip_interfaces | join_lines)"
    tprint "  networks:   $(scan_rip_networks | join_lines)"
    tprint ""
    tprint "1) List RIP config"
    tprint "2) Add RIP interface (SAFE)"
    tprint "3) Delete RIP interface (existing)"
    tprint "4) Add RIP network (SAFE)"
    tprint "5) Delete RIP network (existing)"
    tprint "6) Back"
    local c
    tread c "Select menu option #: "
    case "$c" in
      1) rip_list_config ;;
      2) rip_add_interface_safe ;;
      3) rip_delete_interface_existing ;;
      4) rip_add_network_safe ;;
      5) rip_delete_network_existing ;;
      6) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# -----------------------------
# Raw mode (edit ANY aspect)
# -----------------------------
# FIX: raw mode was open-ended. Now it rejects dangerous characters
# and rejects quotes (since we won't eval or preserve quoting).
raw_mode() {
  tprint ""
  tprint "RAW MODE WARNING:"
  tprint "  Raw mode can change anything."
  tprint "  This mode is RESTRICTED to prevent unsafe input."
  tprint ""
  tprint "Rules:"
  tprint "  - Must start with: set ...  OR  delete ..."
  # FIX: this line previously contained a literal backtick inside double quotes,
  # which breaks parsing and causes: unexpected EOF while looking for matching ``
  tprint '  - NO quotes, NO ; | & $ ` ( ) < > \\'
  tprint ""
  tprint "Example:"
  tprint "  set service ssh port 22"
  tprint "Blank = cancel"
  tprint ""

  local cmd yn
  tread cmd "> "
  [ -z "$cmd" ] && return 0

  if reject_if_unsafe_commandline "$cmd"; then
    tprint ""
    tprint "ERROR: Unsafe characters detected."
    tprint "Remove quotes or shell symbols and try again."
    pause
    return 0
  fi

  # Split first token (set/delete) safely
  # shellcheck disable=SC2086
  set -- $cmd
  local verb="${1:-}"
  shift || true

  case "$verb" in
    set|delete) ;;
    *)
      tprint "ERROR: Raw mode only allows commands starting with 'set' or 'delete'."
      pause
      return 0
      ;;
  esac

  yn="$(choose_yes_no "Are you sure you want to run that command?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  case "$verb" in
    set)    cfg_set "$@" ;;
    delete) cfg_delete "$@" ;;
  esac
  cfg_apply
}

# -----------------------------
# Main
# -----------------------------
main_menu() {
  die_no_access_if_needed

  while true; do
    tprint ""
    tprint "=================================="
    tprint " VyOS Dynamic Menu (Scan + CRUD)"
    tprint "=================================="
    show_detected_summary
    tprint "1) Interfaces submenu"
    tprint "2) Firewall submenu"
    tprint "3) NAT submenu"
    tprint "4) System submenu (users + hostname)"
    tprint "5) DNS Forwarding submenu"
    tprint "6) RIP submenu"
    tprint "7) Raw mode (restricted set/delete)"
    tprint "8) Show full config (commands)"
    tprint "9) Exit"
    tprint ""
    local c
    tread c "Select menu option #: "
    case "$c" in
      1) iface_menu ;;
      2) firewall_menu ;;
      3) nat_menu ;;
      4) system_menu ;;
      5) dns_forwarding_menu ;;
      6) rip_menu ;;
      7) raw_mode ;;
      8) tprint ""; get_cfg_cmds >"$TTY"; tprint ""; pause ;;
      9)
        cfg_end >/dev/null 2>&1 || true
        builtin exit 0
        ;;
      *) tprint "Invalid." ;;
    esac
  done
}

main_menu
