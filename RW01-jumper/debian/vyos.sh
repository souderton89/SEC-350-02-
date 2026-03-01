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
if [ "$(id -gn 2>/dev/null)" != "vyattacfg" ]; then
  SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
  exec sg vyattacfg -c "/bin/vbash '$SCRIPT_PATH' $*"
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
  local session_env
  session_env="$(cli-shell-api getSessionEnv "$PPID" 2>/dev/null || true)"
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
  tread yn "Commit + Save now? (y/n) [y]: "
  yn="${yn:-y}"
  case "$yn" in
    y|Y) return 0 ;;
    *)   return 1 ;;
  esac
}

cfg_apply() {
  if confirm_commit_save; then
    disable_completion_env

    local out rc
    out="$(cfg_commit <"$TTY" 2>&1)"
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
  tprint ""
  tprint "You selected: ADD user"
  tprint "This will create: system login user <username> + password"
  tprint ""

  u="$(ask "Username (example: admin2)" "")"
  [ -z "$u" ] && return 0

  fn="$(ask "Full name (optional)" "")"
  pw="$(ask "Password (plaintext) (will be hashed by VyOS)" "")"
  [ -z "$pw" ] && tprint "Password required." && pause && return 0

  tprint ""
  tprint "SUMMARY:"
  tprint "  username: $u"
  [ -n "$fn" ] && tprint "  full-name: $fn"
  tprint "  password: (set)"
  tprint ""
  pause

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
  pause

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
  local cur newhn
  tprint ""
  tprint "===================="
  tprint " Hostname Menu"
  tprint "===================="
  cur="$(get_current_hostname)"
  tprint "Current hostname: ${cur:-UNKNOWN}"
  tprint ""

  newhn="$(ask "New hostname (example: vyos-edge01)" "")"
  [ -z "$newhn" ] && return 0

  tprint ""
  tprint "You are setting system host-name to: $newhn"
  tprint ""
  pause

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

  action="$(ask "Action (accept/drop/reject)" "accept")"
  proto="$(ask "Protocol (tcp/udp/icmp/any)" "tcp")"
  desc="$(ask "Description (optional)" "")"
  saddr="$(ask "Source address (optional) (example: 172.16.50.0/29)" "")"
  daddr="$(ask "Destination address (optional) (example: 172.16.200.10)" "")"
  sport="$(ask "Source port (optional) (example: 443)" "")"
  dport="$(ask "Destination port (optional) (example: 22 or 1514-1515)" "")"
  state_est="$(ask "Match ESTABLISHED state? (y/n)" "n")"
  state_rel="$(ask "Match RELATED state? (y/n)" "n")"
  state_new="$(ask "Match NEW state? (y/n)" "n")"

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
  pause

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

fw_update_single_field() {
  local rs n tail val

  tprint ""
  tprint "You selected: Update ONE field (existing rule)"
  tprint "Next steps:"
  tprint "  1) Select a ruleset"
  tprint "  2) Select an EXISTING rule number"
  tprint "  3) Enter the field path + new value"
  tprint ""

  rs="$(fw_choose_ruleset_existing_only)" || return 0
  n="$(fw_choose_rule_number_existing "$rs")" || return 0
  fw_preview_rule "$rs" "$n"

  tprint "Common field paths:"
  tprint "  action"
  tprint "  description"
  tprint "  protocol"
  tprint "  destination address"
  tprint "  destination port"
  tprint "  source address"
  tprint "  source port"
  tprint "  state established"
  tprint ""

  tail="$(ask "Field path (words after: rule <N>)" "")"
  [ -z "$tail" ] && return 0
  val="$(ask "New value" "")"
  [ -z "$val" ] && return 0

  cfg_begin || return 0
  # shellcheck disable=SC2086
  cfg_set firewall ipv4 name "$rs" rule "$n" $tail "$val"
  cfg_apply
}

fw_delete_rule() {
  local rs n

  tprint ""
  tprint "You selected: Delete existing rule"
  tprint "Next steps:"
  tprint "  1) Select a ruleset"
  tprint "  2) Select an EXISTING rule number to delete"
  tprint ""

  rs="$(fw_choose_ruleset_existing_only)" || return 0
  n="$(fw_choose_rule_number_existing "$rs")" || return 0
  fw_preview_rule "$rs" "$n"

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
  local to from ruleset existing_rs

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
  pause

  cfg_begin || return 0
  cfg_set firewall zone "$to" from "$from" firewall name "$ruleset"
  cfg_apply
}

zone_update_binding_existing() {
  local to from ruleset existing_rs

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
  pause

  cfg_begin || return 0
  cfg_set firewall zone "$to" from "$from" firewall name "$ruleset"
  cfg_apply
}

zone_delete_binding_existing() {
  local to from existing_rs

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
  pause

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
    tprint "3) Update ONE field in an existing rule"
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
  tprint ""
  tprint "You are selecting a NAT TYPE:"
  tprint "  destination = DNAT / port forwarding"
  tprint "  source      = SNAT / masquerade"
  tprint ""
  local t
  t="$(ask "NAT type (destination/source)" "destination")"
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

  load_array ifs scan_eth_ifaces
  require_nonempty_list_or_return "Ethernet interfaces (for inbound)" "${ifs[@]}" || return 0

  if select_from_list "Select inbound interface (usually WAN like eth0)" "${ifs[@]}"; then
    inif="$SELECTED"
  else
    return 0
  fi

  proto="$(ask "Protocol (tcp/udp)" "tcp")"
  dport="$(ask "Public port (example: 80)" "80")"
  taddr="$(ask "Inside IP (example: 172.16.50.3)" "172.16.50.3")"
  tport="$(ask "Inside port (example: 80)" "80")"

  tprint ""
  tprint "SUMMARY (DNAT rule $n):"
  tprint "  description: $desc"
  tprint "  inbound-interface: $inif"
  tprint "  protocol: $proto"
  tprint "  public port: $dport"
  tprint "  translation: $taddr:$tport"
  tprint ""
  pause

  cfg_begin || return 0
  cfg_set nat destination rule "$n" description "$desc"
  cfg_set nat destination rule "$n" inbound-interface name "$inif"
  cfg_set nat destination rule "$n" protocol "$proto"
  cfg_set nat destination rule "$n" destination port "$dport"
  cfg_set nat destination rule "$n" translation address "$taddr"
  cfg_set nat destination rule "$n" translation port "$tport"
  cfg_apply
}

nat_update_single_field() {
  local type n tail val

  tprint ""
  tprint "You selected: Update ONE field in an existing NAT rule"
  tprint ""

  type="$(nat_choose_type)"
  [ -z "$type" ] && return 0
  n="$(nat_choose_rule_number_existing "$type")" || return 0

  nat_preview_rule "$type" "$n"

  tprint "Common field paths:"
  tprint "  description"
  tprint "  destination port"
  tprint "  inbound-interface name"
  tprint "  outbound-interface name"
  tprint "  source address"
  tprint "  protocol"
  tprint "  translation address"
  tprint "  translation port"
  tprint ""

  tail="$(ask "Field path (words after: rule <N>)" "")"
  [ -z "$tail" ] && return 0
  val="$(ask "New value" "")"
  [ -z "$val" ] && return 0

  cfg_begin || return 0
  # shellcheck disable=SC2086
  cfg_set nat "$type" rule "$n" $tail "$val"
  cfg_apply
}

nat_delete_rule() {
  local type n

  tprint ""
  tprint "You selected: Delete existing NAT rule"
  tprint ""

  type="$(nat_choose_type)"
  [ -z "$type" ] && return 0
  n="$(nat_choose_rule_number_existing "$type")" || return 0

  nat_preview_rule "$type" "$n"
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
    tprint "3) Update ONE field in an existing NAT rule"
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
  local ifs=() iface ip desc

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
  desc="$(ask "Description (optional) (example: Hamed-DMZ)" "")"

  tprint ""
  tprint "SUMMARY:"
  tprint "  interface: $iface"
  tprint "  address: $ip"
  [ -n "$desc" ] && tprint "  description: $desc"
  tprint ""
  pause

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

# -----------------------------
# Raw mode (edit ANY aspect)
# -----------------------------
raw_mode() {
  tprint ""
  tprint "RAW MODE WARNING:"
  tprint "  Raw mode CAN overwrite or delete anything."
  tprint "  Only use if you know exactly what you are doing."
  tprint ""
  tprint "Type ONE config command starting with: set ...  OR  delete ..."
  tprint "Examples:"
  tprint "  delete interfaces ethernet eth1 address 172.16.50.2/29"
  tprint "  set firewall zone LAN from DMZ firewall name 'DMZ-to-LAN'"
  tprint "Blank = cancel"
  tprint ""
  local cmd yn
  tread cmd "> "
  [ -z "$cmd" ] && return 0

  tread yn "Are you sure you want to run that command? (y/n) [n]: "
  yn="${yn:-n}"
  case "$yn" in
    y|Y) ;;
    *) tprint "Canceled."; pause; return 0 ;;
  esac

  cfg_begin || return 0

  # Use API wrappers for raw commands too (only set/delete supported here)
  case "$cmd" in
    set\ *)    eval "cfg_$cmd" ;;
    delete\ *) eval "cfg_$cmd" ;;
    *) tprint "ERROR: Raw mode only allows commands starting with 'set' or 'delete'."; cfg_end; pause; return 0 ;;
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
    tprint "5) Raw mode (set/delete anything)"
    tprint "6) Show full config (commands)"
    tprint "7) Exit"
    tprint ""
    local c
    tread c "Select menu option #: "
    case "$c" in
      1) iface_menu ;;
      2) firewall_menu ;;
      3) nat_menu ;;
      4) system_menu ;;
      5) raw_mode ;;
      6) tprint ""; get_cfg_cmds >"$TTY"; tprint ""; pause ;;
      7)
        cfg_end >/dev/null 2>&1 || true
        builtin exit 0
        ;;
      *) tprint "Invalid." ;;
    esac
  done
}

main_menu
