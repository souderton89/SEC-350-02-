#!/bin/vbash
# vyos-dynamic-menu.sh (v3.1 — hostname input support)
# Dynamic CRUD menu: Interfaces + Firewall + NAT + System + DNS + RIP + Static Routes + DHCP + SSH
# v3.0 additions:
#   - Port Group Management (create/edit/delete) under Firewall AND NAT menus
#   - Smart group-aware pickers for all source/destination port and address fields
#   - Address group + Network group support in all firewall and NAT rule builders
# v3.1 additions:
#   - All IP/address input fields now accept hostnames (e.g. DHCP01 or DHCP01.capstone.local)
#   - resolve_hostname_to_ip() resolves hostnames to IPv4 at input time via getent/dig/nslookup/host
#   - ask_ip_or_hostname()  wraps all plain-IPv4 prompts
#   - ask_cidr_or_hostname() wraps all CIDR prompts (hostname → resolve + ask prefix, or plain CIDR)

TTY="/dev/tty"

export PATH=/opt/vyatta/bin:/opt/vyatta/sbin:/usr/sbin:/usr/bin:/sbin:/bin

if [ "$(id -gn 2>/dev/null)" != "vyattacfg" ]; then
  SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
  ARGS=""
  for a in "$@"; do
    ARGS="$ARGS $(printf "%q" "$a")"
  done
  VBASH="$(command -v vbash 2>/dev/null || echo /bin/vbash)"
  exec sg vyattacfg -c "$VBASH $(printf "%q" "$SCRIPT_PATH")$ARGS"
fi

source /opt/vyatta/etc/functions/script-template

# ============================================================
# TTY-SAFE IO
# ============================================================
tprint()  { printf "%s\n" "$*" >"$TTY"; }
tprintf() { printf "$@" >"$TTY"; }

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
    read -r -t 300 -p "$__prompt" __val <"$TTY" || {
      tprint ""; tprint "(Input timeout or TTY error — canceling)"
      printf -v "$__var" "%s" ""; return 1
    }
  else
    read -r -t 300 __val <"$TTY" || {
      tprint ""; tprint "(Input timeout or TTY error — canceling)"
      printf -v "$__var" "%s" ""; return 1
    }
  fi
  printf -v "$__var" "%s" "$__val"
}

tread_secret() {
  local __var="$1"; shift
  local __prompt="${1:-Password: }"
  local __val=""
  disable_completion_env
  read -r -s -t 300 -p "$__prompt" __val <"$TTY" || {
    printf "\n" >"$TTY"
    tprint "(Input timeout or TTY error — canceling)"
    printf -v "$__var" "%s" ""; return 1
  }
  printf "\n" >"$TTY"
  printf -v "$__var" "%s" "$__val"
}

pause() { tprint ""; local _; tread _ "Press Enter to continue..." || true; }

strip_quotes() {
  local s="$1"
  s="${s#[\'\"]}"
  s="${s%[\'\"]}"
  echo "$s"
}

join_lines() { tr '\n' ' ' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'; }

# ============================================================
# CONFIG CACHE
# ============================================================
_CFG_CACHE=""
_CFG_CACHE_VALID=0

cfg_cache_refresh() {
  local out
  out="$(run show configuration commands 2>&1)" || true
  if echo "$out" | grep -qiE "not assigned to any operator group|permission denied|authorization|not authorized|internal error"; then
    tprint ""; tprint "ERROR: No permission to read config."; tprint ""; tprint "$out"; return 1
  fi
  if [ -z "$out" ]; then
    tprint ""; tprint "ERROR: 'show configuration commands' returned nothing."; return 1
  fi
  _CFG_CACHE="$out"; _CFG_CACHE_VALID=1; return 0
}

cfg_cache_invalidate() { _CFG_CACHE=""; _CFG_CACHE_VALID=0; }

grep_cfg() {
  if [ "$_CFG_CACHE_VALID" -eq 0 ]; then cfg_cache_refresh || return 1; fi
  printf "%s\n" "$_CFG_CACHE" | grep -F "$1" || true
}

get_cfg_cmds() {
  if [ "$_CFG_CACHE_VALID" -eq 0 ]; then cfg_cache_refresh || return 1; fi
  printf "%s\n" "$_CFG_CACHE"
}

# ============================================================
# LOAD_ARRAY
# ============================================================
_LOAD_ARRAY_TMP=""
_load_array_cleanup() {
  [ -n "$_LOAD_ARRAY_TMP" ] && rm -f "$_LOAD_ARRAY_TMP" 2>/dev/null || true
}
trap '_load_array_cleanup' EXIT

load_array() {
  local __name="$1"; shift
  local __line="" __tmpfile
  __tmpfile="$(mktemp /tmp/vyos_arr_XXXXXX 2>/dev/null)" || {
    tprint "ERROR: could not create temp file."; return 1
  }
  _LOAD_ARRAY_TMP="$__tmpfile"
  "$@" >"$__tmpfile" 2>/dev/null || true
  eval "${__name}=()"
  while IFS= read -r __line; do
    [ -n "$__line" ] || continue
    eval "${__name}+=(\"\$__line\")"
  done <"$__tmpfile"
  rm -f "$__tmpfile" 2>/dev/null || true
  _LOAD_ARRAY_TMP=""
}

# ============================================================
# INPUT VALIDATION
# ============================================================
is_valid_username() { echo "$1" | grep -Eq '^[A-Za-z_][A-Za-z0-9_.-]{0,31}$'; }
is_valid_hostname() {
  local hn="$1"
  [ -z "$hn" ] && return 1
  [ "${#hn}" -gt 253 ] && return 1
  echo "$hn" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
}
is_valid_ipv4() {
  echo "$1" | awk -F. '
    NF!=4{exit 1}
    {for(i=1;i<=4;i++){if($i!~/^[0-9]+$/)exit 1;if($i<0||$i>255)exit 1}}
    END{exit 0}'
}
is_valid_cidr4() {
  local cidr="$1"
  echo "$cidr" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$' || return 1
  is_valid_ipv4 "${cidr%/*}"
}
is_valid_port_or_range() {
  local p="$1"
  echo "$p" | grep -Eq '^[0-9]{1,5}(-[0-9]{1,5})?$' || return 1
  local a="${p%%-*}"
  [ "$a" -ge 1 ] 2>/dev/null || return 1
  [ "$a" -le 65535 ] 2>/dev/null || return 1
  if echo "$p" | grep -q -- '-'; then
    local b="${p#*-}"
    [ "$b" -ge 1 ] 2>/dev/null || return 1
    [ "$b" -le 65535 ] 2>/dev/null || return 1
    [ "$a" -le "$b" ] 2>/dev/null || return 1
  fi
  return 0
}
is_safe_ruleset_name() { echo "$1" | grep -Eq '^[A-Za-z0-9_.-]{1,64}$'; }
is_safe_iface_name()   { echo "$1" | grep -Eq '^[A-Za-z0-9_.:-]{1,32}$'; }
is_safe_free_text() {
  printf "%s" "$1" | grep -Eq '^[[:print:]]{1,128}$' && ! printf "%s" "$1" | grep -Eq '[`|]'
}
reject_if_unsafe_commandline() {
  local s="$1"
  printf "%s" "$s" | grep -Eq '[;&|`$<>()\\]' && return 0
  printf "%s" "$s" | grep -Pq '[\r\n\t]' 2>/dev/null && return 0
  printf "%s" "$s" | cat -A | grep -q '\^I' && return 0
  printf "%s" "$s" | grep -Eq "[\"']" && return 0
  return 1
}

# ============================================================
# v3.1 NEW: HOSTNAME RESOLUTION HELPERS
# ============================================================

# Attempt to resolve a hostname to its first IPv4 address.
# Tries getent, then dig, then nslookup, then host in order.
# Prints the resolved IP on success; prints nothing on failure.
resolve_hostname_to_ip() {
  local hn="$1" resolved=""

  # Try getent (fastest, uses /etc/hosts + system resolver)
  if command -v getent >/dev/null 2>&1; then
    resolved="$(getent ahosts "$hn" 2>/dev/null \
      | awk '/STREAM/{print $1; exit}' \
      | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && \
      getent ahosts "$hn" 2>/dev/null | awk '/STREAM/{print $1; exit}' || true)"
    # Safer two-step for older awks
    if [ -z "$resolved" ]; then
      resolved="$(getent ahosts "$hn" 2>/dev/null \
        | awk '{print $1}' | head -n 1 || true)"
    fi
  fi

  # Try dig
  if [ -z "$resolved" ] && command -v dig >/dev/null 2>&1; then
    resolved="$(dig +short A "$hn" 2>/dev/null | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
      && dig +short A "$hn" 2>/dev/null | head -n 1 || true)"
    if [ -z "$resolved" ]; then
      resolved="$(dig +short A "$hn" 2>/dev/null | head -n 1 || true)"
    fi
  fi

  # Try nslookup
  if [ -z "$resolved" ] && command -v nslookup >/dev/null 2>&1; then
    resolved="$(nslookup "$hn" 2>/dev/null \
      | awk '/^Address: /{print $2}' | grep -v '#' | head -n 1 || true)"
  fi

  # Try host
  if [ -z "$resolved" ] && command -v host >/dev/null 2>&1; then
    resolved="$(host -t A "$hn" 2>/dev/null \
      | awk '/has address/{print $NF}' | head -n 1 || true)"
  fi

  # Validate the result is actually an IPv4
  if [ -n "$resolved" ] && is_valid_ipv4 "$resolved"; then
    echo "$resolved"
    return 0
  fi
  return 1
}

# Accept either a plain IPv4 or a hostname, resolve hostname if needed.
# Usage: result="$(ask_ip_or_hostname "prompt label" "default")"
# Returns an IPv4 on stdout, or empty string on cancel/error.
ask_ip_or_hostname() {
  local label="${1:-IP or hostname}" def="${2:-}" val="" resolved=""
  while true; do
    if [ -n "$def" ]; then
      tread val "$label (IP or hostname) [$def]: " || return 0
      val="${val:-$def}"
    else
      tread val "$label (IP or hostname): " || return 0
    fi
    [ -z "$val" ] && { echo ""; return 0; }

    # Already a plain IPv4?
    if is_valid_ipv4 "$val"; then
      echo "$val"; return 0
    fi

    # Looks like a hostname?
    if is_valid_hostname "$val"; then
      tprint "  Resolving '$val'..."
      resolved="$(resolve_hostname_to_ip "$val" || true)"
      if [ -n "$resolved" ]; then
        tprint "  Resolved: $val -> $resolved"
        echo "$resolved"; return 0
      else
        tprint "  ERROR: Could not resolve '$val' to an IPv4 address."
        tprint "  Check DNS/hosts and try again, or enter a plain IPv4."
        continue
      fi
    fi

    tprint "  ERROR: '$val' is not a valid IPv4 address or resolvable hostname."
  done
}

# Accept either a plain CIDR (x.x.x.x/yy) or a hostname (resolved to IP,
# then the user is prompted for the prefix length), or a plain IPv4 (same).
# Usage: result="$(ask_cidr_or_hostname "prompt label" "default")"
# Returns a CIDR string on stdout, or empty string on cancel/error.
ask_cidr_or_hostname() {
  local label="${1:-IP/CIDR or hostname}" def="${2:-}" val="" resolved="" prefix=""
  while true; do
    if [ -n "$def" ]; then
      tread val "$label (CIDR, IP, or hostname) [$def]: " || return 0
      val="${val:-$def}"
    else
      tread val "$label (CIDR, IP, or hostname): " || return 0
    fi
    [ -z "$val" ] && { echo ""; return 0; }

    # Already a valid CIDR?
    if is_valid_cidr4 "$val"; then
      echo "$val"; return 0
    fi

    # Plain IPv4 without prefix — ask for prefix length
    if is_valid_ipv4 "$val"; then
      tread prefix "  Prefix length (e.g. 24): " || return 0
      [ -z "$prefix" ] && { tprint "  Prefix length required."; continue; }
      if is_valid_cidr4 "$val/$prefix"; then
        echo "$val/$prefix"; return 0
      else
        tprint "  ERROR: Invalid prefix length '$prefix'. Must be 0-32."; continue
      fi
    fi

    # Hostname — resolve then ask for prefix
    if is_valid_hostname "$val"; then
      tprint "  Resolving '$val'..."
      resolved="$(resolve_hostname_to_ip "$val" || true)"
      if [ -n "$resolved" ]; then
        tprint "  Resolved: $val -> $resolved"
        tread prefix "  Prefix length (e.g. 24): " || return 0
        [ -z "$prefix" ] && { tprint "  Prefix length required."; continue; }
        if is_valid_cidr4 "$resolved/$prefix"; then
          echo "$resolved/$prefix"; return 0
        else
          tprint "  ERROR: Invalid prefix length '$prefix'. Must be 0-32."; continue
        fi
      else
        tprint "  ERROR: Could not resolve '$val' to an IPv4 address."
        tprint "  Check DNS/hosts and try again, or enter a plain IP or CIDR."
        continue
      fi
    fi

    tprint "  ERROR: '$val' is not a valid CIDR, IPv4 address, or resolvable hostname."
  done
}

# ============================================================
# API SESSION
# ============================================================
API_ACTIVE=0
MY_SET="" MY_DELETE="" MY_COMMIT="" SAVE_BIN=""

api_detect_bins() {
  local SBIN="/opt/vyatta/sbin"
  MY_SET="$SBIN/my_set"; MY_DELETE="$SBIN/my_delete"; MY_COMMIT="$SBIN/my_commit"
  local candidates=(
    "$SBIN/vyos-config-save"   "$SBIN/vyatta-save-config"
    "$SBIN/vyos-save-config"   "$SBIN/vyos-save-config.py"
    "/usr/libexec/vyos/vyos-config-save"  "/usr/libexec/vyos/vyos-save-config"
    "/usr/libexec/vyos/vyos-save-config.py"
    "/usr/lib/vyos/vyos-config-save"      "/usr/lib/vyos/vyos-save-config.py"
  )
  SAVE_BIN=""
  local c; for c in "${candidates[@]}"; do [ -x "$c" ] && SAVE_BIN="$c" && break; done
}

api_begin() {
  disable_completion_env; api_detect_bins
  if ! command -v cli-shell-api >/dev/null 2>&1; then tprint "ERROR: cli-shell-api not found."; pause; return 1; fi
  if [ ! -x "$MY_SET" ] || [ ! -x "$MY_DELETE" ] || [ ! -x "$MY_COMMIT" ]; then tprint "ERROR: my_set/my_delete/my_commit not found."; pause; return 1; fi
  local session_env=""
  session_env="$(cli-shell-api getSessionEnv "$PPID" 2>/dev/null || true)"
  [ -z "$session_env" ] && session_env="$(cli-shell-api getSessionEnv "$$" 2>/dev/null || true)"
  if [ -z "$session_env" ]; then tprint "ERROR: cli-shell-api getSessionEnv failed."; pause; return 1; fi
  eval "$session_env"
  if ! cli-shell-api setupSession <"$TTY" >"$TTY" 2>&1; then tprint "ERROR: setupSession failed."; pause; return 1; fi
  cli-shell-api inSession >/dev/null 2>&1 || {
    tprint "ERROR: inSession check failed."
    cli-shell-api teardownSession >/dev/null 2>&1 || true
    pause; return 1
  }
  API_ACTIVE=1; return 0
}

api_end() {
  disable_completion_env
  [ "$API_ACTIVE" -eq 1 ] && cli-shell-api teardownSession <"$TTY" >"$TTY" 2>&1 || true
  API_ACTIVE=0
}

cfg_set()    { [ "$API_ACTIVE" -eq 1 ] || { tprint "ERROR: no API session"; return 1; }; "$MY_SET" "$@"; }
cfg_delete() { [ "$API_ACTIVE" -eq 1 ] || { tprint "ERROR: no API session"; return 1; }; "$MY_DELETE" "$@"; }
cfg_commit() { [ "$API_ACTIVE" -eq 1 ] || { tprint "ERROR: no API session"; return 1; }; "$MY_COMMIT"; }
cfg_save() {
  [ "$API_ACTIVE" -eq 1 ] || { tprint "ERROR: no API session"; return 1; }
  if [ -n "${SAVE_BIN:-}" ] && [ -x "$SAVE_BIN" ]; then "$SAVE_BIN"; return $?; fi
  tprint "ERROR: no working save binary found."; return 1
}
cfg_begin() { api_begin; }
cfg_end()   { api_end; }
cfg_rollback_and_end() {
  [ "$API_ACTIVE" -eq 1 ] && { tprint "(Rolling back open config session.)"; cfg_end >/dev/null 2>&1 || true; }
}
trap 'cfg_end >/dev/null 2>&1 || true; _load_array_cleanup' EXIT

# ============================================================
# ACCESS GUARDS
# ============================================================
warn_if_no_access() { if ! cfg_cache_refresh; then pause; return 1; fi; return 0; }
die_no_access_if_needed() { cfg_cache_refresh || exit 1; }

# ============================================================
# UI HELPERS
# ============================================================
SELECTED=""

select_from_list() {
  local title="$1"; shift
  local arr=("$@")
  local i choice
  tprint ""; tprint "=== $title ==="
  if [ "${#arr[@]}" -eq 0 ]; then tprint "(none found)"; return 1; fi
  for i in "${!arr[@]}"; do tprintf "%2d) %s\n" "$((i+1))" "${arr[$i]}"; done
  tprint " 0) Cancel"; tprint ""
  tread choice "Select #: " || return 1
  if [ -z "$choice" ] || ! echo "$choice" | grep -Eq '^[0-9]+$'; then tprint "Invalid."; return 1; fi
  [ "$choice" -eq 0 ] && return 1
  if [ "$choice" -lt 1 ] || [ "$choice" -gt "${#arr[@]}" ]; then tprint "Invalid."; return 1; fi
  SELECTED="${arr[$((choice-1))]}"; return 0
}

select_from_list_default() {
  local title="$1"; shift
  local def="$1"; shift
  local arr=("$@")
  local i choice def_idx=""
  tprint ""; tprint "=== $title ==="
  if [ "${#arr[@]}" -eq 0 ]; then tprint "(none found)"; return 1; fi
  for i in "${!arr[@]}"; do
    if [ -n "$def" ] && [ "${arr[$i]}" = "$def" ]; then
      tprintf "%2d) %s  (default)\n" "$((i+1))" "${arr[$i]}"; def_idx="$((i+1))"
    else
      tprintf "%2d) %s\n" "$((i+1))" "${arr[$i]}"
    fi
  done
  tprint " 0) Cancel"; tprint ""
  if [ -n "$def_idx" ]; then
    tread choice "Select # [${def_idx}]: " || return 1
    choice="${choice:-$def_idx}"
  else
    tread choice "Select #: " || return 1
  fi
  if [ -z "$choice" ] || ! echo "$choice" | grep -Eq '^[0-9]+$'; then tprint "Invalid."; return 1; fi
  [ "$choice" -eq 0 ] && return 1
  if [ "$choice" -lt 1 ] || [ "$choice" -gt "${#arr[@]}" ]; then tprint "Invalid."; return 1; fi
  SELECTED="${arr[$((choice-1))]}"; return 0
}

choose_yes_no() {
  local prompt="$1" def="${2:-n}" def_label="No"
  { [ "$def" = "y" ] || [ "$def" = "Y" ]; } && def_label="Yes"
  if select_from_list_default "$prompt" "$def_label" "Yes" "No"; then
    case "$SELECTED" in Yes) echo "y";; No) echo "n";; esac; return 0
  fi
  return 1
}

choose_fw_action() {
  local def="${1:-accept}"
  select_from_list_default "Action for matched traffic" "$def" "accept" "drop" "reject" && echo "$SELECTED" && return 0
  return 1
}

choose_fw_protocol() {
  local def="${1:-tcp}"
  select_from_list_default "Protocol" "$def" "tcp" "udp" "tcp_udp" "icmp" "any" && echo "$SELECTED" && return 0
  return 1
}

choose_nat_type() {
  local def="${1:-destination}"
  tprint ""; tprint "  destination = DNAT / port forwarding"; tprint "  source      = SNAT / masquerade"
  select_from_list_default "NAT type" "$def" "destination" "source" && echo "$SELECTED" && return 0
  return 1
}

choose_tcp_udp() {
  local def="${1:-tcp}"
  select_from_list_default "Protocol (tcp/udp)" "$def" "tcp" "udp" && echo "$SELECTED" && return 0
  return 1
}

ask() {
  local prompt="$1" def="${2:-}" val=""
  if [ -n "$def" ]; then
    tread val "$prompt [$def]: " || true; echo "${val:-$def}"
  else
    tread val "$prompt: " || true; echo "$val"
  fi
}

confirm_commit_save() {
  local yn; yn="$(choose_yes_no "Commit + Save now?" "y" || true)"
  [ "${yn:-n}" = "y" ]
}

cfg_apply() {
  if confirm_commit_save; then
    disable_completion_env
    local out rc
    out="$(cfg_commit 2>&1)"; rc=$?
    printf "%s\n" "$out" >"$TTY"
    if echo "$out" | grep -qi "No configuration changes to commit"; then
      tprint ""; tprint "NOTE: Nothing changed — nothing to commit."
      cfg_end; cfg_cache_invalidate; pause; return 0
    fi
    if [ $rc -ne 0 ]; then
      tprint ""; tprint "ERROR: commit failed."
      cfg_end; cfg_cache_invalidate; pause; return 1
    fi
    disable_completion_env
    if ! cfg_save <"$TTY" >"$TTY" 2>&1; then
      tprint ""; tprint "ERROR: save failed. Changes committed but not saved."
      cfg_end; cfg_cache_invalidate; pause; return 1
    fi
    tprint "DONE: committed + saved."; cfg_end
  else
    tprint "Not committed."; cfg_end
  fi
  cfg_cache_invalidate; pause; return 0
}

# ============================================================
# SAFETY HELPERS
# ============================================================
is_number_in_list() { local needle="$1"; shift; local x; for x in "$@"; do [ "$x" = "$needle" ] && return 0; done; return 1; }
is_in_list()        { local needle="$1"; shift; local x; for x in "$@"; do [ "$x" = "$needle" ] && return 0; done; return 1; }
next_free_rule_number() { local used=("$@") n=10; while is_number_in_list "$n" "${used[@]}"; do n=$((n+10)); done; echo "$n"; }
require_numeric() { echo "$1" | grep -Eq '^[0-9]+$'; }
require_nonempty_list_or_return() {
  local label="$1"; shift
  if [ "${#@}" -eq 0 ] || { [ "$#" -eq 1 ] && [ -z "$1" ]; }; then
    tprint ""; tprint "Nothing available: $label"; tprint ""; pause; return 1
  fi
  return 0
}

# ============================================================
# SCAN FUNCTIONS
# ============================================================

# --- Firewall ---
scan_firewall_rulesets() {
  grep_cfg "set firewall ipv4 name " | awk '{print $5}' | sort -u | while read -r n; do strip_quotes "$n"; done
}
scan_firewall_rule_numbers() {
  local rs="$1"
  { grep_cfg "set firewall ipv4 name '$rs' rule " | awk '{print $7}'
    grep_cfg "set firewall ipv4 name $rs rule "   | awk '{print $7}'; } | sort -u
}

# --- NAT ---
scan_nat_dest_rules()   { grep_cfg "set nat destination rule " | awk '{print $5}' | sort -u; }
scan_nat_source_rules() { grep_cfg "set nat source rule "      | awk '{print $5}' | sort -u; }

# --- Interfaces ---
scan_eth_ifaces()      { grep_cfg "set interfaces ethernet " | awk '{print $4}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_bond_ifaces()     { grep_cfg "set interfaces bonding "  | awk '{print $4}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_vlan_ifaces() {
  grep_cfg "set interfaces ethernet " | grep -F " vif " | awk '{print $4 "." $6}' | sort -u | while read -r x; do strip_quotes "$x"; done
  grep_cfg "set interfaces bonding "  | grep -F " vif " | awk '{print $4 "." $6}' | sort -u | while read -r x; do strip_quotes "$x"; done
}
scan_loopback_ifaces() { grep_cfg "set interfaces loopback " | awk '{print $4}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_all_ifaces() { { scan_eth_ifaces; scan_bond_ifaces; scan_vlan_ifaces; scan_loopback_ifaces; } | sort -u; }

# --- Zones ---
scan_fw_zones() { grep_cfg "set firewall zone " | awk '{print $4}' | sort -u; }
scan_zone_bindings() {
  grep_cfg "set firewall zone " | grep -F " from " | grep -F " firewall name " \
    | awk '{print $4 "|" $6 "|" $9}' \
    | while IFS='|' read -r to from rs; do echo "$(strip_quotes "$to")|$(strip_quotes "$from")|$(strip_quotes "$rs")"; done | sort -u
}
binding_exists()      { local to="$1" from="$2"; scan_zone_bindings | grep -F -q "${to}|${from}|"; }
binding_get_ruleset() { local to="$1" from="$2"; scan_zone_bindings | grep -F "${to}|${from}|" | head -n 1 | awk -F'|' '{print $3}'; }

# --- System ---
scan_login_users()    { grep_cfg "set system login user " | awk '{print $5}' | sort -u | while read -r u; do strip_quotes "$u"; done; }
get_current_username(){ (id -un 2>/dev/null || true) | tr -d '\n'; }
get_current_hostname() {
  local hn; hn="$(grep_cfg "set system host-name " | head -n 1 | awk '{print $4}' || true)"
  hn="$(strip_quotes "$hn")"; [ -n "$hn" ] && echo "$hn" || (hostname 2>/dev/null || true)
}

# --- DNS ---
scan_dns_allow_from()     { grep_cfg "set service dns forwarding allow-from "    | awk '{print $6}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_dns_listen_address() { grep_cfg "set service dns forwarding listen-address " | awk '{print $6}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
dns_system_is_enabled()   { grep_cfg "set service dns forwarding system" | grep -q .; }
scan_dns_name_servers()   { grep_cfg "set system name-server " | awk '{print $4}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_dns_forward_domains(){ grep_cfg "set service dns forwarding domain " | grep -F " name-server " | awk '{print $6}' | sort -u | while read -r x; do strip_quotes "$x"; done; }

# --- RIP ---
scan_rip_interfaces()        { grep_cfg "set protocols rip interface "          | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_rip_networks()          { grep_cfg "set protocols rip network "            | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_rip_neighbors()         { grep_cfg "set protocols rip neighbor "           | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_rip_passive_interfaces(){ grep_cfg "set protocols rip passive-interface "  | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_rip_redistribute()      { grep_cfg "set protocols rip redistribute "       | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_rip_static_routes()     { grep_cfg "set protocols rip route "              | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_rip_iface_settings()    { grep_cfg " ip rip " | sort -u; }

# --- Static routes ---
scan_static_routes() {
  grep_cfg "set protocols static route " | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done
}
scan_static_route_nexthops() {
  local prefix="$1"
  { grep_cfg "set protocols static route $prefix next-hop "
    grep_cfg "set protocols static route '$prefix' next-hop "; } | awk '{print $7}' | sort -u | while read -r x; do strip_quotes "$x"; done
}
scan_static_blackholes() {
  grep_cfg "set protocols static route " | grep -F " blackhole" | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done
}

# --- DHCP ---
scan_dhcp_pools() {
  grep_cfg "set service dhcp-server shared-network-name " | awk '{print $6}' | sort -u | while read -r x; do strip_quotes "$x"; done
}
scan_dhcp_subnets() {
  local pool="$1"
  { grep_cfg "set service dhcp-server shared-network-name $pool subnet "
    grep_cfg "set service dhcp-server shared-network-name '$pool' subnet "; } | awk '{print $8}' | sort -u | while read -r x; do strip_quotes "$x"; done
}

# --- SSH ---
scan_ssh_listen_addresses() {
  grep_cfg "set service ssh listen-address " | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done
}
ssh_get_port()   { grep_cfg "set service ssh port " | awk '{print $5}' | head -n 1 | while read -r x; do strip_quotes "$x"; done; }
ssh_is_enabled() { grep_cfg "set service ssh" | grep -q .; }

# ============================================================
# v3.0 NEW: SCAN — PORT / ADDRESS / NETWORK GROUPS
# ============================================================

scan_port_groups() {
  grep_cfg "set firewall group port-group " \
    | awk '{print $5}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

scan_port_group_members() {
  local grp="$1"
  { grep_cfg "set firewall group port-group $grp port "
    grep_cfg "set firewall group port-group '$grp' port "; } \
    | awk '{print $NF}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

scan_address_groups() {
  grep_cfg "set firewall group address-group " \
    | awk '{print $5}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

scan_address_group_members() {
  local grp="$1"
  { grep_cfg "set firewall group address-group $grp address "
    grep_cfg "set firewall group address-group '$grp' address "; } \
    | awk '{print $NF}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

scan_network_groups() {
  grep_cfg "set firewall group network-group " \
    | awk '{print $5}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

scan_network_group_members() {
  local grp="$1"
  { grep_cfg "set firewall group network-group $grp network "
    grep_cfg "set firewall group network-group '$grp' network "; } \
    | awk '{print $NF}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

# ============================================================
# Interface address helpers
# ============================================================
resolve_iface_path() {
  local iface="$1"
  echo "$iface" | grep -Eq '^eth[0-9]+\.[0-9]+$'  && { echo "ethernet|${iface%%.*}|${iface#*.}"; return; }
  echo "$iface" | grep -Eq '^bond[0-9]+\.[0-9]+$' && { echo "bonding|${iface%%.*}|${iface#*.}";  return; }
  echo "$iface" | grep -Eq '^bond[0-9]+'           && { echo "bonding|$iface|";   return; }
  echo "$iface" | grep -Eq '^lo[0-9]*$'            && { echo "loopback|$iface|";  return; }
  echo "ethernet|$iface|"
}

iface_cfg_set() {
  local iface="$1"; shift; local r t p v
  r="$(resolve_iface_path "$iface")"
  t="$(echo "$r"|cut -d'|' -f1)" p="$(echo "$r"|cut -d'|' -f2)" v="$(echo "$r"|cut -d'|' -f3)"
  [ -n "$v" ] && cfg_set interfaces "$t" "$p" vif "$v" "$@" || cfg_set interfaces "$t" "$p" "$@"
}

iface_cfg_delete() {
  local iface="$1"; shift; local r t p v
  r="$(resolve_iface_path "$iface")"
  t="$(echo "$r"|cut -d'|' -f1)" p="$(echo "$r"|cut -d'|' -f2)" v="$(echo "$r"|cut -d'|' -f3)"
  [ -n "$v" ] && cfg_delete interfaces "$t" "$p" vif "$v" "$@" || cfg_delete interfaces "$t" "$p" "$@"
}

scan_iface_addresses() {
  local iface="$1"; local r t p v pattern
  r="$(resolve_iface_path "$iface")"
  t="$(echo "$r"|cut -d'|' -f1)" p="$(echo "$r"|cut -d'|' -f2)" v="$(echo "$r"|cut -d'|' -f3)"
  [ -n "$v" ] && pattern="set interfaces $t $p vif $v address " || pattern="set interfaces $t $p address "
  grep_cfg "$pattern" | awk '{print $NF}' | sort -u | while read -r x; do strip_quotes "$x"; done
}

get_iface_description() {
  local iface="$1"; local r t p v pattern
  r="$(resolve_iface_path "$iface")"
  t="$(echo "$r"|cut -d'|' -f1)" p="$(echo "$r"|cut -d'|' -f2)" v="$(echo "$r"|cut -d'|' -f3)"
  [ -n "$v" ] && pattern="set interfaces $t $p vif $v description " || pattern="set interfaces $t $p description "
  grep_cfg "$pattern" | awk '{for(i=1;i<=NF;i++) if($i=="description"){ s=""; for(j=i+1;j<=NF;j++) s=s (j>i+1?" ":"") $j; print s; break }}' | head -n 1 | while read -r x; do strip_quotes "$x"; done
}

iface_is_disabled() {
  local iface="$1"; local r t p v pattern
  r="$(resolve_iface_path "$iface")"
  t="$(echo "$r"|cut -d'|' -f1)" p="$(echo "$r"|cut -d'|' -f2)" v="$(echo "$r"|cut -d'|' -f3)"
  [ -n "$v" ] && pattern="set interfaces $t $p vif $v disable" || pattern="set interfaces $t $p disable"
  grep_cfg "$pattern" | grep -q .
}

# ============================================================
# COMPACT SUMMARIES
# ============================================================
_iface_summary() {
  tprint "  Ethernet:  $(scan_eth_ifaces   | join_lines || echo NONE)"
  tprint "  Bonding:   $(scan_bond_ifaces  | join_lines || echo NONE)"
  tprint "  VLANs:     $(scan_vlan_ifaces  | join_lines || echo NONE)"
  tprint "  Loopback:  $(scan_loopback_ifaces | join_lines || echo NONE)"
}
_fw_summary() {
  tprint "  Rulesets:    $(scan_firewall_rulesets | join_lines || echo NONE)"
  tprint "  Zones:       $(scan_fw_zones          | join_lines || echo NONE)"
  tprint "  Port Groups: $(scan_port_groups       | join_lines || echo NONE)"
}
_nat_summary() {
  tprint "  DNAT rules: $(scan_nat_dest_rules   | join_lines || echo NONE)"
  tprint "  SNAT rules: $(scan_nat_source_rules | join_lines || echo NONE)"
}
_dns_summary() {
  tprint "  allow-from:     $(scan_dns_allow_from     | join_lines || echo NONE)"
  tprint "  listen-address: $(scan_dns_listen_address | join_lines || echo NONE)"
  local sys="disabled"; dns_system_is_enabled && sys="ENABLED"
  tprint "  system:         $sys"
  tprint "  name-servers:   $(scan_dns_name_servers    | join_lines || echo NONE)"
  tprint "  fwd domains:    $(scan_dns_forward_domains | join_lines || echo NONE)"
}
_rip_summary() {
  tprint "  interfaces:         $(scan_rip_interfaces         | join_lines || echo NONE)"
  tprint "  networks:           $(scan_rip_networks           | join_lines || echo NONE)"
  tprint "  neighbors:          $(scan_rip_neighbors          | join_lines || echo NONE)"
  tprint "  passive-interfaces: $(scan_rip_passive_interfaces | join_lines || echo NONE)"
  tprint "  redistribute:       $(scan_rip_redistribute       | join_lines || echo NONE)"
  local di="disabled"
  grep_cfg "set protocols rip default-information originate" | grep -q . && di="ENABLED"
  tprint "  default-info originate: $di"
}

run_cmd_to_tty() {
  local cmd="$1"; tprint ""; tprint ">> $cmd"; tprint "--------------------------------------------------------"
  # shellcheck disable=SC2086
  run $cmd >"$TTY" 2>&1 || tprint "(command unavailable on this build)"
  tprint "--------------------------------------------------------"
}

# ============================================================
# v3.0 NEW: GROUP DISPLAY HELPERS
# ============================================================

print_port_groups_inline() {
  local groups=(); load_array groups scan_port_groups
  if [ "${#groups[@]}" -eq 0 ]; then tprint "  (no port groups defined)"; return 0; fi
  local g members
  for g in "${groups[@]}"; do
    members="$(scan_port_group_members "$g" | join_lines || echo "(empty)")"
    tprintf "  %-20s  ports: %s\n" "$g" "$members"
  done
}

print_address_groups_inline() {
  local groups=(); load_array groups scan_address_groups
  if [ "${#groups[@]}" -eq 0 ]; then tprint "  (no address groups defined)"; return 0; fi
  local g members
  for g in "${groups[@]}"; do
    members="$(scan_address_group_members "$g" | join_lines || echo "(empty)")"
    tprintf "  %-20s  addresses: %s\n" "$g" "$members"
  done
}

print_network_groups_inline() {
  local groups=(); load_array groups scan_network_groups
  if [ "${#groups[@]}" -eq 0 ]; then tprint "  (no network groups defined)"; return 0; fi
  local g members
  for g in "${groups[@]}"; do
    members="$(scan_network_group_members "$g" | join_lines || echo "(empty)")"
    tprintf "  %-20s  networks: %s\n" "$g" "$members"
  done
}

# ============================================================
# v3.0 NEW: SMART PICKERS
# ============================================================

choose_port_or_group_field() {
  local side="${1:-destination}" cur="${2:-}"
  local port_groups=(); load_array port_groups scan_port_groups

  tprint ""; tprint "--- $side port: current='${cur:-(none)}' ---"

  if [ "${#port_groups[@]}" -gt 0 ]; then
    tprint "Available port groups:"; print_port_groups_inline; tprint ""
    select_from_list_default "Input type for $side port" "plain port" \
      "plain port" "port group" "delete / clear" || { echo ""; return 0; }
  else
    tprint "(no port groups defined — plain port only)"
    select_from_list_default "Input type for $side port" "plain port" \
      "plain port" "delete / clear" || { echo ""; return 0; }
  fi

  case "$SELECTED" in
    "plain port")
      local val; val="$(ask "$side port or range (e.g. 443 or 8000-8080)" "")"
      [ -z "$val" ] && { echo ""; return 0; }
      if ! is_valid_port_or_range "$val"; then tprint "ERROR: Invalid port."; pause; echo ""; return 0; fi
      echo "plain:$val" ;;
    "port group")
      tprint ""; tprint "Available port groups:"; print_port_groups_inline; tprint ""
      select_from_list "Select port group for $side port" "${port_groups[@]}" || { echo ""; return 0; }
      echo "group:$SELECTED" ;;
    "delete / clear") echo "delete" ;;
    *) echo "" ;;
  esac
}

# v3.1: choose_addr_or_group_field now accepts hostname input for plain IPv4/CIDR
choose_addr_or_group_field() {
  local side="${1:-destination}" cur="${2:-}"
  local addr_groups=() net_groups=()
  load_array addr_groups scan_address_groups
  load_array net_groups  scan_network_groups

  local has_groups=0
  { [ "${#addr_groups[@]}" -gt 0 ] || [ "${#net_groups[@]}" -gt 0 ]; } && has_groups=1

  tprint ""; tprint "--- $side address: current='${cur:-(none)}' ---"

  local choices=("plain IPv4/CIDR or hostname")
  [ "${#addr_groups[@]}" -gt 0 ] && choices+=("address group")
  [ "${#net_groups[@]}"  -gt 0 ] && choices+=("network group")
  choices+=("delete / clear")

  if [ "$has_groups" -eq 1 ]; then
    tprint "Available address groups:"; print_address_groups_inline
    tprint "Available network groups:"; print_network_groups_inline; tprint ""
  else
    tprint "(no address/network groups defined — plain IP/hostname only)"
  fi

  select_from_list_default "Input type for $side address" "plain IPv4/CIDR or hostname" \
    "${choices[@]}" || { echo ""; return 0; }

  case "$SELECTED" in
    "plain IPv4/CIDR or hostname")
      local val; val="$(ask_ip_or_hostname "$side address" "")"
      [ -z "$val" ] && { echo ""; return 0; }
      echo "plain:$val" ;;
    "address group")
      tprint ""; print_address_groups_inline; tprint ""
      select_from_list "Select address group for $side" "${addr_groups[@]}" || { echo ""; return 0; }
      echo "addrgroup:$SELECTED" ;;
    "network group")
      tprint ""; print_network_groups_inline; tprint ""
      select_from_list "Select network group for $side" "${net_groups[@]}" || { echo ""; return 0; }
      echo "netgroup:$SELECTED" ;;
    "delete / clear") echo "delete" ;;
    *) echo "" ;;
  esac
}

apply_port_picker_result() {
  local type="$1" rs="$2" n="$3" side="$4" result="$5"
  [ -z "$result" ] && return 0
  local prefix val; prefix="${result%%:*}"; val="${result#*:}"
  case "$type" in
    firewall)
      case "$prefix" in
        plain)  cfg_set    firewall ipv4 name "$rs" rule "$n" "$side" port "$val" ;;
        group)  cfg_delete firewall ipv4 name "$rs" rule "$n" "$side" port 2>/dev/null || true
                cfg_set    firewall ipv4 name "$rs" rule "$n" "$side" group port-group "$val" ;;
        delete) cfg_delete firewall ipv4 name "$rs" rule "$n" "$side" port            2>/dev/null || true
                cfg_delete firewall ipv4 name "$rs" rule "$n" "$side" group port-group 2>/dev/null || true ;;
      esac ;;
    nat)
      case "$prefix" in
        plain)  cfg_set    nat "$rs" rule "$n" "$side" port "$val" ;;
        group)  cfg_delete nat "$rs" rule "$n" "$side" port             2>/dev/null || true
                cfg_set    nat "$rs" rule "$n" "$side" group port-group "$val" ;;
        delete) cfg_delete nat "$rs" rule "$n" "$side" port             2>/dev/null || true
                cfg_delete nat "$rs" rule "$n" "$side" group port-group 2>/dev/null || true ;;
      esac ;;
  esac
}

apply_addr_picker_result() {
  local type="$1" rs="$2" n="$3" side="$4" result="$5"
  [ -z "$result" ] && return 0
  local prefix val; prefix="${result%%:*}"; val="${result#*:}"
  case "$type" in
    firewall)
      case "$prefix" in
        plain)     cfg_delete firewall ipv4 name "$rs" rule "$n" "$side" group address-group 2>/dev/null || true
                   cfg_delete firewall ipv4 name "$rs" rule "$n" "$side" group network-group 2>/dev/null || true
                   cfg_set    firewall ipv4 name "$rs" rule "$n" "$side" address "$val" ;;
        addrgroup) cfg_delete firewall ipv4 name "$rs" rule "$n" "$side" address            2>/dev/null || true
                   cfg_delete firewall ipv4 name "$rs" rule "$n" "$side" group network-group 2>/dev/null || true
                   cfg_set    firewall ipv4 name "$rs" rule "$n" "$side" group address-group "$val" ;;
        netgroup)  cfg_delete firewall ipv4 name "$rs" rule "$n" "$side" address             2>/dev/null || true
                   cfg_delete firewall ipv4 name "$rs" rule "$n" "$side" group address-group 2>/dev/null || true
                   cfg_set    firewall ipv4 name "$rs" rule "$n" "$side" group network-group "$val" ;;
        delete)    cfg_delete firewall ipv4 name "$rs" rule "$n" "$side" address             2>/dev/null || true
                   cfg_delete firewall ipv4 name "$rs" rule "$n" "$side" group address-group 2>/dev/null || true
                   cfg_delete firewall ipv4 name "$rs" rule "$n" "$side" group network-group 2>/dev/null || true ;;
      esac ;;
    nat)
      case "$prefix" in
        plain)     cfg_delete nat "$rs" rule "$n" "$side" group address-group 2>/dev/null || true
                   cfg_delete nat "$rs" rule "$n" "$side" group network-group 2>/dev/null || true
                   cfg_set    nat "$rs" rule "$n" "$side" address "$val" ;;
        addrgroup) cfg_delete nat "$rs" rule "$n" "$side" address            2>/dev/null || true
                   cfg_delete nat "$rs" rule "$n" "$side" group network-group 2>/dev/null || true
                   cfg_set    nat "$rs" rule "$n" "$side" group address-group "$val" ;;
        netgroup)  cfg_delete nat "$rs" rule "$n" "$side" address             2>/dev/null || true
                   cfg_delete nat "$rs" rule "$n" "$side" group address-group 2>/dev/null || true
                   cfg_set    nat "$rs" rule "$n" "$side" group network-group "$val" ;;
        delete)    cfg_delete nat "$rs" rule "$n" "$side" address             2>/dev/null || true
                   cfg_delete nat "$rs" rule "$n" "$side" group address-group 2>/dev/null || true
                   cfg_delete nat "$rs" rule "$n" "$side" group network-group 2>/dev/null || true ;;
      esac ;;
  esac
}

# ============================================================
# ZONE HELPERS
# ============================================================

get_unassigned_real_ifaces() {
  if [ "$_CFG_CACHE_VALID" -eq 0 ]; then cfg_cache_refresh || return 1; fi
  local all=() assigned=() result=()
  load_array all scan_all_ifaces
  local zi z i
  while IFS='|' read -r z i; do [ -n "$i" ] && assigned+=("$i"); done < <(scan_zone_ifaces)
  local iface
  for iface in "${all[@]}"; do
    echo "$iface" | grep -Eq '^lo[0-9]*$' && continue
    is_in_list "$iface" "${assigned[@]}" && continue
    result+=("$iface")
  done
  printf '%s\n' "${result[@]}"
}

zone_create_single_interface() {
  local zones=() zname yn zone_type default_action
  cfg_cache_refresh || return 0
  load_array zones scan_fw_zones
  tprint ""; tprint "Existing zones: ${zones[*]:-(none)}"; tprint ""
  select_from_list_default "Zone type" "normal" "normal" "local-zone (router self)" || return 0
  case "$SELECTED" in "local-zone (router self)") zone_type="local" ;; *) zone_type="normal" ;; esac
  local iface=""
  if [ "$zone_type" = "normal" ]; then
    local unassigned_ifaces=(); load_array unassigned_ifaces get_unassigned_real_ifaces
    require_nonempty_list_or_return "unassigned real interfaces" "${unassigned_ifaces[@]}" || return 0
    select_from_list "Select interface for new zone" "${unassigned_ifaces[@]}" || return 0
    iface="$SELECTED"
  fi
  [ "$zone_type" = "local" ] && zname="$(ask "Local zone name" "")" || zname="$(ask "Zone name for $iface" "")"
  [ -z "$zname" ] && return 0
  if ! is_safe_ruleset_name "$zname"; then tprint "ERROR: Invalid zone name."; pause; return 0; fi
  if is_in_list "$zname" "${zones[@]}"; then tprint "ERROR: Zone '$zname' already exists."; pause; return 0; fi
  select_from_list_default "Default action for $zname" "drop" "drop" "accept" "reject" || return 0
  default_action="$SELECTED"
  tprint ""
  [ "$zone_type" = "local" ] && tprint "SUMMARY: local-zone '$zname' default-action=$default_action" \
    || tprint "SUMMARY: zone '$zname' interface=$iface default-action=$default_action"
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  if [ "$zone_type" = "local" ]; then
    cfg_set firewall zone "$zname" local-zone
    cfg_set firewall zone "$zname" default-action "$default_action"
  else
    cfg_set firewall zone "$zname" default-action "$default_action"
    cfg_set firewall zone "$zname" member interface "$iface"
  fi
  cfg_apply
}

zone_create_batch_from_interfaces() {
  cfg_cache_refresh || return 0
  local unassigned_ifaces=() yn; load_array unassigned_ifaces get_unassigned_real_ifaces
  require_nonempty_list_or_return "unassigned real interfaces" "${unassigned_ifaces[@]}" || return 0
  tprint ""; tprint "Found ${#unassigned_ifaces[@]} unassigned real interfaces:"
  printf '%s\n' "${unassigned_ifaces[@]}" | awk '{print "  - " $0}' >"$TTY"
  tprint ""; tprint "Leave zone name blank to skip an interface."; tprint ""
  local existing_zones=(); load_array existing_zones scan_fw_zones
  local created_zones=() batch_ifaces=() batch_znames=() batch_actions=()
  local iface zname default_action
  for iface in "${unassigned_ifaces[@]}"; do
    tprint ""; tprint "--- Interface: $iface ---"
    zname="$(ask "Zone name for $iface (blank to skip)" "")"
    [ -z "$zname" ] && { tprint "Skipped $iface."; continue; }
    if ! is_safe_ruleset_name "$zname"; then tprint "ERROR: Invalid. Skipping."; continue; fi
    if is_in_list "$zname" "${existing_zones[@]}" || is_in_list "$zname" "${created_zones[@]}"; then
      tprint "ERROR: Zone '$zname' already used. Skipping."; continue
    fi
    select_from_list_default "Default action for $zname" "drop" "drop" "accept" "reject" || { tprint "Skipped."; continue; }
    default_action="$SELECTED"
    tprint "Queued: zone '$zname' interface=$iface default-action=$default_action"
    batch_ifaces+=("$iface"); batch_znames+=("$zname"); batch_actions+=("$default_action"); created_zones+=("$zname")
  done
  [ "${#batch_znames[@]}" -eq 0 ] && { tprint ""; tprint "Nothing to create."; pause; return 0; }
  tprint ""; tprint "=== Batch Summary ==="
  local idx
  for idx in "${!batch_znames[@]}"; do
    tprintf "  zone %-16s  interface=%-12s  default-action=%s\n" "${batch_znames[$idx]}" "${batch_ifaces[$idx]}" "${batch_actions[$idx]}"
  done
  tprint ""
  yn="$(choose_yes_no "Create all zones above?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  for idx in "${!batch_znames[@]}"; do
    cfg_set firewall zone "${batch_znames[$idx]}" default-action "${batch_actions[$idx]}"
    cfg_set firewall zone "${batch_znames[$idx]}" member interface "${batch_ifaces[$idx]}"
  done
  cfg_apply; tprint "Batch zone creation complete."; pause
}

# ============================================================
# INTERFACE MENU
# ============================================================
_iface_choose() {
  local label="${1:-Select interface}"; local all=()
  load_array all scan_all_ifaces
  require_nonempty_list_or_return "interfaces" "${all[@]}" || return 1
  select_from_list "$label" "${all[@]}" && echo "$SELECTED" && return 0; return 1
}

# v3.1: accepts hostname or CIDR
iface_op_set_ip() {
  local iface addrs=() new_ip yn
  iface="$(_iface_choose "Select interface — add/change IP")" || return 0
  load_array addrs scan_iface_addresses "$iface"
  tprint ""; tprint "Current addresses on $iface: ${addrs[*]:-(none)}"
  new_ip="$(ask_cidr_or_hostname "New address for $iface" "")"
  [ -z "$new_ip" ] && return 0
  if is_in_list "$new_ip" "${addrs[@]}"; then tprint "ERROR: $new_ip already configured."; pause; return 0; fi
  tprint ""; tprint "SUMMARY: $iface add address $new_ip"
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; iface_cfg_set "$iface" address "$new_ip"; cfg_apply
}

iface_op_delete_ip() {
  local iface addrs=() target yn
  iface="$(_iface_choose "Select interface — delete IP")" || return 0
  load_array addrs scan_iface_addresses "$iface"
  require_nonempty_list_or_return "addresses on $iface" "${addrs[@]}" || return 0
  select_from_list "Select address to DELETE" "${addrs[@]}" || return 0; target="$SELECTED"
  tprint ""; tprint "Delete: $target from $iface"
  yn="$(choose_yes_no "Proceed?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; iface_cfg_delete "$iface" address "$target"; cfg_apply
}

iface_op_set_description() {
  local iface cur_desc new_desc yn
  iface="$(_iface_choose "Select interface — set description")" || return 0
  cur_desc="$(get_iface_description "$iface")"
  tprint ""; tprint "Current description: ${cur_desc:-(none)}"
  new_desc="$(ask "New description (blank to delete)" "")"
  [ -n "$new_desc" ] && ! is_safe_free_text "$new_desc" && { tprint "ERROR: Unsupported characters."; pause; return 0; }
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  [ -z "$new_desc" ] && iface_cfg_delete "$iface" description || iface_cfg_set "$iface" description "$new_desc"
  cfg_apply
}

iface_op_enable_disable() {
  local iface yn
  iface="$(_iface_choose "Select interface — enable or disable")" || return 0
  tprint ""
  if iface_is_disabled "$iface"; then
    tprint "$iface is: DISABLED"
    yn="$(choose_yes_no "Enable $iface?" "y" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; iface_cfg_delete "$iface" disable
  else
    tprint "$iface is: ENABLED"
    yn="$(choose_yes_no "Disable $iface?" "n" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; iface_cfg_set "$iface" disable
  fi
  cfg_apply
}

iface_op_show_details() {
  local iface; iface="$(_iface_choose "Select interface — show details")" || return 0
  local r t p v
  r="$(resolve_iface_path "$iface")"
  t="$(echo "$r"|cut -d'|' -f1)" p="$(echo "$r"|cut -d'|' -f2)" v="$(echo "$r"|cut -d'|' -f3)"
  tprint ""; tprint "=== $iface ==="; tprint "--- Config ---"; tprint "--------------------------------------------------------"
  if [ -n "$v" ]; then
    grep_cfg "set interfaces $t $p vif $v " >"$TTY" 2>/dev/null || true
  else
    grep_cfg "set interfaces $t $p " >"$TTY" 2>/dev/null || true
  fi
  tprint "--------------------------------------------------------"; tprint ""
  tprint "  Addresses:   $(scan_iface_addresses "$iface" | join_lines || echo "(none)")"
  tprint "  Description: $(get_iface_description "$iface" || echo "(none)")"
  iface_is_disabled "$iface" && tprint "  Admin state: DISABLED" || tprint "  Admin state: enabled"
  tprint ""; tprint "--- Operational ---"; tprint "--------------------------------------------------------"
  run show interfaces "$t" "$p" >"$TTY" 2>&1 || run show interfaces >"$TTY" 2>&1 || true
  tprint "--------------------------------------------------------"; pause
}

iface_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "=========================="; tprint " Interfaces"; tprint "=========================="
    _iface_summary; tprint ""
    tprint "1) Set / add IP address"
    tprint "2) Delete IP address"
    tprint "3) Set description"
    tprint "4) Enable / disable interface"
    tprint "5) Show interface details"
    tprint "6) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) iface_op_set_ip ;; 2) iface_op_delete_ip ;; 3) iface_op_set_description ;;
      4) iface_op_enable_disable ;; 5) iface_op_show_details ;; 6) return 0 ;; *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# FIREWALL RULES
# ============================================================
fw_choose_ruleset_existing_only() {
  local arr=(); load_array arr scan_firewall_rulesets
  require_nonempty_list_or_return "firewall rulesets" "${arr[@]}" || return 1
  select_from_list "Select ruleset" "${arr[@]}" && echo "$SELECTED" && return 0; return 1
}

fw_choose_ruleset_or_new() {
  local arr=(); load_array arr scan_firewall_rulesets
  if [ "${#arr[@]}" -gt 0 ]; then
    if select_from_list "Select ruleset (or cancel to type new name)" "${arr[@]}"; then echo "$SELECTED"; return 0; fi
  fi
  local rs; rs="$(ask "Ruleset name (e.g. DMZ-to-LAN)" "")"
  [ -z "$rs" ] && return 1
  if ! is_safe_ruleset_name "$rs"; then tprint "ERROR: Invalid ruleset name."; pause; return 1; fi
  echo "$rs"
}

fw_choose_rule_number_existing() {
  local rs="$1" arr=(); load_array arr scan_firewall_rule_numbers "$rs"
  require_nonempty_list_or_return "rules in $rs" "${arr[@]}" || return 1
  select_from_list "Select existing rule number in $rs" "${arr[@]}" && echo "$SELECTED" && return 0; return 1
}

fw_choose_rule_number_new_only() {
  local rs="$1" used=() suggested n
  load_array used scan_firewall_rule_numbers "$rs"
  suggested="$(next_free_rule_number "${used[@]}")"
  tprint ""; tprint "Existing rules in $rs: ${used[*]:-(none)}"; tprint "Next free: $suggested"; tprint ""
  while true; do
    n="$(ask "New rule number" "$suggested")"
    [ -z "$n" ] && { tprint "Required."; continue; }
    require_numeric "$n" || { tprint "ERROR: must be a number."; continue; }
    is_number_in_list "$n" "${used[@]}" && { tprint "ERROR: rule $n exists."; continue; }
    break
  done
  echo "$n"
}

fw_preview_rule() {
  local rs="$1" n="$2"
  tprint ""; tprint "Current config — $rs rule $n:"; tprint "--------------------------------------------------------"
  grep_cfg "set firewall ipv4 name '$rs' rule $n " >"$TTY" 2>/dev/null || true
  grep_cfg "set firewall ipv4 name $rs rule $n "   >>"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"; tprint ""
}

fw_list_ruleset() {
  local rs; rs="$(fw_choose_ruleset_existing_only)" || return 0
  tprint ""; tprint "Ruleset: $rs"; tprint "--------------------------------------------------------"
  grep_cfg "set firewall ipv4 name '$rs' " >"$TTY" 2>/dev/null || true
  grep_cfg "set firewall ipv4 name $rs "   >>"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"; pause
}

fw_add_rule_guided_safe() {
  local rs n action proto desc yn
  local saddr_result="" daddr_result="" sport_result="" dport_result=""
  local state_est state_rel state_new

  tprint ""; tprint "ADD firewall rule (safe — new rule number only)"
  rs="$(fw_choose_ruleset_or_new)" || return 0
  n="$(fw_choose_rule_number_new_only "$rs")" || return 0
  tprint ""; tprint "Creating: $rs rule $n — fill optional fields or leave blank."
  action="$(choose_fw_action "accept")" || return 0
  proto="$(choose_fw_protocol "tcp")"   || return 0
  desc="$(ask "Description (optional)" "")"
  [ -n "$desc" ] && ! is_safe_free_text "$desc" && { tprint "ERROR: Invalid description."; pause; return 0; }

  saddr_result="$(choose_addr_or_group_field "source" "")"
  daddr_result="$(choose_addr_or_group_field "destination" "")"
  sport_result="$(choose_port_or_group_field "source" "")"
  dport_result="$(choose_port_or_group_field "destination" "")"

  state_est="$(choose_yes_no "Match ESTABLISHED?" "n" || echo "n")"
  state_rel="$(choose_yes_no "Match RELATED?"     "n" || echo "n")"
  state_new="$(choose_yes_no "Match NEW?"         "n" || echo "n")"

  tprint ""; tprint "SUMMARY: $rs rule $n  action=$action  proto=$proto"
  [ -n "$saddr_result" ] && tprint "  src-addr:  $saddr_result"
  [ -n "$sport_result" ] && tprint "  src-port:  $sport_result"
  [ -n "$daddr_result" ] && tprint "  dst-addr:  $daddr_result"
  [ -n "$dport_result" ] && tprint "  dst-port:  $dport_result"
  [ -n "$desc"         ] && tprint "  desc:      $desc"
  tprint ""
  yn="$(choose_yes_no "Create this rule?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  local existing_rs=(); load_array existing_rs scan_firewall_rulesets
  if ! is_in_list "$rs" "${existing_rs[@]}"; then
    tprint "New ruleset '$rs' — setting default-action drop."
    cfg_set firewall ipv4 name "$rs" default-action drop
  fi
  cfg_set firewall ipv4 name "$rs" rule "$n" action "$action"
  [ -n "$desc"  ] && cfg_set firewall ipv4 name "$rs" rule "$n" description "$desc"
  [ -n "$proto" ] && [ "$proto" != "any" ] && cfg_set firewall ipv4 name "$rs" rule "$n" protocol "$proto"
  [ -n "$saddr_result" ] && apply_addr_picker_result firewall "$rs" "$n" source      "$saddr_result"
  [ -n "$daddr_result" ] && apply_addr_picker_result firewall "$rs" "$n" destination "$daddr_result"
  [ -n "$sport_result" ] && apply_port_picker_result firewall "$rs" "$n" source      "$sport_result"
  [ -n "$dport_result" ] && apply_port_picker_result firewall "$rs" "$n" destination "$dport_result"
  { [ "$state_est" = "y" ] || [ "$state_est" = "Y" ]; } && cfg_set firewall ipv4 name "$rs" rule "$n" state established
  { [ "$state_rel" = "y" ] || [ "$state_rel" = "Y" ]; } && cfg_set firewall ipv4 name "$rs" rule "$n" state related
  { [ "$state_new" = "y" ] || [ "$state_new" = "Y" ]; } && cfg_set firewall ipv4 name "$rs" rule "$n" state new
  cfg_apply
}

fw_update_single_field() {
  local rs n field yn
  local fields=("action" "description" "protocol" "source address" "source port"
                "destination address" "destination port"
                "state established" "state related" "state new" "back")
  rs="$(fw_choose_ruleset_existing_only)" || return 0
  n="$(fw_choose_rule_number_existing "$rs")" || return 0
  fw_preview_rule "$rs" "$n"
  select_from_list "Select field to update" "${fields[@]}" || return 0
  field="$SELECTED"; [ "$field" = "back" ] && return 0

  case "$field" in
    action)
      local val; val="$(choose_fw_action "accept")" || return 0
      cfg_begin || return 0; cfg_set firewall ipv4 name "$rs" rule "$n" action "$val"; cfg_apply ;;
    protocol)
      local val; val="$(choose_fw_protocol "tcp")" || return 0
      cfg_begin || return 0
      [ "$val" = "any" ] && cfg_delete firewall ipv4 name "$rs" rule "$n" protocol \
                         || cfg_set   firewall ipv4 name "$rs" rule "$n" protocol "$val"
      cfg_apply ;;
    description)
      tprint "Leave blank to DELETE."; local val; val="$(ask "New description" "")"
      [ -n "$val" ] && ! is_safe_free_text "$val" && { tprint "ERROR."; pause; return 0; }
      cfg_begin || return 0
      [ -z "$val" ] && cfg_delete firewall ipv4 name "$rs" rule "$n" description \
                    || cfg_set   firewall ipv4 name "$rs" rule "$n" description "$val"
      cfg_apply ;;
    "source address")
      local result; result="$(choose_addr_or_group_field "source" "")"
      [ -z "$result" ] && return 0
      cfg_begin || return 0; apply_addr_picker_result firewall "$rs" "$n" source "$result"; cfg_apply ;;
    "destination address")
      local result; result="$(choose_addr_or_group_field "destination" "")"
      [ -z "$result" ] && return 0
      cfg_begin || return 0; apply_addr_picker_result firewall "$rs" "$n" destination "$result"; cfg_apply ;;
    "source port")
      local result; result="$(choose_port_or_group_field "source" "")"
      [ -z "$result" ] && return 0
      cfg_begin || return 0; apply_port_picker_result firewall "$rs" "$n" source "$result"; cfg_apply ;;
    "destination port")
      local result; result="$(choose_port_or_group_field "destination" "")"
      [ -z "$result" ] && return 0
      cfg_begin || return 0; apply_port_picker_result firewall "$rs" "$n" destination "$result"; cfg_apply ;;
    "state established"|"state related"|"state new")
      local st="${field#state }"
      yn="$(choose_yes_no "Enable this state match?" "y" || echo "n")"
      cfg_begin || return 0
      [ "$yn" = "y" ] && cfg_set   firewall ipv4 name "$rs" rule "$n" state "$st" \
                      || cfg_delete firewall ipv4 name "$rs" rule "$n" state "$st"
      cfg_apply ;;
    *) tprint "Invalid."; pause ;;
  esac
}

fw_delete_rule() {
  local rs n yn
  rs="$(fw_choose_ruleset_existing_only)" || return 0
  n="$(fw_choose_rule_number_existing "$rs")" || return 0
  fw_preview_rule "$rs" "$n"
  yn="$(choose_yes_no "Delete rule $n from $rs?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete firewall ipv4 name "$rs" rule "$n"; cfg_apply
}

# ============================================================
# v3.0 NEW: PORT GROUP MANAGEMENT
# ============================================================

pg_add_ports_loop() {
  local token
  while true; do
    tread token "  Add port or range (blank = done): " || break
    [ -z "$token" ] && break
    if is_valid_port_or_range "$token"; then echo "$token"
    else tprint "  ERROR: '$token' invalid (1-65535 or range lo-hi). Try again."; fi
  done
}

pg_add_ports_csv() {
  local raw token
  tread raw "  Enter ports/ranges comma-separated (e.g. 80,443,8000-8080): " || return 0
  [ -z "$raw" ] && return 0
  printf "%s" "$raw" | tr ',' '\n' | while IFS= read -r token; do
    token="$(printf "%s" "$token" | tr -d ' ')"
    [ -z "$token" ] && continue
    if is_valid_port_or_range "$token"; then echo "$token"
    else tprint "  ERROR: '$token' invalid — skipped."; fi
  done
}

pg_collect_ports() {
  tprint ""
  select_from_list_default "How do you want to add ports?" "one at a time" \
    "one at a time" "comma-separated list" || return 0
  case "$SELECTED" in
    "one at a time")         tprint "  (blank line = done)"; pg_add_ports_loop ;;
    "comma-separated list")  pg_add_ports_csv ;;
  esac
}

pg_list_all() {
  local groups=(); load_array groups scan_port_groups
  tprint ""; tprint "=== Port Groups ==="
  [ "${#groups[@]}" -eq 0 ] && tprint "  (none defined)" || print_port_groups_inline
  tprint ""; pause
}

pg_create_safe() {
  local existing=() name ports=() yn
  load_array existing scan_port_groups
  tprint ""; tprint "=== Create Port Group ==="
  tprint "Existing groups: ${existing[*]:-(none)}"; tprint ""
  name="$(ask "New group name (e.g. WEB-PORTS, AD-TCP)" "")"
  [ -z "$name" ] && return 0
  if ! is_safe_ruleset_name "$name"; then tprint "ERROR: Invalid name."; pause; return 0; fi
  if is_in_list "$name" "${existing[@]}"; then tprint "ERROR: '$name' already exists. Use Edit."; pause; return 0; fi
  tprint ""; tprint "Add ports to group '$name':"
  load_array ports pg_collect_ports
  if [ "${#ports[@]}" -eq 0 ]; then tprint "ERROR: No valid ports entered."; pause; return 0; fi
  tprint ""; tprint "SUMMARY: create port-group '$name'  ports: ${ports[*]}"; tprint ""
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  local p; for p in "${ports[@]}"; do cfg_set firewall group port-group "$name" port "$p"; done
  cfg_apply
}

pg_edit_members() {
  local existing=() grp members=() yn
  load_array existing scan_port_groups
  require_nonempty_list_or_return "port groups" "${existing[@]}" || return 0
  tprint ""; tprint "=== Edit Port Group Members ==="
  tprint "Groups:"; print_port_groups_inline; tprint ""
  select_from_list "Select port group to edit" "${existing[@]}" || return 0
  grp="$SELECTED"
  load_array members scan_port_group_members "$grp"
  tprint ""; tprint "Current members of '$grp': ${members[*]:-(empty)}"; tprint ""
  select_from_list_default "Edit action" "add ports" "add ports" "remove a port" || return 0

  case "$SELECTED" in
    "add ports")
      local new_ports=(); tprint ""; tprint "Add ports to '$grp':"
      load_array new_ports pg_collect_ports
      [ "${#new_ports[@]}" -eq 0 ] && { tprint "No ports entered."; pause; return 0; }
      local to_add=() p
      for p in "${new_ports[@]}"; do
        is_in_list "$p" "${members[@]}" && { tprint "  NOTE: '$p' already in group — skipped."; continue; }
        to_add+=("$p")
      done
      [ "${#to_add[@]}" -eq 0 ] && { tprint "All ports already exist."; pause; return 0; }
      tprint ""; tprint "SUMMARY: add to '$grp': ${to_add[*]}"
      yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
      [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
      cfg_begin || return 0
      for p in "${to_add[@]}"; do cfg_set firewall group port-group "$grp" port "$p"; done
      cfg_apply ;;

    "remove a port")
      require_nonempty_list_or_return "ports in '$grp'" "${members[@]}" || return 0
      select_from_list "Select port to REMOVE from '$grp'" "${members[@]}" || return 0
      local target="$SELECTED"
      tprint ""; tprint "SUMMARY: remove port '$target' from group '$grp'"
      [ "${#members[@]}" -le 1 ] && tprint "WARNING: Last port — group will be empty after removal."
      yn="$(choose_yes_no "Proceed?" "n" || echo "n")"
      [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
      cfg_begin || return 0; cfg_delete firewall group port-group "$grp" port "$target"; cfg_apply ;;
  esac
}

pg_delete_safe() {
  local existing=() grp yn
  load_array existing scan_port_groups
  require_nonempty_list_or_return "port groups" "${existing[@]}" || return 0
  tprint ""; tprint "=== Delete Port Group ==="
  tprint "Groups:"; print_port_groups_inline; tprint ""
  select_from_list "Select port group to DELETE" "${existing[@]}" || return 0
  grp="$SELECTED"
  local refs
  refs="$(grep_cfg "port-group '$grp'" | grep -v "set firewall group" | head -n 5 || true)"
  [ -z "$refs" ] && refs="$(grep_cfg "port-group $grp" | grep -v "set firewall group" | head -n 5 || true)"
  tprint ""
  if [ -n "$refs" ]; then
    tprint "WARNING: '$grp' is referenced in rules:"; printf "%s\n" "$refs" >"$TTY"
    tprint "Deleting it will leave broken group references."; tprint ""
  fi
  tprint "DELETE port-group: $grp  (ports: $(scan_port_group_members "$grp" | join_lines || echo empty))"; tprint ""
  yn="$(choose_yes_no "Proceed?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete firewall group port-group "$grp"; cfg_apply
}

port_group_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "=============================="; tprint " Port Group Management"; tprint "=============================="
    tprint "Groups:"; print_port_groups_inline; tprint ""
    tprint "1) List all port groups (detailed)"
    tprint "2) Create port group"
    tprint "3) Edit group members (add / remove ports)"
    tprint "4) Delete port group"
    tprint "5) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) pg_list_all ;; 2) pg_create_safe ;; 3) pg_edit_members ;;
      4) pg_delete_safe ;; 5) return 0 ;; *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# ZONE BINDINGS + ZONE MANAGEMENT
# ============================================================
scan_zone_ifaces() {
  grep_cfg "set firewall zone " | grep -F " member interface " \
    | awk '{print $4 "|" $7}' \
    | while IFS='|' read -r z i; do echo "$(strip_quotes "$z")|$(strip_quotes "$i")"; done | sort -u
}
scan_zone_default_action() {
  local zone="$1"
  grep_cfg "set firewall zone $zone default-action " | awk '{print $NF}' | head -n 1 | while read -r x; do strip_quotes "$x"; done
}
zone_list_full() {
  local zones=(); load_array zones scan_fw_zones
  if [ "${#zones[@]}" -eq 0 ]; then tprint "(no zones defined)"; pause; return 0; fi
  tprint ""; tprint "=== Zones ==="
  local z da ifaces
  for z in "${zones[@]}"; do
    da="$(scan_zone_default_action "$z" || echo -)"
    ifaces="$(scan_zone_ifaces | awk -F'|' -v z="$z" '$1==z{print $2}' | tr '\n' ' ' || echo -)"
    tprintf "  %-16s  default-action=%-8s  interfaces=%s\n" "$z" "${da:-(none)}" "${ifaces:-(none)}"
  done
  tprint ""; tprint "=== Bindings (TO <- FROM = RULESET) ==="
  local b=(); load_array b scan_zone_bindings
  if [ "${#b[@]}" -gt 0 ]; then
    printf "%s\n" "${b[@]}" | awk -F'|' '{printf "  %-12s <- %-12s  =  %s\n",$1,$2,$3}' >"$TTY"
  else tprint "  (none)"; fi
  pause
}
zone_is_local_zone() {
  local z="$1"
  { grep_cfg "set firewall zone $z local-zone"; grep_cfg "set firewall zone '$z' local-zone"; } | grep -q . 2>/dev/null
}
zone_has_members() { local z="$1"; scan_zone_ifaces | grep -qF "$z|" 2>/dev/null; }
zone_delete_safe() {
  local zones=() target yn bindings=()
  load_array zones scan_fw_zones
  require_nonempty_list_or_return "firewall zones" "${zones[@]}" || return 0
  select_from_list "Select zone to DELETE" "${zones[@]}" || return 0; target="$SELECTED"
  load_array bindings scan_zone_bindings
  local refs=() b; for b in "${bindings[@]}"; do echo "$b" | grep -qF "$target" && refs+=("$b"); done
  tprint ""
  if [ "${#refs[@]}" -gt 0 ]; then
    tprint "WARNING: The following bindings reference '$target' and will also be deleted:"
    local r; for r in "${refs[@]}"; do tprint "  $r"; done; tprint ""
  fi
  tprint "About to DELETE zone: $target"
  yn="$(choose_yes_no "Proceed?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete firewall zone "$target"; cfg_apply
}
zone_assign_interface() {
  local zones=() zname ifaces=() cur_ifaces=() yn
  load_array zones scan_fw_zones
  require_nonempty_list_or_return "firewall zones" "${zones[@]}" || return 0
  select_from_list "Select zone to assign interface to" "${zones[@]}" || return 0; zname="$SELECTED"
  cur_ifaces=()
  local zi; while IFS='|' read -r z i; do [ "$z" = "$zname" ] && cur_ifaces+=("$i"); done < <(scan_zone_ifaces)
  tprint ""; tprint "Current interfaces on $zname: ${cur_ifaces[*]:-(none)}"
  load_array ifaces scan_all_ifaces
  require_nonempty_list_or_return "interfaces" "${ifaces[@]}" || return 0
  select_from_list "Select interface to assign to $zname" "${ifaces[@]}" || return 0; local iface="$SELECTED"
  if is_in_list "$iface" "${cur_ifaces[@]}"; then tprint "ERROR: $iface already assigned."; pause; return 0; fi
  local other_zone; other_zone="$(scan_zone_ifaces | awk -F'|' -v i="$iface" '$2==i{print $1}' | head -n 1 || true)"
  if [ -n "$other_zone" ]; then
    tprint "WARNING: $iface already assigned to zone '$other_zone'."
    yn="$(choose_yes_no "Continue anyway?" "n" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  fi
  yn="$(choose_yes_no "Assign $iface to zone $zname?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set firewall zone "$zname" member interface "$iface"; cfg_apply
}
zone_remove_interface() {
  local zname cur_ifaces=() target yn
  local zones=(); load_array zones scan_fw_zones
  require_nonempty_list_or_return "firewall zones" "${zones[@]}" || return 0
  select_from_list "Select zone to remove interface from" "${zones[@]}" || return 0; zname="$SELECTED"
  cur_ifaces=()
  local zi; while IFS='|' read -r z i; do [ "$z" = "$zname" ] && cur_ifaces+=("$i"); done < <(scan_zone_ifaces)
  require_nonempty_list_or_return "interfaces assigned to $zname" "${cur_ifaces[@]}" || return 0
  select_from_list "Select interface to REMOVE from $zname" "${cur_ifaces[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Remove $target from zone $zname?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete firewall zone "$zname" member interface "$target"; cfg_apply
}
zone_set_default_action() {
  local zones=() zname cur da yn
  load_array zones scan_fw_zones
  require_nonempty_list_or_return "firewall zones" "${zones[@]}" || return 0
  select_from_list "Select zone to update default-action" "${zones[@]}" || return 0; zname="$SELECTED"
  if ! zone_has_members "$zname" && ! zone_is_local_zone "$zname"; then
    tprint ""; tprint "BLOCKED: Cannot set default-action — zone has no interface members."; pause; return 0
  fi
  cur="$(scan_zone_default_action "$zname" || echo -)"
  tprint ""; tprint "Current default-action on $zname: ${cur:-(none set)}"
  select_from_list_default "New default-action" "${cur:-drop}" "drop" "accept" "reject" || return 0; da="$SELECTED"
  yn="$(choose_yes_no "Set $zname default-action to $da?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set firewall zone "$zname" default-action "$da"; cfg_apply
}
zone_set_intrazone_action() {
  local zones=() zname cur yn
  load_array zones scan_fw_zones
  require_nonempty_list_or_return "firewall zones" "${zones[@]}" || return 0
  select_from_list "Select zone to set intra-zone action" "${zones[@]}" || return 0; zname="$SELECTED"
  cur="$(grep_cfg "set firewall zone $zname intra-zone-filtering " | awk '{print $NF}' | head -n 1 | while read -r x; do strip_quotes "$x"; done || echo -)"
  tprint ""; tprint "Current intra-zone-filtering on $zname: ${cur:-(none)}"
  select_from_list_default "Intra-zone traffic action" "${cur:-accept}" "accept" "drop" || return 0
  local action="$SELECTED"
  yn="$(choose_yes_no "Set $zname intra-zone-filtering to $action?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set firewall zone "$zname" intra-zone-filtering action "$action"; cfg_apply
}
zone_choose_existing() {
  local zones=(); load_array zones scan_fw_zones
  require_nonempty_list_or_return "firewall zones" "${zones[@]}" || return 1
  select_from_list "Select zone" "${zones[@]}" && echo "$SELECTED" && return 0; return 1
}
zone_binding_preview() {
  tprint ""; tprint "Binding: TO='$1' <- FROM='$2'"; tprint "--------------------------------------------------------"
  grep_cfg "set firewall zone $1 from $2 firewall name " >"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"; tprint ""
}
zone_list_bindings() {
  tprint ""; tprint "Current zone bindings (TO <- FROM = RULESET):"; tprint ""
  local b=(); load_array b scan_zone_bindings
  if [ "${#b[@]}" -eq 0 ]; then tprint "(none found)"; pause; return 0; fi
  printf "%s\n" "${b[@]}" | awk -F'|' '{printf "  %s <- %s   =   %s\n",$1,$2,$3}' >"$TTY"; pause
}
zone_add_binding_safe() {
  local to from ruleset yn
  to="$(zone_choose_existing)"   || return 0
  from="$(zone_choose_existing)" || return 0
  if [ "$to" = "$from" ]; then tprint ""; tprint "ERROR: TO and FROM cannot be the same."; pause; return 0; fi
  if binding_exists "$to" "$from"; then
    tprint ""; tprint "ERROR: Binding already exists."; pause; return 0
  fi
  local rs_arr=(); load_array rs_arr scan_firewall_rulesets
  require_nonempty_list_or_return "firewall rulesets" "${rs_arr[@]}" || return 0
  select_from_list "Select ruleset for binding" "${rs_arr[@]}" || return 0; ruleset="$SELECTED"
  tprint ""; tprint "SUMMARY: $to <- $from  =  $ruleset"
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set firewall zone "$to" from "$from" firewall name "$ruleset"; cfg_apply
}
zone_update_binding_existing() {
  local to from ruleset existing_rs yn
  to="$(zone_choose_existing)"   || return 0
  from="$(zone_choose_existing)" || return 0
  if ! binding_exists "$to" "$from"; then tprint ""; tprint "ERROR: No existing binding."; pause; return 0; fi
  existing_rs="$(binding_get_ruleset "$to" "$from")"
  tprint ""; tprint "Current ruleset: ${existing_rs:-UNKNOWN}"
  local rs_arr=(); load_array rs_arr scan_firewall_rulesets
  require_nonempty_list_or_return "firewall rulesets" "${rs_arr[@]}" || return 0
  select_from_list "Select new ruleset" "${rs_arr[@]}" || return 0; ruleset="$SELECTED"
  tprint ""; tprint "SUMMARY: $to <- $from  OLD=${existing_rs:-UNKNOWN}  NEW=$ruleset"
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set firewall zone "$to" from "$from" firewall name "$ruleset"; cfg_apply
}
zone_delete_binding_existing() {
  local to from existing_rs yn
  to="$(zone_choose_existing)"   || return 0
  from="$(zone_choose_existing)" || return 0
  if ! binding_exists "$to" "$from"; then tprint ""; tprint "ERROR: No existing binding."; pause; return 0; fi
  existing_rs="$(binding_get_ruleset "$to" "$from")"
  tprint ""; tprint "Deleting: $to <- $from  =  ${existing_rs:-UNKNOWN}"
  yn="$(choose_yes_no "Proceed?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete firewall zone "$to" from "$from" firewall name; cfg_apply
}
zone_bindings_menu() {
  while true; do
    tprint ""; tprint "=============================="; tprint " Zone Firewall Bindings"; tprint "=============================="
    tprint "1) List bindings"; tprint "2) ADD binding (safe)"; tprint "3) UPDATE binding"; tprint "4) DELETE binding"; tprint "5) Back"
    local c; tread c "Select menu option #: " || continue
    case "$c" in
      1) zone_list_bindings ;; 2) zone_add_binding_safe ;; 3) zone_update_binding_existing ;;
      4) zone_delete_binding_existing ;; 5) return 0 ;; *) tprint "Invalid." ;;
    esac
  done
}
zone_management_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== Zone Management ======"
    tprint "Zones: $(scan_fw_zones | join_lines || echo NONE)"; tprint ""
    tprint "1) List all zones + bindings"
    tprint "2) Create zone (single interface)"
    tprint "3) Create zones (batch)"
    tprint "4) Delete zone"
    tprint "5) Assign interface to zone"
    tprint "6) Remove interface from zone"
    tprint "7) Set default-action"
    tprint "8) Set intra-zone action"
    tprint "9) Zone bindings (TO/FROM/ruleset)"
    tprint "10) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) zone_list_full ;; 2) zone_create_single_interface ;; 3) zone_create_batch_from_interfaces ;;
      4) zone_delete_safe ;; 5) zone_assign_interface ;; 6) zone_remove_interface ;;
      7) zone_set_default_action ;; 8) zone_set_intrazone_action ;; 9) zone_bindings_menu ;; 10) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# ZONE LOGGING AUDIT
# ============================================================
fw_policy_has_default_log() {
  local policy="$1"
  { grep_cfg "set firewall ipv4 name '$policy' default-log"
    grep_cfg "set firewall ipv4 name $policy default-log"; } | grep -qF "default-log" 2>/dev/null
}
fw_policy_default_action() {
  local policy="$1" val=""
  val="$({ grep_cfg "set firewall ipv4 name $policy default-action "
           grep_cfg "set firewall ipv4 name '$policy' default-action "; } \
         | awk '{print $NF}' | head -n 1 | while read -r x; do strip_quotes "$x"; done)"
  echo "${val:--}"
}
_fw_divider() { awk 'BEGIN{for(i=0;i<60;i++) printf "-"; print ""}' >"$TTY"; }

fw_zone_logging_audit() {
  local policies=() missing=() policy da da_display log_state yn p
  local col_pol=32 col_act=22
  while true; do
    tprint ""; tprint "====== Zone Policy Logging Audit ======"; tprint ""
    tprint "Scanning all ipv4 firewall policies..."; tprint ""
    policies=(); load_array policies scan_firewall_rulesets
    if [ "${#policies[@]}" -eq 0 ]; then tprint "(no ipv4 firewall policies found)"; pause; return 0; fi
    tprintf "  %-${col_pol}s  %-${col_act}s  %s\n" "Policy" "Default-action" "Logging"
    _fw_divider; missing=()
    for policy in "${policies[@]}"; do
      da="$(fw_policy_default_action "$policy")"
      case "$da" in drop) da_display="drop" ;; accept) da_display="accept  <-- WARNING" ;; *) da_display="$da" ;; esac
      if fw_policy_has_default_log "$policy"; then log_state="[OK]   dropped pkts logged"
      else log_state="[MISS] dropped pkts NOT logged"; missing+=("$policy"); fi
      tprintf "  %-${col_pol}s  %-${col_act}s  %s\n" "$policy" "$da_display" "$log_state"
    done
    _fw_divider
    if [ "${#missing[@]}" -eq 0 ]; then
      tprint ""; tprint "  RESULT: All ${#policies[@]} policies have default-log enabled."; tprint ""; pause; return 0
    fi
    tprint ""; tprint "  RESULT: ${#missing[@]} of ${#policies[@]} policies MISSING default-log:"
    for p in "${missing[@]}"; do tprintf "    - %s\n" "$p"; done; tprint ""
    yn="$(choose_yes_no "Enable default-log on all ${#missing[@]} missing policies now?" "y" || echo "n")"
    if [ "$yn" != "y" ]; then
      tprint ""; tprint "Commands to run manually:"; tprint "--------------------------------------------------------"
      for p in "${missing[@]}"; do tprintf "  set firewall ipv4 name '%s' default-log\n" "$p"; done
      tprint "  commit"; tprint "  save"; tprint "--------------------------------------------------------"; pause; return 0
    fi
    cfg_begin || return 0; tprint ""; tprint "Staging default-log commands..."
    local staged=0
    for p in "${missing[@]}"; do
      fw_policy_has_default_log "$p" && { tprintf "  (already set, skipping) %s\n" "$p" >"$TTY"; continue; }
      tprintf "  set firewall ipv4 name '%s' default-log\n" "$p" >"$TTY"
      cfg_set firewall ipv4 name "$p" default-log; staged=$((staged+1))
    done
    tprint ""
    if [ "$staged" -eq 0 ]; then tprint "  NOTE: All already had default-log set."; cfg_end; cfg_cache_invalidate
    else cfg_apply; fi
    tprint ""; tprint "Re-running audit to verify..."
  done
}

firewall_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== Firewall ======"
    _fw_summary; tprint ""
    tprint "1) List ruleset"
    tprint "2) Add rule (safe)"
    tprint "3) Update rule field"
    tprint "4) Delete rule"
    tprint "5) Port Group Management"
    tprint "6) Zone management"
    tprint "7) Zone logging audit"
    tprint "8) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) fw_list_ruleset ;; 2) fw_add_rule_guided_safe ;; 3) fw_update_single_field ;;
      4) fw_delete_rule ;; 5) port_group_menu ;; 6) zone_management_menu ;;
      7) fw_zone_logging_audit ;; 8) return 0 ;; *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# NAT
# ============================================================
nat_choose_type() {
  local def="${1:-destination}"
  tprint ""; tprint "  destination = DNAT / port forwarding"; tprint "  source      = SNAT / masquerade"
  select_from_list_default "NAT type" "$def" "destination" "source" && echo "$SELECTED" && return 0; return 1
}
nat_choose_rule_number_existing() {
  local type="$1" arr=()
  [ "$type" = "destination" ] && load_array arr scan_nat_dest_rules || load_array arr scan_nat_source_rules
  require_nonempty_list_or_return "NAT $type rules" "${arr[@]}" || return 1
  select_from_list "Select existing $type rule" "${arr[@]}" && echo "$SELECTED" && return 0; return 1
}
nat_preview_rule() {
  tprint ""; tprint "NAT $1 rule $2:"; tprint "--------------------------------------------------------"
  grep_cfg "set nat $1 rule $2 " >"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"; tprint ""
}
nat_list() {
  tprint ""; tprint "--- NAT config ---"; tprint "--------------------------------------------------------"
  grep_cfg "set nat " >"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"; pause
}

# v3.1: nat_add_dnat_guided — translation IP accepts hostname
nat_add_dnat_guided() {
  local n desc inif proto yn dport_result="" taddr tport used=() suggested ifs=()
  load_array used scan_nat_dest_rules; suggested="$(next_free_rule_number "${used[@]}")"
  tprint ""; tprint "ADD DNAT rule (safe — new only)"
  tprint "Existing DNAT rules: ${used[*]:-(none)}  |  Next free: $suggested"; tprint ""
  while true; do
    n="$(ask "DNAT rule number" "$suggested")"
    require_numeric "$n" || { tprint "ERROR: must be a number."; continue; }
    is_number_in_list "$n" "${used[@]}" && { tprint "ERROR: rule $n exists."; continue; }
    break
  done
  desc="$(ask "Description" "DNAT")"
  [ -n "$desc" ] && ! is_safe_free_text "$desc" && { tprint "ERROR: Invalid description."; pause; return 0; }
  load_array ifs scan_eth_ifaces
  require_nonempty_list_or_return "ethernet interfaces" "${ifs[@]}" || return 0
  select_from_list "Inbound interface (WAN)" "${ifs[@]}" || return 0; inif="$SELECTED"
  proto="$(choose_tcp_udp "tcp")" || return 0
  tprint ""; tprint "Public (destination) port:"
  dport_result="$(choose_port_or_group_field "destination" "")"
  taddr="$(ask_ip_or_hostname "Inside (translation) IP" "")"
  [ -z "$taddr" ] && { tprint "Translation IP required."; pause; return 0; }
  tport="$(ask "Inside port (single)" "")"
  is_valid_port_or_range "$tport" || { tprint "ERROR: Invalid port."; pause; return 0; }
  tprint ""; tprint "SUMMARY: DNAT rule $n  in=$inif  proto=$proto"
  [ -n "$dport_result" ] && tprint "  dst-port: $dport_result"
  tprint "  translate to: $taddr:$tport  desc=$desc"; tprint ""
  yn="$(choose_yes_no "Create?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set nat destination rule "$n" description "$desc"
  cfg_set nat destination rule "$n" inbound-interface name "$inif"
  cfg_set nat destination rule "$n" protocol "$proto"
  cfg_set nat destination rule "$n" translation address "$taddr"
  cfg_set nat destination rule "$n" translation port "$tport"
  [ -n "$dport_result" ] && apply_port_picker_result nat destination "$n" destination "$dport_result"
  cfg_apply
}

# v3.1: nat_add_snat_guided — translation address accepts hostname
nat_add_snat_guided() {
  local n desc outif proto mode taddr tport yn
  local saddr_result="" daddr_result="" sport_result="" dport_result=""
  local used=() suggested ifs=()
  load_array used scan_nat_source_rules; suggested="$(next_free_rule_number "${used[@]}")"
  tprint ""; tprint "ADD SNAT rule (safe — new only)"
  tprint "Existing SNAT rules: ${used[*]:-(none)}  |  Next free: $suggested"; tprint ""
  while true; do
    n="$(ask "SNAT rule number" "$suggested")"
    require_numeric "$n" || { tprint "ERROR: must be a number."; continue; }
    is_number_in_list "$n" "${used[@]}" && { tprint "ERROR: rule $n exists."; continue; }
    break
  done
  desc="$(ask "Description" "SNAT")"
  [ -n "$desc" ] && ! is_safe_free_text "$desc" && { tprint "ERROR: Invalid description."; pause; return 0; }
  load_array ifs scan_eth_ifaces
  require_nonempty_list_or_return "ethernet interfaces" "${ifs[@]}" || return 0
  select_from_list "Outbound interface (WAN)" "${ifs[@]}" || return 0; outif="$SELECTED"
  tprint ""; tprint "  masquerade = use outbound interface IP"; tprint "  address    = specify a static translation IP or hostname"
  select_from_list_default "Translation mode" "masquerade" "masquerade" "address" || return 0; mode="$SELECTED"
  if [ "$mode" = "masquerade" ]; then taddr="masquerade"
  else
    taddr="$(ask_ip_or_hostname "Translation address" "")"
    [ -z "$taddr" ] && { tprint "Translation address required."; pause; return 0; }
  fi
  proto="$(choose_fw_protocol "any" || true)"; [ -z "$proto" ] && return 0
  saddr_result="$(choose_addr_or_group_field "source" "")"
  daddr_result="$(choose_addr_or_group_field "destination" "")"
  sport_result="$(choose_port_or_group_field "source" "")"
  dport_result="$(choose_port_or_group_field "destination" "")"
  tport="$(ask "Translation port (optional, blank to skip)" "")"
  [ -n "$tport" ] && ! is_valid_port_or_range "$tport" && { tprint "ERROR: Invalid port."; pause; return 0; }
  tprint ""; tprint "SUMMARY: SNAT rule $n  out=$outif  xlat=$taddr  proto=$proto"
  [ -n "$saddr_result" ] && tprint "  src-addr:  $saddr_result"
  [ -n "$sport_result" ] && tprint "  src-port:  $sport_result"
  [ -n "$daddr_result" ] && tprint "  dst-addr:  $daddr_result"
  [ -n "$dport_result" ] && tprint "  dst-port:  $dport_result"
  [ -n "$tport"        ] && tprint "  xlat-port: $tport"; tprint ""
  yn="$(choose_yes_no "Create?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set nat source rule "$n" description "$desc"
  cfg_set nat source rule "$n" outbound-interface name "$outif"
  [ -n "$proto" ] && [ "$proto" != "any" ] && cfg_set nat source rule "$n" protocol "$proto"
  cfg_set nat source rule "$n" translation address "$taddr"
  [ -n "$tport" ] && cfg_set nat source rule "$n" translation port "$tport"
  [ -n "$saddr_result" ] && apply_addr_picker_result nat source "$n" source      "$saddr_result"
  [ -n "$daddr_result" ] && apply_addr_picker_result nat source "$n" destination "$daddr_result"
  [ -n "$sport_result" ] && apply_port_picker_result nat source "$n" source      "$sport_result"
  [ -n "$dport_result" ] && apply_port_picker_result nat source "$n" destination "$dport_result"
  cfg_apply
}

# v3.1: nat_update_single_field — translation address accepts hostname
nat_update_single_field() {
  local type n field yn
  local fields=("description" "protocol" "source address" "source port"
                "destination address" "destination port"
                "inbound-interface name" "outbound-interface name"
                "translation address" "translation port" "back")
  type="$(nat_choose_type)" || return 0; [ -z "$type" ] && return 0
  n="$(nat_choose_rule_number_existing "$type")" || return 0
  nat_preview_rule "$type" "$n"
  select_from_list "Select field to update" "${fields[@]}" || return 0
  field="$SELECTED"; [ "$field" = "back" ] && return 0

  case "$field" in
    description)
      tprint "Leave blank to DELETE."; local val; val="$(ask "New description" "")"
      [ -n "$val" ] && ! is_safe_free_text "$val" && { tprint "ERROR."; pause; return 0; }
      cfg_begin || return 0
      [ -z "$val" ] && cfg_delete nat "$type" rule "$n" description || cfg_set nat "$type" rule "$n" description "$val"
      cfg_apply ;;
    protocol)
      local val; val="$(choose_fw_protocol "tcp")" || return 0
      cfg_begin || return 0
      [ "$val" = "any" ] && cfg_delete nat "$type" rule "$n" protocol || cfg_set nat "$type" rule "$n" protocol "$val"
      cfg_apply ;;
    "source address")
      local result; result="$(choose_addr_or_group_field "source" "")"
      [ -z "$result" ] && return 0; cfg_begin || return 0
      apply_addr_picker_result nat "$type" "$n" source "$result"; cfg_apply ;;
    "destination address")
      local result; result="$(choose_addr_or_group_field "destination" "")"
      [ -z "$result" ] && return 0; cfg_begin || return 0
      apply_addr_picker_result nat "$type" "$n" destination "$result"; cfg_apply ;;
    "source port")
      local result; result="$(choose_port_or_group_field "source" "")"
      [ -z "$result" ] && return 0; cfg_begin || return 0
      apply_port_picker_result nat "$type" "$n" source "$result"; cfg_apply ;;
    "destination port")
      local result; result="$(choose_port_or_group_field "destination" "")"
      [ -z "$result" ] && return 0; cfg_begin || return 0
      apply_port_picker_result nat "$type" "$n" destination "$result"; cfg_apply ;;
    "translation address")
      tprint "Leave blank to DELETE. For SNAT: 'masquerade' is valid. Hostname also accepted."
      local val; val="$(ask_ip_or_hostname "Translation address (or 'masquerade')" "")"
      # Allow 'masquerade' keyword override for SNAT
      if [ -z "$val" ]; then
        local raw_val; tread raw_val "  (or type 'masquerade' / blank to DELETE): " || true
        [ -n "$raw_val" ] && [ "$raw_val" = "masquerade" ] && val="masquerade"
      fi
      cfg_begin || return 0
      [ -z "$val" ] && cfg_delete nat "$type" rule "$n" translation address \
                    || cfg_set   nat "$type" rule "$n" translation address "$val"
      cfg_apply ;;
    "translation port")
      tprint "Leave blank to DELETE."; local val; val="$(ask "Port or range" "")"
      [ -n "$val" ] && ! is_valid_port_or_range "$val" && { tprint "ERROR."; pause; return 0; }
      cfg_begin || return 0
      [ -z "$val" ] && cfg_delete nat "$type" rule "$n" translation port \
                    || cfg_set   nat "$type" rule "$n" translation port "$val"
      cfg_apply ;;
    "inbound-interface name"|"outbound-interface name")
      tprint "Leave blank to DELETE."; local val; val="$(ask "Interface name (e.g. eth0)" "")"
      [ -n "$val" ] && ! is_safe_iface_name "$val" && { tprint "ERROR."; pause; return 0; }
      cfg_begin || return 0
      local ifdir="${field%%-*}"
      [ -z "$val" ] && cfg_delete nat "$type" rule "$n" "${ifdir}-interface" name \
                    || cfg_set   nat "$type" rule "$n" "${ifdir}-interface" name "$val"
      cfg_apply ;;
    *) tprint "Invalid."; pause ;;
  esac
}

nat_delete_rule() {
  local type n yn
  type="$(nat_choose_type)" || return 0; [ -z "$type" ] && return 0
  n="$(nat_choose_rule_number_existing "$type")" || return 0
  nat_preview_rule "$type" "$n"
  yn="$(choose_yes_no "Delete NAT $type rule $n?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete nat "$type" rule "$n"; cfg_apply
}

nat_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== NAT ======"
    _nat_summary; tprint ""
    tprint "1) List NAT rules"
    tprint "2) Add DNAT rule (safe)"
    tprint "3) Add SNAT rule (safe)"
    tprint "4) Update NAT rule field"
    tprint "5) Delete NAT rule"
    tprint "6) Port Group Management"
    tprint "7) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) nat_list ;; 2) nat_add_dnat_guided ;; 3) nat_add_snat_guided ;;
      4) nat_update_single_field ;; 5) nat_delete_rule ;; 6) port_group_menu ;; 7) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# SYSTEM
# ============================================================
user_add_menu() {
  local u pw fn existing=() yn
  u="$(ask "New username" "")"; [ -z "$u" ] && return 0
  if ! is_valid_username "$u"; then tprint "ERROR: Invalid username."; pause; return 0; fi
  load_array existing scan_login_users
  if is_in_list "$u" "${existing[@]}"; then tprint "ERROR: User '$u' already exists."; pause; return 0; fi
  fn="$(ask "Full name (optional)" "")"
  [ -n "$fn" ] && ! is_safe_free_text "$fn" && { tprint "ERROR: Invalid full name."; pause; return 0; }
  tread_secret pw "Password (hidden): " || return 0
  [ -z "$pw" ] && { tprint "Password required."; pause; return 0; }
  tprint ""; tprint "SUMMARY: create user $u"
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  [ -n "$fn" ] && cfg_set system login user "$u" full-name "$fn"
  cfg_set system login user "$u" authentication plaintext-password "$pw"
  cfg_apply
}
user_remove_menu() {
  local users=() current target yn
  load_array users scan_login_users
  require_nonempty_list_or_return "login users" "${users[@]}" || return 0
  current="$(get_current_username)"
  [ -n "$current" ] && tprint "Currently logged in as: $current"
  select_from_list "Select user to REMOVE" "${users[@]}" || return 0; target="$SELECTED"
  if [ -n "$current" ] && [ "$target" = "$current" ]; then tprint "ERROR: Cannot remove yourself."; pause; return 0; fi
  tprint ""; tprint "About to REMOVE user: $target"
  yn="$(choose_yes_no "Proceed?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete system login user "$target"; cfg_apply
}
user_change_password_menu() {
  local users=() target pw1 pw2 current yn
  load_array users scan_login_users
  require_nonempty_list_or_return "login users" "${users[@]}" || return 0
  current="$(get_current_username)"
  tprint ""; tprint "=== Change User Password ==="
  select_from_list "Select user to change password" "${users[@]}" || return 0; target="$SELECTED"
  if [ -n "$current" ] && [ "$target" = "$current" ]; then
    tprint ""; tprint "NOTE: You are changing your OWN password ($current)."
    yn="$(choose_yes_no "Continue?" "y" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  fi
  tprint ""; tprint "Setting new password for: $target"
  while true; do
    pw1="" pw2=""
    tread_secret pw1 "New password       : " || return 0
    [ -z "$pw1" ] && { tprint "ERROR: Password cannot be blank."; continue; }
    tread_secret pw2 "Confirm password   : " || return 0
    [ "$pw1" = "$pw2" ] && break
    tprint ""; tprint "ERROR: Passwords do not match. Try again."; tprint ""
  done
  tprint ""; tprint "SUMMARY: change password for '$target'"
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set system login user "$target" authentication plaintext-password "$pw1"; cfg_apply
}
users_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== User Management ======"
    tprint "Users: $(scan_login_users | join_lines || echo NONE)"; tprint ""
    tprint "1) Add user"; tprint "2) Remove user"; tprint "3) Change user password"; tprint "4) Back"
    local c; tread c "Select: " || continue
    case "$c" in 1) user_add_menu ;; 2) user_remove_menu ;; 3) user_change_password_menu ;; 4) return 0 ;; *) tprint "Invalid." ;; esac
  done
}
hostname_menu() {
  local cur newhn yn; cur="$(get_current_hostname)"
  tprint ""; tprint "Current hostname: ${cur:-UNKNOWN}"
  newhn="$(ask "New hostname" "")"; [ -z "$newhn" ] && return 0
  if ! is_valid_hostname "$newhn"; then tprint "ERROR: Invalid hostname."; pause; return 0; fi
  yn="$(choose_yes_no "Set hostname to: $newhn ?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set system host-name "$newhn"; cfg_apply
}
system_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== System ======"
    tprint "Hostname: $(get_current_hostname || echo UNKNOWN)"
    tprint "Users:    $(scan_login_users | join_lines || echo NONE)"; tprint ""
    tprint "1) User management"; tprint "2) Change hostname"; tprint "3) Back"
    local c; tread c "Select: " || continue
    case "$c" in 1) users_menu ;; 2) hostname_menu ;; 3) return 0 ;; *) tprint "Invalid." ;; esac
  done
}

# ============================================================
# DNS FORWARDING
# ============================================================

# v3.1: allow-from accepts hostname → resolves → asks prefix
dns_add_allow_from_safe() {
  local current_af=() current_la=() new_af la_needed yn
  load_array current_af scan_dns_allow_from; load_array current_la scan_dns_listen_address
  tprint ""; tprint "Current allow-from: ${current_af[*]:-(none)}"
  new_af="$(ask_cidr_or_hostname "New allow-from subnet" "")"
  [ -z "$new_af" ] && return 0
  is_in_list "$new_af" "${current_af[@]}" && { tprint "ERROR: $new_af already exists."; pause; return 0; }
  if [ "${#current_la[@]}" -eq 0 ]; then
    tprint ""; tprint "IMPORTANT: listen-address also required."
    la_needed="$(ask_ip_or_hostname "listen-address" "")"
    [ -z "$la_needed" ] && return 0
  fi
  yn="$(choose_yes_no "Add allow-from $new_af?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set service dns forwarding allow-from "$new_af"
  [ -n "${la_needed:-}" ] && cfg_set service dns forwarding listen-address "$la_needed"
  cfg_apply
}
dns_delete_allow_from_existing() {
  local current_af=() current_la=() target yn
  load_array current_af scan_dns_allow_from; load_array current_la scan_dns_listen_address
  require_nonempty_list_or_return "DNS allow-from entries" "${current_af[@]}" || return 0
  select_from_list "Select allow-from to DELETE" "${current_af[@]}" || return 0; target="$SELECTED"
  if [ "${#current_af[@]}" -le 1 ] && { [ "${#current_la[@]}" -ge 1 ] || dns_system_is_enabled; }; then
    tprint "BLOCKED: Cannot delete last allow-from."; pause; return 0
  fi
  yn="$(choose_yes_no "Delete allow-from $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete service dns forwarding allow-from "$target"; cfg_apply
}

# v3.1: listen-address accepts hostname
dns_add_listen_address_safe() {
  local current_af=() current_la=() new_la af_needed yn
  load_array current_af scan_dns_allow_from; load_array current_la scan_dns_listen_address
  tprint ""; tprint "Current listen-address: ${current_la[*]:-(none)}"
  new_la="$(ask_ip_or_hostname "New listen-address" "")"
  [ -z "$new_la" ] && return 0
  is_in_list "$new_la" "${current_la[@]}" && { tprint "ERROR: $new_la already exists."; pause; return 0; }
  if [ "${#current_af[@]}" -eq 0 ]; then
    tprint ""; tprint "IMPORTANT: allow-from also required."
    af_needed="$(ask_cidr_or_hostname "allow-from subnet" "")"
    [ -z "$af_needed" ] && return 0
  fi
  yn="$(choose_yes_no "Add listen-address $new_la?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set service dns forwarding listen-address "$new_la"
  [ -n "${af_needed:-}" ] && cfg_set service dns forwarding allow-from "$af_needed"
  cfg_apply
}
dns_delete_listen_address_existing() {
  local current_af=() current_la=() target yn
  load_array current_af scan_dns_allow_from; load_array current_la scan_dns_listen_address
  require_nonempty_list_or_return "DNS listen-address entries" "${current_la[@]}" || return 0
  select_from_list "Select listen-address to DELETE" "${current_la[@]}" || return 0; target="$SELECTED"
  if [ "${#current_la[@]}" -le 1 ] && { [ "${#current_af[@]}" -ge 1 ] || dns_system_is_enabled; }; then
    tprint "BLOCKED: Cannot delete last listen-address."; pause; return 0
  fi
  yn="$(choose_yes_no "Delete listen-address $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete service dns forwarding listen-address "$target"; cfg_apply
}
dns_system_forwarding_toggle() {
  local current_af=() current_la=() yn
  load_array current_af scan_dns_allow_from; load_array current_la scan_dns_listen_address; tprint ""
  if dns_system_is_enabled; then
    tprint "DNS system forwarding: ENABLED"
    yn="$(choose_yes_no "Disable it?" "y" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; cfg_delete service dns forwarding system; cfg_apply
  else
    tprint "DNS system forwarding: DISABLED"
    if [ "${#current_la[@]}" -eq 0 ] || [ "${#current_af[@]}" -eq 0 ]; then
      tprint "BLOCKED: Need both listen-address and allow-from first."; pause; return 0
    fi
    yn="$(choose_yes_no "Enable it?" "y" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; cfg_set service dns forwarding system; cfg_apply
  fi
}
dns_list_name_servers() {
  tprint ""; tprint "Current name-servers:"; tprint "--------------------------------------------------------"
  local ns=(); load_array ns scan_dns_name_servers
  [ "${#ns[@]}" -eq 0 ] && tprint "  (none)" || { local n; for n in "${ns[@]}"; do tprint "  $n"; done; }
  tprint "--------------------------------------------------------"; tprint ""
  grep_cfg "set system name-server " >"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"; pause
}

# v3.1: name-server accepts hostname
dns_add_name_server_safe() {
  local current=() ip yn; load_array current scan_dns_name_servers
  tprint ""; tprint "Current name-servers: ${current[*]:-(none)}"; tprint ""
  ip="$(ask_ip_or_hostname "Name-server" "")"
  [ -z "$ip" ] && return 0
  is_in_list "$ip" "${current[@]}" && { tprint "ERROR: $ip already configured."; pause; return 0; }
  yn="$(choose_yes_no "Add name-server $ip?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set system name-server "$ip"; cfg_apply
}
dns_delete_name_server_existing() {
  local current=() target yn; load_array current scan_dns_name_servers
  require_nonempty_list_or_return "System name-servers" "${current[@]}" || return 0
  select_from_list "Select name-server to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Delete name-server $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete system name-server "$target"; cfg_apply
}

# v3.1: domain forwarding server accepts hostname
dns_add_domain_forwarding_safe() {
  local current=() domain server yn; load_array current scan_dns_forward_domains
  tprint ""; tprint "Current forwarding domains: ${current[*]:-(none)}"; tprint ""
  domain="$(ask "Domain to forward (e.g. yourdomain.local)" "")"; [ -z "$domain" ] && return 0
  is_valid_hostname "$domain" || { tprint "ERROR: Invalid domain."; pause; return 0; }
  is_in_list "$domain" "${current[@]}" && { tprint "ERROR: Domain already has forwarding entry."; pause; return 0; }
  server="$(ask_ip_or_hostname "Server to forward $domain queries to" "")"
  [ -z "$server" ] && return 0
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set service dns forwarding domain "$domain" name-server "$server"; cfg_apply
}
dns_delete_domain_forwarding_existing() {
  local current=() target yn; load_array current scan_dns_forward_domains
  require_nonempty_list_or_return "DNS forwarding domains" "${current[@]}" || return 0
  select_from_list "Select domain forwarding to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Delete dns forwarding domain $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete service dns forwarding domain "$target"; cfg_apply
}
dns_forwarding_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "=============================="; tprint " DNS Forwarding"; tprint "=============================="
    _dns_summary; tprint ""
    tprint "1)  List full DNS config"
    tprint "2)  Add allow-from (safe)"
    tprint "3)  Delete allow-from"
    tprint "4)  Add listen-address (safe)"
    tprint "5)  Delete listen-address"
    tprint "6)  Toggle system forwarding"
    tprint "7)  List name-servers"
    tprint "8)  Add name-server (safe)"
    tprint "9)  Delete name-server"
    tprint "10) Add domain forwarding"
    tprint "11) Delete domain forwarding"
    tprint "12) Back"
    local c; tread c "Select menu option #: " || continue
    case "$c" in
      1)  tprint ""; grep_cfg "set service dns forwarding " >"$TTY" 2>/dev/null || true; pause ;;
      2)  dns_add_allow_from_safe ;; 3)  dns_delete_allow_from_existing ;;
      4)  dns_add_listen_address_safe ;; 5)  dns_delete_listen_address_existing ;;
      6)  dns_system_forwarding_toggle ;; 7)  dns_list_name_servers ;;
      8)  dns_add_name_server_safe ;; 9)  dns_delete_name_server_existing ;;
      10) dns_add_domain_forwarding_safe ;; 11) dns_delete_domain_forwarding_existing ;;
      12) return 0 ;; *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# RIP
# ============================================================
rip_neighbor_context_warning() {
  local neighbors=() passive=()
  load_array neighbors scan_rip_neighbors; load_array passive scan_rip_passive_interfaces
  local passive_default=0; is_in_list "default" "${passive[@]}" && passive_default=1
  tprint ""; tprint "--- Neighbor / Passive-interface ---"
  if [ "$passive_default" -eq 1 ]; then
    tprint "  passive-interface default: SET"
    if [ "${#neighbors[@]}" -eq 0 ]; then tprint "  WARNING: No neighbors → RIP is SILENT."
    else tprint "  Unicast neighbors:"; local n; for n in "${neighbors[@]}"; do tprint "    $n"; done; fi
  else
    tprint "  passive-interface default: NOT set"
    [ "${#neighbors[@]}" -gt 0 ] && tprint "  NOTE: neighbor entries are redundant without passive-interface default."
  fi
  tprint ""
}
rip_list_config() {
  tprint ""; tprint "--- RIP config ---"
  grep_cfg "set protocols rip " >"$TTY" 2>/dev/null || true
  tprint ""; tprint "--- Per-interface RIP ---"
  local il; il="$(scan_rip_iface_settings)"
  [ -n "$il" ] && printf "%s\n" "$il" >"$TTY" || tprint "(none)"
  rip_neighbor_context_warning
  run_cmd_to_tty "show ip rip"; run_cmd_to_tty "show ip rip status"; run_cmd_to_tty "show ip route rip"; pause
}
rip_add_interface_safe() {
  local current=() ifs=() iface yn
  load_array current scan_rip_interfaces; load_array ifs scan_eth_ifaces
  tprint ""; tprint "Current RIP interfaces: ${current[*]:-(none)}"
  [ "${#ifs[@]}" -gt 0 ] && { select_from_list "Select interface" "${ifs[@]}" && iface="$SELECTED"; } || true
  [ -z "${iface:-}" ] && iface="$(ask "Interface name" "")"
  [ -z "$iface" ] && return 0
  is_safe_iface_name "$iface" || { tprint "ERROR: Invalid interface name."; pause; return 0; }
  is_in_list "$iface" "${current[@]}" && { tprint "ERROR: $iface already a RIP interface."; pause; return 0; }
  yn="$(choose_yes_no "Add RIP interface: $iface?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set protocols rip interface "$iface"; cfg_apply
}
rip_delete_interface_existing() {
  local current=() target yn; load_array current scan_rip_interfaces
  require_nonempty_list_or_return "RIP interfaces" "${current[@]}" || return 0
  select_from_list "Select RIP interface to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Delete RIP interface $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete protocols rip interface "$target"; cfg_apply
}

# v3.1: rip network accepts hostname → resolves → asks prefix
rip_add_network_safe() {
  local current=() net yn; load_array current scan_rip_networks
  tprint ""; tprint "Current RIP networks: ${current[*]:-(none)}"
  net="$(ask_cidr_or_hostname "Network" "")"
  [ -z "$net" ] && return 0
  is_in_list "$net" "${current[@]}" && { tprint "ERROR: $net already exists."; pause; return 0; }
  yn="$(choose_yes_no "Add RIP network $net?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set protocols rip network "$net"; cfg_apply
}
rip_delete_network_existing() {
  local current=() target yn; load_array current scan_rip_networks
  require_nonempty_list_or_return "RIP networks" "${current[@]}" || return 0
  select_from_list "Select RIP network to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Delete RIP network $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete protocols rip network "$target"; cfg_apply
}
rip_neighbor_reachable_via_rip() {
  local neighbor_ip="$1" rip_ifaces=(); load_array rip_ifaces scan_rip_interfaces
  [ "${#rip_ifaces[@]}" -eq 0 ] && return 1
  local n_int; n_int="$(printf "%s" "$neighbor_ip" | awk -F. '{printf "%d", ($1*16777216)+($2*65536)+($3*256)+$4}')"
  local iface
  for iface in "${rip_ifaces[@]}"; do
    local addr_cidr; addr_cidr="$(grep_cfg "set interfaces ethernet $iface address " | awk '{print $6}' | head -n 1 | while read -r x; do strip_quotes "$x"; done)"
    [ -z "$addr_cidr" ] && continue
    local net_ip="${addr_cidr%/*}" prefix="${addr_cidr#*/}"
    [ -z "$net_ip" ] || [ -z "$prefix" ] && continue
    echo "$prefix" | grep -Eq '^[0-9]+$' || continue
    local mask=$(( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF ))
    local net_int; net_int="$(printf "%s" "$net_ip" | awk -F. '{printf "%d", ($1*16777216)+($2*65536)+($3*256)+$4}')"
    [ $(( net_int & mask )) -eq $(( n_int & mask )) ] && return 0
  done
  return 1
}

# v3.1: rip neighbor accepts hostname
rip_add_neighbor_safe() {
  local current=() passive=() ip yn
  load_array current scan_rip_neighbors; load_array passive scan_rip_passive_interfaces
  rip_neighbor_context_warning; tprint "Current neighbors: ${current[*]:-(none)}"
  ip="$(ask_ip_or_hostname "Neighbor" "")"
  [ -z "$ip" ] && return 0
  is_in_list "$ip" "${current[@]}" && { tprint "ERROR: $ip already exists."; pause; return 0; }
  if ! rip_neighbor_reachable_via_rip "$ip"; then
    tprint "WARNING: $ip may not be reachable via any RIP interface subnet."
    local cont; cont="$(choose_yes_no "Continue anyway?" "n" || echo "n")"
    [ "$cont" != "y" ] && { tprint "Canceled."; pause; return 0; }
  fi
  if ! is_in_list "default" "${passive[@]}"; then
    tprint "NOTE: passive-interface default is NOT set — neighbor entry is redundant."
    local cont2; cont2="$(choose_yes_no "Add neighbor anyway?" "n" || echo "n")"
    [ "$cont2" != "y" ] && { tprint "Canceled."; pause; return 0; }
  fi
  yn="$(choose_yes_no "Add RIP neighbor $ip?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set protocols rip neighbor "$ip"; cfg_apply
}
rip_delete_neighbor_existing() {
  local current=() passive=() target yn
  load_array current scan_rip_neighbors; load_array passive scan_rip_passive_interfaces
  require_nonempty_list_or_return "RIP neighbors" "${current[@]}" || return 0
  is_in_list "default" "${passive[@]}" && [ "${#current[@]}" -le 1 ] && \
    tprint "WARNING: Deleting last neighbor with passive-interface default → RIP goes SILENT."
  select_from_list "Select RIP neighbor to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Delete RIP neighbor $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete protocols rip neighbor "$target"; cfg_apply
}
rip_add_passive_interface_safe() {
  local current=() ifs=() iface yn
  load_array current scan_rip_passive_interfaces; load_array ifs scan_eth_ifaces
  tprint ""; tprint "Current passive interfaces: ${current[*]:-(none)}"
  local choices=("default"); local i; for i in "${ifs[@]}"; do choices+=("$i"); done
  select_from_list "Select interface or 'default'" "${choices[@]}" && iface="$SELECTED" \
    || iface="$(ask "Interface or 'default'" "")"
  [ -z "$iface" ] && return 0
  [ "$iface" != "default" ] && ! is_safe_iface_name "$iface" && { tprint "ERROR: Invalid."; pause; return 0; }
  is_in_list "$iface" "${current[@]}" && { tprint "ERROR: $iface already passive."; pause; return 0; }
  yn="$(choose_yes_no "Set passive interface: $iface?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set protocols rip passive-interface "$iface"; cfg_apply
}
rip_delete_passive_interface_existing() {
  local current=() target yn; load_array current scan_rip_passive_interfaces
  require_nonempty_list_or_return "RIP passive interfaces" "${current[@]}" || return 0
  select_from_list "Select passive interface to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Delete passive interface $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete protocols rip passive-interface "$target"; cfg_apply
}
rip_add_redistribute_safe() {
  local current=() src metric yn
  local sources=("connected" "static" "ospf" "bgp" "kernel")
  load_array current scan_rip_redistribute
  local available=() s; for s in "${sources[@]}"; do is_in_list "$s" "${current[@]}" || available+=("$s"); done
  [ "${#available[@]}" -eq 0 ] && { tprint "All redistribute sources already configured."; pause; return 0; }
  tprint ""; tprint "Currently redistributing: ${current[*]:-(none)}"
  select_from_list "Select route source to redistribute" "${available[@]}" || return 0; src="$SELECTED"
  metric="$(ask "Metric 1-16 (optional)" "")"
  if [ -n "$metric" ]; then echo "$metric" | grep -Eq '^([1-9]|1[0-6])$' || { tprint "ERROR: Metric must be 1-16."; pause; return 0; }; fi
  yn="$(choose_yes_no "Redistribute $src?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set protocols rip redistribute "$src"
  [ -n "$metric" ] && cfg_set protocols rip redistribute "$src" metric "$metric"
  cfg_apply
}
rip_delete_redistribute_existing() {
  local current=() target yn; load_array current scan_rip_redistribute
  require_nonempty_list_or_return "RIP redistribute sources" "${current[@]}" || return 0
  select_from_list "Select redistribute source to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Delete redistribute $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete protocols rip redistribute "$target"; cfg_apply
}
rip_default_information_toggle() {
  local yn is_set=0
  grep_cfg "set protocols rip default-information originate" | grep -q . && is_set=1; tprint ""
  if [ "$is_set" -eq 1 ]; then
    tprint "default-information originate: ENABLED"
    yn="$(choose_yes_no "Disable it?" "y" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; cfg_delete protocols rip default-information originate
  else
    tprint "default-information originate: DISABLED"
    yn="$(choose_yes_no "Enable it?" "y" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; cfg_set protocols rip default-information originate
  fi
  cfg_apply
}
is_valid_rip_timer() {
  local v="$1"; echo "$v" | grep -Eq '^[0-9]+$' || return 1
  [ "$v" -ge 5 ] 2>/dev/null && [ "$v" -le 2147483647 ] 2>/dev/null
}
rip_timers_menu() {
  local update="" timeout="" gc="" yn val
  local cur_u cur_t cur_g
  cur_u="$(grep_cfg "set protocols rip timers update "             | awk '{print $6}' | head -n 1 | while read -r x; do strip_quotes "$x"; done)"
  cur_t="$(grep_cfg "set protocols rip timers timeout "            | awk '{print $6}' | head -n 1 | while read -r x; do strip_quotes "$x"; done)"
  cur_g="$(grep_cfg "set protocols rip timers garbage-collection " | awk '{print $6}' | head -n 1 | while read -r x; do strip_quotes "$x"; done)"
  tprint ""; tprint "RIP timers (defaults: update=30 timeout=180 gc=120)"
  tprint "  update: ${cur_u:-30}  timeout: ${cur_t:-180}  gc: ${cur_g:-120}"
  tprint "Leave blank to keep existing."; tprint ""
  val="$(ask "Update timer" "")";            [ -n "$val" ] && { is_valid_rip_timer "$val" || { tprint "ERROR."; pause; return 0; }; update="$val"; }
  val="$(ask "Timeout timer" "")";           [ -n "$val" ] && { is_valid_rip_timer "$val" || { tprint "ERROR."; pause; return 0; }; timeout="$val"; }
  val="$(ask "Garbage-collection timer" "")";[ -n "$val" ] && { is_valid_rip_timer "$val" || { tprint "ERROR."; pause; return 0; }; gc="$val"; }
  [ -z "$update" ] && [ -z "$timeout" ] && [ -z "$gc" ] && { tprint "Nothing entered."; pause; return 0; }
  yn="$(choose_yes_no "Apply timer changes?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  [ -n "$update"  ] && cfg_set protocols rip timers update "$update"
  [ -n "$timeout" ] && cfg_set protocols rip timers timeout "$timeout"
  [ -n "$gc"      ] && cfg_set protocols rip timers garbage-collection "$gc"
  cfg_apply
}
rip_timers_reset() {
  local yn; yn="$(choose_yes_no "Reset ALL RIP timers to defaults?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete protocols rip timers; cfg_apply
}

# v3.1: rip static route accepts hostname → resolves → asks prefix
rip_add_static_route_safe() {
  local current=() net yn; load_array current scan_rip_static_routes
  tprint ""; tprint "WARNING: RIP static route is NOT installed in kernel."
  tprint "Current RIP static routes: ${current[*]:-(none)}"
  net="$(ask_cidr_or_hostname "Route" "")"
  [ -z "$net" ] && return 0
  is_in_list "$net" "${current[@]}" && { tprint "ERROR: $net already exists."; pause; return 0; }
  yn="$(choose_yes_no "Add RIP static route $net?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set protocols rip route "$net"; cfg_apply
}
rip_delete_static_route_existing() {
  local current=() target yn; load_array current scan_rip_static_routes
  require_nonempty_list_or_return "RIP static routes" "${current[@]}" || return 0
  select_from_list "Select RIP static route to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Delete RIP static route $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete protocols rip route "$target"; cfg_apply
}
rip_iface_settings_menu() {
  local ifs=() iface; load_array ifs scan_eth_ifaces
  require_nonempty_list_or_return "ethernet interfaces" "${ifs[@]}" || return 0
  select_from_list "Select interface for per-interface RIP settings" "${ifs[@]}" || return 0; iface="$SELECTED"
  tprint ""; tprint "Current RIP settings on $iface:"; tprint "--------------------------------------------------------"
  grep_cfg "set interfaces ethernet $iface ip rip " >"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"
  local options=("split-horizon enable (default)" "split-horizon disable" "split-horizon poison-reverse"
                 "authentication plaintext" "authentication MD5"
                 "delete ALL per-interface RIP settings" "back")
  select_from_list "Select setting for $iface" "${options[@]}" || return 0
  case "$SELECTED" in
    "split-horizon enable (default)")
      local yn; yn="$(choose_yes_no "Remove split-horizon override?" "y" || echo "n")"
      [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
      cfg_begin || return 0; cfg_delete interfaces ethernet "$iface" ip rip split-horizon; cfg_apply ;;
    "split-horizon disable")
      local yn; yn="$(choose_yes_no "Disable split-horizon on $iface?" "y" || echo "n")"
      [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
      cfg_begin || return 0; cfg_set interfaces ethernet "$iface" ip rip split-horizon disable; cfg_apply ;;
    "split-horizon poison-reverse")
      local yn; yn="$(choose_yes_no "Enable poison-reverse on $iface?" "y" || echo "n")"
      [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
      cfg_begin || return 0; cfg_set interfaces ethernet "$iface" ip rip split-horizon poison-reverse; cfg_apply ;;
    "authentication plaintext")
      local pw yn; tprint "WARNING: plaintext password sent in cleartext."
      tread_secret pw "RIP plaintext password: " || return 0
      [ -z "$pw" ] && { tprint "Password required."; pause; return 0; }
      yn="$(choose_yes_no "Set plaintext RIP auth on $iface?" "y" || echo "n")"
      [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
      cfg_begin || return 0
      cfg_set interfaces ethernet "$iface" ip rip authentication mode plaintext
      cfg_set interfaces ethernet "$iface" ip rip authentication plaintext-password "$pw"
      cfg_apply ;;
    "authentication MD5")
      local keyid pw yn
      keyid="$(ask "MD5 Key ID (1-255)" "1")"
      echo "$keyid" | grep -Eq '^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$' || { tprint "ERROR: Key ID must be 1-255."; pause; return 0; }
      tread_secret pw "MD5 password (max 16 chars): " || return 0
      [ -z "$pw" ] && { tprint "Password required."; pause; return 0; }
      [ "${#pw}" -gt 16 ] && { tprint "ERROR: Max 16 characters."; pause; return 0; }
      yn="$(choose_yes_no "Set MD5 RIP auth on $iface?" "y" || echo "n")"
      [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
      cfg_begin || return 0
      cfg_set interfaces ethernet "$iface" ip rip authentication mode md5
      cfg_set interfaces ethernet "$iface" ip rip authentication md5 "$keyid" password "$pw"
      cfg_apply ;;
    "delete ALL per-interface RIP settings")
      local yn; yn="$(choose_yes_no "Delete ALL RIP settings on $iface?" "n" || echo "n")"
      [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
      cfg_begin || return 0; cfg_delete interfaces ethernet "$iface" ip rip; cfg_apply ;;
    "back") return 0 ;;
    *) tprint "Invalid."; pause ;;
  esac
}
rip_set_default_distance() {
  local cur dist yn
  cur="$(grep_cfg "set protocols rip default-distance " | awk '{print $5}' | head -n 1 | while read -r x; do strip_quotes "$x"; done)"
  tprint ""; tprint "Current default-distance: ${cur:-120 (VyOS default)}"
  dist="$(ask "New default distance (1-255)" "${cur:-120}")"; [ -z "$dist" ] && return 0
  echo "$dist" | grep -Eq '^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$' || { tprint "ERROR: Must be 1-255."; pause; return 0; }
  yn="$(choose_yes_no "Set default-distance to $dist?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set protocols rip default-distance "$dist"; cfg_apply
}
rip_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== RIP ======"; _rip_summary; tprint ""
    tprint "1)  List RIP config + runtime"
    tprint "2)  Add interface (safe)"
    tprint "3)  Delete interface"
    tprint "4)  Add network (safe)"
    tprint "5)  Delete network"
    tprint "6)  Add neighbor / unicast peer (safe)"
    tprint "7)  Delete neighbor"
    tprint "8)  Add passive interface (safe)"
    tprint "9)  Delete passive interface"
    tprint "10) Redistribute into RIP (safe)"
    tprint "11) Delete redistribute"
    tprint "12) Toggle default-information originate"
    tprint "13) Set timers"
    tprint "14) Reset timers to defaults"
    tprint "15) Add static route (advanced)"
    tprint "16) Delete static route"
    tprint "17) Per-interface settings (split-horizon / auth)"
    tprint "18) Set default distance"
    tprint "19) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1)  rip_list_config ;; 2)  rip_add_interface_safe ;; 3)  rip_delete_interface_existing ;;
      4)  rip_add_network_safe ;; 5)  rip_delete_network_existing ;; 6)  rip_add_neighbor_safe ;;
      7)  rip_delete_neighbor_existing ;; 8)  rip_add_passive_interface_safe ;;
      9)  rip_delete_passive_interface_existing ;; 10) rip_add_redistribute_safe ;;
      11) rip_delete_redistribute_existing ;; 12) rip_default_information_toggle ;;
      13) rip_timers_menu ;; 14) rip_timers_reset ;; 15) rip_add_static_route_safe ;;
      16) rip_delete_static_route_existing ;; 17) rip_iface_settings_menu ;;
      18) rip_set_default_distance ;; 19) return 0 ;; *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# STATIC ROUTES
# ============================================================

# v3.1: next-hop accepts hostname
static_route_add_safe() {
  local current=() prefix nexthop distance yn; load_array current scan_static_routes
  tprint ""; tprint "Current static routes: ${current[*]:-(none)}"; tprint ""
  prefix="$(ask_cidr_or_hostname "Destination prefix" "")"
  [ -z "$prefix" ] && return 0
  tprint ""; tprint "  nexthop   = route via a gateway IP"; tprint "  blackhole = silently discard"
  select_from_list_default "Route type" "nexthop" "nexthop" "blackhole" || return 0; local rtype="$SELECTED"
  if [ "$rtype" = "nexthop" ]; then
    nexthop="$(ask_ip_or_hostname "Next-hop gateway" "")"
    [ -z "$nexthop" ] && return 0
  fi
  distance="$(ask "Admin distance (1-255, optional)" "")"
  if [ -n "$distance" ]; then
    echo "$distance" | grep -Eq '^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$' || { tprint "ERROR: 1-255."; pause; return 0; }
  fi
  tprint ""
  [ "$rtype" = "blackhole" ] && tprint "SUMMARY: static blackhole $prefix${distance:+ distance $distance}" \
    || tprint "SUMMARY: static route $prefix via $nexthop${distance:+ distance $distance}"
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  if [ "$rtype" = "blackhole" ]; then
    cfg_set protocols static route "$prefix" blackhole
    [ -n "$distance" ] && cfg_set protocols static route "$prefix" blackhole distance "$distance"
  else
    cfg_set protocols static route "$prefix" next-hop "$nexthop"
    [ -n "$distance" ] && cfg_set protocols static route "$prefix" next-hop "$nexthop" distance "$distance"
  fi
  cfg_apply
}
static_route_delete() {
  local current=() prefix nexthops=() yn; load_array current scan_static_routes
  require_nonempty_list_or_return "static routes" "${current[@]}" || return 0
  select_from_list "Select route to delete" "${current[@]}" || return 0; prefix="$SELECTED"
  tprint ""; tprint "Config for $prefix:"; tprint "--------------------------------------------------------"
  { grep_cfg "set protocols static route $prefix "; grep_cfg "set protocols static route '$prefix' "; } >"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"
  load_array nexthops scan_static_route_nexthops "$prefix"
  if [ "${#nexthops[@]}" -gt 1 ]; then
    select_from_list_default "Delete scope" "entire prefix" "entire prefix" "${nexthops[@]}" || return 0
    if [ "$SELECTED" = "entire prefix" ]; then
      yn="$(choose_yes_no "Delete entire route $prefix?" "n" || echo "n")"
      [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
      cfg_begin || return 0; cfg_delete protocols static route "$prefix"; cfg_apply
    else
      local nh="$SELECTED"
      yn="$(choose_yes_no "Delete next-hop $nh from $prefix?" "n" || echo "n")"
      [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
      cfg_begin || return 0; cfg_delete protocols static route "$prefix" next-hop "$nh"; cfg_apply
    fi
  else
    yn="$(choose_yes_no "Delete route $prefix?" "n" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; cfg_delete protocols static route "$prefix"; cfg_apply
  fi
}
static_route_list() {
  tprint ""; tprint "--- Static routes ---"; tprint "--------------------------------------------------------"
  grep_cfg "set protocols static route " >"$TTY" 2>/dev/null || tprint "(none)"
  tprint "--------------------------------------------------------"; tprint ""
  run_cmd_to_tty "show ip route static"; pause
}
static_routes_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== Static Routes ======"
    tprint "Routes: $(scan_static_routes | join_lines || echo NONE)"; tprint ""
    tprint "1) List static routes"; tprint "2) Add route (safe)"; tprint "3) Delete route"; tprint "4) Back"
    local c; tread c "Select: " || continue
    case "$c" in 1) static_route_list ;; 2) static_route_add_safe ;; 3) static_route_delete ;; 4) return 0 ;; *) tprint "Invalid." ;; esac
  done
}

# ============================================================
# DHCP SERVER
# ============================================================
dhcp_show_pool() {
  local pool="$1"; tprint ""; tprint "--- DHCP pool: $pool ---"; tprint "--------------------------------------------------------"
  { grep_cfg "set service dhcp-server shared-network-name $pool "; grep_cfg "set service dhcp-server shared-network-name '$pool' "; } >"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"
}

# v3.1: DHCP pool creation — subnet CIDR, range IPs, gateway, DNS all accept hostname
dhcp_add_pool_safe() {
  local pools=() name subnet range_start range_stop gateway dns lease yn
  load_array pools scan_dhcp_pools
  tprint ""; tprint "Existing DHCP pools: ${pools[*]:-(none)}"; tprint ""
  name="$(ask "Pool name" "")"; [ -z "$name" ] && return 0
  is_safe_ruleset_name "$name" || { tprint "ERROR: Invalid pool name."; pause; return 0; }
  is_in_list "$name" "${pools[@]}" && { tprint "ERROR: Pool '$name' already exists."; pause; return 0; }
  subnet="$(ask_cidr_or_hostname "Subnet" "")"
  [ -z "$subnet" ] && return 0
  range_start="$(ask_ip_or_hostname "Range start IP" "")"
  [ -z "$range_start" ] && return 0
  range_stop="$(ask_ip_or_hostname "Range stop IP" "")"
  [ -z "$range_stop" ] && return 0
  gateway="$(ask_ip_or_hostname "Default gateway (optional, blank to skip)" "")"
  dns="$(ask_ip_or_hostname "DNS server (optional, blank to skip)" "")"
  lease="$(ask "Lease time in seconds (optional, default 86400)" "")"
  if [ -n "$lease" ]; then
    echo "$lease" | grep -Eq '^[0-9]+$' || { tprint "ERROR: Must be numeric."; pause; return 0; }
    [ "$lease" -lt 60 ] 2>/dev/null && { tprint "ERROR: Minimum 60 seconds."; pause; return 0; }
  fi
  tprint ""; tprint "SUMMARY: DHCP pool $name  subnet=$subnet  range=$range_start—$range_stop"
  [ -n "$gateway" ] && tprint "  gateway: $gateway"; [ -n "$dns" ] && tprint "  dns: $dns"
  [ -n "$lease"   ] && tprint "  lease: ${lease}s"
  yn="$(choose_yes_no "Create pool?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set service dhcp-server shared-network-name "$name" subnet "$subnet" range 0 start "$range_start"
  cfg_set service dhcp-server shared-network-name "$name" subnet "$subnet" range 0 stop "$range_stop"
  [ -n "$gateway" ] && cfg_set service dhcp-server shared-network-name "$name" subnet "$subnet" option default-router "$gateway"
  [ -n "$dns" ]     && cfg_set service dhcp-server shared-network-name "$name" subnet "$subnet" option name-server "$dns"
  [ -n "$lease" ]   && cfg_set service dhcp-server shared-network-name "$name" subnet "$subnet" lease "$lease"
  cfg_apply
}
dhcp_delete_pool() {
  local pools=() target yn; load_array pools scan_dhcp_pools
  require_nonempty_list_or_return "DHCP pools" "${pools[@]}" || return 0
  select_from_list "Select DHCP pool to DELETE" "${pools[@]}" || return 0; target="$SELECTED"
  dhcp_show_pool "$target"
  yn="$(choose_yes_no "Delete DHCP pool $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete service dhcp-server shared-network-name "$target"; cfg_apply
}

# v3.1: static mapping reserved IP accepts hostname
dhcp_add_static_mapping() {
  local pools=() pool subnets=() subnet name mac ip yn
  load_array pools scan_dhcp_pools
  require_nonempty_list_or_return "DHCP pools" "${pools[@]}" || return 0
  select_from_list "Select DHCP pool for static mapping" "${pools[@]}" || return 0; pool="$SELECTED"
  load_array subnets scan_dhcp_subnets "$pool"
  require_nonempty_list_or_return "subnets in pool $pool" "${subnets[@]}" || return 0
  select_from_list "Select subnet" "${subnets[@]}" || return 0; subnet="$SELECTED"
  name="$(ask "Mapping name (e.g. printer)" "")"; [ -z "$name" ] && return 0
  is_safe_ruleset_name "$name" || { tprint "ERROR: Invalid mapping name."; pause; return 0; }
  mac="$(ask "MAC address (xx:xx:xx:xx:xx:xx)" "")"; [ -z "$mac" ] && return 0
  echo "$mac" | grep -Eiq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' || { tprint "ERROR: Invalid MAC."; pause; return 0; }
  ip="$(ask_ip_or_hostname "Reserved IP" "")"
  [ -z "$ip" ] && return 0
  tprint ""; tprint "SUMMARY: $pool $subnet static-mapping $name  $mac → $ip"
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set service dhcp-server shared-network-name "$pool" subnet "$subnet" static-mapping "$name" mac "$mac"
  cfg_set service dhcp-server shared-network-name "$pool" subnet "$subnet" static-mapping "$name" ip-address "$ip"
  cfg_apply
}
dhcp_show_leases() { run_cmd_to_tty "show dhcp server leases"; pause; }
dhcp_server_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== DHCP Server ======"
    tprint "Pools: $(scan_dhcp_pools | join_lines || echo NONE)"; tprint ""
    tprint "1) List DHCP config"; tprint "2) Add pool (safe)"; tprint "3) Delete pool"
    tprint "4) Add static mapping"; tprint "5) Show current leases"; tprint "6) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) tprint ""; grep_cfg "set service dhcp-server " >"$TTY" 2>/dev/null || tprint "(none)"; pause ;;
      2) dhcp_add_pool_safe ;; 3) dhcp_delete_pool ;; 4) dhcp_add_static_mapping ;;
      5) dhcp_show_leases ;; 6) return 0 ;; *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# SSH SERVICE
# ============================================================
ssh_show_config() {
  tprint ""; tprint "--- SSH config ---"; tprint "--------------------------------------------------------"
  grep_cfg "set service ssh " >"$TTY" 2>/dev/null || tprint "(no SSH config found)"
  tprint "--------------------------------------------------------"; tprint ""
  run_cmd_to_tty "show service ssh"; pause
}
ssh_set_port() {
  local cur_port new_port yn; cur_port="$(ssh_get_port)"
  tprint ""; tprint "Current SSH port: ${cur_port:-22 (default)}"
  new_port="$(ask "New SSH port" "${cur_port:-22}")"; [ -z "$new_port" ] && return 0
  is_valid_port_or_range "$new_port" || { tprint "ERROR: Invalid port."; pause; return 0; }
  echo "$new_port" | grep -q '-' && { tprint "ERROR: Single port only."; pause; return 0; }
  yn="$(choose_yes_no "Set SSH port to $new_port?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set service ssh port "$new_port"; cfg_apply
}

# v3.1: SSH listen address accepts hostname
ssh_add_listen_address() {
  local current=() new_addr yn; load_array current scan_ssh_listen_addresses
  tprint ""; tprint "Current listen addresses: ${current[*]:-(all interfaces)}"
  new_addr="$(ask_ip_or_hostname "Listen address" "")"
  [ -z "$new_addr" ] && return 0
  is_in_list "$new_addr" "${current[@]}" && { tprint "ERROR: $new_addr already configured."; pause; return 0; }
  yn="$(choose_yes_no "Restrict SSH to $new_addr?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set service ssh listen-address "$new_addr"; cfg_apply
}
ssh_delete_listen_address() {
  local current=() target yn; load_array current scan_ssh_listen_addresses
  require_nonempty_list_or_return "SSH listen addresses" "${current[@]}" || return 0
  select_from_list "Select listen address to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Remove SSH listen-address $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete service ssh listen-address "$target"; cfg_apply
}
ssh_toggle_password_auth() {
  local cur_state yn
  cur_state="$(grep_cfg "set service ssh disable-password-authentication" | grep -q . && echo "DISABLED" || echo "enabled")"
  tprint ""; tprint "Password authentication: $cur_state"
  if [ "$cur_state" = "DISABLED" ]; then
    yn="$(choose_yes_no "Re-enable password authentication?" "n" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; cfg_delete service ssh disable-password-authentication; cfg_apply
  else
    tprint "WARNING: Ensure key-based auth works FIRST."
    yn="$(choose_yes_no "Disable password authentication?" "n" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; cfg_set service ssh disable-password-authentication; cfg_apply
  fi
}
ssh_toggle_service() {
  local yn
  if ssh_is_enabled; then
    tprint ""; tprint "SSH is currently: ENABLED"
    yn="$(choose_yes_no "Disable SSH service?" "n" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; cfg_delete service ssh; cfg_apply
  else
    tprint ""; tprint "SSH is currently: DISABLED"
    yn="$(choose_yes_no "Enable SSH service?" "y" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; cfg_set service ssh; cfg_apply
  fi
}
ssh_service_menu() {
  warn_if_no_access || return 0
  while true; do
    local ssh_state; ssh_is_enabled && ssh_state="ENABLED" || ssh_state="disabled"
    local cur_port; cur_port="$(ssh_get_port)"; cur_port="${cur_port:-22 (default)}"
    tprint ""; tprint "====== SSH Service ======"
    tprint "Status: $ssh_state  |  Port: $cur_port"
    tprint "Listen: $(scan_ssh_listen_addresses | join_lines || echo "(all interfaces)")"; tprint ""
    tprint "1) Show SSH config"; tprint "2) Set port"; tprint "3) Add listen address"
    tprint "4) Delete listen address"; tprint "5) Toggle password authentication"
    tprint "6) Enable / disable SSH service"; tprint "7) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) ssh_show_config ;; 2) ssh_set_port ;; 3) ssh_add_listen_address ;;
      4) ssh_delete_listen_address ;; 5) ssh_toggle_password_auth ;;
      6) ssh_toggle_service ;; 7) return 0 ;; *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# RAW MODE
# ============================================================
raw_mode() {
  tprint ""; tprint "RAW MODE — restricted set/delete only"
  tprint "Start with 'set' or 'delete', no quotes/tabs/shell metacharacters"; tprint ""
  local cmd yn
  tread cmd "> " || return 0; [ -z "$cmd" ] && return 0
  if reject_if_unsafe_commandline "$cmd"; then tprint "ERROR: Unsafe characters."; pause; return 0; fi
  # shellcheck disable=SC2086
  set -- $cmd; local verb="${1:-}"; shift || true
  case "$verb" in set|delete) ;; *) tprint "ERROR: Must start with 'set' or 'delete'."; pause; return 0 ;; esac
  yn="$(choose_yes_no "Run: $verb $* ?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  case "$verb" in set) cfg_set "$@" ;; delete) cfg_delete "$@" ;; esac
  cfg_apply
}

# ============================================================
# MAIN MENU
# ============================================================
main_menu() {
  die_no_access_if_needed
  while true; do
    cfg_cache_refresh 2>/dev/null || true
    tprint ""
    tprint "======================================"
    tprint " VyOS Dynamic Menu  (v3.1)"
    tprint "======================================"
    tprint "Interfaces:   $(scan_all_ifaces       | join_lines || echo NONE)"
    tprint "FW rulesets:  $(scan_firewall_rulesets | join_lines || echo NONE)"
    tprint "FW zones:     $(scan_fw_zones          | join_lines || echo NONE)"
    tprint "Port groups:  $(scan_port_groups       | join_lines || echo NONE)"
    tprint "Static routes:$(scan_static_routes     | join_lines || echo NONE)"
    tprint "DHCP pools:   $(scan_dhcp_pools        | join_lines || echo NONE)"
    tprint "NAT dest:     $(scan_nat_dest_rules    | join_lines || echo NONE)"
    tprint "NAT src:      $(scan_nat_source_rules  | join_lines || echo NONE)"
    tprint ""
    tprint " 1) Interfaces       (eth / bond / VLAN / loopback)"
    tprint " 2) Firewall         (rules + port groups + zone management)"
    tprint " 3) NAT              (DNAT / SNAT)"
    tprint " 4) Static Routes"
    tprint " 5) DHCP Server"
    tprint " 6) SSH Service"
    tprint " 7) System           (users + hostname)"
    tprint " 8) DNS Forwarding"
    tprint " 9) RIP"
    tprint "10) Raw mode         (restricted set/delete)"
    tprint "11) Show full config"
    tprint "12) Exit"
    tprint ""
    local c; tread c "Select: " || continue
    case "$c" in
      1)  iface_menu ;;
      2)  firewall_menu ;;
      3)  nat_menu ;;
      4)  static_routes_menu ;;
      5)  dhcp_server_menu ;;
      6)  ssh_service_menu ;;
      7)  system_menu ;;
      8)  dns_forwarding_menu ;;
      9)  rip_menu ;;
      10) raw_mode ;;
      11) tprint ""; get_cfg_cmds >"$TTY" 2>/dev/null || true; tprint ""; pause ;;
      12) cfg_end >/dev/null 2>&1 || true; builtin exit 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

main_menu
