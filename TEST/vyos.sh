#!/bin/vbash
# vyos-dynamic-menu.sh (v2.1 COMPLETE REFACTORED)
# Dynamic CRUD menu: Interfaces + Firewall + NAT + System + DNS + RIP + Static Routes + DHCP + SSH
#
# KEY IMPROVEMENTS (v2.1):
# - Zone creation: TWO modes now
#   * Single mode: assign one interface to one zone per invocation, return to menu
#   * Batch mode: scan unassigned interfaces, prompt for zone names in sequence
# - All loopback (lo) interfaces filtered from zone/interface lists
# - All menu selections are NUMBERED (user types numbers, not text)
# - Text input only for: names, IPs, descriptions, passwords
#
# EFFICIENCY (v2):
# - CONFIG CACHE: get_cfg_cmds output captured ONCE per menu action
# - MERGED INTERFACE MENU: unified eth/bond/VLAN/loopback
# - RELEVANT SUMMARIES: each submenu shows only what's needed
# - REDUCED PAUSES: no double-pause on inline output
#
# SAFETY:
# - ADD never overwrites existing items
# - All user input validated before cfg_set/cfg_delete
# - grep -F used throughout (no regex injection)
# - reject_if_unsafe_commandline guards raw mode
#
# AUDIT FIXES: FIX-1 through FIX-15 retained

TTY="/dev/tty"

# FIX-3: Harden PATH before any command lookups or sg re-exec.
export PATH=/opt/vyatta/bin:/opt/vyatta/sbin:/usr/sbin:/usr/bin:/sbin:/bin

if [ "$(id -gn 2>/dev/null)" != "vyattacfg" ]; then
  SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
  ARGS=""
  for a in "$@"; do
    ARGS="$ARGS $(printf "%q" "$a")"
  done
  # FIX-6: detect vbash dynamically
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

# FIX-15: 300s timeout on all reads
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
  # FIX-2: password briefly visible in /proc cmdline — VyOS platform limitation
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
  # FIX-13: strip both single and double quotes
  local s="$1"
  s="${s#[\'\"]}"
  s="${s%[\'\"]}"
  echo "$s"
}

# FIX-10: strip leading AND trailing whitespace
join_lines() { tr '\n' ' ' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'; }

# ============================================================
# CONFIG CACHE  ← core efficiency improvement
# ============================================================
_CFG_CACHE=""
_CFG_CACHE_VALID=0

cfg_cache_refresh() {
  local out
  out="$(run show configuration commands 2>&1)" || true

  if echo "$out" | grep -qiE "not assigned to any operator group|permission denied|authorization|not authorized|internal error"; then
    tprint ""
    tprint "ERROR: No permission to read config ('show configuration commands')."
    tprint "Run as a VyOS admin user or fix this user's operator permissions."
    tprint ""
    tprint "VyOS returned:"
    tprint "----------------------------------------"
    tprint "$out"
    tprint "----------------------------------------"
    return 1
  fi

  if [ -z "$out" ]; then
    tprint ""
    tprint "ERROR: 'show configuration commands' returned nothing."
    tprint "Check permissions or CLI session health."
    return 1
  fi

  _CFG_CACHE="$out"
  _CFG_CACHE_VALID=1
  return 0
}

cfg_cache_invalidate() {
  _CFG_CACHE=""
  _CFG_CACHE_VALID=0
}

grep_cfg() {
  if [ "$_CFG_CACHE_VALID" -eq 0 ]; then
    cfg_cache_refresh || return 1
  fi
  printf "%s\n" "$_CFG_CACHE" | grep -F "$1" || true
}

get_cfg_cmds() {
  if [ "$_CFG_CACHE_VALID" -eq 0 ]; then
    cfg_cache_refresh || return 1
  fi
  printf "%s\n" "$_CFG_CACHE"
}

# ============================================================
# LOAD_ARRAY (FIX-8: safe tmp-file pattern, no eval on values)
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
    tprint "ERROR: could not create temp file for load_array."; return 1
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
is_valid_username() {
  echo "$1" | grep -Eq '^[A-Za-z_][A-Za-z0-9_.-]{0,31}$'
}
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
# API SESSION
# ============================================================
API_ACTIVE=0
MY_SET="" MY_DELETE="" MY_COMMIT="" SAVE_BIN=""

api_detect_bins() {
  local SBIN="/opt/vyatta/sbin"
  MY_SET="$SBIN/my_set"
  MY_DELETE="$SBIN/my_delete"
  MY_COMMIT="$SBIN/my_commit"
  local candidates=(
    "$SBIN/vyos-config-save"   "$SBIN/vyatta-save-config"
    "$SBIN/vyos-save-config"   "$SBIN/vyos-save-config.py"
    "/usr/libexec/vyos/vyos-config-save"  "/usr/libexec/vyos/vyos-save-config"
    "/usr/libexec/vyos/vyos-save-config.py"
    "/usr/lib/vyos/vyos-config-save"      "/usr/lib/vyos/vyos-save-config.py"
  )
  SAVE_BIN=""
  local c
  for c in "${candidates[@]}"; do
    [ -x "$c" ] && SAVE_BIN="$c" && break
  done
}

api_begin() {
  disable_completion_env
  api_detect_bins
  if ! command -v cli-shell-api >/dev/null 2>&1; then
    tprint "ERROR: cli-shell-api not found."; pause; return 1
  fi
  if [ ! -x "$MY_SET" ] || [ ! -x "$MY_DELETE" ] || [ ! -x "$MY_COMMIT" ]; then
    tprint "ERROR: my_set/my_delete/my_commit not found in /opt/vyatta/sbin."; pause; return 1
  fi
  local session_env=""
  session_env="$(cli-shell-api getSessionEnv "$PPID" 2>/dev/null || true)"
  [ -z "$session_env" ] && session_env="$(cli-shell-api getSessionEnv "$$" 2>/dev/null || true)"
  if [ -z "$session_env" ]; then
    tprint "ERROR: cli-shell-api getSessionEnv failed."; pause; return 1
  fi
  eval "$session_env"
  if ! cli-shell-api setupSession <"$TTY" >"$TTY" 2>&1; then
    tprint "ERROR: setupSession failed."; pause; return 1
  fi
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
  if [ -n "${SAVE_BIN:-}" ] && [ -x "$SAVE_BIN" ]; then
    "$SAVE_BIN"; return $?
  fi
  tprint "ERROR: no working save binary found."
  tprint "Changes ARE committed but not saved to disk."
  return 1
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
warn_if_no_access() {
  if ! cfg_cache_refresh; then
    pause; return 1
  fi
  return 0
}

die_no_access_if_needed() {
  cfg_cache_refresh || exit 1
}

# ============================================================
# UI HELPERS
# ============================================================
SELECTED=""

select_from_list() {
  local title="$1"; shift
  local arr=("$@")
  local i choice

  tprint ""
  tprint "=== $title ==="
  if [ "${#arr[@]}" -eq 0 ]; then tprint "(none found)"; return 1; fi

  for i in "${!arr[@]}"; do
    tprintf "%2d) %s\n" "$((i+1))" "${arr[$i]}"
  done
  tprint " 0) Cancel"
  tprint ""

  tread choice "Select #: " || return 1
  if [ -z "$choice" ] || ! echo "$choice" | grep -Eq '^[0-9]+$'; then tprint "Invalid."; return 1; fi
  [ "$choice" -eq 0 ] && return 1
  if [ "$choice" -lt 1 ] || [ "$choice" -gt "${#arr[@]}" ]; then tprint "Invalid."; return 1; fi

  SELECTED="${arr[$((choice-1))]}"
  return 0
}

select_from_list_default() {
  local title="$1"; shift
  local def="$1"; shift
  local arr=("$@")
  local i choice def_idx=""

  tprint ""
  tprint "=== $title ==="
  if [ "${#arr[@]}" -eq 0 ]; then tprint "(none found)"; return 1; fi

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
    tread choice "Select # [${def_idx}]: " || return 1
    choice="${choice:-$def_idx}"
  else
    tread choice "Select #: " || return 1
  fi

  if [ -z "$choice" ] || ! echo "$choice" | grep -Eq '^[0-9]+$'; then tprint "Invalid."; return 1; fi
  [ "$choice" -eq 0 ] && return 1
  if [ "$choice" -lt 1 ] || [ "$choice" -gt "${#arr[@]}" ]; then tprint "Invalid."; return 1; fi

  SELECTED="${arr[$((choice-1))]}"
  return 0
}

choose_yes_no() {
  local prompt="$1" def="${2:-n}" def_label="No"
  { [ "$def" = "y" ] || [ "$def" = "Y" ]; } && def_label="Yes"
  if select_from_list_default "$prompt" "$def_label" "Yes" "No"; then
    case "$SELECTED" in Yes) echo "y";; No) echo "n";; esac
    return 0
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
  tprint ""; tprint "  destination = DNAT / port forwarding"
  tprint "  source      = SNAT / masquerade"
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
    tread val "$prompt [$def]: " || true
    echo "${val:-$def}"
  else
    tread val "$prompt: " || true
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
    out="$(cfg_commit 2>&1)"; rc=$?
    printf "%s\n" "$out" >"$TTY"

    if echo "$out" | grep -qi "No configuration changes to commit"; then
      tprint ""; tprint "NOTE: Nothing changed — nothing to commit."
      cfg_end; cfg_cache_invalidate; pause; return 0
    fi
    if [ $rc -ne 0 ]; then
      tprint ""; tprint "ERROR: commit failed. Nothing applied."
      cfg_end; cfg_cache_invalidate; pause; return 1
    fi

    disable_completion_env
    if ! cfg_save <"$TTY" >"$TTY" 2>&1; then
      tprint ""; tprint "ERROR: save failed. Changes committed but not saved to disk."
      cfg_end; cfg_cache_invalidate; pause; return 1
    fi

    tprint "DONE: committed + saved."
    cfg_end
  else
    tprint "Not committed. (No changes saved.)"
    cfg_end
  fi
  cfg_cache_invalidate
  pause
  return 0
}

# ============================================================
# SAFETY HELPERS
# ============================================================
is_number_in_list() {
  local needle="$1"; shift
  local x; for x in "$@"; do [ "$x" = "$needle" ] && return 0; done; return 1
}
is_in_list() {
  local needle="$1"; shift
  local x; for x in "$@"; do [ "$x" = "$needle" ] && return 0; done; return 1
}
next_free_rule_number() {
  local used=("$@") n=10
  while is_number_in_list "$n" "${used[@]}"; do n=$((n+10)); done
  echo "$n"
}
require_numeric() { echo "$1" | grep -Eq '^[0-9]+$'; }

require_nonempty_list_or_return() {
  local label="$1"; shift
  if [ "${#@}" -eq 0 ] || { [ "$#" -eq 1 ] && [ -z "$1" ]; }; then
    tprint ""; tprint "Nothing available: $label"
    tprint "(Config has none, or permission problem reading config.)"
    tprint ""; pause; return 1
  fi
  return 0
}

# ============================================================
# SCAN FUNCTIONS  (all use grep_cfg — reads from cache)
# ============================================================

# --- Firewall ---
scan_firewall_rulesets() {
  grep_cfg "set firewall ipv4 name " | awk '{print $5}' | sort -u | while read -r n; do strip_quotes "$n"; done
}
scan_firewall_rule_numbers() {
  local rs="$1"
  {
    grep_cfg "set firewall ipv4 name '$rs' rule " | awk '{print $7}'
    grep_cfg "set firewall ipv4 name $rs rule "   | awk '{print $7}'
  } | sort -u
}

# --- NAT ---
scan_nat_dest_rules()   { grep_cfg "set nat destination rule " | awk '{print $5}' | sort -u; }
scan_nat_source_rules() { grep_cfg "set nat source rule "      | awk '{print $5}' | sort -u; }

# --- Interfaces ---
scan_eth_ifaces()      { grep_cfg "set interfaces ethernet " | awk '{print $4}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_bond_ifaces()     { grep_cfg "set interfaces bonding "  | awk '{print $4}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_vlan_ifaces() {
  grep_cfg "set interfaces ethernet " | grep -F " vif " | awk '{print $4 "." $6}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
  grep_cfg "set interfaces bonding " | grep -F " vif " | awk '{print $4 "." $6}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}
scan_loopback_ifaces() { grep_cfg "set interfaces loopback " | awk '{print $4}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_all_ifaces() {
  { scan_eth_ifaces; scan_bond_ifaces; scan_vlan_ifaces; scan_loopback_ifaces; } | sort -u
}

# --- Zones ---
scan_fw_zones() { grep_cfg "set firewall zone " | awk '{print $4}' | sort -u; }
scan_zone_bindings() {
  grep_cfg "set firewall zone " \
    | grep -F " from " | grep -F " firewall name " \
    | awk '{print $4 "|" $6 "|" $9}' \
    | while IFS='|' read -r to from rs; do
        echo "$(strip_quotes "$to")|$(strip_quotes "$from")|$(strip_quotes "$rs")"
      done | sort -u
}

binding_exists() {
  # Returns 0 if a TO<-FROM binding already exists in config.
  local to="$1" from="$2"
  scan_zone_bindings | grep -F -q "${to}|${from}|"
}

binding_get_ruleset() {
  # Returns the ruleset name currently attached to a TO<-FROM binding.
  local to="$1" from="$2"
  scan_zone_bindings | grep -F "${to}|${from}|" | head -n 1 | awk -F'|' '{print $3}'
}

# --- System ---
scan_login_users() {
  grep_cfg "set system login user " | awk '{print $5}' | sort -u | while read -r u; do strip_quotes "$u"; done
}
get_current_username() { (id -un 2>/dev/null || true) | tr -d '\n'; }
get_current_hostname() {
  local hn
  hn="$(grep_cfg "set system host-name " | head -n 1 | awk '{print $4}' || true)"
  hn="$(strip_quotes "$hn")"
  [ -n "$hn" ] && echo "$hn" || (hostname 2>/dev/null || true)
}

# --- DNS ---
scan_dns_allow_from()    { grep_cfg "set service dns forwarding allow-from "    | awk '{print $6}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_dns_listen_address() { grep_cfg "set service dns forwarding listen-address " | awk '{print $6}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
dns_system_is_enabled()  { grep_cfg "set service dns forwarding system" | grep -q .; }
scan_dns_name_servers()  { grep_cfg "set system name-server " | awk '{print $4}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_dns_forward_domains() { grep_cfg "set service dns forwarding domain " | grep -F " name-server " | awk '{print $6}' | sort -u | while read -r x; do strip_quotes "$x"; done; }

# --- RIP ---
scan_rip_interfaces()       { grep_cfg "set protocols rip interface "           | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_rip_networks()         { grep_cfg "set protocols rip network "             | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_rip_neighbors()        { grep_cfg "set protocols rip neighbor "            | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_rip_passive_interfaces(){ grep_cfg "set protocols rip passive-interface " | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_rip_redistribute()     { grep_cfg "set protocols rip redistribute "        | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_rip_static_routes()    { grep_cfg "set protocols rip route "               | awk '{print $5}' | sort -u | while read -r x; do strip_quotes "$x"; done; }
scan_rip_iface_settings()   { grep_cfg " ip rip " | sort -u; }

# --- Static routes ---
scan_static_routes() {
  grep_cfg "set protocols static route " \
    | awk '{print $5}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

scan_static_route_nexthops() {
  local prefix="$1"
  {
    grep_cfg "set protocols static route $prefix next-hop "
    grep_cfg "set protocols static route '$prefix' next-hop "
  } | awk '{print $7}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

scan_static_blackholes() {
  grep_cfg "set protocols static route " \
    | grep -F " blackhole" \
    | awk '{print $5}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

# --- DHCP ---
scan_dhcp_pools() {
  grep_cfg "set service dhcp-server shared-network-name " \
    | awk '{print $6}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

scan_dhcp_subnets() {
  local pool="$1"
  {
    grep_cfg "set service dhcp-server shared-network-name $pool subnet "
    grep_cfg "set service dhcp-server shared-network-name '$pool' subnet "
  } | awk '{print $8}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

# --- SSH ---
scan_ssh_listen_addresses() {
  grep_cfg "set service ssh listen-address " \
    | awk '{print $5}' | sort -u \
    | while read -r x; do strip_quotes "$x"; done
}

ssh_get_port() {
  grep_cfg "set service ssh port " \
    | awk '{print $5}' | head -n 1 \
    | while read -r x; do strip_quotes "$x"; done
}

ssh_is_enabled() {
  grep_cfg "set service ssh" | grep -q .
}

# --- Interface address helpers ---
resolve_iface_path() {
  local iface="$1"
  echo "$iface" | grep -Eq '^eth[0-9]+\.[0-9]+$'  && { echo "ethernet|${iface%%.*}|${iface#*.}"; return; }
  echo "$iface" | grep -Eq '^bond[0-9]+\.[0-9]+$' && { echo "bonding|${iface%%.*}|${iface#*.}"; return; }
  echo "$iface" | grep -Eq '^bond[0-9]+'           && { echo "bonding|$iface|";   return; }
  echo "$iface" | grep -Eq '^lo[0-9]*$'            && { echo "loopback|$iface|";  return; }
  echo "ethernet|$iface|"
}

iface_cfg_set() {
  local iface="$1"; shift
  local r t p v
  r="$(resolve_iface_path "$iface")"
  t="$(echo "$r"|cut -d'|' -f1)" p="$(echo "$r"|cut -d'|' -f2)" v="$(echo "$r"|cut -d'|' -f3)"
  [ -n "$v" ] && cfg_set interfaces "$t" "$p" vif "$v" "$@" || cfg_set interfaces "$t" "$p" "$@"
}

iface_cfg_delete() {
  local iface="$1"; shift
  local r t p v
  r="$(resolve_iface_path "$iface")"
  t="$(echo "$r"|cut -d'|' -f1)" p="$(echo "$r"|cut -d'|' -f2)" v="$(echo "$r"|cut -d'|' -f3)"
  [ -n "$v" ] && cfg_delete interfaces "$t" "$p" vif "$v" "$@" || cfg_delete interfaces "$t" "$p" "$@"
}

scan_iface_addresses() {
  local iface="$1"
  local r t p v pattern
  r="$(resolve_iface_path "$iface")"
  t="$(echo "$r"|cut -d'|' -f1)" p="$(echo "$r"|cut -d'|' -f2)" v="$(echo "$r"|cut -d'|' -f3)"
  [ -n "$v" ] && pattern="set interfaces $t $p vif $v address " || pattern="set interfaces $t $p address "
  grep_cfg "$pattern" | awk '{print $NF}' | sort -u | while read -r x; do strip_quotes "$x"; done
}

get_iface_description() {
  local iface="$1"
  local r t p v pattern
  r="$(resolve_iface_path "$iface")"
  t="$(echo "$r"|cut -d'|' -f1)" p="$(echo "$r"|cut -d'|' -f2)" v="$(echo "$r"|cut -d'|' -f3)"
  [ -n "$v" ] && pattern="set interfaces $t $p vif $v description " || pattern="set interfaces $t $p description "
  grep_cfg "$pattern" | awk '{
    for(i=1;i<=NF;i++) if($i=="description"){ s=""; for(j=i+1;j<=NF;j++) s=s (j>i+1?" ":"") $j; print s; break }
  }' | head -n 1 | while read -r x; do strip_quotes "$x"; done
}

iface_is_disabled() {
  local iface="$1"
  local r t p v pattern
  r="$(resolve_iface_path "$iface")"
  t="$(echo "$r"|cut -d'|' -f1)" p="$(echo "$r"|cut -d'|' -f2)" v="$(echo "$r"|cut -d'|' -f3)"
  [ -n "$v" ] && pattern="set interfaces $t $p vif $v disable" || pattern="set interfaces $t $p disable"
  grep_cfg "$pattern" | grep -q .
}

# ============================================================
# COMPACT SUMMARIES
# ============================================================
_iface_summary() {
  tprint "  Ethernet:  $(scan_eth_ifaces  | join_lines || echo NONE)"
  tprint "  Bonding:   $(scan_bond_ifaces  | join_lines || echo NONE)"
  tprint "  VLANs:     $(scan_vlan_ifaces  | join_lines || echo NONE)"
  tprint "  Loopback:  $(scan_loopback_ifaces | join_lines || echo NONE)"
}
_fw_summary() {
  tprint "  Rulesets: $(scan_firewall_rulesets | join_lines || echo NONE)"
  tprint "  Zones:    $(scan_fw_zones | join_lines || echo NONE)"
}
_nat_summary() {
  tprint "  DNAT rules: $(scan_nat_dest_rules   | join_lines || echo NONE)"
  tprint "  SNAT rules: $(scan_nat_source_rules | join_lines || echo NONE)"
}
_dns_summary() {
  tprint "  allow-from:     $(scan_dns_allow_from    | join_lines || echo NONE)"
  tprint "  listen-address: $(scan_dns_listen_address | join_lines || echo NONE)"
  local sys="disabled"; dns_system_is_enabled && sys="ENABLED"
  tprint "  system:         $sys"
  tprint "  name-servers:   $(scan_dns_name_servers   | join_lines || echo NONE)"
  tprint "  fwd domains:    $(scan_dns_forward_domains | join_lines || echo NONE)"
}
_rip_summary() {
  tprint "  interfaces:         $(scan_rip_interfaces        | join_lines || echo NONE)"
  tprint "  networks:           $(scan_rip_networks          | join_lines || echo NONE)"
  tprint "  neighbors:          $(scan_rip_neighbors         | join_lines || echo NONE)"
  tprint "  passive-interfaces: $(scan_rip_passive_interfaces| join_lines || echo NONE)"
  tprint "  redistribute:       $(scan_rip_redistribute      | join_lines || echo NONE)"
  local di="disabled"
  grep_cfg "set protocols rip default-information originate" | grep -q . && di="ENABLED"
  tprint "  default-info originate: $di"
}

run_cmd_to_tty() {
  local cmd="$1"
  tprint ""; tprint ">> $cmd"
  tprint "--------------------------------------------------------"
  # shellcheck disable=SC2086
  run $cmd >"$TTY" 2>&1 || tprint "(command unavailable on this build)"
  tprint "--------------------------------------------------------"
}

# ============================================================
# ZONE HELPERS (v2.1 — FIXED)
# ============================================================

get_unassigned_real_ifaces() {
  # Returns real interfaces NOT already in a zone, excluding loopback.
  # FIX: ensure cache is warm before calling scan_zone_ifaces, and
  #      collect assigned ifaces into an array before filtering.

  # Ensure cache is valid before any scan calls
  if [ "$_CFG_CACHE_VALID" -eq 0 ]; then
    cfg_cache_refresh || return 1
  fi

  local all=() assigned=() result=()
  load_array all scan_all_ifaces

  # Collect all interfaces already assigned to any zone
  local zi z i
  while IFS='|' read -r z i; do
    [ -n "$i" ] && assigned+=("$i")
  done < <(scan_zone_ifaces)

  # Filter: exclude loopback and already-assigned
  local iface
  for iface in "${all[@]}"; do
    # Skip loopback
    if echo "$iface" | grep -Eq '^lo[0-9]*$'; then
      continue
    fi
    # Skip if already assigned to a zone
    if is_in_list "$iface" "${assigned[@]}"; then
      continue
    fi
    result+=("$iface")
  done

  printf '%s\n' "${result[@]}"
}

zone_create_single_interface() {
  # MODE A: Create ONE zone — normal or local-zone type.
  #
  # FIXES applied:
  #   - Normal zone: interface selection only shown for normal type
  #   - Local zone:  interface selection skipped entirely (local-zone has no member)
  #   - Both types:  default-action drop set before interface assignment
  #   - Cache refreshed before unassigned iface scan

  local zones=() zname yn zone_type default_action

  # Refresh cache before scanning
  cfg_cache_refresh || return 0

  load_array zones scan_fw_zones
  tprint ""; tprint "Existing zones: ${zones[*]:-(none)}"; tprint ""

  # Ask zone type FIRST so we know whether to show interface selection
  select_from_list_default "Zone type" "normal" "normal" "local-zone (router self)" || return 0
  case "$SELECTED" in
    "local-zone (router self)") zone_type="local" ;;
    *) zone_type="normal" ;;
  esac

  # For normal zones only: pick an unassigned interface
  local iface=""
  if [ "$zone_type" = "normal" ]; then
    local unassigned_ifaces=()
    load_array unassigned_ifaces get_unassigned_real_ifaces
    require_nonempty_list_or_return "unassigned real interfaces" "${unassigned_ifaces[@]}" || return 0
    select_from_list "Select interface for new zone" "${unassigned_ifaces[@]}" || return 0
    iface="$SELECTED"
  fi

  # Ask zone name
  if [ "$zone_type" = "local" ]; then
    zname="$(ask "Local zone name (e.g. LOCAL, ROUTER)" "")"
  else
    zname="$(ask "Zone name for $iface (e.g. LAN, WAN, DMZ)" "")"
  fi
  [ -z "$zname" ] && return 0

  if ! is_safe_ruleset_name "$zname"; then
    tprint "ERROR: Invalid zone name (letters/numbers/_/./- max 64)."; pause; return 0
  fi
  if is_in_list "$zname" "${zones[@]}"; then
    tprint "ERROR: Zone '$zname' already exists."; pause; return 0
  fi

  # Ask default-action
  select_from_list_default "Default action for $zname" "drop" "drop" "accept" "reject" || return 0
  default_action="$SELECTED"

  # Confirm summary
  tprint ""
  if [ "$zone_type" = "local" ]; then
    tprint "SUMMARY: create local-zone '$zname'  default-action=$default_action"
    tprint "         (no interface member — local-zone represents the router itself)"
  else
    tprint "SUMMARY: create zone '$zname'  interface=$iface  default-action=$default_action"
  fi
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0

  if [ "$zone_type" = "local" ]; then
    # local-zone: set local-zone flag and default-action; NO interface member
    cfg_set firewall zone "$zname" local-zone
    cfg_set firewall zone "$zname" default-action "$default_action"
  else
    # normal zone: set default-action FIRST, then assign interface
    cfg_set firewall zone "$zname" default-action "$default_action"
    cfg_set firewall zone "$zname" member interface "$iface"
  fi

  cfg_apply
}

zone_create_batch_from_interfaces() {
  # MODE B: Batch-create zones from all unassigned interfaces.
  #
  # FIXES applied:
  #   - Cache refreshed before scan
  #   - Single cfg_begin / cfg_apply wraps the entire batch (one commit)
  #   - default-action set before interface assignment for every zone
  #   - In-memory created_zones tracks names used this session to catch
  #     intra-batch duplicates (cache is invalid mid-session)
  #   - Skipped interfaces are tracked to avoid double-assignment

  # Refresh cache before scanning
  cfg_cache_refresh || return 0

  local unassigned_ifaces=() yn
  load_array unassigned_ifaces get_unassigned_real_ifaces
  require_nonempty_list_or_return "unassigned real interfaces" "${unassigned_ifaces[@]}" || return 0

  tprint ""; tprint "Found ${#unassigned_ifaces[@]} unassigned real interfaces:"
  printf '%s\n' "${unassigned_ifaces[@]}" | awk '{print "  - " $0}' >"$TTY"
  tprint ""
  tprint "You will be prompted for a zone name and default-action for each."
  tprint "Leave the zone name blank to skip an interface."
  tprint ""

  # Collect zone definitions interactively BEFORE opening a config session
  # so we don't hold the session open during user input.
  local existing_zones=()
  load_array existing_zones scan_fw_zones

  # Track zones defined in this batch (in-memory duplicate guard)
  local created_zones=()

  # Arrays to hold what we will commit
  local batch_ifaces=()
  local batch_znames=()
  local batch_actions=()

  local iface zname default_action

  for iface in "${unassigned_ifaces[@]}"; do
    tprint ""; tprint "--- Interface: $iface ---"

    zname="$(ask "Zone name for $iface (blank to skip)" "")"
    [ -z "$zname" ] && { tprint "Skipped $iface."; continue; }

    if ! is_safe_ruleset_name "$zname"; then
      tprint "ERROR: Invalid zone name (letters/numbers/_/./- max 64). Skipping $iface."; continue
    fi
    # Check against already-existing zones AND zones created in this batch
    if is_in_list "$zname" "${existing_zones[@]}" || is_in_list "$zname" "${created_zones[@]}"; then
      tprint "ERROR: Zone '$zname' already exists or was already used in this batch. Skipping."; continue
    fi

    select_from_list_default "Default action for $zname" "drop" "drop" "accept" "reject" || {
      tprint "Skipped $iface (no action selected)."; continue
    }
    default_action="$SELECTED"

    tprint "Queued: zone '$zname'  interface=$iface  default-action=$default_action"
    batch_ifaces+=("$iface")
    batch_znames+=("$zname")
    batch_actions+=("$default_action")
    created_zones+=("$zname")
  done

  # Nothing to do?
  if [ "${#batch_znames[@]}" -eq 0 ]; then
    tprint ""; tprint "Nothing to create."; pause; return 0
  fi

  # Show summary and confirm before opening the config session
  tprint ""
  tprint "=== Batch Summary ==="
  local idx
  for idx in "${!batch_znames[@]}"; do
    tprintf "  zone %-16s  interface=%-12s  default-action=%s\n" \
      "${batch_znames[$idx]}" "${batch_ifaces[$idx]}" "${batch_actions[$idx]}"
  done
  tprint ""
  yn="$(choose_yes_no "Create all zones above in a single commit?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  # Open ONE config session for the entire batch
  cfg_begin || return 0

  for idx in "${!batch_znames[@]}"; do
    zname="${batch_znames[$idx]}"
    iface="${batch_ifaces[$idx]}"
    default_action="${batch_actions[$idx]}"

    tprint "Staging: zone '$zname'  interface=$iface  default-action=$default_action"
    # Set default-action FIRST, then assign interface (per VyOS docs)
    cfg_set firewall zone "$zname" default-action "$default_action"
    cfg_set firewall zone "$zname" member interface "$iface"
  done

  # Single commit + save for the whole batch
  cfg_apply

  tprint "Batch zone creation complete."
  pause
}

# ============================================================
# INTERFACE MENU
# ============================================================
_iface_choose() {
  local label="${1:-Select interface}"
  local all=()
  load_array all scan_all_ifaces
  require_nonempty_list_or_return "interfaces" "${all[@]}" || return 1
  select_from_list "$label" "${all[@]}" && echo "$SELECTED" && return 0
  return 1
}

iface_op_set_ip() {
  local iface addrs=() new_ip yn
  iface="$(_iface_choose "Select interface — add/change IP")" || return 0
  load_array addrs scan_iface_addresses "$iface"
  tprint ""
  tprint "Current addresses on $iface: ${addrs[*]:-(none)}"
  tprint "VyOS supports multiple IPs per interface."
  tprint ""
  new_ip="$(ask "New address (CIDR) e.g. 192.168.1.1/24" "")"
  [ -z "$new_ip" ] && return 0
  if ! is_valid_cidr4 "$new_ip"; then
    tprint "ERROR: Must be IPv4/CIDR like 192.168.1.1/24."; pause; return 0
  fi
  if is_in_list "$new_ip" "${addrs[@]}"; then
    tprint "ERROR: $new_ip already configured on $iface."; pause; return 0
  fi
  tprint ""; tprint "SUMMARY:  $iface  add address $new_ip"
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  iface_cfg_set "$iface" address "$new_ip"
  cfg_apply
}

iface_op_delete_ip() {
  local iface addrs=() target yn
  iface="$(_iface_choose "Select interface — delete IP from")" || return 0
  load_array addrs scan_iface_addresses "$iface"
  require_nonempty_list_or_return "addresses on $iface" "${addrs[@]}" || return 0
  select_from_list "Select address to DELETE from $iface" "${addrs[@]}" || return 0
  target="$SELECTED"
  tprint ""; tprint "Delete: $target  from  $iface"
  yn="$(choose_yes_no "Proceed?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  iface_cfg_delete "$iface" address "$target"
  cfg_apply
}

iface_op_set_description() {
  local iface cur_desc new_desc yn
  iface="$(_iface_choose "Select interface — set description")" || return 0
  cur_desc="$(get_iface_description "$iface")"
  tprint ""; tprint "Current description on $iface: ${cur_desc:-(none)}"
  tprint "Leave blank to DELETE the description."
  new_desc="$(ask "New description" "")"
  if [ -n "$new_desc" ] && ! is_safe_free_text "$new_desc"; then
    tprint "ERROR: Unsupported characters in description."; pause; return 0
  fi
  tprint ""
  [ -z "$new_desc" ] && tprint "SUMMARY: DELETE description on $iface" || tprint "SUMMARY: $iface description → $new_desc"
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
    cfg_begin || return 0
    iface_cfg_delete "$iface" disable
  else
    tprint "$iface is: ENABLED"
    tprint "WARNING: Disabling a live interface drops all traffic through it."
    yn="$(choose_yes_no "Disable $iface?" "n" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0
    iface_cfg_set "$iface" disable
  fi
  cfg_apply
}

iface_op_show_details() {
  local iface
  iface="$(_iface_choose "Select interface — show details")" || return 0
  local r t p v
  r="$(resolve_iface_path "$iface")"
  t="$(echo "$r"|cut -d'|' -f1)" p="$(echo "$r"|cut -d'|' -f2)" v="$(echo "$r"|cut -d'|' -f3)"

  tprint ""; tprint "=== $iface ==="
  tprint "--- Config ---"
  tprint "--------------------------------------------------------"
  if [ -n "$v" ]; then
    grep_cfg "set interfaces $t $p vif $v " >"$TTY" 2>/dev/null || true
    grep_cfg "set interfaces $t '$p' vif $v " >>"$TTY" 2>/dev/null || true
  else
    grep_cfg "set interfaces $t $p " >"$TTY" 2>/dev/null || true
    grep_cfg "set interfaces $t '$p' " >>"$TTY" 2>/dev/null || true
  fi
  tprint "--------------------------------------------------------"
  tprint ""
  tprint "  Type:        $t"
  tprint "  Addresses:   $(scan_iface_addresses "$iface" | join_lines || echo "(none)")"
  tprint "  Description: $(get_iface_description "$iface" || echo "(none)")"
  iface_is_disabled "$iface" && tprint "  Admin state: DISABLED" || tprint "  Admin state: enabled"
  tprint ""
  tprint "--- Operational ---"
  tprint "--------------------------------------------------------"
  run show interfaces "$t" "$p" >"$TTY" 2>&1 || run show interfaces >"$TTY" 2>&1 || true
  tprint "--------------------------------------------------------"
  pause
}

iface_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""
    tprint "=========================="
    tprint " Interfaces"
    tprint "=========================="
    _iface_summary
    tprint "Types: ethernet · bonding · VLAN (ethX.VID) · loopback"
    tprint ""
    tprint "1) Set / add IP address"
    tprint "2) Delete IP address"
    tprint "3) Set description"
    tprint "4) Enable / disable interface"
    tprint "5) Show interface details"
    tprint "6) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) iface_op_set_ip ;;
      2) iface_op_delete_ip ;;
      3) iface_op_set_description ;;
      4) iface_op_enable_disable ;;
      5) iface_op_show_details ;;
      6) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# FIREWALL RULES
# ============================================================
fw_choose_ruleset_existing_only() {
  local arr=(); load_array arr scan_firewall_rulesets
  require_nonempty_list_or_return "firewall rulesets" "${arr[@]}" || return 1
  select_from_list "Select ruleset" "${arr[@]}" && echo "$SELECTED" && return 0
  return 1
}

fw_choose_ruleset_or_new() {
  local arr=(); load_array arr scan_firewall_rulesets
  if [ "${#arr[@]}" -gt 0 ]; then
    if select_from_list "Select ruleset (or cancel to type a new name)" "${arr[@]}"; then
      echo "$SELECTED"; return 0
    fi
  fi
  local rs; rs="$(ask "Ruleset name (e.g. DMZ-to-LAN)" "")"
  [ -z "$rs" ] && return 1
  if ! is_safe_ruleset_name "$rs"; then
    tprint "ERROR: Invalid ruleset name (letters/numbers/_/./- max 64)."; pause; return 1
  fi
  echo "$rs"
}

fw_choose_rule_number_existing() {
  local rs="$1" arr=()
  load_array arr scan_firewall_rule_numbers "$rs"
  require_nonempty_list_or_return "rules in $rs" "${arr[@]}" || return 1
  select_from_list "Select existing rule number in $rs" "${arr[@]}" && echo "$SELECTED" && return 0
  return 1
}

fw_choose_rule_number_new_only() {
  local rs="$1" used=() suggested n
  load_array used scan_firewall_rule_numbers "$rs"
  suggested="$(next_free_rule_number "${used[@]}")"
  tprint ""; tprint "Existing rules in $rs: ${used[*]:-(none)}"
  tprint "Next free rule number: $suggested"; tprint ""
  while true; do
    n="$(ask "New rule number" "$suggested")"
    [ -z "$n" ] && { tprint "Required."; continue; }
    require_numeric "$n" || { tprint "ERROR: must be a number."; continue; }
    is_number_in_list "$n" "${used[@]}" && { tprint "ERROR: rule $n exists. Use Update/Delete to change it."; continue; }
    break
  done
  echo "$n"
}

fw_preview_rule() {
  local rs="$1" n="$2"
  tprint ""; tprint "Current config — $rs rule $n:"
  tprint "--------------------------------------------------------"
  grep_cfg "set firewall ipv4 name '$rs' rule $n " >"$TTY" 2>/dev/null || true
  grep_cfg "set firewall ipv4 name $rs rule $n "   >>"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"; tprint ""
}

fw_list_ruleset() {
  local rs; rs="$(fw_choose_ruleset_existing_only)" || return 0
  tprint ""; tprint "Ruleset: $rs"
  tprint "--------------------------------------------------------"
  grep_cfg "set firewall ipv4 name '$rs' " >"$TTY" 2>/dev/null || true
  grep_cfg "set firewall ipv4 name $rs "   >>"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"
  pause
}

fw_add_rule_guided_safe() {
  local rs n action proto desc saddr daddr sport dport state_est state_rel state_new yn
  tprint ""; tprint "ADD firewall rule (safe — new rule number only)"
  rs="$(fw_choose_ruleset_or_new)" || return 0
  n="$(fw_choose_rule_number_new_only "$rs")" || return 0
  tprint ""; tprint "Creating: $rs rule $n — fill optional fields or leave blank."
  action="$(choose_fw_action "accept")" || return 0
  proto="$(choose_fw_protocol "tcp")" || return 0
  desc="$(ask "Description (optional)" "")"
  [ -n "$desc" ] && ! is_safe_free_text "$desc" && { tprint "ERROR: Invalid description."; pause; return 0; }
  saddr="$(ask "Source address/CIDR (optional)" "")"
  [ -n "$saddr" ] && ! is_valid_cidr4 "$saddr" && ! is_valid_ipv4 "$saddr" && { tprint "ERROR: Must be IPv4 or CIDR."; pause; return 0; }
  daddr="$(ask "Destination address/CIDR (optional)" "")"
  [ -n "$daddr" ] && ! is_valid_cidr4 "$daddr" && ! is_valid_ipv4 "$daddr" && { tprint "ERROR: Must be IPv4 or CIDR."; pause; return 0; }
  sport="$(ask "Source port or range (optional)" "")"
  [ -n "$sport" ] && ! is_valid_port_or_range "$sport" && { tprint "ERROR: Invalid port."; pause; return 0; }
  dport="$(ask "Destination port or range (optional)" "")"
  [ -n "$dport" ] && ! is_valid_port_or_range "$dport" && { tprint "ERROR: Invalid port."; pause; return 0; }
  state_est="$(choose_yes_no "Match ESTABLISHED?" "n" || echo "n")"
  state_rel="$(choose_yes_no "Match RELATED?"     "n" || echo "n")"
  state_new="$(choose_yes_no "Match NEW?"         "n" || echo "n")"

  tprint ""; tprint "SUMMARY: $rs rule $n  action=$action  proto=$proto"
  [ -n "$saddr"  ] && tprint "  src-addr: $saddr"
  [ -n "$sport"  ] && tprint "  src-port: $sport"
  [ -n "$daddr"  ] && tprint "  dst-addr: $daddr"
  [ -n "$dport"  ] && tprint "  dst-port: $dport"
  [ -n "$desc"   ] && tprint "  desc: $desc"
  tprint ""
  yn="$(choose_yes_no "Create this rule?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  # Auto-set ruleset default-action drop if this is a brand-new ruleset (VyOS requires it)
  local existing_rs=()
  load_array existing_rs scan_firewall_rulesets
  if ! is_in_list "$rs" "${existing_rs[@]}"; then
    tprint "New ruleset \'$rs\' — setting default-action drop."
    cfg_set firewall ipv4 name "$rs" default-action drop
  fi
  cfg_set firewall ipv4 name "$rs" rule "$n" action "$action"
  [ -n "$desc"  ] && cfg_set firewall ipv4 name "$rs" rule "$n" description "$desc"
  [ -n "$proto" ] && [ "$proto" != "any" ] && cfg_set firewall ipv4 name "$rs" rule "$n" protocol "$proto"
  [ -n "$saddr" ] && cfg_set firewall ipv4 name "$rs" rule "$n" source address "$saddr"
  [ -n "$daddr" ] && cfg_set firewall ipv4 name "$rs" rule "$n" destination address "$daddr"
  [ -n "$sport" ] && cfg_set firewall ipv4 name "$rs" rule "$n" source port "$sport"
  [ -n "$dport" ] && cfg_set firewall ipv4 name "$rs" rule "$n" destination port "$dport"
  # VyOS 2025 rolling: state match requires "enable" keyword
  { [ "$state_est" = "y" ] || [ "$state_est" = "Y" ]; } && cfg_set firewall ipv4 name "$rs" rule "$n" state established
  { [ "$state_rel" = "y" ] || [ "$state_rel" = "Y" ]; } && cfg_set firewall ipv4 name "$rs" rule "$n" state related
  { [ "$state_new" = "y" ] || [ "$state_new" = "Y" ]; } && cfg_set firewall ipv4 name "$rs" rule "$n" state new
  cfg_apply
}

fw_update_single_field() {
  local rs n field val yn
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
      val="$(choose_fw_action "accept")" || return 0
      cfg_begin || return 0; cfg_set firewall ipv4 name "$rs" rule "$n" action "$val"; cfg_apply ;;
    protocol)
      val="$(choose_fw_protocol "tcp")" || return 0
      cfg_begin || return 0
      [ "$val" = "any" ] && cfg_delete firewall ipv4 name "$rs" rule "$n" protocol \
                         || cfg_set   firewall ipv4 name "$rs" rule "$n" protocol "$val"
      cfg_apply ;;
    description)
      tprint "Leave blank to DELETE."; val="$(ask "New description" "")"
      [ -n "$val" ] && ! is_safe_free_text "$val" && { tprint "ERROR: Invalid."; pause; return 0; }
      cfg_begin || return 0
      [ -z "$val" ] && cfg_delete firewall ipv4 name "$rs" rule "$n" description \
                    || cfg_set   firewall ipv4 name "$rs" rule "$n" description "$val"
      cfg_apply ;;
    "source address"|"destination address")
      tprint "Leave blank to DELETE."; val="$(ask "IPv4 or CIDR" "")"
      [ -n "$val" ] && ! is_valid_ipv4 "$val" && ! is_valid_cidr4 "$val" && { tprint "ERROR: Invalid."; pause; return 0; }
      cfg_begin || return 0
      local side="${field%% *}"
      [ -z "$val" ] && cfg_delete firewall ipv4 name "$rs" rule "$n" "$side" address \
                    || cfg_set   firewall ipv4 name "$rs" rule "$n" "$side" address "$val"
      cfg_apply ;;
    "source port"|"destination port")
      tprint "Leave blank to DELETE."; val="$(ask "Port or range" "")"
      [ -n "$val" ] && ! is_valid_port_or_range "$val" && { tprint "ERROR: Invalid port."; pause; return 0; }
      cfg_begin || return 0
      local pside="${field%% *}"
      [ -z "$val" ] && cfg_delete firewall ipv4 name "$rs" rule "$n" "$pside" port \
                    || cfg_set   firewall ipv4 name "$rs" rule "$n" "$pside" port "$val"
      cfg_apply ;;
    "state established"|"state related"|"state new")
      yn="$(choose_yes_no "Enable this state match?" "y" || echo "n")"
      local st="${field#state }"
      cfg_begin || return 0
      # VyOS rolling current: state match is just the state name, no "enable" keyword
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
# ZONE BINDINGS
# ============================================================
scan_zone_ifaces() {
  grep_cfg "set firewall zone " | grep -F " member interface " \
    | awk '{print $4 "|" $7}' \
    | while IFS='|' read -r z i; do echo "$(strip_quotes "$z")|$(strip_quotes "$i")"; done \
    | sort -u
}

scan_zone_default_action() {
  local zone="$1"
  grep_cfg "set firewall zone $zone default-action " \
    | awk '{print $NF}' | head -n 1 | while read -r x; do strip_quotes "$x"; done
}

zone_list_full() {
  local zones=(); load_array zones scan_fw_zones
  if [ "${#zones[@]}" -eq 0 ]; then tprint "(no zones defined)"; pause; return 0; fi
  tprint ""
  tprint "=== Zones ==="
  local z da ifaces
  for z in "${zones[@]}"; do
    da="$(scan_zone_default_action "$z" || echo -)"
    ifaces="$(scan_zone_ifaces | awk -F'|' -v z="$z" '$1==z{print $2}' | tr '\n' ' ' || echo -)"
    tprintf "  %-16s  default-action=%-8s  interfaces=%s\n" "$z" "${da:-(none)}" "${ifaces:-(none)}"
  done
  tprint ""
  tprint "=== Bindings (TO <- FROM = RULESET) ==="
  local b=(); load_array b scan_zone_bindings
  if [ "${#b[@]}" -gt 0 ]; then
    printf "%s\n" "${b[@]}" | awk -F'|' '{printf "  %-12s <- %-12s  =  %s\n",$1,$2,$3}' >"$TTY"
  else
    tprint "  (none)"
  fi
  pause
}

zone_is_local_zone() {
  local z="$1"
  {
    grep_cfg "set firewall zone $z local-zone"
    grep_cfg "set firewall zone '$z' local-zone"
  } | grep -q . 2>/dev/null
}

zone_has_members() {
  local z="$1"
  scan_zone_ifaces | grep -qF "$z|" 2>/dev/null
}

zone_delete_safe() {
  local zones=() target yn bindings=()
  load_array zones scan_fw_zones
  require_nonempty_list_or_return "firewall zones" "${zones[@]}" || return 0
  select_from_list "Select zone to DELETE" "${zones[@]}" || return 0
  target="$SELECTED"

  load_array bindings scan_zone_bindings
  local refs=()
  local b; for b in "${bindings[@]}"; do
    echo "$b" | grep -qF "$target" && refs+=("$b")
  done
  tprint ""
  if [ "${#refs[@]}" -gt 0 ]; then
    tprint "WARNING: The following bindings reference zone '$target' and will also be deleted:"
    local r; for r in "${refs[@]}"; do tprint "  $r"; done
    tprint ""
  fi
  tprint "About to DELETE zone: $target"
  yn="$(choose_yes_no "Proceed?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_delete firewall zone "$target"
  cfg_apply
}

zone_assign_interface() {
  local zones=() zname ifaces=() cur_ifaces=() yn
  load_array zones scan_fw_zones
  require_nonempty_list_or_return "firewall zones" "${zones[@]}" || return 0
  select_from_list "Select zone to assign interface to" "${zones[@]}" || return 0
  zname="$SELECTED"

  cur_ifaces=()
  local zi; while IFS='|' read -r z i; do
    [ "$z" = "$zname" ] && cur_ifaces+=("$i")
  done < <(scan_zone_ifaces)
  tprint ""; tprint "Current interfaces on $zname: ${cur_ifaces[*]:-(none)}"

  load_array ifaces scan_all_ifaces
  require_nonempty_list_or_return "interfaces" "${ifaces[@]}" || return 0
  select_from_list "Select interface to assign to $zname" "${ifaces[@]}" || return 0
  local iface="$SELECTED"

  if is_in_list "$iface" "${cur_ifaces[@]}"; then
    tprint "ERROR: $iface is already assigned to $zname."; pause; return 0
  fi

  local other_zone
  other_zone="$(scan_zone_ifaces | awk -F'|' -v i="$iface" '$2==i{print $1}' | head -n 1 || true)"
  if [ -n "$other_zone" ]; then
    tprint "WARNING: $iface is already assigned to zone '$other_zone'."
    tprint "An interface can only belong to one zone. Assigning here will conflict."
    yn="$(choose_yes_no "Continue anyway?" "n" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  fi

  yn="$(choose_yes_no "Assign $iface to zone $zname?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set firewall zone "$zname" member interface "$iface"
  cfg_apply
}

zone_remove_interface() {
  local zname cur_ifaces=() target yn
  local zones=(); load_array zones scan_fw_zones
  require_nonempty_list_or_return "firewall zones" "${zones[@]}" || return 0
  select_from_list "Select zone to remove interface from" "${zones[@]}" || return 0
  zname="$SELECTED"

  cur_ifaces=()
  local zi; while IFS='|' read -r z i; do
    [ "$z" = "$zname" ] && cur_ifaces+=("$i")
  done < <(scan_zone_ifaces)

  require_nonempty_list_or_return "interfaces assigned to $zname" "${cur_ifaces[@]}" || return 0
  select_from_list "Select interface to REMOVE from $zname" "${cur_ifaces[@]}" || return 0
  target="$SELECTED"

  yn="$(choose_yes_no "Remove $target from zone $zname?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_delete firewall zone "$zname" member interface "$target"
  cfg_apply
}

zone_set_default_action() {
  local zones=() zname cur da yn
  load_array zones scan_fw_zones
  require_nonempty_list_or_return "firewall zones" "${zones[@]}" || return 0
  select_from_list "Select zone to update default-action" "${zones[@]}" || return 0
  zname="$SELECTED"

  if ! zone_has_members "$zname" && ! zone_is_local_zone "$zname"; then
    tprint ""
    tprint "BLOCKED (VyOS bug T7112): Cannot set default-action on zone '$zname'"
    tprint "because it has no interface members."
    tprint "Use 'Assign interface to zone' first, then retry."
    pause; return 0
  fi

  cur="$(scan_zone_default_action "$zname" || echo -)"
  tprint ""; tprint "Current default-action on $zname: ${cur:-(none set)}"
  select_from_list_default "New default-action" "${cur:-drop}" "drop" "accept" "reject" || return 0
  da="$SELECTED"
  yn="$(choose_yes_no "Set $zname default-action to $da?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set firewall zone "$zname" default-action "$da"
  cfg_apply
}

zone_set_intrazone_action() {
  local zones=() zname cur yn
  load_array zones scan_fw_zones
  require_nonempty_list_or_return "firewall zones" "${zones[@]}" || return 0
  select_from_list "Select zone to set intra-zone action" "${zones[@]}" || return 0
  zname="$SELECTED"
  cur="$(grep_cfg "set firewall zone $zname intra-zone-filtering " \
        | awk '{print $NF}' | head -n 1 | while read -r x; do strip_quotes "$x"; done || echo -)"
  tprint ""; tprint "Current intra-zone-filtering on $zname: ${cur:-(none — VyOS default is accept)}"
  select_from_list_default "Intra-zone traffic action" "${cur:-accept}" "accept" "drop" || return 0
  local action="$SELECTED"
  yn="$(choose_yes_no "Set $zname intra-zone-filtering to $action?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set firewall zone "$zname" intra-zone-filtering action "$action"
  cfg_apply
}

zone_choose_existing() {
  local zones=(); load_array zones scan_fw_zones
  require_nonempty_list_or_return "firewall zones" "${zones[@]}" || return 1
  select_from_list "Select zone" "${zones[@]}" && echo "$SELECTED" && return 0
  return 1
}

zone_binding_preview() {
  tprint ""; tprint "Binding: TO='$1' <- FROM='$2'"
  tprint "--------------------------------------------------------"
  grep_cfg "set firewall zone $1 from $2 firewall name " >"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"; tprint ""
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

  local rs_arr=()
  load_array rs_arr scan_firewall_rulesets
  require_nonempty_list_or_return "firewall rulesets" "${rs_arr[@]}" || return 0
  select_from_list "Select ruleset for binding" "${rs_arr[@]}" || return 0
  ruleset="$SELECTED"

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

  local rs_arr=()
  load_array rs_arr scan_firewall_rulesets
  require_nonempty_list_or_return "firewall rulesets" "${rs_arr[@]}" || return 0
  select_from_list "Select new ruleset" "${rs_arr[@]}" || return 0
  ruleset="$SELECTED"

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
    tprint " Zone Firewall Bindings"
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
    tread c "Select menu option #: " || continue
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

zone_management_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== Zone Management ======"
    tprint "Zones: $(scan_fw_zones | join_lines || echo NONE)"; tprint ""
    tprint "1) List all zones + bindings"
    tprint "2) Create zone (single interface mode)"
    tprint "3) Create zones (batch mode from unassigned interfaces)"
    tprint "4) Delete zone"
    tprint "5) Assign interface to zone"
    tprint "6) Remove interface from zone"
    tprint "7) Set default-action"
    tprint "8) Set intra-zone action"
    tprint "9) Zone bindings (TO/FROM/ruleset)"
    tprint "10) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) zone_list_full ;;
      2) zone_create_single_interface ;;
      3) zone_create_batch_from_interfaces ;;
      4) zone_delete_safe ;;
      5) zone_assign_interface ;;
      6) zone_remove_interface ;;
      7) zone_set_default_action ;;
      8) zone_set_intrazone_action ;;
      9) zone_bindings_menu ;;
      10) return 0 ;;
      *) tprint "Invalid." ;;
    esac
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
    tprint "5) Zone management"
    tprint "6) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) fw_list_ruleset ;;
      2) fw_add_rule_guided_safe ;;
      3) fw_update_single_field ;;
      4) fw_delete_rule ;;
      5) zone_management_menu ;;
      6) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# NAT
# ============================================================
nat_choose_type() {
  local def="${1:-destination}"
  tprint ""; tprint "  destination = DNAT / port forwarding"
  tprint "  source      = SNAT / masquerade"
  select_from_list_default "NAT type" "$def" "destination" "source" || return 1
  echo "$SELECTED"
}

nat_choose_rule_number_existing() {
  local type="$1" arr=()
  [ "$type" = "destination" ] && load_array arr scan_nat_dest_rules || load_array arr scan_nat_source_rules
  require_nonempty_list_or_return "NAT $type rules" "${arr[@]}" || return 1
  select_from_list "Select existing $type rule" "${arr[@]}" && echo "$SELECTED" && return 0
  return 1
}

nat_preview_rule() {
  tprint ""; tprint "NAT $1 rule $2:"
  tprint "--------------------------------------------------------"
  grep_cfg "set nat $1 rule $2 " >"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"; tprint ""
}

nat_list() {
  tprint ""; tprint "--- NAT config ---"
  tprint "--------------------------------------------------------"
  grep_cfg "set nat " >"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"
  pause
}

nat_add_dnat_guided() {
  local n desc inif proto dport taddr tport used=() suggested ifs=() yn
  load_array used scan_nat_dest_rules
  suggested="$(next_free_rule_number "${used[@]}")"
  tprint ""; tprint "ADD DNAT rule (safe — new only)"
  tprint "Existing DNAT rules: ${used[*]:-(none)}  |  Next free: $suggested"; tprint ""
  while true; do
    n="$(ask "DNAT rule number" "$suggested")"
    require_numeric "$n" || { tprint "ERROR: must be a number."; continue; }
    is_number_in_list "$n" "${used[@]}" && { tprint "ERROR: rule $n exists. Use Update."; continue; }
    break
  done
  desc="$(ask "Description" "DNAT")"
  [ -n "$desc" ] && ! is_safe_free_text "$desc" && { tprint "ERROR: Invalid description."; pause; return 0; }
  load_array ifs scan_eth_ifaces
  require_nonempty_list_or_return "ethernet interfaces" "${ifs[@]}" || return 0
  select_from_list "Inbound interface (WAN)" "${ifs[@]}" || return 0; inif="$SELECTED"
  proto="$(choose_tcp_udp "tcp")" || return 0
  dport="$(ask "Public (destination) port" "80")"
  is_valid_port_or_range "$dport" || { tprint "ERROR: Invalid port."; pause; return 0; }
  taddr="$(ask "Inside IP" "")"
  is_valid_ipv4 "$taddr" || { tprint "ERROR: Invalid IPv4."; pause; return 0; }
  tport="$(ask "Inside port" "80")"
  is_valid_port_or_range "$tport" || { tprint "ERROR: Invalid port."; pause; return 0; }

  tprint ""; tprint "SUMMARY: DNAT rule $n  in=$inif  proto=$proto  pub:$dport → $taddr:$tport  desc=$desc"
  yn="$(choose_yes_no "Create?" "y" || echo "n")"
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

nat_add_snat_guided() {
  local n desc outif proto saddr daddr sport dport taddr tport mode used=() suggested ifs=() yn
  load_array used scan_nat_source_rules
  suggested="$(next_free_rule_number "${used[@]}")"
  tprint ""; tprint "ADD SNAT rule (safe — new only)"
  tprint "Existing SNAT rules: ${used[*]:-(none)}  |  Next free: $suggested"; tprint ""
  while true; do
    n="$(ask "SNAT rule number" "$suggested")"
    require_numeric "$n" || { tprint "ERROR: must be a number."; continue; }
    is_number_in_list "$n" "${used[@]}" && { tprint "ERROR: rule $n exists. Use Update."; continue; }
    break
  done
  desc="$(ask "Description" "SNAT")"
  [ -n "$desc" ] && ! is_safe_free_text "$desc" && { tprint "ERROR: Invalid description."; pause; return 0; }
  load_array ifs scan_eth_ifaces
  require_nonempty_list_or_return "ethernet interfaces" "${ifs[@]}" || return 0
  select_from_list "Outbound interface (WAN)" "${ifs[@]}" || return 0; outif="$SELECTED"
  tprint ""; tprint "  masquerade = use outbound interface IP"
  tprint "  address    = specify a static translation IP"
  select_from_list_default "Translation mode" "masquerade" "masquerade" "address" || return 0; mode="$SELECTED"
  if [ "$mode" = "masquerade" ]; then
    taddr="masquerade"
  else
    taddr="$(ask "Translation address (IPv4)" "")"
    is_valid_ipv4 "$taddr" || { tprint "ERROR: Invalid IPv4."; pause; return 0; }
  fi
  proto="$(choose_fw_protocol "any" || true)"; [ -z "$proto" ] && return 0
  saddr="$(ask "Source address match (optional)" "")"
  [ -n "$saddr" ] && ! is_valid_cidr4 "$saddr" && ! is_valid_ipv4 "$saddr" && { tprint "ERROR: Invalid."; pause; return 0; }
  daddr="$(ask "Destination address match (optional)" "")"
  [ -n "$daddr" ] && ! is_valid_cidr4 "$daddr" && ! is_valid_ipv4 "$daddr" && { tprint "ERROR: Invalid."; pause; return 0; }
  sport="$(ask "Source port match (optional)" "")";      [ -n "$sport" ] && ! is_valid_port_or_range "$sport" && { tprint "ERROR: Invalid port."; pause; return 0; }
  dport="$(ask "Destination port match (optional)" "")"; [ -n "$dport" ] && ! is_valid_port_or_range "$dport" && { tprint "ERROR: Invalid port."; pause; return 0; }
  tport="$(ask "Translation port (optional)" "")";       [ -n "$tport" ] && ! is_valid_port_or_range "$tport" && { tprint "ERROR: Invalid port."; pause; return 0; }

  tprint ""; tprint "SUMMARY: SNAT rule $n  out=$outif  xlat=$taddr  proto=$proto"
  [ -n "$saddr" ] && tprint "  src-addr: $saddr"; [ -n "$sport" ] && tprint "  src-port: $sport"
  [ -n "$daddr" ] && tprint "  dst-addr: $daddr"; [ -n "$dport" ] && tprint "  dst-port: $dport"
  [ -n "$tport" ] && tprint "  xlat-port: $tport"; tprint ""
  yn="$(choose_yes_no "Create?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set nat source rule "$n" description "$desc"
  cfg_set nat source rule "$n" outbound-interface name "$outif"
  [ -n "$proto" ] && [ "$proto" != "any" ] && cfg_set nat source rule "$n" protocol "$proto"
  [ -n "$saddr" ] && cfg_set nat source rule "$n" source address "$saddr"
  [ -n "$sport" ] && cfg_set nat source rule "$n" source port "$sport"
  [ -n "$daddr" ] && cfg_set nat source rule "$n" destination address "$daddr"
  [ -n "$dport" ] && cfg_set nat source rule "$n" destination port "$dport"
  cfg_set nat source rule "$n" translation address "$taddr"
  [ -n "$tport" ] && cfg_set nat source rule "$n" translation port "$tport"
  cfg_apply
}

nat_update_single_field() {
  local type n field val yn
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
      tprint "Leave blank to DELETE."; val="$(ask "New description" "")"
      [ -n "$val" ] && ! is_safe_free_text "$val" && { tprint "ERROR."; pause; return 0; }
      cfg_begin || return 0
      [ -z "$val" ] && cfg_delete nat "$type" rule "$n" description \
                    || cfg_set   nat "$type" rule "$n" description "$val"
      cfg_apply ;;
    protocol)
      val="$(choose_fw_protocol "tcp")" || return 0
      cfg_begin || return 0
      [ "$val" = "any" ] && cfg_delete nat "$type" rule "$n" protocol \
                         || cfg_set   nat "$type" rule "$n" protocol "$val"
      cfg_apply ;;
    "source address"|"destination address")
      tprint "Leave blank to DELETE."; val="$(ask "IPv4 or CIDR" "")"
      [ -n "$val" ] && ! is_valid_ipv4 "$val" && ! is_valid_cidr4 "$val" && { tprint "ERROR."; pause; return 0; }
      cfg_begin || return 0
      local nside="${field%% *}"
      [ -z "$val" ] && cfg_delete nat "$type" rule "$n" "$nside" address \
                    || cfg_set   nat "$type" rule "$n" "$nside" address "$val"
      cfg_apply ;;
    "source port"|"destination port"|"translation port")
      tprint "Leave blank to DELETE."; val="$(ask "Port or range" "")"
      [ -n "$val" ] && ! is_valid_port_or_range "$val" && { tprint "ERROR."; pause; return 0; }
      cfg_begin || return 0
      local np="${field%% *}"
      [ -z "$val" ] && cfg_delete nat "$type" rule "$n" "$np" port \
                    || cfg_set   nat "$type" rule "$n" "$np" port "$val"
      cfg_apply ;;
    "translation address")
      tprint "Leave blank to DELETE. For SNAT: masquerade is valid."
      val="$(ask "Translation address" "")"
      [ -n "$val" ] && [ "$val" != "masquerade" ] && ! is_valid_ipv4 "$val" && ! is_valid_cidr4 "$val" \
        && { tprint "ERROR."; pause; return 0; }
      cfg_begin || return 0
      [ -z "$val" ] && cfg_delete nat "$type" rule "$n" translation address \
                    || cfg_set   nat "$type" rule "$n" translation address "$val"
      cfg_apply ;;
    "inbound-interface name"|"outbound-interface name")
      tprint "Leave blank to DELETE."; val="$(ask "Interface name (e.g. eth0)" "")"
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
    tprint "6) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) nat_list ;;
      2) nat_add_dnat_guided ;;
      3) nat_add_snat_guided ;;
      4) nat_update_single_field ;;
      5) nat_delete_rule ;;
      6) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# SYSTEM (users + hostname)
# ============================================================
user_add_menu() {
  local u pw fn existing=() yn
  u="$(ask "New username (e.g. admin2)" "")"
  [ -z "$u" ] && return 0
  if ! is_valid_username "$u"; then tprint "ERROR: Invalid username."; pause; return 0; fi
  load_array existing scan_login_users
  if is_in_list "$u" "${existing[@]}"; then
    tprint "ERROR: User '$u' already exists. Use Remove + Add to replace."; pause; return 0
  fi
  fn="$(ask "Full name (optional)" "")"
  [ -n "$fn" ] && ! is_safe_free_text "$fn" && { tprint "ERROR: Invalid full name."; pause; return 0; }
  tread_secret pw "Password (hidden): " || return 0
  [ -z "$pw" ] && { tprint "Password required."; pause; return 0; }
  tprint ""; tprint "SUMMARY: create user $u$( [ -n "$fn" ] && echo " ($fn)" )"
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
  if [ -n "$current" ] && [ "$target" = "$current" ]; then
    tprint "ERROR: Cannot remove yourself ($current)."; pause; return 0
  fi
  tprint ""; tprint "About to REMOVE user: $target"
  grep_cfg "set system login user '$target' " >"$TTY" 2>/dev/null || true
  grep_cfg "set system login user $target "   >>"$TTY" 2>/dev/null || true
  tprint ""
  yn="$(choose_yes_no "Proceed?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete system login user "$target"; cfg_apply
}

users_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== User Management ======"
    tprint "Users: $(scan_login_users | join_lines || echo NONE)"; tprint ""
    tprint "1) Add user"
    tprint "2) Remove user"
    tprint "3) Back"
    local c; tread c "Select: " || continue
    case "$c" in 1) user_add_menu ;; 2) user_remove_menu ;; 3) return 0 ;; *) tprint "Invalid." ;; esac
  done
}

hostname_menu() {
  local cur newhn yn
  cur="$(get_current_hostname)"
  tprint ""; tprint "Current hostname: ${cur:-UNKNOWN}"
  newhn="$(ask "New hostname (e.g. vyos-edge01)" "")"
  [ -z "$newhn" ] && return 0
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
    tprint "1) User management"
    tprint "2) Change hostname"
    tprint "3) Back"
    local c; tread c "Select: " || continue
    case "$c" in 1) users_menu ;; 2) hostname_menu ;; 3) return 0 ;; *) tprint "Invalid." ;; esac
  done
}

# ============================================================
# DNS FORWARDING
# ============================================================
dns_add_allow_from_safe() {
  local current_af=() current_la=() new_af la_needed yn
  load_array current_af scan_dns_allow_from
  load_array current_la scan_dns_listen_address
  tprint ""; tprint "Current allow-from: ${current_af[*]:-(none)}"
  new_af="$(ask "New allow-from subnet (CIDR)" "")"
  [ -z "$new_af" ] && return 0
  is_valid_cidr4 "$new_af" || { tprint "ERROR: Must be IPv4/CIDR."; pause; return 0; }
  is_in_list "$new_af" "${current_af[@]}" && { tprint "ERROR: $new_af already exists."; pause; return 0; }
  if [ "${#current_la[@]}" -eq 0 ]; then
    tprint ""; tprint "IMPORTANT: listen-address also required for commit."
    la_needed="$(ask "listen-address IP to add now" "")"
    [ -z "$la_needed" ] && return 0
    is_valid_ipv4 "$la_needed" || { tprint "ERROR: Invalid IPv4."; pause; return 0; }
  fi
  tprint "SUMMARY: add allow-from $new_af$( [ -n "${la_needed:-}" ] && echo " + listen-address $la_needed" )"
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
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
    tprint "BLOCKED: Cannot delete last allow-from while listen-address exists or system forwarding is on."
    pause; return 0
  fi
  yn="$(choose_yes_no "Delete allow-from $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete service dns forwarding allow-from "$target"; cfg_apply
}

dns_add_listen_address_safe() {
  local current_af=() current_la=() new_la af_needed yn
  load_array current_af scan_dns_allow_from; load_array current_la scan_dns_listen_address
  tprint ""; tprint "Current listen-address: ${current_la[*]:-(none)}"
  new_la="$(ask "New listen-address IP" "")"
  [ -z "$new_la" ] && return 0
  is_valid_ipv4 "$new_la" || { tprint "ERROR: Must be valid IPv4."; pause; return 0; }
  is_in_list "$new_la" "${current_la[@]}" && { tprint "ERROR: $new_la already exists."; pause; return 0; }
  if [ "${#current_af[@]}" -eq 0 ]; then
    tprint ""; tprint "IMPORTANT: allow-from also required for commit."
    af_needed="$(ask "allow-from subnet (CIDR) to add now" "")"
    [ -z "$af_needed" ] && return 0
    is_valid_cidr4 "$af_needed" || { tprint "ERROR: Must be IPv4/CIDR."; pause; return 0; }
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
    tprint "BLOCKED: Cannot delete last listen-address while allow-from exists or system forwarding is on."
    pause; return 0
  fi
  yn="$(choose_yes_no "Delete listen-address $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete service dns forwarding listen-address "$target"; cfg_apply
}

dns_system_forwarding_toggle() {
  local current_af=() current_la=() yn
  load_array current_af scan_dns_allow_from; load_array current_la scan_dns_listen_address
  tprint ""
  if dns_system_is_enabled; then
    tprint "DNS system forwarding: ENABLED"
    yn="$(choose_yes_no "Disable it?" "y" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; cfg_delete service dns forwarding system; cfg_apply
  else
    tprint "DNS system forwarding: DISABLED"
    if [ "${#current_la[@]}" -eq 0 ] || [ "${#current_af[@]}" -eq 0 ]; then
      tprint "BLOCKED: Need both listen-address and allow-from before enabling."
      pause; return 0
    fi
    yn="$(choose_yes_no "Enable it?" "y" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; cfg_set service dns forwarding system; cfg_apply
  fi
}

dns_list_name_servers() {
  tprint ""
  tprint "You selected: List system name-servers"
  tprint "Command: set system name-server <A.B.C.D>"
  tprint ""
  tprint "Current name-servers:"
  tprint "--------------------------------------------------------"
  local ns=()
  load_array ns scan_dns_name_servers
  if [ "${#ns[@]}" -eq 0 ]; then
    tprint "  (none configured)"
  else
    local n; for n in "${ns[@]}"; do tprint "  $n"; done
  fi
  tprint "--------------------------------------------------------"
  tprint ""
  tprint "Raw config lines:"
  tprint "--------------------------------------------------------"
  (grep_cfg "set system name-server " || true) >"$TTY"
  tprint "--------------------------------------------------------"
  pause
}

dns_add_name_server_safe() {
  local current=() ip yn

  load_array current scan_dns_name_servers

  tprint ""
  tprint "You selected: ADD system name-server (SAFE - will not duplicate)"
  tprint "Command: set system name-server <A.B.C.D>"
  tprint "This tells VyOS which upstream DNS server to query."
  tprint ""
  tprint "Current name-servers: ${current[*]:-(none)}"
  tprint ""

  ip="$(ask "Name-server IP (example: 10.0.17.2)" "")"
  [ -z "$ip" ] && return 0

  if ! is_valid_ipv4 "$ip"; then
    tprint "ERROR: Must be a valid IPv4 address."
    pause
    return 0
  fi

  if is_in_list "$ip" "${current[@]}"; then
    tprint ""
    tprint "ERROR: Name-server already configured: $ip"
    pause
    return 0
  fi

  tprint ""
  tprint "SUMMARY:"
  tprint "  set system name-server $ip"
  tprint ""
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set system name-server "$ip"
  cfg_apply
}

dns_delete_name_server_existing() {
  local current=() target yn

  load_array current scan_dns_name_servers

  tprint ""
  tprint "You selected: DELETE system name-server (existing)"
  tprint "Command: delete system name-server <A.B.C.D>"
  tprint ""

  require_nonempty_list_or_return "System name-servers" "${current[@]}" || return 0

  if select_from_list "Select name-server to DELETE" "${current[@]}"; then
    target="$SELECTED"
  else
    return 0
  fi

  tprint ""
  tprint "You are about to delete: system name-server $target"
  tprint ""
  yn="$(choose_yes_no "Proceed with delete?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_delete system name-server "$target"
  cfg_apply
}

dns_add_domain_forwarding_safe() {
  local current=() domain server yn

  load_array current scan_dns_forward_domains

  tprint ""
  tprint "You selected: ADD domain forwarding (SAFE - will not overwrite)"
  tprint "Command: set service dns forwarding domain <domain> name-server <IP>"
  tprint "Example: set service dns forwarding domain yourdomain.local name-server 192.168.6.1"
  tprint ""
  tprint "Current forwarding domains: ${current[*]:-(none)}"
  tprint ""

  domain="$(ask "Domain to forward (e.g. yourdomain.local)" "")"
  [ -z "$domain" ] && return 0

  if ! is_valid_hostname "$domain"; then
    tprint "ERROR: Invalid domain name."
    pause
    return 0
  fi

  if is_in_list "$domain" "${current[@]}"; then
    tprint ""
    tprint "ERROR: Domain '$domain' already has a forwarding entry."
    tprint "Use Delete + Add to replace it."
    pause
    return 0
  fi

  server="$(ask "Server IP to forward $domain queries to" "")"
  [ -z "$server" ] && return 0

  if ! is_valid_ipv4 "$server"; then
    tprint "ERROR: Must be a valid IPv4 address."
    pause
    return 0
  fi

  tprint ""
  tprint "SUMMARY:"
  tprint "  set service dns forwarding domain $domain name-server $server"
  tprint ""
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_set service dns forwarding domain "$domain" name-server "$server"
  cfg_apply
}

dns_delete_domain_forwarding_existing() {
  local current=() target yn

  load_array current scan_dns_forward_domains

  tprint ""
  tprint "You selected: DELETE domain forwarding (existing)"
  tprint "Command: delete service dns forwarding domain <domain>"
  tprint ""

  require_nonempty_list_or_return "DNS forwarding domains" "${current[@]}" || return 0

  select_from_list "Select domain forwarding entry to DELETE" "${current[@]}" || return 0
  target="$SELECTED"

  tprint ""
  tprint "You are about to delete: dns forwarding domain $target"
  tprint ""
  tprint "Current config for this domain:"
  tprint "--------------------------------------------------------"
  {
    grep_cfg "set service dns forwarding domain $target "
    grep_cfg "set service dns forwarding domain '$target' "
  } >"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"
  tprint ""

  yn="$(choose_yes_no "Proceed with delete?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }

  cfg_begin || return 0
  cfg_delete service dns forwarding domain "$target"
  cfg_apply
}

dns_forwarding_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "=============================="
    tprint " DNS Forwarding Submenu"
    tprint "=============================="
    _dns_summary; tprint ""
    tprint "1) List full DNS forwarding config"
    tprint "2) Add allow-from (safe)"
    tprint "3) Delete allow-from"
    tprint "4) Add listen-address (safe)"
    tprint "5) Delete listen-address"
    tprint "6) Toggle system forwarding"
    tprint "--- System Name-Servers ---"
    tprint "7) List name-servers"
    tprint "8) Add name-server (safe)"
    tprint "9) Delete name-server"
    tprint "--- Domain Forwarding ---"
    tprint "10) Add domain forwarding  (set service dns forwarding domain <domain> name-server <IP>)"
    tprint "11) Delete domain forwarding"
    tprint "12) Back"
    local c; tread c "Select menu option #: " || continue
    case "$c" in
      1)  tprint ""; grep_cfg "set service dns forwarding " >"$TTY" 2>/dev/null || true; pause ;;
      2)  dns_add_allow_from_safe ;;
      3)  dns_delete_allow_from_existing ;;
      4)  dns_add_listen_address_safe ;;
      5)  dns_delete_listen_address_existing ;;
      6)  dns_system_forwarding_toggle ;;
      7)  dns_list_name_servers ;;
      8)  dns_add_name_server_safe ;;
      9)  dns_delete_name_server_existing ;;
      10) dns_add_domain_forwarding_safe ;;
      11) dns_delete_domain_forwarding_existing ;;
      12) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# RIP
# ============================================================
rip_neighbor_context_warning() {
  local neighbors=() passive=()
  load_array neighbors scan_rip_neighbors
  load_array passive scan_rip_passive_interfaces
  local passive_default=0
  is_in_list "default" "${passive[@]}" && passive_default=1
  tprint ""; tprint "--- Neighbor / Passive-interface ---"
  if [ "$passive_default" -eq 1 ]; then
    tprint "  passive-interface default: SET (all ifaces passive, no multicast)"
    if [ "${#neighbors[@]}" -eq 0 ]; then
      tprint "  WARNING: No neighbors → RIP is SILENT. Add neighbor or remove passive default."
    else
      tprint "  Unicast neighbors:"; local n; for n in "${neighbors[@]}"; do tprint "    $n"; done
    fi
  else
    tprint "  passive-interface default: NOT set (multicasting on all active ifaces)"
    if [ "${#neighbors[@]}" -gt 0 ]; then
      tprint "  NOTE: neighbor entries are redundant without passive-interface default."
    fi
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
  run_cmd_to_tty "show ip rip"
  run_cmd_to_tty "show ip rip status"
  run_cmd_to_tty "show ip route rip"
  pause
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
  local current=() target yn
  load_array current scan_rip_interfaces
  require_nonempty_list_or_return "RIP interfaces" "${current[@]}" || return 0
  select_from_list "Select RIP interface to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Delete RIP interface $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete protocols rip interface "$target"; cfg_apply
}

rip_add_network_safe() {
  local current=() net yn
  load_array current scan_rip_networks
  tprint ""; tprint "Current RIP networks: ${current[*]:-(none)}"
  net="$(ask "Network (CIDR) e.g. 10.0.66.0/28" "")"
  [ -z "$net" ] && return 0
  is_valid_cidr4 "$net" || { tprint "ERROR: Must be IPv4/CIDR."; pause; return 0; }
  is_in_list "$net" "${current[@]}" && { tprint "ERROR: $net already exists."; pause; return 0; }
  yn="$(choose_yes_no "Add RIP network $net?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set protocols rip network "$net"; cfg_apply
}

rip_delete_network_existing() {
  local current=() target yn
  load_array current scan_rip_networks
  require_nonempty_list_or_return "RIP networks" "${current[@]}" || return 0
  select_from_list "Select RIP network to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Delete RIP network $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete protocols rip network "$target"; cfg_apply
}

rip_neighbor_reachable_via_rip() {
  local neighbor_ip="$1" rip_ifaces=()
  load_array rip_ifaces scan_rip_interfaces
  [ "${#rip_ifaces[@]}" -eq 0 ] && return 1
  local n_int
  n_int="$(printf "%s" "$neighbor_ip" | awk -F. '{printf "%d", ($1*16777216)+($2*65536)+($3*256)+$4}')"
  local iface
  for iface in "${rip_ifaces[@]}"; do
    local addr_cidr
    addr_cidr="$(grep_cfg "set interfaces ethernet $iface address " | awk '{print $6}' | head -n 1 | while read -r x; do strip_quotes "$x"; done)"
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

rip_add_neighbor_safe() {
  local current=() passive=() ip yn
  load_array current scan_rip_neighbors; load_array passive scan_rip_passive_interfaces
  rip_neighbor_context_warning
  tprint "Current neighbors: ${current[*]:-(none)}"
  ip="$(ask "Neighbor IP" "")"
  [ -z "$ip" ] && return 0
  is_valid_ipv4 "$ip" || { tprint "ERROR: Must be valid IPv4."; pause; return 0; }
  is_in_list "$ip" "${current[@]}" && { tprint "ERROR: $ip already exists."; pause; return 0; }
  if ! rip_neighbor_reachable_via_rip "$ip"; then
    tprint "WARNING: $ip may not be reachable via any RIP interface subnet."
    local cont; cont="$(choose_yes_no "Continue anyway?" "n" || echo "n")"
    [ "$cont" != "y" ] && { tprint "Canceled."; pause; return 0; }
  fi
  if ! is_in_list "default" "${passive[@]}"; then
    tprint "NOTE: passive-interface default is NOT set — neighbor entry is redundant without it."
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
    tprint "WARNING: Deleting last neighbor with passive-interface default set → RIP goes SILENT."
  select_from_list "Select RIP neighbor to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Delete RIP neighbor $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete protocols rip neighbor "$target"; cfg_apply
}

rip_add_passive_interface_safe() {
  local current=() ifs=() iface yn
  load_array current scan_rip_passive_interfaces; load_array ifs scan_eth_ifaces
  tprint ""; tprint "Current passive interfaces: ${current[*]:-(none)}"
  tprint "'default' makes ALL interfaces passive (use with neighbors for unicast)."
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
  local current=() target yn
  load_array current scan_rip_passive_interfaces
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
  local available=(); local s
  for s in "${sources[@]}"; do is_in_list "$s" "${current[@]}" || available+=("$s"); done
  [ "${#available[@]}" -eq 0 ] && { tprint "All redistribute sources already configured."; pause; return 0; }
  tprint ""; tprint "Currently redistributing: ${current[*]:-(none)}"
  select_from_list "Select route source to redistribute" "${available[@]}" || return 0; src="$SELECTED"
  metric="$(ask "Metric 1-16 (optional, default=1)" "")"
  if [ -n "$metric" ]; then
    echo "$metric" | grep -Eq '^([1-9]|1[0-6])$' || { tprint "ERROR: Metric must be 1-16."; pause; return 0; }
  fi
  yn="$(choose_yes_no "Redistribute $src$([ -n "$metric" ] && echo " metric $metric")?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set protocols rip redistribute "$src"
  [ -n "$metric" ] && cfg_set protocols rip redistribute "$src" metric "$metric"
  cfg_apply
}

rip_delete_redistribute_existing() {
  local current=() target yn
  load_array current scan_rip_redistribute
  require_nonempty_list_or_return "RIP redistribute sources" "${current[@]}" || return 0
  select_from_list "Select redistribute source to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Delete redistribute $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete protocols rip redistribute "$target"; cfg_apply
}

rip_default_information_toggle() {
  local yn is_set=0
  grep_cfg "set protocols rip default-information originate" | grep -q . && is_set=1
  tprint ""
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
  local v="$1"
  echo "$v" | grep -Eq '^[0-9]+$' || return 1
  [ "$v" -ge 5 ] 2>/dev/null && [ "$v" -le 2147483647 ] 2>/dev/null
}

rip_timers_menu() {
  local update="" timeout="" gc="" yn val
  local cur_u cur_t cur_g
  cur_u="$(grep_cfg "set protocols rip timers update "             | awk '{print $6}' | head -n 1 | while read -r x; do strip_quotes "$x"; done)"
  cur_t="$(grep_cfg "set protocols rip timers timeout "            | awk '{print $6}' | head -n 1 | while read -r x; do strip_quotes "$x"; done)"
  cur_g="$(grep_cfg "set protocols rip timers garbage-collection " | awk '{print $6}' | head -n 1 | while read -r x; do strip_quotes "$x"; done)"
  tprint ""; tprint "RIP timers (range 5–2147483647, defaults: update=30 timeout=180 gc=120)"
  tprint "  update:             ${cur_u:-30 (default)}"
  tprint "  timeout:            ${cur_t:-180 (default)}"
  tprint "  garbage-collection: ${cur_g:-120 (default)}"
  tprint "Leave blank to keep existing."; tprint ""
  val="$(ask "Update timer" "")";            [ -n "$val" ] && { is_valid_rip_timer "$val" || { tprint "ERROR: 5-2147483647."; pause; return 0; }; update="$val"; }
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
  local yn; yn="$(choose_yes_no "Reset ALL RIP timers to VyOS defaults?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete protocols rip timers; cfg_apply
}

rip_add_static_route_safe() {
  local current=() net yn
  load_array current scan_rip_static_routes
  tprint ""; tprint "WARNING: RIP static route exists ONLY in RIP — not installed in kernel."
  tprint "Prefer 'redistribute static' for normal static routes."
  tprint "Current RIP static routes: ${current[*]:-(none)}"
  net="$(ask "Route (CIDR)" "")"
  [ -z "$net" ] && return 0
  is_valid_cidr4 "$net" || { tprint "ERROR: Must be IPv4/CIDR."; pause; return 0; }
  is_in_list "$net" "${current[@]}" && { tprint "ERROR: $net already exists."; pause; return 0; }
  yn="$(choose_yes_no "Add RIP static route $net?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set protocols rip route "$net"; cfg_apply
}

rip_delete_static_route_existing() {
  local current=() target yn
  load_array current scan_rip_static_routes
  require_nonempty_list_or_return "RIP static routes" "${current[@]}" || return 0
  select_from_list "Select RIP static route to DELETE" "${current[@]}" || return 0; target="$SELECTED"
  yn="$(choose_yes_no "Delete RIP static route $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete protocols rip route "$target"; cfg_apply
}

rip_iface_settings_menu() {
  local ifs=() iface
  load_array ifs scan_eth_ifaces
  require_nonempty_list_or_return "ethernet interfaces" "${ifs[@]}" || return 0
  select_from_list "Select interface for per-interface RIP settings" "${ifs[@]}" || return 0; iface="$SELECTED"
  tprint ""; tprint "Current RIP settings on $iface:"
  tprint "--------------------------------------------------------"
  grep_cfg "set interfaces ethernet $iface ip rip "    >"$TTY" 2>/dev/null || true
  grep_cfg "set interfaces ethernet '$iface' ip rip " >>"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"
  local options=("split-horizon enable (default)" "split-horizon disable" "split-horizon poison-reverse"
                 "authentication plaintext" "authentication MD5"
                 "delete ALL per-interface RIP settings" "back")
  select_from_list "Select setting for $iface" "${options[@]}" || return 0
  case "$SELECTED" in
    "split-horizon enable (default)")
      local yn; yn="$(choose_yes_no "Remove split-horizon override (restore default)?" "y" || echo "n")"
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
      local pw yn
      tprint "WARNING: plaintext password is sent in cleartext in RIP updates."
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
      echo "$keyid" | grep -Eq '^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$' \
        || { tprint "ERROR: Key ID must be 1-255."; pause; return 0; }
      tread_secret pw "MD5 password (max 16 chars): " || return 0
      [ -z "$pw" ] && { tprint "Password required."; pause; return 0; }
      [ "${#pw}" -gt 16 ] && { tprint "ERROR: Max 16 characters."; pause; return 0; }
      yn="$(choose_yes_no "Set MD5 RIP auth on $iface (key $keyid)?" "y" || echo "n")"
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
  tprint "255 = effectively disabled (route not installed in kernel)."
  dist="$(ask "New default distance (1-255)" "${cur:-120}")"
  [ -z "$dist" ] && return 0
  echo "$dist" | grep -Eq '^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$' \
    || { tprint "ERROR: Must be 1-255."; pause; return 0; }
  yn="$(choose_yes_no "Set default-distance to $dist?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set protocols rip default-distance "$dist"; cfg_apply
}

rip_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== RIP ======"
    _rip_summary; tprint ""
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
      1)  rip_list_config ;;
      2)  rip_add_interface_safe ;;
      3)  rip_delete_interface_existing ;;
      4)  rip_add_network_safe ;;
      5)  rip_delete_network_existing ;;
      6)  rip_add_neighbor_safe ;;
      7)  rip_delete_neighbor_existing ;;
      8)  rip_add_passive_interface_safe ;;
      9)  rip_delete_passive_interface_existing ;;
      10) rip_add_redistribute_safe ;;
      11) rip_delete_redistribute_existing ;;
      12) rip_default_information_toggle ;;
      13) rip_timers_menu ;;
      14) rip_timers_reset ;;
      15) rip_add_static_route_safe ;;
      16) rip_delete_static_route_existing ;;
      17) rip_iface_settings_menu ;;
      18) rip_set_default_distance ;;
      19) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# STATIC ROUTES
# ============================================================
static_route_add_safe() {
  local current=() prefix nexthop distance yn
  load_array current scan_static_routes
  tprint ""; tprint "Current static routes: ${current[*]:-(none)}"; tprint ""
  prefix="$(ask "Destination prefix (CIDR, e.g. 10.10.0.0/24)" "")"
  [ -z "$prefix" ] && return 0
  is_valid_cidr4 "$prefix" || { tprint "ERROR: Must be IPv4/CIDR."; pause; return 0; }
  tprint ""; tprint "  nexthop   = route via a gateway IP"
  tprint "  blackhole = silently discard (null route)"
  select_from_list_default "Route type" "nexthop" "nexthop" "blackhole" || return 0
  local rtype="$SELECTED"
  if [ "$rtype" = "nexthop" ]; then
    nexthop="$(ask "Next-hop gateway IP" "")"
    [ -z "$nexthop" ] && return 0
    is_valid_ipv4 "$nexthop" || { tprint "ERROR: Must be valid IPv4."; pause; return 0; }
  fi
  distance="$(ask "Admin distance (1-255, optional, default 1)" "")"
  if [ -n "$distance" ]; then
    echo "$distance" | grep -Eq '^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$' \
      || { tprint "ERROR: Distance must be 1-255."; pause; return 0; }
  fi
  tprint ""
  if [ "$rtype" = "blackhole" ]; then
    tprint "SUMMARY: static blackhole $prefix${distance:+ distance $distance}"
  else
    tprint "SUMMARY: static route $prefix via $nexthop${distance:+ distance $distance}"
  fi
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
  local current=() prefix nexthops=() yn
  load_array current scan_static_routes
  require_nonempty_list_or_return "static routes" "${current[@]}" || return 0
  select_from_list "Select route to delete" "${current[@]}" || return 0
  prefix="$SELECTED"
  tprint ""; tprint "Config for $prefix:"
  tprint "--------------------------------------------------------"
  {
    grep_cfg "set protocols static route $prefix "
    grep_cfg "set protocols static route '$prefix' "
  } >"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"
  load_array nexthops scan_static_route_nexthops "$prefix"
  if [ "${#nexthops[@]}" -gt 1 ]; then
    tprint ""; tprint "Multiple next-hops exist."
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
  tprint ""; tprint "--- Static routes (config) ---"
  tprint "--------------------------------------------------------"
  grep_cfg "set protocols static route " >"$TTY" 2>/dev/null || tprint "(none)"
  tprint "--------------------------------------------------------"
  tprint ""
  run_cmd_to_tty "show ip route static"
  pause
}

static_routes_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== Static Routes ======"
    tprint "Routes: $(scan_static_routes | join_lines || echo NONE)"; tprint ""
    tprint "1) List static routes"
    tprint "2) Add route (safe)"
    tprint "3) Delete route"
    tprint "4) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) static_route_list ;;
      2) static_route_add_safe ;;
      3) static_route_delete ;;
      4) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# DHCP SERVER
# ============================================================
dhcp_show_pool() {
  local pool="$1"
  tprint ""; tprint "--- DHCP pool: $pool ---"
  tprint "--------------------------------------------------------"
  {
    grep_cfg "set service dhcp-server shared-network-name $pool "
    grep_cfg "set service dhcp-server shared-network-name '$pool' "
  } >"$TTY" 2>/dev/null || true
  tprint "--------------------------------------------------------"
}

dhcp_add_pool_safe() {
  local pools=() name subnet range_start range_stop gateway dns lease yn
  load_array pools scan_dhcp_pools
  tprint ""; tprint "Existing DHCP pools: ${pools[*]:-(none)}"; tprint ""
  name="$(ask "Pool name (e.g. LAN, MGMT)" "")"
  [ -z "$name" ] && return 0
  if ! is_safe_ruleset_name "$name"; then
    tprint "ERROR: Invalid pool name (letters/numbers/_/./- max 64)."; pause; return 0
  fi
  if is_in_list "$name" "${pools[@]}"; then
    tprint "ERROR: Pool '$name' already exists. Use Delete + Add to rebuild."; pause; return 0
  fi
  subnet="$(ask "Subnet (CIDR, e.g. 192.168.1.0/24)" "")"
  [ -z "$subnet" ] && return 0
  is_valid_cidr4 "$subnet" || { tprint "ERROR: Must be IPv4/CIDR."; pause; return 0; }
  range_start="$(ask "Range start IP (e.g. 192.168.1.100)" "")"
  [ -z "$range_start" ] && return 0
  is_valid_ipv4 "$range_start" || { tprint "ERROR: Must be valid IPv4."; pause; return 0; }
  range_stop="$(ask "Range stop IP (e.g. 192.168.1.200)" "")"
  [ -z "$range_stop" ] && return 0
  is_valid_ipv4 "$range_stop" || { tprint "ERROR: Must be valid IPv4."; pause; return 0; }
  gateway="$(ask "Default gateway IP (optional)" "")"
  [ -n "$gateway" ] && ! is_valid_ipv4 "$gateway" && { tprint "ERROR: Must be valid IPv4."; pause; return 0; }
  dns="$(ask "DNS server IP (optional)" "")"
  [ -n "$dns" ] && ! is_valid_ipv4 "$dns" && { tprint "ERROR: Must be valid IPv4."; pause; return 0; }
  lease="$(ask "Lease time in seconds (optional, default 86400)" "")"
  if [ -n "$lease" ]; then
    echo "$lease" | grep -Eq '^[0-9]+$' || { tprint "ERROR: Must be numeric."; pause; return 0; }
    [ "$lease" -lt 60 ] 2>/dev/null && { tprint "ERROR: Minimum lease 60 seconds."; pause; return 0; }
  fi
  tprint ""
  tprint "SUMMARY: DHCP pool $name"
  tprint "  subnet:  $subnet"
  tprint "  range:   $range_start — $range_stop"
  [ -n "$gateway" ] && tprint "  gateway: $gateway"
  [ -n "$dns"     ] && tprint "  dns:     $dns"
  [ -n "$lease"   ] && tprint "  lease:   ${lease}s"
  yn="$(choose_yes_no "Create pool?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set service dhcp-server shared-network-name "$name" subnet "$subnet" range 0 start "$range_start"
  cfg_set service dhcp-server shared-network-name "$name" subnet "$subnet" range 0 stop "$range_stop"
  [ -n "$gateway" ] && cfg_set service dhcp-server shared-network-name "$name" subnet "$subnet" option default-router "$gateway"
  [ -n "$dns" ] && cfg_set service dhcp-server shared-network-name "$name" subnet "$subnet" option name-server "$dns"
  [ -n "$lease" ] && cfg_set service dhcp-server shared-network-name "$name" subnet "$subnet" lease "$lease"
  cfg_apply
}

dhcp_delete_pool() {
  local pools=() target yn
  load_array pools scan_dhcp_pools
  require_nonempty_list_or_return "DHCP pools" "${pools[@]}" || return 0
  select_from_list "Select DHCP pool to DELETE" "${pools[@]}" || return 0
  target="$SELECTED"
  dhcp_show_pool "$target"
  yn="$(choose_yes_no "Delete DHCP pool $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_delete service dhcp-server shared-network-name "$target"
  cfg_apply
}

dhcp_add_static_mapping() {
  local pools=() pool subnets=() subnet name mac ip yn
  load_array pools scan_dhcp_pools
  require_nonempty_list_or_return "DHCP pools" "${pools[@]}" || return 0
  select_from_list "Select DHCP pool for static mapping" "${pools[@]}" || return 0
  pool="$SELECTED"
  load_array subnets scan_dhcp_subnets "$pool"
  require_nonempty_list_or_return "subnets in pool $pool" "${subnets[@]}" || return 0
  select_from_list "Select subnet" "${subnets[@]}" || return 0
  subnet="$SELECTED"
  name="$(ask "Mapping name (e.g. printer, server1)" "")"
  [ -z "$name" ] && return 0
  is_safe_ruleset_name "$name" || { tprint "ERROR: Invalid mapping name."; pause; return 0; }
  mac="$(ask "MAC address (xx:xx:xx:xx:xx:xx)" "")"
  [ -z "$mac" ] && return 0
  echo "$mac" | grep -Eiq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' \
    || { tprint "ERROR: Invalid MAC address."; pause; return 0; }
  ip="$(ask "Reserved IP" "")"
  [ -z "$ip" ] && return 0
  is_valid_ipv4 "$ip" || { tprint "ERROR: Must be valid IPv4."; pause; return 0; }
  tprint ""; tprint "SUMMARY: $pool $subnet static-mapping $name  $mac → $ip"
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set service dhcp-server shared-network-name "$pool" subnet "$subnet" static-mapping "$name" mac "$mac"
  cfg_set service dhcp-server shared-network-name "$pool" subnet "$subnet" static-mapping "$name" ip-address "$ip"
  cfg_apply
}

dhcp_show_leases() {
  run_cmd_to_tty "show dhcp server leases"
  pause
}

dhcp_server_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== DHCP Server ======"
    tprint "Pools: $(scan_dhcp_pools | join_lines || echo NONE)"; tprint ""
    tprint "1) List DHCP config"
    tprint "2) Add pool (safe)"
    tprint "3) Delete pool"
    tprint "4) Add static mapping"
    tprint "5) Show current leases"
    tprint "6) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) tprint ""; grep_cfg "set service dhcp-server " >"$TTY" 2>/dev/null || tprint "(none)"; pause ;;
      2) dhcp_add_pool_safe ;;
      3) dhcp_delete_pool ;;
      4) dhcp_add_static_mapping ;;
      5) dhcp_show_leases ;;
      6) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# SSH SERVICE
# ============================================================
ssh_show_config() {
  tprint ""; tprint "--- SSH config ---"
  tprint "--------------------------------------------------------"
  grep_cfg "set service ssh " >"$TTY" 2>/dev/null || tprint "(no SSH config found)"
  tprint "--------------------------------------------------------"
  tprint ""
  run_cmd_to_tty "show service ssh"
  pause
}

ssh_set_port() {
  local cur_port new_port yn
  cur_port="$(ssh_get_port)"
  tprint ""; tprint "Current SSH port: ${cur_port:-22 (default)}"
  tprint "WARNING: Changing port drops existing SSH sessions on the old port after commit."
  new_port="$(ask "New SSH port" "${cur_port:-22}")"
  [ -z "$new_port" ] && return 0
  is_valid_port_or_range "$new_port" || { tprint "ERROR: Invalid port."; pause; return 0; }
  echo "$new_port" | grep -q '-' && { tprint "ERROR: Port must be a single value, not a range."; pause; return 0; }
  yn="$(choose_yes_no "Set SSH port to $new_port?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set service ssh port "$new_port"
  cfg_apply
}

ssh_add_listen_address() {
  local current=() new_addr yn
  load_array current scan_ssh_listen_addresses
  tprint ""; tprint "Current listen addresses: ${current[*]:-(all interfaces)}"
  new_addr="$(ask "Listen address (IPv4)" "")"
  [ -z "$new_addr" ] && return 0
  is_valid_ipv4 "$new_addr" || { tprint "ERROR: Must be valid IPv4."; pause; return 0; }
  is_in_list "$new_addr" "${current[@]}" && { tprint "ERROR: $new_addr already configured."; pause; return 0; }
  yn="$(choose_yes_no "Restrict SSH to listen on $new_addr?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_set service ssh listen-address "$new_addr"
  cfg_apply
}

ssh_delete_listen_address() {
  local current=() target yn
  load_array current scan_ssh_listen_addresses
  require_nonempty_list_or_return "SSH listen addresses" "${current[@]}" || return 0
  select_from_list "Select listen address to DELETE" "${current[@]}" || return 0
  target="$SELECTED"
  yn="$(choose_yes_no "Remove SSH listen-address $target?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  cfg_delete service ssh listen-address "$target"
  cfg_apply
}

ssh_toggle_password_auth() {
  local cur_state yn
  cur_state="$(grep_cfg "set service ssh disable-password-authentication" | grep -q . && echo "DISABLED" || echo "enabled")"
  tprint ""; tprint "Password authentication: $cur_state"
  if [ "$cur_state" = "DISABLED" ]; then
    tprint "NOTE: Key-based auth only. Enabling password auth reduces security."
    yn="$(choose_yes_no "Re-enable password authentication?" "n" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; cfg_delete service ssh disable-password-authentication; cfg_apply
  else
    tprint "WARNING: Disabling password auth — ensure key-based auth works FIRST."
    yn="$(choose_yes_no "Disable password authentication?" "n" || echo "n")"
    [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
    cfg_begin || return 0; cfg_set service ssh disable-password-authentication; cfg_apply
  fi
}

ssh_toggle_service() {
  local yn
  if ssh_is_enabled; then
    tprint ""; tprint "SSH is currently: ENABLED"
    tprint "WARNING: Disabling SSH will close all active SSH sessions after commit."
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
    tprint "1) Show SSH config"
    tprint "2) Set port"
    tprint "3) Add listen address"
    tprint "4) Delete listen address"
    tprint "5) Toggle password authentication"
    tprint "6) Enable / disable SSH service"
    tprint "7) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) ssh_show_config ;;
      2) ssh_set_port ;;
      3) ssh_add_listen_address ;;
      4) ssh_delete_listen_address ;;
      5) ssh_toggle_password_auth ;;
      6) ssh_toggle_service ;;
      7) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# RAW MODE
# ============================================================
raw_mode() {
  tprint ""; tprint "RAW MODE — restricted set/delete only"
  tprint "Rules: start with 'set' or 'delete', no quotes/tabs/shell metacharacters"
  tprint "Example: set service ssh port 22 | Blank = cancel"; tprint ""
  local cmd yn
  tread cmd "> " || return 0
  [ -z "$cmd" ] && return 0
  if reject_if_unsafe_commandline "$cmd"; then
    tprint "ERROR: Unsafe characters detected."; pause; return 0
  fi
  # shellcheck disable=SC2086
  set -- $cmd
  local verb="${1:-}"; shift || true
  case "$verb" in
    set|delete) ;;
    *) tprint "ERROR: Must start with 'set' or 'delete'."; pause; return 0 ;;
  esac
  yn="$(choose_yes_no "Run: $verb $* ?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0
  case "$verb" in
    set)    cfg_set "$@" ;;
    delete) cfg_delete "$@" ;;
  esac
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
    tprint " VyOS Dynamic Menu  (v2.1 REFACTORED)"
    tprint "======================================"
    tprint "Interfaces:   $(scan_all_ifaces       | join_lines || echo NONE)"
    tprint "FW rulesets:  $(scan_firewall_rulesets | join_lines || echo NONE)"
    tprint "FW zones:     $(scan_fw_zones          | join_lines || echo NONE)"
    tprint "Static routes:$(scan_static_routes     | join_lines || echo NONE)"
    tprint "DHCP pools:   $(scan_dhcp_pools        | join_lines || echo NONE)"
    tprint "NAT dest:     $(scan_nat_dest_rules   | join_lines || echo NONE)"
    tprint "NAT src:      $(scan_nat_source_rules | join_lines || echo NONE)"
    tprint ""
    tprint " 1) Interfaces       (eth / bond / VLAN / loopback)"
    tprint " 2) Firewall         (rules + zone management)"
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
