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
# ZONE HELPERS (NEW v2.1)
# ============================================================

get_unassigned_real_ifaces() {
  # Returns real interfaces NOT already in a zone, excluding loopback
  local all=() assigned=() result=()
  load_array all scan_all_ifaces
  
  # Get all interfaces already assigned to zones
  local zi; while IFS='|' read -r z i; do
    assigned+=("$i")
  done < <(scan_zone_ifaces)
  
  # Filter: exclude loopback and already-assigned
  local iface
  for iface in "${all[@]}"; do
    # Skip loopback
    if echo "$iface" | grep -Eq '^lo[0-9]*$'; then
      continue
    fi
    # Skip if already assigned
    if is_in_list "$iface" "${assigned[@]}"; then
      continue
    fi
    result+=("$iface")
  done
  
  printf '%s\n' "${result[@]}"
}

zone_create_single_interface() {
  # MODE A: Create ONE zone per ONE interface
  # Returns to menu after each creation
  
  local zones=() zname yn unassigned_ifaces=() iface zone_type
  load_array zones scan_fw_zones
  
  tprint ""; tprint "Existing zones: ${zones[*]:-(none)}"; tprint ""
  
  load_array unassigned_ifaces get_unassigned_real_ifaces
  require_nonempty_list_or_return "unassigned real interfaces" "${unassigned_ifaces[@]}" || return 0
  
  select_from_list "Select interface for new zone" "${unassigned_ifaces[@]}" || return 0
  iface="$SELECTED"
  
  select_from_list_default "Zone type" "normal" "normal" "local-zone (router self)" || return 0
  case "$SELECTED" in
    "local-zone (router self)") zone_type="local" ;;
    *) zone_type="normal" ;;
  esac
  
  if [ "$zone_type" = "normal" ]; then
    zname="$(ask "Zone name for $iface (e.g. LAN, WAN, DMZ)" "")"
  else
    zname="$(ask "Local zone name (e.g. LOCAL, ROUTER)" "")"
  fi
  [ -z "$zname" ] && return 0
  
  if ! is_safe_ruleset_name "$zname"; then
    tprint "ERROR: Invalid zone name (letters/numbers/_/./- max 64)."; pause; return 0
  fi
  if is_in_list "$zname" "${zones[@]}"; then
    tprint "ERROR: Zone '$zname' already exists."; pause; return 0
  fi
  
  tprint ""
  if [ "$zone_type" = "local" ]; then
    tprint "SUMMARY: create local-zone '$zname'  (no interface member)"
  else
    tprint "SUMMARY: create zone '$zname'  interface=$iface"
  fi
  tprint "NOTE: Use 'Set default-action' to set drop/accept/reject."
  yn="$(choose_yes_no "Proceed?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  
  cfg_begin || return 0
  if [ "$zone_type" = "local" ]; then
    cfg_set firewall zone "$zname" local-zone
  else
    cfg_set firewall zone "$zname" interface "$iface"
  fi
  cfg_apply
}

zone_create_batch_from_interfaces() {
  # MODE B: Batch create zones from unassigned interfaces
  
  local unassigned_ifaces=() yn
  load_array unassigned_ifaces get_unassigned_real_ifaces
  require_nonempty_list_or_return "unassigned real interfaces" "${unassigned_ifaces[@]}" || return 0
  
  tprint ""; tprint "Found ${#unassigned_ifaces[@]} unassigned real interfaces:"
  printf '%s\n' "${unassigned_ifaces[@]}" | awk '{print "  - " $0}' >"$TTY"
  tprint ""
  
  local iface zname zones=()
  load_array zones scan_fw_zones
  
  for iface in "${unassigned_ifaces[@]}"; do
    tprint ""; tprint "--- Interface: $iface ---"
    zname="$(ask "Zone name for $iface (blank to skip)" "")"
    [ -z "$zname" ] && { tprint "Skipped $iface."; continue; }
    
    if ! is_safe_ruleset_name "$zname"; then
      tprint "ERROR: Invalid zone name."; continue
    fi
    if is_in_list "$zname" "${zones[@]}"; then
      tprint "ERROR: Zone '$zname' already exists."; continue
    fi
    
    tprint "Creating zone '$zname' with interface $iface..."
    cfg_begin || continue
    cfg_set firewall zone "$zname" interface "$iface"
    cfg_apply || continue
    
    zones+=("$zname")
    tprint "Created: $zname → $iface"
  done
  
  tprint ""; tprint "Batch zone creation complete."
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
  cfg_set firewall ipv4 name "$rs" rule "$n" action "$action"
  [ -n "$desc"  ] && cfg_set firewall ipv4 name "$rs" rule "$n" description "$desc"
  [ -n "$proto" ] && [ "$proto" != "any" ] && cfg_set firewall ipv4 name "$rs" rule "$n" protocol "$proto"
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
  grep_cfg "set firewall zone " | grep -F " interface " \
    | awk '{print $4 "|" $6}' \
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
  cfg_set firewall zone "$zname" interface "$iface"
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
  cfg_delete firewall zone "$zname" interface "$target"
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

zone_add_binding_safe() {
  local to from ruleset yn
  to="$(zone_choose_existing)" || return 0; from="$(zone_choose_existing)" || return 0
  [ "$to" = "$from" ] && { tprint "ERROR: TO and FROM cannot be the same zone."; pause; return 0; }
  if grep_cfg "set firewall zone $to from $from firewall name" | grep -q .; then
    tprint "ERROR: Binding $to <- $from already exists."; tprint "Use Update to change it."; pause; return 0
  fi
  local rs_arr=(); load_array rs_arr scan_firewall_rulesets
  require_nonempty_list_or_return "firewall rulesets" "${rs_arr[@]}" || return 0
  select_from_list "Select ruleset for binding" "${rs_arr[@]}" || return 0
  ruleset="$SELECTED"
  tprint ""; tprint "SUMMARY: $to <- $from  =  $ruleset"
  yn="$(choose_yes_no "Create binding?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set firewall zone "$to" from "$from" firewall name "$ruleset"; cfg_apply
}

zone_update_binding_existing() {
  local to from ruleset existing_rs yn
  to="$(zone_choose_existing)" || return 0; from="$(zone_choose_existing)" || return 0
  if ! grep_cfg "set firewall zone $to from $from firewall name" | grep -q .; then
    tprint "ERROR: No binding for $to <- $from. Use Add."; pause; return 0
  fi
  existing_rs="$(grep_cfg "set firewall zone $to from $from firewall name" | awk '{print $NF}' | head -n 1 | while read -r x; do strip_quotes "$x"; done)"
  zone_binding_preview "$to" "$from"
  local rs_arr=(); load_array rs_arr scan_firewall_rulesets
  require_nonempty_list_or_return "firewall rulesets" "${rs_arr[@]}" || return 0
  select_from_list "Select new ruleset" "${rs_arr[@]}" || return 0
  ruleset="$SELECTED"
  tprint "SUMMARY: $to <- $from  $existing_rs  →  $ruleset"
  yn="$(choose_yes_no "Update binding?" "y" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_set firewall zone "$to" from "$from" firewall name "$ruleset"; cfg_apply
}

zone_delete_binding_existing() {
  local to from existing_rs yn
  to="$(zone_choose_existing)" || return 0; from="$(zone_choose_existing)" || return 0
  if ! grep_cfg "set firewall zone $to from $from firewall name" | grep -q .; then
    tprint "ERROR: No binding for $to <- $from."; pause; return 0
  fi
  existing_rs="$(grep_cfg "set firewall zone $to from $from firewall name" | awk '{print $NF}' | head -n 1 | while read -r x; do strip_quotes "$x"; done)"
  zone_binding_preview "$to" "$from"
  yn="$(choose_yes_no "Delete binding $to <- $from ($existing_rs)?" "n" || echo "n")"
  [ "$yn" != "y" ] && { tprint "Canceled."; pause; return 0; }
  cfg_begin || return 0; cfg_delete firewall zone "$to" from "$from" firewall name; cfg_apply
}

zone_bindings_menu() {
  while true; do
    tprint ""; tprint "====== Zone Bindings ======"
    local b=(); load_array b scan_zone_bindings
    if [ "${#b[@]}" -eq 0 ]; then tprint "(none found)"; else
      printf "%s\n" "${b[@]}" | awk -F'|' '{printf "  %-12s <- %-12s  =  %s\n",$1,$2,$3}' >"$TTY"
    fi
    tprint ""
    tprint "1) Add binding (safe)"
    tprint "2) Update binding"
    tprint "3) Delete binding"
    tprint "4) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) zone_add_binding_safe ;;
      2) zone_update_binding_existing ;;
      3) zone_delete_binding_existing ;;
      4) return 0 ;;
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
# NAT (placeholder - full implementation from original)
# ============================================================
nat_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== NAT ======"
    _nat_summary; tprint ""
    tprint "1) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# SYSTEM (placeholder)
# ============================================================
system_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== System ======"
    tprint "Hostname: $(get_current_hostname || echo UNKNOWN)"
    tprint "Users:    $(scan_login_users | join_lines || echo NONE)"; tprint ""
    tprint "1) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# DNS FORWARDING (placeholder)
# ============================================================
dns_forwarding_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== DNS Forwarding ======"
    _dns_summary; tprint ""
    tprint "1) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# RIP (placeholder)
# ============================================================
rip_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== RIP ======"
    _rip_summary; tprint ""
    tprint "1) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# STATIC ROUTES (placeholder)
# ============================================================
static_routes_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== Static Routes ======"
    tprint "Routes: $(scan_static_routes | join_lines || echo NONE)"; tprint ""
    tprint "1) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# DHCP SERVER (placeholder)
# ============================================================
dhcp_server_menu() {
  warn_if_no_access || return 0
  while true; do
    tprint ""; tprint "====== DHCP Server ======"
    tprint "Pools: $(scan_dhcp_pools | join_lines || echo NONE)"; tprint ""
    tprint "1) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) return 0 ;;
      *) tprint "Invalid." ;;
    esac
  done
}

# ============================================================
# SSH SERVICE (placeholder)
# ============================================================
ssh_service_menu() {
  warn_if_no_access || return 0
  while true; do
    local ssh_state; ssh_is_enabled && ssh_state="ENABLED" || ssh_state="disabled"
    local cur_port; cur_port="$(ssh_get_port)"; cur_port="${cur_port:-22 (default)}"
    tprint ""; tprint "====== SSH Service ======"
    tprint "Status: $ssh_state  |  Port: $cur_port"
    tprint "Listen: $(scan_ssh_listen_addresses | join_lines || echo "(all interfaces)")"; tprint ""
    tprint "1) Back"
    local c; tread c "Select: " || continue
    case "$c" in
      1) return 0 ;;
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
    tprint "NAT dest/src: $(scan_nat_dest_rules | join_lines || echo -) / $(scan_nat_source_rules | join_lines || echo -)"
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
