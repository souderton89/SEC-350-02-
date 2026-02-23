#!/bin/vbash
# vyos-dynamic-menu.sh
# Dynamic CRUD menu for Firewall (ipv4 rulesets) + NAT + Interfaces
# Scans live config each time. No hardcoded rules.
#
# SAFETY GOALS:
# - "ADD" must NOT overwrite existing items.
#   * Add DNAT: blocks rule number if it already exists.
#   * Add Firewall rule: blocks rule number if it already exists in that ruleset.
# - User is ALWAYS shown what exists + the next suggested free rule number.
# - Updates/changes to existing rules must be done via Update/Delete menus (not Add).
#
# USER FRIENDLY:
# - Every submenu repeats detected items.
# - Every prompt explains WHAT you are selecting.
# - If a list is empty (permissions or no config), you get a clear error (no blind "Select:").
# - Uses grep -F (no regex from user input).
# - Preview before delete/update.
#
# PORTABILITY FIX (CRITICAL):
# - Any function used like var="$(func)" MUST print UI to STDERR,
#   and ONLY print the final value to STDOUT.
#   Otherwise menus get "captured" and disappear on some systems/terminals.

source /opt/vyatta/etc/functions/script-template

# -----------------------------
# UI helpers (IMPORTANT)
# -----------------------------
ui() { echo "$*" >&2; }
uiblank() { echo >&2; }
uiprintf() { printf "%s" "$*" >&2; }
uiprintfln() { printf "%s\n" "$*" >&2; }

pause() { uiblank; read -r -p "Press Enter to continue..." _; }

strip_quotes() {
  local s="$1"
  s="${s#\'}"
  s="${s%\'}"
  echo "$s"
}

join_lines() { tr '\n' ' ' | sed 's/[[:space:]]*$//'; }

# ---- ACCESS CHECKS ----
get_cfg_cmds() {
  # capture stderr too so we can detect permission errors
  run show configuration commands 2>&1
}

die_no_access_if_needed() {
  local out
  out="$(get_cfg_cmds || true)"

  if echo "$out" | grep -qiE "not assigned to any operator group|permission denied|authorization|not authorized|internal error"; then
    ui ""
    ui "ERROR: This user does not have permission to read the live config."
    ui "The script needs: 'show configuration commands'."
    ui ""
    ui "Fix:"
    ui "  - Run as a VyOS admin user, OR"
    ui "  - Fix this user's operator/admin permissions."
    ui ""
    ui "What VyOS returned:"
    ui "----------------------------------------"
    ui "$out"
    ui "----------------------------------------"
    ui ""
    exit 1
  fi

  if [ -z "$out" ]; then
    ui ""
    ui "ERROR: 'show configuration commands' returned NOTHING."
    ui "This usually means permission problems or a broken CLI session."
    ui ""
    exit 1
  fi
}

show_detected_summary() {
  local ifs rulesets nd ns
  ifs="$(scan_eth_ifaces | join_lines)"
  rulesets="$(scan_firewall_rulesets | join_lines)"
  nd="$(scan_nat_dest_rules | join_lines)"
  ns="$(scan_nat_source_rules | join_lines)"

  ui "Detected right now:"
  ui "  Interfaces: ${ifs:-NONE}"
  ui "  FW rulesets: ${rulesets:-NONE}"
  ui "  NAT dest rules: ${nd:-NONE}"
  ui "  NAT source rules: ${ns:-NONE}"
  ui ""
}

# Print a numbered menu and set SELECTED (UI printed to STDERR)
select_from_list() {
  local title="$1"; shift
  local arr=("$@")
  local i choice

  ui ""
  ui "=== $title ==="

  if [ "${#arr[@]}" -eq 0 ]; then
    ui "(none found)"
    return 1
  fi

  for i in "${!arr[@]}"; do
    uiprintfln "$(printf "%2d) %s" "$((i+1))" "${arr[$i]}")"
  done
  ui " 0) Cancel"
  ui ""

  read -r -p "Select option #: " choice
  if [ -z "$choice" ] || ! echo "$choice" | grep -Eq '^[0-9]+$'; then
    ui "Invalid."
    return 1
  fi
  if [ "$choice" -eq 0 ]; then
    return 1
  fi
  if [ "$choice" -lt 1 ] || [ "$choice" -gt "${#arr[@]}" ]; then
    ui "Invalid."
    return 1
  fi

  SELECTED="${arr[$((choice-1))]}"
  return 0
}

ask() {
  # prompt to STDERR so it never disappears inside $(...)
  local prompt="$1"
  local def="${2:-}"
  local val=""
  if [ -n "$def" ]; then
    read -r -p "$prompt [$def]: " val
    echo "${val:-$def}"
  else
    read -r -p "$prompt: " val
    echo "$val"
  fi
}

confirm_commit_save() {
  local yn
  read -r -p "Commit + Save now? (y/n) [y]: " yn
  yn="${yn:-y}"
  case "$yn" in
    y|Y) return 0 ;;
    *)   return 1 ;;
  esac
}

cfg_apply() {
  if confirm_commit_save; then
    commit
    save
    ui "DONE: committed + saved."
  else
    ui "Not committed. (No changes saved.)"
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

require_numeric() {
  local v="$1"
  echo "$v" | grep -Eq '^[0-9]+$'
}

require_nonempty_list_or_return() {
  local label="$1"; shift
  local arr=("$@")
  if [ "${#arr[@]}" -eq 0 ]; then
    ui ""
    ui "ERROR: Nothing available for: $label"
    ui "Possible reasons:"
    ui "  - The config has none, OR"
    ui "  - Permission problem (cannot read config)."
    ui ""
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
  mapfile -t a < <(scan_firewall_rule_numbers_quoted "$rs")
  mapfile -t b < <(scan_firewall_rule_numbers_unquoted "$rs")
  merged=("${a[@]}" "${b[@]}")
  if [ "${#merged[@]}" -gt 0 ]; then
    mapfile -t merged < <(printf "%s\n" "${merged[@]}" | sed '/^$/d' | sort -u)
  fi
  printf "%s\n" "${merged[@]}"
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

# -----------------------------
# Firewall CRUD
# -----------------------------
fw_choose_ruleset_existing_only() {
  local arr=()
  mapfile -t arr < <(scan_firewall_rulesets)

  ui ""
  ui "You are selecting a FIREWALL RULESET (existing)."
  ui "Examples: DMZ-to-LAN, WAN-to-DMZ, LAN-to-WAN"
  ui ""

  require_nonempty_list_or_return "Firewall rulesets" "${arr[@]}" || return 1

  ui "Available rulesets:"
  printf "  - %s\n" "${arr[@]}" >&2
  ui ""

  if select_from_list "Select WHICH ruleset to use" "${arr[@]}"; then
    echo "$SELECTED"
    return 0
  fi
  return 1
}

fw_choose_ruleset_or_new() {
  local arr=()
  mapfile -t arr < <(scan_firewall_rulesets)

  ui ""
  ui "You are selecting a FIREWALL RULESET."
  ui "Examples: DMZ-to-LAN, WAN-to-DMZ, LAN-to-WAN"
  ui ""

  if [ "${#arr[@]}" -gt 0 ]; then
    ui "Available rulesets:"
    printf "  - %s\n" "${arr[@]}" >&2
    ui ""

    if select_from_list "Select a ruleset to use" "${arr[@]}"; then
      echo "$SELECTED"
      return 0
    fi
  else
    ui "No rulesets detected."
  fi

  ui ""
  ui "No selection made. Type a ruleset name to create/use."
  local rs
  rs="$(ask "Ruleset name (example: DMZ-to-LAN)" "")"
  [ -z "$rs" ] && return 1
  echo "$rs"
}

fw_choose_rule_number_existing() {
  local rs="$1"
  local arr=()
  mapfile -t arr < <(scan_firewall_rule_numbers "$rs")

  ui ""
  ui "You are selecting an EXISTING RULE NUMBER in: $rs"
  ui ""

  require_nonempty_list_or_return "Firewall rules inside ruleset '$rs'" "${arr[@]}" || return 1

  ui "Existing rule numbers:"
  printf "  - %s\n" "${arr[@]}" >&2
  ui ""

  if select_from_list "Select existing rule number" "${arr[@]}"; then
    echo "$SELECTED"
    return 0
  fi
  return 1
}

fw_choose_rule_number_new_only() {
  local rs="$1"
  local used=() suggested n
  mapfile -t used < <(scan_firewall_rule_numbers "$rs")

  ui ""
  ui "ADD MODE (SAFE): You are selecting a NEW RULE NUMBER in: $rs"
  ui "Add will NOT overwrite existing numbers."
  ui ""

  ui "Existing rule numbers:"
  if [ "${#used[@]}" -gt 0 ]; then
    printf "  - %s\n" "${used[@]}" >&2
  else
    ui "  (none)"
  fi
  ui ""

  suggested="$(next_free_rule_number "${used[@]}")"
  ui "Suggested next free rule number: $suggested"
  ui ""

  while true; do
    n="$(ask "Rule number (new only)" "$suggested")"
    [ -z "$n" ] && ui "Rule number required." && continue
    if ! require_numeric "$n"; then
      ui "ERROR: must be a number (example: 10)."
      continue
    fi
    if is_number_in_list "$n" "${used[@]}"; then
      ui "ERROR: rule $n already exists in $rs."
      ui "Use Update/Delete to change existing rules."
      continue
    fi
    break
  done
  echo "$n"
}

fw_preview_rule() {
  local rs="$1" n="$2"
  ui ""
  ui "Current config lines for: firewall ipv4 name '$rs' rule $n"
  ui "--------------------------------------------------------"
  get_cfg_cmds | grep -F "set firewall ipv4 name '$rs' rule $n " || true
  get_cfg_cmds | grep -F "set firewall ipv4 name $rs rule $n " || true
  ui "--------------------------------------------------------"
  ui ""
}

fw_list_ruleset() {
  local rs
  ui ""
  ui "You selected: List ruleset"
  ui "Next: choose WHICH ruleset to view."
  ui ""
  rs="$(fw_choose_ruleset_existing_only)" || return 0

  ui ""
  ui "Showing commands for ruleset: $rs"
  ui "--------------------------------------------------------"
  get_cfg_cmds | grep -F "set firewall ipv4 name '$rs' " || true
  get_cfg_cmds | grep -F "set firewall ipv4 name $rs " || true
  ui "--------------------------------------------------------"
  pause
}

fw_add_rule_guided_safe() {
  local rs n action proto desc saddr daddr sport dport state_est state_rel state_new

  ui ""
  ui "You selected: ADD rule (SAFE - new only)"
  ui "Next steps:"
  ui "  1) Select a ruleset"
  ui "  2) Select a NEW rule number (script suggests next free)"
  ui "  3) Enter fields"
  ui ""

  rs="$(fw_choose_ruleset_or_new)" || return 0
  n="$(fw_choose_rule_number_new_only "$rs")" || return 0

  ui ""
  ui "Now creating NEW rule: firewall ipv4 name '$rs' rule $n"
  ui "Leave optional fields blank to skip."
  ui ""

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

  ui ""
  ui "SUMMARY:"
  ui "  ruleset: $rs"
  ui "  rule: $n"
  ui "  action: $action"
  [ -n "$proto" ] && ui "  protocol: $proto"
  [ -n "$saddr" ] && ui "  source address: $saddr"
  [ -n "$sport" ] && ui "  source port: $sport"
  [ -n "$daddr" ] && ui "  destination address: $daddr"
  [ -n "$dport" ] && ui "  destination port: $dport"
  [ -n "$desc" ] && ui "  description: $desc"
  ui ""
  pause

  configure
  set firewall ipv4 name "$rs" rule "$n" action "$action"
  [ -n "$desc" ] && set firewall ipv4 name "$rs" rule "$n" description "$desc"

  if [ -n "$proto" ] && [ "$proto" != "any" ]; then
    set firewall ipv4 name "$rs" rule "$n" protocol "$proto"
  fi

  [ -n "$saddr" ] && set firewall ipv4 name "$rs" rule "$n" source address "$saddr"
  [ -n "$daddr" ] && set firewall ipv4 name "$rs" rule "$n" destination address "$daddr"
  [ -n "$sport" ] && set firewall ipv4 name "$rs" rule "$n" source port "$sport"
  [ -n "$dport" ] && set firewall ipv4 name "$rs" rule "$n" destination port "$dport"

  [ "$state_est" = "y" ] || [ "$state_est" = "Y" ] && set firewall ipv4 name "$rs" rule "$n" state established
  [ "$state_rel" = "y" ] || [ "$state_rel" = "Y" ] && set firewall ipv4 name "$rs" rule "$n" state related
  [ "$state_new" = "y" ] || [ "$state_new" = "Y" ] && set firewall ipv4 name "$rs" rule "$n" state new

  cfg_apply
}

fw_update_single_field() {
  local rs n tail val

  ui ""
  ui "You selected: Update ONE field (existing rule)"
  ui "Next steps:"
  ui "  1) Select a ruleset"
  ui "  2) Select an EXISTING rule number"
  ui "  3) Enter the field path + new value"
  ui ""

  rs="$(fw_choose_ruleset_existing_only)" || return 0
  n="$(fw_choose_rule_number_existing "$rs")" || return 0
  fw_preview_rule "$rs" "$n"

  ui "Common field paths:"
  ui "  action"
  ui "  description"
  ui "  protocol"
  ui "  destination address"
  ui "  destination port"
  ui "  source address"
  ui "  source port"
  ui "  state established"
  ui ""

  tail="$(ask "Field path (words after: rule <N>)" "")"
  [ -z "$tail" ] && return 0
  val="$(ask "New value" "")"
  [ -z "$val" ] && return 0

  configure
  # shellcheck disable=SC2086
  set firewall ipv4 name "$rs" rule "$n" $tail "$val"
  cfg_apply
}

fw_delete_rule() {
  local rs n

  ui ""
  ui "You selected: Delete existing rule"
  ui "Next steps:"
  ui "  1) Select a ruleset"
  ui "  2) Select an EXISTING rule number to delete"
  ui ""

  rs="$(fw_choose_ruleset_existing_only)" || return 0
  n="$(fw_choose_rule_number_existing "$rs")" || return 0
  fw_preview_rule "$rs" "$n"

  configure
  delete firewall ipv4 name "$rs" rule "$n"
  cfg_apply
}

firewall_menu() {
  while true; do
    ui ""
    ui "========================"
    ui " Firewall Menu (Dynamic)"
    ui "========================"
    show_detected_summary
    ui "SAFE RULES:"
    ui "  - ADD will NOT overwrite existing rule numbers."
    ui "  - Update/Delete only work on EXISTING rules."
    ui ""
    ui "1) List ruleset (show commands)"
    ui "2) ADD rule (SAFE - new only)"
    ui "3) Update ONE field in an existing rule"
    ui "4) Delete existing rule"
    ui "5) Back"
    read -r -p "Select menu option #: " c
    case "$c" in
      1) fw_list_ruleset ;;
      2) fw_add_rule_guided_safe ;;
      3) fw_update_single_field ;;
      4) fw_delete_rule ;;
      5) return 0 ;;
      *) ui "Invalid." ;;
    esac
  done
}

# -----------------------------
# NAT CRUD
# -----------------------------
nat_choose_type() {
  ui ""
  ui "You are selecting a NAT TYPE:"
  ui "  destination = DNAT / port forwarding"
  ui "  source      = SNAT / masquerade"
  ui ""
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
    mapfile -t arr < <(scan_nat_dest_rules)
  else
    mapfile -t arr < <(scan_nat_source_rules)
  fi

  ui ""
  ui "You are selecting an EXISTING NAT RULE NUMBER (type: $type)"
  ui ""

  require_nonempty_list_or_return "NAT $type rules" "${arr[@]}" || return 1

  ui "Existing rule numbers:"
  printf "  - %s\n" "${arr[@]}" >&2
  ui ""

  if select_from_list "Select existing NAT rule number" "${arr[@]}"; then
    echo "$SELECTED"
    return 0
  fi
  return 1
}

nat_preview_rule() {
  local type="$1" n="$2"
  ui ""
  ui "Current config lines for: nat $type rule $n"
  ui "--------------------------------------------------------"
  get_cfg_cmds | grep -F "set nat $type rule $n " || true
  ui "--------------------------------------------------------"
  ui ""
}

nat_list() {
  ui ""
  ui "You selected: List NAT"
  ui "Showing NAT commands (current config):"
  ui ""
  get_cfg_cmds | grep -F "set nat " || true
  pause
}

nat_add_dnat_guided() {
  local n desc inif proto dport taddr tport
  local used=() suggested
  local ifs=()

  ui ""
  ui "You selected: Add DNAT rule (SAFE - new only)"
  ui "Next steps:"
  ui "  1) Choose a NEW rule number (script suggests next free)"
  ui "  2) Pick inbound interface"
  ui "  3) Enter ports + translation"
  ui ""

  mapfile -t used < <(scan_nat_dest_rules)

  ui "Existing DNAT (destination) rule numbers:"
  if [ "${#used[@]}" -gt 0 ]; then
    printf "  - %s\n" "${used[@]}" >&2
  else
    ui "  (none)"
  fi
  ui ""

  suggested="$(next_free_rule_number "${used[@]}")"
  ui "Suggested next free rule number: $suggested"
  ui ""

  while true; do
    n="$(ask "DNAT rule number (new only)" "$suggested")"
    [ -z "$n" ] && ui "Rule number required." && continue
    if ! require_numeric "$n"; then
      ui "ERROR: must be a number (example: 10)."
      continue
    fi
    if is_number_in_list "$n" "${used[@]}"; then
      ui "ERROR: rule $n already exists. Add mode will NOT overwrite."
      ui "Use Update/Delete to change existing rules."
      continue
    fi
    break
  done

  desc="$(ask "Description (example: HTTP -> DMZ)" "DNAT")"

  mapfile -t ifs < <(scan_eth_ifaces)
  ui ""
  ui "Inbound interface choices (usually WAN like eth0):"
  if [ "${#ifs[@]}" -gt 0 ]; then
    printf "  - %s\n" "${ifs[@]}" >&2
  else
    ui "  (none detected)"
  fi
  ui ""

  if [ "${#ifs[@]}" -gt 0 ] && select_from_list "Select inbound interface" "${ifs[@]}"; then
    inif="$SELECTED"
  else
    inif="$(ask "Inbound interface name (example: eth0)" "eth0")"
  fi

  proto="$(ask "Protocol (tcp/udp)" "tcp")"
  dport="$(ask "Public port (example: 80)" "80")"
  taddr="$(ask "Inside IP (example: 172.16.50.3)" "172.16.50.3")"
  tport="$(ask "Inside port (example: 80)" "80")"

  ui ""
  ui "SUMMARY (DNAT rule $n):"
  ui "  description: $desc"
  ui "  inbound-interface: $inif"
  ui "  protocol: $proto"
  ui "  public port: $dport"
  ui "  translation: $taddr:$tport"
  ui ""
  pause

  configure
  set nat destination rule "$n" description "$desc"
  set nat destination rule "$n" inbound-interface name "$inif"
  set nat destination rule "$n" protocol "$proto"
  set nat destination rule "$n" destination port "$dport"
  set nat destination rule "$n" translation address "$taddr"
  set nat destination rule "$n" translation port "$tport"
  cfg_apply
}

nat_update_single_field() {
  local type n tail val

  ui ""
  ui "You selected: Update ONE field in an existing NAT rule"
  ui "Next steps:"
  ui "  1) Choose NAT type"
  ui "  2) Choose EXISTING rule number"
  ui "  3) Enter field path + new value"
  ui ""

  type="$(nat_choose_type)"
  [ -z "$type" ] && return 0
  n="$(nat_choose_rule_number_existing "$type")" || return 0

  nat_preview_rule "$type" "$n"

  ui "Common field paths:"
  ui "  description"
  ui "  destination port"
  ui "  inbound-interface name"
  ui "  outbound-interface name"
  ui "  source address"
  ui "  protocol"
  ui "  translation address"
  ui "  translation port"
  ui ""

  tail="$(ask "Field path (words after: rule <N>)" "")"
  [ -z "$tail" ] && return 0
  val="$(ask "New value" "")"
  [ -z "$val" ] && return 0

  configure
  # shellcheck disable=SC2086
  set nat "$type" rule "$n" $tail "$val"
  cfg_apply
}

nat_delete_rule() {
  local type n

  ui ""
  ui "You selected: Delete existing NAT rule"
  ui "Next steps:"
  ui "  1) Choose NAT type"
  ui "  2) Choose EXISTING rule number to delete"
  ui ""

  type="$(nat_choose_type)"
  [ -z "$type" ] && return 0
  n="$(nat_choose_rule_number_existing "$type")" || return 0

  nat_preview_rule "$type" "$n"
  configure
  delete nat "$type" rule "$n"
  cfg_apply
}

nat_menu() {
  while true; do
    ui ""
    ui "=================="
    ui " NAT Menu (Dynamic)"
    ui "=================="
    show_detected_summary
    ui "SAFE RULES:"
    ui "  - ADD DNAT will NOT overwrite existing rule numbers."
    ui "  - Update/Delete only work on EXISTING rules."
    ui ""
    ui "1) List NAT (show commands)"
    ui "2) Add DNAT rule (SAFE - new only)"
    ui "3) Update ONE field in an existing NAT rule"
    ui "4) Delete existing NAT rule"
    ui "5) Back"
    read -r -p "Select menu option #: " c
    case "$c" in
      1) nat_list ;;
      2) nat_add_dnat_guided ;;
      3) nat_update_single_field ;;
      4) nat_delete_rule ;;
      5) return 0 ;;
      *) ui "Invalid." ;;
    esac
  done
}

# -----------------------------
# Interfaces
# -----------------------------
iface_set_ip() {
  local ifs=() iface ip desc
  mapfile -t ifs < <(scan_eth_ifaces)

  ui ""
  ui "You selected: Set interface IP + description"
  ui "Next steps:"
  ui "  1) Choose an interface"
  ui "  2) Enter a CIDR address"
  ui "  3) Optional description"
  ui ""

  require_nonempty_list_or_return "Ethernet interfaces" "${ifs[@]}" || return 0

  ui "Interfaces available:"
  printf "  - %s\n" "${ifs[@]}" >&2
  ui ""

  if select_from_list "Select interface to configure" "${ifs[@]}"; then
    iface="$SELECTED"
  else
    return 0
  fi

  ip="$(ask "New address (CIDR) (example: 172.16.50.2/29)" "")"
  [ -z "$ip" ] && return 0
  desc="$(ask "Description (optional) (example: Hamed-DMZ)" "")"

  ui ""
  ui "SUMMARY:"
  ui "  interface: $iface"
  ui "  address: $ip"
  [ -n "$desc" ] && ui "  description: $desc"
  ui ""
  pause

  configure
  set interfaces ethernet "$iface" address "$ip"
  [ -n "$desc" ] && set interfaces ethernet "$iface" description "$desc"
  cfg_apply
}

iface_show() {
  ui ""
  ui "You selected: Show interfaces"
  ui ""
  run show interfaces
  ui ""
  pause
}

iface_menu() {
  while true; do
    ui ""
    ui "========================"
    ui " Interfaces Menu (Dynamic)"
    ui "========================"
    show_detected_summary
    ui "1) Set interface IP + description"
    ui "2) Show interfaces"
    ui "3) Back"
    read -r -p "Select menu option #: " c
    case "$c" in
      1) iface_set_ip ;;
      2) iface_show ;;
      3) return 0 ;;
      *) ui "Invalid." ;;
    esac
  done
}

# -----------------------------
# Raw mode (edit ANY aspect)
# -----------------------------
raw_mode() {
  ui ""
  ui "RAW MODE WARNING:"
  ui "  Raw mode CAN overwrite or delete anything."
  ui "  Only use if you know exactly what you are doing."
  ui ""
  ui "Type ONE config command starting with: set ...  OR  delete ..."
  ui "Examples:"
  ui "  delete interfaces ethernet eth1 address 172.16.50.2/29"
  ui "  set firewall zone LAN from DMZ firewall name 'DMZ-to-LAN'"
  ui "Blank = cancel"
  ui ""
  local cmd yn
  read -r -p "> " cmd
  [ -z "$cmd" ] && return 0

  read -r -p "Are you sure you want to run that command? (y/n) [n]: " yn
  yn="${yn:-n}"
  case "$yn" in
    y|Y) ;;
    *) ui "Canceled."; pause; return 0 ;;
  esac

  configure
  eval "$cmd"
  cfg_apply
}

# -----------------------------
# Main
# -----------------------------
main_menu() {
  die_no_access_if_needed

  while true; do
    ui ""
    ui "=================================="
    ui " VyOS Dynamic Menu (Scan + CRUD)"
    ui "=================================="
    show_detected_summary
    ui "1) Interfaces submenu"
    ui "2) Firewall submenu"
    ui "3) NAT submenu"
    ui "4) Raw mode (set/delete anything)"
    ui "5) Show full config (commands)"
    ui "6) Exit"
    ui ""
    read -r -p "Select menu option #: " c
    case "$c" in
      1) iface_menu ;;
      2) firewall_menu ;;
      3) nat_menu ;;
      4) raw_mode ;;
      5) echo; get_cfg_cmds; echo; pause ;;
      6) exit 0 ;;
      *) ui "Invalid." ;;
    esac
  done
}

main_menu
