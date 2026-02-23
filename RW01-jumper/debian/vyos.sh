#!/bin/vbash
# vyos-dynamic-menu.sh
# Dynamic CRUD menu for Firewall (ipv4 rulesets) + NAT + Interfaces
# Scans live config each time. No hardcoded rules.
#
# SAFETY GOALS (what you asked for):
# - "ADD" must NOT overwrite existing items.
#   * Add DNAT: blocks rule number if it already exists.
#   * Add Firewall rule: blocks rule number if it already exists in that ruleset.
# - User must be told what exists + what the next free rule number is.
# - Updates/changes to existing rules must be done via Update/Delete menus (not Add).
#
# USER FRIENDLY:
# - Every submenu repeats detected items.
# - Every "Select:" is preceded by a clear explanation.
# - Uses grep -F (no regex from user input).
# - Preview before delete/update.

source /opt/vyatta/etc/functions/script-template

# -----------------------------
# Helpers
# -----------------------------
pause() { echo; read -r -p "Press Enter to continue..." _; }

strip_quotes() {
  local s="$1"
  s="${s#\'}"
  s="${s%\'}"
  echo "$s"
}

join_lines() { tr '\n' ' ' | sed 's/[[:space:]]*$//'; }

get_cfg_cmds() {
  run show configuration commands
}

show_detected_summary() {
  local ifs rulesets nd ns
  ifs="$(scan_eth_ifaces | join_lines)"
  rulesets="$(scan_firewall_rulesets | join_lines)"
  nd="$(scan_nat_dest_rules | join_lines)"
  ns="$(scan_nat_source_rules | join_lines)"

  echo "Detected right now:"
  echo "  Interfaces: ${ifs:-NONE}"
  echo "  FW rulesets: ${rulesets:-NONE}"
  echo "  NAT dest rules: ${nd:-NONE}"
  echo "  NAT source rules: ${ns:-NONE}"
  echo
}

# Print a numbered menu and return selected item in SELECTED
select_from_list() {
  local title="$1"; shift
  local arr=("$@")
  local i choice

  echo
  echo "=== $title ==="

  if [ "${#arr[@]}" -eq 0 ]; then
    echo "(none found)"
    return 1
  fi

  for i in "${!arr[@]}"; do
    printf "%2d) %s\n" "$((i+1))" "${arr[$i]}"
  done
  echo " 0) Cancel"
  echo

  read -r -p "Select: " choice
  if [ -z "$choice" ] || ! echo "$choice" | grep -Eq '^[0-9]+$'; then
    echo "Invalid."
    return 1
  fi
  if [ "$choice" -eq 0 ]; then
    return 1
  fi
  if [ "$choice" -lt 1 ] || [ "$choice" -gt "${#arr[@]}" ]; then
    echo "Invalid."
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
    echo "DONE: committed + saved."
  else
    echo "Not committed."
  fi
  exit
}

# ---- SAFETY HELPERS (NEW) ----
is_number_in_list() {
  local needle="$1"; shift
  local x
  for x in "$@"; do
    [ "$x" = "$needle" ] && return 0
  done
  return 1
}

next_free_rule_number() {
  # Finds next free integer >= 10 using increments of 10 (10,20,30...)
  # usage: next_free_rule_number "${arr[@]}"
  local used=("$@")
  local n=10
  while is_number_in_list "$n" "${used[@]}"; do
    n=$((n+10))
  done
  echo "$n"
}

require_numeric() {
  # usage: require_numeric "$val" || continue/return
  local v="$1"
  echo "$v" | grep -Eq '^[0-9]+$'
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
fw_choose_ruleset_or_new() {
  local arr=()
  mapfile -t arr < <(scan_firewall_rulesets)

  echo
  echo "You must choose a firewall RULESET."
  echo "Ruleset examples: DMZ-to-LAN, WAN-to-DMZ, LAN-to-WAN"
  echo
  echo "Available rulesets detected:"
  if [ "${#arr[@]}" -gt 0 ]; then
    printf "  - %s\n" "${arr[@]}"
  else
    echo "  (none detected)"
  fi
  echo

  if [ "${#arr[@]}" -gt 0 ]; then
    if select_from_list "Select a ruleset to use" "${arr[@]}"; then
      echo "$SELECTED"
      return 0
    fi
  fi

  echo "No selection made. Type a ruleset name to create/use."
  local rs
  rs="$(ask "Ruleset name (example: DMZ-to-LAN)" "")"
  [ -z "$rs" ] && return 1
  echo "$rs"
}

fw_choose_rule_number_existing() {
  # Existing rule number selection ONLY (safe for update/delete)
  local rs="$1"
  local arr=()
  mapfile -t arr < <(scan_firewall_rule_numbers "$rs")

  echo
  echo "Choose an EXISTING rule number in ruleset: $rs"
  echo "Existing rule numbers detected:"
  if [ "${#arr[@]}" -gt 0 ]; then
    printf "  - %s\n" "${arr[@]}"
  else
    echo "  (none detected)"
  fi
  echo

  if [ "${#arr[@]}" -eq 0 ]; then
    echo "No rules exist in $rs."
    return 1
  fi

  if select_from_list "Select existing rule number" "${arr[@]}"; then
    echo "$SELECTED"
    return 0
  fi
  return 1
}

fw_choose_rule_number_new_only() {
  # NEW rule number selection ONLY (safe add)
  local rs="$1"
  local used=() suggested n
  mapfile -t used < <(scan_firewall_rule_numbers "$rs")

  echo
  echo "ADD MODE (SAFE): You must choose a NEW rule number for ruleset: $rs"
  echo "Existing rule numbers:"
  if [ "${#used[@]}" -gt 0 ]; then
    printf "  - %s\n" "${used[@]}"
  else
    echo "  (none)"
  fi
  echo

  suggested="$(next_free_rule_number "${used[@]}")"
  echo "Suggested next free rule number: $suggested"
  echo "Tip: use 10,20,30... to stay organized."
  echo

  while true; do
    n="$(ask "Rule number (new only)" "$suggested")"
    [ -z "$n" ] && echo "Rule number required." && continue
    if ! require_numeric "$n"; then
      echo "ERROR: rule number must be a number (example: 10)."
      continue
    fi
    if is_number_in_list "$n" "${used[@]}"; then
      echo "ERROR: rule $n already exists in $rs. Add mode will NOT overwrite."
      echo "Use Update ONE field / Delete to change existing rules."
      continue
    fi
    break
  done

  echo "$n"
}

fw_preview_rule() {
  local rs="$1" n="$2"
  echo
  echo "Current config lines for: firewall ipv4 name '$rs' rule $n"
  echo "--------------------------------------------------------"
  get_cfg_cmds | grep -F "set firewall ipv4 name '$rs' rule $n " || true
  get_cfg_cmds | grep -F "set firewall ipv4 name $rs rule $n " || true
  echo "--------------------------------------------------------"
  echo
}

fw_list_ruleset() {
  local arr=() rs

  echo
  echo "You selected: List ruleset"
  echo "Next, choose WHICH ruleset you want to view."
  echo

  mapfile -t arr < <(scan_firewall_rulesets)

  if [ "${#arr[@]}" -eq 0 ]; then
    echo "No firewall rulesets detected."
    pause
    return 0
  fi

  echo "Available rulesets:"
  printf "  - %s\n" "${arr[@]}"
  echo

  if ! select_from_list "Select WHICH ruleset to show" "${arr[@]}"; then
    return 0
  fi

  rs="$SELECTED"
  echo
  echo "Showing commands for ruleset: $rs"
  echo "--------------------------------------------------------"
  get_cfg_cmds | grep -F "set firewall ipv4 name '$rs' " || true
  get_cfg_cmds | grep -F "set firewall ipv4 name $rs " || true
  echo "--------------------------------------------------------"
  pause
}

# --- SAFE ADD (NEW ONLY) ---
fw_add_rule_guided_safe() {
  local rs n action proto desc saddr daddr sport dport state_est state_rel state_new

  echo
  echo "You selected: ADD rule (SAFE - will not overwrite)"
  echo "Ruleset -> NEW rule number -> prompts."
  echo "If you want to change an existing rule, use Update ONE field."
  echo

  rs="$(fw_choose_ruleset_or_new)" || return 0
  n="$(fw_choose_rule_number_new_only "$rs")" || return 0

  echo "Creating NEW rule: firewall ipv4 name '$rs' rule $n"
  echo "Leave optional fields blank to skip."
  echo
  echo "Examples you can type:"
  echo "  Protocol: tcp"
  echo "  Destination address: 172.16.200.10"
  echo "  Destination port: 1514-1515"
  echo

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

  echo
  echo "SUMMARY (Firewall rule $rs / $n):"
  echo "  action: $action"
  [ -n "$proto" ] && echo "  protocol: $proto"
  [ -n "$saddr" ] && echo "  source address: $saddr"
  [ -n "$sport" ] && echo "  source port: $sport"
  [ -n "$daddr" ] && echo "  destination address: $daddr"
  [ -n "$dport" ] && echo "  destination port: $dport"
  [ -n "$desc" ] && echo "  description: $desc"
  echo

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

  echo
  echo "You selected: Update ONE field"
  echo "Next, choose a ruleset, then choose an EXISTING rule number."
  echo

  rs="$(fw_choose_ruleset_or_new)" || return 0
  n="$(fw_choose_rule_number_existing "$rs")" || return 0

  fw_preview_rule "$rs" "$n"

  echo "Common field paths you can type:"
  echo "  action"
  echo "  description"
  echo "  protocol"
  echo "  destination address"
  echo "  destination port"
  echo "  source address"
  echo "  source port"
  echo "  state established"
  echo
  echo "Example:"
  echo "  Field path: destination port"
  echo "  New value: 1514-1515"
  echo

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

  echo
  echo "You selected: Delete rule"
  echo "Next, choose a ruleset, then choose an EXISTING rule number."
  echo

  rs="$(fw_choose_ruleset_or_new)" || return 0
  n="$(fw_choose_rule_number_existing "$rs")" || return 0

  fw_preview_rule "$rs" "$n"

  echo "You are deleting: firewall ipv4 name '$rs' rule $n"
  configure
  delete firewall ipv4 name "$rs" rule "$n"
  cfg_apply
}

firewall_menu() {
  while true; do
    echo
    echo "========================"
    echo " Firewall Menu (Dynamic)"
    echo "========================"
    show_detected_summary
    echo "SAFE RULES:"
    echo "  - ADD will NOT overwrite existing rule numbers."
    echo "  - To modify existing rules, use Update ONE field."
    echo
    echo "Examples:"
    echo "  Ruleset: DMZ-to-LAN"
    echo "  New rule #: (auto suggested)"
    echo "  Field path: destination port"
    echo "  Value: 1514-1515"
    echo
    echo "1) List ruleset (show commands)"
    echo "2) ADD rule (SAFE - new only)"
    echo "3) Update ONE field in an existing rule"
    echo "4) Delete existing rule"
    echo "5) Back"
    read -r -p "Select: " c
    case "$c" in
      1) fw_list_ruleset ;;
      2) fw_add_rule_guided_safe ;;
      3) fw_update_single_field ;;
      4) fw_delete_rule ;;
      5) return 0 ;;
      *) echo "Invalid." ;;
    esac
  done
}

# -----------------------------
# NAT CRUD
# -----------------------------
nat_list() {
  echo
  echo "You selected: List NAT"
  echo "Showing NAT commands (current config):"
  echo
  get_cfg_cmds | grep -F "set nat " || true
  pause
}

nat_choose_type() {
  echo
  echo "You must choose a NAT TYPE:"
  echo "  destination = DNAT / port forwarding"
  echo "  source      = SNAT / masquerade"
  echo
  local t
  t="$(ask "NAT type (destination/source)" "destination")"
  case "$t" in
    destination|source) echo "$t" ;;
    *) echo "" ;;
  esac
}

nat_choose_rule_number_or_new() {
  local type="$1"
  local arr=()

  if [ "$type" = "destination" ]; then
    mapfile -t arr < <(scan_nat_dest_rules)
  else
    mapfile -t arr < <(scan_nat_source_rules)
  fi

  echo
  echo "You must choose an EXISTING NAT RULE NUMBER (type: $type)"
  echo "Available rule numbers detected:"
  if [ "${#arr[@]}" -gt 0 ]; then
    printf "  - %s\n" "${arr[@]}"
  else
    echo "  (none detected)"
  fi
  echo

  if [ "${#arr[@]}" -eq 0 ]; then
    return 1
  fi

  if select_from_list "Select existing NAT rule number" "${arr[@]}"; then
    echo "$SELECTED"
    return 0
  fi
  return 1
}

nat_preview_rule() {
  local type="$1" n="$2"
  echo
  echo "Current config lines for: nat $type rule $n"
  echo "--------------------------------------------------------"
  get_cfg_cmds | grep -F "set nat $type rule $n " || true
  echo "--------------------------------------------------------"
  echo
}

# ---- SAFE ADD DNAT (NEW ONLY) ----
nat_add_dnat_guided() {
  local n desc inif proto dport taddr tport
  local used=() suggested

  echo
  echo "You selected: Add DNAT rule (guided)"
  echo "This creates a port forward (WAN -> inside host)."
  echo "IMPORTANT: Add mode will NOT overwrite an existing rule number."
  echo "If you need to change an existing rule, use Update ONE field or Delete."
  echo

  mapfile -t used < <(scan_nat_dest_rules)

  echo "Existing DNAT (destination) rule numbers:"
  if [ "${#used[@]}" -gt 0 ]; then
    printf "  - %s\n" "${used[@]}"
  else
    echo "  (none)"
  fi
  echo

  suggested="$(next_free_rule_number "${used[@]}")"
  echo "Suggested next free rule number: $suggested"
  echo

  while true; do
    n="$(ask "DNAT rule number (new only)" "$suggested")"
    [ -z "$n" ] && echo "Rule number required." && continue
    if ! require_numeric "$n"; then
      echo "ERROR: rule number must be a number (example: 10)."
      continue
    fi
    if is_number_in_list "$n" "${used[@]}"; then
      echo "ERROR: rule $n already exists. Add mode will NOT overwrite."
      echo "Use Update menu to change rule $n, or choose a new number."
      continue
    fi
    break
  done

  desc="$(ask "Description (example: HTTP -> DMZ)" "DNAT")"

  local ifs=()
  mapfile -t ifs < <(scan_eth_ifaces)

  echo
  echo "Inbound interface choices (usually WAN interface like eth0):"
  if [ "${#ifs[@]}" -gt 0 ]; then
    printf "  - %s\n" "${ifs[@]}"
  else
    echo "  (none detected)"
  fi
  echo

  if [ "${#ifs[@]}" -gt 0 ] && select_from_list "Select inbound interface" "${ifs[@]}"; then
    inif="$SELECTED"
  else
    inif="$(ask "Inbound interface name (example: eth0)" "eth0")"
  fi

  proto="$(ask "Protocol (tcp/udp)" "tcp")"
  dport="$(ask "Public port (example: 80)" "80")"
  taddr="$(ask "Inside IP (example: 172.16.50.3)" "172.16.50.3")"
  tport="$(ask "Inside port (example: 80)" "80")"

  echo
  echo "SUMMARY (DNAT rule $n):"
  echo "  inbound-interface: $inif"
  echo "  protocol: $proto"
  echo "  public port: $dport"
  echo "  translation: $taddr:$tport"
  echo

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
  echo
  echo "You selected: Update ONE field in a NAT rule"
  echo

  type="$(nat_choose_type)"
  [ -z "$type" ] && return 0
  n="$(nat_choose_rule_number_or_new "$type")" || return 0

  nat_preview_rule "$type" "$n"

  echo "Common field paths you can type:"
  echo "  description"
  echo "  destination port"
  echo "  inbound-interface name"
  echo "  outbound-interface name"
  echo "  source address"
  echo "  protocol"
  echo "  translation address"
  echo "  translation port"
  echo

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
  echo
  echo "You selected: Delete NAT rule"
  echo

  type="$(nat_choose_type)"
  [ -z "$type" ] && return 0
  n="$(nat_choose_rule_number_or_new "$type")" || return 0

  nat_preview_rule "$type" "$n"
  echo "You are deleting: nat $type rule $n"
  configure
  delete nat "$type" rule "$n"
  cfg_apply
}

nat_menu() {
  while true; do
    echo
    echo "=================="
    echo " NAT Menu (Dynamic)"
    echo "=================="
    show_detected_summary
    echo "SAFE RULES:"
    echo "  - ADD DNAT will NOT overwrite existing rule numbers."
    echo "  - Use Update/Delete to change existing rules."
    echo
    echo "1) List NAT (show commands)"
    echo "2) Add DNAT rule (SAFE - new only)"
    echo "3) Update ONE field in an existing NAT rule"
    echo "4) Delete existing NAT rule"
    echo "5) Back"
    read -r -p "Select: " c
    case "$c" in
      1) nat_list ;;
      2) nat_add_dnat_guided ;;
      3) nat_update_single_field ;;
      4) nat_delete_rule ;;
      5) return 0 ;;
      *) echo "Invalid." ;;
    esac
  done
}

# -----------------------------
# Interfaces
# -----------------------------
iface_set_ip() {
  local ifs=() iface ip desc
  mapfile -t ifs < <(scan_eth_ifaces)

  echo
  echo "You selected: Set interface IP"
  echo
  echo "Interfaces available:"
  if [ "${#ifs[@]}" -gt 0 ]; then
    printf "  - %s\n" "${ifs[@]}"
  else
    echo "  (none detected)"
  fi
  echo "Example: interface eth1, IP 172.16.50.2/29"
  echo

  if [ "${#ifs[@]}" -gt 0 ] && select_from_list "Select interface to configure" "${ifs[@]}"; then
    iface="$SELECTED"
  else
    iface="$(ask "Interface name (example: eth0)" "")"
    [ -z "$iface" ] && return 0
  fi

  ip="$(ask "New address (CIDR) (example: 172.16.50.2/29)" "")"
  [ -z "$ip" ] && return 0
  desc="$(ask "Description (optional) (example: Hamed-DMZ)" "")"

  configure
  set interfaces ethernet "$iface" address "$ip"
  [ -n "$desc" ] && set interfaces ethernet "$iface" description "$desc"
  cfg_apply
}

iface_show() {
  echo
  run show interfaces
  echo
  pause
}

iface_menu() {
  while true; do
    echo
    echo "========================"
    echo " Interfaces Menu (Dynamic)"
    echo "========================"
    show_detected_summary
    echo "Examples:"
    echo "  Interface: eth1"
    echo "  IP/CIDR: 172.16.50.2/29"
    echo "  Description: Hamed-DMZ"
    echo
    echo "1) Set interface IP + description"
    echo "2) Show interfaces"
    echo "3) Back"
    read -r -p "Select: " c
    case "$c" in
      1) iface_set_ip ;;
      2) iface_show ;;
      3) return 0 ;;
      *) echo "Invalid." ;;
    esac
  done
}

# -----------------------------
# Raw mode (edit ANY aspect)
# -----------------------------
raw_mode() {
  echo
  echo "RAW MODE WARNING:"
  echo "  Raw mode CAN overwrite or delete anything."
  echo "  Only use if you know exactly what you are doing."
  echo
  echo "Type ONE config command starting with: set ...  OR  delete ..."
  echo "Examples:"
  echo "  delete interfaces ethernet eth1 address 172.16.50.2/29"
  echo "  set firewall zone LAN from DMZ firewall name 'DMZ-to-LAN'"
  echo "Blank = cancel"
  echo
  local cmd
  read -r -p "> " cmd
  [ -z "$cmd" ] && return 0

  configure
  eval "$cmd"
  cfg_apply
}

# -----------------------------
# Main
# -----------------------------
main_menu() {
  while true; do
    echo
    echo "=================================="
    echo " VyOS Dynamic Menu (Scan + CRUD)"
    echo "=================================="
    show_detected_summary
    echo "1) Interfaces submenu"
    echo "2) Firewall submenu"
    echo "3) NAT submenu"
    echo "4) Raw mode (set/delete anything)"
    echo "5) Show full config (commands)"
    echo "6) Exit"
    echo
    read -r -p "Select: " c
    case "$c" in
      1) iface_menu ;;
      2) firewall_menu ;;
      3) nat_menu ;;
      4) raw_mode ;;
      5) echo; get_cfg_cmds; echo; pause ;;
      6) exit 0 ;;
      *) echo "Invalid." ;;
    esac
  done
}

main_menu
