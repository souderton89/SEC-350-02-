#!/usr/bin/env bash
set -euo pipefail

# --- Repo + key defaults ---
REPO_URL="https://github.com/souderton89/SEC-350-02-.git"
REPO_DIR_NAME="SEC-350-02-"                              # folder name on disk after clone
DEFAULT_KEY_REL_PATH="RW01-jumper/debian/hamed_bar.pub"  # path INSIDE repo to public key
SUDOERS_DROPIN_NAME="classes"                            # /etc/sudoers.d/classes

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: Run as root (use sudo)."
    exit 1
  fi
}

detect_os() {
  if [[ ! -f /etc/os-release ]]; then
    echo "ERROR: /etc/os-release not found; cannot detect OS."
    exit 1
  fi

  # shellcheck disable=SC1091
  source /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_LIKE="${ID_LIKE:-}"

  case "$OS_ID" in
    rocky|rhel|centos|almalinux|fedora) OS_FAMILY="rhel" ;;
    ubuntu|debian)                     OS_FAMILY="debian" ;;
    *)
      if [[ "$OS_LIKE" == *"rhel"* ]] || [[ "$OS_LIKE" == *"fedora"* ]]; then
        OS_FAMILY="rhel"
      elif [[ "$OS_LIKE" == *"debian"* ]]; then
        OS_FAMILY="debian"
      else
        OS_FAMILY="unknown"
      fi
      ;;
  esac
}

user_exists() { id "$1" &>/dev/null; }

valid_username() {
  local u="$1"
  [[ "$u" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

prompt_username() {
  local u
  read -r -p "Enter username to create: " u
  [[ -n "$u" ]] || { echo "Username cannot be blank."; return 1; }
  [[ "$u" != "root" ]] || { echo "Refusing to modify/create 'root'."; return 1; }
  valid_username "$u" || { echo "Invalid username. Use: lowercase letters/digits/_/- (start with letter or _). Max 32 chars."; return 1; }
  echo "$u"
}

add_to_group_if_needed() {
  local u="$1"
  local grp="$2"

  if id -nG "$u" | tr ' ' '\n' | grep -qx "$grp"; then
    echo "User '$u' is already in group '$grp'."
  else
    usermod -aG "$grp" "$u"
    echo "Added '$u' to group '$grp'."
  fi
}

remove_from_group_if_present() {
  local u="$1"
  local grp="$2"

  if id -nG "$u" | tr ' ' '\n' | grep -qx "$grp"; then
    if command -v gpasswd &>/dev/null; then
      gpasswd -d "$u" "$grp" >/dev/null 2>&1 || true
    elif command -v deluser &>/dev/null; then
      deluser "$u" "$grp" >/dev/null 2>&1 || true
    fi
    echo "Removed '$u' from group '$grp' (if supported)."
  fi
}

# --- Repo helpers ---
install_git() {
  if command -v git &>/dev/null; then
    echo "Git is already installed."
    return
  fi

  echo "Installing git..."
  if [[ "$OS_FAMILY" == "rhel" ]]; then
    if command -v dnf &>/dev/null; then dnf -y install git; else yum -y install git; fi
  elif [[ "$OS_FAMILY" == "debian" ]]; then
    apt-get update
    apt-get install -y git
  else
    echo "ERROR: Unsupported OS for installing git."
    return 1
  fi
  echo "Git installed."
}

clone_or_update_repo_for_user() {
  local u="$1"
  local home_dir="/home/$u"
  local repo_dir="$home_dir/$REPO_DIR_NAME"

  install_git

  if [[ ! -d "$home_dir" ]]; then
    echo "ERROR: Home directory not found: $home_dir"
    return 1
  fi

  if [[ -d "$repo_dir/.git" ]]; then
    echo "Repo already exists at $repo_dir — pulling latest..."
    sudo -u "$u" git -C "$repo_dir" pull --ff-only
  elif [[ -e "$repo_dir" ]]; then
    echo "ERROR: $repo_dir exists but is not a git repo. Rename/remove it and retry."
    return 1
  else
    echo "Cloning repo into $repo_dir ..."
    sudo -u "$u" git clone "$REPO_URL" "$repo_dir"
  fi

  chown -R "$u:$u" "$repo_dir"
  echo "Repo ready."
}

setup_authorized_keys_from_repo() {
  local u="$1"
  local home_dir="/home/$u"
  local repo_dir="$home_dir/$REPO_DIR_NAME"

  if [[ ! -d "$repo_dir" ]]; then
    echo "ERROR: Repo directory not found: $repo_dir"
    echo "Run the clone step first."
    return 1
  fi

  echo "This will copy a public key file from the repo into:"
  echo "  $home_dir/.ssh/authorized_keys"
  echo
  read -r -p "Enter key path INSIDE repo [default: $DEFAULT_KEY_REL_PATH]: " key_rel
  key_rel="${key_rel:-$DEFAULT_KEY_REL_PATH}"

  local key_src="$repo_dir/$key_rel"
  local ssh_dir="$home_dir/.ssh"
  local auth_keys="$ssh_dir/authorized_keys"

  if [[ ! -f "$key_src" ]]; then
    echo "ERROR: Key file not found: $key_src"
    echo
    echo "Here are some files inside the repo that look like keys (best guess):"
    find "$repo_dir" -maxdepth 6 -type f \( -name "*.pub" -o -iname "*key*" -o -iname "*id_rsa*" -o -iname "*ed25519*" \) 2>/dev/null | head -n 50 || true
    echo
    echo "Tip: re-run and paste one of those relative paths."
    return 1
  fi

  mkdir -p "$ssh_dir"
  cp -f "$key_src" "$auth_keys"

  chmod 700 "$ssh_dir"
  chmod 600 "$auth_keys"
  chown -R "$u:$u" "$ssh_dir"

  echo "authorized_keys configured for user '$u'."
  echo "Source: $key_src"
}

bootstrap_git_repo_and_ssh_key() {
  local u="$1"
  clone_or_update_repo_for_user "$u"
  setup_authorized_keys_from_repo "$u"
}

# --- Sudoers management (/etc/sudoers.d/classes) ---
sudoers_file_path() { echo "/etc/sudoers.d/${SUDOERS_DROPIN_NAME}"; }

ensure_passwordless_sudo() {
  local u="$1"
  local f
  f="$(sudoers_file_path)"
  local line="${u} ALL=(ALL) NOPASSWD: ALL"

  [[ -f "$f" ]] || touch "$f"
  chmod 0440 "$f"

  if grep -qFx "$line" "$f"; then
    echo "Passwordless sudo already set for '$u' in $f"
  else
    echo "$line" >> "$f"
    echo "Added passwordless sudo for '$u' in $f"
  fi

  if command -v visudo &>/dev/null; then
    if ! visudo -cf "$f" &>/dev/null; then
      echo "ERROR: visudo check failed for $f. Reverting last change."
      sed -i "\#^${u}[[:space:]]\+ALL=(ALL)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL\$#d" "$f"
      visudo -cf "$f" &>/dev/null || true
      return 1
    fi
  fi
}

remove_passwordless_sudo_if_present() {
  local u="$1"
  local f
  f="$(sudoers_file_path)"
  local pattern="^${u}[[:space:]]+ALL=\\(ALL\\)[[:space:]]+NOPASSWD:[[:space:]]+ALL$"

  if [[ -f "$f" ]]; then
    if grep -Eq "$pattern" "$f"; then
      sed -i -E "/$pattern/d" "$f"
      echo "Removed NOPASSWD sudo line for '$u' from $f"
      if command -v visudo &>/dev/null; then
        visudo -cf "$f" &>/dev/null || true
      fi
    fi
  fi
}

# --- KEY-ONLY creation (teacher intent) ---
create_user_key_only() {
  local u="$1"

  if user_exists "$u"; then
    echo "User '$u' already exists. Skipping creation."
  else
    useradd -m -s /bin/bash "$u"
    echo "Created user '$u' (useradd)."
  fi

  passwd -l "$u" &>/dev/null || true
  echo "Locked password for '$u' (RSA key-only login)."
}

# --- PASSWORD USER creation ---
create_user_with_password() {
  local u="$1"

  if user_exists "$u"; then
    echo "User '$u' already exists. Skipping creation."
  else
    if [[ "$OS_FAMILY" == "rhel" ]]; then
      useradd -m -s /bin/bash "$u"
      echo "Created user '$u' (useradd)."
      echo "Set password for '$u':"
      passwd "$u"
    elif [[ "$OS_FAMILY" == "debian" ]]; then
      adduser "$u"
      echo "Created user '$u' (adduser)."
    else
      echo "ERROR: Unsupported OS family."
      return 1
    fi
  fi
}

# 1) RSA key-only ADMIN user (sudoer + NOPASSWD)
add_rsa_admin_user() {
  local u
  u="$(prompt_username)" || return

  if [[ "$OS_FAMILY" == "debian" ]] && ! command -v sudo &>/dev/null; then
    echo "sudo not found. Installing..."
    apt-get update
    apt-get install -y sudo
  fi

  create_user_key_only "$u"

  if [[ "$OS_FAMILY" == "rhel" ]]; then
    add_to_group_if_needed "$u" "wheel"
  else
    add_to_group_if_needed "$u" "sudo"
  fi

  ensure_passwordless_sudo "$u"
  echo "Done. '$u' is RSA key-only AND is a sudo/admin user (NOPASSWD configured)."

  echo
  read -r -p "Also install git, clone repo, and set authorized_keys now? [y/N]: " yn
  if [[ "${yn,,}" == "y" ]]; then
    bootstrap_git_repo_and_ssh_key "$u"
  fi
}

# 2) RSA key-only NON-sudo user
add_rsa_user_no_sudo() {
  local u
  u="$(prompt_username)" || return

  create_user_key_only "$u"

  if [[ "$OS_FAMILY" == "rhel" ]]; then
    remove_from_group_if_present "$u" "wheel"
  else
    remove_from_group_if_present "$u" "sudo"
  fi
  remove_passwordless_sudo_if_present "$u"

  echo "Done. '$u' is RSA key-only and NOT a sudo/admin user."

  echo
  read -r -p "Also install git, clone repo, and set authorized_keys now? [y/N]: " yn
  if [[ "${yn,,}" == "y" ]]; then
    bootstrap_git_repo_and_ssh_key "$u"
  fi
}

# 3) PASSWORD REGULAR user (no sudo)
add_password_user_no_sudo() {
  local u
  u="$(prompt_username)" || return

  create_user_with_password "$u"

  if [[ "$OS_FAMILY" == "rhel" ]]; then
    remove_from_group_if_present "$u" "wheel"
  else
    remove_from_group_if_present "$u" "sudo"
  fi
  remove_passwordless_sudo_if_present "$u"

  echo "Done. '$u' is a regular user (password login) and NOT a sudo/admin user."
}

# 4) PASSWORD SUDOER user (sudoer, requires password)
add_password_admin_user() {
  local u
  u="$(prompt_username)" || return

  if [[ "$OS_FAMILY" == "debian" ]] && ! command -v sudo &>/dev/null; then
    echo "sudo not found. Installing..."
    apt-get update
    apt-get install -y sudo
  fi

  create_user_with_password "$u"

  if [[ "$OS_FAMILY" == "rhel" ]]; then
    add_to_group_if_needed "$u" "wheel"
  else
    add_to_group_if_needed "$u" "sudo"
  fi

  remove_passwordless_sudo_if_present "$u"
  echo "Done. '$u' is a sudo/admin user (password required for sudo)."
}

set_hostname() {
  local current
  current="$(hostnamectl --static 2>/dev/null || hostname)"
  echo "Current hostname: $current"

  read -r -p "Enter NEW hostname: " new_host
  [[ -n "$new_host" ]] || { echo "Hostname cannot be blank."; return; }

  if ! [[ "$new_host" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
    echo "ERROR: Invalid hostname. Use letters/numbers/hyphens (no spaces)."
    return
  fi

  hostnamectl set-hostname "$new_host"
  echo "Hostname set to: $new_host"

  if grep -qE '^127\.0\.1\.1[[:space:]]+' /etc/hosts; then
    sed -i -E "s/^127\.0\.1\.1[[:space:]].*/127.0.1.1\t${new_host}/" /etc/hosts
  else
    printf "\n127.0.1.1\t%s\n" "$new_host" >> /etc/hosts
  fi

  echo "Updated /etc/hosts."
}

disable_root_ssh() {
  local cfg="/etc/ssh/sshd_config"

  if [[ ! -f "$cfg" ]]; then
    echo "ERROR: $cfg not found."
    return
  fi

  if grep -qE '^[#[:space:]]*PermitRootLogin[[:space:]]+' "$cfg"; then
    sed -i -E 's/^[#[:space:]]*PermitRootLogin[[:space:]]+.*/PermitRootLogin no/' "$cfg"
  else
    printf "\nPermitRootLogin no\n" >> "$cfg"
  fi

  echo "Set: PermitRootLogin no"
  echo "Restarting SSH daemon..."

  if systemctl is-enabled --quiet sshd 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
    systemctl restart sshd
  elif systemctl is-enabled --quiet ssh 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl restart ssh
  elif systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -qx 'sshd.service'; then
    systemctl restart sshd
  elif systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -qx 'ssh.service'; then
    systemctl restart ssh
  else
    echo "WARNING: Could not find sshd/ssh systemd service. OpenSSH server may not be installed."
    return
  fi

  echo "SSH service restarted."
}

# -----------------------------
# NETWORK CONFIG (Netplan or NM)
# -----------------------------

default_iface() {
  ip -o link show 2>/dev/null | awk -F': ' '{print $2}' \
    | grep -Ev '^(lo|docker|br-|virbr|veth|tun|tap)' \
    | head -n 1
}

valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [[ "$o" -ge 0 && "$o" -le 255 ]] || return 1
  done
  return 0
}

valid_cidr() {
  local cidr="$1"
  [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]] || return 1
  local ip="${cidr%/*}"
  valid_ipv4 "$ip"
}

split_dns_to_yaml_list() {
  # input: "10.0.5.5,1.1.1.1" or "10.0.5.5 1.1.1.1"
  local raw="$1"
  raw="${raw//,/ }"
  raw="$(echo "$raw" | xargs)"
  local out=""
  local d
  for d in $raw; do
    if valid_ipv4 "$d"; then
      out+="${out:+, }$d"
    fi
  done
  echo "$out"
}

detect_network_tool() {
  # Prefer netplan if it's installed + /etc/netplan exists
  if command -v netplan &>/dev/null && [[ -d /etc/netplan ]] && ls /etc/netplan/*.yaml &>/dev/null; then
    echo "netplan"
    return
  fi

  # Prefer NetworkManager if it's active and nmcli exists
  if command -v nmcli &>/dev/null && systemctl is-active --quiet NetworkManager 2>/dev/null; then
    echo "nm"
    return
  fi

  # Fallback: if nmtui exists, usually NetworkManager is intended
  if command -v nmtui &>/dev/null; then
    echo "nm"
    return
  fi

  echo "unknown"
}

configure_netplan_static() {
  local iface="$1" ipcidr="$2" gw="$3" dns_raw="$4" search_domain="$5"
  local dns_list
  dns_list="$(split_dns_to_yaml_list "$dns_raw")"

  local out_file="/etc/netplan/99-static-${iface}.yaml"

  echo "Netplan detected."
  echo "Writing: $out_file"
  [[ -f "$out_file" ]] && cp -a "$out_file" "${out_file}.bak.$(date +%F-%H%M%S)"

  cat >"$out_file" <<EOF
network:
  version: 2
  ethernets:
    ${iface}:
      dhcp4: false
      addresses:
        - ${ipcidr}
      routes:
        - to: default
          via: ${gw}
      nameservers:
        addresses: [${dns_list}]
        search: [${search_domain}]
EOF

  chmod 600 "$out_file"

  echo "Running: netplan generate"
  netplan generate
  echo "Running: netplan apply"
  netplan apply

  echo "Netplan applied."
}

nm_find_conn_for_iface() {
  local iface="$1"
  local conn=""

  conn="$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: -v i="$iface" '$2==i{print $1; exit}')" || true
  if [[ -z "$conn" ]]; then
    conn="$(nmcli -t -f NAME,DEVICE con show 2>/dev/null | awk -F: -v i="$iface" '$2==i{print $1; exit}')" || true
  fi

  echo "$conn"
}

configure_nmcli_static() {
  local iface="$1" ipcidr="$2" gw="$3" dns_raw="$4" search_domain="$5"
  local dns_list
  dns_list="$(split_dns_to_yaml_list "$dns_raw")"
  dns_list="${dns_list//, /,}"   # nmcli likes commas with no spaces: 1.1.1.1,8.8.8.8

  echo "NetworkManager detected."

  if ! command -v nmcli &>/dev/null; then
    echo "ERROR: nmcli not found, but NetworkManager config requested."
    echo "Install NetworkManager tools or use netplan."
    return 1
  fi

  local conn
  conn="$(nm_find_conn_for_iface "$iface")"

  if [[ -z "$conn" ]]; then
    echo "No NM connection found for $iface. Creating one named '${iface}'..."
    nmcli con add type ethernet ifname "$iface" con-name "$iface" >/dev/null
    conn="$iface"
  fi

  echo "Using connection: $conn"

  nmcli con mod "$conn" ipv4.method manual
  nmcli con mod "$conn" ipv4.addresses "$ipcidr"
  nmcli con mod "$conn" ipv4.gateway "$gw"
  nmcli con mod "$conn" ipv4.dns "$dns_list"
  nmcli con mod "$conn" ipv4.dns-search "$search_domain"
  nmcli con mod "$conn" ipv6.method ignore

  echo "Bringing connection up..."
  nmcli con up "$conn"

  echo "NetworkManager config applied."
}

configure_network() {
  local tool
  tool="$(detect_network_tool)"

  if [[ "$tool" == "unknown" ]]; then
    echo "ERROR: Could not detect netplan or NetworkManager (nmtui/nmcli)."
    echo "Install netplan OR NetworkManager, then re-run."
    return 1
  fi

  local def_if
  def_if="$(default_iface)"
  read -r -p "Interface name [default: ${def_if:-NONE}]: " iface
  iface="${iface:-$def_if}"

  if [[ -z "${iface:-}" ]]; then
    echo "ERROR: Could not determine interface. Enter it manually (example: ens18)."
    return 1
  fi

  local ipcidr gw dns search
  read -r -p "Static IP/CIDR (example 10.0.5.93/24): " ipcidr
  valid_cidr "$ipcidr" || { echo "ERROR: Invalid IP/CIDR: $ipcidr"; return 1; }

  read -r -p "Gateway (example 10.0.5.2): " gw
  valid_ipv4 "$gw" || { echo "ERROR: Invalid gateway: $gw"; return 1; }

  read -r -p "DNS servers (comma or space separated, example 10.0.5.5,1.1.1.1): " dns
  [[ -n "${dns// }" ]] || { echo "ERROR: DNS cannot be blank."; return 1; }

  read -r -p "Search domain (example hamed.local): " search
  [[ -n "${search// }" ]] || { echo "ERROR: Search domain cannot be blank."; return 1; }

  echo
  echo "About to apply:"
  echo "  Tool:   $tool"
  echo "  Iface:  $iface"
  echo "  IP:     $ipcidr"
  echo "  GW:     $gw"
  echo "  DNS:    $dns"
  echo "  Search: $search"
  echo

  read -r -p "Continue? [y/N]: " yn
  if [[ "${yn,,}" != "y" ]]; then
    echo "Canceled."
    return
  fi

  if [[ "$tool" == "netplan" ]]; then
    configure_netplan_static "$iface" "$ipcidr" "$gw" "$dns" "$search"
  else
    configure_nmcli_static "$iface" "$ipcidr" "$gw" "$dns" "$search"
  fi
}

menu() {
  echo
  echo "=============================="
  echo " System Setup Menu"
  echo " OS Detected: $OS_ID ($OS_FAMILY)"
  echo "=============================="
  echo "1) Add RSA key-only ADMIN user (NOPASSWD sudo via /etc/sudoers.d/$SUDOERS_DROPIN_NAME)"
  echo "2) Add RSA key-only NON-SUDO user"
  echo "3) Add PASSWORD REGULAR user (no sudo)"
  echo "4) Add PASSWORD SUDOER user (sudo requires password)"
  echo "5) Set hostname"
  echo "6) Disable root SSH login"
  echo "7) Configure network (netplan OR nmtui/NetworkManager)"
  echo "8) Install git + clone repo + set authorized_keys (for an existing user)"
  echo "9) Exit"
  echo
  read -r -p "Choose an option [1-9]: " choice
  echo

  case "$choice" in
    1) add_rsa_admin_user ;;
    2) add_rsa_user_no_sudo ;;
    3) add_password_user_no_sudo ;;
    4) add_password_admin_user ;;
    5) set_hostname ;;
    6) disable_root_ssh ;;
    7) configure_network ;;
    8)
      read -r -p "Enter EXISTING username to configure repo+authorized_keys for: " u
      [[ -n "$u" ]] || { echo "Username cannot be blank."; return; }
      if ! user_exists "$u"; then
        echo "ERROR: User '$u' does not exist."
        return
      fi
      bootstrap_git_repo_and_ssh_key "$u"
      ;;
    9) echo "Exiting."; exit 0 ;;
    *) echo "Invalid choice." ;;
  esac
}

main() {
  require_root
  detect_os

  if [[ "$OS_FAMILY" == "unknown" ]]; then
    echo "ERROR: Unsupported OS (ID=$OS_ID, ID_LIKE=$OS_LIKE)."
    exit 1
  fi

  while true; do
    menu
  done
}

main "$@"
