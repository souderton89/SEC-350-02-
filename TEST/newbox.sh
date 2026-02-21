#!/usr/bin/env bash
set -euo pipefail

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

  # Normalize to two families we care about
  case "$OS_ID" in
    rocky|rhel|centos|almalinux|fedora)
      OS_FAMILY="rhel"
      ;;
    ubuntu|debian)
      OS_FAMILY="debian"
      ;;
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

user_exists() {
  local u="$1"
  id "$u" &>/dev/null
}

valid_username() {
  local u="$1"
  # Practical Linux username rules: start with letter/_ then letters/digits/_/-
  [[ "$u" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
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

add_admin_user_rhel() {
  read -r -p "Enter username to create: " u
  [[ -n "$u" ]] || { echo "Username cannot be blank."; return; }

  if [[ "$u" == "root" ]]; then
    echo "Refusing to modify/create 'root'."
    return
  fi

  if ! valid_username "$u"; then
    echo "Invalid username. Use: lowercase letters/digits/_/- (start with letter or _). Max 32 chars."
    return
  fi

  if user_exists "$u"; then
    echo "User '$u' already exists. Skipping creation."
  else
    useradd -m -s /bin/bash "$u"
    echo "Created user '$u' (useradd)."
  fi

  echo "Set password for '$u':"
  passwd "$u"

  add_to_group_if_needed "$u" "wheel"
  echo "Done. '$u' is now an admin user via 'wheel'."
}

add_admin_user_debian() {
  read -r -p "Enter username to create: " u
  [[ -n "$u" ]] || { echo "Username cannot be blank."; return; }

  if [[ "$u" == "root" ]]; then
    echo "Refusing to modify/create 'root'."
    return
  fi

  if ! valid_username "$u"; then
    echo "Invalid username. Use: lowercase letters/digits/_/- (start with letter or _). Max 32 chars."
    return
  fi

  # Ensure sudo exists on minimal installs
  if ! command -v sudo &>/dev/null; then
    echo "sudo not found. Installing..."
    apt-get update
    apt-get install -y sudo
  fi

  if user_exists "$u"; then
    echo "User '$u' already exists. Skipping creation."
  else
    # Interactive: asks password + user details
    adduser "$u"
    echo "Created user '$u' (adduser)."
  fi

  add_to_group_if_needed "$u" "sudo"
  echo "Done. '$u' is now an admin user via 'sudo'."
}

set_hostname() {
  local current
  current="$(hostnamectl --static 2>/dev/null || hostname)"
  echo "Current hostname: $current"

  read -r -p "Enter NEW hostname: " new_host
  [[ -n "$new_host" ]] || { echo "Hostname cannot be blank."; return; }

  # Basic validation: letters/numbers/hyphen, no spaces
  if ! [[ "$new_host" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
    echo "ERROR: Invalid hostname. Use letters/numbers/hyphens (no spaces)."
    return
  fi

  hostnamectl set-hostname "$new_host"
  echo "Hostname set to: $new_host"

  # Update hosts (helps Ubuntu; harmless on Rocky)
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

  # Set or add PermitRootLogin no
  if grep -qE '^[#[:space:]]*PermitRootLogin[[:space:]]+' "$cfg"; then
    sed -i -E 's/^[#[:space:]]*PermitRootLogin[[:space:]]+.*/PermitRootLogin no/' "$cfg"
  else
    printf "\nPermitRootLogin no\n" >> "$cfg"
  fi

  echo "Set: PermitRootLogin no"

  # Restart ssh service (name differs)
  if systemctl list-unit-files | grep -q '^sshd\.service'; then
    systemctl restart sshd
  else
    systemctl restart ssh
  fi

  echo "SSH service restarted."
}

menu() {
  echo
  echo "=============================="
  echo " System Setup Menu"
  echo " OS Detected: $OS_ID ($OS_FAMILY)"
  echo "=============================="
  echo "1) Add a sudo/admin user"
  echo "2) Set hostname"
  echo "3) Disable root SSH login"
  echo "4) Exit"
  echo
  read -r -p "Choose an option [1-4]: " choice
  echo

  case "$choice" in
    1)
      if [[ "$OS_FAMILY" == "rhel" ]]; then
        add_admin_user_rhel
      elif [[ "$OS_FAMILY" == "debian" ]]; then
        add_admin_user_debian
      else
        echo "ERROR: Unsupported OS for user creation (ID=$OS_ID)."
      fi
      ;;
    2)
      set_hostname
      ;;
    3)
      disable_root_ssh
      ;;
    4)
      echo "Exiting."
      exit 0
      ;;
    *)
      echo "Invalid choice."
      ;;
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
