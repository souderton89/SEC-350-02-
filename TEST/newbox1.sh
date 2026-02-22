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
      # Interactive: prompts for password + user info
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

  # Ensure they do NOT get NOPASSWD in /etc/sudoers.d/classes
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

  # More reliable service detection:
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
  echo "7) Install git + clone repo + set authorized_keys (for an existing user)"
  echo "8) Exit"
  echo
  read -r -p "Choose an option [1-8]: " choice
  echo

  case "$choice" in
    1) add_rsa_admin_user ;;
    2) add_rsa_user_no_sudo ;;
    3) add_password_user_no_sudo ;;
    4) add_password_admin_user ;;
    5) set_hostname ;;
    6) disable_root_ssh ;;
    7)
      read -r -p "Enter EXISTING username to configure repo+authorized_keys for: " u
      [[ -n "$u" ]] || { echo "Username cannot be blank."; return; }
      if ! user_exists "$u"; then
        echo "ERROR: User '$u' does not exist."
        return
      fi
      bootstrap_git_repo_and_ssh_key "$u"
      ;;
    8) echo "Exiting."; exit 0 ;;
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
