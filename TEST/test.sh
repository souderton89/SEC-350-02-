#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
CYN='\033[0;36m'
BLD='\033[1m'
RESET='\033[0m'

trap 'echo -e "${RED}ERROR: line $LINENO: $BASH_COMMAND${RESET}" >&2' ERR

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
  echo "ERROR: Bash 4.3 or newer is required (found ${BASH_VERSION})." >&2
  exit 1
fi

REPO_URL="https://github.com/souderton89/SEC-350-02-.git"
REPO_DIR_NAME="SEC-350-02-"
DEFAULT_KEY_REL_PATH="RW01-jumper/debian/hamed_bar.pub"
SUDOERS_DROPIN_NAME="classes"
CONFIG_FILE="/etc/system-setup.conf"

# Global arrays for DHCP subnet data — must be global so collect_subnet()
# (child function) can populate them and setup_dhcp_server() can read them.
# 'declare -a' inside a function creates local arrays — root cause of the
# INTERFACESv4='1' bug.
declare -a NET_IFACE=() NET_SUBNET=() NET_NETMASK=() NET_CIDR=()
declare -a NET_RANGE_START=() NET_RANGE_END=() NET_ROUTER=() NET_DNS=()
declare -a NET_DOMAIN=() NET_LEASE_DEF=() NET_LEASE_MAX=() NET_STATIC_HOSTS=()

info()    { echo -e "${CYN}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GRN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YEL}[WARN]${RESET}  $*" >&2; }
err()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
header()  { echo -e "\n${BLD}${CYN}══════════════════════════════${RESET}\n${BLD} $*${RESET}\n${BLD}${CYN}══════════════════════════════${RESET}"; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "Run as root (use sudo)."
    exit 1
  fi
}

detect_os() {
  if [[ ! -f /etc/os-release ]]; then
    err "/etc/os-release not found; cannot detect OS."
    exit 1
  fi
  source /etc/os-release || true
  OS_ID="${ID:-unknown}"
  OS_LIKE="${ID_LIKE:-}"
  OS_VERSION_ID="${VERSION_ID:-}"

  if [[ "$OS_ID" == "unknown" && -f /etc/os-release ]]; then
    OS_ID="$(   grep -E '^ID='        /etc/os-release | cut -d= -f2 | tr -d '"' )"
    OS_LIKE="$( grep -E '^ID_LIKE='   /etc/os-release | cut -d= -f2 | tr -d '"' )"
    OS_VERSION_ID="$(grep -E '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"' )"
    OS_ID="${OS_ID:-unknown}"
  fi

  case "$OS_ID" in
    rocky|rhel|centos|almalinux|fedora) OS_FAMILY="rhel"     ;;
    ubuntu|debian|kali|linuxmint)       OS_FAMILY="debian"   ;;
    vyos)                               OS_FAMILY="vyos"     ;;
    alpine)                             OS_FAMILY="alpine"   ;;
    opensuse*|sles)                     OS_FAMILY="opensuse" ;;
    arch|manjaro|endeavouros)           OS_FAMILY="arch"     ;;
    *)
      if   [[ "$OS_LIKE" == *rhel*   || "$OS_LIKE" == *fedora* ]]; then OS_FAMILY="rhel"
      elif [[ "$OS_LIKE" == *debian* || "$OS_LIKE" == *ubuntu* ]]; then OS_FAMILY="debian"
      elif [[ "$OS_LIKE" == *suse*   ]];                           then OS_FAMILY="opensuse"
      elif [[ "$OS_LIKE" == *arch*   ]];                           then OS_FAMILY="arch"
      else OS_FAMILY="unknown"
      fi
      ;;
  esac

  if [[ "$OS_FAMILY" == "debian" ]] && command -v vbash &>/dev/null 2>&1; then
    OS_FAMILY="vyos"
    OS_ID="vyos"
  fi
}

pkg_install() {
  local pkgs=("$@")
  case "$OS_FAMILY" in
    debian)   apt-get -qq update && apt-get install -y "${pkgs[@]}" ;;
    rhel)     if command -v dnf &>/dev/null; then dnf -y install "${pkgs[@]}"; else yum -y install "${pkgs[@]}"; fi ;;
    vyos)     apt-get -qq update && apt-get install -y "${pkgs[@]}" ;;
    alpine)   apk add --no-cache "${pkgs[@]}" ;;
    opensuse) zypper --non-interactive install "${pkgs[@]}" ;;
    arch)     pacman -Sy --noconfirm "${pkgs[@]}" ;;
    *)        err "Unsupported OS for package install."; return 1 ;;
  esac
}

load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE" || {
      warn "Could not source $CONFIG_FILE — ignoring saved config."
    }
  fi
}

save_config() {
  umask 077
  cat >"$CONFIG_FILE" <<EOF
REPO_URL="${REPO_URL}"
REPO_DIR_NAME="${REPO_DIR_NAME}"
DEFAULT_KEY_REL_PATH="${DEFAULT_KEY_REL_PATH}"
SUDOERS_DROPIN_NAME="${SUDOERS_DROPIN_NAME}"
EOF
  ok "Saved config → $CONFIG_FILE"
}

configure_repo_settings() {
  header "Repo + Key Settings"
  echo "  REPO_URL           : $REPO_URL"
  echo "  REPO_DIR_NAME      : $REPO_DIR_NAME"
  echo "  DEFAULT_KEY_REL_PATH: $DEFAULT_KEY_REL_PATH"
  echo "  SUDOERS_DROPIN_NAME: $SUDOERS_DROPIN_NAME"
  echo

  local v
  read -r -p "New REPO_URL           [Enter=keep]: " v; [[ -n "${v// }" ]] && REPO_URL="$v"
  read -r -p "New REPO_DIR_NAME      [Enter=keep]: " v; [[ -n "${v// }" ]] && REPO_DIR_NAME="$v"
  read -r -p "New DEFAULT_KEY_REL_PATH [Enter=keep]: " v; [[ -n "${v// }" ]] && DEFAULT_KEY_REL_PATH="$v"
  read -r -p "New SUDOERS_DROPIN_NAME  [Enter=keep]: " v; [[ -n "${v// }" ]] && SUDOERS_DROPIN_NAME="$v"

  save_config
}

user_exists() { id "$1" &>/dev/null; }

valid_username() {
  [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

prompt_username() {
  local u
  read -r -p "Enter username: " u
  u="${u// /}"
  [[ -n "$u" ]]     || { err "Username cannot be blank."; return 1; }
  [[ "$u" != root ]] || { err "Refusing to operate on 'root'."; return 1; }
  valid_username "$u" || { err "Invalid username '$u'. Must start with [a-z_], followed by [a-z0-9_-], max 32 chars total."; return 1; }
  echo "$u"
}

add_to_group_if_needed() {
  local u="$1" grp="$2"
  if id -nG "$u" | tr ' ' '\n' | grep -qx "$grp"; then
    info "User '$u' already in group '$grp'."
  else
    usermod -aG "$grp" "$u"
    ok "Added '$u' to group '$grp'."
  fi
}

remove_from_group_if_present() {
  local u="$1" grp="$2"
  if id -nG "$u" | tr ' ' '\n' | grep -qx "$grp"; then
    if command -v gpasswd &>/dev/null; then
      gpasswd -d "$u" "$grp" >/dev/null 2>&1 && ok "Removed '$u' from group '$grp'." || \
        warn "gpasswd failed to remove '$u' from group '$grp' — verify manually."
    elif command -v deluser &>/dev/null; then
      deluser "$u" "$grp" >/dev/null 2>&1 && ok "Removed '$u' from group '$grp'." || \
        warn "deluser failed to remove '$u' from group '$grp' — verify manually."
    else
      warn "Neither gpasswd nor deluser found. Could not remove '$u' from group '$grp'. Remove manually."
    fi
  fi
}

get_sudo_group() {
  case "$OS_FAMILY" in
    rhel|opensuse) echo "wheel" ;;
    alpine)        echo "wheel" ;;
    arch)          echo "wheel" ;;
    *)             echo "sudo"  ;;
  esac
}

sudoers_file() { echo "/etc/sudoers.d/${SUDOERS_DROPIN_NAME}"; }

ensure_sudo_installed() {
  command -v sudo &>/dev/null && return 0
  info "sudo not found — installing..."
  pkg_install sudo
}

ensure_passwordless_sudo() {
  local u="$1"
  local f; f="$(sudoers_file)"
  local line="${u} ALL=(ALL) NOPASSWD: ALL"

  [[ -f "$f" ]] || touch "$f"
  chmod 0440 "$f"

  if grep -qFx "$line" "$f"; then
    info "NOPASSWD sudo already set for '$u'."
    return 0
  fi

  echo "$line" >> "$f"

  if command -v visudo &>/dev/null; then
    if ! visudo -cf "$f" &>/dev/null; then
      err "visudo syntax check failed on $f — reverting."
      grep -vFx "$line" "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
      chmod 0440 "$f"
      return 1
    fi
  fi
  ok "NOPASSWD sudo configured for '$u' in $f"
}

remove_passwordless_sudo_if_present() {
  local u="$1"
  local f; f="$(sudoers_file)"
  [[ -f "$f" ]] || return 0

  local line="${u} ALL=(ALL) NOPASSWD: ALL"
  if grep -qFx "$line" "$f"; then
    grep -vFx "$line" "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
    chmod 0440 "$f"
    ok "Removed NOPASSWD sudo for '$u' from $f"
    if command -v visudo &>/dev/null; then visudo -cf "$f" &>/dev/null || true; fi
  fi
}

get_current_login_user() {
  local u="${SUDO_USER:-}"
  [[ -z "$u" ]] && u="$(logname 2>/dev/null || true)"
  echo "$u"
}

_getent_passwd() {
  if command -v getent &>/dev/null; then
    getent passwd "$@"
  else
    if [[ $# -eq 0 ]]; then
      cat /etc/passwd
    else
      grep -E "^${1}:" /etc/passwd || true
    fi
  fi
}

is_deletable_user() {
  local user="$1"
  local entry uid home
  entry="$(_getent_passwd "$user" 2>/dev/null || true)"
  [[ -n "$entry" ]] || return 1

  uid="$(echo "$entry" | cut -d: -f3)"
  home="$(echo "$entry" | cut -d: -f6)"

  [[ "$user" != root    ]] || return 1
  [[ "$user" != nobody  ]] || return 1
  [[ "$uid"  =~ ^[0-9]+$ ]] || return 1
  (( uid >= 1000 ))          || return 1
  [[ "$home" == /home/* || "$home" == /root ]] && [[ "$user" != root ]] || \
    [[ "$home" == /home/* ]] || return 1
  return 0
}

list_deletable_users() {
  _getent_passwd | awk -F: '{print $1}' | while read -r u; do
    is_deletable_user "$u" && echo "$u" || true
  done
}

delete_user_by_name() {
  local target="$1"
  [[ -n "${target// }" ]]  || { err "Blank username."; return 1; }
  [[ "$target" != root ]]  || { err "Will not delete root."; return 1; }
  user_exists "$target"    || { err "User '$target' not found."; return 1; }

  pkill -u "$target" 2>/dev/null || true
  remove_passwordless_sudo_if_present "$target"

  if [[ "$OS_FAMILY" == "debian" || "$OS_FAMILY" == "vyos" ]] && command -v deluser &>/dev/null; then
    deluser --remove-home "$target"
  elif [[ "$OS_FAMILY" == "alpine" ]]; then
    local user_home
    user_home="$(_getent_passwd "$target" | cut -d: -f6)"
    deluser "$target"
    if [[ "$user_home" == /home/* && -d "$user_home" ]]; then
      rm -rf "${user_home:?home dir is empty}"
    fi
  else
    userdel -r "$target"
  fi
  ok "Deleted user: $target"
}

delete_users_menu() {
  local current; current="$(get_current_login_user)"

  header "Delete Users  (current login: ${current:-<unknown>})"
  mapfile -t users < <(list_deletable_users)

  if [[ "${#users[@]}" -eq 0 ]]; then
    info "No deletable users found (UID≥1000, /home/*)."
    return 0
  fi

  local i
  for i in "${!users[@]}"; do
    printf "  %2d) %s\n" "$((i+1))" "${users[$i]}"
  done
  echo "   0) Cancel"

  local choice
  read -r -p $'\nEnter number: ' choice
  [[ "$choice" =~ ^[0-9]+$ ]]                          || { err "Invalid input."; return 1; }
  [[ "$choice" -eq 0 ]]                                && { info "Canceled."; return 0; }
  (( choice >= 1 && choice <= ${#users[@]} ))          || { err "Out of range."; return 1; }

  local target="${users[$((choice-1))]}"
  [[ -z "${current:-}" || "$target" != "$current" ]]  || { err "Cannot delete the current session user: $current"; return 1; }

  echo
  echo "  Selected: ${BLD}$target${RESET}"
  read -r -p "  Type DELETE to confirm: " confirm
  [[ "$confirm" == DELETE ]] || { info "Canceled."; return 0; }

  delete_user_by_name "$target"
}

create_user_key_only() {
  local u="$1"
  if user_exists "$u"; then
    info "User '$u' already exists — skipping creation."
  else
    case "$OS_FAMILY" in
      alpine) adduser -D -s /bin/sh "$u" ;;
      *)      useradd -m -s /bin/bash "$u" ;;
    esac
    ok "Created user '$u'."
  fi
  if passwd -l "$u" &>/dev/null 2>&1; then
    true
  elif command -v usermod &>/dev/null; then
    usermod -L "$u" &>/dev/null || true
  fi
  info "Password locked for '$u' (RSA key-only login)."
}

create_user_with_password() {
  local u="$1"
  if user_exists "$u"; then
    info "User '$u' already exists — skipping creation."
    return 0
  fi

  case "$OS_FAMILY" in
    debian|vyos)
      adduser "$u"
      ;;
    alpine)
      adduser -D -s /bin/sh "$u"
      echo "Set password for '$u':"
      passwd "$u"
      ;;
    rhel|opensuse|arch)
      useradd -m -s /bin/bash "$u"
      ok "Created user '$u'."
      echo "Set password for '$u':"
      passwd "$u"
      ;;
    *)
      err "Unsupported OS family for user creation."
      return 1
      ;;
  esac
  ok "User '$u' created."
}

add_rsa_admin_user() {
  local u; u="$(prompt_username)" || return
  ensure_sudo_installed
  create_user_key_only "$u"
  add_to_group_if_needed "$u" "$(get_sudo_group)"
  ensure_passwordless_sudo "$u"
  ok "'$u' → RSA-only, NOPASSWD sudo admin."
  _offer_git_bootstrap "$u"
}

add_rsa_user_no_sudo() {
  local u; u="$(prompt_username)" || return
  create_user_key_only "$u"
  remove_from_group_if_present "$u" "$(get_sudo_group)"
  remove_passwordless_sudo_if_present "$u"
  ok "'$u' → RSA-only, no sudo."
  _offer_git_bootstrap "$u"
}

add_password_user_no_sudo() {
  local u; u="$(prompt_username)" || return
  create_user_with_password "$u"
  remove_from_group_if_present "$u" "$(get_sudo_group)"
  remove_passwordless_sudo_if_present "$u"
  ok "'$u' → password login, no sudo."
}

add_password_admin_user() {
  local u; u="$(prompt_username)" || return
  ensure_sudo_installed
  create_user_with_password "$u"
  add_to_group_if_needed "$u" "$(get_sudo_group)"
  remove_passwordless_sudo_if_present "$u"
  ok "'$u' → password sudo (password required)."
}

_offer_git_bootstrap() {
  local u="$1"
  echo
  read -r -p "Also clone repo + set authorized_keys for '$u'? [y/N]: " yn
  [[ "${yn,,}" == y ]] && bootstrap_git_repo_and_ssh_key "$u"
}

generate_ssh_key() {
  local u="$1"
  local home_dir="/home/$u"
  local ssh_dir="$home_dir/.ssh"

  [[ -d "$home_dir" ]] || { err "Home dir not found: $home_dir"; return 1; }

  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"

  local keyfile="$ssh_dir/id_rsa"
  local key_type="rsa"
  local bits="4096"
  local comment; comment="${u}@$(get_machine_hostname)"

  echo
  echo "  Key types: rsa (4096-bit) | ed25519"
  read -r -p "  Key type [rsa]: " kt
  case "${kt,,}" in
    ed25519)
      key_type="ed25519"
      keyfile="$ssh_dir/id_ed25519"
      ;;
    rsa|"")
      key_type="rsa"
      ;;
    *)
      warn "Unknown type '$kt', defaulting to rsa."
      ;;
  esac

  read -r -p "  Key filename [$keyfile]: " kf
  [[ -n "${kf// }" ]] && keyfile="$kf"

  if [[ -f "$keyfile" ]]; then
    read -r -p "  Key $keyfile already exists. Overwrite? [y/N]: " ow
    [[ "${ow,,}" == y ]] || { info "Skipped key generation."; return 0; }
  fi

  if [[ "$key_type" == "ed25519" ]]; then
    sudo -H -u "$u" ssh-keygen -t ed25519 -C "$comment" -f "$keyfile" -N ""
  else
    sudo -H -u "$u" ssh-keygen -t rsa -b "$bits" -C "$comment" -f "$keyfile" -N ""
  fi

  chown -R "$u:$u" "$ssh_dir"
  chmod 600 "$keyfile"
  chmod 644 "${keyfile}.pub" 2>/dev/null || true

  ok "SSH key generated: $keyfile"
  echo
  info "Public key:"
  cat "${keyfile}.pub"
}

generate_ssh_key_menu() {
  local u
  read -r -p "Enter username to generate SSH key for: " u
  [[ -n "$u" ]] || { err "Username cannot be blank."; return 1; }
  user_exists "$u" || { err "User '$u' does not exist."; return 1; }
  generate_ssh_key "$u"
}

install_git() {
  command -v git &>/dev/null && { info "Git already installed."; return 0; }
  info "Installing git..."
  pkg_install git
  ok "Git installed."
}

get_machine_hostname() {
  local h
  if command -v hostnamectl &>/dev/null; then
    h="$(hostnamectl --static 2>/dev/null | tr -d '[:space:]')"
    [[ -n "$h" ]] && { echo "$h"; return; }
  fi
  if [[ -r /etc/hostname ]]; then
    h="$(tr -d '[:space:]' < /etc/hostname)"
    [[ -n "$h" ]] && { echo "$h"; return; }
  fi
  hostname 2>/dev/null | tr -d '[:space:]' || echo "localhost"
}
get_short_hostname()   { local h; h="$(get_machine_hostname)"; echo "${h%%-*}"; }

repo_host_from_url() {
  local url="$1" host
  host="$(echo "$url" | sed -E 's#^https?://([^/]+)/.*$#\1#')"
  [[ -n "${host:-}" && "$host" != "$url" ]] && echo "$host" || echo "github.com"
}

prompt_github_creds_and_store() {
  local u="$1"
  header "GitHub Credential Setup"
  warn "Credentials will be stored in plaintext at /home/$u/.git-credentials"
  warn "Use a fine-grained token with minimal permissions."
  echo

  local gh_user token
  read -r -p "GitHub username: " gh_user
  [[ -n "${gh_user// }" ]] || { err "GitHub username cannot be blank."; return 1; }

  read -rsp "GitHub token (hidden): " token; echo
  [[ -n "${token// }" ]] || { err "Token cannot be blank."; return 1; }

  sudo -H -u "$u" git config --global credential.helper store

  local host; host="$(repo_host_from_url "$REPO_URL")"
  printf "protocol=https\nhost=%s\nusername=%s\npassword=%s\n\n" \
    "$host" "$gh_user" "$token" \
    | sudo -H -u "$u" git credential approve

  local creds_file="/home/$u/.git-credentials"
  if [[ -f "$creds_file" ]]; then
    chmod 600 "$creds_file"
    ok "Permissions set to 600 on $creds_file"
  fi

  ok "Credentials stored for '$u' (helper=store)."
}

ensure_git_identity() {
  local u="$1"
  local name email

  name="$(sudo -H -u "$u" git config --global --get user.name  2>/dev/null || true)"
  email="$(sudo -H -u "$u" git config --global --get user.email 2>/dev/null || true)"

  [[ -n "${name// }" && -n "${email// }" ]] && return 0

  info "Git identity not fully configured for '$u'."

  if [[ -z "${name// }" ]]; then
    read -r -p "git user.name  (e.g. Hamed): " name
    [[ -n "${name// }" ]] || { err "user.name cannot be blank."; return 1; }
    sudo -H -u "$u" git config --global user.name "$name"
  fi

  if [[ -z "${email// }" ]]; then
    read -r -p "git user.email (e.g. you@example.com): " email
    [[ -n "${email// }" ]] || { err "user.email cannot be blank."; return 1; }
    sudo -H -u "$u" git config --global user.email "$email"
  fi

  ok "Git identity set: name='$name'  email='$email'"
}

ensure_hostname_dir_in_repo() {
  local u="$1" repo_dir="$2"
  local short_host; short_host="$(get_short_hostname)"

  if [[ -z "${short_host// }" ]]; then
    warn "Could not determine short hostname; skipping host directory creation."
    return 1
  fi

  local host_dir="$repo_dir/$short_host"

  if [[ ! -d "$host_dir" ]]; then
    info "Creating host directory in repo: $host_dir"
    sudo -H -u "$u" mkdir -p "$host_dir"
    printf 'hi from %s\n' "$short_host" | sudo -H -u "$u" tee "$host_dir/README.md" >/dev/null
    return 0
  fi

  info "Host directory already exists: $host_dir"
  return 1
}

git_add_commit_and_push_prompted() {
  local u="$1" repo_dir="$2"

  info "Running: git add ."
  sudo -H -u "$u" git -C "$repo_dir" add .

  if sudo -H -u "$u" git -C "$repo_dir" diff --cached --quiet; then
    info "No staged changes to commit."
    return 0
  fi

  ensure_git_identity "$u"

  local msg
  read -r -p "Commit message: " msg
  msg="$(echo "$msg" | tr -dc '[:print:]')"
  [[ -n "${msg// }" ]] || { err "Commit message cannot be blank."; return 1; }

  sudo -H -u "$u" git -C "$repo_dir" commit -m "$msg"

  local branch
  branch="$(sudo -H -u "$u" git -C "$repo_dir" rev-parse --abbrev-ref HEAD)"
  info "Pushing to origin/$branch ..."
  sudo -H -u "$u" git -C "$repo_dir" push -u origin "$branch"

  ok "Commit + push complete."
}

clone_or_update_repo_for_user() {
  local u="$1"
  local home_dir="/home/$u"
  local repo_dir="$home_dir/$REPO_DIR_NAME"

  install_git

  [[ -d "$home_dir" ]] || { err "Home directory not found: $home_dir"; return 1; }

  if [[ -d "$repo_dir/.git" ]]; then
    info "Repo exists at $repo_dir — pulling latest..."
    sudo -H -u "$u" git -C "$repo_dir" pull --ff-only
  elif [[ -e "$repo_dir" ]]; then
    err "$repo_dir exists but is not a git repo. Rename/remove it and retry."
    return 1
  else
    info "Cloning $REPO_URL → $repo_dir ..."
    sudo -H -u "$u" git clone "$REPO_URL" "$repo_dir"
  fi

  chown -R "$u:$u" "$repo_dir"

  if ensure_hostname_dir_in_repo "$u" "$repo_dir"; then
    chown -R "$u:$u" "$repo_dir"
    prompt_github_creds_and_store "$u"
    git_add_commit_and_push_prompted "$u" "$repo_dir"
  else
    info "Hostname directory already present — no commit needed. Use menu option 8 to push manual changes."
  fi

  ok "Repo ready: $repo_dir"
}

setup_authorized_keys_from_repo() {
  local u="$1"
  local home_dir="/home/$u"
  local repo_dir="$home_dir/$REPO_DIR_NAME"

  [[ -d "$repo_dir" ]] || { err "Repo not found: $repo_dir  — run clone step first."; return 1; }

  echo
  read -r -p "Key path INSIDE repo [default: $DEFAULT_KEY_REL_PATH]: " key_rel
  key_rel="${key_rel:-$DEFAULT_KEY_REL_PATH}"

  local key_src="$repo_dir/$key_rel"
  local ssh_dir="$home_dir/.ssh"
  local auth_keys="$ssh_dir/authorized_keys"

  if [[ ! -f "$key_src" ]]; then
    err "Key file not found: $key_src"
    echo
    info "Repo files that look like public keys:"
    find "$repo_dir" -maxdepth 6 -type f \( -name "*.pub" -o -iname "*key*" -o -iname "*id_rsa*" -o -iname "*ed25519*" \) 2>/dev/null | head -50 || true
    return 1
  fi

  mkdir -p "$ssh_dir"

  if [[ -f "$auth_keys" ]]; then
    read -r -p "authorized_keys already exists. Append or overwrite? [a/o]: " amode
    case "${amode,,}" in
      o) cp -f "$key_src" "$auth_keys" ;;
      *) cat "$key_src" >> "$auth_keys" ;;
    esac
  else
    cp -f "$key_src" "$auth_keys"
  fi

  chmod 700 "$ssh_dir"
  chmod 600 "$auth_keys"
  chown -R "$u:$u" "$ssh_dir"
  ok "authorized_keys configured for '$u'."
}

bootstrap_git_repo_and_ssh_key() {
  local u="$1"
  clone_or_update_repo_for_user "$u"
  setup_authorized_keys_from_repo "$u"
}

set_hostname() {
  local current; current="$(get_machine_hostname)"
  info "Current hostname: $current"

  local new_host
  read -r -p "New hostname: " new_host
  [[ -n "$new_host" ]] || { err "Hostname cannot be blank."; return; }
  [[ "$new_host" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]] || {
    err "Invalid hostname. Use letters/digits/hyphens only."
    return
  }

  if [[ "$OS_FAMILY" == "vyos" ]]; then
    warn "VyOS: apply hostname via 'set system host-name $new_host' in configure mode."
    warn "Running hostnamectl as fallback (session only)..."
  fi

  hostnamectl set-hostname "$new_host" 2>/dev/null || hostname "$new_host"
  ok "Hostname set to: $new_host"

  for prefix in "127.0.1.1" "127.0.0.1"; do
    if grep -qE "^${prefix}[[:space:]]+${current}([[:space:]]|$)" /etc/hosts 2>/dev/null; then
      sed -i -E "s/^(${prefix}[[:space:]]+)${current}(.*)/\1${new_host}\2/" /etc/hosts
      ok "Updated /etc/hosts (${prefix} entry)."
    fi
  done
}

disable_root_ssh() {
  local cfg="/etc/ssh/sshd_config"
  [[ -f "$cfg" ]] || { err "$cfg not found."; return; }

  if [[ "$OS_FAMILY" == "vyos" ]]; then
    warn "VyOS: use 'set service ssh disable-host-validation' / 'delete service ssh allow-root'"
    warn "Patching sshd_config directly as fallback..."
  fi

  if grep -qE '^[#[:space:]]*PermitRootLogin[[:space:]]+' "$cfg"; then
    sed -i -E 's/^[#[:space:]]*PermitRootLogin[[:space:]]+.*/PermitRootLogin no/' "$cfg"
  else
    printf '\nPermitRootLogin no\n' >> "$cfg"
  fi
  ok "Set: PermitRootLogin no"

  local svc
  for svc in sshd ssh openssh; do
    if systemctl is-active --quiet "${svc}.service" 2>/dev/null || \
       systemctl is-enabled --quiet "${svc}.service" 2>/dev/null; then
      systemctl restart "${svc}.service"
      ok "Restarted: ${svc}.service"
      return
    fi
  done

  if command -v rc-service &>/dev/null; then
    rc-service sshd restart && ok "Restarted sshd (OpenRC)." && return
  fi

  warn "Could not find/restart SSH service automatically. Restart it manually."
}

default_iface() {
  ip -o link show 2>/dev/null \
    | awk -F': ' '{print $2}' \
    | grep -Ev '^(lo|docker|br-|virbr|veth|tun|tap|dummy)' \
    | head -1
}

valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS='.'; read -r o1 o2 o3 o4 <<<"$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    (( o >= 0 && o <= 255 )) || return 1
  done
}

valid_cidr() {
  local cidr="$1"
  [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]] || return 1
  valid_ipv4 "${cidr%/*}"
}

dns_to_list() {
  local raw="$1" sep="${2:-, }"
  local out=()
  read -r -a parts <<<"${raw//,/ }"
  for d in "${parts[@]}"; do
    valid_ipv4 "$d" && out+=("$d")
  done
  local IFS="$sep"; echo "${out[*]}"
}

detect_network_tool() {
  [[ "$OS_FAMILY" == "vyos" ]] && { echo "vyos"; return; }

  if command -v netplan &>/dev/null && [[ -d /etc/netplan ]]; then
    echo "netplan"; return
  fi

  if command -v nmcli &>/dev/null && \
     systemctl is-active --quiet NetworkManager 2>/dev/null; then
    echo "nm"; return
  fi

  if [[ "$OS_FAMILY" == "alpine" ]]; then
    echo "ifupdown"; return
  fi

  echo "unknown"
}

# ── LIST existing netplan files so user can pick one to edit ──────────────
list_netplan_files() {
  find /etc/netplan -maxdepth 1 \( -name "*.yaml" -o -name "*.yml" -o -name "*.disabled" \) 2>/dev/null | sort
}

# ── NEW: interactive netplan file editor / selector ───────────────────────
manage_netplan_files() {
  header "Manage Existing Netplan Files"

  local files=()
  mapfile -t files < <(list_netplan_files)

  if [[ "${#files[@]}" -eq 0 ]]; then
    info "No .yaml/.yml files found in /etc/netplan"
    return 0
  fi

  echo "  Existing netplan files:"
  echo
  local i
  for i in "${!files[@]}"; do
    local fstatus="active"
    [[ "${files[$i]}" == *.disabled ]] && fstatus="DISABLED"
    printf "  %2d) %-55s [%s]\n" "$((i+1))" "${files[$i]}" "$fstatus"
  done
  echo "   0) Back"
  echo

  local choice
  read -r -p "Select file to manage [0-${#files[@]}]: " choice
  [[ "$choice" =~ ^[0-9]+$ ]] || { err "Invalid input."; return 1; }
  [[ "$choice" -eq 0 ]]       && return 0
  (( choice >= 1 && choice <= ${#files[@]} )) || { err "Out of range."; return 1; }

  local selected="${files[$((choice-1))]}"
  echo
  echo "  Selected: ${BLD}$selected${RESET}"
  echo
  echo "  1) View contents"
  echo "  2) Edit IPs via wizard  (re-prompts interface/IP/GW/DNS)"
  echo "  3) Edit with nano       (raw YAML editor)"
  echo "  4) Disable              (rename to .disabled)"
  echo "  5) Enable               (remove .disabled suffix)"
  echo "  6) Delete"
  echo "  7) Back"
  echo

  local action
  read -r -p "Action [1-7]: " action
  case "$action" in
    1)
      echo
      cat "$selected"
      ;;

    2)
      # ── IP wizard: read existing values as defaults, re-prompt, rewrite ──
      header "Edit Netplan File via Wizard: $(basename "$selected")"

      # Parse existing values from YAML for smart defaults
      local cur_iface cur_ip cur_gw cur_dns cur_search
      cur_iface="$(grep -E '^\s+\w[^:]+:$' "$selected" 2>/dev/null \
        | grep -vE '^\s+(network|version|ethernets|nameservers|routes|addresses|dhcp4|dhcp6):$' \
        | awk '{gsub(/:$/,"",$1); print $1}' | head -1 || true)"
      cur_ip="$(grep -E '^\s+- [0-9]' "$selected" 2>/dev/null \
        | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -1 || true)"
      cur_gw="$(grep -E 'via:' "$selected" 2>/dev/null \
        | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
      cur_dns="$(grep -E 'addresses: \[' "$selected" 2>/dev/null \
        | grep -Eo '([0-9]+\.){3}[0-9]+' | tr '\n' ',' | sed 's/,$//' || true)"
      cur_search="$(grep 'search:' "$selected" 2>/dev/null \
        | grep -Eo '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' | head -1 || true)"

      # Show detected defaults
      echo "  Detected current settings:"
      echo "    Interface : ${cur_iface:-<not detected>}"
      echo "    IP/CIDR   : ${cur_ip:-<not detected>}"
      echo "    Gateway   : ${cur_gw:-<not detected>}"
      echo "    DNS       : ${cur_dns:-<not detected>}"
      echo "    Search    : ${cur_search:-<none>}"
      echo

      # Prompt — show detected value as default
      local new_iface new_ip new_gw new_dns new_search

      # Interface: numbered selection, with current as default hint
      local _picked_iface
      if prompt_select_iface _picked_iface "interface (currently: ${cur_iface:-unknown})"; then
        new_iface="$_picked_iface"
      else
        # fallback: keep detected value if picker fails (e.g. only 1 iface)
        new_iface="${cur_iface:-}"
      fi
      [[ -n "${new_iface// }" ]] || { err "Interface cannot be blank."; return 1; }
      info "Using interface: $new_iface"

      read -r -p "  IP/CIDR   [${cur_ip:-e.g. 192.168.1.10/24}]: " new_ip
      new_ip="${new_ip:-$cur_ip}"
      [[ -n "${new_ip// }" ]] || { err "IP/CIDR cannot be blank — could not detect from file."; return 1; }
      valid_cidr "$new_ip" || { err "Invalid IP/CIDR: $new_ip"; return 1; }

      read -r -p "  Gateway   [${cur_gw:-e.g. 192.168.1.1}]: " new_gw
      new_gw="${new_gw:-$cur_gw}"
      [[ -n "${new_gw// }" ]] || { err "Gateway cannot be blank — could not detect from file."; return 1; }
      valid_ipv4 "$new_gw" || { err "Invalid gateway: $new_gw"; return 1; }

      read -r -p "  DNS       [${cur_dns:-e.g. 8.8.8.8,8.8.4.4}]: " new_dns
      new_dns="${new_dns:-$cur_dns}"
      [[ -n "${new_dns// }" ]] || { err "DNS cannot be blank — could not detect from file."; return 1; }

      read -r -p "  Search domain [${cur_search:-Enter=skip}]: " new_search
      new_search="${new_search:-$cur_search}"
      new_search="$(echo "${new_search:-}" | tr -dc 'a-zA-Z0-9.-')"

      local new_dns_list; new_dns_list="$(dns_to_list "$new_dns" ", ")"

      echo
      echo "  ── New settings ────────────────────────"
      echo "  Interface : $new_iface"
      echo "  IP/CIDR   : $new_ip"
      echo "  Gateway   : $new_gw"
      echo "  DNS       : $new_dns_list"
      echo "  Search    : ${new_search:-<none>}"
      echo "  File      : $selected"
      echo "  ────────────────────────────────────────"
      echo

      read -r -p "  Write and apply? [y/N]: " yn
      [[ "${yn,,}" == y ]] || { info "Canceled."; return 0; }

      # Back up old file
      cp -a "$selected" "${selected}.bak.$(date +%F-%H%M%S)"

      # Rewrite the file
      {
        cat <<YAML
network:
  version: 2
  ethernets:
    ${new_iface}:
      dhcp4: false
      addresses:
        - ${new_ip}
      routes:
        - to: default
          via: ${new_gw}
      nameservers:
        addresses: [${new_dns_list}]
YAML
        [[ -n "${new_search// }" ]] && echo "        search: [${new_search}]"
      } > "$selected"

      chmod 600 "$selected"

      # Disable any OTHER files that reference this interface
      local ef
      while IFS= read -r ef; do
        [[ "$ef" == "$selected" ]] && continue
        if grep -q "$new_iface" "$ef" 2>/dev/null; then
          mv "$ef" "${ef}.disabled"
          warn "Disabled conflicting file: $(basename "$ef")"
        fi
      done < <(find /etc/netplan -maxdepth 1 \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null)

      netplan generate && netplan apply && ok "Netplan applied." \
        || err "netplan apply failed — check $selected"
      ;;

    3)
      if command -v nano &>/dev/null; then
        nano "$selected"
        read -r -p "Run 'netplan apply' now? [y/N]: " yn
        if [[ "${yn,,}" == y ]]; then
          if netplan generate && netplan apply; then
            ok "Netplan applied."
          else
            err "netplan apply failed — check $selected"
          fi
        fi
      else
        err "nano not found. Install it first via Package Management."
      fi
      ;;
    4)
      if [[ "$selected" == *.disabled ]]; then
        info "Already disabled."
      else
        mv "$selected" "${selected}.disabled"
        ok "Disabled: ${selected}.disabled"
        read -r -p "Run 'netplan apply' now? [y/N]: " yn
        if [[ "${yn,,}" == y ]]; then
          if netplan generate && netplan apply; then ok "Applied."; else err "netplan apply failed."; fi
        fi
      fi
      ;;
    5)
      if [[ "$selected" == *.disabled ]]; then
        local enabled="${selected%.disabled}"
        mv "$selected" "$enabled"
        ok "Enabled: $enabled"
        read -r -p "Run 'netplan apply' now? [y/N]: " yn
        if [[ "${yn,,}" == y ]]; then
          if netplan generate && netplan apply; then ok "Applied."; else err "netplan apply failed."; fi
        fi
      else
        info "File is already active (not .disabled)."
      fi
      ;;
    6)
      read -r -p "  Delete '$selected'? This cannot be undone. [y/N]: " yn
      if [[ "${yn,,}" == y ]]; then
        rm -f "$selected"
        ok "Deleted: $selected"
        read -r -p "Run 'netplan apply' now? [y/N]: " yn2
        if [[ "${yn2,,}" == y ]]; then
          if netplan generate && netplan apply; then ok "Applied."; else err "netplan apply failed."; fi
        fi
      else
        info "Canceled."
      fi
      ;;
    7) return 0 ;;
    *) warn "Invalid choice." ;;
  esac
}

configure_netplan_static() {
  local iface="$1" ipcidr="$2" gw="$3" dns_raw="$4" search="${5:-}"
  local dns_list; dns_list="$(dns_to_list "$dns_raw" ", ")"
  local out_file="/etc/netplan/99-static-${iface}.yaml"

  # ── Disable any OTHER netplan files that configure this interface
  #    to prevent "Conflicting default route declarations" errors
  local existing
  while IFS= read -r existing; do
    [[ "$existing" == "$out_file" ]] && continue
    if grep -q "$iface" "$existing" 2>/dev/null; then
      local disabled="${existing}.disabled"
      warn "Disabling conflicting netplan file: $(basename "$existing") → $(basename "$disabled")"
      mv "$existing" "$disabled"
    fi
  done < <(find /etc/netplan -maxdepth 1 \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null)

  info "Writing Netplan config: $out_file"
  [[ -f "$out_file" ]] && cp -a "$out_file" "${out_file}.bak.$(date +%F-%H%M%S)"

  {
    cat <<YAML
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
YAML
    [[ -n "${search// }" ]] && echo "        search: [${search}]"
  } > "$out_file"

  chmod 600 "$out_file"

  local disabled_count
  disabled_count=$(find /etc/netplan -maxdepth 1 -name "*.disabled" 2>/dev/null | wc -l)
  if (( disabled_count > 0 )); then
    warn "$disabled_count conflicting netplan file(s) renamed to .disabled"
    warn "To review/re-enable them use: Network → Manage existing netplan files"
  fi

  netplan generate
  netplan apply
  ok "Netplan applied."
}

nm_find_conn() {
  local iface="$1"
  nmcli -t -f NAME,DEVICE con show --active 2>/dev/null \
    | awk -F: -v i="$iface" '$2==i{print $1; exit}' || true
  nmcli -t -f NAME,DEVICE con show 2>/dev/null \
    | awk -F: -v i="$iface" '$2==i{print $1; exit}' || true
}

configure_nmcli_static() {
  local iface="$1" ipcidr="$2" gw="$3" dns_raw="$4" search="${5:-}"
  local dns_nm; dns_nm="$(dns_to_list "$dns_raw" " ")"

  command -v nmcli &>/dev/null || { err "nmcli not found."; return 1; }

  local conn; conn="$(nm_find_conn "$iface" | head -1)"
  if [[ -z "$conn" ]]; then
    info "No NM connection found for $iface — creating '${iface}'..."
    nmcli con add type ethernet ifname "$iface" con-name "$iface" >/dev/null
    conn="$iface"
  fi
  info "Using NM connection: $conn"

  nmcli con mod "$conn" ipv4.method    manual
  nmcli con mod "$conn" ipv4.addresses "$ipcidr"
  nmcli con mod "$conn" ipv4.gateway   "$gw"
  nmcli con mod "$conn" ipv4.dns       "$dns_nm"
  nmcli con mod "$conn" ipv4.dns-search "${search:-}"
  nmcli con mod "$conn" ipv6.method    ignore
  nmcli con up  "$conn"
  ok "NetworkManager config applied."
}

configure_vyos_static() {
  local iface="$1" ipcidr="$2" gw="$3" dns_raw="$4" search="${5:-}"
  read -r -a dns_arr <<<"${dns_raw//,/ }"

  warn "VyOS: this script generates the vbash commands — paste them in configure mode."
  echo
  echo "  ─── Copy/paste into 'configure' mode ───────────────────────────────"
  echo "  set interfaces ethernet $iface address '$ipcidr'"
  echo "  set protocols static route 0.0.0.0/0 next-hop '${gw}'"
  for d in "${dns_arr[@]}"; do
    valid_ipv4 "$d" && echo "  set system name-server '$d'"
  done
  [[ -n "${search// }" ]] && echo "  set system domain-name '$search'"
  echo "  commit"
  echo "  save"
  echo "  ──────────────────────────────────────────────────────────────────────"
  echo

  read -r -p "Attempt to run vbash automatically? [y/N]: " yn
  if [[ "${yn,,}" == y ]]; then
    if command -v vbash &>/dev/null; then
      vbash -c "
        source /opt/vyatta/etc/functions/script-template
        configure
        set interfaces ethernet $iface address '$ipcidr'
        set protocols static route 0.0.0.0/0 next-hop '${gw}'
        $(for d in "${dns_arr[@]}"; do valid_ipv4 "$d" && echo "set system name-server '$d'"; done)
        $( [[ -n "${search// }" ]] && echo "set system domain-name '$search'" )
        commit
        save
        exit
      " && ok "VyOS config applied." || warn "vbash run had errors — verify manually."
    else
      warn "vbash not found. Run the commands above manually."
    fi
  fi
}

configure_ifupdown_static() {
  local iface="$1" ipcidr="$2" gw="$3" dns_raw="$4" search="${5:-}"
  local ip="${ipcidr%/*}" prefix="${ipcidr#*/}"
  local cfg="/etc/network/interfaces"

  local netmask
  case "$prefix" in
    8)  netmask="255.0.0.0"     ;;
    16) netmask="255.255.0.0"   ;;
    24) netmask="255.255.255.0" ;;
    32) netmask="255.255.255.255" ;;
    *)  warn "Complex prefix /$prefix — you may need to set netmask manually."; netmask="255.255.255.0" ;;
  esac

  [[ -f "$cfg" ]] && cp "$cfg" "${cfg}.bak.$(date +%F-%H%M%S)"

  sed -i "/^auto ${iface}/,/^$/d" "$cfg" 2>/dev/null || true

  cat >> "$cfg" <<EOF

auto ${iface}
iface ${iface} inet static
    address ${ip}
    netmask ${netmask}
    gateway ${gw}
    dns-nameservers ${dns_raw//,/ }
EOF
  [[ -n "${search// }" ]] && echo "    dns-search ${search}" >> "$cfg"

  if [[ "$OS_FAMILY" == "alpine" ]]; then
    {
      [[ -n "${search// }" ]] && echo "search ${search}"
      for d in ${dns_raw//,/ }; do valid_ipv4 "$d" && echo "nameserver $d"; done
    } > /etc/resolv.conf
    info "Updated /etc/resolv.conf (Alpine)."
  else
    info "Skipping /etc/resolv.conf update — managed by resolvconf/systemd-resolved on this OS."
  fi

  ifdown "$iface" 2>/dev/null || true
  ifup   "$iface"
  ok "ifupdown static config applied for $iface."
}

collect_network_inputs() {
  local iface
  prompt_select_iface iface "interface to configure" || return 1
  info "Using interface: $iface"

  local ipcidr gw dns search
  read -r -p "Static IP/CIDR (e.g. 10.0.5.93/24): " ipcidr
  valid_cidr "$ipcidr" || { err "Invalid IP/CIDR: $ipcidr"; return 1; }

  read -r -p "Gateway (e.g. 10.0.5.2): " gw
  valid_ipv4 "$gw" || { err "Invalid gateway: $gw"; return 1; }

  read -r -p "DNS (comma/space separated, e.g. 10.0.5.5,1.1.1.1): " dns
  [[ -n "${dns// }" ]] || { err "DNS cannot be blank."; return 1; }

  read -r -p "Search domain (optional) [Enter=skip]: " search
  search="$(echo "${search:-}" | tr -dc 'a-zA-Z0-9.-')"

  echo
  echo "  ── Summary ─────────────────────────"
  echo "  Interface : $iface"
  echo "  IP/CIDR   : $ipcidr"
  echo "  Gateway   : $gw"
  echo "  DNS       : $dns"
  echo "  Search    : ${search:-<none>}"
  echo "  ────────────────────────────────────"
  echo

  read -r -p "Apply? [y/N]: " yn
  [[ "${yn,,}" == y ]] || { info "Canceled."; return 1; }

  _NET_IFACE="$iface"; _NET_IPCIDR="$ipcidr"; _NET_GW="$gw"
  _NET_DNS="$dns"; _NET_SEARCH="$search"
}

configure_network() {
  local tool; tool="$(detect_network_tool)"

  if [[ "$tool" == "unknown" ]]; then
    err "Could not detect netplan, NetworkManager, or ifupdown."
    err "Install one of those and re-run."
    return 1
  fi
  info "Network tool detected: $tool"

  collect_network_inputs || return 1

  case "$tool" in
    netplan)   configure_netplan_static  "$_NET_IFACE" "$_NET_IPCIDR" "$_NET_GW" "$_NET_DNS" "$_NET_SEARCH" ;;
    nm)        configure_nmcli_static    "$_NET_IFACE" "$_NET_IPCIDR" "$_NET_GW" "$_NET_DNS" "$_NET_SEARCH" ;;
    vyos)      configure_vyos_static     "$_NET_IFACE" "$_NET_IPCIDR" "$_NET_GW" "$_NET_DNS" "$_NET_SEARCH" ;;
    ifupdown)  configure_ifupdown_static "$_NET_IFACE" "$_NET_IPCIDR" "$_NET_GW" "$_NET_DNS" "$_NET_SEARCH" ;;
  esac
}

# ── NEW: Network sub-menu (replaces direct configure_network call) ─────────
network_menu() {
  while true; do
    local tool; tool="$(detect_network_tool)"
    header "Network Configuration  |  Tool: $tool"
    echo "  1) Configure static IP         (wizard)"
    echo "  2) Manage existing netplan files (view / edit / disable / enable)"
    echo "  3) Back"
    echo

    read -r -p "Choose [1-3]: " sub; echo
    case "$sub" in
      1) configure_network ;;
      2)
        if [[ "$tool" == "netplan" ]]; then
          manage_netplan_files
        else
          warn "Netplan file management is only available when netplan is the active tool (detected: $tool)."
        fi
        ;;
      3) return 0 ;;
      *) warn "Invalid choice." ;;
    esac
  done
}

show_system_status() {
  header "System Status"
  echo "  OS          : $OS_ID $OS_VERSION_ID ($OS_FAMILY)"
  echo "  Hostname    : $(get_machine_hostname)"
  echo "  IP addrs    : $(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | tr '\n' ' ')"
  echo "  Default GW  : $(ip route show default 2>/dev/null | awk '/default/{print $3}' | head -1)"
  echo "  Network tool: $(detect_network_tool)"
  echo "  Root SSH    : $(grep -E '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'not set')"
  echo "  Sudoers file: $(sudoers_file) $([ -f "$(sudoers_file)" ] && echo '[exists]' || echo '[not found]')"
  echo
  echo "  ── Netplan files ─────────────────────────────────────────────────"
  local f
  while IFS= read -r f; do
    local tag="  "
    [[ "$f" == *.disabled ]] && tag="${YEL}DIS${RESET}"
    echo -e "    [${tag}] $f"
  done < <(find /etc/netplan -maxdepth 1 \( -name "*.yaml" -o -name "*.yml" -o -name "*.disabled" \) 2>/dev/null | sort)
  echo
  echo "  ── Regular users (UID≥1000) ──────────────────────"
  _getent_passwd | awk -F: '$3>=1000 && $1!="nobody" && $1!="nfsnobody" {printf "  %-20s UID=%-6s HOME=%s\n",$1,$3,$6}'
  echo
}

ADMIN_TOOLS_debian=(
  net-tools curl wget nano vim htop tree
  iotop iftop nmap tcpdump traceroute
  dnsutils whois lsof strace sysstat
  tmux screen unzip zip rsync jq
  ufw fail2ban git openssl ca-certificates
)

ADMIN_TOOLS_rhel=(
  net-tools curl wget nano vim htop tree
  iotop iftop nmap tcpdump traceroute
  bind-utils whois lsof strace sysstat
  tmux screen unzip zip rsync jq
  firewalld fail2ban git openssl ca-certificates
)

ADMIN_TOOLS_alpine=(
  net-tools curl wget nano vim htop tree
  iotop iftop nmap tcpdump traceroute
  bind-tools whois lsof strace sysstat
  tmux screen unzip zip rsync jq
  git openssl ca-certificates
)

ADMIN_TOOLS_opensuse=(
  net-tools curl wget nano vim htop tree
  iotop iftop nmap tcpdump traceroute
  bind-utils whois lsof strace sysstat
  tmux screen unzip zip rsync jq
  firewalld fail2ban git openssl ca-certificates
)

ADMIN_TOOLS_arch=(
  net-tools curl wget nano vim htop tree
  iotop iftop nmap tcpdump traceroute
  bind-utils whois lsof strace sysstat
  tmux screen unzip zip rsync jq
  ufw fail2ban git openssl ca-certificates
)

ADMIN_TOOLS_vyos=(
  net-tools curl wget nano vim htop
  tcpdump traceroute lsof tmux
  unzip zip rsync jq git openssl
)

install_admin_tools_bundle() {
  header "Install Admin Tool Bundle"

  local varname="ADMIN_TOOLS_${OS_FAMILY}"
  declare -p "$varname" &>/dev/null || varname="ADMIN_TOOLS_debian"
  local -n toolref="$varname"
  local tools=("${toolref[@]}")

  echo "  The following tools will be installed for OS family '${OS_FAMILY}':"
  echo
  local i=0
  for t in "${tools[@]}"; do
    printf "    %-25s" "$t"
    i=$(( i + 1 ))
    (( i % 3 == 0 )) && echo || true
  done
  (( i % 3 != 0 )) && echo || true
  echo

  read -r -p "  Proceed with installation? [y/N]: " yn
  [[ "${yn,,}" == y ]] || { info "Canceled."; return 0; }

  echo
  info "Updating package index first..."
  case "$OS_FAMILY" in
    debian|vyos) apt-get -qq update ;;
    rhel)        : ;;
    alpine)      apk update -q ;;
    opensuse)    zypper --non-interactive refresh ;;
    arch)        pacman -Sy --noconfirm >/dev/null 2>&1 || true ;;
  esac

  info "Installing tools..."
  echo
  local failed=() succeeded=()

  for pkg in "${tools[@]}"; do
    printf "    %-30s ... " "$pkg"
    if pkg_install "$pkg" >/dev/null 2>&1; then
      echo -e "${GRN}OK${RESET}"
      succeeded+=("$pkg")
    else
      echo -e "${YEL}SKIPPED / NOT FOUND${RESET}"
      failed+=("$pkg")
    fi
  done

  echo
  ok "Installed: ${#succeeded[@]} packages."
  if [[ "${#failed[@]}" -gt 0 ]]; then
    warn "Skipped (not available on this OS/repo): ${failed[*]}"
  fi
}

install_custom_package() {
  header "Install a Single Package"
  local pkg
  read -r -p "  Package name: " pkg
  pkg="$(echo "$pkg" | tr -dc 'a-zA-Z0-9._+-')"
  [[ -n "${pkg// }" ]] || { err "Package name cannot be blank."; return 1; }

  info "Installing '$pkg'..."
  if pkg_install "$pkg"; then
    ok "'$pkg' installed successfully."
  else
    err "Failed to install '$pkg'. Check the name and your repo config."
    return 1
  fi
}

install_multiple_custom_packages() {
  header "Install Multiple Packages"
  echo "  Enter package names separated by spaces or commas."
  echo

  local raw
  read -r -p "  Packages: " raw
  raw="$(echo "$raw" | tr ',' ' ' | tr -dc 'a-zA-Z0-9 ._+-')"
  [[ -n "${raw// }" ]] || { err "No packages entered."; return 1; }

  local pkgs
  read -r -a pkgs <<<"$raw"

  echo
  info "Will install: ${pkgs[*]}"
  read -r -p "  Confirm? [y/N]: " yn
  [[ "${yn,,}" == y ]] || { info "Canceled."; return 0; }
  echo

  local failed=() succeeded=()
  for pkg in "${pkgs[@]}"; do
    [[ -n "${pkg// }" ]] || continue
    printf "    %-30s ... " "$pkg"
    if pkg_install "$pkg" >/dev/null 2>&1; then
      echo -e "${GRN}OK${RESET}"
      succeeded+=("$pkg")
    else
      echo -e "${RED}FAILED${RESET}"
      failed+=("$pkg")
    fi
  done

  echo
  ok "Done.  Installed: ${#succeeded[@]}  Failed: ${#failed[@]}"
  [[ "${#failed[@]}" -gt 0 ]] && warn "Failed packages: ${failed[*]}"
}

remove_package() {
  header "Remove a Package"
  local pkg
  read -r -p "  Package name to remove: " pkg
  pkg="$(echo "$pkg" | tr -dc 'a-zA-Z0-9._+-')"
  [[ -n "${pkg// }" ]] || { err "Package name cannot be blank."; return 1; }

  read -r -p "  Remove '$pkg'? [y/N]: " yn
  [[ "${yn,,}" == y ]] || { info "Canceled."; return 0; }

  case "$OS_FAMILY" in
    debian|vyos) apt-get remove -y "$pkg" ;;
    rhel)  if command -v dnf &>/dev/null; then dnf remove -y "$pkg"; else yum remove -y "$pkg"; fi ;;
    alpine)   apk del "$pkg" ;;
    opensuse) zypper --non-interactive remove "$pkg" ;;
    arch)     pacman -R --noconfirm "$pkg" ;;
    *) err "Unsupported OS for package removal."; return 1 ;;
  esac && ok "'$pkg' removed." || err "Removal failed."
}

search_package() {
  header "Search for a Package"
  local query
  read -r -p "  Search term: " query
  query="$(echo "$query" | tr -dc 'a-zA-Z0-9._+-')"
  [[ -n "${query// }" ]] || { err "Search term cannot be blank."; return 1; }

  info "Searching for '$query'..."
  echo
  case "$OS_FAMILY" in
    debian|vyos) apt-cache search "$query" 2>/dev/null | sort | head -40 ;;
    rhel)  if command -v dnf &>/dev/null; then dnf search "$query" 2>/dev/null | head -40; else yum search "$query" 2>/dev/null | head -40; fi ;;
    alpine)   apk search "$query" 2>/dev/null | sort | head -40 ;;
    opensuse) zypper search "$query" 2>/dev/null | head -40 ;;
    arch)     pacman -Ss "$query" 2>/dev/null | head -40 ;;
    *) err "Unsupported OS for search."; return 1 ;;
  esac
}

list_installed_packages() {
  header "Installed Packages"
  local filter=""
  read -r -p "  Filter by name (Enter=show all): " filter
  filter="$(echo "$filter" | tr -dc 'a-zA-Z0-9._+-')"
  echo

  case "$OS_FAMILY" in
    debian|vyos)
      dpkg -l 2>/dev/null | grep '^ii' \
        | awk '{printf "  %-35s %s\n",$2,$3}' \
        | grep -i "${filter:-}" | head -80
      ;;
    rhel|opensuse)
      rpm -qa --qf "  %-45{NAME} %{VERSION}\n" 2>/dev/null \
        | grep -i "${filter:-}" | sort | head -80
      ;;
    alpine)
      apk list --installed 2>/dev/null | grep -i "${filter:-}" | head -80
      ;;
    arch)
      pacman -Q 2>/dev/null \
        | awk '{printf "  %-35s %s\n",$1,$2}' \
        | grep -i "${filter:-}" | head -80
      ;;
    *) err "Unsupported OS for package listing."; return 1 ;;
  esac
}

package_management_menu() {
  while true; do
    header "Package Management  |  OS: $OS_ID ($OS_FAMILY)"
    echo "  1) Install admin tool bundle"
    echo "  2) Install a single package"
    echo "  3) Install multiple packages"
    echo "  4) Remove a package"
    echo "  5) Search for a package"
    echo "  6) List installed packages"
    echo "  7) Back"
    echo

    read -r -p "Choose [1-7]: " sub; echo
    case "$sub" in
      1) install_admin_tools_bundle       ;;
      2) install_custom_package           ;;
      3) install_multiple_custom_packages ;;
      4) remove_package                   ;;
      5) search_package                   ;;
      6) list_installed_packages          ;;
      7) return 0                         ;;
      *) warn "Invalid choice."           ;;
    esac
  done
}

run_system_update() {
  header "Full System Update"
  read -r -p "  Proceed? [y/N]: " yn
  [[ "${yn,,}" == y ]] || { info "Canceled."; return 0; }
  echo

  case "$OS_FAMILY" in
    debian|vyos)
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
      apt-get autoremove -y
      apt-get autoclean -y
      ;;
    rhel)
      if command -v dnf &>/dev/null; then dnf update -y && dnf autoremove -y
      else yum update -y; fi
      ;;
    alpine)  apk update && apk upgrade ;;
    opensuse) zypper --non-interactive refresh && zypper --non-interactive update ;;
    arch)    pacman -Syu --noconfirm ;;
    *)       err "Unsupported OS family for system update."; return 1 ;;
  esac

  ok "System update complete."

  local needs_reboot=false
  [[ -f /var/run/reboot-required ]] && needs_reboot=true
  if command -v needs-restarting &>/dev/null; then
    needs-restarting -r &>/dev/null || needs_reboot=true
  fi

  if $needs_reboot; then
    warn "A reboot is required."
    read -r -p "  Reboot now? [y/N]: " rb
    [[ "${rb,,}" == y ]] && reboot
  fi
}

check_updates_only() {
  header "Check Available Updates (dry run)"
  case "$OS_FAMILY" in
    debian|vyos)
      apt-get update -qq
      apt list --upgradable 2>/dev/null | grep -v "Listing..." | head -60 || true
      ;;
    rhel)
      if command -v dnf &>/dev/null; then dnf check-update 2>/dev/null || true
      else yum check-update 2>/dev/null || true; fi
      ;;
    alpine)   apk update -q && apk version -l '<' 2>/dev/null | head -60 || true ;;
    opensuse) zypper --non-interactive refresh && zypper list-updates 2>/dev/null | head -60 || true ;;
    arch)
      pacman -Sy --noconfirm >/dev/null 2>&1
      local updates; updates="$(pacman -Qu 2>/dev/null | head -60 || true)"
      [[ -n "$updates" ]] && echo "$updates" || info "System is up to date."
      ;;
    *) err "Unsupported OS for update check."; return 1 ;;
  esac
}

update_menu() {
  while true; do
    header "System Update  |  OS: $OS_ID ($OS_FAMILY)"
    echo "  1) Full system update"
    echo "  2) Check available updates (dry run)"
    echo "  3) Back"
    echo

    read -r -p "Choose [1-3]: " sub; echo
    case "$sub" in
      1) run_system_update  ;;
      2) check_updates_only ;;
      3) return 0           ;;
      *) warn "Invalid choice." ;;
    esac
  done
}

dhcp_get() {
  local key="$1"
  case "${OS_FAMILY}:${key}" in
    debian:PKG|vyos:PKG)   echo "isc-dhcp-server" ;;
    rhel:PKG)               echo "dhcp-server" ;;
    alpine:PKG)             echo "dhcp" ;;
    opensuse:PKG)           echo "dhcp-server" ;;
    arch:PKG)               echo "dhcp" ;;
    debian:SVC|vyos:SVC)   echo "isc-dhcp-server" ;;
    rhel:SVC)               echo "dhcpd" ;;
    alpine:SVC)             echo "dhcpd" ;;
    opensuse:SVC)           echo "dhcpd" ;;
    arch:SVC)               echo "dhcpd4" ;;
    opensuse:CONF_FILE)     echo "/etc/dhcpd.conf" ;;
    arch:CONF_FILE)         echo "/etc/dhcpd.conf" ;;
    *:CONF_FILE)            echo "/etc/dhcp/dhcpd.conf" ;;
    opensuse:CONF_DIR)      echo "/etc" ;;
    arch:CONF_DIR)          echo "/etc" ;;
    *:CONF_DIR)             echo "/etc/dhcp" ;;
    debian:LEASES|vyos:LEASES)  echo "/var/lib/dhcp/dhcpd.leases" ;;
    rhel:LEASES)                echo "/var/lib/dhcpd/dhcpd.leases" ;;
    alpine:LEASES)              echo "/var/lib/dhcpd/dhcpd.leases" ;;
    opensuse:LEASES)            echo "/var/lib/dhcpd/dhcpd.leases" ;;
    arch:LEASES)                echo "/var/lib/dhcpd/dhcpd.leases" ;;
    *:LEASES)                   echo "/var/lib/dhcp/dhcpd.leases" ;;
    *) echo "" ;;
  esac
}

DHCP_IFACE_FILE_debian="/etc/default/isc-dhcp-server"

cidr_to_netmask() {
  local prefix="$1"
  local mask="" i
  for i in 1 2 3 4; do
    local bits=$(( prefix > 8 ? 8 : prefix ))
    prefix=$(( prefix - bits ))
    local octet=$(( 256 - (1 << (8 - bits)) ))
    mask+="${mask:+.}${octet}"
  done
  echo "$mask"
}

ip_network() {
  local ip="$1" prefix="$2"
  local IFS='.' a b c d
  read -r a b c d <<< "$ip"
  local mask; mask="$(cidr_to_netmask "$prefix")"
  local IFS='.' ma mb mc md
  read -r ma mb mc md <<< "$mask"
  printf "%d.%d.%d.%d" \
    $(( a & ma )) $(( b & mb )) $(( c & mc )) $(( d & md ))
}

suggest_range_start() {
  local network="$1" prefix="$2"
  local IFS='.' a b c d; read -r a b c d <<< "$network"
  if (( prefix <= 24 )); then printf "%d.%d.%d.50" "$a" "$b" "$c"
  else printf "%d.%d.%d.%d" "$a" "$b" "$c" $(( d + 10 )); fi
}

suggest_range_end() {
  local network="$1" prefix="$2"
  local IFS='.' a b c d; read -r a b c d <<< "$network"
  if (( prefix <= 24 )); then printf "%d.%d.%d.200" "$a" "$b" "$c"
  else
    local max=$(( (1 << (32 - prefix)) - 3 ))
    printf "%d.%d.%d.%d" "$a" "$b" "$c" $(( d + max ))
  fi
}

list_interfaces() {
  ip -o link show 2>/dev/null \
    | awk -F': ' '{print $2}' \
    | grep -Ev '^(lo|docker|br-|virbr|veth|tun|tap|dummy)' \
    | sed 's/@.*//'
}

# ── Shared helper: numbered interface picker ──────────────────────────────
# Usage: prompt_select_iface <varname> [label]
# Writes chosen interface name into <varname>. Returns 1 on failure/cancel.
prompt_select_iface() {
  local _psv="$1"
  local _label="${2:-interface}"
  local _ifaces=()
  mapfile -t _ifaces < <(list_interfaces)

  if [[ "${#_ifaces[@]}" -eq 0 ]]; then
    err "No network interfaces detected."
    return 1
  fi

  echo
  echo "  Available interfaces:"
  local _i
  for _i in "${!_ifaces[@]}"; do
    printf "    %d) %s\n" "$((_i+1))" "${_ifaces[$_i]}"
  done
  echo

  local _choice
  read -r -p "  Select ${_label} [1-${#_ifaces[@]}]: " _choice
  [[ "$_choice" =~ ^[0-9]+$ ]]                           || { err "Invalid input."; return 1; }
  (( _choice >= 1 && _choice <= ${#_ifaces[@]} ))        || { err "Out of range."; return 1; }

  printf -v "$_psv" '%s' "${_ifaces[$((_choice-1))]}"
}

collect_subnet() {
  local idx="$1"
  echo
  echo -e "${BLD}${CYN}  ── Subnet #$((idx+1)) ──────────────────────────────────────${RESET}"

  local iface
  prompt_select_iface iface "interface for this subnet" || return 1
  info "Using interface: $iface"
  NET_IFACE[$idx]="$iface"

  local srv_cidr
  read -r -p "  Server IP/CIDR on $iface [e.g. 172.16.150.2/24]: " srv_cidr
  valid_cidr "$srv_cidr" || { err "Invalid CIDR: $srv_cidr"; return 1; }
  local srv_ip="${srv_cidr%/*}"
  local prefix="${srv_cidr#*/}"
  local network; network="$(ip_network "$srv_ip" "$prefix")"
  local netmask; netmask="$(cidr_to_netmask "$prefix")"

  NET_SUBNET[$idx]="$network"
  NET_NETMASK[$idx]="$netmask"
  NET_CIDR[$idx]="$prefix"

  local def_start; def_start="$(suggest_range_start "$network" "$prefix")"
  local def_end;   def_end="$(suggest_range_end   "$network" "$prefix")"
  local rstart rend
  read -r -p "  Pool start [$def_start]: " rstart
  rstart="${rstart:-$def_start}"
  valid_ipv4 "$rstart" || { err "Invalid IP: $rstart"; return 1; }

  read -r -p "  Pool end   [$def_end]: " rend
  rend="${rend:-$def_end}"
  valid_ipv4 "$rend" || { err "Invalid IP: $rend"; return 1; }

  NET_RANGE_START[$idx]="$rstart"
  NET_RANGE_END[$idx]="$rend"

  local def_router="$srv_ip"
  local router
  read -r -p "  Router/gateway to advertise [$def_router]: " router
  router="${router:-$def_router}"
  valid_ipv4 "$router" || { err "Invalid IP: $router"; return 1; }
  NET_ROUTER[$idx]="$router"

  local dns
  read -r -p "  DNS servers (comma/space, e.g. 172.16.150.2,8.8.8.8): " dns
  [[ -n "${dns// }" ]] || { err "DNS cannot be blank."; return 1; }
  NET_DNS[$idx]="$dns"

  local domain
  read -r -p "  Domain name (e.g. lab.local) [Enter=skip]: " domain
  NET_DOMAIN[$idx]="${domain:-}"

  local dltime maxtime
  read -r -p "  Default lease time in seconds [600]: " dltime
  dltime="${dltime:-600}"
  [[ "$dltime" =~ ^[0-9]+$ ]] || dltime=600
  NET_LEASE_DEF[$idx]="$dltime"

  read -r -p "  Max lease time in seconds    [7200]: " maxtime
  maxtime="${maxtime:-7200}"
  [[ "$maxtime" =~ ^[0-9]+$ ]] || maxtime=7200
  NET_LEASE_MAX[$idx]="$maxtime"

  local reservations=()
  echo
  read -r -p "  Add static host reservations (fixed IP by MAC)? [y/N]: " yn
  if [[ "${yn,,}" == y ]]; then
    while true; do
      echo
      local hname hmac hip
      read -r -p "    Hostname (or blank to stop): " hname
      [[ -n "${hname// }" ]] || break
      read -r -p "    MAC address (e.g. 00:11:22:33:44:55): " hmac
      [[ "$hmac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] || {
        warn "Invalid MAC format — skipping this entry."; continue
      }
      read -r -p "    Fixed IP: " hip
      valid_ipv4 "$hip" || { warn "Invalid IP — skipping."; continue; }
      reservations+=("${hname}|${hmac}|${hip}")
      ok "  Reserved: $hname → $hip ($hmac)"
    done
  fi
  local IFS=';'
  NET_STATIC_HOSTS[$idx]="${reservations[*]:-}"
}

build_dhcpd_conf() {
  local num_nets="$1"

  cat <<GLOBAL
# dhcpd.conf — generated by system-setup.sh on $(date)
# DO NOT EDIT MANUALLY — re-run system-setup.sh to regenerate

authoritative;
log-facility local7;

GLOBAL

  local idx
  for (( idx=0; idx<num_nets; idx++ )); do
    local dns_fmt
    dns_fmt="$(echo "${NET_DNS[$idx]}" | tr ',' ' ' | xargs | tr ' ' ',')"

    cat <<SUBNET

# ── Subnet ${NET_SUBNET[$idx]}/${NET_NETMASK[$idx]} on ${NET_IFACE[$idx]} ──
subnet ${NET_SUBNET[$idx]} netmask ${NET_NETMASK[$idx]} {
  range ${NET_RANGE_START[$idx]} ${NET_RANGE_END[$idx]};
  option routers ${NET_ROUTER[$idx]};
  option domain-name-servers ${dns_fmt};
$(  [[ -n "${NET_DOMAIN[$idx]:-}" ]] && echo "  option domain-name \"${NET_DOMAIN[$idx]}\";")
  default-lease-time ${NET_LEASE_DEF[$idx]};
  max-lease-time ${NET_LEASE_MAX[$idx]};
}
SUBNET

    if [[ -n "${NET_STATIC_HOSTS[$idx]:-}" ]]; then
      local IFS=';'
      local entry
      for entry in ${NET_STATIC_HOSTS[$idx]}; do
        local hname hmac hip
        IFS='|' read -r hname hmac hip <<< "$entry"
        cat <<HOST

host ${hname} {
  hardware ethernet ${hmac};
  fixed-address ${hip};
}
HOST
      done
    fi
  done
}

build_vyos_dhcp_commands() {
  local num_nets="$1"
  local idx
  for (( idx=0; idx<num_nets; idx++ )); do
    local pool_name="POOL_${NET_SUBNET[$idx]//./_}"
    local dns_vyos; dns_vyos="$(echo "${NET_DNS[$idx]}" | tr ',' ' ')"
    local cidr="${NET_CIDR[$idx]}"

    echo "# ── Subnet $((idx+1)): ${NET_SUBNET[$idx]} on ${NET_IFACE[$idx]} ──"
    echo "set service dhcp-server shared-network-name '${pool_name}' subnet '${NET_SUBNET[$idx]}/${cidr}' default-router '${NET_ROUTER[$idx]}'"
    echo "set service dhcp-server shared-network-name '${pool_name}' subnet '${NET_SUBNET[$idx]}/${cidr}' range 0 start '${NET_RANGE_START[$idx]}'"
    echo "set service dhcp-server shared-network-name '${pool_name}' subnet '${NET_SUBNET[$idx]}/${cidr}' range 0 stop  '${NET_RANGE_END[$idx]}'"
    for dns in $dns_vyos; do
      valid_ipv4 "$dns" && echo "set service dhcp-server shared-network-name '${pool_name}' subnet '${NET_SUBNET[$idx]}/${cidr}' name-server '${dns}'"
    done
    [[ -n "${NET_DOMAIN[$idx]:-}" ]] && echo "set service dhcp-server shared-network-name '${pool_name}' subnet '${NET_SUBNET[$idx]}/${cidr}' domain-name '${NET_DOMAIN[$idx]}'"
    echo "set service dhcp-server shared-network-name '${pool_name}' subnet '${NET_SUBNET[$idx]}/${cidr}' lease '${NET_LEASE_MAX[$idx]}'"

    if [[ -n "${NET_STATIC_HOSTS[$idx]:-}" ]]; then
      local IFS=';' entry
      for entry in ${NET_STATIC_HOSTS[$idx]}; do
        local hname hmac hip
        IFS='|' read -r hname hmac hip <<< "$entry"
        echo "set service dhcp-server shared-network-name '${pool_name}' subnet '${NET_SUBNET[$idx]}/${cidr}' static-mapping '${hname}' ip-address '${hip}'"
        echo "set service dhcp-server shared-network-name '${pool_name}' subnet '${NET_SUBNET[$idx]}/${cidr}' static-mapping '${hname}' mac-address '${hmac}'"
      done
    fi
    echo
  done
  echo "commit"
  echo "save"
}

install_dhcp_server_pkg() {
  local pkg; pkg="$(dhcp_get PKG)"
  [[ -n "$pkg" ]] || pkg="isc-dhcp-server"

  if command -v dhcpd &>/dev/null; then
    ok "dhcpd already installed."
    return 0
  fi

  info "Installing DHCP server package: $pkg ..."
  pkg_install "$pkg" && ok "DHCP server package installed." || {
    err "Failed to install $pkg"
    return 1
  }
}

# ── DHCP firewall: open UDP 67 (server) and UDP 68 (client) ──────────────
# Checks for firewalld first, installs it if absent, then falls back to
# ufw, then iptables as a last resort.
open_dhcp_firewall() {
  header "Firewall — Opening DHCP Ports (UDP 67/68)"

  # ── 1. firewalld ──────────────────────────────────────────────────────
  if command -v firewall-cmd &>/dev/null; then
    info "firewalld detected — already installed."
  else
    info "firewalld not found — installing..."
    if pkg_install firewalld 2>/dev/null; then
      ok "firewalld installed."
      # Enable + start it
      if command -v systemctl &>/dev/null; then
        systemctl enable --now firewalld
        ok "firewalld enabled and started."
      fi
    else
      warn "Could not install firewalld — will try ufw/iptables fallback."
    fi
  fi

  if command -v firewall-cmd &>/dev/null; then
    # Make sure the service is running before we query it
    if ! firewall-cmd --state &>/dev/null 2>&1; then
      info "Starting firewalld..."
      systemctl start firewalld 2>/dev/null || rc-service firewalld start 2>/dev/null || true
    fi

    # Add the dhcp service (covers UDP 67) permanently
    if firewall-cmd --query-service=dhcp --permanent &>/dev/null 2>&1; then
      info "firewalld: dhcp service already open."
    else
      firewall-cmd --add-service=dhcp --permanent
      ok "firewalld: added dhcp service (UDP 67) permanently."
    fi

    # Also explicitly open UDP 68 (BOOTP client) in case the service def omits it
    if firewall-cmd --query-port=68/udp --permanent &>/dev/null 2>&1; then
      info "firewalld: UDP 68 already open."
    else
      firewall-cmd --add-port=68/udp --permanent
      ok "firewalld: opened UDP 68 permanently."
    fi

    firewall-cmd --reload
    ok "firewalld reloaded — DHCP ports open."
    return 0
  fi

  # ── 2. ufw fallback ───────────────────────────────────────────────────
  if command -v ufw &>/dev/null; then
    info "ufw detected — opening UDP 67/68..."
    ufw allow 67/udp comment "DHCP server"  2>/dev/null || true
    ufw allow 68/udp comment "DHCP client"  2>/dev/null || true
    ufw --force enable 2>/dev/null || true
    ok "ufw: UDP 67/68 allowed."
    return 0
  fi

  # ── 3. iptables last resort ───────────────────────────────────────────
  if command -v iptables &>/dev/null; then
    info "iptables detected — adding UDP 67/68 rules..."
    iptables -C INPUT -p udp --dport 67 -j ACCEPT &>/dev/null 2>&1 || \
      iptables -I INPUT -p udp --dport 67 -j ACCEPT
    iptables -C INPUT -p udp --dport 68 -j ACCEPT &>/dev/null 2>&1 || \
      iptables -I INPUT -p udp --dport 68 -j ACCEPT

    # Persist if possible
    if command -v iptables-save &>/dev/null; then
      if [[ -d /etc/iptables ]]; then
        iptables-save > /etc/iptables/rules.v4
        ok "iptables rules saved to /etc/iptables/rules.v4"
      elif [[ -d /etc/sysconfig ]]; then
        iptables-save > /etc/sysconfig/iptables
        ok "iptables rules saved to /etc/sysconfig/iptables"
      fi
    fi
    ok "iptables: UDP 67/68 allowed."
    return 0
  fi

  warn "No supported firewall tool found (firewalld/ufw/iptables)."
  warn "Manually open UDP 67 and UDP 68 on this host."
}

# ── FIXED: handle commented-out lines and missing file ────────────────────
apply_dhcp_interfaces_debian() {
  local iface_list="$1"
  local iface_file="${DHCP_IFACE_FILE_debian}"

  # Create the file from scratch if it doesn't exist
  if [[ ! -f "$iface_file" ]]; then
    warn "$iface_file not found — creating it."
    cat > "$iface_file" <<EOF
# Defaults for isc-dhcp-server (sourced by systemd unit)
INTERFACESv4="${iface_list}"
INTERFACESv6=""
EOF
    ok "Created $iface_file → INTERFACESv4=\"$iface_list\""
    return 0
  fi

  cp -a "$iface_file" "${iface_file}.bak.$(date +%F-%H%M%S)"

  if grep -qE '^[#[:space:]]*INTERFACESv4=' "$iface_file"; then
    # Replace even if it was commented out
    sed -i -E "s|^[#[:space:]]*INTERFACESv4=.*|INTERFACESv4=\"${iface_list}\"|" "$iface_file"
  elif grep -qE '^[#[:space:]]*INTERFACES=' "$iface_file"; then
    sed -i -E "s|^[#[:space:]]*INTERFACES=.*|INTERFACES=\"${iface_list}\"|" "$iface_file"
  else
    echo "INTERFACESv4=\"${iface_list}\"" >> "$iface_file"
  fi

  ok "Updated $iface_file → INTERFACESv4=\"$iface_list\""
}

enable_dhcp_service() {
  local svc; svc="$(dhcp_get SVC)"
  [[ -n "$svc" ]] || svc="isc-dhcp-server"

  local leases; leases="$(dhcp_get LEASES)"
  if [[ -n "$leases" && ! -f "$leases" ]]; then
    mkdir -p "$(dirname "$leases")"
    touch "$leases"
    info "Created leases file: $leases"
  fi

  if command -v rc-service &>/dev/null; then
    rc-service dhcpd start  2>/dev/null || rc-service "$svc" start
    rc-update add dhcpd     2>/dev/null || rc-update add "$svc"
    ok "DHCP service started + enabled (OpenRC)."
  else
    systemctl enable --now "$svc"
    ok "DHCP service started + enabled: $svc"
  fi
}

show_dhcp_leases() {
  header "Current DHCP Leases"
  local leases; leases="$(dhcp_get LEASES)"

  if [[ -z "$leases" || ! -f "$leases" ]]; then
    for f in /var/lib/dhcpd/dhcpd.leases \
              /var/lib/dhcp/dhcpd.leases \
              /var/db/dhcpd.leases; do
      [[ -f "$f" ]] && { leases="$f"; break; }
    done
  fi

  if [[ -z "${leases:-}" || ! -f "$leases" ]]; then
    warn "Leases file not found."
    return 0
  fi

  info "Leases file: $leases"
  echo

  echo -e "  ${BLD}IP Address        MAC Address        Hostname          Expires${RESET}"
  echo    "  ─────────────────────────────────────────────────────────────────"

  awk '
    /^lease /         { ip=$2 }
    /hardware ethernet/ { mac=$3; gsub(/;/,"",mac) }
    /client-hostname/  { name=$2; gsub(/[";]/,"",name) }
    /ends /           { ends=$3" "$4; gsub(/;/,"",ends) }
    /^\}/             {
      if (ip != "") {
        printf "  %-17s %-18s %-17s %s\n", ip, mac, name, ends
        ip=mac=name=ends=""
      }
    }
  ' "$leases"
  echo
}

show_dhcp_status() {
  header "DHCP Server Status"
  local svc; svc="$(dhcp_get SVC)"
  local conf; conf="$(dhcp_get CONF_FILE)"

  echo "  Config file : ${conf:-n/a}"
  echo "  Service     : ${svc:-n/a}"
  echo

  if command -v systemctl &>/dev/null; then
    systemctl status "${svc:-dhcpd}" --no-pager -l 2>/dev/null | head -20 || \
      warn "Service ${svc} not found or not started."
  elif command -v rc-service &>/dev/null; then
    rc-service dhcpd status 2>/dev/null || warn "dhcpd not running."
  fi

  echo
  if [[ -n "${conf:-}" && -f "${conf}" ]]; then
    info "Config file contents:"
    echo
    cat "$conf"
  fi

  # ── Also show the interfaces file so user can verify ──────────────────
  echo
  if [[ -f "${DHCP_IFACE_FILE_debian}" ]]; then
    info "Interfaces file (${DHCP_IFACE_FILE_debian}):"
    grep -v '^#' "${DHCP_IFACE_FILE_debian}" | grep -v '^$' || true
  fi
}

remove_dhcp_server() {
  header "Remove DHCP Server"
  local pkg; pkg="$(dhcp_get PKG)"
  local conf; conf="$(dhcp_get CONF_FILE)"

  read -r -p "  This will stop the service and remove $pkg. Continue? [y/N]: " yn
  [[ "${yn,,}" == y ]] || { info "Canceled."; return 0; }

  local svc; svc="$(dhcp_get SVC)"
  systemctl stop    "$svc" 2>/dev/null || rc-service "$svc" stop 2>/dev/null || true
  systemctl disable "$svc" 2>/dev/null || rc-update del "$svc" 2>/dev/null || true

  if [[ -n "$conf" && -f "$conf" ]]; then
    cp -a "$conf" "${conf}.removed.$(date +%F-%H%M%S)"
    info "Config backed up: ${conf}.removed.*"
  fi

  case "$OS_FAMILY" in
    debian|vyos) apt-get remove -y "$pkg" 2>/dev/null || true ;;
    rhel)        if command -v dnf &>/dev/null; then dnf remove -y "$pkg"; else yum remove -y "$pkg"; fi ;;
    alpine)      apk del "$pkg" 2>/dev/null || true ;;
    opensuse)    zypper --non-interactive remove "$pkg" 2>/dev/null || true ;;
    arch)        pacman -R --noconfirm "$pkg" 2>/dev/null || true ;;
  esac

  ok "DHCP server removed."
}

setup_dhcp_server() {
  header "DHCP Server Setup"

  # Reset global subnet arrays for a fresh run
  NET_IFACE=(); NET_SUBNET=(); NET_NETMASK=(); NET_CIDR=()
  NET_RANGE_START=(); NET_RANGE_END=(); NET_ROUTER=(); NET_DNS=()
  NET_DOMAIN=(); NET_LEASE_DEF=(); NET_LEASE_MAX=(); NET_STATIC_HOSTS=()

  if [[ "$OS_FAMILY" == "vyos" ]]; then
    _setup_dhcp_vyos
    return $?
  fi

  echo "  Step 1/5 — Install DHCP server package"
  install_dhcp_server_pkg || return 1

  echo
  echo "  Step 2/5 — Define subnets"
  echo
  local num_nets=0
  while true; do
    collect_subnet "$num_nets" || return 1
    num_nets=$(( num_nets + 1 ))
    echo
    read -r -p "  Add another subnet/interface? [y/N]: " more
    [[ "${more,,}" == y ]] || break
  done

  echo
  echo "  Step 3/5 — Review configuration"
  echo
  echo -e "${BLD}  ════ DHCP Configuration Preview ════${RESET}"
  local conf_preview
  conf_preview="$(build_dhcpd_conf "$num_nets")"
  echo "$conf_preview"
  echo

  read -r -p "  Apply this configuration? [y/N]: " yn
  [[ "${yn,,}" == y ]] || { info "Canceled — nothing written."; return 0; }

  echo
  echo "  Step 4/5 — Applying configuration"

  local conf_file; conf_file="$(dhcp_get CONF_FILE)"
  local conf_dir;  conf_dir="$(dhcp_get CONF_DIR)"

  if [[ -f "$conf_file" ]]; then
    cp -a "$conf_file" "${conf_file}.bak.$(date +%F-%H%M%S)"
    info "Backed up existing config → ${conf_file}.bak.*"
  fi

  mkdir -p "$conf_dir"
  echo "$conf_preview" > "$conf_file"
  ok "Config written → $conf_file"

  # ── always set interface binding on debian/vyos ───────────────────────
  if [[ "$OS_FAMILY" == "debian" || "$OS_FAMILY" == "vyos" ]]; then
    local iface_list=""
    local i
    for (( i=0; i<num_nets; i++ )); do
      iface_list+="${iface_list:+ }${NET_IFACE[$i]}"
    done
    info "Binding DHCP service to interface(s): \"$iface_list\""
    apply_dhcp_interfaces_debian "$iface_list"
  fi

  enable_dhcp_service

  echo
  echo "  Step 5/5 — Firewall"
  open_dhcp_firewall

  echo
  ok "DHCP server is up and running!"
  echo
  info "Config file : $conf_file"
  info "Interfaces  : $(grep INTERFACESv4 ${DHCP_IFACE_FILE_debian} 2>/dev/null || echo 'see /etc/default/isc-dhcp-server')"
}

_setup_dhcp_vyos() {
  # Reset global subnet arrays
  NET_IFACE=(); NET_SUBNET=(); NET_NETMASK=(); NET_CIDR=()
  NET_RANGE_START=(); NET_RANGE_END=(); NET_ROUTER=(); NET_DNS=()
  NET_DOMAIN=(); NET_LEASE_DEF=(); NET_LEASE_MAX=(); NET_STATIC_HOSTS=()

  local num_nets=0
  while true; do
    collect_subnet "$num_nets" || return 1
    num_nets=$(( num_nets + 1 ))
    echo
    read -r -p "  Add another subnet? [y/N]: " more
    [[ "${more,,}" == y ]] || break
  done

  echo
  header "VyOS DHCP Configure Commands"
  warn "Paste these into VyOS configure mode:"
  echo
  local cmds; cmds="$(build_vyos_dhcp_commands "$num_nets")"
  echo "$cmds"
  echo

  read -r -p "  Attempt to apply via vbash automatically? [y/N]: " yn
  if [[ "${yn,,}" == y ]] && command -v vbash &>/dev/null; then
    vbash -c "
      source /opt/vyatta/etc/functions/script-template
      configure
      ${cmds}
      exit
    " && ok "VyOS DHCP configured." || warn "vbash run had errors — verify manually."
  fi
}

dhcp_menu() {
  while true; do
    header "DHCP Server  |  OS: $OS_ID ($OS_FAMILY)"
    echo "  1) Setup / reconfigure DHCP server  (install + multi-subnet wizard)"
    echo "  2) View current DHCP leases"
    echo "  3) Show DHCP server status + config"
    echo "  4) Restart DHCP service"
    echo "  5) Remove DHCP server"
    echo "  6) Back"
    echo

    read -r -p "Choose [1-6]: " sub; echo
    local svc; svc="$(dhcp_get SVC)"
    case "$sub" in
      1) setup_dhcp_server ;;
      2) show_dhcp_leases  ;;
      3) show_dhcp_status  ;;
      4)
        info "Restarting DHCP service: ${svc:-dhcpd} ..."
        if command -v rc-service &>/dev/null; then
          rc-service "${svc:-dhcpd}" restart && ok "Restarted." || err "Restart failed."
        else
          systemctl restart "${svc:-dhcpd}" && ok "Restarted." || err "Restart failed."
        fi
        ;;
      5) remove_dhcp_server ;;
      6) return 0           ;;
      *) warn "Invalid choice." ;;
    esac
  done
}

user_management_menu() {
  while true; do
    header "User Management"
    echo "  1) Add RSA-only ADMIN user  (NOPASSWD sudo)"
    echo "  2) Add RSA-only regular user (no sudo)"
    echo "  3) Add password regular user (no sudo)"
    echo "  4) Add password ADMIN user   (sudo requires password)"
    echo "  5) Delete user"
    echo "  6) Generate SSH key for user"
    echo "  7) Back"
    echo

    read -r -p "Choose [1-7]: " sub; echo
    case "$sub" in
      1) add_rsa_admin_user        ;;
      2) add_rsa_user_no_sudo      ;;
      3) add_password_user_no_sudo ;;
      4) add_password_admin_user   ;;
      5) delete_users_menu         ;;
      6) generate_ssh_key_menu     ;;
      7) return 0                  ;;
      *) warn "Invalid choice."   ;;
    esac
  done
}

menu() {
  while true; do
    header "System Setup  |  OS: $OS_ID ($OS_FAMILY)"
    echo "  1) User management     (add / delete / SSH key)"
    echo "  2) Set hostname"
    echo "  3) Disable root SSH login"
    echo "  4) Configure network   (static IP / manage netplan files)"
    echo "  5) Package management  (install bundle / custom / remove / search)"
    echo "  6) System update       (upgrade all packages / check updates)"
    echo "  7) DHCP server         (install / multi-subnet wizard / leases)"
    echo "  8) Git: clone/pull repo + hostname folder (existing user)"
    echo "  9) Set authorized_keys from repo (existing user)"
    echo " 10) Configure repo URL + key path defaults"
    echo " 11) Show system status"
    echo " 12) Exit"
    echo

    read -r -p "Choose [1-12]: " choice; echo

    local u
    case "$choice" in
      1)  user_management_menu ;;
      2)  set_hostname ;;
      3)  disable_root_ssh ;;
      4)  network_menu ;;
      5)  package_management_menu ;;
      6)  update_menu ;;
      7)  dhcp_menu ;;
      8)
        read -r -p "Username: " u
        [[ -n "$u" ]]        || { err "Username cannot be blank."; continue; }
        user_exists "$u"     || { err "User '$u' does not exist."; continue; }
        clone_or_update_repo_for_user "$u"
        ;;
      9)
        read -r -p "Username: " u
        [[ -n "$u" ]]        || { err "Username cannot be blank."; continue; }
        user_exists "$u"     || { err "User '$u' does not exist."; continue; }
        setup_authorized_keys_from_repo "$u"
        ;;
      10) configure_repo_settings ;;
      11) show_system_status ;;
      12) echo "Exiting."; exit 0 ;;
      *)  warn "Invalid choice." ;;
    esac
  done
}

main() {
  require_root
  detect_os

  if [[ "$OS_FAMILY" == "unknown" ]]; then
    err "Unsupported OS (ID=$OS_ID, ID_LIKE=${OS_LIKE:-})."
    exit 1
  fi

  load_config

  if [[ "$OS_FAMILY" == "vyos" ]]; then
    echo
    warn "VyOS detected. Some operations will output configure mode commands."
    echo
  fi

  menu
}

main "$@"
