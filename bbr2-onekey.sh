#!/usr/bin/env bash
# bbr2-onekey.sh - One-click enable TCP BBR2 (with safe fallbacks)
# Tested on Debian/Ubuntu/RHEL/CentOS/Rocky/Alma; needs root.

set -euo pipefail

# ---------- Defaults & Flags ----------
AUTO_REBOOT="no"
INSTALL_XANMOD="auto"   # auto|yes|no  (auto: only for Debian/Ubuntu with apt)
FALLBACK_BBR1="yes"     # whether to fall back to BBR v1 if BBR2 unavailable
DRY_RUN="no"
SYSCTL_FILE="/etc/sysctl.d/99-bbr.conf"

usage() {
  cat <<'EOF'
Usage: sudo bash bbr2-onekey.sh [options]

Options:
  --install-xanmod=yes|no|auto   Try installing XanMod kernel to get BBR2 (Debian/Ubuntu). Default: auto
  --fallback-bbr1=yes|no         If BBR2 unavailable, enable BBR v1. Default: yes
  --reboot-now                   Reboot automatically if a new kernel was installed
  --dry-run                      Show what would be done, make no changes
  -h, --help                     Show this help

Examples:
  sudo bash bbr2-onekey.sh --install-xanmod=auto --reboot-now
  sudo bash bbr2-onekey.sh --install-xanmod=no --fallback-bbr1=no
EOF
}

log() { echo -e "[bbr2] $*"; }
run() { if [[ "$DRY_RUN" == "no" ]]; then eval "$@"; else echo "DRY-RUN: $*"; fi; }

# ---------- Parse Args ----------
for arg in "$@"; do
  case "$arg" in
    --install-xanmod=*) INSTALL_XANMOD="${arg#*=}";;
    --fallback-bbr1=*)  FALLBACK_BBR1="${arg#*=}";;
    --reboot-now)       AUTO_REBOOT="yes";;
    --dry-run)          DRY_RUN="yes";;
    -h|--help)          usage; exit 0;;
    *) echo "Unknown option: $arg"; usage; exit 1;;
  esac
done

# ---------- Sanity checks ----------
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo)."; exit 1
fi

command -v sysctl >/dev/null || { echo "sysctl not found."; exit 1; }

OS_ID=""; OS_VERSION_ID=""
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-}"; OS_VERSION_ID="${VERSION_ID:-}"
fi

has_cmd() { command -v "$1" >/dev/null 2>&1; }
is_deb() { [[ "$OS_ID" =~ (debian|ubuntu|linuxmint|pop) ]] && has_cmd apt; }
is_rpm() { [[ "$OS_ID" =~ (rhel|centos|rocky|almalinux|fedora|ol) ]] && (has_cmd dnf || has_cmd yum); }

kernel="$(uname -r)"
log "Detected OS: ${OS_ID:-unknown} ${OS_VERSION_ID:-} | Kernel: $kernel"

# ---------- Helper: check availability ----------
has_cc_algo() {
  sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | tr ' ' '\n' | grep -qx "$1"
}

load_module_if_present() {
  local mod="$1"
  if [[ -e "/lib/modules/$(uname -r)/kernel/net/ipv4/tcp_$mod.ko"* ]]; then
    run "modprobe tcp_$mod || true"
  fi
}

# ---------- Step 1: try existing kernel for BBR2 ----------
log "Checking for existing BBR2 support in current kernel…"
load_module_if_present "bbr2"
if has_cc_algo "bbr2"; then
  log "BBR2 is available; enabling now."
  run "sysctl -w net.core.default_qdisc=fq"
  run "sysctl -w net.ipv4.tcp_congestion_control=bbr2"
  # Persist across reboots
  run "mkdir -p /etc/sysctl.d"
  run "bash -c 'cat > $SYSCTL_FILE <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr2
EOF'"
  run "sysctl --system >/dev/null"
  log "BBR2 enabled on current kernel."
  sysctl net.ipv4.tcp_congestion_control
  exit 0
else
  log "BBR2 not present in current kernel."
fi

# ---------- Step 2: optionally install XanMod (Debian/Ubuntu) ----------
need_reboot="no"
if [[ "$INSTALL_XANMOD" != "no" ]] && is_deb; then
  log "XanMod option: $INSTALL_XANMOD (Debian/Ubuntu detected)."
  # Only proceed for auto/yes
  if [[ "$INSTALL_XANMOD" == "auto" || "$INSTALL_XANMOD" == "yes" ]]; then
    log "Installing XanMod kernel, which includes BBR2 (package meta selects latest)."
    run "apt-get update"
    # Add XanMod repo if missing
    if ! apt-cache policy | grep -qi xanmod; then
      run "apt-get install -y curl ca-certificates gnupg"
      run "mkdir -p /usr/share/keyrings"
      run "curl -fsSL https://dl.xanmod.org/gpg.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg"
      codename="$(. /etc/os-release; echo $VERSION_CODENAME)"
      run "echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' > /etc/apt/sources.list.d/xanmod.list"
      run "apt-get update"
    fi
    # Install generic XanMod kernel for x86_64
    run "apt-get install -y linux-xanmod-x64v3 || apt-get install -y linux-xanmod"  # fallback meta
    need_reboot="yes"
  fi
else
  if ! is_deb; then
    log "Not a Debian/Ubuntu system; skipping XanMod auto-install."
  else
    log "User disabled XanMod install."
  fi
fi

# After install, check again (post-install requires reboot)
if [[ "$need_reboot" == "yes" ]]; then
  log "A new kernel was installed. BBR2 will be available after reboot."
  if [[ "$AUTO_REBOOT" == "yes" && "$DRY_RUN" == "no" ]]; then
    log "Rebooting now as requested…"
    reboot
    exit 0
  else
    log "Please reboot, then re-run: bash bbr2-onekey.sh   (it will finish enabling BBR2 automatically)."
  fi
fi

# ---------- Step 3: graceful fallback to BBR1 ----------
if [[ "$FALLBACK_BBR1" == "yes" ]]; then
  log "Falling back to enable BBR (v1)."
  load_module_if_present "bbr"
  if has_cc_algo "bbr"; then
    run "sysctl -w net.core.default_qdisc=fq"
    run "sysctl -w net.ipv4.tcp_congestion_control=bbr"
    run "mkdir -p /etc/sysctl.d"
    run "bash -c 'cat > $SYSCTL_FILE <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF'"
    run "sysctl --system >/dev/null"
    log "BBR (v1) enabled (you can later switch to BBR2 after installing a kernel that provides it)."
    sysctl net.ipv4.tcp_congestion_control
    exit 0
  else
    log "Your kernel does not even provide BBR v1. Consider upgrading to a newer kernel."
    exit 2
  fi
else
  log "User requested no fallback. Exiting without changes."
  exit 3
fi
