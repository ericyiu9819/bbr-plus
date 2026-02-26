#!/usr/bin/env bash
# ================================================================
# ATTAS v4.0-final  自適應 TCP 流量調節加速系統
# 融合架構終極審查版
#
# 修復記錄：
#   E-01 : ensure_dirs readonly 重複聲明修復
#   E-03 : bash_monitor_mode local 作用域修復
#   E-06 : main() case 內 local 聲明移出修復
#   E-08 : Python apply_params 未使用變量清理
#   E-09 : uninstall rm -rf 非空守衛
#   E-10 : check_repo_and_mirror 短路邏輯修復
#   E-11 : get_mode_params NaN/負數入口守衛
#   E-13 : detect_scenario int() 轉換異常細化
#   E-15 : switch_mirror UUOC 修復
#
# 安裝：
#   curl -sSL https://raw.githubusercontent.com/YOUR/attas/main/attas.sh | bash
#   wget -qO- https://raw.githubusercontent.com/YOUR/attas/main/attas.sh | bash
#
# 最低要求：bash 4.0+ | Linux kernel 3.10+ | root
# ================================================================
set -uo pipefail
IFS=$'\n\t'

# ================================================================
# ██  GitHub 配置區                                            ██
# ================================================================
readonly GITHUB_USER="your-username"
readonly GITHUB_REPO="attas"
readonly GITHUB_BRANCH="main"
readonly REMOTE_RAW="https://raw.githubusercontent.com"
readonly REMOTE_URL="${REMOTE_RAW}/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/attas.sh"
readonly REMOTE_VER_URL="${REMOTE_RAW}/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/VERSION"

# ================================================================
# ██  全局常量                                                 ██
# ================================================================
readonly VERSION="4.0-final"
readonly INSTALL_DIR="/opt/attas"
readonly LOG_FILE="/var/log/attas.log"
readonly BASELINE_FILE="/etc/attas/baseline.dat"
readonly LEARNED_FILE="/etc/attas/learned.dat"
readonly CONFIG_DIR="/etc/attas"
readonly SYSCTL_CONF="/etc/sysctl.d/99-attas.conf"
readonly MODULES_CONF="/etc/modules-load.d/attas.conf"
readonly SERVICE_FILE="/etc/systemd/system/attas.service"
readonly WATCHDOG_FILE="/etc/systemd/system/attas-watchdog.service"
readonly BIN_PATH="/usr/local/bin/attas"
readonly PY_ENGINE="${INSTALL_DIR}/engine.py"
readonly MONITOR_INTERVAL=30
readonly MIRROR_TIMEOUT=5
readonly MAX_RETRY=3
readonly LOSS_CACHE="/tmp/attas_loss.cache"
readonly LOSS_PID_FILE="/tmp/attas_loss.pid"
readonly ENGINE_MODE_FILE="/tmp/attas_engine.mode"

# ================================================================
# ██  運行時變量                                               ██
# ================================================================
OS_ID=""
OS_VERSION=""
PKG_MANAGER=""
PKG_INSTALL=""
PKG_UPDATE=""
INIT_SYSTEM=""
IS_CONTAINER=false
IS_OPENWRT=false
IS_ALPINE=false
KERNEL_MAJOR=0
KERNEL_MINOR=0
AVAILABLE_ALGOS=""
NET_IFACE=""
BASH_MAJOR=0
PYTHON_CMD=""
ENGINE_MODE="bash"

# ================================================================
# ██  顏色初始化                                               ██
# ================================================================
setup_colors() {
    if [[ -t 1 ]] && \
       [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[1;33m'
        BLUE='\033[0;34m'
        CYAN='\033[0;36m'
        PURPLE='\033[0;35m'
        BOLD='\033[1m'
        NC='\033[0m'
    else
        RED=''
        GREEN=''
        YELLOW=''
        BLUE=''
        CYAN=''
        PURPLE=''
        BOLD=''
        NC=''
    fi
}

# ================================================================
# ██  基礎工具函數                                             ██
# ================================================================
log() {
    local msg="$1"
    local level="${2:-INFO}"
    local color=""
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'N/A')"
    case "$level" in
        OK)   color="$GREEN"  ;;
        WARN) color="$YELLOW" ;;
        ERR)  color="$RED"    ;;
        STEP) color="$PURPLE" ;;
        INFO) color="$CYAN"   ;;
        *)    color=""        ;;
    esac
    echo -e "${color}[${ts}][${level}] ${msg}${NC}"
    echo "[${ts}][${level}] ${msg}" >> "$LOG_FILE" 2>/dev/null || true
}

die()     { log "$1" "ERR"; exit 1; }
has_cmd() { command -v "$1" &>/dev/null; }

safe_sysctl() {
    local param="$1"
    if [[ "$IS_CONTAINER" == true ]]; then
        sysctl -w "$param" &>/dev/null || true
    else
        sysctl -w "$param" &>/dev/null || \
            log "sysctl [${param}] 失敗（可忽略）" "WARN"
    fi
}

# [E-01 修復] 移除函數內 readonly 重複聲明
# LOG_FILE 已在全局聲明為 readonly，此處只做目錄創建
ensure_dirs() {
    mkdir -p "$CONFIG_DIR" "$INSTALL_DIR" \
             "$(dirname "$LOG_FILE")" 2>/dev/null || true
    touch "$LOG_FILE" 2>/dev/null || true
}

get_default_iface() {
    local iface=""
    iface="$(ip route show default 2>/dev/null | \
             awk '/default/{ print $5 }' | head -1)"
    if [[ -n "$iface" ]] && \
       ip link show "$iface" &>/dev/null 2>&1; then
        echo "$iface"
        return
    fi
    ip link show 2>/dev/null | \
        awk -F': ' '/^[0-9]+:/{
            gsub(/ /, "", $2)
            if ($2 != "lo" && $2 != "") print $2
        }' | head -1
}

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'BANNER'
+============================================================+
|   ATTAS v4.0-final  自適應 TCP 加速系統  融合架構終極版   |
|   雙引擎 · BDP動態計算 · 場景識別 · 學習型基線            |
+============================================================+
BANNER
    echo -e "${NC}"
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        has_cmd sudo && exec sudo bash "$0" "$@" || \
            die "需要 root 權限"
    fi
}

check_bash_version() {
    BASH_MAJOR="${BASH_VERSINFO[0]:-0}"
    if [[ "$BASH_MAJOR" -lt 4 ]]; then
        die "需要 bash 4.0+，當前：${BASH_VERSION:-未知}"
    fi
    log "bash ${BASH_VERSION} 版本檢測通過" "OK"
}

ensure_bash() {
    if ! has_cmd bash; then
        case "${PKG_MANAGER:-unknown}" in
            apk)  apk add --no-cache bash &>/dev/null || true ;;
            opkg) opkg install bash &>/dev/null       || true ;;
            *)    install_pkg "bash"                          ;;
        esac
    fi
    if [[ -z "${BASH_VERSION:-}" ]]; then
        exec bash "$0" "$@"
    fi
}

# ================================================================
# ██  管道模式自我落盤                                        ██
# ================================================================
ensure_self_on_disk() {
    local is_pipe=false
    if [[ ! -f "$0" ]] || \
       [[ "$0" == "bash" ]] || \
       [[ "$0" =~ ^/.*bin/bash$ ]]; then
        is_pipe=true
    fi
    [[ "$is_pipe" == false ]] && return 0

    log "管道模式：正在下載腳本..." "WARN"
    local tmp
    tmp="$(mktemp /tmp/attas_XXXXXX.sh)" || \
        die "無法創建臨時文件"

    local ok=false
    if has_cmd curl; then
        curl -sSL --connect-timeout 10 \
             "$REMOTE_URL" -o "$tmp" 2>/dev/null && \
        [[ -s "$tmp" ]] && \
        head -1 "$tmp" | grep -q "bash" && ok=true
    fi
    if [[ "$ok" == false ]] && has_cmd wget; then
        wget -qO "$tmp" --timeout=10 \
             "$REMOTE_URL" 2>/dev/null && \
        [[ -s "$tmp" ]] && \
        head -1 "$tmp" | grep -q "bash" && ok=true
    fi

    if [[ "$ok" == false ]]; then
        rm -f "$tmp"
        die "下載失敗，請手動安裝：
  curl -sSL ${REMOTE_URL} -o attas.sh && bash attas.sh"
    fi

    chmod +x "$tmp"
    log "落盤完成：${tmp}" "OK"
    exec bash "$tmp" "$@"
}

# ================================================================
# ██  版本更新檢測（後台靜默）                                ██
# ================================================================
check_for_updates() {
    (
        local rv=""
        has_cmd curl && \
            rv="$(curl -sSL --connect-timeout 5 \
                  "$REMOTE_VER_URL" 2>/dev/null | \
                  tr -d '[:space:]')"
        if [[ -n "$rv" && "$rv" != "$VERSION" ]]; then
            echo -e "\n${YELLOW}[UPDATE] 新版本：${rv}（當前：${VERSION}）${NC}"
            echo -e "${CYAN}  curl -sSL ${REMOTE_URL} | bash${NC}\n"
        fi
    ) &
}

# ================================================================
# ██  系統識別層                                               ██
# ================================================================
detect_container() {
    if [[ -f "/.dockerenv" ]] || \
       grep -qa 'docker\|lxc\|containerd' \
           /proc/1/cgroup 2>/dev/null || \
       [[ "$(systemd-detect-virt 2>/dev/null \
            || echo none)" =~ \
           ^(docker|lxc|openvz|container)$ ]]; then
        IS_CONTAINER=true
        log "容器環境：部分 sysctl 跳過" "WARN"
    else
        IS_CONTAINER=false
        log "物理機 / 虛擬機環境" "OK"
    fi
}

detect_os() {
    log "識別操作系統..." "STEP"

    if [[ -f /etc/openwrt_release ]]; then
        # shellcheck disable=SC1091
        source /etc/openwrt_release
        OS_ID="openwrt"
        OS_VERSION="${DISTRIB_RELEASE:-unknown}"
        PKG_MANAGER="opkg"
        PKG_INSTALL="opkg install"
        PKG_UPDATE="opkg update"
        IS_OPENWRT=true
        log "OpenWrt ${OS_VERSION}" "OK"
        return
    fi

    if [[ -f /etc/alpine-release ]]; then
        OS_ID="alpine"
        OS_VERSION="$(cat /etc/alpine-release)"
        PKG_MANAGER="apk"
        PKG_INSTALL="apk add --no-cache -q"
        PKG_UPDATE="apk update -q"
        IS_ALPINE=true
        log "Alpine Linux ${OS_VERSION}" "OK"
        return
    fi

    if [[ -f /etc/gentoo-release ]]; then
        OS_ID="gentoo"
        OS_VERSION="$(grep -oE '[0-9.]+' \
                      /etc/gentoo-release | head -1)"
        PKG_MANAGER="emerge"
        PKG_INSTALL="emerge -q"
        PKG_UPDATE="emerge --sync -q"
        log "Gentoo Linux ${OS_VERSION}" "OK"
        return
    fi

    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-0}"
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="rhel"
        OS_VERSION="$(grep -oE '[0-9]+' \
                      /etc/redhat-release | head -1)"
    elif [[ -f /etc/debian_version ]]; then
        OS_ID="debian"
        OS_VERSION="$(cat /etc/debian_version)"
    else
        OS_ID="unknown"
        OS_VERSION="0"
        log "無法識別系統，通用模式" "WARN"
    fi

    if   has_cmd apt-get; then
        PKG_MANAGER="apt"
        PKG_INSTALL="DEBIAN_FRONTEND=noninteractive \
apt-get install -y -qq"
        PKG_UPDATE="apt-get update -qq"
    elif has_cmd dnf; then
        PKG_MANAGER="dnf"
        PKG_INSTALL="dnf install -y -q --skip-broken"
        PKG_UPDATE="dnf makecache -q"
    elif has_cmd yum; then
        PKG_MANAGER="yum"
        PKG_INSTALL="yum install -y -q"
        PKG_UPDATE="yum makecache -q"
    elif has_cmd pacman; then
        PKG_MANAGER="pacman"
        PKG_INSTALL="pacman -S --noconfirm --needed -q"
        PKG_UPDATE="pacman -Sy -q"
    elif has_cmd zypper; then
        PKG_MANAGER="zypper"
        PKG_INSTALL="zypper install -y -q --no-recommends"
        PKG_UPDATE="zypper refresh -q"
    elif has_cmd xbps-install; then
        PKG_MANAGER="xbps"
        PKG_INSTALL="xbps-install -y"
        PKG_UPDATE="xbps-install -S"
    else
        PKG_MANAGER="unknown"
        log "未找到受支持的包管理器" "WARN"
    fi

    log "系統：${OS_ID} ${OS_VERSION} | PM：${PKG_MANAGER}" "OK"
}

detect_init_system() {
    if   [[ -d /run/systemd/system ]] || has_cmd systemctl; then
        INIT_SYSTEM="systemd"
    elif [[ -f /sbin/openrc ]] || has_cmd rc-service; then
        INIT_SYSTEM="openrc"
    elif [[ -d /etc/sv ]] || has_cmd sv; then
        INIT_SYSTEM="runit"
    elif [[ -f /etc/inittab ]]; then
        INIT_SYSTEM="sysvinit"
    else
        INIT_SYSTEM="unknown"
    fi
    log "Init：${INIT_SYSTEM}" "OK"
}

detect_kernel() {
    local kver
    kver="$(uname -r)"
    KERNEL_MAJOR="$(echo "$kver" | cut -d. -f1)"
    KERNEL_MINOR="$(echo "$kver" | cut -d. -f2)"
    AVAILABLE_ALGOS="$(cat \
        /proc/sys/net/ipv4/tcp_available_congestion_control \
        2>/dev/null || echo 'cubic')"
    NET_IFACE="$(get_default_iface)"
    log "內核：${kver} | 接口：${NET_IFACE:-未知}" "INFO"
    log "算法：${AVAILABLE_ALGOS}" "INFO"
}

# ================================================================
# ██  網絡 & 鏡像源管理                                       ██
# ================================================================
test_url() {
    local url="$1"
    local timeout="${2:-${MIRROR_TIMEOUT}}"
    if has_cmd curl; then
        curl -sI --connect-timeout "$timeout" \
             "$url" &>/dev/null && return 0
    fi
    if has_cmd wget; then
        wget -q --spider \
             --timeout="$timeout" "$url" &>/dev/null && return 0
    fi
    return 1
}

test_connectivity() {
    log "測試網絡連通性..." "STEP"
    local h
    for h in "8.8.8.8" "1.1.1.1" "114.114.114.114" "223.5.5.5"; do
        if ping -c 1 -W 3 "$h" &>/dev/null 2>&1; then
            log "網絡正常（via ${h}）" "OK"
            return 0
        fi
    done
    die "網絡不可達，請檢查連接"
}

switch_mirror() {
    log "切換國內鏡像源..." "WARN"
    local codename=""

    case "$PKG_MANAGER" in
        apt)
            cp /etc/apt/sources.list \
               /etc/apt/sources.list.bak 2>/dev/null || true
            codename="$(grep VERSION_CODENAME \
                        /etc/os-release 2>/dev/null | \
                        cut -d= -f2 || echo 'focal')"
            if [[ "$OS_ID" == "ubuntu" ]]; then
                cat > /etc/apt/sources.list << EOF
deb http://mirrors.aliyun.com/ubuntu/ ${codename} main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ ${codename}-updates main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ ${codename}-security main restricted universe multiverse
EOF
            else
                cat > /etc/apt/sources.list << EOF
deb http://mirrors.aliyun.com/debian/ ${codename} main contrib non-free
deb http://mirrors.aliyun.com/debian/ ${codename}-updates main contrib non-free
deb http://mirrors.aliyun.com/debian-security ${codename}-security main
EOF
            fi
            eval "$PKG_UPDATE" 2>/dev/null || true
            log "已切換至阿里雲 APT 鏡像" "OK"
            ;;

        yum|dnf)
            local ver="${OS_VERSION%%.*}"
            mv /etc/yum.repos.d/CentOS-Base.repo \
               /etc/yum.repos.d/CentOS-Base.repo.bak \
               2>/dev/null || true
            if has_cmd curl; then
                curl -sL \
                    "https://mirrors.aliyun.com/repo/Centos-${ver}.repo" \
                    -o /etc/yum.repos.d/CentOS-Base.repo \
                    2>/dev/null || true
            fi
            eval "$PKG_UPDATE" 2>/dev/null || true
            log "已切換至阿里雲 YUM 鏡像" "OK"
            ;;

        pacman)
            # 單引號 EOF 防止 $repo/$arch 被展開
            cat > /etc/pacman.d/mirrorlist << 'EOF'
Server = https://mirrors.aliyun.com/archlinux/$repo/os/$arch
EOF
            eval "$PKG_UPDATE" 2>/dev/null || true
            log "已切換至阿里雲 Pacman 鏡像" "OK"
            ;;

        apk)
            # [E-15 修復] 移除 UUOC，改用重定向讀取
            local av
            av="$(cut -d. -f1-2 < /etc/alpine-release)"
            cat > /etc/apk/repositories << EOF
https://mirrors.aliyun.com/alpine/v${av}/main
https://mirrors.aliyun.com/alpine/v${av}/community
EOF
            eval "$PKG_UPDATE" 2>/dev/null || true
            log "已切換至阿里雲 Alpine 鏡像" "OK"
            ;;

        *)
            log "當前包管理器不支持自動換源" "WARN"
            ;;
    esac
}

# [E-10 修復] 使用短路邏輯，第一個成功後不再繼續測試
check_repo_and_mirror() {
    log "測試軟件源可訪問性..." "STEP"
    local ok=false

    case "$PKG_MANAGER" in
        apt)
            test_url "http://archive.ubuntu.com" && ok=true || \
            test_url "http://deb.debian.org"      && ok=true || true
            ;;
        yum|dnf)
            test_url "http://mirrorlist.centos.org" && ok=true || true
            ;;
        pacman)
            test_url "https://archlinux.org" && ok=true || true
            ;;
        apk)
            test_url "https://dl-cdn.alpinelinux.org" && ok=true || true
            ;;
        *)
            ok=true
            ;;
    esac

    if [[ "$ok" == false ]]; then
        log "默認源不可達，切換鏡像..." "WARN"
        switch_mirror
    else
        log "軟件源正常" "OK"
    fi
}

# ================================================================
# ██  依賴映射 & 安裝引擎                                     ██
# ================================================================
declare -A DEP_MAP
DEP_MAP["ping"]="iputils-ping|iputils|iputils|iputils|iputils|iputils-ping"
DEP_MAP["curl"]="curl|curl|curl|curl|curl|curl"
DEP_MAP["wget"]="wget|wget|wget|wget|wget|wget"
DEP_MAP["bc"]="bc|bc|bc|bc|bc|bc"
DEP_MAP["awk"]="gawk|gawk|gawk|gawk|gawk|gawk"
DEP_MAP["ip"]="iproute2|iproute|iproute2|iproute2|iproute2|ip-full"
DEP_MAP["ss"]="iproute2|iproute|iproute2|iproute2|iproute2|ip-full"
DEP_MAP["tc"]="iproute2|iproute|iproute2|iproute2|iproute2|tc"
DEP_MAP["sysctl"]="procps|procps-ng|procps|procps|procps|procps"
DEP_MAP["modprobe"]="kmod|kmod|kmod|kmod|kmod|kmod"
DEP_MAP["ethtool"]="ethtool|ethtool|ethtool|ethtool|ethtool|ethtool"
DEP_MAP["lsmod"]="kmod|kmod|kmod|kmod|kmod|kmod"

get_pkg_name() {
    local info="$1"
    local idx=1
    case "$PKG_MANAGER" in
        apt)      idx=1 ;;
        dnf|yum)  idx=2 ;;
        pacman)   idx=3 ;;
        apk)      idx=4 ;;
        zypper)   idx=5 ;;
        opkg)     idx=6 ;;
        *)        idx=1 ;;
    esac
    echo "$info" | cut -d'|' -f"${idx}"
}

install_pkg() {
    local pkg="$1"
    [[ -z "$pkg" ]] && return 1
    [[ "$PKG_MANAGER" == "unknown" ]] && return 1
    local retry=0
    while [[ "$retry" -lt "$MAX_RETRY" ]]; do
        eval "$PKG_INSTALL $pkg" &>/dev/null && return 0
        retry=$((retry + 1))
        log "安裝 ${pkg} 重試 (${retry}/${MAX_RETRY})..." "WARN"
        sleep 2
    done
    return 1
}

check_install_cmd() {
    local cmd="$1"
    if has_cmd "$cmd"; then
        log "  [OK] ${cmd}" "OK"
        return 0
    fi
    log "  [!!] ${cmd} 缺失，安裝中..." "WARN"
    local info="${DEP_MAP[$cmd]:-}"
    if [[ -z "$info" ]]; then
        log "  [??] ${cmd} 無映射，跳過" "WARN"
        return 1
    fi
    local pkg
    pkg="$(get_pkg_name "$info")"
    if install_pkg "$pkg" && has_cmd "$cmd"; then
        log "  [OK] ${cmd} 安裝成功" "OK"
        return 0
    fi
    log "  [XX] ${cmd} 安裝失敗" "ERR"
    return 1
}

load_kernel_module() {
    local mod="$1"
    [[ "$IS_CONTAINER" == true ]] && return 0
    [[ "$IS_OPENWRT"   == true ]] && return 0
    if lsmod 2>/dev/null | grep -q "^${mod} "; then
        log "  [OK] [Mod] ${mod}" "OK"
        return 0
    fi
    log "  [>>] [Mod] ${mod} 加載中..." "WARN"
    if modprobe "$mod" &>/dev/null; then
        log "  [OK] [Mod] ${mod} 成功" "OK"
        mkdir -p "$(dirname "$MODULES_CONF")" 2>/dev/null || true
        grep -q "$mod" "$MODULES_CONF" 2>/dev/null || \
            echo "$mod" >> "$MODULES_CONF" 2>/dev/null || true
        return 0
    fi
    log "  [!!] [Mod] ${mod} 失敗（可忽略）" "WARN"
    return 0
}

run_dependency_check() {
    log "==============================" "STEP"
    log "   智能依賴檢測 & 自動安裝   " "STEP"
    log "==============================" "STEP"

    eval "$PKG_UPDATE" 2>/dev/null || \
        log "包索引更新失敗，繼續..." "WARN"

    local cmd
    local failed=0
    for cmd in "${!DEP_MAP[@]}"; do
        check_install_cmd "$cmd" || failed=$((failed + 1))
    done

    local mod
    for mod in tcp_bbr tcp_hybla tcp_vegas \
               tcp_cubic sch_fq sch_fq_codel; do
        load_kernel_module "$mod"
    done

    if   has_cmd python3; then
        PYTHON_CMD="python3"
        log "  [OK] $(python3 --version 2>&1)" "OK"
    elif has_cmd python; then
        PYTHON_CMD="python"
        log "  [OK] $(python --version 2>&1)" "OK"
    else
        log "  [!!] Python 未安裝，嘗試安裝 python3..." "WARN"
        install_pkg "python3" && PYTHON_CMD="python3" || \
            log "  [!!] Python 安裝失敗，將使用 bash 引擎" "WARN"
    fi

    if [[ "$failed" -eq 0 ]]; then
        log "依賴全部就緒" "OK"
    else
        log "依賴完成（${failed} 項失敗，核心功能仍可運行）" "WARN"
    fi
}

# ================================================================
# ██  Python 核心引擎寫入                                     ██
# ================================================================
write_python_engine() {
    log "寫入 Python 核心引擎..." "STEP"
    mkdir -p "$INSTALL_DIR"

    # 單引號 'PYEOF' 防止 bash 展開 Python 內部變量
    cat > "$PY_ENGINE" << 'PYEOF'
#!/usr/bin/env python3
# ================================================================
# ATTAS v4.0-final Python 核心引擎
# 融合：AdaTCP BDP計算 + 連續評分 + ATTAS 工程修復
# ================================================================
import subprocess
import time
import re
import statistics
import logging
import os
import json
from datetime import datetime

# ── 日誌配置 ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/var/log/attas.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("ATTAS")

# ── 常量 ──────────────────────────────────────────────────────
LEARNED_FILE  = "/etc/attas/learned.dat"
HEALTH_FILE   = "/tmp/attas_health.json"
MONITOR_HOSTS = [
    "8.8.8.8",
    "1.1.1.1",
    "114.114.114.114",
    "223.5.5.5"
]
VERSION = "4.0-final"

# ================================================================
# ██  工具函數                                                 ██
# ================================================================
def run_cmd(cmd: str, check: bool = False) -> str:
    try:
        r = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        if check and r.returncode != 0:
            raise subprocess.CalledProcessError(
                r.returncode, cmd
            )
        return r.stdout.strip()
    except Exception:
        return ""


def get_interfaces() -> list:
    out = run_cmd(
        "ip -o link show | awk -F': ' '{print $2}'"
    )
    result = []
    for line in out.splitlines():
        name = line.split()[0].rstrip('@')
        if name and name != 'lo':
            result.append(name)
    return result


def get_default_iface() -> str:
    out = run_cmd(
        "ip route show default | awk '/default/{print $5}'"
    )
    iface = out.strip().split('\n')[0] if out else ""
    if iface:
        check = run_cmd(
            f"ip link show {iface} 2>/dev/null"
        )
        if check:
            return iface
    ifaces = get_interfaces()
    return ifaces[0] if ifaces else ""


def get_link_speed(iface: str) -> int:
    out = run_cmd(
        f"ethtool {iface} 2>/dev/null | grep -i 'Speed'"
    )
    m = re.search(r'(\d+)\s*[Mm]b/?s', out)
    return int(m.group(1)) if m else 1000


# ================================================================
# ██  網絡狀態採樣（修復 AdaTCP RTT 正則 bug）                ██
# ================================================================
def get_rtt_and_loss() -> tuple:
    """
    [FIX] AdaTCP 原始正則 r"/avg/ = .*?/(.*?)/" 無法匹配
    ping 輸出格式：
        rtt min/avg/max/mdev = 1.234/2.345/3.456/0.123 ms
    修復：直接匹配標準格式，取第二個數值（avg）
    """
    rtts = []
    losses = []

    for host in MONITOR_HOSTS:
        out = run_cmd(
            f"ping -c 5 -i 0.3 -W 2 {host} 2>/dev/null"
        )
        if not out:
            losses.append(100.0)
            continue

        # 丟包率匹配
        loss_m = re.search(
            r'(\d+(?:\.\d+)?)\s*%\s*packet loss',
            out
        )
        loss = float(loss_m.group(1)) if loss_m else 100.0
        losses.append(loss)

        # RTT 修復版正則：匹配 min/avg/max/mdev 格式
        rtt_m = re.search(
            r'rtt\s+min/avg/max/(?:mdev|stddev)\s*='
            r'\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+',
            out
        )
        if rtt_m:
            try:
                rtts.append(float(rtt_m.group(1)))
            except ValueError:
                pass

    avg_rtt  = statistics.mean(rtts)   if rtts   else 80.0
    avg_loss = statistics.mean(losses) if losses else 0.0
    return avg_rtt, avg_loss


# ================================================================
# ██  BDP 動態計算                                            ██
# ================================================================
def estimate_bdp(rtt_ms: float, bw_mbps: int) -> int:
    """
    帶寬時延積：BDP = 帶寬(B/s) × RTT(s) × 安全係數
    """
    rtt_s  = rtt_ms / 1000.0
    bw_bps = (bw_mbps * 1_000_000) / 8.0
    bdp    = int(bw_bps * rtt_s * 1.5)
    min_buf = 64  * 1024 * 1024   # 最小 64MB
    max_buf = 512 * 1024 * 1024   # 最大 512MB
    return max(min_buf, min(bdp, max_buf))


# ================================================================
# ██  連續評分引擎                                            ██
# ================================================================
def calc_continuous_score(rtt: float, loss: float) -> float:
    """
    連續線性評分，避免分級閾值的邊界跳變
    score 越高 = 網絡越差
    """
    # 防止負值或 NaN 輸入
    rtt  = max(0.0, float(rtt  if rtt  == rtt  else 80.0))
    loss = max(0.0, float(loss if loss == loss else 0.0))
    return (rtt / 100.0) + (loss * 2.0)


# [E-11 修復] 入口類型守衛，防止 NaN/負數導致 KeyError
def get_mode_params(score: float) -> dict:
    """
    連續評分映射到模式參數
    """
    # 守衛：確保 score 是有效的非負浮點數
    try:
        score = float(score)
        if score != score:  # NaN 檢測
            score = 3.0     # 默認 Fair 模式
    except (TypeError, ValueError):
        score = 3.0

    score = max(0.0, score)

    if score > 6.0:
        return {
            "mode":     "Critical",
            "buf_mult": 4.5,
            "interval": 12,
            "retries1": 7,
            "retries2": 20,
            "qdisc":    "fq"
        }
    elif score > 4.0:
        return {
            "mode":     "Poor",
            "buf_mult": 3.8,
            "interval": 15,
            "retries1": 6,
            "retries2": 18,
            "qdisc":    "fq"
        }
    elif score > 2.5:
        return {
            "mode":     "Fair",
            "buf_mult": 2.8,
            "interval": 25,
            "retries1": 4,
            "retries2": 15,
            "qdisc":    "fq"
        }
    else:
        return {
            "mode":     "Good",
            "buf_mult": 2.2,
            "interval": 40,
            "retries1": 3,
            "retries2": 10,
            "qdisc":    "fq"
        }


# ================================================================
# ██  場景識別器                                              ██
# ================================================================
def detect_scenario() -> str:
    """
    自動識別網絡使用場景：
    video / download / web / default
    """
    try:
        ss_out = run_cmd(
            "ss -t state established 2>/dev/null"
        )
        tw_raw = run_cmd(
            "ss -t state time-wait 2>/dev/null | wc -l"
        )

        established = len(ss_out.splitlines())

        # [E-13 修復] 細化 int() 轉換異常處理
        try:
            time_wait = int(tw_raw.strip())
        except (ValueError, AttributeError):
            time_wait = 0

        if time_wait > 500:
            return "web"
        if 10 < established <= 100:
            return "video"
        if established <= 10:
            return "download"
        return "default"

    except Exception:
        return "default"


def get_scenario_tuning(scenario: str) -> dict:
    """
    針對不同場景的額外調優參數
    """
    tuning = {
        "video": {
            "net.ipv4.tcp_notsent_lowat":       "16384",
            "net.ipv4.tcp_slow_start_after_idle": "0",
            "net.ipv4.tcp_fastopen":             "3",
        },
        "download": {
            "net.ipv4.tcp_window_scaling":        "1",
            "net.ipv4.tcp_slow_start_after_idle": "0",
            "net.ipv4.tcp_fastopen":              "3",
        },
        "web": {
            "net.ipv4.tcp_tw_reuse":         "1",
            "net.ipv4.tcp_fin_timeout":      "15",
            "net.ipv4.tcp_max_syn_backlog":  "65535",
            "net.core.somaxconn":            "65535",
        },
        "default": {
            "net.ipv4.tcp_fastopen":              "3",
            "net.ipv4.tcp_slow_start_after_idle": "0",
        }
    }
    return tuning.get(scenario, tuning["default"])


# ================================================================
# ██  學習型基線                                              ██
# ================================================================
def load_learned_params() -> dict:
    if not os.path.exists(LEARNED_FILE):
        return {}
    try:
        with open(LEARNED_FILE, 'r') as f:
            data = json.load(f)
        log.info(
            f"[LEARN] 加載歷史最優參數"
            f"（Score={data.get('best_score', 'N/A')}）"
        )
        return data
    except Exception:
        return {}


def save_learned_params(
    params: dict,
    score: float,
    rtt: float,
    loss: float
) -> None:
    if score >= 2.5:
        return
    try:
        os.makedirs(
            os.path.dirname(LEARNED_FILE),
            exist_ok=True
        )
        data = {
            "version":    VERSION,
            "timestamp":  datetime.now().isoformat(),
            "best_score": round(score, 3),
            "best_rtt":   round(rtt,   1),
            "best_loss":  round(loss,  1),
            "params":     params
        }
        with open(LEARNED_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        log.info(f"[LEARN] 最優參數已保存（Score={score:.3f}）")
    except Exception as e:
        log.warning(f"[LEARN] 保存失敗：{e}")


# ================================================================
# ██  參數構建 & 應用                                         ██
# ================================================================
def build_params(
    bdp: int,
    mode_p: dict,
    scenario_p: dict,
    bw_mbps: int
) -> dict:
    max_buf = max(
        64 * 1024 * 1024,
        int(bdp * mode_p["buf_mult"])
    )
    # 防止超過系統可用內存的 25%
    try:
        with open('/proc/meminfo') as f:
            mem_kb = int(f.readline().split()[1])
        max_buf = min(max_buf, mem_kb * 1024 // 4)
    except Exception:
        pass

    params = {
        "net.ipv4.tcp_congestion_control": "bbr",
        "net.core.default_qdisc":          mode_p["qdisc"],
        "net.ipv4.tcp_rmem":
            f"4096 131072 {max_buf}",
        "net.ipv4.tcp_wmem":
            f"4096 131072 {max_buf}",
        "net.core.rmem_max":            str(max_buf),
        "net.core.wmem_max":            str(max_buf),
        "net.ipv4.tcp_retries1":        str(mode_p["retries1"]),
        "net.ipv4.tcp_retries2":        str(mode_p["retries2"]),
        "net.ipv4.tcp_fastopen":        "3",
        "net.ipv4.tcp_mtu_probing":     "1",
        "net.ipv4.tcp_window_scaling":  "1",
        "net.ipv4.tcp_adv_win_scale":   "1",
        "net.ipv4.tcp_moderate_rcvbuf": "1",
        "net.core.netdev_max_backlog":  "250000",
        "net.core.somaxconn":           "65535",
        "net.ipv4.tcp_max_syn_backlog": "65535",
        "net.ipv4.ip_local_port_range": "1024 65535",
        "net.ipv4.tcp_tw_reuse":        "1",
    }
    # 疊加場景參數（高優先級覆蓋基礎參數）
    params.update(scenario_p)
    return params


def apply_params(params: dict) -> None:
    """
    應用 sysctl 參數 + tc qdisc 設置
    [E-08 修復] 移除未使用的 result 變量
    [BUG-03 移植] 接口雙重校驗
    """
    for k, v in params.items():
        run_cmd(f"sysctl -w {k}={v}", check=False)

    iface = get_default_iface()
    if not iface:
        log.warning("[TC] 未找到默認接口，跳過 tc 設置")
        return

    qdisc = params.get("net.core.default_qdisc", "fq")
    run_cmd(
        f"tc qdisc replace dev {iface} root {qdisc} 2>/dev/null"
    )
    log.info(f"[TC] {iface} -> {qdisc}")


# ================================================================
# ██  健康狀態報告                                            ██
# ================================================================
def write_health(
    rtt: float,
    loss: float,
    score: float,
    mode: str,
    scenario: str,
    bdp: int
) -> None:
    health = {
        "version":   VERSION,
        "timestamp": datetime.now().isoformat(),
        "rtt_ms":    round(rtt,   1),
        "loss_pct":  round(loss,  1),
        "score":     round(score, 3),
        "mode":      mode,
        "scenario":  scenario,
        "bdp_mb":    round(bdp / 1024 / 1024, 1),
        "algo":      "bbr",
        "status":    "running"
    }
    try:
        with open(HEALTH_FILE, 'w') as f:
            json.dump(health, f, indent=2)
    except Exception:
        pass


# ================================================================
# ██  主循環                                                   ██
# ================================================================
def main() -> None:
    if os.geteuid() != 0:
        print("[ERR] 請使用 root 或 sudo 執行")
        raise SystemExit(1)

    log.info(f"ATTAS v{VERSION} Python 引擎啟動")

    run_cmd("modprobe tcp_bbr 2>/dev/null || true")
    run_cmd("modprobe sch_fq  2>/dev/null || true")

    ifaces    = get_interfaces()
    speeds    = [get_link_speed(i) for i in ifaces]
    assumed_bw = max(speeds) if speeds else 1000
    log.info(f"鏈路速度：{assumed_bw} Mbps")

    # 加載歷史最優參數
    learned = load_learned_params()
    if learned.get("params"):
        log.info("[LEARN] 應用歷史最優參數...")
        apply_params(learned["params"])

    # [E-11 修復] sleep_sec 在循環外初始化，防止首輪異常崩潰
    sleep_sec     = 30
    last_mode     = ""
    last_scenario = ""
    cycle         = 0

    while True:
        try:
            cycle += 1
            log.info(f"--- Cycle #{cycle} ---")

            rtt, loss  = get_rtt_and_loss()
            score      = calc_continuous_score(rtt, loss)
            mode_p     = get_mode_params(score)
            mode       = mode_p["mode"]
            sleep_sec  = mode_p["interval"]
            scenario   = detect_scenario()
            scenario_p = get_scenario_tuning(scenario)
            bdp        = estimate_bdp(rtt, assumed_bw)
            params     = build_params(
                             bdp, mode_p, scenario_p, assumed_bw
                         )

            # 只在模式或場景切換時應用參數（減少寫入頻率）
            if mode != last_mode or scenario != last_scenario:
                apply_params(params)
                log.info(
                    f"[SWITCH] "
                    f"Mode:{last_mode or 'init'}->{mode} | "
                    f"Scene:{last_scenario or 'init'}->{scenario}"
                )
                last_mode     = mode
                last_scenario = scenario
            else:
                log.info(
                    f"[STABLE] Mode:{mode} | Scene:{scenario}"
                )

            log.info(
                f"RTT={rtt:.1f}ms | Loss={loss:.1f}% | "
                f"Score={score:.2f} | "
                f"BDP={bdp // (1024 * 1024)}MB | "
                f"Mode={mode} | Scene={scenario} | "
                f"Next={sleep_sec}s"
            )

            save_learned_params(params, score, rtt, loss)
            write_health(rtt, loss, score, mode, scenario, bdp)

        except Exception as e:
            log.error(f"循環異常：{e}")

        finally:
            time.sleep(sleep_sec)


if __name__ == "__main__":
    main()
PYEOF

    chmod +x "$PY_ENGINE"
    log "Python 引擎寫入完成：${PY_ENGINE}" "OK"
}

# ================================================================
# ██  bash 降級引擎                                           ██
# ================================================================
bash_measure_rtt() {
    local targets=("8.8.8.8" "1.1.1.1" "114.114.114.114")
    local total=0
    local count=0
    local t r
    for t in "${targets[@]}"; do
        r="$(ping -c 3 -W 2 "$t" 2>/dev/null | \
             awk -F'/' 'END{ if ($5 != "") print int($5) }')"
        if [[ -n "$r" && "$r" -gt 0 ]]; then
            total=$((total + r))
            count=$((count + 1))
        fi
    done
    if [[ "$count" -gt 0 ]]; then
        echo $((total / count))
    else
        echo 80
    fi
}

bash_calc_score() {
    local rtt="${1:-80}"
    local loss="${2:-0}"
    loss="${loss%.*}"
    loss="${loss:-0}"
    local score=100
    if   [[ "$rtt"  -gt 200 ]]; then score=$((score - 40))
    elif [[ "$rtt"  -gt 100 ]]; then score=$((score - 20))
    elif [[ "$rtt"  -gt 50  ]]; then score=$((score - 10))
    fi
    if   [[ "$loss" -gt 5   ]]; then score=$((score - 40))
    elif [[ "$loss" -gt 2   ]]; then score=$((score - 25))
    elif [[ "$loss" -gt 0   ]]; then score=$((score - 10))
    fi
    [[ "$score" -lt 0 ]] && score=0
    echo "$score"
}

bash_select_algo() {
    local score="${1:-50}"
    local rtt="${2:-80}"
    if echo "$AVAILABLE_ALGOS" | grep -q "bbr" && \
       { [[ "$KERNEL_MAJOR" -ge 5 ]] || \
         { [[ "$KERNEL_MAJOR" -eq 4 ]] && \
           [[ "$KERNEL_MINOR" -ge 9 ]]; }; }; then
        echo "bbr"
        return
    fi
    if [[ "$rtt" -gt 150 ]] && \
       echo "$AVAILABLE_ALGOS" | grep -q "hybla"; then
        echo "hybla"
        return
    fi
    [[ "$score" -ge 80 ]] && echo "cubic" && return
    echo "$AVAILABLE_ALGOS" | grep -q "vegas" && \
        echo "vegas" && return
    echo "cubic"
}

bash_apply_sysctl() {
    local score="${1:-50}"
    local algo="${2:-cubic}"
    safe_sysctl "net.ipv4.tcp_congestion_control=${algo}"
    local buf
    if   [[ "$score" -ge 80 ]]; then buf=134217728
    elif [[ "$score" -ge 50 ]]; then buf=67108864
    else                              buf=33554432
    fi
    safe_sysctl "net.core.rmem_max=${buf}"
    safe_sysctl "net.core.wmem_max=${buf}"
    safe_sysctl "net.ipv4.tcp_rmem=4096 87380 ${buf}"
    safe_sysctl "net.ipv4.tcp_wmem=4096 65536 ${buf}"
    local p
    for p in \
        "net.ipv4.tcp_fastopen=3" \
        "net.ipv4.tcp_slow_start_after_idle=0" \
        "net.ipv4.tcp_mtu_probing=1" \
        "net.core.netdev_max_backlog=250000" \
        "net.core.somaxconn=65535" \
        "net.ipv4.tcp_max_syn_backlog=65535" \
        "net.ipv4.tcp_tw_reuse=1" \
        "net.ipv4.ip_local_port_range=1024 65535" \
        "net.ipv4.tcp_window_scaling=1" \
        "net.ipv4.tcp_adv_win_scale=1"; do
        safe_sysctl "$p"
    done
    local iface="${NET_IFACE:-}"
    if [[ -n "$iface" ]] && \
       ip link show "$iface" &>/dev/null 2>&1; then
        if [[ "$algo" == "bbr" ]]; then
            tc qdisc replace dev "$iface" root fq \
               2>/dev/null || true
        fi
    fi
}

# 異步丟包監測
start_loss_monitor() {
    if [[ -f "$LOSS_PID_FILE" ]]; then
        local old
        old="$(cat "$LOSS_PID_FILE" 2>/dev/null || echo '')"
        [[ -n "$old" ]] && kill "$old" &>/dev/null || true
        rm -f "$LOSS_PID_FILE"
    fi
    (
        while true; do
            local loss
            loss="$(ping -c 5 -W 2 8.8.8.8 2>/dev/null | \
                    awk '/packet loss/{ \
                         gsub(/%/, ""); print $6 }')"
            echo "${loss:-0}" > "$LOSS_CACHE"
            sleep 25
        done
    ) &
    echo $! > "$LOSS_PID_FILE"
    log "異步丟包監測啟動（PID:$!）" "OK"
}

get_cached_loss() {
    if [[ -f "$LOSS_CACHE" ]]; then
        cat "$LOSS_CACHE" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

stop_loss_monitor() {
    if [[ -f "$LOSS_PID_FILE" ]]; then
        local pid
        pid="$(cat "$LOSS_PID_FILE" 2>/dev/null || echo '')"
        [[ -n "$pid" ]] && kill "$pid" &>/dev/null || true
        rm -f "$LOSS_PID_FILE" "$LOSS_CACHE"
    fi
}

# [E-03 修復] local 聲明移至循環外
bash_monitor_mode() {
    echo "bash" > "$ENGINE_MODE_FILE"
    log "[Engine:bash] 進入監控模式..." "WARN"
    start_loss_monitor
    trap 'stop_loss_monitor; exit 0' SIGTERM SIGINT SIGHUP

    local last_algo=""
    local rtt=""
    local loss=""
    local score=""
    local algo=""

    while true; do
        rtt="$(bash_measure_rtt)"
        loss="$(get_cached_loss)"
        score="$(bash_calc_score "$rtt" "$loss")"
        algo="$(bash_select_algo "$score" "$rtt")"
        log "[bash] RTT:${rtt}ms Loss:${loss}% Score:${score} Algo:${algo}" \
            "INFO"
        if [[ "$algo" != "$last_algo" ]]; then
            log "[bash] Switch: ${last_algo:-init} -> ${algo}" "WARN"
            bash_apply_sysctl "$score" "$algo"
            last_algo="$algo"
        else
            log "[bash] Stable: ${last_algo}" "OK"
        fi
        sleep "$MONITOR_INTERVAL"
    done
}

# ================================================================
# ██  雙引擎啟動器                                            ██
# ================================================================
start_engine() {
    if [[ -n "$PYTHON_CMD" ]] && [[ -f "$PY_ENGINE" ]]; then
        log "啟動 Python 引擎（高精度模式）..." "OK"
        echo "python" > "$ENGINE_MODE_FILE"
        exec "$PYTHON_CMD" "$PY_ENGINE"
    else
        log "Python 不可用，啟動 bash 引擎（降級模式）..." "WARN"
        bash_monitor_mode
    fi
}

# ================================================================
# ██  持久化配置                                              ██
# ================================================================
save_config() {
    local algo="${1:-bbr}"
    mkdir -p "$CONFIG_DIR"
    cat > "$SYSCTL_CONF" << EOF
# ATTAS v${VERSION} - $(date)
net.ipv4.tcp_congestion_control = ${algo}
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 1
EOF
    sysctl -p "$SYSCTL_CONF" &>/dev/null || true
    log "配置持久化：${SYSCTL_CONF}" "OK"
}

# ================================================================
# ██  基準採集 & 報告                                         ██
# ================================================================
capture_baseline() {
    log "採集優化前基準數據..." "STEP"
    local b_algo b_rmem b_wmem b_rtt b_loss
    b_algo="$(cat /proc/sys/net/ipv4/tcp_congestion_control \
              2>/dev/null || echo 'unknown')"
    b_rmem="$(cat /proc/sys/net/core/rmem_max \
              2>/dev/null || echo 0)"
    b_wmem="$(cat /proc/sys/net/core/wmem_max \
              2>/dev/null || echo 0)"
    b_rtt="$(bash_measure_rtt)"
    b_loss="$(ping -c 5 -W 2 8.8.8.8 2>/dev/null | \
              awk '/packet loss/{ \
                   gsub(/%/, ""); print $6 }' || echo 0)"
    {
        echo "BASELINE_TIME='$(date '+%Y-%m-%d %H:%M:%S')'"
        echo "BASELINE_ALGO='${b_algo}'"
        echo "BASELINE_RMEM=${b_rmem}"
        echo "BASELINE_WMEM=${b_wmem}"
        echo "BASELINE_RTT=${b_rtt}"
        echo "BASELINE_LOSS=${b_loss:-0}"
    } > "$BASELINE_FILE"
    log "基準已保存：${BASELINE_FILE}" "OK"
}

show_benchmark_report() {
    if [[ ! -f "$BASELINE_FILE" ]]; then
        log "未找到基準數據，請先執行完整安裝" "WARN"
        return 1
    fi
    if grep -qvE '^[A-Z_]+=.*$' "$BASELINE_FILE" 2>/dev/null; then
        log "基準文件格式異常，拒絕加載" "ERR"
        return 1
    fi
    # shellcheck disable=SC1090
    source "$BASELINE_FILE"

    local cur_algo cur_rmem cur_rtt cur_loss
    local cur_rmem_mb base_rmem_mb engine_mode
    cur_algo="$(cat /proc/sys/net/ipv4/tcp_congestion_control \
                2>/dev/null || echo 'unknown')"
    cur_rmem="$(cat /proc/sys/net/core/rmem_max \
                2>/dev/null || echo 0)"
    cur_rtt="$(bash_measure_rtt)"
    cur_loss="$(ping -c 5 -W 2 8.8.8.8 2>/dev/null | \
               awk '/packet loss/{ \
                    gsub(/%/, ""); print $6 }' || echo 0)"
    cur_rmem_mb=$(( cur_rmem / 1024 / 1024 ))
    base_rmem_mb=$(( ${BASELINE_RMEM:-0} / 1024 / 1024 ))
    engine_mode="$(cat "$ENGINE_MODE_FILE" 2>/dev/null \
                   || echo 'unknown')"

    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "+--------------------------------+------------------+------------------+"
    echo "| ATTAS v${VERSION} Benchmark    |    Before        |    After         |"
    echo "+--------------------------------+------------------+------------------+"
    printf "| %-30s | %-16s | %-16s |\n" \
        "Congestion Algorithm" \
        "${BASELINE_ALGO:-unknown}" "${cur_algo}"
    printf "| %-30s | %-16s | %-16s |\n" \
        "Recv Buffer rmem_max" \
        "${base_rmem_mb}MB" "${cur_rmem_mb}MB"
    printf "| %-30s | %-16s | %-16s |\n" \
        "Average RTT" \
        "${BASELINE_RTT:-N/A}ms" "${cur_rtt}ms"
    printf "| %-30s | %-16s | %-16s |\n" \
        "Packet Loss" \
        "${BASELINE_LOSS:-0}%" "${cur_loss}%"
    printf "| %-30s | %-16s | %-16s |\n" \
        "Engine Mode" "-" "${engine_mode}"
    echo "+--------------------------------+------------------+------------------+"
    echo -e "${NC}"
    echo "Baseline : ${BASELINE_TIME:-unknown}"
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"

    if [[ -f "/tmp/attas_health.json" ]]; then
        echo ""
        echo -e "${YELLOW}--- Live Health (Python Engine) ---${NC}"
        cat /tmp/attas_health.json 2>/dev/null || true
        echo ""
    fi
}

# ================================================================
# ██  看門狗 & 服務安裝                                       ██
# ================================================================
install_watchdog() {
    [[ "$INIT_SYSTEM" != "systemd" ]] && return 0
    local log_path="$LOG_FILE"
    cat > "$WATCHDOG_FILE" << EOF
[Unit]
Description=ATTAS v${VERSION} Watchdog
After=attas.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do if ! systemctl is-active --quiet attas.service; then echo "[WATCHDOG] \$(date) restarting..." >> ${log_path}; systemctl restart attas.service; fi; sleep 60; done'
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable attas-watchdog.service &>/dev/null || true
    systemctl start  attas-watchdog.service &>/dev/null || true
    log "看門狗服務已啟動" "OK"
}

install_service() {
    log "安裝開機自啟服務（${INIT_SYSTEM}）..." "STEP"
    local real_script
    real_script="$(realpath "$0" 2>/dev/null || echo "$0")"
    cp "$real_script" "$BIN_PATH" && chmod +x "$BIN_PATH"

    case "$INIT_SYSTEM" in
        systemd)
            cat > "$SERVICE_FILE" << EOF
[Unit]
Description=ATTAS v${VERSION} Adaptive TCP Acceleration
After=network.target

[Service]
Type=simple
ExecStart=${BIN_PATH} --monitor
Restart=always
RestartSec=15
User=root
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable attas.service &>/dev/null || true
            systemctl start  attas.service &>/dev/null || true
            install_watchdog
            ;;

        openrc)
            cat > /etc/init.d/attas << EOF
#!/sbin/openrc-run
description="ATTAS v${VERSION} TCP Acceleration"
command="${BIN_PATH}"
command_args="--monitor"
pidfile="/run/attas.pid"
command_background=true
output_log="${LOG_FILE}"
error_log="${LOG_FILE}"
EOF
            chmod +x /etc/init.d/attas
            rc-update add attas default &>/dev/null || true
            rc-service attas start      &>/dev/null || true
            ;;

        runit)
            mkdir -p /etc/sv/attas
            cat > /etc/sv/attas/run << EOF
#!/bin/sh
exec ${BIN_PATH} --monitor 2>&1
EOF
            chmod +x /etc/sv/attas/run
            ln -sf /etc/sv/attas \
                   /var/service/attas 2>/dev/null || true
            ;;

        sysvinit)
            local bin_path="$BIN_PATH"
            local log_path="$LOG_FILE"
            cat > /etc/init.d/attas << 'SYSVINIT_EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          attas
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: ATTAS TCP Acceleration
### END INIT INFO
SYSVINIT_EOF
            cat >> /etc/init.d/attas << EOF
case "\$1" in
    start)
        ${bin_path} --monitor >> ${log_path} 2>&1 &
        echo "ATTAS started"
        ;;
    stop)
        pkill -f "attas --monitor" || true
        echo "ATTAS stopped"
        ;;
    restart)
        pkill -f "attas --monitor" || true
        sleep 1
        ${bin_path} --monitor >> ${log_path} 2>&1 &
        echo "ATTAS restarted"
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart}"
        exit 1
        ;;
esac
EOF
            chmod +x /etc/init.d/attas
            update-rc.d attas defaults 2>/dev/null || \
                chkconfig --add attas   2>/dev/null || true
            /etc/init.d/attas start
            ;;

        *)
            grep -q "attas --monitor" \
                 /etc/rc.local 2>/dev/null || \
                echo "${BIN_PATH} --monitor &" \
                     >> /etc/rc.local
            chmod +x /etc/rc.local 2>/dev/null || true
            ;;
    esac
    log "服務安裝完成" "OK"
}

# ================================================================
# ██  狀態顯示 & 卸載                                         ██
# ================================================================
show_status() {
    detect_os
    detect_kernel
    detect_init_system
    local engine_mode
    engine_mode="$(cat "$ENGINE_MODE_FILE" 2>/dev/null \
                   || echo 'unknown')"
    echo -e "${CYAN}${BOLD}"
    echo "+---------------------------------------------------+"
    echo "|         ATTAS v${VERSION} Status                 |"
    echo "+---------------------------------------------------+"
    echo -e "${NC}"
    printf "  %-22s %s\n" "OS:"          "${OS_ID} ${OS_VERSION}"
    printf "  %-22s %s\n" "Init:"        "${INIT_SYSTEM}"
    printf "  %-22s %s\n" "Container:"   "${IS_CONTAINER}"
    printf "  %-22s %s\n" "Interface:"   "${NET_IFACE:-unknown}"
    printf "  %-22s %s\n" "Engine:"      "${engine_mode}"
    printf "  %-22s %s\n" "Algorithm:"   \
        "$(cat /proc/sys/net/ipv4/tcp_congestion_control \
           2>/dev/null || echo 'unknown')"
    printf "  %-22s %s\n" "Avail Algos:" "${AVAILABLE_ALGOS}"
    printf "  %-22s %s\n" "TCP rmem:"    \
        "$(cat /proc/sys/net/ipv4/tcp_rmem \
           2>/dev/null || echo 'unknown')"
    printf "  %-22s %s\n" "TCP wmem:"    \
        "$(cat /proc/sys/net/ipv4/tcp_wmem \
           2>/dev/null || echo 'unknown')"
    printf "  %-22s %s\n" "ATTAS svc:"   \
        "$(systemctl is-active attas.service \
           2>/dev/null || echo 'not installed')"
    printf "  %-22s %s\n" "Watchdog:"    \
        "$(systemctl is-active attas-watchdog.service \
           2>/dev/null || echo 'not installed')"
    echo ""
    echo "--- Recent Logs (last 20 lines) ---"
    tail -20 "$LOG_FILE" 2>/dev/null || echo "(no logs yet)"
    echo ""
}

# [E-09 修復] rm -rf 前加非空守衛，防止路徑為空造成災難性刪除
safe_rm_rf() {
    local target="$1"
    if [[ -z "$target" ]] || \
       [[ "$target" == "/" ]] || \
       [[ "$target" == "/etc" ]] || \
       [[ "$target" == "/opt" ]] || \
       [[ "$target" == "/usr" ]]; then
        log "安全守衛：拒絕刪除危險路徑 ${target}" "ERR"
        return 1
    fi
    rm -rf "$target"
}

uninstall() {
    log "卸載 ATTAS v${VERSION}..." "WARN"
    stop_loss_monitor

    case "$INIT_SYSTEM" in
        systemd)
            local svc
            for svc in attas attas-watchdog; do
                systemctl stop    "${svc}.service" \
                    &>/dev/null || true
                systemctl disable "${svc}.service" \
                    &>/dev/null || true
            done
            rm -f "$SERVICE_FILE" "$WATCHDOG_FILE"
            systemctl daemon-reload &>/dev/null || true
            ;;
        openrc)
            rc-service attas stop   &>/dev/null || true
            rc-update  del attas    &>/dev/null || true
            rm -f /etc/init.d/attas
            ;;
        runit)
            rm -f /var/service/attas
            safe_rm_rf /etc/sv/attas
            ;;
        sysvinit)
            /etc/init.d/attas stop   &>/dev/null || true
            update-rc.d attas remove &>/dev/null || true
            rm -f /etc/init.d/attas
            ;;
        *)
            pkill -f "attas --monitor" &>/dev/null || true
            ;;
    esac

    rm -f "$SYSCTL_CONF" "$BIN_PATH" "$MODULES_CONF"
    rm -f "$ENGINE_MODE_FILE" "$LOSS_CACHE" "$LOSS_PID_FILE"

    # [E-09 修復] 使用 safe_rm_rf 替代裸 rm -rf
    safe_rm_rf "$CONFIG_DIR"
    safe_rm_rf "$INSTALL_DIR"

    sysctl -p &>/dev/null || true
    log "ATTAS 已完全卸載" "OK"
}

# ================================================================
# ██  主入口                                                  ██
# ================================================================
main() {
    setup_colors
    ensure_dirs
    ensure_self_on_disk "$@"
    check_bash_version
    print_banner
    check_for_updates
    check_root "$@"

    # [E-06 修復] local 聲明移至 case 語句前
    local RTT LOSS SCORE ALGO

    case "${1:-install}" in
        --monitor)
            detect_os
            detect_kernel
            start_engine
            ;;
        --monitor-bash)
            detect_os
            detect_kernel
            bash_monitor_mode
            ;;
        --status)
            show_status
            ;;
        --report)
            show_benchmark_report
            ;;
        --health)
            cat /tmp/attas_health.json 2>/dev/null || \
                echo '{"status":"not running"}'
            ;;
        --check-deps)
            detect_os
            test_connectivity
            check_repo_and_mirror
            run_dependency_check
            ;;
        --uninstall)
            detect_os
            detect_init_system
            uninstall
            ;;
        install|*)
            ensure_bash "$@"
            detect_container
            detect_os
            detect_init_system
            detect_kernel
            test_connectivity
            check_repo_and_mirror
            run_dependency_check
            write_python_engine
            capture_baseline

            log "初始網絡評估..." "STEP"
            RTT="$(bash_measure_rtt)"
            LOSS="$(ping -c 5 -W 2 8.8.8.8 2>/dev/null | \
                    awk '/packet loss/{ \
                         gsub(/%/, ""); print $6 }' || echo 0)"
            SCORE="$(bash_calc_score "$RTT" "$LOSS")"
            ALGO="$(bash_select_algo "$SCORE" "$RTT")"

            log "RTT:${RTT}ms Loss:${LOSS}% Score:${SCORE} Algo:${ALGO}" \
                "OK"

            bash_apply_sysctl "$SCORE" "$ALGO"
            save_config "$ALGO"
            install_service

            echo ""
            echo -e "${GREEN}${BOLD}"
            echo "+---------------------------------------------+"
            echo "|  ATTAS v${VERSION} Installation Done!      |"
            echo "+---------------------------------------------+"
            echo -e "${NC}"
            local em
            em="$(cat "$ENGINE_MODE_FILE" 2>/dev/null \
                  || echo 'unknown')"
            echo "  Engine   : ${em}"
            echo "  Status   : attas --status"
            echo "  Report   : attas --report"
            echo "  Health   : attas --health"
            echo "  Deps     : attas --check-deps"
            echo "  Uninstall: attas --uninstall"
            echo "  Log      : ${LOG_FILE}"
            echo ""
            echo -e "${YELLOW}5 分鐘後執行 'attas --report' 查看優化對比${NC}"
            echo -e "${YELLOW}執行 'attas --health' 查看引擎實時狀態${NC}"
            echo ""
            ;;
    esac
}

main "$@"
