#!/usr/bin/env bash
#====================================================================
#     _    ____  _______  __  _____ ____ ____
#    / \  |  _ \| ____\ \/ / |_   _/ ___|  _ \
#   / _ \ | |_) |  _|  \  /    | || |   | |_) |
#  / ___ \|  __/| |___ /  \    | || |___|  __/
# /_/   \_\_|   |_____/_/\_\   |_| \____|_|
#
#  APEX TCP Accelerator v2.2 Final — 自适应参数动态调优
#  适配: Ubuntu/Debian/CentOS/RHEL/AlmaLinux/Rocky/Fedora/Alpine/Arch
#       OpenVZ/LXC/Docker/KVM/VMware/Hyper-V/AWS/GCP/Azure
#       内核 2.6.32 ~ 6.x+
#  原理: 感知硬件 -> 测算BDP -> safe_write过滤 -> 持久化
#====================================================================

set -uo pipefail

# ==================== 颜色与常量 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SYSCTL_CONF="/etc/sysctl.d/99-apex-tcp.conf"
BACKUP_DIR="/etc/apex-tcp-backup"
LOG_FILE="/var/log/apex-tcp.log"
VERSION="2.2.0"

# ==================== 感知层变量 ====================
TOTAL_MEM_KB=0
TOTAL_MEM_MB=0
CPU_CORES=0
ARCH=""
VIRT_TYPE="unknown"
NIC_NAME=""
NIC_SPEED=0
NIC_MTU=1500
KERNEL_MAJOR=0
KERNEL_MINOR=0
ESTIMATED_BW=0
ESTIMATED_RTT=0
BDP_BYTES=0
OS_ID="unknown"
OS_LIKE="unknown"
PKG_MGR="unknown"

# ==================== 推理层变量 ====================
RMEM_MAX=0
WMEM_MAX=0
TCP_RMEM_MAX=0
TCP_WMEM_MAX=0
TCP_RMEM_DEFAULT=0
TCP_WMEM_DEFAULT=0
NETDEV_BUDGET=0
SOMAXCONN=0
BACKLOG=0
CC_ALGO=""
QDISC=""
CONNTRACK_MAX=0
TW_REUSE=0
FIN_TIMEOUT=0
KEEPALIVE_TIME=0
KEEPALIVE_INTVL=0
KEEPALIVE_PROBES=0
SYNACK_RETRIES=0
ORPHAN_RETRIES=0
MAX_TW_BUCKETS=0
MAX_SYN_BACKLOG=0
TCP_FASTOPEN_VAL=0
FILE_MAX=0
NR_OPEN=0
NF_AVAILABLE=0

# ==================== 工具函数 ====================

log_msg() {
    local level="$1"
    shift
    local msg="$*"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown")
    echo "[$ts] [$level] $msg" >> "$LOG_FILE" 2>/dev/null || true
}

print_banner() {
    echo -e "${CYAN}"
    echo "  +===================================================+"
    echo "  |         APEX TCP Accelerator v${VERSION}              |"
    echo "  |     自适应参数动态调优 - 全系统通用 - Final        |"
    echo "  +===================================================+"
    echo "  |  感知硬件 -> 测算BDP -> 计算参数 -> 持久化生效     |"
    echo "  +===================================================+"
    echo -e "${NC}"
}

info()    { echo -e "  ${GREEN}[+]${NC} $*"; }
warn()    { echo -e "  ${YELLOW}[!]${NC} $*"; }
errlog()  { echo -e "  ${RED}[x]${NC} $*"; }
section() { echo -e "\n${BOLD}${BLUE}--- $* ---${NC}"; }
detail()  { echo -e "      ${CYAN}->${NC} $*"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        errlog "请以root权限运行: sudo bash $0"
        exit 1
    fi
}

# 安全的算术自增(避免 ((var++)) 在var=0时返回exit code 1)
safe_incr() {
    local _varname="$1"
    eval "$_varname=\$(( ${!_varname} + 1 ))"
}

# ==================== 模块1: 系统感知层 ====================

detect_os() {
    section "系统感知层"

    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_LIKE="${ID_LIKE:-${OS_ID}}"
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="centos"
        OS_LIKE="rhel"
    elif [[ -f /etc/alpine-release ]]; then
        OS_ID="alpine"
        OS_LIKE="alpine"
    else
        OS_ID="unknown"
        OS_LIKE="unknown"
    fi

    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
    elif command -v apk &>/dev/null; then
        PKG_MGR="apk"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
    elif command -v zypper &>/dev/null; then
        PKG_MGR="zypper"
    else
        PKG_MGR="unknown"
    fi

    info "发行版: ${BOLD}${OS_ID}${NC} (系列: ${OS_LIKE}) | 包管理: ${PKG_MGR}"
}

detect_kernel() {
    local kver
    kver=$(uname -r 2>/dev/null || echo "0.0.0")

    local major minor
    major=$(echo "$kver" | cut -d. -f1)
    minor=$(echo "$kver" | cut -d. -f2)

    if [[ "$major" =~ ^[0-9]+$ ]]; then
        KERNEL_MAJOR=$major
    else
        KERNEL_MAJOR=0
    fi
    if [[ "$minor" =~ ^[0-9]+$ ]]; then
        KERNEL_MINOR=$minor
    else
        KERNEL_MINOR=0
    fi

    ARCH=$(uname -m 2>/dev/null || echo "unknown")

    info "内核: ${BOLD}${kver}${NC} (${KERNEL_MAJOR}.${KERNEL_MINOR}) | 架构: ${ARCH}"

    if (( KERNEL_MAJOR < 4 || (KERNEL_MAJOR == 4 && KERNEL_MINOR < 9) )); then
        warn "内核低于4.9, BBR不可用, 将使用备选方案"
    fi
}

detect_virtualization() {
    VIRT_TYPE="bare-metal"

    # 方法1: systemd
    if command -v systemd-detect-virt &>/dev/null; then
        local detected
        detected=$(systemd-detect-virt 2>/dev/null || echo "none")
        if [[ -n "$detected" && "$detected" != "none" ]]; then
            VIRT_TYPE="$detected"
            info "虚拟化: ${BOLD}${VIRT_TYPE}${NC} (systemd-detect-virt)"
            return
        fi
    fi

    # 方法2: /proc/cpuinfo
    if [[ -f /proc/cpuinfo ]]; then
        if grep -qi "kvm\|qemu" /proc/cpuinfo 2>/dev/null; then
            VIRT_TYPE="kvm"
        elif grep -qi "hypervisor" /proc/cpuinfo 2>/dev/null; then
            VIRT_TYPE="vm-generic"
        fi
    fi

    # 方法3: DMI
    if [[ "$VIRT_TYPE" == "bare-metal" && -f /sys/class/dmi/id/product_name ]]; then
        local product
        product=$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo "")
        case "$product" in
            *"Virtual Machine"*) VIRT_TYPE="hyperv" ;;
            *"VMware"*)          VIRT_TYPE="vmware" ;;
            *"OpenStack"*)       VIRT_TYPE="openstack" ;;
            *"Alibaba"*)         VIRT_TYPE="alibaba-cloud" ;;
            *"Google"*)          VIRT_TYPE="gcp" ;;
        esac
    fi

    # 方法4: OpenVZ
    if [[ -d /proc/vz && ! -d /proc/bc ]]; then
        VIRT_TYPE="openvz"
    fi

    # 方法5: 容器
    if [[ -f /proc/1/cgroup ]]; then
        if grep -q "docker\|lxc\|kubepods\|containerd" /proc/1/cgroup 2>/dev/null; then
            VIRT_TYPE="container"
        fi
    fi
    if [[ -f /.dockerenv ]]; then
        VIRT_TYPE="container"
    fi

    info "虚拟化: ${BOLD}${VIRT_TYPE}${NC}"
}

detect_hardware() {
    # CPU
    CPU_CORES=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)
    if [[ ! "$CPU_CORES" =~ ^[0-9]+$ ]] || (( CPU_CORES < 1 )); then
        CPU_CORES=1
    fi

    # 内存
    TOTAL_MEM_KB=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    if [[ ! "$TOTAL_MEM_KB" =~ ^[0-9]+$ ]] || (( TOTAL_MEM_KB == 0 )); then
        TOTAL_MEM_KB=524288
        warn "内存检测失败, 默认512MB"
    fi
    TOTAL_MEM_MB=$((TOTAL_MEM_KB / 1024))

    info "CPU: ${BOLD}${CPU_CORES}核${NC} | 内存: ${BOLD}${TOTAL_MEM_MB}MB${NC}"
}

detect_network() {
    # 主网卡
    NIC_NAME=""
    if command -v ip &>/dev/null; then
        NIC_NAME=$(ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}')
    fi
    if [[ -z "$NIC_NAME" ]]; then
        NIC_NAME=$(ls /sys/class/net/ 2>/dev/null | grep -v lo | head -1 || echo "")
    fi
    if [[ -z "$NIC_NAME" ]]; then
        NIC_NAME="eth0"
        warn "无法检测网卡, 默认 eth0"
    fi

    # 网卡速率
    NIC_SPEED=0
    if [[ -f "/sys/class/net/${NIC_NAME}/speed" ]]; then
        local raw_speed
        raw_speed=$(cat "/sys/class/net/${NIC_NAME}/speed" 2>/dev/null | tr -dc '0-9-' || echo "0")
        if [[ "$raw_speed" =~ ^-?[0-9]+$ ]]; then
            NIC_SPEED=$raw_speed
        fi
    fi
    if (( NIC_SPEED <= 0 || NIC_SPEED > 100000 )); then
        case "$VIRT_TYPE" in
            kvm|openstack|alibaba-cloud|gcp) NIC_SPEED=1000 ;;
            openvz|container)                NIC_SPEED=1000 ;;
            vmware)                          NIC_SPEED=10000 ;;
            *)                               NIC_SPEED=1000 ;;
        esac
        detail "网卡速率未知, 按虚拟化类型估算: ${NIC_SPEED}Mbps"
    fi

    # MTU
    NIC_MTU=1500
    if [[ -f "/sys/class/net/${NIC_NAME}/mtu" ]]; then
        local raw_mtu
        raw_mtu=$(cat "/sys/class/net/${NIC_NAME}/mtu" 2>/dev/null | tr -dc '0-9' || echo "1500")
        if [[ "$raw_mtu" =~ ^[0-9]+$ ]] && (( raw_mtu > 0 )); then
            NIC_MTU=$raw_mtu
        fi
    fi

    info "网卡: ${BOLD}${NIC_NAME}${NC} | 速率: ${NIC_SPEED}Mbps | MTU: ${NIC_MTU}"
}

estimate_bdp() {
    ESTIMATED_RTT=${APEX_RTT:-0}
    ESTIMATED_BW=${APEX_BW:-${NIC_SPEED}}

    # RTT实测
    if (( ESTIMATED_RTT == 0 )); then
        local rtt_result=0
        local target
        for target in 8.8.8.8 1.1.1.1 9.9.9.9; do
            if command -v ping &>/dev/null; then
                local rtt_line
                rtt_line=$(LC_ALL=C ping -c 3 -W 2 "$target" 2>/dev/null | tail -1 || echo "")
                if [[ "$rtt_line" == *"/"* ]]; then
                    local parsed
                    parsed=$(echo "$rtt_line" | awk -F'/' '{printf "%.0f", $5}' 2>/dev/null || echo "0")
                    if [[ "$parsed" =~ ^[0-9]+$ ]] && (( parsed > 0 && parsed < 5000 )); then
                        rtt_result=$parsed
                        break
                    fi
                fi
            fi
        done

        if (( rtt_result > 0 )); then
            ESTIMATED_RTT=$rtt_result
        else
            ESTIMATED_RTT=50
            detail "RTT探测失败, 使用默认值: 50ms"
        fi
    fi

    # BDP计算
    local bw_bytes_sec=$(( ESTIMATED_BW * 125000 ))
    BDP_BYTES=$(( bw_bytes_sec * ESTIMATED_RTT / 1000 ))

    # 边界
    if (( BDP_BYTES < 65536 )); then
        BDP_BYTES=65536
    fi
    if (( BDP_BYTES > 268435456 )); then
        BDP_BYTES=268435456
    fi

    info "带宽: ${BOLD}${ESTIMATED_BW}Mbps${NC} | RTT: ${BOLD}${ESTIMATED_RTT}ms${NC}"
    info "BDP: ${BOLD}$((BDP_BYTES / 1024))KB${NC} ($((BDP_BYTES / 1024 / 1024))MB)"
}

# ==================== 模块2: 推理引擎 ====================

calculate_params() {
    section "推理引擎 -- 动态计算参数"

    if [[ "$VIRT_TYPE" == "openvz" ]]; then
        warn "OpenVZ环境: 大部分内核参数不可修改, 失败项将跳过"
    fi
    if [[ "$VIRT_TYPE" == "container" ]]; then
        warn "容器环境: 部分参数受namespace限制, 失败项将跳过"
    fi

    calc_buffers
    calc_congestion
    calc_queue
    calc_connection
    calc_keepalive
    calc_conntrack
    calc_file_limits
}

calc_buffers() {
    # Socket缓冲区上限: min(BDP*4, 内存5%)
    local mem_limit=$((TOTAL_MEM_KB * 1024 / 20))
    local bdp_limit=$((BDP_BYTES * 4))

    RMEM_MAX=$bdp_limit
    if (( RMEM_MAX > mem_limit )); then
        RMEM_MAX=$mem_limit
    fi
    if (( RMEM_MAX < 212992 )); then
        RMEM_MAX=212992
    fi
    if (( RMEM_MAX > 134217728 )); then
        RMEM_MAX=134217728
    fi
    WMEM_MAX=$RMEM_MAX

    # TCP三元组
    TCP_RMEM_DEFAULT=$BDP_BYTES
    if (( TCP_RMEM_DEFAULT < 87380 )); then
        TCP_RMEM_DEFAULT=87380
    fi

    TCP_RMEM_MAX=$((BDP_BYTES * 4))
    if (( TCP_RMEM_MAX < 6291456 )); then
        TCP_RMEM_MAX=6291456
    fi
    if (( TCP_RMEM_MAX > RMEM_MAX )); then
        TCP_RMEM_MAX=$RMEM_MAX
    fi

    TCP_WMEM_DEFAULT=$TCP_RMEM_DEFAULT
    TCP_WMEM_MAX=$TCP_RMEM_MAX

    detail "缓冲区: default=$((TCP_RMEM_DEFAULT / 1024))K | max=$((TCP_RMEM_MAX / 1024 / 1024))MB"
}

calc_congestion() {
    CC_ALGO="cubic"

    if (( KERNEL_MAJOR > 4 || (KERNEL_MAJOR == 4 && KERNEL_MINOR >= 9) )); then
        modprobe tcp_bbr 2>/dev/null || true
        sleep 0.3
        local avail
        avail=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || echo "")
        if echo "$avail" | grep -qw "bbr"; then
            CC_ALGO="bbr"
        fi
    fi

    # OpenVZ: 验证是否真的能设置
    if [[ "$VIRT_TYPE" == "openvz" && "$CC_ALGO" == "bbr" ]]; then
        if ! sysctl -w net.ipv4.tcp_congestion_control=bbr &>/dev/null; then
            CC_ALGO=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "cubic")
            warn "OpenVZ无法设置BBR, 保持: ${CC_ALGO}"
        fi
    fi

    # 队列调度
    QDISC="fq"
    if [[ "$CC_ALGO" != "bbr" ]]; then
        QDISC="fq_codel"
    fi

    detail "拥塞控制: ${BOLD}${CC_ALGO}${NC} | 队列: ${QDISC}"
}

calc_queue() {
    BACKLOG=$((CPU_CORES * 1000 + ESTIMATED_BW * 10))
    if (( BACKLOG < 1000 )); then BACKLOG=1000; fi
    if (( BACKLOG > 65536 )); then BACKLOG=65536; fi

    NETDEV_BUDGET=$((300 + CPU_CORES * 100))
    if (( NETDEV_BUDGET > 2000 )); then NETDEV_BUDGET=2000; fi

    detail "Backlog: ${BACKLOG} | NETDEV Budget: ${NETDEV_BUDGET}"
}

calc_connection() {
    if   (( TOTAL_MEM_MB >= 4096 )); then SOMAXCONN=65535
    elif (( TOTAL_MEM_MB >= 2048 )); then SOMAXCONN=32768
    elif (( TOTAL_MEM_MB >= 1024 )); then SOMAXCONN=16384
    elif (( TOTAL_MEM_MB >= 512  )); then SOMAXCONN=8192
    else                                  SOMAXCONN=4096
    fi
    MAX_SYN_BACKLOG=$SOMAXCONN

    TW_REUSE=1
    MAX_TW_BUCKETS=$((SOMAXCONN * 2))
    FIN_TIMEOUT=15

    if   (( ESTIMATED_RTT <= 30  )); then SYNACK_RETRIES=2
    elif (( ESTIMATED_RTT <= 100 )); then SYNACK_RETRIES=3
    else                                  SYNACK_RETRIES=5
    fi
    ORPHAN_RETRIES=2

    TCP_FASTOPEN_VAL=3
    if (( KERNEL_MAJOR < 3 || (KERNEL_MAJOR == 3 && KERNEL_MINOR < 7) )); then
        TCP_FASTOPEN_VAL=0
    fi

    detail "SOMAXCONN: ${SOMAXCONN} | FIN: ${FIN_TIMEOUT}s | TFO: ${TCP_FASTOPEN_VAL}"
}

calc_keepalive() {
    KEEPALIVE_TIME=300
    KEEPALIVE_INTVL=30
    KEEPALIVE_PROBES=3

    if (( TOTAL_MEM_MB < 512 )); then
        KEEPALIVE_TIME=120
        KEEPALIVE_INTVL=15
    fi

    detail "Keepalive: ${KEEPALIVE_TIME}s / ${KEEPALIVE_INTVL}s / ${KEEPALIVE_PROBES}次"
}

calc_conntrack() {
    NF_AVAILABLE=0
    if [[ -f /proc/sys/net/netfilter/nf_conntrack_max ]]; then
        NF_AVAILABLE=1
    else
        modprobe nf_conntrack 2>/dev/null || true
        if [[ -f /proc/sys/net/netfilter/nf_conntrack_max ]]; then
            NF_AVAILABLE=1
        fi
    fi

    if (( NF_AVAILABLE == 1 )); then
        CONNTRACK_MAX=$((TOTAL_MEM_KB * 1024 / 320 / 4))
        if (( CONNTRACK_MAX < 65536 )); then CONNTRACK_MAX=65536; fi
        if (( CONNTRACK_MAX > 2097152 )); then CONNTRACK_MAX=2097152; fi
        detail "Conntrack: ${CONNTRACK_MAX}"
    fi
}

calc_file_limits() {
    FILE_MAX=$((TOTAL_MEM_KB * 1024 / 4096))
    if (( FILE_MAX < 65536 )); then FILE_MAX=65536; fi
    if (( FILE_MAX > 6553560 )); then FILE_MAX=6553560; fi

    # nr_open: 必须 <= file-max 且 <= 内核硬上限
    NR_OPEN=$FILE_MAX
    if (( NR_OPEN > 1048576 )); then
        NR_OPEN=1048576
    fi

    detail "file-max: ${FILE_MAX} | nr_open: ${NR_OPEN}"
}

# ==================== 模块3: 执行引擎 ====================

# 核心: safe_write — 检测 /proc/sys 路径存在才写入
safe_write() {
    local key="$1"
    local val="$2"
    local conf_file="$3"
    local proc_path="/proc/sys/$(echo "$key" | tr '.' '/')"

    if [[ -e "$proc_path" ]]; then
        echo "$key = $val" >> "$conf_file"
        return 0
    else
        log_msg "SKIP" "参数不存在: $key -> $proc_path"
        return 1
    fi
}

ensure_sysctl_d() {
    # CentOS 6 可能没有 sysctl.d 支持
    mkdir -p /etc/sysctl.d 2>/dev/null || true

    # 测试 sysctl --system 是否可用
    if ! sysctl --system &>/dev/null 2>&1; then
        SYSCTL_CONF="/etc/sysctl.conf"
        warn "sysctl.d 不可用, 降级写入: ${SYSCTL_CONF}"
        if [[ -f "$SYSCTL_CONF" ]]; then
            cp "$SYSCTL_CONF" "${BACKUP_DIR}/sysctl.conf.orig.$(date +%s)" 2>/dev/null || true
        fi
    fi
}

backup_current() {
    section "备份当前配置"

    mkdir -p "$BACKUP_DIR" 2>/dev/null || true
    local ts
    ts=$(date '+%Y%m%d_%H%M%S' 2>/dev/null || echo "000000")
    local backup_file="${BACKUP_DIR}/sysctl_backup_${ts}.conf"

    {
        echo "# APEX TCP backup - ${ts}"
        echo "# uname: $(uname -a 2>/dev/null || echo unknown)"
        echo ""
        local key
        for key in \
            net.ipv4.tcp_congestion_control \
            net.core.default_qdisc \
            net.core.rmem_max \
            net.core.wmem_max \
            net.core.rmem_default \
            net.core.wmem_default \
            net.ipv4.tcp_rmem \
            net.ipv4.tcp_wmem \
            net.ipv4.tcp_mem \
            net.core.somaxconn \
            net.ipv4.tcp_max_syn_backlog \
            net.ipv4.tcp_tw_reuse \
            net.ipv4.tcp_fin_timeout \
            net.ipv4.tcp_fastopen \
            net.ipv4.tcp_keepalive_time \
            net.ipv4.tcp_slow_start_after_idle \
            net.core.netdev_max_backlog \
            net.core.netdev_budget \
            fs.file-max; do
            local val
            val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
            echo "$key = $val"
        done
    } > "$backup_file"

    if [[ -f "$SYSCTL_CONF" ]]; then
        cp "$SYSCTL_CONF" "${BACKUP_DIR}/99-apex-tcp_${ts}.conf.bak" 2>/dev/null || true
    fi

    info "备份: ${backup_file}"
}

generate_sysctl() {
    section "生成优化配置"

    local conf="$SYSCTL_CONF"
    local skipped=0

    # 写入头部
    cat > "$conf" << HEADER_EOF
#====================================================================
# APEX TCP Accelerator v${VERSION} - Final
# 生成: $(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown")
# 系统: ${OS_ID} | 内核: $(uname -r 2>/dev/null || echo "unknown")
# 虚拟化: ${VIRT_TYPE} | 硬件: ${CPU_CORES}C ${TOTAL_MEM_MB}MB
# 网卡: ${NIC_NAME} ${NIC_SPEED}Mbps MTU:${NIC_MTU}
# BDP: $((BDP_BYTES / 1024))KB (BW=${ESTIMATED_BW}Mbps RTT=${ESTIMATED_RTT}ms)
# 仅写入当前内核支持的参数 (safe_write过滤)
#====================================================================

HEADER_EOF

    # --- 拥塞控制 ---
    echo "#--- 拥塞控制 ---" >> "$conf"
    safe_write "net.ipv4.tcp_congestion_control" "$CC_ALGO" "$conf" || safe_incr skipped
    safe_write "net.core.default_qdisc" "$QDISC" "$conf" || safe_incr skipped

    # --- Socket缓冲区 ---
    echo "" >> "$conf"
    echo "#--- Socket缓冲区 (BDP自适应) ---" >> "$conf"
    safe_write "net.core.rmem_max" "$RMEM_MAX" "$conf" || safe_incr skipped
    safe_write "net.core.wmem_max" "$WMEM_MAX" "$conf" || safe_incr skipped
    safe_write "net.core.rmem_default" "$TCP_RMEM_DEFAULT" "$conf" || safe_incr skipped
    safe_write "net.core.wmem_default" "$TCP_WMEM_DEFAULT" "$conf" || safe_incr skipped

    # --- TCP缓冲区三元组 ---
    echo "" >> "$conf"
    echo "#--- TCP缓冲区三元组 (min/default/max) ---" >> "$conf"
    safe_write "net.ipv4.tcp_rmem" "4096 ${TCP_RMEM_DEFAULT} ${TCP_RMEM_MAX}" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_wmem" "4096 ${TCP_WMEM_DEFAULT} ${TCP_WMEM_MAX}" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_mem" "$((TOTAL_MEM_KB / 8)) $((TOTAL_MEM_KB / 4)) $((TOTAL_MEM_KB / 2))" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_moderate_rcvbuf" "1" "$conf" || safe_incr skipped

    # --- 窗口与协议 ---
    echo "" >> "$conf"
    echo "#--- 窗口/协议 ---" >> "$conf"
    safe_write "net.ipv4.tcp_window_scaling" "1" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_timestamps" "1" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_sack" "1" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_dsack" "1" "$conf" || safe_incr skipped

    # --- 连接管理 ---
    echo "" >> "$conf"
    echo "#--- 连接管理 (内存自适应) ---" >> "$conf"
    safe_write "net.core.somaxconn" "$SOMAXCONN" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_max_syn_backlog" "$MAX_SYN_BACKLOG" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_abort_on_overflow" "0" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_max_tw_buckets" "$MAX_TW_BUCKETS" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_tw_reuse" "$TW_REUSE" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_fin_timeout" "$FIN_TIMEOUT" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_synack_retries" "$SYNACK_RETRIES" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_syn_retries" "$SYNACK_RETRIES" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_orphan_retries" "$ORPHAN_RETRIES" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_max_orphans" "$((SOMAXCONN * 2))" "$conf" || safe_incr skipped

    # --- TCP Fast Open ---
    if (( TCP_FASTOPEN_VAL > 0 )); then
        echo "" >> "$conf"
        echo "#--- TCP Fast Open ---" >> "$conf"
        safe_write "net.ipv4.tcp_fastopen" "$TCP_FASTOPEN_VAL" "$conf" || safe_incr skipped
    fi

    # --- Keepalive ---
    echo "" >> "$conf"
    echo "#--- Keepalive ---" >> "$conf"
    safe_write "net.ipv4.tcp_keepalive_time" "$KEEPALIVE_TIME" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_keepalive_intvl" "$KEEPALIVE_INTVL" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_keepalive_probes" "$KEEPALIVE_PROBES" "$conf" || safe_incr skipped

    # --- 网卡/中断 ---
    echo "" >> "$conf"
    echo "#--- 网卡 (CPU自适应) ---" >> "$conf"
    safe_write "net.core.netdev_max_backlog" "$BACKLOG" "$conf" || safe_incr skipped
    safe_write "net.core.netdev_budget" "$NETDEV_BUDGET" "$conf" || safe_incr skipped
    safe_write "net.core.netdev_budget_usecs" "$((NETDEV_BUDGET * 4))" "$conf" || safe_incr skipped

    # --- MTU探测 ---
    echo "" >> "$conf"
    echo "#--- MTU探测 ---" >> "$conf"
    safe_write "net.ipv4.tcp_mtu_probing" "1" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_base_mss" "1024" "$conf" || safe_incr skipped

    # --- 其他优化 ---
    echo "" >> "$conf"
    echo "#--- 其他优化 ---" >> "$conf"
    safe_write "net.ipv4.tcp_slow_start_after_idle" "0" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_no_metrics_save" "1" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_ecn" "2" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_ecn_fallback" "1" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_retries2" "8" "$conf" || safe_incr skipped
    safe_write "net.ipv4.ip_local_port_range" "1024 65535" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_autocorking" "1" "$conf" || safe_incr skipped
    safe_write "net.ipv4.tcp_notsent_lowat" "16384" "$conf" || safe_incr skipped

    # --- 文件描述符 ---
    echo "" >> "$conf"
    echo "#--- 文件描述符 ---" >> "$conf"
    safe_write "fs.file-max" "$FILE_MAX" "$conf" || safe_incr skipped

    # --- IPv6 ---
    echo "" >> "$conf"
    echo "#--- IPv6 ---" >> "$conf"
    safe_write "net.ipv6.conf.all.disable_ipv6" "0" "$conf" || safe_incr skipped
    safe_write "net.ipv6.conf.default.disable_ipv6" "0" "$conf" || safe_incr skipped

    # --- 安全加固 ---
    echo "" >> "$conf"
    echo "#--- 安全 ---" >> "$conf"
    safe_write "net.ipv4.conf.all.rp_filter" "1" "$conf" || safe_incr skipped
    safe_write "net.ipv4.conf.default.rp_filter" "1" "$conf" || safe_incr skipped
    safe_write "net.ipv4.icmp_echo_ignore_broadcasts" "1" "$conf" || safe_incr skipped
    safe_write "net.ipv4.conf.all.accept_redirects" "0" "$conf" || safe_incr skipped
    safe_write "net.ipv4.conf.default.accept_redirects" "0" "$conf" || safe_incr skipped

    # --- Conntrack ---
    if (( NF_AVAILABLE == 1 )); then
        echo "" >> "$conf"
        echo "#--- Conntrack ---" >> "$conf"
        safe_write "net.netfilter.nf_conntrack_max" "$CONNTRACK_MAX" "$conf" || safe_incr skipped
        safe_write "net.netfilter.nf_conntrack_tcp_timeout_established" "7200" "$conf" || safe_incr skipped
        safe_write "net.netfilter.nf_conntrack_tcp_timeout_time_wait" "30" "$conf" || safe_incr skipped
        safe_write "net.netfilter.nf_conntrack_tcp_timeout_fin_wait" "15" "$conf" || safe_incr skipped
        safe_write "net.netfilter.nf_conntrack_tcp_timeout_close_wait" "15" "$conf" || safe_incr skipped
    fi

    local total_written
    total_written=$(grep -c '=' "$conf" 2>/dev/null || echo 0)

    info "已写入: ${conf}"
    info "参数: ${total_written}个生效 | ${skipped}个因内核不支持跳过"
}

apply_live() {
    section "应用配置"

    # 加载模块
    if [[ "$CC_ALGO" == "bbr" ]]; then
        modprobe tcp_bbr 2>/dev/null || true
    fi

    # 逐行应用
    local errors=0
    local applied=0
    local line key val

    while IFS= read -r line; do
        # 跳过注释和空行
        case "$line" in
            "#"*|"") continue ;;
        esac
        # 跳过纯空白行
        local trimmed
        trimmed=$(echo "$line" | tr -d '[:space:]')
        if [[ -z "$trimmed" ]]; then
            continue
        fi

        # 解析 key = value
        key=$(echo "$line" | sed 's/[[:space:]]*=.*//' | sed 's/^[[:space:]]*//')
        val=$(echo "$line" | sed 's/[^=]*=[[:space:]]*//')

        if [[ -n "$key" && -n "$val" ]]; then
            if sysctl -w "${key}=${val}" &>/dev/null; then
                safe_incr applied
            else
                safe_incr errors
                log_msg "FAIL" "sysctl -w ${key}=${val}"
            fi
        fi
    done < "$SYSCTL_CONF"

    # 队列调度
    if command -v tc &>/dev/null && [[ -n "$NIC_NAME" ]]; then
        tc qdisc replace dev "$NIC_NAME" root "$QDISC" 2>/dev/null || true
        detail "队列 ${QDISC} -> ${NIC_NAME}"
    fi

    info "生效: ${applied}个 | 失败: ${errors}个"
    if (( errors > 0 )); then
        warn "失败的参数通常是虚拟化/容器限制, 不影响已生效项"
    fi
}

apply_ulimits() {
    section "文件描述符限制"

    # 方法1: PAM limits
    if [[ -d /etc/security ]]; then
        mkdir -p /etc/security/limits.d 2>/dev/null || true
        cat > /etc/security/limits.d/99-apex.conf << LIMITS_EOF
# APEX TCP Accelerator v${VERSION}
* soft nofile ${NR_OPEN}
* hard nofile ${NR_OPEN}
* soft nproc 65535
* hard nproc 65535
root soft nofile ${NR_OPEN}
root hard nofile ${NR_OPEN}
LIMITS_EOF
        info "PAM limits: ${NR_OPEN}"
    else
        warn "无 /etc/security (Alpine/BusyBox?), 跳过PAM limits"
    fi

    # 方法2: systemd
    if command -v systemctl &>/dev/null && [[ -d /etc/systemd ]]; then
        mkdir -p /etc/systemd/system.conf.d 2>/dev/null || true
        cat > /etc/systemd/system.conf.d/apex-limits.conf << SD_EOF
[Manager]
DefaultLimitNOFILE=${NR_OPEN}
DefaultLimitNPROC=65535
SD_EOF
        info "systemd limits: ${NR_OPEN}"
    fi

    # 方法3: Alpine OpenRC
    if [[ "$OS_ID" == "alpine" ]] && [[ -d /etc/local.d ]]; then
        cat > /etc/local.d/apex-ulimits.start << RC_EOF
#!/bin/sh
ulimit -n ${NR_OPEN} 2>/dev/null || true
RC_EOF
        chmod +x /etc/local.d/apex-ulimits.start 2>/dev/null || true
        info "OpenRC limits: /etc/local.d/apex-ulimits.start"
    fi
}

# ==================== 模块4: 验证 ====================

verify_and_report() {
    section "验证结果"

    echo ""
    printf "  %-26s %s\n" "参数" "当前值"
    printf "  %-26s %s\n" "--------------------------" "--------------------"

    local items
    items=(
        "拥塞控制|net.ipv4.tcp_congestion_control"
        "队列调度|net.core.default_qdisc"
        "RMEM MAX|net.core.rmem_max"
        "WMEM MAX|net.core.wmem_max"
        "TCP RMEM|net.ipv4.tcp_rmem"
        "TCP WMEM|net.ipv4.tcp_wmem"
        "SOMAXCONN|net.core.somaxconn"
        "SYN Backlog|net.ipv4.tcp_max_syn_backlog"
        "TW Reuse|net.ipv4.tcp_tw_reuse"
        "FIN Timeout|net.ipv4.tcp_fin_timeout"
        "Keepalive Time|net.ipv4.tcp_keepalive_time"
        "Fast Open|net.ipv4.tcp_fastopen"
        "MTU Probing|net.ipv4.tcp_mtu_probing"
        "Slow Start Idle|net.ipv4.tcp_slow_start_after_idle"
        "Backlog|net.core.netdev_max_backlog"
        "File Max|fs.file-max"
    )

    local item label key val
    for item in "${items[@]}"; do
        label=$(echo "$item" | cut -d'|' -f1)
        key=$(echo "$item" | cut -d'|' -f2)
        val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
        printf "  %-26s %s\n" "$label" "$val"
    done

    echo ""

    # tc状态
    if command -v tc &>/dev/null && [[ -n "$NIC_NAME" ]]; then
        echo -e "  ${CYAN}队列状态:${NC}"
        tc -s qdisc show dev "$NIC_NAME" 2>/dev/null | head -3 | while IFS= read -r line; do
            echo "      $line"
        done
    fi
}

# ==================== 卸载 ====================

uninstall() {
    section "卸载 APEX TCP"

    local removed=0

    if [[ -f "$SYSCTL_CONF" ]]; then
        rm -f "$SYSCTL_CONF"
        info "已删除: ${SYSCTL_CONF}"
        safe_incr removed
    fi

    if [[ -f /etc/sysctl.d/99-apex-tcp.conf ]]; then
        rm -f /etc/sysctl.d/99-apex-tcp.conf
        safe_incr removed
    fi

    if [[ -f /etc/security/limits.d/99-apex.conf ]]; then
        rm -f /etc/security/limits.d/99-apex.conf
        info "已删除: PAM limits"
        safe_incr removed
    fi

    if [[ -f /etc/systemd/system.conf.d/apex-limits.conf ]]; then
        rm -f /etc/systemd/system.conf.d/apex-limits.conf
        info "已删除: systemd limits"
        safe_incr removed
    fi

    if [[ -f /etc/local.d/apex-ulimits.start ]]; then
        rm -f /etc/local.d/apex-ulimits.start
        info "已删除: OpenRC limits"
        safe_incr removed
    fi

    sysctl --system &>/dev/null 2>&1 || sysctl -p &>/dev/null 2>&1 || true

    if (( removed > 0 )); then
        info "已恢复系统默认 (删除${removed}个文件)"
    else
        warn "未找到APEX配置文件"
    fi

    info "备份保留在: ${BACKUP_DIR}"
    echo ""
}

# ==================== 主菜单 ====================

show_menu() {
    echo -e "${BOLD}"
    echo "  +-------------------------------------+"
    echo "  | 1) 自适应TCP加速 (推荐)             |"
    echo "  | 2) 仅诊断, 不修改                   |"
    echo "  | 3) 卸载/恢复默认                    |"
    echo "  | 4) 自定义BW/RTT后优化               |"
    echo "  | 0) 退出                             |"
    echo "  +-------------------------------------+"
    echo -e "${NC}"
}

run_diagnose() {
    detect_os
    detect_kernel
    detect_virtualization
    detect_hardware
    detect_network
    estimate_bdp
    calculate_params
    verify_and_report
}

run_full() {
    detect_os
    detect_kernel
    detect_virtualization
    detect_hardware
    detect_network
    estimate_bdp
    calculate_params
    ensure_sysctl_d
    backup_current
    generate_sysctl
    apply_live
    apply_ulimits
    verify_and_report
    show_complete
}

run_custom() {
    detect_os
    detect_kernel
    detect_virtualization
    detect_hardware
    detect_network

    local custom_bw custom_rtt

    echo -ne "  输入带宽 Mbps [${NIC_SPEED}]: "
    read -r custom_bw
    echo -ne "  输入RTT ms [50]: "
    read -r custom_rtt

    # 校验输入
    if [[ -n "$custom_bw" && "$custom_bw" =~ ^[0-9]+$ ]]; then
        export APEX_BW="$custom_bw"
    else
        export APEX_BW="$NIC_SPEED"
    fi
    if [[ -n "$custom_rtt" && "$custom_rtt" =~ ^[0-9]+$ ]]; then
        export APEX_RTT="$custom_rtt"
    else
        export APEX_RTT="50"
    fi

    estimate_bdp
    calculate_params
    ensure_sysctl_d
    backup_current
    generate_sysctl
    apply_live
    apply_ulimits
    verify_and_report
    show_complete
}

show_complete() {
    section "APEX TCP 加速完成"
    echo ""
    echo -e "  ${GREEN}配置文件: ${SYSCTL_CONF}${NC}"
    echo -e "  ${GREEN}备份目录: ${BACKUP_DIR}${NC}"
    echo -e "  ${GREEN}重启后自动生效 (持久化)${NC}"
    echo ""
    echo -e "  ${YELLOW}可用环境变量覆盖自动探测:${NC}"
    echo -e "  ${YELLOW}  APEX_BW=500  APEX_RTT=150  sudo bash $0 --auto${NC}"
    echo ""
    log_msg "INFO" "完成 CC=${CC_ALGO} BDP=${BDP_BYTES} BW=${ESTIMATED_BW} RTT=${ESTIMATED_RTT}"
}

# ==================== 入口 ====================

main() {
    check_root
    print_banner
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/dev/null"
    mkdir -p "$BACKUP_DIR" 2>/dev/null || true

    case "${1:-}" in
        --auto|-a)
            run_full
            exit 0
            ;;
        --diagnose|-d)
            run_diagnose
            exit 0
            ;;
        --uninstall|-u)
            uninstall
            exit 0
            ;;
        --help|-h)
            echo "APEX TCP Accelerator v${VERSION}"
            echo ""
            echo "用法: sudo bash $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --auto, -a        自动优化 (推荐)"
            echo "  --diagnose, -d    仅诊断不修改"
            echo "  --uninstall, -u   卸载恢复默认"
            echo "  --help, -h        显示帮助"
            echo "  (无参数)          交互菜单"
            echo ""
            echo "环境变量:"
            echo "  APEX_BW=500       覆盖带宽 (Mbps)"
            echo "  APEX_RTT=150      覆盖延迟 (ms)"
            exit 0
            ;;
        "")
            # 交互模式
            ;;
        *)
            errlog "未知选项: $1 (用 --help 查看帮助)"
            exit 1
            ;;
    esac

    # 交互菜单
    show_menu
    echo -ne "  ${BOLD}请选择 [1]: ${NC}"
    read -r choice
    choice="${choice:-1}"

    case "$choice" in
        1) run_full ;;
        2) run_diagnose ;;
        3) uninstall ;;
        4) run_custom ;;
        0) echo "  再见!"; exit 0 ;;
        *)
            errlog "无效选择: $choice"
            exit 1
            ;;
    esac
}

main "$@"
