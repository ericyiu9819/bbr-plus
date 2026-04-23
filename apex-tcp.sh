#!/usr/bin/env bash
#
# ╔══════════════════════════════════════════════════════════════╗
# ║  APEX TCP -- VPS 五层加速 一键安装脚本 v2.0                   ║
# ║  基于第一性原理: Throughput = min(Window, BDP) / RTT          ║
# ║  L1 拥塞感知 | L2 窗口缓冲 | L3 发送效率 | L4 调度排队 | L5 连接 ║
# ╚══════════════════════════════════════════════════════════════╝
#
# 用法:
#   curl -fsSL https://your-url/apex-tcp.sh -o apex-tcp.sh
#   chmod +x apex-tcp.sh && sudo bash apex-tcp.sh
#
# 支持: Ubuntu 20.04/22.04/24.04, Debian 11/12+, CentOS/RHEL 8/9
# 内核: 4.9+ (BBRv1), 6.1+ (BBR 含 v2/v3 改进)
#

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 安全选项
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
set -euo pipefail

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 颜色与工具函数
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

separator() {
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 全局常量 (品牌与路径)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
readonly BRAND="APEX TCP"
readonly BACKUP_DIR="/root/.apex-tcp-backup"
readonly SYSCTL_CONF="/etc/sysctl.d/99-apex-tcp.conf"
readonly SYSTEMD_LIMITS="/etc/systemd/system.conf.d/99-apex-tcp.conf"
readonly ROUTE_SCRIPT="/usr/local/bin/apex-tcp-routes.sh"
readonly ROUTE_SERVICE="/etc/systemd/system/apex-tcp-routes.service"
readonly LIMITS_MARKER="# APEX-TCP-AUTO"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 全局变量 (由检测函数赋值)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
KVER_FULL=""
KVER_MAJOR=0
KVER_MINOR=0
KVER_NUM=0
TOTAL_MEM_MB=0
DEFAULT_IFACE=""
DEFAULT_GW=""
BBR_ALGO=""
QDISC=""
TCP_MEM_MAX=0
RMEM_MAX=0
WMEM_MAX=0
RMEM_DEFAULT=0
WMEM_DEFAULT=0
OPTMEM_MAX=0
INITCWND=0
INITRWND=0
TFO_VALUE=0

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 前置检查
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "请以 root 权限运行此脚本: sudo bash $0"
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        error "无法识别操作系统: /etc/os-release 不存在"
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    case "${ID:-unknown}" in
        ubuntu|debian)
            info "检测到系统: ${PRETTY_NAME:-$ID}"
            ;;
        centos|rhel|rocky|almalinux|fedora)
            info "检测到系统: ${PRETTY_NAME:-$ID}"
            ;;
        *)
            warn "未经测试的系统: ${PRETTY_NAME:-$ID}, 将尝试继续"
            ;;
    esac
}

get_kernel_version() {
    KVER_FULL=$(uname -r)
    KVER_MAJOR=$(echo "$KVER_FULL" | cut -d. -f1)
    KVER_MINOR=$(echo "$KVER_FULL" | cut -d. -f2)
    # 清洗非数字字符, 防止非标准版本号导致算术错误
    KVER_MAJOR=${KVER_MAJOR//[^0-9]/}
    KVER_MINOR=${KVER_MINOR//[^0-9]/}
    KVER_MAJOR=${KVER_MAJOR:-0}
    KVER_MINOR=${KVER_MINOR:-0}
    KVER_NUM=$(( KVER_MAJOR * 100 + KVER_MINOR ))
    info "内核版本: ${KVER_FULL} (计算值: ${KVER_NUM})"
}

get_total_mem_mb() {
    TOTAL_MEM_MB=$(awk '/^MemTotal:/ {printf "%d", $2 / 1024}' /proc/meminfo)
    TOTAL_MEM_MB=${TOTAL_MEM_MB:-512}
    info "系统内存: ${TOTAL_MEM_MB} MB"
}

get_default_iface() {
    DEFAULT_IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}') || true
    if [[ -z "$DEFAULT_IFACE" ]]; then
        DEFAULT_IFACE=$(ip -o link show up 2>/dev/null \
            | awk -F': ' '!/lo/{print $2; exit}') || true
    fi
    if [[ -z "$DEFAULT_IFACE" ]]; then
        warn "未能检测到默认网卡"
    else
        info "默认网卡: ${DEFAULT_IFACE}"
    fi
}

get_default_gw() {
    DEFAULT_GW=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}') || true
    if [[ -z "$DEFAULT_GW" ]]; then
        warn "未能检测到默认网关"
    else
        info "默认网关: ${DEFAULT_GW}"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 备份当前配置
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
backup_config() {
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    mkdir -p "${BACKUP_DIR}"

    # 备份 sysctl 全量
    sysctl -a > "${BACKUP_DIR}/sysctl-all-${timestamp}.conf" 2>/dev/null || true

    # 备份已有的 apex-tcp 配置
    for f in /etc/sysctl.d/99-apex-tcp*.conf; do
        [[ -f "$f" ]] && cp "$f" "${BACKUP_DIR}/" 2>/dev/null || true
    done

    # 备份 limits.conf
    if [[ -f /etc/security/limits.conf ]]; then
        cp /etc/security/limits.conf "${BACKUP_DIR}/limits.conf.${timestamp}"
    fi

    # 备份路由表
    ip route show > "${BACKUP_DIR}/routes-${timestamp}.txt" 2>/dev/null || true

    success "配置已备份至 ${BACKUP_DIR}/"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# L1 -- 拥塞感知层: BBR
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
configure_l1_congestion() {
    separator
    info "L1 -- 配置拥塞控制算法 (BBR)"

    # 加载 BBR 内核模块
    if ! lsmod | grep -q "^tcp_bbr"; then
        modprobe tcp_bbr 2>/dev/null || true
    fi

    # 持久化模块加载
    if [[ -d /etc/modules-load.d ]]; then
        echo "tcp_bbr" > /etc/modules-load.d/tcp-bbr.conf
    elif [[ -f /etc/modules ]]; then
        if ! grep -qx "tcp_bbr" /etc/modules; then
            echo "tcp_bbr" >> /etc/modules
        fi
    fi

    # 检测可用算法
    local available_cc
    available_cc=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null) || true
    info "可用拥塞控制算法: ${available_cc}"

    if echo "${available_cc}" | grep -qw "bbr"; then
        BBR_ALGO="bbr"
        success "BBR 可用, 将设为默认"
    else
        BBR_ALGO=$(cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null) || BBR_ALGO="cubic"
        warn "BBR 不可用 (内核过旧或未编译), 保持当前算法: ${BBR_ALGO}"
    fi

    if [[ ${KVER_NUM} -ge 601 ]]; then
        info "内核 >= 6.1, BBR 模块包含 v2/v3 改进"
    elif [[ ${KVER_NUM} -ge 518 ]]; then
        info "内核 >= 5.18, BBR 包含部分 v2 改进"
    else
        info "内核 < 5.18, 使用 BBRv1 (仍优于 CUBIC)"
    fi

    success "L1 拥塞控制: ${BBR_ALGO}"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# L2 -- 窗口缓冲层: 大缓冲区 + 窗口优化
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
configure_l2_buffers() {
    separator
    info "L2 -- 配置缓冲区与窗口参数"

    if [[ ${TOTAL_MEM_MB} -le 1024 ]]; then
        TCP_MEM_MAX=67108864        # 64 MiB
        RMEM_MAX=67108864
        WMEM_MAX=67108864
        RMEM_DEFAULT=131072
        WMEM_DEFAULT=65536
        info "小内存模式 (<=1GB): 缓冲区上限 64 MiB"
    elif [[ ${TOTAL_MEM_MB} -le 4096 ]]; then
        TCP_MEM_MAX=134217728       # 128 MiB
        RMEM_MAX=134217728
        WMEM_MAX=134217728
        RMEM_DEFAULT=262144
        WMEM_DEFAULT=131072
        info "中等内存模式 (1-4GB): 缓冲区上限 128 MiB"
    elif [[ ${TOTAL_MEM_MB} -le 16384 ]]; then
        TCP_MEM_MAX=268435456       # 256 MiB
        RMEM_MAX=268435456
        WMEM_MAX=268435456
        RMEM_DEFAULT=262144
        WMEM_DEFAULT=131072
        info "大内存模式 (4-16GB): 缓冲区上限 256 MiB"
    else
        TCP_MEM_MAX=536870912       # 512 MiB
        RMEM_MAX=536870912
        WMEM_MAX=536870912
        RMEM_DEFAULT=262144
        WMEM_DEFAULT=131072
        info "超大内存模式 (>16GB): 缓冲区上限 512 MiB"
    fi

    INITCWND=32
    INITRWND=32

    success "L2 缓冲区: rmem_max=${RMEM_MAX}, initcwnd=${INITCWND}"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# L3 -- 发送效率层: 零拷贝 + 内存优化
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
configure_l3_efficiency() {
    separator
    info "L3 -- 配置发送效率参数"

    OPTMEM_MAX=1048576

    if grep -q "iommu=pt" /proc/cmdline 2>/dev/null; then
        success "IOMMU 已设置为直通模式 (iommu=pt)"
    else
        info "IOMMU 未设置直通模式 (VPS 环境通常由宿主机管理)"
    fi

    success "L3 效率参数: optmem_max=${OPTMEM_MAX}"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# L4 -- 排队调度层: fq + 网卡优化
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
configure_l4_qdisc() {
    separator
    info "L4 -- 配置排队调度"

    QDISC="fq"

    if command -v ethtool &>/dev/null && [[ -n "${DEFAULT_IFACE}" ]]; then
        local ring_output=""
        ring_output=$(ethtool -g "${DEFAULT_IFACE}" 2>/dev/null) || ring_output=""

        local max_rx=""
        local max_tx=""
        if [[ -n "${ring_output}" ]]; then
            max_rx=$(echo "${ring_output}" \
                | sed -n '/Pre-set maximums/,/^$/p' \
                | awk '/^RX:/ {print $2}')
            max_tx=$(echo "${ring_output}" \
                | sed -n '/Pre-set maximums/,/^$/p' \
                | awk '/^TX:/ {print $2}')
        fi

        if [[ -n "${max_rx}" ]] && [[ "${max_rx}" =~ ^[0-9]+$ ]] && [[ ${max_rx} -gt 0 ]]; then
            local target_tx="${max_tx:-${max_rx}}"
            if [[ ! "${target_tx}" =~ ^[0-9]+$ ]]; then
                target_tx="${max_rx}"
            fi
            if ethtool -G "${DEFAULT_IFACE}" rx "${max_rx}" tx "${target_tx}" 2>/dev/null; then
                success "网卡环形缓冲区已调至最大: RX=${max_rx} TX=${target_tx}"
            else
                info "虚拟网卡不支持调整环形缓冲区 (VPS 正常现象)"
            fi
        else
            info "无法获取网卡缓冲区信息 (VPS 虚拟网卡正常现象)"
        fi

        ethtool -K "${DEFAULT_IFACE}" tso on 2>/dev/null || true
        ethtool -K "${DEFAULT_IFACE}" gso on 2>/dev/null || true
        ethtool -K "${DEFAULT_IFACE}" gro on 2>/dev/null || true
        info "已尝试启用 TSO/GSO/GRO offload"
    else
        info "ethtool 不可用或未检测到网卡, 跳过网卡优化"
    fi

    success "L4 队列调度: ${QDISC}"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# L5 -- 连接优化层: TFO + 连接回收 + MPTCP 检测
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
configure_l5_connection() {
    separator
    info "L5 -- 配置连接优化"

    TFO_VALUE=3

    if [[ ${KVER_NUM} -ge 506 ]]; then
        if sysctl net.mptcp.enabled &>/dev/null; then
            local mptcp_status
            mptcp_status=$(sysctl -n net.mptcp.enabled 2>/dev/null) || mptcp_status="unknown"
            info "MPTCP 可用 (内核 >= 5.6), 当前状态: ${mptcp_status}"
            info "MPTCP 需要应用层配合, 此脚本不自动启用"
            info "如需启用: sysctl -w net.mptcp.enabled=1"
        fi
    fi

    success "L5 连接优化: TFO=${TFO_VALUE}"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 写入 sysctl 配置
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
write_sysctl() {
    separator
    info "写入 sysctl 配置文件"

    local gen_date
    gen_date=$(date '+%Y-%m-%d %H:%M:%S')

    cat > "${SYSCTL_CONF}" << EOF
# ================================================================
#  ${BRAND} -- 自动生成于 ${gen_date}
#  基础真理: Throughput = min(Window, BDP) / RTT
#  内核: ${KVER_FULL} | 内存: ${TOTAL_MEM_MB} MB
# ================================================================

# ----------------------------------------------------------------
# L1: 拥塞控制 -- 精准 BDP 估计
# ----------------------------------------------------------------
net.core.default_qdisc = ${QDISC}
net.ipv4.tcp_congestion_control = ${BBR_ALGO}

# ----------------------------------------------------------------
# L2: 缓冲区与窗口 -- 窗口 >= BDP
# ----------------------------------------------------------------
net.ipv4.tcp_rmem = 4096 ${RMEM_DEFAULT} ${TCP_MEM_MAX}
net.ipv4.tcp_wmem = 4096 ${WMEM_DEFAULT} ${TCP_MEM_MAX}
net.core.rmem_max = ${RMEM_MAX}
net.core.wmem_max = ${WMEM_MAX}
net.core.rmem_default = ${RMEM_DEFAULT}
net.core.wmem_default = ${WMEM_DEFAULT}
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_mtu_probing = 1

# ----------------------------------------------------------------
# L3: 发送效率 -- 释放 CPU
# ----------------------------------------------------------------
net.core.optmem_max = ${OPTMEM_MAX}

# ----------------------------------------------------------------
# L4: 排队调度 -- 消灭突发
# ----------------------------------------------------------------
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 65535
net.core.somaxconn = 65535

# ----------------------------------------------------------------
# L5: 连接优化 -- 快速建立与回收
# ----------------------------------------------------------------
net.ipv4.tcp_fastopen = ${TFO_VALUE}
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_ecn_fallback = 1
net.ipv4.ip_local_port_range = 1024 65535

# ----------------------------------------------------------------
# 安全加固 (兼顾性能)
# ----------------------------------------------------------------
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# ----------------------------------------------------------------
# 系统资源限制
# ----------------------------------------------------------------
fs.file-max = 2097152
EOF

    success "配置已写入 ${SYSCTL_CONF}"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 写入文件描述符限制
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
write_limits() {
    info "配置文件描述符限制"

    local limits_file="/etc/security/limits.conf"

    if [[ -f "${limits_file}" ]]; then
        if ! grep -qF "${LIMITS_MARKER}" "${limits_file}"; then
            cat >> "${limits_file}" << EOF

${LIMITS_MARKER}
* soft nofile 655360
* hard nofile 655360
root soft nofile 655360
root hard nofile 655360
* soft nproc 655360
* hard nproc 655360
EOF
            success "文件描述符限制已写入 ${limits_file}"
        else
            info "文件描述符限制已存在, 跳过"
        fi
    else
        warn "${limits_file} 不存在, 跳过"
    fi

    if [[ -d /etc/systemd ]]; then
        mkdir -p "$(dirname "${SYSTEMD_LIMITS}")"
        cat > "${SYSTEMD_LIMITS}" << 'SYSTEMD_LIMITS_EOF'
[Manager]
DefaultLimitNOFILE=655360
DefaultLimitNPROC=655360
SYSTEMD_LIMITS_EOF
        success "systemd 全局文件描述符限制已配置"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 配置路由 (initcwnd / initrwnd)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
configure_routes() {
    separator
    info "配置初始拥塞窗口 (initcwnd=${INITCWND}, initrwnd=${INITRWND})"

    if [[ -z "${DEFAULT_GW}" ]] || [[ -z "${DEFAULT_IFACE}" ]]; then
        warn "未检测到默认网关或网卡, 跳过路由修改"
        return 0
    fi

    # 立即修改默认路由
    if ip route change default via "${DEFAULT_GW}" dev "${DEFAULT_IFACE}" \
        initcwnd "${INITCWND}" initrwnd "${INITRWND}" 2>/dev/null; then
        success "默认路由已更新: initcwnd=${INITCWND} initrwnd=${INITRWND}"
    else
        warn "默认路由更新失败 (某些 VPS 不允许修改, 不影响其他优化)"
    fi

    # 创建独立路由脚本
    cat > "${ROUTE_SCRIPT}" << 'SCRIPT_EOF'
#!/bin/bash
# APEX TCP: 设置默认路由的 initcwnd 和 initrwnd
set -e
GW=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')
IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
if [ -n "$GW" ] && [ -n "$IFACE" ]; then
    ip route change default via "$GW" dev "$IFACE" initcwnd 32 initrwnd 32 2>/dev/null || true
    echo "apex-tcp-routes: OK (GW=$GW, IFACE=$IFACE)"
else
    echo "apex-tcp-routes: SKIP (no default route found)"
fi
SCRIPT_EOF
    chmod 755 "${ROUTE_SCRIPT}"

    # 创建 systemd 服务
    cat > "${ROUTE_SERVICE}" << UNIT_EOF
[Unit]
Description=${BRAND} - Set initcwnd and initrwnd on default route
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${ROUTE_SCRIPT}

[Install]
WantedBy=multi-user.target
UNIT_EOF

    systemctl daemon-reload
    systemctl enable "$(basename "${ROUTE_SERVICE}")" 2>/dev/null || true
    success "initcwnd 开机持久化服务已配置"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 应用并验证
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
apply_and_verify() {
    separator
    info "应用配置并验证"

    sysctl --system > /dev/null 2>&1 || true
    sysctl -p "${SYSCTL_CONF}" > /dev/null 2>&1 || true

    success "sysctl 配置已全部加载"

    echo ""
    separator
    echo -e "${BOLD}${GREEN}"
    echo "  =========================================="
    echo "     ${BRAND} -- 五层加速配置完成"
    echo "  =========================================="
    echo -e "${NC}"

    echo -e "${BOLD}配置验证:${NC}"
    echo ""

    local val_cc val_qd val_rm val_wm val_om val_tfo val_ecn val_sm
    val_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) || val_cc="N/A"
    val_qd=$(sysctl -n net.core.default_qdisc 2>/dev/null)         || val_qd="N/A"
    val_rm=$(sysctl -n net.core.rmem_max 2>/dev/null)               || val_rm="0"
    val_wm=$(sysctl -n net.core.wmem_max 2>/dev/null)               || val_wm="0"
    val_om=$(sysctl -n net.core.optmem_max 2>/dev/null)             || val_om="0"
    val_tfo=$(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null)          || val_tfo="N/A"
    val_ecn=$(sysctl -n net.ipv4.tcp_ecn 2>/dev/null)               || val_ecn="N/A"
    val_sm=$(sysctl -n net.core.somaxconn 2>/dev/null)              || val_sm="N/A"

    local rm_mib=0 wm_mib=0 om_mib=0
    if [[ "${val_rm}" =~ ^[0-9]+$ ]]; then rm_mib=$(( val_rm / 1048576 )); fi
    if [[ "${val_wm}" =~ ^[0-9]+$ ]]; then wm_mib=$(( val_wm / 1048576 )); fi
    if [[ "${val_om}" =~ ^[0-9]+$ ]]; then om_mib=$(( val_om / 1048576 )); fi

    printf "  %-34s %s\n"              "L1 拥塞控制:"      "${val_cc}"
    printf "  %-34s %s\n"              "L1 队列调度:"      "${val_qd}"
    printf "  %-34s %s bytes (%s MiB)\n" "L2 rmem_max:"    "${val_rm}" "${rm_mib}"
    printf "  %-34s %s bytes (%s MiB)\n" "L2 wmem_max:"    "${val_wm}" "${wm_mib}"
    printf "  %-34s %s bytes (%s MiB)\n" "L3 optmem_max:"  "${val_om}" "${om_mib}"
    printf "  %-34s %s\n"              "L5 TCP Fast Open:" "${val_tfo}"
    printf "  %-34s %s\n"              "L5 ECN:"           "${val_ecn}"
    printf "  %-34s %s\n"              "L5 somaxconn:"     "${val_sm}"
    echo ""

    local route_info=""
    route_info=$(ip route show default 2>/dev/null) || route_info=""
    if echo "${route_info}" | grep -q "initcwnd"; then
        local val_icwnd val_irwnd
        val_icwnd=$(echo "${route_info}" | grep -o 'initcwnd [0-9]*' | head -1) || val_icwnd="N/A"
        val_irwnd=$(echo "${route_info}" | grep -o 'initrwnd [0-9]*' | head -1) || val_irwnd="N/A"
        printf "  %-34s %s\n" "路由 initcwnd:" "${val_icwnd}"
        printf "  %-34s %s\n" "路由 initrwnd:" "${val_irwnd}"
    else
        printf "  %-34s %s\n" "路由 initcwnd:" "未生效 (VPS 可能不支持)"
    fi

    echo ""
    separator
    echo ""
    echo -e "${BOLD}重要说明:${NC}"
    echo ""
    echo "  1. 配置已立即生效, 且重启后自动加载"
    echo "  2. 备份位于 ${BACKUP_DIR}/"
    echo "  3. 配置文件: ${SYSCTL_CONF}"
    echo ""
    echo -e "${BOLD}可选进阶操作:${NC}"
    echo ""
    echo "  * 启用 MPTCP:        sysctl -w net.mptcp.enabled=1"
    echo "  * 安装 iperf3 测速:  apt install -y iperf3"
    echo "  * 查看 BBR 状态:     ss -ti | grep bbr"
    echo "  * 查看完整配置:      cat ${SYSCTL_CONF}"
    echo ""
    echo -e "${BOLD}卸载方法:${NC}"
    echo ""
    echo "  rm -f ${SYSCTL_CONF}"
    echo "  rm -f ${ROUTE_SERVICE}"
    echo "  rm -f ${SYSTEMD_LIMITS}"
    echo "  rm -f ${ROUTE_SCRIPT}"
    echo "  rm -f /etc/modules-load.d/tcp-bbr.conf"
    echo "  systemctl daemon-reload"
    echo "  sysctl --system"
    echo ""
    separator
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 主流程
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
main() {
    echo ""
    echo -e "${BOLD}${CYAN}"
    echo "  =========================================="
    echo "   ${BRAND} -- VPS 五层加速 一键安装 v2.0"
    echo "   Throughput = min(Window, BDP) / RTT"
    echo "  =========================================="
    echo -e "${NC}"
    echo ""

    check_root
    check_os
    get_kernel_version
    get_total_mem_mb
    get_default_iface
    get_default_gw

    separator
    info "备份当前配置..."
    backup_config

    configure_l1_congestion
    configure_l2_buffers
    configure_l3_efficiency
    configure_l4_qdisc
    configure_l5_connection

    write_sysctl
    write_limits
    configure_routes

    apply_and_verify
}

main "$@"
