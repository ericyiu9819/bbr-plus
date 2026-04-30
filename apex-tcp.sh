#!/usr/bin/env bash
set -euo pipefail

CONF_FILE="/etc/sysctl.d/99-tcp-physics-opt.conf"
BACKUP_DIR="/etc/tcp-physics-backup"
MODE="${1:-install}"

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "错误：请使用 root 权限运行。"
        exit 1
    fi
}

check_command() {
    if ! command -v sysctl >/dev/null 2>&1; then
        echo "错误：未找到 sysctl 命令。"
        exit 1
    fi
}

detect_bbr() {
    echo "当前内核：$(uname -r)"

    # 尝试加载模块；如果 BBR 已内建进内核，modprobe 失败也不一定是问题。
    modprobe tcp_bbr 2>/dev/null || true

    if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
        echo "错误：当前内核未检测到 BBR 支持。"
        echo "建议升级到 Linux 4.9+，更推荐 Linux 5.x 或 6.x 内核。"
        exit 1
    fi
}

backup_current() {
    mkdir -p "$BACKUP_DIR"

    local backup_file
    backup_file="$BACKUP_DIR/sysctl-backup-$(date +%Y%m%d-%H%M%S).conf"

    {
        echo "# Backup created at $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# Kernel: $(uname -r)"
        echo

        for key in \
            net.core.default_qdisc \
            net.ipv4.tcp_congestion_control \
            net.ipv4.tcp_window_scaling \
            net.ipv4.tcp_timestamps \
            net.ipv4.tcp_sack \
            net.core.rmem_max \
            net.core.wmem_max \
            net.ipv4.tcp_rmem \
            net.ipv4.tcp_wmem \
            net.ipv4.tcp_fastopen \
            net.ipv4.tcp_mtu_probing \
            net.ipv4.tcp_no_metrics_save
        do
            sysctl "$key" 2>/dev/null || true
        done
    } > "$backup_file"

    echo "已备份当前 TCP 参数到：$backup_file"
}

write_config() {
    local tmp_file
    tmp_file="$(mktemp)"

    cat > "$tmp_file" <<'EOF'
# TCP Physics Optimization
#
# Design goals:
# 1. Use BBR to estimate bottleneck bandwidth and minimum RTT.
# 2. Use fq to support stable packet pacing.
# 3. Allow TCP auto-tuning to use larger buffers on high-BDP paths.
# 4. Avoid risky or fake acceleration settings.

# Queue discipline. fq is recommended for BBR pacing.
net.core.default_qdisc = fq

# Congestion control.
net.ipv4.tcp_congestion_control = bbr

# TCP window scaling for high bandwidth-delay product paths.
net.ipv4.tcp_window_scaling = 1

# TCP timestamps help RTT measurement and modern TCP behavior.
net.ipv4.tcp_timestamps = 1

# Selective ACK improves loss recovery.
net.ipv4.tcp_sack = 1

# Socket buffer upper limits.
# These are maximums; TCP auto-tuning decides actual usage.
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728

# TCP auto-tuning buffers: min default max.
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

# TCP Fast Open:
# 0 = disabled
# 1 = client
# 2 = server
# 3 = client and server
net.ipv4.tcp_fastopen = 3

# Path MTU probing:
# 0 = disabled
# 1 = weak probing
# 2 = always probing
net.ipv4.tcp_mtu_probing = 1

# Do not permanently cache bad TCP metrics from unstable routes.
net.ipv4.tcp_no_metrics_save = 1
EOF

    install -m 0644 "$tmp_file" "$CONF_FILE"
    rm -f "$tmp_file"
}

apply_config() {
    echo "正在应用配置：$CONF_FILE"

    if ! sysctl -p "$CONF_FILE"; then
        echo "错误：配置应用失败。"
        echo "可能原因：当前内核不支持某些参数，例如 fq 或 BBR。"
        exit 1
    fi

    validate_config
}

validate_config() {
    local cc
    local qdisc

    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"

    if [ "$cc" != "bbr" ]; then
        echo "错误：BBR 未成功启用。当前拥塞控制算法为：$cc"
        exit 1
    fi

    if [ "$qdisc" != "fq" ]; then
        echo "错误：fq 队列未成功启用。当前默认队列为：$qdisc"
        exit 1
    fi

    echo "验证通过：BBR 与 fq 已成功启用。"
}

show_status() {
    echo
    echo "====== 当前 TCP 状态 ======"
    echo

    sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null || true
    sysctl net.ipv4.tcp_congestion_control 2>/dev/null || true
    sysctl net.core.default_qdisc 2>/dev/null || true

    echo
    sysctl net.ipv4.tcp_window_scaling 2>/dev/null || true
    sysctl net.ipv4.tcp_timestamps 2>/dev/null || true
    sysctl net.ipv4.tcp_sack 2>/dev/null || true
    sysctl net.ipv4.tcp_fastopen 2>/dev/null || true
    sysctl net.ipv4.tcp_mtu_probing 2>/dev/null || true
    sysctl net.ipv4.tcp_no_metrics_save 2>/dev/null || true

    echo
    sysctl net.core.rmem_max 2>/dev/null || true
    sysctl net.core.wmem_max 2>/dev/null || true
    sysctl net.ipv4.tcp_rmem 2>/dev/null || true
    sysctl net.ipv4.tcp_wmem 2>/dev/null || true

    echo
    echo "====== BBR 模块状态 ======"
    if lsmod 2>/dev/null | grep -q '^tcp_bbr'; then
        lsmod | grep '^tcp_bbr'
    else
        echo "tcp_bbr 未显示在 lsmod 中；如果 BBR 已生效，说明它可能已内建进内核。"
    fi

    echo
    echo "====== 验证建议 ======"
    echo "1. 对比安装前后的单连接速度。"
    echo "2. 对比空载 RTT 与满载 RTT。"
    echo "3. 如果满载 RTT 暴涨，说明瓶颈更可能是队列膨胀或线路拥塞。"
    echo "4. 如果晚高峰仍然明显变慢，优先检查线路、路由、丢包和 VPS 超售。"
}

latest_backup_file() {
    find "$BACKUP_DIR" -maxdepth 1 -type f -name 'sysctl-backup-*.conf' 2>/dev/null | sort | tail -n 1
}

rollback_config() {
    local backup_file

    if [ -f "$CONF_FILE" ]; then
        rm -f "$CONF_FILE"
        echo "已删除优化配置文件：$CONF_FILE"
    else
        echo "未发现优化配置文件：$CONF_FILE"
    fi

    backup_file="$(latest_backup_file || true)"

    if [ -n "${backup_file:-}" ] && [ -f "$backup_file" ]; then
        echo "正在恢复最近一次备份：$backup_file"

        if ! sysctl -p "$backup_file"; then
            echo "警告：备份恢复未完全成功。可能是当前内核不支持其中某些参数。"
        else
            echo "备份参数已恢复。"
        fi
    else
        echo "未找到可用备份。已仅删除本脚本生成的配置文件。"
    fi

    show_status
}

install_config() {
    detect_bbr
    backup_current
    write_config
    apply_config
    show_status
}

usage() {
    cat <<EOF
用法：
  bash $0 install    安装并应用 TCP 优化
  bash $0 status     查看当前 TCP 状态
  bash $0 rollback   删除优化配置并尝试恢复最近一次备份

示例：
  bash $0 install
  bash $0 status
  bash $0 rollback
EOF
}

main() {
    need_root
    check_command

    case "$MODE" in
        install)
            install_config
            ;;
        status)
            show_status
            ;;
        rollback)
            rollback_config
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main
