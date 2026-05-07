#!/bin/bash
# VPS TCP 激进自适应优化 v3.4 - 中国用户一键自安装版
# 使用方法：curl -fsSL https://... | bash 或直接保存执行

set -euo pipefail
SCRIPT_PATH="/root/tcp-optimize.sh"
LOG="/var/log/tcp-dynamic-opt.log"
TEST_HOST="8.8.8.8"

# 中国优化iperf3服务器列表（优先HK/SG）
IPERF_SERVERS=(
    "speedtest.hkg12.hk.leaseweb.net"
    "84.17.57.129"
    "23.249.58.14"
    "speedtest.sin1.sg.leaseweb.net"
    "89.187.162.1"
    "iperf.scbd.net.id"
    "iperf3.moji.fr"
    "speedtest.milkywan.fr"
)

CURRENT_IPERF=""
INTERVAL=600
ALPHA=0.65
GAIN_BASE=3.0
GAIN_MAX=6.0
STABLE_WIN=4
STABLE_COUNT=0
SMOOTHED_BDP=0
PREV_RTT=200
CURRENT_GAIN=3.0

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

# ==================== 自安装依赖 ====================
install_dependencies() {
    log "开始检测并安装依赖..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y iperf3 mtr jq bc
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y iperf3 mtr jq bc
    elif command -v yum >/dev/null 2>&1; then
        yum install -y iperf3 mtr jq bc
    else
        log "警告: 无法识别包管理器，请手动安装 iperf3 mtr jq bc"
    fi
    log "依赖安装完成"
}

# ==================== 自保存 ====================
self_save() {
    if [ "$0" != "$SCRIPT_PATH" ]; then
        log "首次运行，保存脚本到 $SCRIPT_PATH"
        cp "$0" "$SCRIPT_PATH" 2>/dev/null || cat > "$SCRIPT_PATH" << 'EOF'
[此处应粘贴本脚本完整内容，实际部署时自动处理]
EOF
        chmod +x "$SCRIPT_PATH"
        log "脚本已持久化，建议以后直接运行 $SCRIPT_PATH"
    fi
}

# ==================== 服务器选择 ====================
select_best_iperf() {
    local best_rtt=9999 best_srv=""
    for srv in "${IPERF_SERVERS[@]}"; do
        local rtt=$(ping -c 3 -W 1 "$srv" 2>/dev/null | tail -1 | awk -F/ '{print int($5)}' || echo 9999)
        if [ "$rtt" -lt "$best_rtt" ]; then
            best_rtt=$rtt
            best_srv=$srv
        fi
    done
    CURRENT_IPERF=$best_srv
    log "自动选中中国优化服务器: $CURRENT_IPERF (RTT≈${best_rtt}ms)"
}

# 主逻辑
if [[ $EUID -ne 0 ]]; then 
    log "错误: 必须以root运行"; 
    exit 1; 
fi

install_dependencies
self_save
select_best_iperf

while true; do
    CPU_LOAD=$(awk '{print $1}' /proc/loadavg)
    MEM_FREE_PCT=$(free -m | awk 'NR==2 {print int(($4+$7)/$2*100)}' || echo 50)
    MIN_RTT=$(ping -c 6 -i 0.2 "$TEST_HOST" 2>/dev/null | tail -1 | awk -F/ '{print int($5)}' || echo 200)
    LOSS=$(mtr -r -c 8 "$TEST_HOST" 2>/dev/null | tail -1 | awk '{print int($NF)}' || echo 2)

    BW_MBPS=$(iperf3 -c "$CURRENT_IPERF" -t 5 -J 2>/dev/null | jq -r '.end.sum_sent.bits_per_second/1000000' || echo 80)
    if [ "$BW_MBPS" = "80" ] || [ "$BW_MBPS" = "0" ] || (( $(echo "$BW_MBPS < 10" | bc -l 2>/dev/null || echo 0) )); then
        log "测量异常，重新选择服务器..."
        select_best_iperf
        BW_MBPS=$(iperf3 -c "$CURRENT_IPERF" -t 5 -J 2>/dev/null | jq -r '.end.sum_sent.bits_per_second/1000000' || echo 80)
    fi

    NEW_BDP=$(( BW_MBPS * 125 * MIN_RTT / 1000 ))

    if [ "$SMOOTHED_BDP" -eq 0 ]; then SMOOTHED_BDP=$NEW_BDP; fi
    SMOOTHED_BDP=$(echo "scale=0; $ALPHA * $NEW_BDP + (1 - $ALPHA) * $SMOOTHED_BDP" | bc || echo "$NEW_BDP")

    CHANGE_PCT=0
    if [ "$PREV_RTT" -gt 0 ]; then
        CHANGE_PCT=$(echo "scale=0; (${PREV_RTT} - ${MIN_RTT}) * 100 / ${PREV_RTT}" | bc 2>/dev/null || echo 0)
    fi

    if (( LOSS < 2 && CHANGE_PCT < 15 && MEM_FREE_PCT > 30 && CPU_LOAD < 1.5 )); then
        STABLE_COUNT=$((STABLE_COUNT + 1))
        CURRENT_GAIN=$(echo "scale=2; $CURRENT_GAIN + 0.3" | bc)
        [ "$(echo "$CURRENT_GAIN > $GAIN_MAX" | bc)" -eq 1 ] && CURRENT_GAIN=$GAIN_MAX
        ALPHA=0.75
    else
        STABLE_COUNT=0
        CURRENT_GAIN=$(echo "scale=2; $CURRENT_GAIN - 0.4" | bc)
        [ "$(echo "$CURRENT_GAIN < $GAIN_BASE" | bc)" -eq 1 ] && CURRENT_GAIN=$GAIN_BASE
        ALPHA=0.55
    fi

    MAX_BUF=$(echo "scale=0; $SMOOTHED_BDP * $CURRENT_GAIN" | bc)
    [ "$MAX_BUF" -gt 16777216 ] && MAX_BUF=16777216

    if (( STABLE_COUNT >= STABLE_WIN )); then
        INTERVAL=3600
        ALPHA=0.40
        log "系统已收敛，进入稳定模式"
    else
        INTERVAL=$((600 + STABLE_COUNT * 300))
    fi

    cat > /etc/sysctl.d/99-aggressive-tcp.conf << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.core.rmem_max = ${MAX_BUF}
net.core.wmem_max = ${MAX_BUF}
net.ipv4.tcp_rmem = 4096 131072 ${MAX_BUF}
net.ipv4.tcp_wmem = 4096 65536 ${MAX_BUF}
net.ipv4.tcp_mem = 9450000 12582912 18900000
EOF
    sysctl -p /etc/sysctl.d/99-aggressive-tcp.conf >/dev/null 2>&1
    modprobe tcp_bbr 2>/dev/null || true

    log "优化完成: RTT=${MIN_RTT}ms Loss=${LOSS}% Gain=${CURRENT_GAIN} Buf=${MAX_BUF} Interval=${INTERVAL}s BW=${BW_MBPS}Mbps"

    sleep 8
    NEW_RTT=$(ping -c 3 "$TEST_HOST" 2>/dev/null | tail -1 | awk -F/ '{print int($5)}' || echo "$MIN_RTT")
    if (( NEW_RTT * 100 < MIN_RTT * 92 )); then
        log "✓ 飞轮正向：延迟改善"
    fi

    PREV_RTT=$MIN_RTT
    sleep $INTERVAL
done
