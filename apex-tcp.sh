#!/bin/bash
# VPS TCP 激进自适应优化 v3.6 - 中国用户最终修复版（jq + 整数双收敛）
set -euo pipefail
SCRIPT_PATH="/root/tcp-optimize.sh"
LOG="/var/log/tcp-dynamic-opt.log"
TEST_HOST="8.8.8.8"

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

# ==================== 安全函数 ====================
safe_rtt() {
    local host=$1
    local raw=$(ping -c 3 -W 2 "$host" 2>/dev/null | tail -n 1 | awk -F/ '{print $5}' | tr -dc '0-9' | head -c 10)
    if [[ -z "$raw" || "$raw" -eq 0 ]]; then
        echo 9999
    else
        echo "$raw"
    fi
}

safe_bw_mbps() {
    local srv=$1
    local json=$(iperf3 -c "$srv" -t 5 -J 2>/dev/null || echo '{}')
    local bps=$(echo "$json" | jq -r '.end.sum_sent.bits_per_second // 0')
    if [[ "$bps" == "null" || -z "$bps" || "$bps" -eq 0 ]]; then
        echo 80
    else
        echo "$((bps / 1000000))"
    fi
}

# ==================== 服务器选择 ====================
select_best_iperf() {
    local best_rtt=9999 best_srv=""
    log "开始选择最优服务器..."
    for srv in "${IPERF_SERVERS[@]}"; do
        local rtt=$(safe_rtt "$srv")
        log "  测试 $srv → RTT=${rtt}ms"
        if [ "$rtt" -lt "$best_rtt" ]; then
            best_rtt=$rtt
            best_srv=$srv
        fi
    done
    CURRENT_IPERF=$best_srv
    log "✅ 选中: $CURRENT_IPERF (RTT≈${best_rtt}ms)"
}

# ==================== 安装 & 自保存 ====================
install_dependencies() {
    log "安装依赖..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y iperf3 mtr jq bc
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y iperf3 mtr jq bc
    elif command -v yum >/dev/null 2>&1; then
        yum install -y iperf3 mtr jq bc
    fi
}

self_save() {
    if [ "$0" != "$SCRIPT_PATH" ]; then
        log "持久化脚本到 $SCRIPT_PATH"
        cp "$0" "$SCRIPT_PATH" 2>/dev/null || cat "$0" > "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
    fi
}

# 主流程
if [[ $EUID -ne 0 ]]; then 
    log "错误: 必须root运行"; exit 1; 
fi

install_dependencies
self_save
select_best_iperf

while true; do
    CPU_LOAD=$(awk '{print $1}' /proc/loadavg)
    MEM_FREE_PCT=$(free -m | awk 'NR==2 {print int(($4+$7)/$2*100)}' || echo 50)
    MIN_RTT=$(safe_rtt "$TEST_HOST")
    LOSS=$(mtr -r -c 8 "$TEST_HOST" 2>/dev/null | tail -1 | awk '{print int($NF)}' || echo 2)

    # 带宽测量（强容错）
    BW_MBPS=$(safe_bw_mbps "$CURRENT_IPERF")
    if [ "$BW_MBPS" -eq 80 ]; then
        log "测量异常，重新选择服务器..."
        select_best_iperf
        BW_MBPS=$(safe_bw_mbps "$CURRENT_IPERF")
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

    log "优化完成: RTT=${MIN_RTT}ms Loss=${LOSS}% Gain=${CURRENT_GAIN} Buf=${MAX_BUF} BW≈${BW_MBPS}Mbps Server=${CURRENT_IPERF}"

    sleep 8
    NEW_RTT=$(safe_rtt "$TEST_HOST")
    if (( NEW_RTT * 100 < MIN_RTT * 92 )); then
        log "✓ 飞轮正向：延迟改善"
    fi

    PREV_RTT=$MIN_RTT
    sleep $INTERVAL
done
