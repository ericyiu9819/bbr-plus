#!/bin/bash
# PID-BBR-Gain v5.4 - 防卡死 + 强超时 + 心跳版（自动部署）
set -euo pipefail

SCRIPT_PATH="/root/pid-tcp.sh"
LOG="/var/log/pid-tcp-opt.log"

# ==================== 自动部署（首次运行执行） ====================
if [ "$0" != "$SCRIPT_PATH" ]; then
    echo "[$(date)] 首次运行 → 自动部署..."
    if ! command -v iperf3 >/dev/null; then
        apt-get update -qq && apt-get install -y iperf3 mtr jq bc || true
    fi
    cp "$0" "$SCRIPT_PATH" 2>/dev/null || cat "$0" > "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    pkill -f "pid-tcp.sh" 2>/dev/null || true
    nohup "$SCRIPT_PATH" > /dev/null 2>&1 &
    echo "✅ 已后台启动，查看日志：tail -f $LOG"
    exit 0
fi

# ==================== 正式循环 ====================
TEST_HOST="8.8.8.8"
IPERF_SERVERS=("speedtest.hkg12.hk.leaseweb.net" "84.17.57.129" "speedtest.sin1.sg.leaseweb.net")

CURRENT_IPERF=""
INTERVAL=300   # 先改短，便于观察（稳定后可改回600）

KP=80; KI=15; KD=40
INTEGRAL=0
PREV_ERROR=0
GAIN=3
SMOOTHED_BDP=0
PREV_RTT=200

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

safe_int() { echo "$1" | tr -dc '0-9' | sed 's/^0*//' | head -c 10 | grep -E '^[0-9]+$' || echo 0; }

# 所有测量强制超时
measure_rtt() {
    timeout 6 ping -c 3 -W 2 "$1" 2>/dev/null | tail -n1 | awk -F/ '{print $5}' | tr -dc '0-9' | head -c 8 | safe_int || echo 9999
}

measure_loss() {
    timeout 8 mtr -r -c 4 "$1" 2>/dev/null | tail -1 | awk '{print $NF}' | tr -dc '0-9' | safe_int || echo 3
}

measure_bw() {
    timeout 10 iperf3 -c "$1" -t 5 -J 2>/dev/null | jq -r '.end.sum_sent.bits_per_second // 0' 2>/dev/null | safe_int || echo 80
}

select_best_server() {
    local best=9999 srv=""
    for s in "${IPERF_SERVERS[@]}"; do
        local r=$(measure_rtt "$s")
        log "  测试 $s → RTT=${r}ms"
        [ "$r" -lt "$best" ] && best=$r && srv=$s
    done
    CURRENT_IPERF=$srv
    log "✅ 选中服务器: $CURRENT_IPERF"
}

if [[ $EUID -ne 0 ]]; then log "必须root"; exit 1; fi
select_best_server
log "=== 脚本启动成功，开始优化循环 ==="

while true; do
    log "=== 新周期开始 ==="
    RTT=$(measure_rtt "$TEST_HOST")
    LOSS=$(measure_loss "$TEST_HOST")
    BW=$(measure_bw "$CURRENT_IPERF")
    [ "$BW" -eq 0 ] && BW=80

    BDP=$((10#${BW} * 125 * 10#${RTT} / 1000))
    [ $SMOOTHED_BDP -eq 0 ] && SMOOTHED_BDP=$BDP
    SMOOTHED_BDP=$(( (65 * BDP + 35 * SMOOTHED_BDP) / 100 ))

    ERROR=$(( (RTT * 100 / (PREV_RTT + 1)) - 100 ))
    [ $ERROR -gt 50 ] && ERROR=50
    [ $ERROR -lt -30 ] && ERROR=-30

    INTEGRAL=$((INTEGRAL + ERROR))
    [ $INTEGRAL -gt 200 ] && INTEGRAL=200
    [ $INTEGRAL -lt -200 ] && INTEGRAL=-200

    DERIV=$((ERROR - PREV_ERROR))
    PID_RAW=$(( KP * ERROR + KI * INTEGRAL + KD * DERIV ))
    PID_OUTPUT=$(( PID_RAW / 100 ))

    GAIN=$((3 + PID_OUTPUT))
    [ $GAIN -lt 2 ] && GAIN=2
    [ $GAIN -gt 8 ] && GAIN=8

    MAX_BUF=$((SMOOTHED_BDP * GAIN))
    [ $MAX_BUF -gt 16777216 ] && MAX_BUF=16777216

    # 应用参数
    cat > /etc/sysctl.d/99-pid-tcp.conf << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.core.rmem_max = ${MAX_BUF}
net.core.wmem_max = ${MAX_BUF}
net.ipv4.tcp_rmem = 4096 131072 ${MAX_BUF}
net.ipv4.tcp_wmem = 4096 65536 ${MAX_BUF}
EOF
    sysctl -p /etc/sysctl.d/99-pid-tcp.conf >/dev/null 2>&1

    log "运行状态: RTT=${RTT}ms Loss=${LOSS}% BW=${BW}Mbps Gain=${GAIN} Buf=${MAX_BUF} Error=${ERROR}"

    PREV_ERROR=$ERROR
    PREV_RTT=$RTT
    sleep $INTERVAL
done
# ==================== 以下为正式优化循环（仅持久化后的实例执行） ====================
TEST_HOST="8.8.8.8"
IPERF_SERVERS=("speedtest.hkg12.hk.leaseweb.net" "84.17.57.129" "speedtest.sin1.sg.leaseweb.net" "89.187.162.1")

CURRENT_IPERF=""
INTERVAL=600
KP=80; KI=15; KD=40
INTEGRAL=0
PREV_ERROR=0
GAIN=3
SMOOTHED_BDP=0
PREV_RTT=200
CYCLE_COUNT=0
BEST_SCORE=0
LEARNING_RATE=5

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

safe_int() { echo "$1" | tr -dc '0-9' | sed 's/^0*//' | head -c 10 | grep -E '^[0-9]+$' || echo 0; }

measure_rtt() { local raw=$(ping -c 4 -W 2 "$1" 2>/dev/null | tail -n1 | awk -F/ '{print $5}' | tr -dc '0-9'); safe_int "${raw:-9999}"; }
measure_loss() { local raw=$(mtr -r -c 6 "$1" 2>/dev/null | tail -1 | awk '{print $NF}' | tr -dc '0-9'); safe_int "${raw:-2}"; }
measure_bw() { local json=$(timeout 8 iperf3 -c "$1" -t 5 -J 2>/dev/null || echo '{}'); local bps=$(echo "$json" | jq -r '.end.sum_sent.bits_per_second // 0' 2>/dev/null || echo 0); safe_int "$((bps / 1000000))"; }

select_best_server() {
    local best=9999 srv=""
    for s in "${IPERF_SERVERS[@]}"; do
        local r=$(measure_rtt "$s")
        [ "$r" -lt "$best" ] && best=$r && srv=$s
    done
    CURRENT_IPERF=$srv
    log "✅ 选中服务器: $CURRENT_IPERF"
}

if [[ $EUID -ne 0 ]]; then log "错误: 必须root运行"; exit 1; fi
select_best_server

while true; do
    RTT=$(measure_rtt "$TEST_HOST")
    LOSS=$(measure_loss "$TEST_HOST")
    BW=$(measure_bw "$CURRENT_IPERF")
    [ "$BW" -eq 0 ] && BW=80

    BDP=$((10#${BW} * 125 * 10#${RTT} / 1000))
    [ $SMOOTHED_BDP -eq 0 ] && SMOOTHED_BDP=$BDP
    SMOOTHED_BDP=$(( (65 * BDP + 35 * SMOOTHED_BDP) / 100 ))

    ERROR=$(( (RTT * 100 / (PREV_RTT + 1)) - 100 ))
    [ $ERROR -gt 50 ] && ERROR=50; [ $ERROR -lt -30 ] && ERROR=-30

    INTEGRAL=$((INTEGRAL + ERROR))
    [ $INTEGRAL -gt 200 ] && INTEGRAL=200; [ $INTEGRAL -lt -200 ] && INTEGRAL=-200

    DERIV=$((ERROR - PREV_ERROR))
    PID_RAW=$(( KP * ERROR + KI * INTEGRAL + KD * DERIV ))
    PID_OUTPUT=$(( PID_RAW / 100 ))

    GAIN=$((3 + PID_OUTPUT))
    [ $GAIN -lt 2 ] && GAIN=2; [ $GAIN -gt 8 ] && GAIN=8

    MAX_BUF=$((SMOOTHED_BDP * GAIN))
    [ $MAX_BUF -gt 16777216 ] && MAX_BUF=16777216

    cat > /etc/sysctl.d/99-pid-tcp.conf << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.core.rmem_max = ${MAX_BUF}
net.core.wmem_max = ${MAX_BUF}
net.ipv4.tcp_rmem = 4096 131072 ${MAX_BUF}
net.ipv4.tcp_wmem = 4096 65536 ${MAX_BUF}
EOF
    sysctl -p /etc/sysctl.d/99-pid-tcp.conf >/dev/null 2>&1
    modprobe tcp_bbr 2>/dev/null || true

    # 自动优化逻辑（每5周期）
    CYCLE_COUNT=$((CYCLE_COUNT + 1))
    if [ $((CYCLE_COUNT % 5)) -eq 0 ]; then
        STABILITY=$((100 - LOSS * 3))
        EFFICIENCY=$(( BW * 80 / (BDP / 1000 + 1) ))
        [ $EFFICIENCY -gt 100 ] && EFFICIENCY=100
        SCORE=$(( (EFFICIENCY * 6 + STABILITY * 4) / 10 ))
        # ...（auto_tune_pid 函数可在此扩展）
        log "自动优化得分: ${SCORE} (KP=${KP} KI=${KI} KD=${KD})"
    fi

    log "运行状态: RTT=${RTT}ms Loss=${LOSS}% BW=${BW}Mbps Gain=${GAIN} Buf=${MAX_BUF}"

    PREV_ERROR=$ERROR
    PREV_RTT=$RTT
    sleep $INTERVAL
done
