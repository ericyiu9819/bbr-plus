#!/bin/bash
# PID-BBR-Gain 自适应TCP优化 v5.1 - 全部整数化 + 零浮点错误版
set -euo pipefail
LOG="/var/log/pid-tcp-opt.log"
TEST_HOST="8.8.8.8"

IPERF_SERVERS=("speedtest.hkg12.hk.leaseweb.net" "84.17.57.129" "speedtest.sin1.sg.leaseweb.net" "89.187.162.1")

CURRENT_IPERF=""
INTERVAL=600

# PID参数（扩大100倍，全部整数运算）
KP=80      # 实际0.8
KI=15      # 实际0.15
KD=40      # 实际0.4
INTEGRAL=0
PREV_ERROR=0
GAIN=3
SMOOTHED_BDP=0
PREV_RTT=200

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

safe_int() {
    echo "$1" | tr -dc '0-9' | sed 's/^0*//' | head -c 10 | grep -E '^[0-9]+$' || echo 0
}

measure_rtt() {
    local raw=$(ping -c 4 -W 2 "$1" 2>/dev/null | tail -n1 | awk -F/ '{print $5}' | tr -dc '0-9')
    safe_int "${raw:-9999}"
}

measure_loss() {
    local raw=$(mtr -r -c 6 "$1" 2>/dev/null | tail -1 | awk '{print $NF}' | tr -dc '0-9')
    safe_int "${raw:-2}"
}

measure_bw() {
    local json=$(timeout 8 iperf3 -c "$1" -t 5 -J 2>/dev/null || echo '{}')
    local bps=$(echo "$json" | jq -r '.end.sum_sent.bits_per_second // 0' 2>/dev/null || echo 0)
    safe_int "$((bps / 1000000))"
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

if [[ $EUID -ne 0 ]]; then log "必须root运行"; exit 1; fi

command -v iperf3 >/dev/null || apt-get update -qq && apt-get install -y iperf3 mtr jq bc 2>/dev/null || true
select_best_server

while true; do
    RTT=$(measure_rtt "$TEST_HOST")
    LOSS=$(measure_loss "$TEST_HOST")
    BW=$(measure_bw "$CURRENT_IPERF")
    [ "$BW" -eq 0 ] && BW=80

    BDP=$((10#${BW} * 125 * 10#${RTT} / 1000))
    [ $SMOOTHED_BDP -eq 0 ] && SMOOTHED_BDP=$BDP
    SMOOTHED_BDP=$(( (65 * BDP + 35 * SMOOTHED_BDP) / 100 ))

    # PID核心（全部整数）
    ERROR=$(( (RTT * 100 / (PREV_RTT + 1)) - 100 ))
    [ $ERROR -gt 50 ] && ERROR=50
    [ $ERROR -lt -30 ] && ERROR=-30

    INTEGRAL=$((INTEGRAL + ERROR))
    [ $INTEGRAL -gt 200 ] && INTEGRAL=200
    [ $INTEGRAL -lt -200 ] && INTEGRAL=-200

    DERIV=$((ERROR - PREV_ERROR))

    # PID输出 = (KP*ERROR + KI*INTEGRAL + KD*DERIV) / 100
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
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = ${MAX_BUF}
net.core.wmem_max = ${MAX_BUF}
net.ipv4.tcp_rmem = 4096 131072 ${MAX_BUF}
net.ipv4.tcp_wmem = 4096 65536 ${MAX_BUF}
EOF
    sysctl -p /etc/sysctl.d/99-pid-tcp.conf >/dev/null 2>&1
    modprobe tcp_bbr 2>/dev/null || true

    log "PID状态: RTT=${RTT} Loss=${LOSS} BW=${BW} Error=${ERROR} Integral=${INTEGRAL} Gain=${GAIN} Buf=${MAX_BUF}"

    PREV_ERROR=$ERROR
    PREV_RTT=$RTT
    sleep $INTERVAL
done
