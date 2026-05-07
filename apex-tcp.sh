#!/bin/bash
# PID-BBR-Gain 自适应TCP优化 v5.0 - 全新控制论算法
set -euo pipefail
LOG="/var/log/pid-tcp-opt.log"
TEST_HOST="8.8.8.8"

IPERF_SERVERS=("speedtest.hkg12.hk.leaseweb.net" "84.17.57.129" "speedtest.sin1.sg.leaseweb.net")

CURRENT_IPERF=""
INTERVAL=600

# PID参数（可在线自适应调优）
KP=0.8
KI=0.15
KD=0.4
INTEGRAL=0
PREV_ERROR=0
GAIN=3.0
SMOOTHED_BDP=0
PREV_RTT=200

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

safe_int() { echo "$1" | tr -dc '0-9' | sed 's/^0*//' | head -c 10 | grep -E '^[0-9]+$' || echo 0; }

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
        [ "$r" -lt "$best" ] && best=$r && srv=$s
    done
    CURRENT_IPERF=$srv
    log "选中服务器: $CURRENT_IPERF"
}

if [[ $EUID -ne 0 ]]; then log "必须root"; exit 1; fi
# 安装依赖（幂等）
command -v iperf3 >/dev/null || apt-get update -qq && apt-get install -y iperf3 mtr jq bc 2>/dev/null || true
select_best_server

while true; do
    RTT=$(measure_rtt "$TEST_HOST")
    LOSS=$(measure_loss "$TEST_HOST")
    BW=$(measure_bw "$CURRENT_IPERF")
    [ "$BW" -eq 0 ] && BW=80

    BDP=$((10#${BW} * 125 * 10#${RTT} / 1000))
    [ $SMOOTHED_BDP -eq 0 ] && SMOOTHED_BDP=$BDP
    SMOOTHED_BDP=$(( (65 * BDP + 35 * SMOOTHED_BDP) / 100 ))   # 简单低通

    # PID核心计算
    ERROR=$(( (RTT * 100 / (PREV_RTT + 1)) - 100 ))   # 百分比偏差（>0表示恶化）
    [ $ERROR -gt 50 ] && ERROR=50
    [ $ERROR -lt -30 ] && ERROR=-30

    INTEGRAL=$((INTEGRAL + ERROR))
    [ $INTEGRAL -gt 200 ] && INTEGRAL=200   # 抗饱和
    [ $INTEGRAL -lt -200 ] && INTEGRAL=-200

    DERIV=$((ERROR - PREV_ERROR))
    PID_OUTPUT=$(( KP*ERROR + KI*INTEGRAL + KD*DERIV ))

    GAIN=$((3 + PID_OUTPUT / 10))
    [ $GAIN -lt 2 ] && GAIN=2
    [ $GAIN -gt 8 ] && GAIN=8

    MAX_BUF=$((SMOOTHED_BDP * GAIN))
    [ $MAX_BUF -gt 16777216 ] && MAX_BUF=16777216

    # 应用
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
