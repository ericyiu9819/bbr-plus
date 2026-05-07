#!/bin/bash
# PID-BBR-Gain 自适应TCP优化 v5.3 - 完整自动部署版（一键运行）
set -euo pipefail

# ==================== 自动部署逻辑（只在首次或手动调用时执行） ====================
SCRIPT_PATH="/root/pid-tcp.sh"
LOG="/var/log/pid-tcp-opt.log"

if [ "$0" != "$SCRIPT_PATH" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 首次运行 → 开始自动部署..."
    
    # 1. 安装依赖（幂等）
    if ! command -v iperf3 >/dev/null || ! command -v jq >/dev/null; then
        echo "安装依赖 iperf3 mtr jq bc ..."
        if command -v apt-get >/dev/null; then
            apt-get update -qq && apt-get install -y iperf3 mtr jq bc
        elif command -v yum >/dev/null; then
            yum install -y iperf3 mtr jq bc
        elif command -v dnf >/dev/null; then
            dnf install -y iperf3 mtr jq bc
        fi
    fi

    # 2. 自身持久化
    cp "$0" "$SCRIPT_PATH" 2>/dev/null || cat "$0" > "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"

    # 3. 停止旧实例（安全）
    pkill -f "pid-tcp.sh" 2>/dev/null || true

    # 4. 后台启动自身
    nohup "$SCRIPT_PATH" > /dev/null 2>&1 &
    echo "✅ 自动部署完成！脚本已在后台运行"
    echo "查看日志：tail -f $LOG"
    exit 0
fi

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
