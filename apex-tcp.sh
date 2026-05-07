#!/bin/bash
# SVCC v9.1 - 強化狀態向量 + 異常過濾 + 歷史記憶（從你日志重新演绎）
set -euo pipefail

SCRIPT_PATH="/root/svcc-tcp.sh"
LOG="/var/log/svcc-tcp.log"

if [ "$0" != "$SCRIPT_PATH" ]; then
    echo "[$(date)] SVCC v9.1 自動部署..."
    cp "$0" "$SCRIPT_PATH" 2>/dev/null || cat "$0" > "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    pkill -f "svcc-tcp.sh" 2>/dev/null || true
    nohup "$SCRIPT_PATH" > /dev/null 2>&1 &
    echo "✅ SVCC v9.1 已啟動"
    exit 0
fi

INTERVAL=90
GAIN=4
MAX_BUF=8388608
HISTORY_FILL=0   # 簡單記憶

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

safe_int() { echo "$1" | tr -dc '0-9' | sed 's/^0*//' | head -c 10 | grep -E '^[0-9]+$' || echo 0; }

if [[ $EUID -ne 0 ]]; then log "必須root"; exit 1; fi

while true; do
    # 強化採集：取 sent bytes 最大的連接
    read -r RTT CWND INFLIGHT <<< $(ss -tin | awk 'NR>1 && $7 ~ /^[0-9]/ {print $3,$5,$7}' | sort -k3 -nr | head -n1)
    RTT=$(safe_int "${RTT:-180}")
    CWND=$(safe_int "${CWND:-16}")
    INFLIGHT=$(safe_int "${INFLIGHT:-0}")

    # 異常值過濾
    [ $RTT -gt 5000 ] && RTT=180
    [ $CWND -gt 1000000 ] && CWND=40

    MEM_FREE=$(free -m | awk 'NR==2 {print int(($4+$7)/$2*100)}' || echo 50)
    FILL_RATE=$(( INFLIGHT * 100 / (CWND * 1448 + 1) ))

    # 歷史平滑
    HISTORY_FILL=$(( (HISTORY_FILL * 7 + FILL_RATE) / 8 ))

    log "狀態向量: RTT=${RTT} CWND=${CWND} Fill=${FILL_RATE}% HistFill=${HISTORY_FILL}% Mem=${MEM_FREE}%"

    # 交叉協同 + 記憶
    if [ $MEM_FREE -lt 30 ]; then
        GAIN=2
    elif [ $HISTORY_FILL -lt 45 ]; then
        GAIN=$((GAIN + 1))
        [ $GAIN -gt 8 ] && GAIN=8
    elif [ $RTT -gt 450 ] && [ $HISTORY_FILL -gt 60 ]; then
        GAIN=$((GAIN - 1))
        [ $GAIN -lt 3 ] && GAIN=3
    else
        GAIN=$((GAIN > 5 ? GAIN - 1 : GAIN))
    fi

    MAX_BUF=$(( CWND * 1448 * GAIN + 3145728 ))
    [ $MAX_BUF -gt 16777216 ] && MAX_BUF=16777216
    [ $MAX_BUF -lt 4194304 ] && MAX_BUF=4194304

    cat > /etc/sysctl.d/99-svcc.conf << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.core.rmem_max = ${MAX_BUF}
net.core.wmem_max = ${MAX_BUF}
net.ipv4.tcp_rmem = 4096 131072 ${MAX_BUF}
net.ipv4.tcp_wmem = 4096 65536 ${MAX_BUF}
EOF
    sysctl -p /etc/sysctl.d/99-svcc.conf >/dev/null 2>&1

    log "SVCC調整: Gain=${GAIN} MaxBuf=${MAX_BUF} HistFill=${HISTORY_FILL}%"

    sleep $INTERVAL
done
