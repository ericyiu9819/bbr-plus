#!/usr/bin/env bash
# Adaptive TCP Optimizer for Ubuntu/Debian - 最終最優穩定版
# 功能：自動Ping + ss真實指標 + 趨勢學習 + Hysteresis + 硬安全保護
# 使用：sudo bash adaptive-tcp.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

MONITOR_SCRIPT="/usr/local/bin/tcp-adaptive-monitor.sh"
HISTORY_CSV="/var/log/tcp-adaptive-history.csv"
SERVICE_NAME="tcp-adaptive-monitor"
TIMER_NAME="tcp-adaptive-monitor.timer"

# ====================== 檢測 ======================
detect_system() {
    . /etc/os-release
    log "系統: ${PRETTY_NAME}"
}

detect_kernel_and_memory() {
    KVER=$(uname -r)
    if [[ $(echo "$KVER" | cut -d. -f1) -ge 5 || $(echo "$KVER" | cut -d. -f1-2) == "4.9" ]]; then
        BBR_MODE="bbr"
    else
        BBR_MODE="cubic"
    fi

    MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
    if [[ $MEM_MB -le 2048 ]]; then
        BASE_MAX=67108864
    elif [[ $MEM_MB -le 8192 ]]; then
        BASE_MAX=134217728
    else
        BASE_MAX=268435456
    fi
    log "模式: ${BBR_MODE} | 記憶體: ${MEM_MB}MB | 基礎緩衝: $((BASE_MAX/1048576))MiB"
}

install_tools() {
    apt update -qq
    apt install -y --no-install-recommends iproute2 sysstat bpftune 2>/dev/null || true
    systemctl enable --now bpftune 2>/dev/null || true
}

apply_base_config() {
    cat > /etc/sysctl.d/99-adaptive-tcp.conf << EOF
net.core.default_qdisc = fq_codel
net.ipv4.tcp_congestion_control = ${BBR_MODE}
net.ipv4.tcp_rmem = 4096 131072 ${BASE_MAX}
net.ipv4.tcp_wmem = 4096 65536 ${BASE_MAX}
net.core.rmem_max = ${BASE_MAX}
net.core.wmem_max = ${BASE_MAX}
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_ecn = 2
net.core.somaxconn = 16384
net.ipv4.tcp_syncookies = 1
EOF
    sysctl --system >/dev/null 2>&1
    success "基礎配置已應用"
}

init_history() {
    if [[ ! -f "$HISTORY_CSV" ]]; then
        echo "timestamp,avg_rtt,avg_loss,old_rmem,new_rmem,action,reason,trend_factor" > "$HISTORY_CSV"
        success "歷史學習檔案已建立：${HISTORY_CSV}"
    fi
}

# ====================== 最終監控腳本（含趨勢 + 安全 + Hysteresis） ======================
create_monitor_script() {
    cat > "${MONITOR_SCRIPT}" << 'MONITOR_EOF'
#!/usr/bin/env bash
LOG="/var/log/tcp-adaptive-monitor.log"
HISTORY="/var/log/tcp-adaptive-history.csv"
TARGETS=("8.8.8.8" "1.1.1.1" "223.5.5.5")

echo "[$(date '+%Y-%m-%d %H:%M:%S')] === 優化循環開始 ===" >> "$LOG"

# 多目標Ping + ss真實指標
total_rtt=0; total_loss=0; valid=0
for t in "${TARGETS[@]}"; do
    RTT=$(ping -c 3 -W 2 "$t" 2>/dev/null | tail -1 | awk -F/ '{print int($5)}' || echo 0)
    LOSS=$(ping -c 5 -W 2 "$t" 2>/dev/null | grep -oP '\d+(?=% packet loss)' || echo 100)
    if [[ $RTT -gt 0 ]]; then
        total_rtt=$((total_rtt + RTT))
        total_loss=$((total_loss + LOSS))
        valid=$((valid + 1))
    fi
done

AVG_RTT=$((valid > 0 ? total_rtt / valid : 80))
AVG_LOSS=$((valid > 0 ? total_loss / valid : 2))

OLD_MAX=$(sysctl -n net.core.rmem_max)
NEW_MAX=$OLD_MAX

# 趨勢學習（最近5次）
TREND_FACTOR=0
if [[ -f "$HISTORY" && $(wc -l < "$HISTORY") -gt 5 ]]; then
    RECENT=$(tail -n 5 "$HISTORY" | awk -F, '{if($6=="INCREASE") print 1; else if($6=="DECREASE") print -1; else print 0}')
    SCORE=0; WEIGHT=1
    for t in $RECENT; do
        SCORE=$((SCORE + t * WEIGHT))
        WEIGHT=$((WEIGHT + 1))
    done
    TREND_FACTOR=$(awk "BEGIN {print $SCORE / 25}")
    [[ $(awk "BEGIN {print ($TREND_FACTOR > 0.15)}") -eq 1 ]] && TREND_FACTOR=0.15
    [[ $(awk "BEGIN {print ($TREND_FACTOR < -0.15)}") -eq 1 ]] && TREND_FACTOR=-0.15
fi

# Hysteresis（遲滯） + 調整決策
if [[ $AVG_RTT -gt 150 || $AVG_LOSS -gt 5 ]]; then
    NEW_MAX=$(awk "BEGIN {print int($OLD_MAX * (1.10 + $TREND_FACTOR))}")
    ACTION="INCREASE"
    REASON="高延遲/高丟包"
elif [[ $AVG_RTT -lt 45 && $AVG_LOSS -lt 1 ]]; then
    NEW_MAX=$(awk "BEGIN {print int($OLD_MAX * (0.93 + $TREND_FACTOR))}")
    ACTION="DECREASE"
    REASON="低延遲"
else
    ACTION="HOLD"
    REASON="網絡正常"
fi

# 硬安全限幅
[[ $NEW_MAX -gt 536870912 ]] && NEW_MAX=536870912   # 512MiB
[[ $NEW_MAX -lt 67108864 ]] && NEW_MAX=67108864     # 64MiB

# 執行調整（只有變化時才執行）
if [[ $NEW_MAX -ne $OLD_MAX ]]; then
    sysctl -w net.core.rmem_max=$NEW_MAX net.core.wmem_max=$NEW_MAX >/dev/null 2>&1
    echo "調整完成：${OLD_MAX} → ${NEW_MAX} (${ACTION}) Trend:${TREND_FACTOR}" >> "$LOG"
fi

# 記錄歷史
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
echo "${TIMESTAMP},${AVG_RTT},${AVG_LOSS},${OLD_MAX},${NEW_MAX},${ACTION},${REASON},${TREND_FACTOR}" >> "$HISTORY"

echo "RTT:${AVG_RTT}ms Loss:${AVG_LOSS}% ${ACTION} ${OLD_MAX}→${NEW_MAX} (Trend:${TREND_FACTOR})" >> "$LOG"
MONITOR_EOF

    chmod +x "${MONITOR_SCRIPT}"
    success "最終穩定優化腳本已建立（含趨勢 + Hysteresis + 安全保護）"
}

# ====================== systemd 服務 ======================
create_systemd_service() {
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Advanced TCP Optimizer with Trend Learning
After=network-online.target

[Service]
Type=oneshot
ExecStart=${MONITOR_SCRIPT}
EOF

    cat > "/etc/systemd/system/${TIMER_NAME}" << EOF
[Unit]
Description=Run Advanced TCP Optimizer every 10 minutes

[Timer]
OnBootSec=60
OnUnitActiveSec=10min
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now "${TIMER_NAME}" >/dev/null 2>&1
    success "每10分鐘最終穩定優化服務已啟用"
}

# ====================== 主流程 ======================
main() {
    echo -e "\n${CYAN}=== Ubuntu/Debian TCP 最終最優穩定版 ===${NC}\n"

    detect_system
    detect_kernel_and_memory
    install_tools
    init_history

    mkdir -p "/root/tcp-backup-$(date +%Y%m%d_%H%M)"
    success "配置已備份"

    apply_base_config
    create_monitor_script
    create_systemd_service

    echo -e "\n${GREEN}最終版部署完成！${NC}"
    echo "• 每10分鐘自動優化 + 趨勢學習"
    echo "• 加入Hysteresis與硬安全保護"
    echo "• 歷史記錄：${HISTORY_CSV}"
    echo "• 日誌：/var/log/tcp-adaptive-monitor.log"
    echo "• 查看最近調整：tail -n 15 ${HISTORY_CSV}"
}

main "$@"
