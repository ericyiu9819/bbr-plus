#!/usr/bin/env bash
echo "=== TCP 優化殘留參數徹底清理 ==="

# 1. 查找並移除所有舊的 sysctl 配置
echo "正在清理 sysctl 殘留..."
find /etc/sysctl.d/ -name "*tcp*" -o -name "*bbr*" -o -name "*apex*" -o -name "*server*" -o -name "*99-*" 2>/dev/null | while read -r file; do
    echo "移除: $file"
    rm -f "$file"
done

rm -f /etc/sysctl.d/99-apex-tcp.conf
rm -f /etc/sysctl.d/99-adaptive-tcp.conf.bak*

# 2. 清理 systemd 服務
echo "清理舊的 systemd 服務..."
systemctl stop tcp-adaptive-monitor.timer 2>/dev/null || true
systemctl disable tcp-adaptive-monitor.timer 2>/dev/null || true
systemctl stop tcp-adaptive-monitor.service 2>/dev/null || true

rm -f /etc/systemd/system/tcp-adaptive-monitor.*
rm -f /etc/systemd/system/apex-tcp-routes.service
rm -f /usr/local/bin/apex-tcp-routes.sh
rm -f /usr/local/bin/*bbr* 2>/dev/null

# 3. 恢復默認 sysctl
echo "恢復默認 TCP 參數..."
cat > /etc/sysctl.d/99-default-tcp.conf << EOF
net.core.default_qdisc = fq_codel
net.ipv4.tcp_congestion_control = cubic
net.ipv4.tcp_rmem = 4096 87380 6291456
net.ipv4.tcp_wmem = 4096 16384 4194304
EOF

sysctl --system >/dev/null 2>&1

# 4. 檢查並清理模組
echo "當前擁塞控制算法: $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "可用算法: $(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null)"

# 5. 最終檢查列表
echo ""
echo "=== 重要檢查項目 ==="
echo "1. 當前擁塞控制: $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "2. 緩衝區大小: rmem_max = $(sysctl -n net.core.rmem_max)"
echo "3. 運行中的定時任務:"
systemctl list-timers | grep -E "tcp|adaptive|apex|bbr" || echo "   無相關定時任務"
echo ""
echo "清理完成！現在可以安全安裝新的自適應腳本了。"
