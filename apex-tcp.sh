#!/bin/bash
# =============================================
# VPS TCP 加速冗余清理脚本 v2.4（精炼无冗余版）
# 功能：清理 + 激进 BBR 收敛与探测
# =============================================

set -euo pipefail

LOGFILE="/var/log/clean-tcp-redundancy.log"

perform_cleanup() {
    {
        echo "=== VPS TCP 冗余清理 + 激进 BBR 优化开始 $(date '+%Y-%m-%d %H:%M:%S') ==="

        echo "→ 清理 /var/log 冗余日志..."
        find /var/log -type f -name "*.log" -size +10M -exec truncate -s 0 {} \; 2>/dev/null || true
        find /var/log -type f \( -name "*.gz" -o -name "*.old" -o -name "*.1" \) -delete 2>/dev/null || true

        echo "→ 清理 apt 缓存..."
        apt clean
        apt autoclean
        rm -rf /var/cache/apt/archives/* 2>/dev/null || true

        echo "→ 清理临时文件..."
        find /tmp -mindepth 1 ! -name ".tmp" -delete 2>/dev/null || true
        find /var/tmp -mindepth 1 -delete 2>/dev/null || true

        echo "→ 检查并移除旧内核..."
        CURRENT_KERNEL="$(uname -r)"
        apt purge -y $(dpkg --list | grep -E 'linux-image-[0-9]' | awk '{print $2}' | grep -v "$CURRENT_KERNEL" | grep -v "linux-image-generic" || true) 2>/dev/null || true
        update-grub 2>/dev/null || true

        echo "→ 清理残留网络配置..."
        rm -f /etc/sysctl.d/99-*.conf.bak 2>/dev/null || true

        echo "→ 优化 journal 日志..."
        journalctl --vacuum-time=7d
        journalctl --vacuum-size=100M

        echo "→ 应用激进 BBR 收敛 & 探测优化..."
        cat > /etc/sysctl.d/99-bbr.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 激进缓冲（16M 平衡低内存）
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 131072 16777216
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# 收敛加速
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 8192

# 探测激进
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_bbr_probe_rtt_win_ms = 3000
EOF

        sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1 || true
        echo "✅ 激进 BBR 优化已应用"

        sync
        echo "=== 清理 + 激进 BBR 优化完成 $(date '+%Y-%m-%d %H:%M:%S') ==="
        echo "磁盘使用: $(df -h / | tail -n 1)"
    } | tee -a "$LOGFILE"
}

install_cron() {
    if ! crontab -l 2>/dev/null | grep -q "clean-tcp-redundancy.sh"; then
        (crontab -l 2>/dev/null; echo "0 4 * * * /root/clean-tcp-redundancy.sh >> /var/log/clean-tcp-redundancy.log 2>&1") | crontab -
        echo "✅ 已添加每日凌晨4点自动任务" | tee -a "$LOGFILE"
    else
        echo "ℹ️ 定时任务已存在" | tee -a "$LOGFILE"
    fi
}

perform_cleanup
install_cron

echo "=== 脚本 v2.4（精炼版）执行完毕 ==="
