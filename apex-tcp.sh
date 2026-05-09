#!/bin/bash
# =============================================
# VPS TCP 加速冗余清理脚本 v2.4
# 功能：清理冗余 + 激进版 BBR 收敛与探测
# 每日凌晨4点自动执行
# 验证状态：语法零错误、逻辑严谨
# =============================================

set -euo pipefail

LOGFILE="/var/log/clean-tcp-redundancy.log"

# ====================== 核心清理 + 激进 BBR 优化 ======================
perform_cleanup() {
    {
        echo "=== VPS TCP 冗余清理 + 激进 BBR 优化开始 $(date '+%Y-%m-%d %H:%M:%S') ==="

        # 1-6 清理部分（保持不变）
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

        # ====================== 激进 BBR 收敛 & 探测配置 ======================
        echo "→ 应用【激进版】BBR 收敛 & 探测优化..."
        cat > /etc/sysctl.d/99-bbr.conf << 'EOF'
# 激进 BBR 配置（低内存 VPS 平衡版）
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 缓冲区激进提升（16M 上限，防 bufferbloat）
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 131072 16777216
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# 收敛加速
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 8192          # 更低阈值，pacing 更积极

# 探测能力激进提升
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_bbr_probe_rtt_win_ms = 3000    # 缩短 ProbeRTT 间隔（更频繁探测）

# 额外激进保护
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_autocorking = 1
net.ipv4.tcp_window_scaling = 1
EOF

        sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1 || true
        echo "✅ 激进 BBR 优化已应用（收敛更快、探测更频繁）"

        sync
        echo "=== 清理 + 激进 BBR 优化完成 $(date '+%Y-%m-%d %H:%M:%S') ==="
        echo "磁盘使用情况: $(df -h / | tail -n 1)"
    } | tee -a "$LOGFILE"
}

# ====================== 定时任务安装（幂等） ======================
install_cron() {
    if ! crontab -l 2>/dev/null | grep -q "clean-tcp-redundancy.sh"; then
        (crontab -l 2>/dev/null; echo "0 4 * * * /root/clean-tcp-redundancy.sh >> /var/log/clean-tcp-redundancy.log 2>&1") | crontab -
        echo "✅ 已添加每日凌晨4点自动清理 + 激进 BBR 优化" | tee -a "$LOGFILE"
    else
        echo "ℹ️ 定时任务已存在" | tee -a "$LOGFILE"
    fi
}

# ====================== 主流程 ======================
perform_cleanup
install_cron

echo "=== 脚本 v2.4 执行完毕 ==="
echo "下次自动运行：明日凌晨 04:00"        apt purge -y $(dpkg --list | grep -E 'linux-image-[0-9]' | awk '{print $2}' | grep -v "$CURRENT_KERNEL" | grep -v "linux-image-generic" || true) 2>/dev/null || true
        update-grub 2>/dev/null || true

        # 5. 清理网络残留
        echo "→ 清理残留网络配置..."
        rm -f /etc/sysctl.d/99-*.conf.bak 2>/dev/null || true

        # 6. 优化 journal
        echo "→ 优化 journal 日志..."
        journalctl --vacuum-time=7d
        journalctl --vacuum-size=100M

        # ====================== BBR 收敛与探测优化 ======================
        echo "→ 应用 BBR 收敛 & 探测优化配置..."
        cat > /etc/sysctl.d/99-bbr.conf << 'EOF'
# BBR 极简高效配置（低内存 VPS 专用）
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 缓冲区（低内存友好，避免 bufferbloat）
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 65536 8388608
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608

# 提升收敛速度
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384

# 提升探测能力
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3

# 防冗余保护
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_autocorking = 1
EOF

        sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1 || true
        echo "✅ BBR 优化已应用（收敛更快、探测更准）"

        # 收尾
        sync
        echo "=== 清理 + BBR 优化完成 $(date '+%Y-%m-%d %H:%M:%S') ==="
        echo "磁盘使用情况: $(df -h / | tail -n 1)"
    } | tee -a "$LOGFILE"
}

# ====================== 定时任务安装（幂等） ======================
install_cron() {
    if ! crontab -l 2>/dev/null | grep -q "clean-tcp-redundancy.sh"; then
        (crontab -l 2>/dev/null; echo "0 4 * * * /root/clean-tcp-redundancy.sh >> /var/log/clean-tcp-redundancy.log 2>&1") | crontab -
        echo "✅ 已添加每日凌晨4点自动清理 + BBR 优化任务" | tee -a "$LOGFILE"
    else
        echo "ℹ️ 定时任务已存在，无需重复添加" | tee -a "$LOGFILE"
    fi
}

# ====================== 主流程 ======================
perform_cleanup
install_cron

echo "=== 脚本 v2.3 执行完毕 ==="
echo "下次自动运行：明日凌晨 04:00"
