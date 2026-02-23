#!/bin/bash
# GrokAccel v2.0 Universal - 适配任何 Linux 系统
# Grok 2026 独家优化版
set -euo pipefail

echo -e "\033[1;32m🚀 GrokAccel v2.0 Universal 开始安装...\033[0m"

# 1. Root 检查
if [ "$(id -u)" -ne 0 ]; then
  echo -e "\033[1;31m❌ 请用 root 或 sudo 执行！\033[0m"
  exit 1
fi

# 2. 备份原配置
BACKUP_DIR="/etc/grokaccel_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -f /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true
cp -rf /etc/sysctl.d/ "$BACKUP_DIR/" 2>/dev/null || true
echo -e "\033[1;32m✅ 配置已备份到：$BACKUP_DIR\033[0m"

# 3. 自动安装依赖
echo -e "\033[1;33m📦 正在安装依赖 (python3 curl iproute2)...\033[0m"
PACKAGES="python3 curl iproute2"

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq && apt-get install -y $PACKAGES
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y $PACKAGES
elif command -v yum >/dev/null 2>&1; then
  yum install -y $PACKAGES
elif command -v pacman >/dev/null 2>&1; then
  pacman -Syu --needed --noconfirm $PACKAGES
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache $PACKAGES
elif command -v zypper >/dev/null 2>&1; then
  zypper install -y $PACKAGES
else
  echo -e "\033[1;33m⚠️ 未知包管理器，请手动确保 python3、curl、iproute2 已安装\033[0m"
fi

# 4. 基础 TCP 优化参数（适用于所有内核）
cat > /etc/sysctl.d/99-grokaccel-base.conf << 'EOF'
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 8192
vm.swappiness = 10
EOF

sysctl -p /etc/sysctl.d/99-grokaccel-base.conf >/dev/null 2>&1 || true

# 5. 加载模块
modprobe tcp_bbr 2>/dev/null || true
modprobe tcp_hybla 2>/dev/null || true

# 6. 创建自适应守护进程（随机间隔 + 日志）
cat > /usr/local/bin/grokaccel_daemon.py << 'PYEOF'
#!/usr/bin/env python3
import subprocess, re, time, os, random, logging
from collections import deque

logging.basicConfig(filename='/var/log/grokaccel.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

print("GrokAccel v2.0 Universal 守护进程启动...")
logging.info("守护进程启动")

TARGETS = ['223.5.5.5', '180.76.76.76', '8.8.8.8']
HISTORY = deque(maxlen=10)

def ping_rtt(host):
    try:
        out = subprocess.check_output(['ping', '-c', '3', '-W', '2', host], stderr=subprocess.STDOUT).decode()
        rtt = float(re.search(r'rtt min/avg/max/mdev = .*?/(.*?)/', out).group(1)) if re.search(r'rtt', out) else 999
        loss = float(re.search(r'(\d+)% packet loss', out).group(1)) if re.search(r'packet loss', out) else 0
        return rtt, loss
    except:
        return 999, 100

def grok_predict_score():
    if not HISTORY: return 50, 150, 5
    avg_rtt = sum(r for r,l in HISTORY) / len(HISTORY)
    avg_loss = sum(l for r,l in HISTORY) / len(HISTORY)
    score = max(0, 100 - avg_rtt * 0.55 - avg_loss * 7)
    return score, avg_rtt, avg_loss

def adjust_tcp(score, rtt, loss):
    if score > 75:
        os.system("sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1")
        os.system("sysctl -w net.core.rmem_max=134217728 >/dev/null 2>&1")
        logging.info(f"🌟 极致模式 RTT:{rtt:.1f}ms")
    elif score > 45:
        os.system("sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1")
        logging.info(f"⚡ 平衡模式 RTT:{rtt:.1f}ms")
    else:
        os.system("sysctl -w net.ipv4.tcp_congestion_control=hybla >/dev/null 2>&1")
        logging.info(f"🛡️ 抗抖模式 RTT:{rtt:.1f}ms 丢包:{loss:.1f}%")

while True:
    for t in TARGETS:
        r, l = ping_rtt(t)
        HISTORY.append((r, l))
        time.sleep(0.3)
    score, rtt, loss = grok_predict_score()
    adjust_tcp(score, rtt, loss)
    sleep_time = random.randint(20, 55)   # 随机间隔，更低调
    time.sleep(sleep_time)
PYEOF

chmod +x /usr/local/bin/grokaccel_daemon.py

# 7. 安装服务（systemd 优先）
if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/grokaccel.service << 'EOF'
[Unit]
Description=GrokAccel v2.0 Universal TCP Accelerator
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/grokaccel_daemon.py
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now grokaccel.service
  echo -e "\033[1;32m✅ 已安装为 systemd 服务\033[0m"
else
  # 非 systemd 回退方案
  cat > /usr/local/bin/grokaccel_start.sh << 'EOF'
#!/bin/bash
nohup /usr/bin/python3 /usr/local/bin/grokaccel_daemon.py >> /var/log/grokaccel.log 2>&1 &
echo $! > /var/run/grokaccel.pid
EOF
  chmod +x /usr/local/bin/grokaccel_start.sh
  /usr/local/bin/grokaccel_start.sh
  (crontab -l 2>/dev/null | grep -v grokaccel; echo "@reboot /usr/local/bin/grokaccel_start.sh") | crontab -
  echo -e "\033[1;32m✅ 非 systemd 系统：已用 nohup + crontab 开机自启\033[0m"
fi

echo -e "\033[1;32m🎉 GrokAccel v2.0 Universal 安装完成！\033[0m"
echo "📊 查看日志：tail -f /var/log/grokaccel.log"
echo "🔍 systemd 状态（如果适用）：systemctl status grokaccel"
echo "🛑 停止服务：systemctl stop grokaccel   （或 pkill -f grokaccel_daemon）"
echo ""
echo "一键卸载命令（复制执行）："
echo "systemctl stop grokaccel && systemctl disable grokaccel 2>/dev/null || true; rm -f /etc/sysctl.d/99-grokaccel* /usr/local/bin/grokaccel* /etc/systemd/system/grokaccel.service /var/log/grokaccel.log; crontab -l | grep -v grokaccel | crontab -; sysctl -p"
echo ""
echo "建议重启 VPS：reboot"
echo "这是目前市面上最通用的版本了！装完告诉我你的系统和效果，我还能继续给你加多路径、仪表盘等功能～"
