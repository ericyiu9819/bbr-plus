#!/bin/bash
# GrokAccel 全系統通用版 - 一鍵安裝腳本（2026 最新優化）
# 支援 Ubuntu/Debian/CentOS/Alma/Rocky/Fedora/Alpine/Arch 等全部系統

set -e
echo "🚀 GrokAccel 全系統通用版 一鍵安裝開始（視頻+下載專用）..."

# ==================== 1. 自動安裝依賴 ====================
echo "🔧 正在檢查並安裝必要依賴（python3、curl）..."
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y python3 curl iproute2 ethtool
elif command -v yum >/dev/null; then
    yum install -y python3 curl iproute ethtool
elif command -v dnf >/dev/null; then
    dnf install -y python3 curl iproute ethtool
elif command -v apk >/dev/null; then
    apk add --no-cache python3 curl iproute2 ethtool
elif command -v pacman >/dev/null; then
    pacman -Syu --noconfirm python curl iproute2 ethtool
fi

# ==================== 2. 安裝主程式 ====================
sudo mkdir -p /opt/adatcp
sudo cat > /opt/adatcp/adatcp.py << 'PYEOF'
#!/usr/bin/env python3
import subprocess
import time
import re
import statistics
import logging
import os

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("/var/log/adatcp.log"), logging.StreamHandler()]
)

def run_cmd(cmd, check=True):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""

def get_interfaces():
    out = run_cmd("ip -o link show | awk -F': ' '{print $2}'")
    return [i.split()[0] for i in out.splitlines() if not i.startswith("lo")]

def get_link_speed(iface):
    out = run_cmd(f"ethtool {iface} 2>/dev/null | grep -i speed")
    match = re.search(r"(\d+)Mb/s", out)
    return int(match.group(1)) if match else 1000

def get_rtt_and_loss():
    hosts = ["8.8.8.8", "1.1.1.1", "223.5.5.5", "203.80.96.10", "www.google.com"]
    rtts, losses = [], []
    for host in hosts:
        out = run_cmd(f"ping -c 6 -i 0.2 -W 2 {host} 2>/dev/null")
        loss_match = re.search(r"(\d+)% packet loss", out)
        loss = int(loss_match.group(1)) if loss_match else 100
        rtt_match = re.search(r"/avg/ = .*?/(.*?)/", out)
        if rtt_match:
            try: rtts.append(float(rtt_match.group(1)))
            except: pass
        losses.append(loss)
    return statistics.mean(rtts) if rtts else 80.0, statistics.mean(losses) if losses else 0

def estimate_bdp(rtt_ms, bw_mbps):
    rtt_s = rtt_ms / 1000.0
    bw_bps = bw_mbps * 1_000_000 / 8.0
    return int(bw_bps * rtt_s * 1.5)

def get_adaptive_params(rtt, loss):
    score = (rtt / 100.0) + (loss * 2.0)
    if score > 6.0:
        return "嚴重模式", 4.5, 12, 7, 20
    elif score > 4.0:
        return "惡劣模式", 3.8, 15, 6, 18
    elif score > 2.5:
        return "一般模式", 2.8, 25, 4, 15
    else:
        return "優秀模式", 2.2, 40, 3, 10

def decide_and_get_params(rtt, loss, bdp, assumed_bw):
    params = {}
    params["net.ipv4.tcp_congestion_control"] = "bbr"
    mode, multiplier, sleep_sec, retries1, retries2 = get_adaptive_params(rtt, loss)
    max_buf = max(64 * 1024 * 1024, int(bdp * multiplier))
    params["net.ipv4.tcp_rmem"] = f"4096 131072 {max_buf}"
    params["net.ipv4.tcp_wmem"] = f"4096 131072 {max_buf}"
    params["net.core.rmem_max"] = str(max_buf)
    params["net.core.wmem_max"] = str(max_buf)
    params["net.core.default_qdisc"] = "fq_codel"
    params["net.ipv4.tcp_retries1"] = str(retries1)
    params["net.ipv4.tcp_retries2"] = str(retries2)
    params["net.ipv4.tcp_fastopen"] = "3"
    params["net.ipv4.tcp_max_syn_backlog"] = "8192"
    params["net.core.somaxconn"] = "8192"
    return params, mode, sleep_sec

def apply_params(params):
    for k, v in params.items():
        run_cmd(f"sysctl -w {k}={v}", check=False)
    for iface in get_interfaces()[:1]:
        run_cmd(f"tc qdisc replace dev {iface} root fq_codel 2>/dev/null || true")

def main():
    if os.geteuid() != 0:
        print("❌ 請用 root 或 sudo 執行")
        exit(1)
    logging.info("🚀 AdaTCP 全系統通用版啟動（視頻+下載專用）")
    run_cmd("modprobe tcp_bbr 2>/dev/null || true")
    assumed_bw = max((get_link_speed(i) for i in get_interfaces()), default=1000)
    logging.info(f"偵測到最大鏈路速度: {assumed_bw} Mbps")
    while True:
        try:
            rtt, loss = get_rtt_and_loss()
            bdp = estimate_bdp(rtt, assumed_bw)
            params, mode, sleep_sec = decide_and_get_params(rtt, loss, bdp, assumed_bw)
            apply_params(params)
            logging.info(f"✅ {mode} 調整完成 | RTT={rtt:.1f}ms | 丟包={loss:.1f}% | BDP≈{bdp//(1024*1024)}MB | CC=BBR | 下一輪 {sleep_sec}s")
        except Exception as e:
            logging.error(f"迴圈異常: {e}")
        time.sleep(sleep_sec)

if __name__ == "__main__":
    main()
PYEOF

sudo chmod +x /opt/adatcp/adatcp.py

# ==================== 3. 通用啟動方式 ====================
if command -v systemctl >/dev/null && systemctl --version >/dev/null 2>&1; then
    # 有 systemd 的系統（推薦）
    sudo cat > /etc/systemd/system/adatcp.service << EOF
[Unit]
Description=AdaTCP 全日實時自適應版 TCP 加速器
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/adatcp/adatcp.py
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable --now adatcp
    echo "✅ 使用 systemd 啟動成功"
else
    # 沒有 systemd 的系統（舊系統、容器）
    sudo cat > /usr/local/bin/adatcp-daemon << EOF
#!/bin/bash
while true; do
    if ! pgrep -f adatcp.py >/dev/null; then
        nohup python3 /opt/adatcp/adatcp.py >> /var/log/adatcp.log 2>&1 &
    fi
    sleep 30
done
EOF
    sudo chmod +x /usr/local/bin/adatcp-daemon
    crontab -l 2>/dev/null | grep -v adatcp-daemon | crontab -
    (crontab -l 2>/dev/null; echo "@reboot /usr/local/bin/adatcp-daemon") | crontab -
    nohup /usr/local/bin/adatcp-daemon >/dev/null 2>&1 &
    echo "✅ 使用 crontab + nohup 啟動成功（無 systemd 系統）"
fi

# ==================== 4. 安裝完成後自動打開程式 ====================
echo ""
echo "🎉 安裝完成！AdaTCP 已自動啟動並開始全日自適應優化"
echo "正在自動打開即時運行畫面（按 Ctrl + C 可退出監控，程式繼續在後台運行）..."
sleep 2
if command -v journalctl >/dev/null; then
    sudo journalctl -u adatcp -f
else
    tail -f /var/log/adatcp.log
fi
