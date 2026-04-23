#!/bin/bash
# VPN Server + Dashboard Installer
# Supports: Hysteria 2 (UDP) + VLESS+Reality (TCP)

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SERVER_IP=$(curl -s -4 ifconfig.me || ip route get 1 2>/dev/null | awk '{print $NF;exit}')

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  VPN Server + Dashboard Installer${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Server IP: ${GREEN}$SERVER_IP${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Install dependencies
echo -e "${YELLOW}[1/6] Installing dependencies...${NC}"
apt-get update
apt-get install -y curl wget gnupg2 ca-certificates lsb-release ubuntu-keyring
apt-get install -y python3 python3-pip nginx git certbot python3-certbot-nginx

# Install Docker
echo -e "${YELLOW}[2/6] Installing Docker...${NC}"
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
fi

# Setup firewall
echo -e "${YELLOW}[3/6] Configuring firewall...${NC}"
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8443/udp comment 'Hysteria 2'
ufw --force enable

# Generate credentials
HYSTERIA_PASS=$(openssl rand -base64 16 | tr -d '=+/')
HYSTERIA_OBFS=$(openssl rand -base64 8 | tr -d '=+/')
VLESS_UUID=$(cat /proc/sys/kernel/random/uuid)
VLESS_PRIVATE=$(openssl genpkey -algorithm x25519 -outform der 2>/dev/null | base64 | tr '+/' '-_' | tr -d '=')
XUI_USER=$(openssl rand -hex 4)
XUI_PASS=$(openssl rand -base64 12 | tr -d '=+/')

echo -e "${YELLOW}[4/6] Installing Hysteria 2...${NC}"
mkdir -p /etc/hysteria2
mkdir -p /opt/vpn-dashboard

# Hysteria 2 Config
cat > /etc/hysteria2/config.yaml <> EOF
listen: :8443
tls:
  cert: /etc/hysteria2/certs/server.crt
  key: /etc/hysteria2/certs/server.key
auth:
  type: password
  password: $HYSTERIA_PASS
obfs:
  type: salamander
  salamander:
    password: $HYSTERIA_OBFS
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 25165824
  maxConnReceiveWindow: 25165824
masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
EOF

# Generate self-signed cert for Hysteria
openssl req -x509 -nodes -days 365 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /etc/hysteria2/certs/server.key -out /etc/hysteria2/certs/server.crt \
    -subj "/CN=$SERVER_IP" 2>/dev/null
chmod 600 /etc/hysteria2/certs/*

# Install Hysteria 2 binary
bash <> (curl -fsSL https://get.hy2.sh/)
systemctl enable hysteria-server.service

# Install x-ui (VLESS+Reality)
echo -e "${YELLOW}[5/6] Installing x-ui (VLESS+Reality)...${NC}"
bash < (curl -Ls https://raw.githubusercontent.com/vaxilu/x-ui/master/install.sh)

# Configure x-ui
mkdir -p /etc/x-ui
sqlite3 /etc/x-ui/x-ui.db <> SQL
UPDATE settings SET value = '$XUI_USER' WHERE key = 'username';
UPDATE settings SET value = '$XUI_PASS' WHERE key = 'password';
UPDATE settings SET value = '$(openssl rand -hex 8)' WHERE key = 'webBasePath';
SQL

# Get webBasePath
WEB_PATH=$(sqlite3 /etc/x-ui/x-ui.db "SELECT value FROM settings WHERE key='webBasePath';" 2>/dev/null || echo "$(openssl rand -hex 8)")

# Setup Dashboard
echo -e "${YELLOW}[6/6] Installing VPN Dashboard...${NC}"
cat > /opt/vpn-dashboard/app.py <> 'DASHEOF'
#!/usr/bin/env python3
import flask
import psutil
import subprocess
import json
import os
from datetime import datetime
from functools import wraps

app = flask.Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32).hex()

ADMIN_USER = 'admin'
ADMIN_PASS = os.environ.get('DASHBOARD_PASS', 'vpnadmin123')

def check_auth(username, password):
    return username == ADMIN_USER and password == ADMIN_PASS

def authenticate():
    return flask.Response('Access denied', 401, 
        {'WWW-Authenticate': 'Basic realm="VPN Dashboard"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = flask.request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def get_system_info():
    return {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory': {
            'total': round(psutil.virtual_memory().total / 1024**3, 2),
            'used': round(psutil.virtual_memory().used / 1024**3, 2),
            'percent': psutil.virtual_memory().percent
        },
        'disk': {
            'total': round(psutil.disk_usage('/').total / 1024**3, 2),
            'used': round(psutil.disk_usage('/').used / 1024**3, 2),
            'percent': psutil.disk_usage('/').percent
        },
        'uptime': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M'),
        'load_avg': [round(x, 2) for x in psutil.getloadavg()]
    }

def get_network_stats():
    try:
        net_io = psutil.net_io_counters()
        return {
            'total': {
                'rx_gb': round(net_io.bytes_recv / 1024**3, 2),
                'tx_gb': round(net_io.bytes_sent / 1024**3, 2)
            }
        }
    except:
        return {'total': {'rx_gb': 0, 'tx_gb': 0}}

def get_hysteria_status():
    try:
        result = subprocess.run(['systemctl', 'is-active', 'hysteria-server'], 
            capture_output=True, text=True, timeout=5)
        status = result.stdout.strip()
        
        # Get connections
        ss = subprocess.run(['ss', '-unap'], capture_output=True, text=True, timeout=5)
        conns = sum(1 for line in ss.stdout.split('\n') if 'hysteria' in line.lower())
        
        return {'status': status, 'connections': conns}
    except:
        return {'status': 'unknown', 'connections': 0}

def get_xui_status():
    try:
        result = subprocess.run(['systemctl', 'is-active', 'x-ui'], 
            capture_output=True, text=True, timeout=5)
        return {'status': result.stdout.strip()}
    except:
        return {'status': 'unknown'}

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPN Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh; color: #fff; padding: 20px;
        }
        .container { max-width: 1100px; margin: 0 auto; }
        h1 { text-align: center; color: #00d9ff; margin-bottom: 10px; }
        .subtitle { text-align: center; color: #888; margin-bottom: 30px; font-size: 14px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; }
        .card {
            background: rgba(255,255,255,0.05); border-radius: 16px;
            padding: 24px; border: 1px solid rgba(255,255,255,0.1);
        }
        .card h2 { color: #00d9ff; margin-bottom: 15px; font-size: 18px; display: flex; align-items: center; gap: 10px; }
        .stat-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .stat-row:last-child { border-bottom: none; }
        .stat-label { color: #888; }
        .stat-value { font-weight: bold; }
        .badge {
            display: inline-block; padding: 4px 12px; border-radius: 20px;
            font-size: 12px; font-weight: bold;
        }
        .badge.success { background: #00ff88; color: #000; }  /* Green for active */
        .badge.error { background: #ff4444; color: #fff; }
        .code-box {
            background: #0a0a1a; border: 1px solid #333; border-radius: 8px;
            padding: 15px; font-family: monospace; font-size: 11px; color: #00ff88;
            word-break: break-all; margin-top: 10px;
        }
        .btn {
            padding: 8px 16px; border: none; border-radius: 6px;
            cursor: pointer; font-weight: bold; transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.8; }
        .btn-primary { background: #00d9ff; color: #000; }
        .btn-success { background: #00ff88; color: #000; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 VPN Dashboard</h1>
        <p class="subtitle">{{ server_ip }} • {{ timestamp }}</p>
        
        <div class="grid">
            <!-- System -->
            <div class="card">
                <h2>💻 System</h2>
                <div class="stat-row">
                    <span class="stat-label">CPU</span>
                    <span class="stat-value">{{ system.cpu_percent }}%</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">RAM</span>
                    <span class="stat-value">{{ system.memory.used }}/{{ system.memory.total }} GB ({{ system.memory.percent }}%)</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Disk</span>
                    <span class="stat-value">{{ system.disk.used }}/{{ system.disk.total }} GB ({{ system.disk.percent }}%)</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Uptime</span>
                    <span class="stat-value">{{ system.uptime }}</span>
                </div>
            </div>
            
            <!-- Hysteria 2 -->
            <div class="card">
                <h2>⚡ Hysteria 2 (UDP)</h2>
                <div class="stat-row">
                    <span class="stat-label">Status</span>
                    <span class="badge {{ 'success' if hysteria.status == 'active' else 'error' }}">
                        {{ hysteria.status | upper }}
                    </span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Connections</span>
                    <span class="stat-value">{{ hysteria.connections }}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Port</span>
                    <span class="stat-value">8443/UDP</span>
                </div>
                <button class="btn btn-primary" style="margin-top: 15px; width: 100%;" 
                        onclick="copyToClipboard('hysteria-url')">📋 Copy Hysteria URL</button>
                <input type="text" id="hysteria-url" value="hysteria2://{{ hysteria_pass }}@{{ server_ip }}:8443?obfs=salamander&obfs-password={{ hysteria_obfs }}&insecure=1#Hysteria2" 
                       style="position: absolute; left: -9999px;">
            </div>
            
            <!-- VLESS -->
            <div class="card">
                <h2>🔒 VLESS + Reality (TCP)</h2>
                <div class="stat-row">
                    <span class="stat-label">Status</span>
                    <span class="badge {{ 'success' if xui.status == 'active' else 'error' }}">
                        {{ xui.status | upper }}
                    </span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Panel</span>
                    <span class="stat-value"><a href="https://{{ server_ip }}:{{ xui_port }}{{ web_path }}" target="_blank" style="color: #00d9ff;">Open x-ui</a></span>
                </div>
                <button class="btn btn-success" style="margin-top: 15px; width: 100%;" 
                        onclick="copyToClipboard('vless-url')">📋 Copy VLESS URL</button>
                <input type="text" id="vless-url" value="vless://{{ vless_uuid }}@{{ server_ip }}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.nvidia.com&pbk={{ vless_public }}&type=tcp&fp=chrome#VLESS-Reality" 
                       style="position: absolute; left: -9999px;">
            </div>
            
            <!-- Network -->
            <div class="card">
                <h2>📊 Traffic</h2>
                <div class="stat-row">
                    <span class="stat-label">Received</span>
                    <span class="stat-value" style="color: #00ff88;">{{ network.total.rx_gb }} GB ⬇️</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Sent</span>
                    <span class="stat-value" style="color: #ffa500;">{{ network.total.tx_gb }} GB ⬆️</span>
                </div>
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 30px; color: #666; font-size: 12px;">
            VPN Server • Auto-refresh: 30s • Dashboard Port: 8080
        </div>
    </div>
    
    <script>
        function copyToClipboard(elementId) {
            const el = document.getElementById(elementId);
            el.select();
            document.execCommand('copy');
            alert('Copied to clipboard!');
        }
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>
"""

@app.route('/')
@requires_auth
def dashboard():
    return flask.render_template_string(DASHBOARD_HTML,
        system=get_system_info(),
        network=get_network_stats(),
        hysteria=get_hysteria_status(),
        xui=get_xui_status(),
        server_ip=os.environ.get('SERVER_IP', '127.0.0.1'),
        hysteria_pass=os.environ.get('HYSTERIA_PASS', ''),
        hysteria_obfs=os.environ.get('HYSTERIA_OBFS', ''),
        vless_uuid=os.environ.get('VLESS_UUID', ''),
        vless_public=os.environ.get('VLESS_PUBLIC', ''),
        xui_port=os.environ.get('XUI_PORT', '54321'),
        web_path=os.environ.get('WEB_PATH', '/'),
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

@app.route('/api/stats')
@requires_auth
def api_stats():
    return flask.jsonify({
        'system': get_system_info(),
        'network': get_network_stats(),
        'hysteria': get_hysteria_status(),
        'xui': get_xui_status(),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/restart/<service>', methods=['POST'])
@requires_auth
def restart_service(service):
    import subprocess
    allowed = ['hysteria-server', 'x-ui', 'nginx']
    if service not in allowed:
        return flask.jsonify({'error': 'Service not allowed'}), 403
    result = subprocess.run(['systemctl', 'restart', service], 
        capture_output=True, text=True, timeout=30)
    return flask.jsonify({'success': result.returncode == 0, 
        'service': service, 'error': result.stderr if result.returncode != 0 else None})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=False)
DASHEOF

chmod +x /opt/vpn-dashboard/app.py
python3 -m pip install flask psutil --quiet

# Dashboard systemd service
cat > /etc/systemd/system/vpn-dashboard.service <> EOF
[Unit]
Description=VPN Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vpn-dashboard
Environment="SERVER_IP=$SERVER_IP"
Environment="HYSTERIA_PASS=$HYSTERIA_PASS"
Environment="HYSTERIA_OBFS=$HYSTERIA_OBFS"
Environment="VLESS_UUID=$VLESS_UUID"
Environment="VLESS_PUBLIC=$VLESS_PRIVATE"
Environment="XUI_PORT=54321"
Environment="WEB_PATH=/$WEB_PATH"
Environment="DASHBOARD_PASS=$XUI_PASS"
ExecStart=/usr/bin/python3 /opt/vpn-dashboard/app.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Nginx config for dashboard
cat > /etc/nginx/sites-available/vpn-dashboard <> EOF
server {
    listen 9443 ssl http2;
    server_name _;
    
    ssl_certificate /etc/letsencrypt/live/dboard.$SERVER_IP.sslip.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dboard.$SERVER_IP.sslip.io/privkey.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

ln -sf /etc/nginx/sites-available/vpn-dashboard /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# Save credentials
cat > /root/vpn-credentials.txt <> EOF
=== VPN Server Credentials ===
Server IP: $SERVER_IP

=== Hysteria 2 (UDP) ===
URL: hysteria2://$HYSTERIA_PASS@$SERVER_IP:8443?obfs=salamander&obfs-password=$HYSTERIA_OBFS&insecure=1#Hysteria2
Password: $HYSTERIA_PASS
Obfs Password: $HYSTERIA_OBFS
Port: 8443/UDP

=== VLESS + Reality (TCP) ===
UUID: $VLESS_UUID
Public Key: $VLESS_PRIVATE
SNI: www.nvidia.com
Flow: xtls-rprx-vision
Port: 443/TCP

=== x-ui Panel ===
URL: https://$SERVER_IP:54321/$WEB_PATH
Username: $XUI_USER
Password: $XUI_PASS

=== Dashboard ===
URL: https://$SERVER_IP:9443/
Username: admin
Password: $XUI_PASS

=== Client Apps ===
iOS: Shadowrocket, Hiddify
Android: Hiddify, NekoBox
Windows: Hiddify, NekoRay
macOS: Hiddify
EOF

chmod 600 /root/vpn-credentials.txt

# Start everything
systemctl enable --now hysteria-server
systemctl enable --now vpn-dashboard
certbot --nginx -d dboard.$SERVER_IP.sslip.io --agree-tos -n -m admin@localhost 2>/dev/null || true

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  ✅ VPN Server Installed Successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
cat /root/vpn-credentials.txt
echo ""
echo -e "${BLUE}========================================${NC}"
