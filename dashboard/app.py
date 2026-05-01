#!/usr/bin/env python3
"""VPN Dashboard - Web interface for monitoring VPN services

Supports:
- Hysteria 2 (QUIC/UDP proxy)
- VLESS + Reality (Xray proxy)
- System metrics monitoring
- SSL certificate management (Let's Encrypt)
"""

import flask
import psutil
import subprocess
import json
import os
import re
from datetime import datetime
from functools import wraps

# Configuration from environment variables
SECRET_KEY = os.environ.get('DASHBOARD_SECRET_KEY', 'change-this-secret-key-in-production')
ADMIN_USER = os.environ.get('DASHBOARD_ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('DASHBOARD_ADMIN_PASS', 'JURb8ZZcUBRBdArqM9c')
SERVER_DOMAIN = os.environ.get('SERVER_DOMAIN', 'dboard.foolsland.ru')
X_UI_DOMAIN = os.environ.get('X_UI_DOMAIN', 'dboard.foolsland.ru')
X_UI_PORT = os.environ.get('X_UI_PORT', '9443')
X_UI_PATH = os.environ.get('X_UI_PATH', '/V2ETsZ9G7I666NBTlFBkEk6/')
LETSENCRYPT_EMAIL = os.environ.get('LETSENCRYPT_EMAIL', 'admin@example.com')
NGINX_SITES_PATH = os.environ.get('NGINX_SITES_PATH', '/etc/nginx/sites-available')
XUI_DB_PATH = os.environ.get('XUI_DB_PATH', '/usr/local/x-ui/x-ui.db')
XUI_DB_PATH_ALT = '/etc/x-ui/x-ui.db'

app = flask.Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY


def format_bytes(bytes_val):
    """Format bytes to human readable string"""
    if bytes_val == 0:
        return '0 B'
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while bytes_val >= 1024 and i < len(units) - 1:
        bytes_val /= 1024
        i += 1
    return f'{bytes_val:.2f} {units[i]}'


def check_auth(username, password):
    """Check if username and password are correct"""
    return username == ADMIN_USER and password == ADMIN_PASS


def authenticate():
    """Send 401 response that enables web auth"""
    return flask.Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Dashboard"'}
    )


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = flask.request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def get_system_info():
    """Get system metrics"""
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
    """Get network traffic statistics"""
    try:
        net_io = psutil.net_io_counters()
        interfaces = psutil.net_if_stats()
        
        primary_iface = None
        for iface, stats in interfaces.items():
            if iface != 'lo' and stats.isup:
                primary_iface = iface
                break
        
        iface_stats = None
        if primary_iface:
            iface_stats = {
                'name': primary_iface,
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
        
        return {
            'total': {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            },
            'primary_interface': iface_stats
        }
    except Exception as e:
        return {'error': str(e)}



# Traffic DB
TRAFFIC_DB = '/var/lib/vpn-dashboard/traffic.db'

def init_traffic_db():
    try:
        os.makedirs('/var/lib/vpn-dashboard', exist_ok=True)
        import sqlite3
        conn = sqlite3.connect(TRAFFIC_DB)
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS traffic_logs (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, interface TEXT, bytes_in BIGINT, bytes_out BIGINT)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_time ON traffic_logs(timestamp)")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB error: {e}")

def log_traffic_hourly():
    try:
        init_traffic_db()
        import sqlite3, psutil
        from datetime import datetime, timedelta
        conn = sqlite3.connect(TRAFFIC_DB)
        c = conn.cursor()
        net = psutil.net_io_counters()
        c.execute("INSERT INTO traffic_logs (interface, bytes_in, bytes_out) VALUES (?, ?, ?)", ('ens3', net.bytes_recv, net.bytes_sent))
        cutoff = datetime.now() - timedelta(days=30)
        c.execute("DELETE FROM traffic_logs WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def get_traffic_history(hours=24):
    try:
        init_traffic_db()
        import sqlite3
        from datetime import datetime, timedelta
        conn = sqlite3.connect(TRAFFIC_DB)
        c = conn.cursor()
        since = datetime.now() - timedelta(hours=hours)
        c.execute("SELECT timestamp, bytes_in, bytes_out FROM traffic_logs WHERE timestamp > ? ORDER BY timestamp", (since,))
        rows = c.fetchall()
        conn.close()
        data = []
        prev_in, prev_out = None, None
        for row in rows:
            ts, b_in, b_out = row
            if prev_in is not None:
                data.append({'timestamp': ts, 'in_gb': round(max(0, b_in - prev_in) / (1024**3), 2), 'out_gb': round(max(0, b_out - prev_out) / (1024**3), 2)})
            prev_in, prev_out = b_in, b_out
        return {'data': data}
    except Exception as e:
        return {'data': [], 'error': str(e)}

init_traffic_db()

def get_hysteria_connections():
    """Get active Hysteria2 connections"""
    try:
        result = subprocess.run(
            ['docker', 'logs', 'hysteria2', '--tail', '500'],
            capture_output=True, text=True, timeout=10
        )
        logs = result.stdout + result.stderr
        
        connections = []
        seen_ips = set()
        
        for line in logs.split('\n'):
            if 'client connected' in line or 'client disconnected' in line:
                try:
                    ip_match = re.search(r'"addr":\s*"([^:]+):', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if ip not in seen_ips and not ip.startswith('::'):
                            seen_ips.add(ip)
                            connections.append({
                                'ip': ip,
                                'protocol': 'Hysteria2',
                                'status': 'connected' if 'connected' in line else 'disconnected',
                                'time': line.split('Z')[0][-8:] if 'Z' in line else ''
                            })
                except:
                    pass
        
        ss_result = subprocess.run(
            ['ss', '-tunap'],
            capture_output=True, text=True, timeout=5
        )
        active_ips = set()
        for line in ss_result.stdout.split('\n'):
            if 'hysteria' in line.lower():
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+):\d+', line)
                if ip_match:
                    active_ips.add(ip_match.group(1))
        
        for conn in connections:
            conn['active'] = conn['ip'] in active_ips
        
        return connections[:20]
    except Exception as e:
        return [{'ip': 'error', 'error': str(e)}]


def get_vless_connections():
    """Get active VLESS connections"""
    try:
        ss_result = subprocess.run(
            ['ss', '-tunap'],
            capture_output=True, text=True, timeout=5
        )
        
        connections = []
        seen_ips = set()
        
        for line in ss_result.stdout.split('\n'):
            if 'xray' in line.lower():
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+):\d+', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if ip not in seen_ips and ip not in ['127.0.0.1', '0.0.0.0']:
                        seen_ips.add(ip)
                        connections.append({
                            'ip': ip,
                            'protocol': 'VLESS+Reality',
                            'active': True
                        })
        
        return connections[:20]
    except Exception as e:
        return [{'ip': 'error', 'error': str(e)}]


def get_hysteria_stats():
    """Get Hysteria2 from systemd"""
    try:
        status_result = subprocess.run(['systemctl', 'is-active', 'hysteria-server'], capture_output=True, text=True, timeout=5)
        service_status = status_result.stdout.strip() if status_result.returncode == 0 else 'stopped'
        ss_result = subprocess.run(['ss', '-tunap'], capture_output=True, text=True, timeout=5)
        active_conns = ss_result.stdout.count('hysteria') if 'hysteria' in ss_result.stdout else 0
        return {
            'status': service_status,
            'active_connections': active_conns,
            'tx_human': 'N/A',
            'rx_human': 'N/A'
        }
    except Exception as e:
        return {'status': 'stopped', 'error': str(e)}

        
        ss_result = subprocess.run(
            ['ss', '-tunap'],
            capture_output=True, text=True, timeout=5
        )
        active_conns = ss_result.stdout.count('hysteria') if 'hysteria' in ss_result.stdout else 0
        
        return {
            'status': 'running',
            'active_connections': active_conns,
            'log_lines': len(logs.split('\n')),
            'tx_bytes': total_tx,
            'rx_bytes': total_rx,
            'tx_human': format_bytes(total_tx),
            'rx_human': format_bytes(total_rx),
            'note': 'Traffic stats from container logs'
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def get_xui_traffic_stats():
    """Get traffic statistics from x-ui database"""
    try:
        import sqlite3
        
        db_path = XUI_DB_PATH if os.path.exists(XUI_DB_PATH) else XUI_DB_PATH_ALT
        
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT protocol, up, down FROM inbounds WHERE protocol LIKE "%vless%" OR protocol LIKE "%trojan%"')
            rows = cursor.fetchall()
            
            total_tx = 0
            total_rx = 0
            for row in rows:
                try:
                    up = row['up'] if row['up'] else 0
                    down = row['down'] if row['down'] else 0
                    total_tx += int(up)
                    total_rx += int(down)
                except:
                    pass
            
            conn.close()
            return {'tx': total_tx, 'rx': total_rx}
    except Exception:
        pass
    
    return {'tx': 0, 'rx': 0}


def get_vless_stats():
    """Get VLESS Reality statistics"""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'x-ui'],
            capture_output=True, text=True, timeout=5
        )
        xui_status = result.stdout.strip()
        
        ss_result = subprocess.run(
            ['ss', '-tunap'],
            capture_output=True, text=True, timeout=5
        )
        vless_conns = ss_result.stdout.count('xray') if 'xray' in ss_result.stdout else 0
        
        port_check = subprocess.run(
            ['ss', '-tlnp'],
            capture_output=True, text=True, timeout=5
        )
        port_443 = '443' in port_check.stdout
        
        traffic = get_xui_traffic_stats()
        
        return {
            'status': xui_status,
            'active_connections': vless_conns,
            'port_443_listening': port_443,
            'protocol': 'VLESS+Reality',
            'tx_bytes': traffic.get('tx', 0),
            'rx_bytes': traffic.get('rx', 0),
            'tx_human': format_bytes(traffic.get('tx', 0)),
            'rx_human': format_bytes(traffic.get('rx', 0))
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def get_ssl_cert_info():
    """Get Let's Encrypt certificates"""
    try:
        certs_dir = '/etc/letsencrypt/live/'
        if not os.path.exists(certs_dir):
            return {'status': 'not_found', 'certificates': []}
        
        certificates = []
        
        for domain in os.listdir(certs_dir):
            cert_path = os.path.join(certs_dir, domain, 'fullchain.pem')
            if os.path.exists(cert_path):
                result = subprocess.run(
                    ['openssl', 'x509', '-in', cert_path, '-noout', '-dates', '-subject'],
                    capture_output=True, text=True, timeout=5
                )
                
                lines = result.stdout.strip().split('\n')
                info = {'domain': domain, 'status': 'active', 'raw': lines}
                
                for line in lines:
                    if 'notBefore' in line:
                        info['not_before'] = line.split('=')[1] if '=' in line else line
                    elif 'notAfter' in line:
                        info['not_after'] = line.split('=')[1] if '=' in line else line
                    elif 'subject' in line:
                        info['subject'] = line.split('=')[1] if '=' in line else line
                
                if 'not_after' in info:
                    try:
                        expiry = datetime.strptime(info['not_after'], '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry - datetime.now()).days
                        info['days_until_expiry'] = days_left
                    except:
                        pass
                
                certificates.append(info)
        
        certificates.sort(key=lambda x: x.get('days_until_expiry', 999))
        
        return {'status': 'active', 'certificates': certificates, 'total': len(certificates)}
    except Exception as e:
        return {'status': 'error', 'error': str(e), 'certificates': []}


def get_docker_containers():
    """Get Docker container status"""
    try:
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{.Names}}\t{{.Status}}\t{{.Ports}}'],
            capture_output=True, text=True, timeout=5
        )
        
        containers = []
        for line in result.stdout.strip().split('\n'):
            if line:
                parts = line.split('\t')
                containers.append({
                    'name': parts[0] if len(parts) > 0 else '',
                    'status': parts[1] if len(parts) > 1 else '',
                    'ports': parts[2] if len(parts) > 2 else ''
                })
        
        return containers
    except Exception as e:
        return [{'name': 'error', 'status': str(e)}]



# ========== DNS Functions ==========

def get_bind_stats():
    """Get BIND DNS server statistics"""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'named'],
            capture_output=True, text=True, timeout=5
        )
        service_status = result.stdout.strip()
        
        version = "Unknown"
        try:
            ver_result = subprocess.run(
                ['named', '-v'],
                capture_output=True, text=True, timeout=5
            )
            version = ver_result.stdout.strip() if ver_result.stdout else "Unknown"
        except:
            pass
        
        interfaces = []
        try:
            ss_result = subprocess.run(
                ['ss', '-tlnp'],
                capture_output=True, text=True, timeout=5
            )
            for line in ss_result.stdout.split('\n'):
                if 'named' in line and ':53' in line:
                    parts = line.split()
                    for part in parts:
                        if ':53' in part:
                            interfaces.append(part.strip())
        except:
            pass
        
        return {
            'status': service_status,
            'version': version,
            'interfaces': list(set(interfaces))[:5]
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def get_dns_zones():
    """Get configured DNS zones"""
    try:
        zones = []
        config_path = '/etc/bind/named.conf.local'
        
        if not os.path.exists(config_path):
            return {'status': 'config_not_found', 'zones': []}
        
        with open(config_path, 'r') as f:
            cfg = f.read()
        
        zone_pattern = r'zone\s+"([^"]+)"\s*\{([^}]+)\}'
        matches = re.findall(zone_pattern, cfg, re.DOTALL)
        
        for zone_name, zone_config in matches:
            zone_info = {
                'name': zone_name,
                'type': 'unknown',
                'file': None,
                'masters': []
            }
            
            type_match = re.search(r'type\s+(\w+)', zone_config)
            if type_match:
                zone_info['type'] = type_match.group(1)
            
            file_match = re.search(r'file\s+"([^"]+)"', zone_config)
            if file_match:
                zone_info['file'] = file_match.group(1)
            
            masters_match = re.search(r'masters\s*\{([^}]+)\}', zone_config)
            if masters_match:
                masters_str = masters_match.group(1)
                zone_info['masters'] = [m.strip().rstrip(';') for m in masters_str.split(';') if m.strip()]
            
            zones.append(zone_info)
        
        return {'status': 'active', 'zones': zones, 'total': len(zones)}
    except Exception as e:
        return {'status': 'error', 'error': str(e), 'zones': []}


def reload_bind():
    """Reload BIND configuration"""
    try:
        result = subprocess.run(
            ['rndc', 'reload'],
            capture_output=True, text=True, timeout=15
        )
        
        if result.returncode == 0:
            return {'success': True, 'message': 'BIND reloaded successfully'}
        else:
            return {'success': False, 'error': result.stderr or 'Unknown error'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


# ========== Original functions preserved below ==========


@app.route('/')
@requires_auth

def dashboard():
    """Main dashboard page"""
    system = get_system_info()
    network = get_network_stats()
    hysteria = get_hysteria_stats()
    vless = get_vless_stats()
    ssl = get_ssl_cert_info()
    dns = get_bind_stats()
    dns_zones = get_dns_zones()
    docker = get_docker_containers()
    
    return flask.render_template_string(DASHBOARD_HTML,
        system=system,
        network=network,
        hysteria=hysteria,
        vless=vless,
        ssl=ssl,
        dns=dns,
        dns_zones=dns_zones,
        docker=docker,
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        server_domain=SERVER_DOMAIN,
        server_ip=SERVER_DOMAIN,
        x_ui_port=X_UI_PORT,
        x_ui_domain=X_UI_DOMAIN,
        x_ui_path=X_UI_PATH
    )


@app.route('/api/stats')
@requires_auth
def api_stats():
    """API endpoint for stats"""
    return flask.jsonify({
        'system': get_system_info(),
        'network': get_network_stats(),
        'hysteria': get_hysteria_stats(),
        'vless': get_vless_stats(),
        'ssl': get_ssl_cert_info(),
        'docker': get_docker_containers(),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/connections')
@requires_auth
def api_connections():
    """API endpoint for active connections"""
    return flask.jsonify({
        'hysteria': get_hysteria_connections(),
        'vless': get_vless_connections(),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/ssl/renew/<domain>', methods=['POST'])
@requires_auth
def api_renew_cert(domain):
    """Renew a Let's Encrypt certificate"""
    try:
        result = subprocess.run(
            ['certbot', 'renew', '--cert-name', domain, '--force-renewal', '--non-interactive'],
            capture_output=True, text=True, timeout=120
        )
        
        if result.returncode == 0:
            subprocess.run(['systemctl', 'reload', 'nginx'], timeout=10)
            return flask.jsonify({'success': True, 'message': f'Certificate for {domain} renewed successfully'})
        else:
            return flask.jsonify({'success': False, 'error': result.stderr}), 400
    except Exception as e:
        return flask.jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ssl/renew/all', methods=['POST'])
@requires_auth
def api_renew_all_certs():
    """Renew all Let's Encrypt certificates"""
    try:
        result = subprocess.run(
            ['certbot', 'renew', '--non-interactive'],
            capture_output=True, text=True, timeout=300
        )
        
        if result.returncode == 0:
            subprocess.run(['systemctl', 'reload', 'nginx'], timeout=10)
            return flask.jsonify({'success': True, 'message': 'All certificates renewed successfully'})
        else:
            return flask.jsonify({'success': False, 'error': result.stderr}), 400
    except Exception as e:
        return flask.jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ssl/create', methods=['POST'])
@requires_auth
def api_create_cert():
    """Create a new Let's Encrypt certificate"""
    try:
        data = flask.request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return flask.jsonify({'success': False, 'error': 'Domain is required'}), 400
        
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', domain):
            return flask.jsonify({'success': False, 'error': 'Invalid domain format'}), 400
        
        result = subprocess.run(
            ['certbot', '--nginx', '-d', domain, '--non-interactive', '--agree-tos', 
             '--email', LETSENCRYPT_EMAIL, '--redirect'],
            capture_output=True, text=True, timeout=120
        )
        
        if result.returncode == 0:
            return flask.jsonify({'success': True, 'message': f'Certificate for {domain} created successfully'})
        else:
            return flask.jsonify({'success': False, 'error': result.stderr}), 400
    except Exception as e:
        return flask.jsonify({'success': False, 'error': str(e)}), 500



@app.route('/api/dns')
@requires_auth
def api_dns():
    """API endpoint for DNS stats"""
    return flask.jsonify({
        'dns': get_bind_stats(),
        'zones': get_dns_zones(),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/dns/zone')
@requires_auth
def api_dns_zone():
    """Get zone file content"""
    try:
        with open('/etc/bind/zones/db.foolsland.ru', 'r') as f:
            return flask.jsonify({'success': True, 'content': f.read()})
    except Exception as e:
        return flask.jsonify({'success': False, 'error': str(e)})

@app.route('/api/dns/zone', methods=['POST'])
@requires_auth
def api_dns_zone_save():
    """Save zone file content"""
    try:
        data = flask.request.get_json()
        content = data.get('content', '')
        with open('/etc/bind/zones/db.foolsland.ru', 'w') as f:
            f.write(content)
        subprocess.run(['rndc', 'reload'], capture_output=True, timeout=15)
        return flask.jsonify({'success': True, 'message': 'Zone saved and BIND reloaded'})
    except Exception as e:
        return flask.jsonify({'success': False, 'error': str(e)})

@app.route('/api/dns/record', methods=['POST'])
@requires_auth
def api_dns_record_add():
    """Add new DNS record"""
    try:
        data = flask.request.get_json()
        name = data.get('name', '')
        rtype = data.get('type', 'A')
        rdata = data.get('data', '')
        ttl = str(data.get('ttl', '86400'))
        
        record_line = f"{name:<8} IN      {ttl:<6} {rtype:<8} {rdata}\n"
        
        with open('/etc/bind/zones/db.foolsland.ru', 'r') as f:
            lines = f.readlines()
        
        insert_pos = len(lines)
        for i, line in enumerate(lines):
            if 'MX' in line or 'TXT' in line or 'CAA' in line:
                insert_pos = i
                break
        lines.insert(insert_pos, record_line)
        
        with open('/etc/bind/zones/db.foolsland.ru', 'w') as f:
            f.writelines(lines)
        
        subprocess.run(['rndc', 'reload'], capture_output=True, timeout=15)
        return flask.jsonify({'success': True, 'message': f'Record {name} added'})
    except Exception as e:
        return flask.jsonify({'success': False, 'error': str(e)})


DASHBOARD_HTML = '''<!DOCTYPE html>
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
            min-height: 100vh;
            color: #fff;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { text-align: center; margin-bottom: 10px; color: #00d9ff; }
        .subtitle { text-align: center; color: #888; margin-bottom: 30px; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: rgba(255,255,255,0.05);
            border-radius: 16px;
            padding: 24px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .card h2 {
            color: #00d9ff;
            margin-bottom: 15px;
            font-size: 18px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .stat-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .stat-row:last-child { border-bottom: none; }
        .stat-label { color: #888; }
        .stat-value { font-weight: bold; color: #fff; }
        .stat-value.good { color: #00ff88; }
        .stat-value.warning { color: #ffa500; }
        .stat-value.danger { color: #ff4444; }
        .progress-bar {
            background: rgba(255,255,255,0.1);
            border-radius: 4px;
            height: 8px;
            margin-top: 5px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s;
        }
        .progress-fill.good { background: #00ff88; }
        .progress-fill.warning { background: #ffa500; }
        .progress-fill.danger { background: #ff4444; }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }
        .badge.success { background: #00ff88; color: #000; }
        .badge.running { background: #00d9ff; color: #000; }
        .badge.error { background: #ff4444; color: #fff; }
        .container-list { list-style: none; }
        .container-list li {
            padding: 8px;
            background: rgba(0,0,0,0.2);
            margin-bottom: 8px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 13px;
        }
        .conn-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        .conn-table th, .conn-table td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .conn-table th { color: #888; font-weight: normal; }
        .conn-table tr:hover { background: rgba(255,255,255,0.05); }
        .conn-ip { color: #00d9ff; font-family: monospace; }
        .conn-protocol { color: #ffa500; }
        .conn-status { font-weight: bold; }
        .conn-status.active { color: #00ff88; }
        .conn-status.inactive { color: #888; }
        .clickable {
            cursor: pointer;
            transition: color 0.2s;
        }
        .clickable:hover { color: #00d9ff; }
        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            overflow-y: auto;
        }
        .modal-content {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            margin: 5% auto;
            padding: 24px;
            border-radius: 16px;
            max-width: 600px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .modal-close {
            background: none;
            border: none;
            color: #fff;
            font-size: 24px;
            cursor: pointer;
        }
        .modal-close:hover { color: #ff4444; }
        .ssl-actions {
            margin-top: 15px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: bold;
            transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.8; }
        .btn-primary { background: #00d9ff; color: #000; }
        .btn-success { background: #00ff88; color: #000; }
        .btn-warning { background: #ffa500; color: #000; }
        .btn-small { padding: 4px 8px; font-size: 11px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; color: #888; margin-bottom: 5px; }
        .form-group input {
            width: 100%;
            padding: 10px;
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 6px;
            background: rgba(0,0,0,0.3);
            color: #fff;
            font-size: 14px;
        }
        .cert-item {
            background: rgba(0,0,0,0.2);
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        .cert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .cert-domain { color: #00d9ff; font-weight: bold; }
        .refresh-info {
            text-align: center;
            color: #666;
            font-size: 12px;
            margin-top: 20px;
        }
        a.panel-link {
            display: block;
            text-align: center;
            background: rgba(0,217,255,0.2);
            color: #00d9ff;
            padding: 10px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: bold;
        }
        a.panel-link:hover { background: rgba(0,217,255,0.3); }
    </style>
</head>
<body>
    <div class="container">
        <div style="text-align: left; margin-bottom: 10px;"><a href="https://foolsland.ru" style="color: #00d9ff; text-decoration: none; font-size: 14px;">← Back to foolsland.ru</a></div>
        <h1>📊 Dashboard</h1>
        <p class="subtitle">{{ server_domain }} • {{ timestamp }}</p>
        
        <div class="grid">
            <!-- System Info -->
            <div class="card">
                <h2>💻 System</h2>
                <div class="stat-row">
                    <span class="stat-label">CPU</span>
                    <span class="stat-value {% if system.cpu_percent > 80 %}danger{% elif system.cpu_percent > 50 %}warning{% else %}good{% endif %}">
                        {{ system.cpu_percent }}%
                    </span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill {% if system.cpu_percent > 80 %}danger{% elif system.cpu_percent > 50 %}warning{% else %}good{% endif %}" 
                         style="width: {{ system.cpu_percent }}%"></div>
                </div>
                
                <div class="stat-row" style="margin-top: 15px;">
                    <span class="stat-label">RAM</span>
                    <span class="stat-value {% if system.memory.percent > 80 %}danger{% elif system.memory.percent > 50 %}warning{% else %}good{% endif %}">
                        {{ system.memory.used }} / {{ system.memory.total }} GB ({{ system.memory.percent }}%)
                    </span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill {% if system.memory.percent > 80 %}danger{% elif system.memory.percent > 50 %}warning{% else %}good{% endif %}" 
                         style="width: {{ system.memory.percent }}%"></div>
                </div>
                
                <div class="stat-row" style="margin-top: 15px;">
                    <span class="stat-label">Disk</span>
                    <span class="stat-value {% if system.disk.percent > 80 %}danger{% elif system.disk.percent > 50 %}warning{% else %}good{% endif %}">
                        {{ system.disk.used }} / {{ system.disk.total }} GB ({{ system.disk.percent }}%)
                    </span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill {% if system.disk.percent > 80 %}danger{% elif system.disk.percent > 50 %}warning{% else %}good{% endif %}" 
                         style="width: {{ system.disk.percent }}%"></div>
                </div>
                
                <div class="stat-row" style="margin-top: 15px;">
                    <span class="stat-label">Uptime</span>
                    <span class="stat-value">{{ system.uptime }}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Load Avg</span>
                    <span class="stat-value">{{ system.load_avg[0] }}, {{ system.load_avg[1] }}, {{ system.load_avg[2] }}</span>
                </div>
            </div>
            
            <!-- Hysteria2 Stats -->
            <div class="card">
                <h2>🚀 Hysteria 2</h2>
                <div class="stat-row">
                    <span class="stat-label">Status</span>
                    <span class="badge {% if hysteria.status == 'active' %}success{% else %}error{% endif %}">
                        {{ hysteria.status | upper }}
                    </span>
                </div>
                <div class="stat-row clickable" onclick="showConnections('hysteria')">
                    <span class="stat-label">Active Connections</span>
                    <span class="stat-value">{{ hysteria.active_connections }} ▼</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Port</span>
                    <span class="stat-value">8443/UDP</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Traffic ↓</span>
                    <span class="stat-value" style="color: #00ff88;">{{ hysteria.rx_human }}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Traffic ↑</span>
                    <span class="stat-value" style="color: #ffa500;">{{ hysteria.tx_human }}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Obfuscation</span>
                    <span class="stat-value">salamander</span>
                </div>
            </div>
            
            <!-- VLESS Reality Stats -->
            <div class="card">
                <h2>🛡️ VLESS + Reality</h2>
                <div class="stat-row">
                    <span class="stat-label">Status</span>
                    <span class="badge {% if vless.status == 'active' %}success{% else %}error{% endif %}">
                        {{ vless.status | upper }}
                    </span>
                </div>
                <div class="stat-row clickable" onclick="showConnections('vless')">
                    <span class="stat-label">Active Connections</span>
                    <span class="stat-value">{{ vless.active_connections }} ▼</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Port 443</span>
                    <span class="stat-value {% if vless.port_443_listening %}good{% else %}danger{% endif %}">
                        {% if vless.port_443_listening %}LISTENING{% else %}NOT LISTENING{% endif %}
                    </span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Traffic ↓</span>
                    <span class="stat-value" style="color: #00ff88;">{{ vless.rx_human }}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Traffic ↑</span>
                    <span class="stat-value" style="color: #ffa500;">{{ vless.tx_human }}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">SNI</span>
                    <span class="stat-value">www.nvidia.com</span>
                </div>
                <div class="stat-row" style="margin-top: 15px;">
                    <a href="https://{{ x_ui_domain }}:{{ x_ui_port }}{{ x_ui_path }}" target="_blank" class="panel-link">
                        🎛️ Open X-UI Panel →
                    </a>
                </div>
            </div>
            
            <!-- SSL Certificate -->
            <div class="card">
                <h2>🔒 SSL Certificates</h2>
                <div class="stat-row">
                    <span class="stat-label">Status</span>
                    <span class="badge {% if ssl.status == 'active' %}success{% else %}error{% endif %}">
                        {{ ssl.status | upper }}
                    </span>
                </div>
                {% if ssl.status == 'active' %}
                <div class="stat-row">
                    <span class="stat-label">Total Certificates</span>
                    <span class="stat-value">{{ ssl.total }}</span>
                </div>
                <div class="ssl-actions">
                    <button class="btn btn-primary" onclick="showCreateCertModal()">
                        ➕ New Certificate
                    </button>
                    <button class="btn btn-warning" onclick="renewAllCerts()">
                        🔄 Renew All
                    </button>
                </div>
                <div style="margin-top: 15px;">
                    {% for cert in ssl.certificates %}
                    <div class="cert-item">
                        <div class="cert-header">
                            <span class="cert-domain">{{ cert.domain }}</span>
                            <button class="btn btn-warning btn-small" onclick="renewCert('{{ cert.domain }}')">
                                🔄 Renew
                            </button>
                        </div>
                        <div style="color: #888; font-size: 13px; margin-bottom: 8px;">
                            Expires: {{ cert.not_after }}
                        </div>
                        <span class="badge {% if cert.days_until_expiry < 30 %}error{% elif cert.days_until_expiry < 60 %}warning{% else %}success{% endif %}">
                            {{ cert.days_until_expiry }} days left
                        </span>
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
            </div>
            
            <!-- Network Stats -->
            <div class="card">
                <h2>🌐 Network</h2>
                {% if network.primary_interface %}
                <div class="stat-row">
                    <span class="stat-label">Interface</span>
                    <span class="stat-value">{{ network.primary_interface.name }}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Received</span>
                    <span class="stat-value">{{ (network.primary_interface.bytes_recv / 1024 / 1024 / 1024) | round(2) }} GB</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Sent</span>
                    <span class="stat-value">{{ (network.primary_interface.bytes_sent / 1024 / 1024 / 1024) | round(2) }} GB</span>
                </div>
                {% endif %}
                <div class="stat-row">
                    <span class="stat-label">Total Received</span>
                    <span class="stat-value">{{ (network.total.bytes_recv / 1024 / 1024 / 1024) | round(2) }} GB</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Total Sent</span>
                    <span class="stat-value">{{ (network.total.bytes_sent / 1024 / 1024 / 1024) | round(2) }} GB</span>
                </div>
            </div>
            
            <!-- DNS Server -->
            <div class="card">
                <h2>🌍 DNS Server (BIND9)</h2>
                <div class="stat-row">
                    <span class="stat-label">Status</span>
                    <span class="badge {% if dns.status == 'active' %}success{% else %}error{% endif %}">
                        {{ dns.status | upper }}
                    </span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Version</span>
                    <span class="stat-value" style="font-size: 12px;">{{ dns.version }}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Zones</span>
                    <span class="stat-value">{{ dns_zones.total }}</span>
                </div>
                <div style="margin-top: 15px;">
                    <button class="btn btn-primary" onclick="showZoneEditor()">📝 Edit Zone</button>
                    <button class="btn btn-success" onclick="showAddDNS()">➕ Add Record</button>
                </div>
                <div id="dnsStatus" style="margin-top: 10px; font-size: 12px;"></div>
            </div>
            <!-- Docker removed -->
        <!-- Resource History removed -->
        
                
        <!-- Traffic History Chart - В НИЗУ -->
        <div class="card" style="margin-top: 20px; grid-column: 1 / -1;">
            <h2>📊 Traffic History (24h)</h2>
            <div style="margin-bottom: 10px;">
                <span style="color: #00ff88;">⬇️ IN: <span id="total-in">--</span> GB</span> | 
                <span style="color: #ffa500;">⬆️ OUT: <span id="total-out">--</span> GB</span>
            </div>
            <div style="height: 350px; background: rgba(0,0,0,0.2); border-radius: 10px; padding: 10px;">
                <canvas id="trafficChart" width="1100" height="300"></canvas>
            </div>
            <div style="margin-top: 10px; text-align: center;">
                <button class="btn btn-primary btn-small" onclick="loadTrafficChart()">🔄 Refresh</button>
                <button class="btn btn-success btn-small" onclick="logTrafficNow()">💾 Log Now</button>
            </div>
        </div>
        
<p class="refresh-info">Auto-refresh every 30 seconds • Press F5 to refresh manually</p>
    </div>
    
    <!-- DNS Zone Editor Modal -->
    <div id="zoneEditorModal" class="modal">
        <div class="modal-content" style="max-width: 900px;">
            <div class="modal-header">
                <h2>📝 DNS Zone Editor</h2>
                <button class="modal-close" onclick="hideZoneEditor()">&times;</button>
            </div>
            <p style="color: #888; margin-bottom: 10px; font-size: 12px;">/etc/bind/zones/db.foolsland.ru</p>
            <textarea id="zoneContent" style="width: 100%; height: 400px; background: #0a0a1a; color: #00ff88; border: 1px solid #333; padding: 10px; font-family: monospace; font-size: 12px; border-radius: 6px; resize: vertical;"></textarea>
            <div style="margin-top: 15px;">
                <button class="btn btn-primary" onclick="loadZone()">🔄 Load Zone</button>
                <button class="btn btn-success" onclick="saveZone()">💾 Save & Reload BIND</button>
            </div>
            <div id="zoneResult" style="margin-top: 15px;"></div>
        </div>
    </div>
    
    <!-- Add DNS Record Modal -->
    <div id="addDNSModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>➕ Add DNS Record</h2>
                <button class="modal-close" onclick="hideAddDNS()">&times;</button>
            </div>
            <div class="form-group">
                <label>Subdomain Name</label>
                <input type="text" id="dnsName" placeholder="e.g., newvpn">
            </div>
            <div class="form-group">
                <label>Record Type</label>
                <select id="dnsType" style="width: 100%; padding: 10px; background: rgba(0,0,0,0.3); color: #fff; border: 1px solid #444; border-radius: 6px;">
                    <option value="A">A (IPv4 Address)</option>
                    <option value="AAAA">AAAA (IPv6 Address)</option>
                    <option value="CNAME">CNAME (Alias)</option>
                    <option value="TXT">TXT (Text)</option>
                </select>
            </div>
            <div class="form-group">
                <label>Value / Data</label>
                <input type="text" id="dnsData" placeholder="e.g., 2.26.54.174">
            </div>
            <div class="form-group">
                <label>TTL (seconds)</label>
                <input type="number" id="dnsTTL" value="86400">
            </div>
            <button class="btn btn-success" onclick="submitDNS()">➕ Add Record</button>
            <div id="addDNSResult" style="margin-top: 15px;"></div>
        </div>
    </div>
    
    <!-- Connections Modal -->
    <div id="connectionsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">🔌 Active Connections</h2>
                <button class="modal-close" onclick="hideConnections()">&times;</button>
            </div>
            <div id="modalContent">
                <p style="text-align:center;color:#888;">Loading...</p>
            </div>
        </div>
    </div>
    
    <!-- Create Certificate Modal -->
    <div id="createCertModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>🔒 New SSL Certificate</h2>
                <button class="modal-close" onclick="hideCreateCertModal()">&times;</button>
            </div>
            <div class="form-group">
                <label>Domain Name</label>
                <input type="text" id="newCertDomain" placeholder="e.g., vpn.example.com" />
            </div>
            <div style="display: flex; gap: 10px; justify-content: flex-end;">
                <button class="btn" style="background: #666; color: #fff;" onclick="hideCreateCertModal()">Cancel</button>
                <button class="btn btn-success" onclick="createCert()">➕ Create Certificate</button>
            </div>
            <div id="createCertResult" style="margin-top: 15px;"></div>
        </div>
    </div>
    
    <script>
        setTimeout(() => location.reload(), 30000);
        
        function showConnections(protocol) {
            const modal = document.getElementById('connectionsModal');
            const content = document.getElementById('modalContent');
            const title = document.getElementById('modalTitle');
            
            title.textContent = protocol === 'hysteria' ? '🚀 Hysteria2 Connections' : '🛡️ VLESS+Reality Connections';
            modal.style.display = 'block';
            content.innerHTML = '<p style="text-align:center;color:#888;">Loading...</p>';
            
            fetch('/api/connections')
                .then(r => r.json())
                .then(data => {
                    const conns = protocol === 'hysteria' ? data.hysteria : data.vless;
                    if (!conns || conns.length === 0) {
                        content.innerHTML = '<p style="text-align:center;color:#888;">No connections found</p>';
                        return;
                    }
                    
                    let html = '<table class="conn-table"><thead><tr><th>IP Address</th><th>Protocol</th><th>Status</th></tr></thead><tbody>';
                    conns.forEach(c => {
                        const statusClass = c.active ? 'active' : 'inactive';
                        const statusText = c.active ? '● ACTIVE' : '○ INACTIVE';
                        html += `<tr><td class="conn-ip">${c.ip}</td><td class="conn-protocol">${c.protocol}</td><td class="conn-status ${statusClass}">${statusText}</td></tr>`;
                    });
                    html += '</tbody></table>';
                    content.innerHTML = html;
                })
                .catch(err => {
                    content.innerHTML = '<p style="text-align:center;color:#ff4444;">Error loading connections</p>';
                });
        }
        
        function hideConnections() {
            document.getElementById('connectionsModal').style.display = 'none';
        }
        
        window.onclick = function(event) {
            const modal = document.getElementById('connectionsModal');
            if (event.target === modal) hideConnections();
            const certModal = document.getElementById('createCertModal');
            if (event.target === certModal) hideCreateCertModal();
        }
        
        function showCreateCertModal() {
            document.getElementById('createCertModal').style.display = 'block';
            document.getElementById('newCertDomain').value = '';
            document.getElementById('createCertResult').innerHTML = '';
        }
        
        function hideCreateCertModal() {
            document.getElementById('createCertModal').style.display = 'none';
        }
        
        function createCert() {
            const domain = document.getElementById('newCertDomain').value.trim();
            const resultDiv = document.getElementById('createCertResult');
            
            if (!domain) {
                resultDiv.innerHTML = '<p style="color:#ff4444;">Please enter a domain name</p>';
                return;
            }
            
            resultDiv.innerHTML = '<p style="color:#00d9ff;">⏳ Creating certificate...</p>';
            
            fetch('/api/ssl/create', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({domain: domain})
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    resultDiv.innerHTML = '<p style="color:#00ff88;">✅ ' + data.message + '</p>';
                    setTimeout(() => location.reload(), 3000);
                } else {
                    resultDiv.innerHTML = '<p style="color:#ff4444;">❌ Error: ' + (data.error || 'Unknown error') + '</p>';
                }
            })
            .catch(err => {
                resultDiv.innerHTML = '<p style="color:#ff4444;">❌ Error: ' + err + '</p>';
            });
        }
        
        function renewCert(domain) {
            const resultDiv = document.getElementById('createCertResult');
            resultDiv.innerHTML = '<p style="color:#00d9ff;">⏳ Renewing certificate for ' + domain + '...</p>';
            
            fetch('/api/ssl/renew/' + domain, {method: 'POST'})
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    resultDiv.innerHTML = '<p style="color:#00ff88;">✅ ' + data.message + '</p>';
                    setTimeout(() => location.reload(), 3000);
                } else {
                    resultDiv.innerHTML = '<p style="color:#ff4444;">❌ Error: ' + (data.error || 'Unknown error') + '</p>';
                }
            })
            .catch(err => {
                resultDiv.innerHTML = '<p style="color:#ff4444;">❌ Error: ' + err + '</p>';
            });
        }
        
        function renewAllCerts() {
            if (!confirm('Renew all SSL certificates?')) return;
            
            const resultDiv = document.getElementById('createCertResult');
            resultDiv.innerHTML = '<p style="color:#00d9ff;">⏳ Running certbot...</p>';
            
            fetch('/api/ssl/renew/all', {method: 'POST'})
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    resultDiv.innerHTML = '<p style="color:#00ff88;">✅ ' + data.message + '</p>';
                    setTimeout(() => location.reload(), 3000);
                } else {
                    resultDiv.innerHTML = '<p style="color:#ff4444;">❌ Error: ' + (data.error || 'Unknown error') + '</p>';
                }
            })
            .catch(err => {
                resultDiv.innerHTML = '<p style="color:#ff4444;">❌ Error: ' + err + '</p>';
            });
        }

        // DNS Editor Functions
        function showZoneEditor() {
            document.getElementById('zoneEditorModal').style.display = 'block';
            loadZone();
        }
        function hideZoneEditor() {
            document.getElementById('zoneEditorModal').style.display = 'none';
        }
        function showAddDNS() {
            document.getElementById('addDNSModal').style.display = 'block';
        }
        function hideAddDNS() {
            document.getElementById('addDNSModal').style.display = 'none';
        }
        function loadZone() {
            const resultDiv = document.getElementById('zoneResult');
            resultDiv.innerHTML = '<span style="color:#00d9ff">⏳ Loading...</span>';
            fetch('/api/dns/zone')
                .then(r => r.json())
                .then(data => {
                    if (data.success && data.content) {
                        document.getElementById('zoneContent').value = data.content;
                        resultDiv.innerHTML = '<span style="color:#00ff88">✅ Zone loaded</span>';
                    } else {
                        resultDiv.innerHTML = '<span style="color:#ff4444">❌ Error: ' + (data.error || 'Failed') + '</span>';
                    }
                });
        }
        function saveZone() {
            const content = document.getElementById('zoneContent').value;
            if (!confirm('Save zone and reload BIND?')) return;
            const resultDiv = document.getElementById('zoneResult');
            resultDiv.innerHTML = '<span style="color:#00d9ff">⏳ Saving...</span>';
            fetch('/api/dns/zone', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({content: content})
            })
            .then(r => r.json())
            .then(data => {
                resultDiv.innerHTML = data.success ? 
                    '<span style="color:#00ff88">✅ ' + data.message + '</span>' : 
                    '<span style="color:#ff4444">❌ ' + data.error + '</span>';
                if (data.success) setTimeout(() => location.reload(), 2000);
            });
        }
                // Traffic Chart
        function drawTrafficChart(data) {
            const c = document.getElementById('trafficChart');
            if (!c) return;
            const x = c.getContext('2d');
            x.clearRect(0, 0, c.width, c.height);
            if (data.length == 0) {
                x.fillStyle = '#888';
                x.font = '16px Arial';
                x.textAlign = 'center';
                x.fillText('No data yet. Click "Log Now" to start collecting.', c.width/2, 110);
                return;
            }
            let tIn=0, tOut=0, mVal=0;
            data.forEach(d=>{tIn+=d.in_gb; tOut+=d.out_gb; mVal=Math.max(mVal,d.in_gb,d.out_gb);});
            document.getElementById('total-in').textContent=tIn.toFixed(2);
            document.getElementById('total-out').textContent=tOut.toFixed(2);
            if(mVal==0)mVal=1;
            const barW=30, step=(c.width-100)/Math.max(data.length, 24);
            data.forEach((d,i)=>{
                const px=50+i*step;
                const hIn=(d.in_gb/mVal)*180, hOut=(d.out_gb/mVal)*180;
                x.fillStyle='#00ff88'; x.fillRect(px, 200-hIn, barW/2, hIn);
                x.fillStyle='#ffa500'; x.fillRect(px+barW/2, 200-hOut, barW/2, hOut);
            });
            x.strokeStyle='#555'; x.beginPath(); x.moveTo(50, 200); x.lineTo(c.width-50, 200); x.stroke();
        }
        function loadTrafficChart(){
            fetch('/api/traffic/history?hours=24').then(r=>r.json()).then(d=>{ if(d.data)drawTrafficChart(d.data);}).catch(e=>console.error(e));
        }
        function logTrafficNow(){fetch('/api/traffic/log',{method:'POST'}).then(()=>setTimeout(loadTrafficChart,500));}
        setTimeout(loadTrafficChart, 1000);

        // Traffic Chart
        function drawTrafficChart(data) {
            const c = document.getElementById('trafficChart');
            if (!c) return;
            const x = c.getContext('2d');
            x.clearRect(0, 0, c.width, c.height);
            if (data.length == 0) {
                x.fillStyle = '#888';
                x.font = '16px Arial';
                x.textAlign = 'center';
                x.fillText('No data yet. Click "Log Now".', c.width/2, 110);
                return;
            }
            let tIn=0, tOut=0, mVal=0;
            data.forEach(d=>{tIn+=d.in_gb; tOut+=d.out_gb; mVal=Math.max(mVal,d.in_gb,d.out_gb);});
            document.getElementById('total-in').textContent=tIn.toFixed(2);
            document.getElementById('total-out').textContent=tOut.toFixed(2);
            if(mVal==0)mVal=1;
            const barW=30, step=(c.width-100)/Math.max(data.length, 24);
            data.forEach((d,i)=>{
                const px=50+i*step;
                const hIn=(d.in_gb/mVal)*180, hOut=(d.out_gb/mVal)*180;
                x.fillStyle='#00ff88'; x.fillRect(px, 200-hIn, barW/2, hIn);
                x.fillStyle='#ffa500'; x.fillRect(px+barW/2, 200-hOut, barW/2, hOut);
            });
            x.strokeStyle='#555'; x.beginPath(); x.moveTo(50, 200); x.lineTo(c.width-50, 200); x.stroke();
        }
        function loadTrafficChart(){
            fetch('/api/traffic/history?hours=24').then(r=>r.json()).then(d=>{ if(d.data)drawTrafficChart(d.data);}).catch(e=>console.error(e));
        }
        function logTrafficNow(){fetch('/api/traffic/log',{method:'POST'}).then(()=>setTimeout(loadTrafficChart,500));}
        setTimeout(loadTrafficChart, 1000);

function submitDNS() {
            const name = document.getElementById('dnsName').value.trim();
            const type = document.getElementById('dnsType').value;
            const data = document.getElementById('dnsData').value.trim();
            const ttl = document.getElementById('dnsTTL').value;
            const resultDiv = document.getElementById('addDNSResult');
            if (!name || !data) {
                resultDiv.innerHTML = '<span style="color:#ff4444">❌ Name and Value required</span>';
                return;
            }
            resultDiv.innerHTML = '<span style="color:#00d9ff">⏳ Adding...</span>';
            fetch('/api/dns/record', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name: name, type: type, data: data, ttl: ttl})
            })
            .then(r => r.json())
            .then(data => {
                resultDiv.innerHTML = data.success ? 
                    '<span style="color:#00ff88">✅ ' + data.message + '</span>' : 
                    '<span style="color:#ff4444">❌ ' + data.error + '</span>';
                if (data.success) setTimeout(() => location.reload(), 1500);
            });
        }
    </script>
</body>
</html>
'''




#!/usr/bin/env python3
"""Additional useful features for VPN Dashboard"""

# ========== System History Tracking ==========

import sqlite3
import json
from datetime import datetime, timedelta

HISTORY_DB = '/var/lib/vpn-dashboard/history.db'

def init_history_db():
    """Initialize SQLite database for resource history"""
    try:
        import os
        os.makedirs('/var/lib/vpn-dashboard', exist_ok=True)
        
        conn = sqlite3.connect(HISTORY_DB)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS resource_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_in BIGINT,
                network_out BIGINT
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON resource_logs(timestamp)
        ''')
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        return {'error': str(e)}

def log_resources():
    """Log current resource usage to database"""
    try:
        init_history_db()
        conn = sqlite3.connect(HISTORY_DB)
        cursor = conn.cursor()
        
        import psutil
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        net_io = psutil.net_io_counters()
        
        cursor.execute('''
            INSERT INTO resource_logs (cpu_percent, memory_percent, disk_percent, network_in, network_out)
            VALUES (?, ?, ?, ?, ?)
        ''', (cpu, memory, disk, net_io.bytes_recv, net_io.bytes_sent))
        
        conn.commit()
        conn.close()
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def get_resource_history(hours=24):
    """Get resource history for charts"""
    try:
        init_history_db()
        conn = sqlite3.connect(HISTORY_DB)
        cursor = conn.cursor()
        
        since = datetime.now() - timedelta(hours=hours)
        cursor.execute('''
            SELECT timestamp, cpu_percent, memory_percent, disk_percent, network_in, network_out
            FROM resource_logs
            WHERE timestamp > ?
            ORDER BY timestamp ASC
        ''', (since,))
        
        rows = cursor.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            history.append({
                'timestamp': row[0],
                'cpu': round(row[1], 2),
                'memory': round(row[2], 2),
                'disk': round(row[3], 2),
                'network_in': row[4],
                'network_out': row[5]
            })
        
        return {'history': history, 'count': len(history)}
    except Exception as e:
        return {'history': [], 'error': str(e)}

# ========== Service Management ==========

def get_service_status(service_name):
    """Get detailed service status"""
    try:
        import subprocess
        
        # Get systemd status
        result = subprocess.run(
            ['systemctl', 'is-active', service_name],
            capture_output=True, text=True, timeout=5
        )
        status = result.stdout.strip()
        
        # Get uptime
        uptime_result = subprocess.run(
            ['systemctl', 'show', service_name, '--property=ActiveEnterTimestamp'],
            capture_output=True, text=True, timeout=5
        )
        uptime = uptime_result.stdout.strip().replace('ActiveEnterTimestamp=', '')
        
        # Get recent logs
        logs_result = subprocess.run(
            ['journalctl', '-u', service_name, '-n', '5', '--no-pager'],
            capture_output=True, text=True, timeout=10
        )
        logs = logs_result.stdout.strip().split('\n')[-5:]
        
        return {
            'name': service_name,
            'status': status,
            'uptime': uptime,
            'logs': logs
        }
    except Exception as e:
        return {'name': service_name, 'status': 'unknown', 'error': str(e)}

def restart_service(service_name):
    """Restart a systemd service"""
    try:
        import subprocess
        result = subprocess.run(
            ['systemctl', 'restart', service_name],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return {'success': True, 'message': f'{service_name} restarted successfully'}
        else:
            return {'success': False, 'error': result.stderr}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def get_all_services():
    """Get status of all VPN-related services"""
    services = ['x-ui', 'named', 'nginx', 'docker', 'fail2ban']
    results = []
    for svc in services:
        results.append(get_service_status(svc))
    return results

# ========== Log Viewer ==========

def get_logs(service_name, lines=50):
    """Get logs from journald"""
    try:
        import subprocess
        
        if service_name == 'system':
            cmd = ['journalctl', '-n', str(lines), '--no-pager']
        else:
            cmd = ['journalctl', '-u', service_name, '-n', str(lines), '--no-pager']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return {'logs': result.stdout.split('\n'), 'service': service_name}
    except Exception as e:
        return {'logs': [], 'error': str(e)}

# ========== Config File Manager ==========

def list_config_files():
    """List important config files"""
    configs = [
        {'path': '/etc/x-ui/x-ui.db', 'name': 'x-ui Database', 'type': 'binary'},
        {'path': '/etc/hysteria2/config.yaml', 'name': 'Hysteria 2 Config', 'type': 'yaml'},
        {'path': '/etc/nginx/sites-available/foolsland.ru', 'name': 'Nginx Site Config', 'type': 'nginx'},
        {'path': '/etc/bind/named.conf.local', 'name': 'BIND Local Config', 'type': 'bind'},
        {'path': '/etc/bind/zones/db.foolsland.ru', 'name': 'DNS Zone File', 'type': 'zone'},
        {'path': '/etc/systemd/system/vpn-dashboard.service', 'name': 'Dashboard Service', 'type': 'systemd'},
        {'path': '/etc/fail2ban/jail.local', 'name': 'Fail2ban Config', 'type': 'config'},
    ]
    
    import os
    existing = []
    for cfg in configs:
        if os.path.exists(cfg['path']):
            cfg['size'] = os.path.getsize(cfg['path'])
            cfg['mtime'] = os.path.getmtime(cfg['path'])
            existing.append(cfg)
    
    return existing

def read_file_safe(file_path, max_size=102400):
    """Read file with size limit"""
    try:
        import os
        if not os.path.exists(file_path):
            return {'error': 'File not found'}
        
        size = os.path.getsize(file_path)
        if size > max_size:
            # Read last max_size bytes
            with open(file_path, 'rb') as f:
                f.seek(-max_size, 2)
                content = f.read().decode('utf-8', errors='ignore')
                return {'content': content, 'truncated': True, 'size': size}
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return {'content': f.read(), 'size': size}
    except Exception as e:
        return {'error': str(e)}

def write_file_safe(file_path, content):
    """Write file with backup"""
    try:
        import shutil
        import os
        
        # Create backup
        backup_path = file_path + '.backup.' + datetime.now().strftime('%Y%m%d_%H%M%S')
        if os.path.exists(file_path):
            shutil.copy2(file_path, backup_path)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return {'success': True, 'backup': backup_path}
    except Exception as e:
        return {'success': False, 'error': str(e)}

# ========== Notifications / Alerts ==========

def check_critical_resources():
    """Check for critical resource usage"""
    import psutil
    alerts = []
    
    cpu = psutil.cpu_percent(interval=1)
    if cpu > 90:
        alerts.append(f'CPU usage critical: {cpu}%')
    
    memory = psutil.virtual_memory()
    if memory.percent > 90:
        alerts.append(f'Memory usage critical: {memory.percent}%')
    
    disk = psutil.disk_usage('/')
    if disk.percent > 90:
        alerts.append(f'Disk usage critical: {disk.percent}%')
    
    return alerts

# Initialize
init_history_db()




# ========== Useful Features API ==========

@app.route('/api/services')
@requires_auth
def api_services():
    """Get all service statuses"""
    return flask.jsonify(get_all_services())

@app.route('/api/services/<name>/restart', methods=['POST'])
@requires_auth
def api_restart_service(name):
    """Restart a service"""
    return flask.jsonify(restart_service(name))

@app.route('/api/logs/<service>')
@requires_auth
def api_logs(service):
    """Get logs for service"""
    lines = flask.request.args.get('lines', 50, type=int)
    return flask.jsonify(get_logs(service, lines))

@app.route('/api/history')
@requires_auth
def api_history():
    """Get resource history"""
    hours = flask.request.args.get('hours', 24, type=int)
    return flask.jsonify(get_resource_history(hours))

@app.route('/api/history/log', methods=['POST'])
@requires_auth
def api_log_resources():
    """Log current resources"""
    return flask.jsonify(log_resources())

@app.route('/api/configs')
@requires_auth
def api_configs():
    """List config files"""
    return flask.jsonify({'configs': list_config_files()})

@app.route('/api/configs/read')
@requires_auth
def api_config_read():
    """Read config file"""
    path = flask.request.args.get('path', '')
    return flask.jsonify(read_file_safe(path))

@app.route('/api/configs/write', methods=['POST'])
@requires_auth
def api_config_write():
    """Write config file"""
    data = flask.request.get_json()
    path = data.get('path', '')
    content = data.get('content', '')
    return flask.jsonify(write_file_safe(path, content))

@app.route('/api/alerts')
@requires_auth  
def api_alerts():
    """Get critical alerts"""
    return flask.jsonify({'alerts': check_critical_resources()})



@app.route('/api/traffic/log', methods=['POST'])
@requires_auth
def api_log_traffic():
    return flask.jsonify(log_traffic_hourly())

@app.route('/api/traffic/history')
@requires_auth
def api_traffic_history():
    hours = flask.request.args.get('hours', 24, type=int)
    return flask.jsonify(get_traffic_history(hours))

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=False)
