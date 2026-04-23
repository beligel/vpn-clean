# VPN Server + Dashboard

Complete VPN server installer with web dashboard. Supports Hysteria 2 (UDP) and VLESS+Reality (TCP) protocols.

## Features

- ⚡ **Hysteria 2** - Fast UDP proxy with obfuscation
- 🔒 **VLESS+Reality** - TCP proxy with TLS camouflage  
- 📊 **Web Dashboard** - Real-time monitoring (no DNS, simple VPN dashboard)
- 🐳 **No Docker** - Native systemd services
- 🟢 **Green Status** - Active services show green badge
- 📱 **Client URLs** - One-click copy for mobile apps

## Quick Install

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/vpn-clean/main/install.sh)"
```

Or clone and run:
```bash
git clone https://github.com/YOUR_USERNAME/vpn-clean.git
cd vpn-clean
sudo bash install.sh
```

## What's Installed

| Component | Description | Port |
|-----------|-------------|------|
| Hysteria 2 | UDP proxy with salamander obfuscation | 8443/UDP |
| x-ui | VLESS+Reality panel | 54321/TCP |
| Dashboard | Python Flask monitoring | 8080 (local) |
| Nginx | Reverse proxy with SSL | 9443 (HTTPS) |

## Dashboard

Access at `https://YOUR_IP:9443/`

**Default login:**
- Username: `admin`
- Password: auto-generated (see `/root/vpn-credentials.txt`)

### Dashboard Features

- 💻 System metrics (CPU, RAM, Disk, Network)
- ⚡ Hysteria 2 status with green/red indicator
- 🔒 VLESS status with direct link to x-ui panel
- 📊 Traffic statistics
- 📋 One-click copy connection URLs
- 🔄 Auto-refresh every 30 seconds

### API Endpoints

```
GET /api/stats     - JSON statistics
POST /api/restart/{service} - Restart service (hysteria-server, x-ui, nginx)
```

## Client Configuration

### Hysteria 2
```
hysteria2://PASSWORD@IP:8443?obfs=salamander&obfs-password=OBFS_PASS&insecure=1#Hysteria2
```

### VLESS + Reality
```
vless://UUID@IP:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.nvidia.com&pbk=PUBLIC_KEY&type=tcp&fp=chrome#VLESS-Reality
```

## Recommended Apps

| Platform | App | Protocols |
|----------|-----|-----------|
| iOS | Hiddify, Shadowrocket | Hysteria 2, VLESS |
| Android | Hiddify, NekoBox | Hysteria 2, VLESS |
| Windows | Hiddify, NekoRay | Hysteria 2, VLESS |
| macOS | Hiddify | Hysteria 2, VLESS |
| Linux | Hysteria CLI, Xray | Hysteria 2, VLESS |

## Management

```bash
# View credentials
cat /root/vpn-credentials.txt

# Check services
systemctl status hysteria-server
systemctl status x-ui
systemctl status vpn-dashboard

# Restart services
systemctl restart hysteria-server
systemctl restart x-ui
systemctl restart vpn-dashboard

# View logs
journalctl -u hysteria-server -f
journalctl -u x-ui -f
```

## Firewall

The installer configures UFW with these rules:
- 22/tcp (SSH)
- 80/tcp (HTTP)
- 443/tcp (HTTPS)
- 9443/tcp (Dashboard HTTPS)
- 8443/udp (Hysteria 2)

## Security

- Auto-generated secure passwords
- Self-signed certificates for Hysteria
- Let's Encrypt for Dashboard (optional)
- Basic HTTP auth for Dashboard

## License

MIT License - Use at your own risk.
