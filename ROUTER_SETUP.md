# Router Setup Guide

Complete reproducible setup instructions for the LLM Gatekeeper on GL-MT3000.

## Prerequisites

- SSH access to router: `ssh root@192.168.0.2`
- Router running OpenWrt (GL.iNet firmware)
- Internet connection on router for package installation

## Step 1: Install Dependencies

```bash
# Update package list
ssh root@192.168.0.2 "opkg update"

# Install required packages (~15MB)
ssh root@192.168.0.2 "opkg install nodogsplash python3-light python3-urllib3"

# Verify installation
ssh root@192.168.0.2 "which python3 && which ndsctl"
```

## Step 2: Deploy Files

### From the smart_router directory:

```bash
# Create nodogsplash htdocs directory
ssh root@192.168.0.2 "mkdir -p /etc/nodogsplash/htdocs"

# Deploy gatekeeper script
scp scripts/gatekeeper.py root@192.168.0.2:/root/
ssh root@192.168.0.2 "chmod +x /root/gatekeeper.py"

# Deploy nodogsplash configuration
scp config/nodogsplash root@192.168.0.2:/etc/config/

# Deploy splash page
scp htdocs/splash.html root@192.168.0.2:/etc/nodogsplash/htdocs/

# Deploy init script
scp init.d/gatekeeper root@192.168.0.2:/etc/init.d/
ssh root@192.168.0.2 "chmod +x /etc/init.d/gatekeeper"
```

## Step 3: Configure Cron Jobs

```bash
# Append cron entries for scheduled mode switching
ssh root@192.168.0.2 "cat >> /etc/crontabs/root << 'EOF'
# Gatekeeper mode switching
0 21 * * * /usr/bin/python3 /root/gatekeeper.py --mode gatekeeper 2>&1 | logger -t gatekeeper-cron
0 5 * * * /usr/bin/python3 /root/gatekeeper.py --mode open 2>&1 | logger -t gatekeeper-cron
EOF"

# Restart cron service
ssh root@192.168.0.2 "/etc/init.d/cron restart"
```

## Step 4: Enable Services

```bash
# Enable gatekeeper to start on boot
ssh root@192.168.0.2 "/etc/init.d/gatekeeper enable"

# Start gatekeeper server
ssh root@192.168.0.2 "/etc/init.d/gatekeeper start"

# Enable nodogsplash (only if currently in nighttime hours)
# During daytime, leave nodogsplash stopped
ssh root@192.168.0.2 "/etc/init.d/nodogsplash enable"
```

## Step 5: Verify Installation

```bash
# Test Gemini API connection
ssh root@192.168.0.2 "python3 /root/gatekeeper.py --test"

# Check gatekeeper service is running
ssh root@192.168.0.2 "ps | grep gatekeeper"

# Check nodogsplash status
ssh root@192.168.0.2 "ndsctl status"

# Check logs
ssh root@192.168.0.2 "logread | grep gatekeeper | tail -20"
```

## Testing the Portal

1. **Enable gatekeeper mode manually:**
   ```bash
   ssh root@192.168.0.2 "python3 /root/gatekeeper.py --mode gatekeeper"
   ```

2. **Connect a device to the router's WiFi**

3. **Open a browser** - should redirect to captive portal

4. **Submit a test justification**

5. **Verify authentication:**
   ```bash
   ssh root@192.168.0.2 "ndsctl clients"
   ```

6. **Return to open mode:**
   ```bash
   ssh root@192.168.0.2 "python3 /root/gatekeeper.py --mode open"
   ```

## Troubleshooting

### Portal not redirecting
```bash
# Check nodogsplash is running
ssh root@192.168.0.2 "ndsctl status"

# Check firewall rules
ssh root@192.168.0.2 "iptables -t nat -L | grep -i nodo"
```

### Gatekeeper server not responding
```bash
# Check if port 2050 is listening
ssh root@192.168.0.2 "netstat -tlnp | grep 2050"

# Restart gatekeeper
ssh root@192.168.0.2 "/etc/init.d/gatekeeper restart"
```

### API errors
```bash
# Test API directly
ssh root@192.168.0.2 "python3 /root/gatekeeper.py --test"

# Check router can reach internet
ssh root@192.168.0.2 "ping -c 3 google.com"
```

### View all logs
```bash
ssh root@192.168.0.2 "logread | grep -E '(gatekeeper|nodogsplash)' | tail -50"
```

## Uninstall

```bash
# Stop and disable services
ssh root@192.168.0.2 "/etc/init.d/gatekeeper stop && /etc/init.d/gatekeeper disable"
ssh root@192.168.0.2 "/etc/init.d/nodogsplash stop && /etc/init.d/nodogsplash disable"

# Remove files
ssh root@192.168.0.2 "rm -f /root/gatekeeper.py /etc/init.d/gatekeeper"

# Remove cron entries (manually edit)
ssh root@192.168.0.2 "crontab -e"

# Optionally remove packages
ssh root@192.168.0.2 "opkg remove nodogsplash python3-light python3-urllib3"
```

## Configuration Notes

### Changing access times
Edit `/etc/crontabs/root` on the router or `config/crontab` locally.

### Changing API key
Edit `/root/gatekeeper.py` on the router, change `GEMINI_API_KEY`.

### Adjusting LLM behavior
Edit the `SYSTEM_PROMPT` variable in `gatekeeper.py`.
