# Router Setup Guide

Complete reproducible setup instructions for the LLM Gatekeeper on GL-MT3000.

## Prerequisites

- SSH access to router: `ssh root@192.168.0.2`
- Router running OpenWrt (GL.iNet firmware)
- Internet connection on router for package installation
- Google Gemini API key

## Step 1: Install Dependencies

```bash
# Update package list
ssh root@192.168.0.2 "opkg update"

# Install required packages
ssh root@192.168.0.2 "opkg install python3-light conntrack"

# Verify installation
ssh root@192.168.0.2 "which python3 && which conntrack"
```

## Step 2: Deploy Gatekeeper Script

```bash
# Deploy gatekeeper script (from smart_router directory)
ssh root@192.168.0.2 "cat > /root/gatekeeper.py" < gatekeeper.py

# Make executable
ssh root@192.168.0.2 "chmod +x /root/gatekeeper.py"
```

## Step 3: Configure API Key

```bash
# Create secrets file with your Gemini API key
ssh root@192.168.0.2 'cat > /root/gatekeeper.secrets << EOF
GEMINI_API_KEY=your-api-key-here
EOF'

# Secure the file
ssh root@192.168.0.2 "chmod 600 /root/gatekeeper.secrets"
```

## Step 4: Deploy Init Script

```bash
# Create init script
ssh root@192.168.0.2 'cat > /etc/init.d/gatekeeper << "INITEOF"
#!/bin/sh /etc/rc.common
# Gatekeeper LLM service for nighttime internet access control

START=99
STOP=10

USE_PROCD=1
PROG=/root/gatekeeper.py

# Load API key from secrets file
. /root/gatekeeper.secrets 2>/dev/null || true

is_nighttime() {
    HOUR=$(date +%H)
    if [ "$HOUR" -ge 21 ] || [ "$HOUR" -lt 5 ]; then
        return 0
    fi
    return 1
}

start_service() {
    logger -t gatekeeper "Starting gatekeeper service"
    procd_open_instance
    procd_set_param env GEMINI_API_KEY="$GEMINI_API_KEY"

    if is_nighttime; then
        logger -t gatekeeper "Nighttime - starting in gatekeeper mode"
        procd_set_param command /usr/bin/python3 -u "$PROG" --mode gatekeeper
    else
        logger -t gatekeeper "Daytime - starting in server-only mode"
        procd_set_param command /usr/bin/python3 -u "$PROG" --server
    fi

    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param pidfile /var/run/gatekeeper.pid
    procd_close_instance
}

stop_service() {
    logger -t gatekeeper "Stopping gatekeeper service"
    /usr/bin/python3 "$PROG" --mode open 2>/dev/null || true
}

reload_service() {
    stop
    start
}
INITEOF'

# Make executable and enable
ssh root@192.168.0.2 "chmod +x /etc/init.d/gatekeeper"
ssh root@192.168.0.2 "/etc/init.d/gatekeeper enable"
```

## Step 5: Configure Cron Jobs (Optional)

The init script auto-detects day/night on startup. For mid-session transitions, add cron jobs:

```bash
ssh root@192.168.0.2 'cat > /etc/crontabs/root << "EOF"
# Gatekeeper mode switching
0 21 * * * . /root/gatekeeper.secrets && export GEMINI_API_KEY && /usr/bin/python3 /root/gatekeeper.py --mode gatekeeper 2>&1 | logger -t gatekeeper-cron
0 5 * * * /usr/bin/python3 /root/gatekeeper.py --mode open 2>&1 | logger -t gatekeeper-cron
EOF'

# Restart cron
ssh root@192.168.0.2 "/etc/init.d/cron restart"
```

**Note**: The 9pm cron job sources the API key from `/root/gatekeeper.secrets` before starting gatekeeper mode.

## Step 6: Start and Verify

```bash
# Start the service
ssh root@192.168.0.2 "/etc/init.d/gatekeeper start"

# Verify it's running
ssh root@192.168.0.2 "ps | grep gatekeeper"

# Test API connection
ssh root@192.168.0.2 ". /root/gatekeeper.secrets && GEMINI_API_KEY=\$GEMINI_API_KEY python3 /root/gatekeeper.py --test"

# Check logs
ssh root@192.168.0.2 "logread | grep gatekeeper | tail -20"
```

## Testing the Portal

### 1. Enable gatekeeper mode manually

```bash
# Stop the service first
ssh root@192.168.0.2 "/etc/init.d/gatekeeper stop"

# Start in gatekeeper mode
ssh root@192.168.0.2 ". /root/gatekeeper.secrets && GEMINI_API_KEY=\$GEMINI_API_KEY python3 /root/gatekeeper.py --mode gatekeeper &"
```

### 2. Verify firewall rules

```bash
# Check iptables NAT rules (should show port 80 redirect to 2050)
ssh root@192.168.0.2 "iptables -t nat -L PREROUTING -n | head -10"

# Check DNS hijacking is active
ssh root@192.168.0.2 "uci show dhcp | grep address"
# Should show: dhcp.@dnsmasq[0].address='/#/192.168.8.1'
```

### 3. Test from a client device

1. Connect a phone/laptop to the router's WiFi
2. Open any HTTP website (not HTTPS)
3. Should redirect to captive portal
4. On iOS/macOS, the captive portal popup should appear automatically

### 4. Return to open mode

```bash
ssh root@192.168.0.2 "python3 /root/gatekeeper.py --mode open"
```

## How It Works

### Nighttime Mode (Gatekeeper)

1. **DNS Hijacking**: All domain lookups resolve to router IP (192.168.8.1)
   ```
   uci add_list dhcp.@dnsmasq[0].address='/#/192.168.8.1'
   ```

2. **HTTP Redirect**: All port 80 traffic redirected to captive portal
   ```
   iptables -t nat -I PREROUTING 1 -i br-lan -p tcp --dport 80 -j REDIRECT --to-port 2050
   ```

3. **Internet Blocking**: Forward chain blocks LAN→WAN
   ```
   iptables -t filter -I FORWARD 1 -i br-lan -o eth0 -j REJECT
   ```

4. **External DNS for API**: Gemini API calls use 8.8.8.8 to bypass local DNS hijacking

### Daytime Mode (Open)

- All firewall rules removed
- DNS hijacking disabled
- Normal internet access

## Troubleshooting

### Captive portal shows router admin UI instead of splash page

The iptables rule might be excluding the gateway IP. Check:
```bash
ssh root@192.168.0.2 "iptables -t nat -L PREROUTING -n | grep 2050"
```

Should show `0.0.0.0/0` for destination, NOT `!192.168.8.1`.

### "Failed to reach AI service" error

DNS hijacking is blocking the Gemini API. The gatekeeper script should use external DNS (8.8.8.8) automatically. Verify:
```bash
ssh root@192.168.0.2 "nslookup generativelanguage.googleapis.com 8.8.8.8"
```

### iOS/macOS not showing captive portal popup

1. Check DNS hijacking is active:
   ```bash
   ssh root@192.168.0.2 "uci show dhcp | grep address"
   ```

2. Forget the WiFi network and reconnect

3. Try opening `http://captive.apple.com` manually

### Gatekeeper server not responding

```bash
# Check if port 2050 is listening
ssh root@192.168.0.2 "netstat -tlnp | grep 2050"

# Restart service
ssh root@192.168.0.2 "/etc/init.d/gatekeeper restart"
```

### View all logs

```bash
ssh root@192.168.0.2 "logread | grep gatekeeper | tail -50"
```

## Uninstall

```bash
# Stop and disable service
ssh root@192.168.0.2 "/etc/init.d/gatekeeper stop"
ssh root@192.168.0.2 "/etc/init.d/gatekeeper disable"

# Remove files
ssh root@192.168.0.2 "rm -f /root/gatekeeper.py /root/gatekeeper.secrets /etc/init.d/gatekeeper"

# Remove cron entries
ssh root@192.168.0.2 "sed -i '/gatekeeper/d' /etc/crontabs/root"
ssh root@192.168.0.2 "/etc/init.d/cron restart"

# Restore DNS (if stuck in gatekeeper mode)
ssh root@192.168.0.2 "uci del_list dhcp.@dnsmasq[0].address='/#/192.168.8.1'; uci commit dhcp; /etc/init.d/dnsmasq restart"
```

## Configuration

### Changing access times

Edit the `is_nighttime()` function in `/etc/init.d/gatekeeper` and update cron times.

### Changing API key

```bash
ssh root@192.168.0.2 "echo 'GEMINI_API_KEY=new-key-here' > /root/gatekeeper.secrets"
ssh root@192.168.0.2 "/etc/init.d/gatekeeper restart"
```

### Adjusting AI behavior

Edit the `SYSTEM_PROMPT` variable in `/root/gatekeeper.py` to change how the AI evaluates requests.

### Changing access durations

Edit the access rules in `SYSTEM_PROMPT` within `gatekeeper.py`.
