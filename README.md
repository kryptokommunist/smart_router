# LLM Gatekeeper for GL-MT3000

An AI-powered captive portal system that controls nighttime internet access on GL.iNet GL-MT3000 (Beryl AX) routers.

## Overview

During nighttime hours (9pm-5am), users must justify their internet access to a Google Gemini AI. The AI evaluates the request and grants timed access based on the legitimacy of the reason.

### Access Rules

| Duration | Valid Reasons |
|----------|---------------|
| 10 min | Quick check that can't wait |
| 60 min | Work/school tasks due TODAY |
| 120 min | Video calls, meetings |

### Schedule

- **5:00 AM - 9:00 PM**: Open access (no restrictions)
- **9:00 PM - 5:00 AM**: Captive portal with LLM justification

## Project Structure

```
smart_router/
├── README.md               # This file
├── ROUTER_SETUP.md         # Reproducible setup instructions
├── scripts/
│   └── gatekeeper.py       # Main Python server
├── config/
│   ├── nodogsplash         # Captive portal config
│   └── crontab             # Scheduled mode switching
├── htdocs/
│   └── splash.html         # User-facing portal page
└── init.d/
    └── gatekeeper          # OpenWrt startup script
```

## Quick Start

See `ROUTER_SETUP.md` for complete installation instructions.

```bash
# Deploy to router
scp scripts/gatekeeper.py root@192.168.0.2:/root/
scp config/nodogsplash root@192.168.0.2:/etc/config/
scp htdocs/splash.html root@192.168.0.2:/etc/nodogsplash/htdocs/
scp init.d/gatekeeper root@192.168.0.2:/etc/init.d/

# Enable and start
ssh root@192.168.0.2 "chmod +x /etc/init.d/gatekeeper && /etc/init.d/gatekeeper enable && /etc/init.d/gatekeeper start"
```

## Testing

```bash
# Test Gemini API connection
ssh root@192.168.0.2 "python3 /root/gatekeeper.py --test"

# Check nodogsplash status
ssh root@192.168.0.2 "ndsctl status"

# View authenticated clients
ssh root@192.168.0.2 "ndsctl clients"

# Check logs
ssh root@192.168.0.2 "logread | grep gatekeeper"
```

## Manual Mode Control

```bash
# Enable captive portal (gatekeeper mode)
ssh root@192.168.0.2 "python3 /root/gatekeeper.py --mode gatekeeper"

# Disable captive portal (open access)
ssh root@192.168.0.2 "python3 /root/gatekeeper.py --mode open"
```

## Requirements

- GL.iNet GL-MT3000 (OpenWrt-based)
- nodogsplash package
- python3-light
- python3-urllib3
- Google Gemini API key

## License

Private project - not for redistribution.
