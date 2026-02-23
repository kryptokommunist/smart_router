# Open Sesame - LLM Gatekeeper for GL-MT3000

<p align="center">
  <img src="logo.png" alt="Open Sesame Logo" width="400">
</p>

<p align="center">
  <strong>An AI-powered captive portal that makes you justify your late-night internet usage</strong>
</p>

---

An AI-powered captive portal system that controls nighttime internet access on GL.iNet GL-MT3000 (Beryl AX) routers. During restricted hours, users must convince a Google Gemini AI that they have a legitimate reason to access the internet.

## How It Works

1. **Connect to WiFi** during nighttime hours (9pm-5am)
2. **Get redirected** to a captive portal chat interface
3. **Explain your reason** for needing internet access
4. **AI evaluates** your justification and asks follow-up questions
5. **Access granted** (or denied) with a time limit

### Access Rules

| Duration | Valid Reasons |
|----------|---------------|
| 10 min | Quick check that can't wait |
| 60 min | Work/school tasks due TODAY |
| 120 min | Video calls, meetings |

For requests over 10 minutes, **proof is required** (screenshot of email, calendar invite, etc.). The AI analyzes uploaded images to verify claims.

### Schedule

- **5:00 AM - 9:00 PM**: Daytime mode (open access with Focus Mode & Lockdown options)
- **9:00 PM - 5:00 AM**: Nighttime mode (captive portal with LLM justification)

### Daytime Features

During the day, you can optionally restrict yourself:

| Feature | Description |
|---------|-------------|
| **Focus Mode** | Blocks distracting sites (YouTube, Instagram, Twitter, etc.) via DNS & IP firewall |
| **Lock Internet** | Voluntarily blocks all internet; requires AI justification to unlock |

Both features have configurable durations (15 min to end-of-day).

## Technical Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      GL-MT3000 Router                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐ │
│  │ DNS Hijack  │───>│ HTTP Redir  │───>│ Captive Portal  │ │
│  │ (dnsmasq)   │    │ (iptables)  │    │ (Python:2050)   │ │
│  └─────────────┘    └─────────────┘    └────────┬────────┘ │
│                                                  │          │
│                                                  v          │
│                                        ┌─────────────────┐  │
│                                        │   Gemini API    │  │
│                                        │ (external DNS)  │  │
│                                        └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

- **DNS Hijacking**: All domains resolve to router IP for captive portal detection
- **HTTP Redirect**: Port 80 traffic redirected to Python server (port 2050)
- **Forward Blocking**: iptables blocks LAN→WAN until access granted
- **External DNS Resolution**: API calls bypass local DNS hijacking via 8.8.8.8
- **Session Management**: Time-limited access with automatic revocation

## Project Structure

```
smart_router/
├── README.md                 # This file
├── ROUTER_SETUP.md           # Reproducible setup instructions
├── CLAUDE.md                 # Development context
├── gatekeeper.py             # Main Python server (~3300 lines)
├── logo.png                  # Project logo
├── config/
│   └── gatekeeper.secrets.example  # API key file format
└── init.d/
    └── gatekeeper            # OpenWrt startup script
```

### Data Files (on router)

```
/root/
├── gatekeeper.py             # Main server
├── gatekeeper.secrets        # API key (GEMINI_API_KEY=...)
├── gatekeeper_settings.json  # Focus mode domains config
└── gatekeeper_history.json   # Permanent stats log
/tmp/
├── gatekeeper_requests.json  # Nightly request summaries (cleared daily)
└── gatekeeper_conversations.json  # Full conversation logs (cleared daily)
```

## Quick Start

See `ROUTER_SETUP.md` for complete installation instructions.

```bash
# Deploy to router
ssh root@192.168.0.2 "cat > /root/gatekeeper.py" < gatekeeper.py

# Create secrets file with your Gemini API key
ssh root@192.168.0.2 'echo "GEMINI_API_KEY=your-key-here" > /root/gatekeeper.secrets'

# Enable and start
ssh root@192.168.0.2 "/etc/init.d/gatekeeper enable && /etc/init.d/gatekeeper start"
```

## Usage

### Testing

```bash
# Test Gemini API connection
ssh root@192.168.0.2 ". /root/gatekeeper.secrets && GEMINI_API_KEY=\$GEMINI_API_KEY python3 /root/gatekeeper.py --test"

# Check if service is running
ssh root@192.168.0.2 "ps | grep gatekeeper"

# View logs
ssh root@192.168.0.2 "logread | grep gatekeeper"
```

### Manual Mode Control

```bash
# Enable captive portal (gatekeeper mode)
ssh root@192.168.0.2 "/etc/init.d/gatekeeper stop"
ssh root@192.168.0.2 ". /root/gatekeeper.secrets && GEMINI_API_KEY=\$GEMINI_API_KEY python3 /root/gatekeeper.py --mode gatekeeper"

# Disable captive portal (open access)
ssh root@192.168.0.2 "python3 /root/gatekeeper.py --mode open"

# Run server only (no firewall changes)
ssh root@192.168.0.2 "python3 /root/gatekeeper.py --server"
```

### Web Interface

| URL | Description |
|-----|-------------|
| `http://192.168.8.1:2050/` | Main portal (LAN) |
| `http://192.168.0.2:2050/` | Main portal (WAN) |
| `http://192.168.8.1:2050/stats` | Statistics dashboard |
| `http://192.168.8.1:2050/settings` | Focus mode domain settings |

## Requirements

### Hardware
- GL.iNet GL-MT3000 (Beryl AX) or similar OpenWrt router
- ~155MB free storage
- ARM Cortex-A53 or equivalent

### Software
- OpenWrt 21.02+
- python3-light
- conntrack-tools (for connection flushing)

### API
- Google Gemini API key (uses `gemma-3-27b-it` model)

## How the AI Decides

The Open Sesame AI acts like a **warm, loving parent** - genuinely caring about your wellbeing while maintaining firm boundaries. It wants you to get good sleep because rest matters for your health and success.

### Behavior
1. **Warmly asks** how much time you need
2. **For >10 minutes**: Kindly requests justification AND proof (screenshot)
3. **Analyzes uploaded images** to verify claims match reality
4. **Can ask up to 3 clarifying questions** before deciding
5. **Tracks request history** with timestamps - patterns and timing matter
6. **Only sends images once** to the AI (not re-referenced in follow-up messages)

### What Gets Approved
- Urgent work emails with deadlines
- School assignments due today
- Scheduled video calls
- Quick checks that cause stress if delayed

### What Gets Denied (with care!)
- "Just want to browse"
- Social media, entertainment
- Vague claims without proof
- Repeated requests for the same reason

Example denial: *"I know it feels important right now, but this can wait until morning. Your sleep tonight will help you tackle it better tomorrow. Sweet dreams!"*

## Stats Dashboard

The `/stats` page shows comprehensive statistics with tabbed views:

### Nighttime Stats (9pm-5am)
- **Approved/Denied** request counts
- **Night Hours** granted (cumulative)
- **Time Distribution** - scatter plot showing when exceptions were requested
- **Weekday Distribution** - bar chart with approved (blue) vs denied (red)

### Daytime Stats (5am-9pm)
- **Focus Sessions** - count of Focus Mode activations
- **Lockdowns** - count of voluntary internet lockdowns
- **Day Hours** - total time spent in Focus Mode + Lockdown
- **Time Distribution** - scatter plot of Focus (orange) and Lockdown (purple) usage
- **Weekday Distribution** - bar chart showing patterns

### Recent Activity
Shows the last 20 events across all modes with color-coded badges.

All stats persist across reboots in `/root/gatekeeper_history.json`.

## Focus Mode

Focus mode blocks distracting websites during daytime when you need to concentrate:

1. Go to the daytime portal and click "Focus Mode"
2. Select duration (15 min to end of day)
3. Sites are blocked via:
   - **DNS blocking**: dnsmasq resolves domains to 0.0.0.0
   - **IP firewall**: iptables blocks resolved IPs (fetched fresh each activation)

Default blocked sites: YouTube, Instagram, Twitter/X, Telegram, ZDF

### Customizing Blocked Sites

Visit `/settings` to add or remove domains. Both the domain and its `www.` variant are handled automatically.

## Blog Post

Read the full story of building this project (including where AI coding assistants still fall short): [Building an AI Gatekeeper](https://kryptokommunist.github.io/tech/2026/02/19/llm-gatekeeper-router.html)

## License

MIT License - feel free to adapt for your own router/use case.
