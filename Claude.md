# Project: Open Sesame - LLM Gatekeeper (GL-MT3000 Beryl AX)

## System Environment
- **Device:** GL.iNet GL-MT3000 (OpenWrt 21.02/4.x based)
- **Architecture:** aarch64_cortex-a53
- **IP Address:** 192.168.0.2 (WAN side) / 192.168.8.1 (LAN side)
- **Access Method:** SSH as `root@192.168.0.2` (pw: root pw is: paStoz-4fufro-munbit )

## Critical Constraints
- **Low Storage:** The router has limited flash. Always check `df -h` before installing packages. Use `/tmp` for temporary files.
- **Opkg over Apt:** Use `opkg update` and `opkg install` instead of `apt`.
- **Python:** Use `python3`. Avoid heavy libraries (Pandas/Scikit-learn). HTTP requests use urllib (built-in).

## Command Execution Pattern
- You are running on a laptop but targeting the router.
- **DO NOT** run local commands like `systemctl` or `apt-get`.
- **ALWAYS** prefix router commands with SSH: `ssh root@192.168.0.2 "[command]"`
- To deploy files: Use `cat file | ssh root@192.168.0.2 "cat > /path/to/file"` (router lacks sftp-server).

## Architecture
The system consists of a single Python file (`gatekeeper.py`) that provides:
- **Nighttime Mode (9pm-5am)**: Captive portal requiring AI justification for internet access
- **Daytime Mode (5am-9pm)**: Open access with optional Focus Mode and Voluntary Lockdown
- **Stats Dashboard**: Tracks all activity with tabbed charts (Night/Day views)
- **Settings Page**: Configure Focus Mode blocked domains

## Key Files (on router)
- `/root/gatekeeper.py` - Main server (~3300 lines)
- `/root/gatekeeper.secrets` - API key (GEMINI_API_KEY=...)
- `/root/gatekeeper_settings.json` - Focus mode domains
- `/root/gatekeeper_history.json` - Permanent stats log

## Repository Structure
- `gatekeeper.py` - Main application with embedded HTML templates
- `init.d/gatekeeper` - OpenWrt init script
- `config/gatekeeper.secrets.example` - API key format example

## Coding Style
- Prefer POSIX-compliant shell scripts or Python 3.
- Use `logger` command in shell or `syslog` in Python for router logging.
- All HTML templates use double curly braces `{{` for CSS (Python format escaping).

# Git

Initialize a git if not existent. Regularly commit.
