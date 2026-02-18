# Project: LLM Gatekeeper (GL-MT3000 Beryl AX)

## System Environment
- **Device:** GL.iNet GL-MT3000 (OpenWrt 21.02/4.x based)
- **Architecture:** aarch64_cortex-a53
- **IP Address:** 192.168.0.2 (WAN side) / 192.168.8.1 (LAN side)
- **Access Method:** SSH as `root@192.168.0.2` (pw: root pw is: paStoz-4fufro-munbit )

## Critical Constraints
- **Low Storage:** The router has limited flash. Always check `df -h` before installing packages. Use `/tmp` for temporary files.
- **Opkg over Apt:** Use `opkg update` and `opkg install` instead of `apt`.
- **Nodogsplash (NDS):** The gatekeeper software is `nodogsplash`. Use `ndsctl` commands for authentication management.
- **Python:** Use `python3`. Avoid heavy libraries (Pandas/Scikit-learn). Use `requests` for API calls.

## Command Execution Pattern
- You are running on a laptop but targeting the router.
- **DO NOT** run local commands like `systemctl` or `apt-get`.
- **ALWAYS** prefix router commands with SSH: `ssh root@192.168.0.2 "[command]"`
- To edit files: Read them via `ssh root@192.168.0.2 "cat /path/to/file"` and write them back using `scp` or `tee`.

## Development Tasks
1. **Captive Portal:** Modify `/etc/nodogsplash/htdocs/splash.html` to include the LLM justification prompt.
2. **Justification Script:** Create `/root/gatekeeper.py` to handle NDS logout/login logic.
3. **Cron/Dæmon:** Ensure the script runs on boot or via a trigger.

## Coding Style
- Prefer POSIX-compliant shell scripts or Python 3.
- Use `logger` command in shell or `syslog` in Python for router logging.

# Git

Initialize a git if not existent. Regularly commit.
