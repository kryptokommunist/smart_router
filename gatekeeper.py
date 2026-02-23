#!/usr/bin/env python3
"""
LLM Gatekeeper for GL-MT3000 Router
Standalone captive portal with Gemini AI justification for nighttime internet access.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import threading
import urllib.request
import urllib.parse
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from datetime import datetime
import hashlib

# Configuration
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemma-3-27b-it:generateContent"
GEMINI_HOST = "generativelanguage.googleapis.com"
SERVER_PORT = 2050  # Use port 2050 for captive portal
API_PORT = 2051   # API port for chat
GATEWAY_IP = "192.168.8.1"
LAN_INTERFACE = "br-lan"
REQUEST_LOG_FILE = "/tmp/gatekeeper_requests.json"  # Temporary log for the night
CONVERSATION_LOG_FILE = "/tmp/gatekeeper_conversations.json"  # Full conversation log, cleared at daytime
PERMANENT_LOG_FILE = "/root/gatekeeper_history.json"  # Persistent log across reboots (short summaries)
SETTINGS_FILE = "/root/gatekeeper_settings.json"  # User settings (focus mode domains, etc.)
EXTERNAL_DNS = "8.8.8.8"  # Use Google DNS to bypass local DNS hijacking

# Default focus mode domains
DEFAULT_FOCUS_DOMAINS = [
    "youtube.com", "www.youtube.com", "m.youtube.com",
    "instagram.com", "www.instagram.com",
    "twitter.com", "www.twitter.com", "x.com", "www.x.com",
    "zdf.de", "www.zdf.de",
    "telegram.org", "www.telegram.org", "web.telegram.org"
]

# Network-wide access (single exemption for entire network)
network_access_expiry = None  # timestamp when access expires, None = blocked
network_access_granted_by = None  # MAC that requested access

# Focus mode state
focus_mode_active = False
focus_mode_expiry = None
focus_mode_blocked_ips = set()

# Voluntary lockdown state (daytime self-imposed restrictions)
voluntary_lockdown_active = False
voluntary_lockdown_expiry = None
voluntary_lockdown_reason = None
voluntary_lockdown_exceptions = []

# Session storage (in-memory, cleared on restart)
sessions = {}  # {session_id: {"mac": str, "ip": str, "history": [], "questions_asked": int}}

# Rate limiting
rate_limit = {}  # {ip: {"count": int, "window_start": timestamp}}
RATE_LIMIT_WINDOW = 300  # 5 minutes
RATE_LIMIT_MAX = 10  # max requests per window


def load_request_log():
    """Load the request log from file."""
    try:
        if os.path.exists(REQUEST_LOG_FILE):
            with open(REQUEST_LOG_FILE, "r") as f:
                return json.load(f)
    except Exception as e:
        log(f"Error loading request log: {e}")
    return []


def save_request_log(requests):
    """Save the request log to file."""
    try:
        with open(REQUEST_LOG_FILE, "w") as f:
            json.dump(requests, f, indent=2)
    except Exception as e:
        log(f"Error saving request log: {e}")


def add_request_to_log(mac, reason, status, duration=None):
    """Add a request to the persistent log."""
    requests = load_request_log()
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mac": mac,
        "reason": reason[:200],  # Truncate long reasons
        "status": status,  # "approved" or "denied"
    }
    if duration:
        entry["duration"] = duration
    requests.append(entry)
    save_request_log(requests)
    log(f"Logged request: {status} for {mac}")

    # Save all requests (approved and denied) to permanent log
    check_and_trim_log()
    save_to_permanent_log(entry)


def clear_request_log():
    """Clear the request log (called when switching to open mode in the morning)."""
    try:
        if os.path.exists(REQUEST_LOG_FILE):
            os.remove(REQUEST_LOG_FILE)
            log("Request log cleared for new day")
    except Exception as e:
        log(f"Error clearing request log: {e}")


# --- Conversation Log Functions (detailed, cleared daily) ---

def load_conversation_log():
    """Load the full conversation log from file."""
    try:
        if os.path.exists(CONVERSATION_LOG_FILE):
            with open(CONVERSATION_LOG_FILE, "r") as f:
                return json.load(f)
    except Exception as e:
        log(f"Error loading conversation log: {e}")
    return []


def save_conversation_log(conversations):
    """Save the full conversation log to file."""
    try:
        with open(CONVERSATION_LOG_FILE, "w") as f:
            json.dump(conversations, f, indent=2)
    except Exception as e:
        log(f"Error saving conversation log: {e}")


def add_conversation_to_log(mac, conversation_history, status, duration=None):
    """Add a complete conversation to the nightly log."""
    conversations = load_conversation_log()
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mac": mac,
        "status": status,
        "conversation": conversation_history  # Full conversation with all messages
    }
    if duration:
        entry["duration"] = duration
    conversations.append(entry)
    save_conversation_log(conversations)
    log(f"Saved conversation to nightly log: {status} for {mac}")


def clear_conversation_log():
    """Clear the conversation log (called when switching to open mode)."""
    try:
        if os.path.exists(CONVERSATION_LOG_FILE):
            os.remove(CONVERSATION_LOG_FILE)
            log("Conversation log cleared for new day")
    except Exception as e:
        log(f"Error clearing conversation log: {e}")


# --- Permanent Log Functions (summaries only) ---

def load_permanent_log():
    """Load the permanent history log from file."""
    try:
        if os.path.exists(PERMANENT_LOG_FILE):
            with open(PERMANENT_LOG_FILE, "r") as f:
                return json.load(f)
    except Exception as e:
        log(f"Error loading permanent log: {e}")
    return []


def save_permanent_log(entries):
    """Save the permanent history log to file."""
    try:
        with open(PERMANENT_LOG_FILE, "w") as f:
            json.dump(entries, f, indent=2)
    except Exception as e:
        log(f"Error saving permanent log: {e}")


def save_to_permanent_log(entry):
    """Append a single entry to the permanent log."""
    entries = load_permanent_log()
    entries.append(entry)
    save_permanent_log(entries)
    desc = entry.get('reason', entry.get('type', 'unknown'))[:50]
    log(f"Saved to permanent log: {entry['timestamp']} - {desc}...")


def check_and_trim_log():
    """Check /overlay free space and trim log if less than 50MB free."""
    try:
        # Get free space on /overlay (persistent storage on OpenWrt)
        result = subprocess.run(["df", "-m", "/overlay"], capture_output=True, text=True, check=False)
        lines = result.stdout.strip().split("\n")
        if len(lines) >= 2:
            # Parse: Filesystem 1M-blocks Used Available Use% Mounted on
            parts = lines[1].split()
            if len(parts) >= 4:
                available_mb = int(parts[3])
                if available_mb < 50:
                    log(f"Low storage: {available_mb}MB free on /overlay, trimming log...")
                    trim_permanent_log()
    except Exception as e:
        log(f"Error checking storage: {e}")


def trim_permanent_log():
    """Delete oldest 50% of entries from permanent log."""
    entries = load_permanent_log()
    if len(entries) <= 10:
        return  # Keep at least 10 entries

    # Keep only the most recent 50%
    half = len(entries) // 2
    entries = entries[half:]
    save_permanent_log(entries)
    log(f"Trimmed permanent log, kept {len(entries)} entries")


# --- Settings Functions ---

def load_settings():
    """Load user settings from file."""
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as f:
                return json.load(f)
    except Exception as e:
        log(f"Error loading settings: {e}")
    return {"focus_domains": DEFAULT_FOCUS_DOMAINS}


def save_settings(settings):
    """Save user settings to file."""
    try:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        log(f"Error saving settings: {e}")


def get_focus_domains():
    """Get the list of domains to block in focus mode."""
    settings = load_settings()
    return settings.get("focus_domains", DEFAULT_FOCUS_DOMAINS)


def set_focus_domains(domains):
    """Set the list of domains to block in focus mode."""
    settings = load_settings()
    settings["focus_domains"] = domains
    save_settings(settings)


# --- Focus Mode Functions ---

def resolve_domain_ips(domain):
    """Resolve a domain to its IP addresses using external DNS."""
    ips = set()
    try:
        result = subprocess.run(
            ["nslookup", domain, EXTERNAL_DNS],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            if "Address" in line and EXTERNAL_DNS not in line and "#" not in line:
                parts = line.split()
                for part in parts:
                    if part.count(".") == 3 and all(p.isdigit() for p in part.split(".")):
                        ips.add(part)
    except Exception as e:
        log(f"Error resolving {domain}: {e}")
    return ips


def enable_focus_mode(duration_minutes):
    """Enable focus mode - block distracting sites via DNS and IP."""
    global focus_mode_active, focus_mode_expiry, focus_mode_blocked_ips

    domains = get_focus_domains()
    log(f"Enabling focus mode for {duration_minutes} minutes, blocking {len(domains)} domains...")

    focus_mode_active = True
    focus_mode_expiry = time.time() + (duration_minutes * 60)
    focus_mode_blocked_ips = set()

    # Block each domain via DNS (dnsmasq) and collect IPs for firewall
    for domain in domains:
        # Add DNS block (resolve to 0.0.0.0)
        subprocess.run(["uci", "add_list", f"dhcp.@dnsmasq[0].address=/{domain}/0.0.0.0"], check=False)

        # Resolve and block IPs
        ips = resolve_domain_ips(domain)
        focus_mode_blocked_ips.update(ips)

    # Commit DNS changes
    subprocess.run(["uci", "commit", "dhcp"], check=False)
    subprocess.run(["/etc/init.d/dnsmasq", "restart"], check=False)

    # Block IPs in firewall
    for ip in focus_mode_blocked_ips:
        subprocess.run(["iptables", "-I", "FORWARD", "1", "-d", ip, "-j", "REJECT"], check=False)

    log(f"Focus mode enabled, blocked {len(focus_mode_blocked_ips)} IPs")

    # Log to permanent history
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "focus_mode",
        "duration": duration_minutes,
        "domains_blocked": len(domains)
    }
    check_and_trim_log()
    save_to_permanent_log(entry)

    return True


def disable_focus_mode():
    """Disable focus mode - unblock sites."""
    global focus_mode_active, focus_mode_expiry, focus_mode_blocked_ips

    if not focus_mode_active:
        return

    log("Disabling focus mode...")

    domains = get_focus_domains()

    # Remove DNS blocks
    for domain in domains:
        subprocess.run(["uci", "del_list", f"dhcp.@dnsmasq[0].address=/{domain}/0.0.0.0"],
                      capture_output=True, check=False)

    # Commit DNS changes
    subprocess.run(["uci", "commit", "dhcp"], check=False)
    subprocess.run(["/etc/init.d/dnsmasq", "restart"], check=False)

    # Remove IP blocks from firewall
    for ip in focus_mode_blocked_ips:
        subprocess.run(["iptables", "-D", "FORWARD", "-d", ip, "-j", "REJECT"],
                      capture_output=True, check=False)

    focus_mode_active = False
    focus_mode_expiry = None
    focus_mode_blocked_ips = set()

    log("Focus mode disabled")


def check_focus_mode_expiry():
    """Check if focus mode has expired."""
    global focus_mode_expiry
    if focus_mode_active and focus_mode_expiry and time.time() > focus_mode_expiry:
        log("Focus mode has expired!")
        disable_focus_mode()


# --- Voluntary Lockdown Functions ---

def enable_voluntary_lockdown(duration_minutes, reason, exceptions):
    """Enable voluntary lockdown - user-initiated internet block during daytime."""
    global voluntary_lockdown_active, voluntary_lockdown_expiry
    global voluntary_lockdown_reason, voluntary_lockdown_exceptions

    log(f"Enabling voluntary lockdown for {duration_minutes} minutes. Reason: {reason}")

    voluntary_lockdown_active = True
    voluntary_lockdown_expiry = time.time() + (duration_minutes * 60)
    voluntary_lockdown_reason = reason
    voluntary_lockdown_exceptions = exceptions

    # Set up firewall rules (same as gatekeeper mode but during daytime)
    setup_firewall()

    log(f"Voluntary lockdown enabled until {datetime.fromtimestamp(voluntary_lockdown_expiry).strftime('%H:%M')}")

    # Log to permanent history
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "voluntary_lockdown",
        "duration": duration_minutes,
        "reason": reason[:200]
    }
    check_and_trim_log()
    save_to_permanent_log(entry)

    return True


def disable_voluntary_lockdown():
    """Disable voluntary lockdown."""
    global voluntary_lockdown_active, voluntary_lockdown_expiry
    global voluntary_lockdown_reason, voluntary_lockdown_exceptions

    if not voluntary_lockdown_active:
        return

    log("Disabling voluntary lockdown...")

    teardown_firewall()

    voluntary_lockdown_active = False
    voluntary_lockdown_expiry = None
    voluntary_lockdown_reason = None
    voluntary_lockdown_exceptions = []

    log("Voluntary lockdown disabled")


def check_voluntary_lockdown_expiry():
    """Check if voluntary lockdown has expired."""
    if voluntary_lockdown_active and voluntary_lockdown_expiry and time.time() > voluntary_lockdown_expiry:
        log("Voluntary lockdown has expired!")
        disable_voluntary_lockdown()


def get_minutes_until_daytime_end():
    """Get minutes until 9pm (end of daytime)."""
    now = datetime.now()
    end_of_daytime = now.replace(hour=21, minute=0, second=0, microsecond=0)
    if now >= end_of_daytime:
        return 0
    return int((end_of_daytime - now).total_seconds() / 60)


def get_status():
    """Get current system status."""
    return {
        "is_nighttime": is_nighttime(),
        "focus_mode_active": focus_mode_active,
        "focus_mode_expiry": focus_mode_expiry,
        "voluntary_lockdown_active": voluntary_lockdown_active,
        "voluntary_lockdown_expiry": voluntary_lockdown_expiry,
        "voluntary_lockdown_reason": voluntary_lockdown_reason,
        "network_access_expiry": network_access_expiry,
        "minutes_until_daytime_end": get_minutes_until_daytime_end()
    }


def get_stats():
    """Calculate statistics from permanent log."""
    entries = load_permanent_log()

    # Separate by type
    nighttime_entries = [e for e in entries if e.get("status") in ("approved", "denied")]
    focus_entries = [e for e in entries if e.get("type") == "focus_mode"]
    lockdown_entries = [e for e in entries if e.get("type") == "voluntary_lockdown"]

    # Nighttime stats
    approved_entries = [e for e in nighttime_entries if e.get("status") == "approved"]
    denied_entries = [e for e in nighttime_entries if e.get("status") == "denied"]
    total_approved = len(approved_entries)
    total_denied = len(denied_entries)
    total_minutes = sum(e.get("duration", 0) for e in approved_entries)

    # Focus mode stats
    total_focus = len(focus_entries)
    total_focus_minutes = sum(e.get("duration", 0) for e in focus_entries)

    # Voluntary lockdown stats
    total_lockdown = len(lockdown_entries)
    total_lockdown_minutes = sum(e.get("duration", 0) for e in lockdown_entries)

    # Recent entries (last 20)
    recent = entries[-20:] if entries else []
    recent.reverse()  # Most recent first

    # Time distribution data for nighttime chart (9pm-5am)
    time_distribution_approved = []
    time_distribution_denied = []
    for entry in nighttime_entries:
        try:
            ts = datetime.strptime(entry.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
            hour = ts.hour + ts.minute / 60.0  # Decimal hour
            duration = entry.get("duration", 10)
            point = {"hour": hour, "duration": duration}
            if entry.get("status") == "approved":
                time_distribution_approved.append(point)
            else:
                time_distribution_denied.append(point)
        except (ValueError, TypeError):
            pass

    # Weekday distribution for nighttime
    weekday_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    weekday_approved = [0] * 7
    weekday_denied = [0] * 7
    for entry in nighttime_entries:
        try:
            ts = datetime.strptime(entry.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
            weekday = ts.weekday()  # 0=Monday, 6=Sunday
            if entry.get("status") == "approved":
                weekday_approved[weekday] += 1
            else:
                weekday_denied[weekday] += 1
        except (ValueError, TypeError):
            pass

    # Time distribution for daytime modes (5am-9pm)
    time_distribution_focus = []
    for entry in focus_entries:
        try:
            ts = datetime.strptime(entry.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
            hour = ts.hour + ts.minute / 60.0
            duration = entry.get("duration", 30)
            time_distribution_focus.append({"hour": hour, "duration": duration})
        except (ValueError, TypeError):
            pass

    time_distribution_lockdown = []
    for entry in lockdown_entries:
        try:
            ts = datetime.strptime(entry.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
            hour = ts.hour + ts.minute / 60.0
            duration = entry.get("duration", 30)
            time_distribution_lockdown.append({"hour": hour, "duration": duration})
        except (ValueError, TypeError):
            pass

    # Weekday distribution for daytime modes
    weekday_focus = [0] * 7
    weekday_lockdown = [0] * 7
    for entry in focus_entries:
        try:
            ts = datetime.strptime(entry.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
            weekday_focus[ts.weekday()] += 1
        except (ValueError, TypeError):
            pass
    for entry in lockdown_entries:
        try:
            ts = datetime.strptime(entry.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
            weekday_lockdown[ts.weekday()] += 1
        except (ValueError, TypeError):
            pass

    return {
        # Nighttime stats
        "total_approved": total_approved,
        "total_denied": total_denied,
        "total_minutes": total_minutes,
        "time_distribution_approved": time_distribution_approved,
        "time_distribution_denied": time_distribution_denied,
        "weekday_approved": weekday_approved,
        "weekday_denied": weekday_denied,
        # Daytime stats
        "total_focus": total_focus,
        "total_focus_minutes": total_focus_minutes,
        "total_lockdown": total_lockdown,
        "total_lockdown_minutes": total_lockdown_minutes,
        "time_distribution_focus": time_distribution_focus,
        "time_distribution_lockdown": time_distribution_lockdown,
        "weekday_focus": weekday_focus,
        "weekday_lockdown": weekday_lockdown,
        # Common
        "recent": recent,
        "weekday_names": weekday_names
    }


# --- End Permanent Log Functions ---


def get_request_history_for_context():
    """Get formatted request history for LLM context."""
    requests = load_request_log()
    if not requests:
        return ""

    history_text = "\n\n## Previous requests tonight:\n"
    for req in requests[-10:]:  # Last 10 requests
        status_emoji = "✓" if req["status"] == "approved" else "✗"
        duration_str = f" ({req.get('duration', '?')} min)" if req["status"] == "approved" else ""
        history_text += f"- [{req['timestamp']}] {status_emoji} {req['reason'][:50]}...{duration_str}\n"

    return history_text

SYSTEM_PROMPT = """You are a loving, caring gatekeeper helping manage internet access during nighttime hours (9pm-5am).

Think of yourself as a warm, supportive parent who genuinely cares about the person's wellbeing. You want them to get good sleep because you know how important rest is for their health, happiness, and success. At the same time, you understand that sometimes life has urgent demands that can't wait.

## Your tone:
- Warm and kind, like a loving parent
- Express genuine care ("I want to make sure you get enough rest tonight")
- Be encouraging ("I know you can handle this!" or "That sounds important, let me help")
- Acknowledge their feelings ("I understand this feels urgent")
- But maintain firm, clear boundaries - sleep matters!

## Access Rules:
- 10 minutes: Quick check that can't wait, would cause stress if delayed
- Up to 60 minutes: Work tasks, school assignments that must be done TODAY
- Up to 120 minutes: Video calls, Zoom meetings, voice calls

## Your behavior:
1. ALWAYS ask how much time they need (in minutes) - warmly, not like an interrogation
2. If they request MORE than 10 minutes:
   a. Kindly ask them to explain why they need that specific amount
   b. Gently request proof (screenshot, email, document, calendar invite)
   c. When they upload an image, review it thoughtfully
3. You may ask up to 3 clarifying questions total
4. Most things CAN wait until morning - and that's actually better for them!
5. Mindless browsing, social media, entertainment = DENY (with love and care)
6. Legitimate work/emergency = APPROVE with appropriate duration

## Proof verification (for requests >10 minutes):
- When the user uploads an image, analyze it carefully
- Check if the image actually supports their stated reason
- Look for: email subject/content, due dates, calendar invites, assignment details
- Be thoughtful about generic or irrelevant images
- If the image doesn't match their claim, kindly explain why you can't approve
- If no proof is provided for >10 minutes, ask warmly: "Could you share a screenshot? An email, calendar invite, or assignment would help me understand the urgency."

## Consider timing patterns:
- Look at previous requests from tonight (shown in context)
- If someone has already been on multiple times, be extra gentle but firm
- Acknowledge patterns: "I see you've been up working tonight - I hope you can rest soon!"

## Response format:
If you need clarification or proof, respond with:
{"status": "question", "message": "Your warm, caring question"}

If you're ready to decide, respond with:
{"status": "approved", "duration": <minutes>, "message": "Warm approval with encouragement"}
or
{"status": "denied", "message": "Kind, caring explanation of why rest is better right now"}

Example denial tone: "I know it feels important right now, but this can wait until morning. Your sleep tonight will help you tackle it better tomorrow. Sweet dreams!"

Example approval tone: "I understand - that deadline is real and you need to get this done. Here's 45 minutes. I'm proud of you for being responsible about your work. Try to rest after!"

IMPORTANT: Always respond with valid JSON only. No markdown, no extra text."""

SPLASH_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Open Sesame</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    color: #e4e4e4;
}
.container {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(10px);
    border-radius: 20px;
    padding: 30px;
    max-width: 500px;
    width: 100%;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.1);
}
.header { text-align: center; margin-bottom: 25px; position: relative; }
.header h1 { font-size: 1.5rem; margin-bottom: 8px; color: #fff; }
.stats-link {
    position: absolute;
    top: 0;
    right: 0;
    font-size: 0.8rem;
    color: #a0a0a0;
    text-decoration: none;
    padding: 5px 10px;
    border-radius: 8px;
    background: rgba(255, 255, 255, 0.05);
    transition: background 0.2s;
}
.stats-link:hover { background: rgba(255, 255, 255, 0.1); color: #fff; }
.time-badge {
    display: inline-block;
    background: rgba(255, 107, 107, 0.2);
    color: #ff6b6b;
    padding: 5px 15px;
    border-radius: 20px;
    font-size: 0.85rem;
}
.header p { margin-top: 15px; font-size: 0.95rem; color: #a0a0a0; line-height: 1.5; }
.chat-container {
    background: rgba(0, 0, 0, 0.2);
    border-radius: 15px;
    padding: 15px;
    margin-bottom: 20px;
    max-height: 300px;
    overflow-y: auto;
}
.message {
    margin-bottom: 12px;
    padding: 12px 15px;
    border-radius: 12px;
    max-width: 85%;
    line-height: 1.4;
}
.message.user { background: #4a69bd; margin-left: auto; border-bottom-right-radius: 4px; }
.message.assistant { background: rgba(255, 255, 255, 0.1); margin-right: auto; border-bottom-left-radius: 4px; }
.message.system { background: rgba(255, 193, 7, 0.15); color: #ffc107; text-align: center; max-width: 100%; font-size: 0.9rem; }
.message.approved { background: rgba(46, 213, 115, 0.15); color: #2ed573; text-align: center; max-width: 100%; }
.message.denied { background: rgba(255, 107, 107, 0.15); color: #ff6b6b; text-align: center; max-width: 100%; }
.input-area { display: flex; gap: 10px; }
textarea {
    flex: 1;
    padding: 15px;
    border: none;
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.1);
    color: #fff;
    font-size: 1rem;
    resize: none;
    height: 60px;
    font-family: inherit;
}
textarea:focus { outline: 2px solid #4a69bd; }
textarea::placeholder { color: #666; }
button {
    padding: 15px 25px;
    border: none;
    border-radius: 12px;
    background: #4a69bd;
    color: #fff;
    font-size: 1rem;
    cursor: pointer;
    font-weight: 500;
}
button:hover:not(:disabled) { background: #3c5aa6; }
button:disabled { opacity: 0.5; cursor: not-allowed; }
.loading { display: none; text-align: center; padding: 15px; }
.loading.active { display: block; }
.spinner {
    width: 30px; height: 30px;
    border: 3px solid rgba(255, 255, 255, 0.1);
    border-top-color: #4a69bd;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin: 0 auto 10px;
}
@keyframes spin { to { transform: rotate(360deg); } }
.rules {
    background: rgba(255, 255, 255, 0.05);
    border-radius: 10px;
    padding: 15px;
    margin-bottom: 20px;
    font-size: 0.85rem;
}
.rules h3 { margin-bottom: 10px; font-size: 0.9rem; color: #a0a0a0; }
.rules ul { list-style: none; padding-left: 0; }
.rules li { padding: 5px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }
.rules li:last-child { border-bottom: none; }
.rules .duration { color: #4a69bd; font-weight: 500; }
.hidden { display: none; }
.image-upload {
    margin-top: 10px;
    padding: 10px;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 10px;
}
.image-upload label {
    display: flex;
    align-items: center;
    gap: 10px;
    cursor: pointer;
    color: #a0a0a0;
    font-size: 0.9rem;
}
.image-upload input[type="file"] {
    display: none;
}
.upload-btn {
    padding: 8px 15px;
    background: rgba(74, 105, 189, 0.3);
    border: 1px dashed #4a69bd;
    border-radius: 8px;
    color: #4a69bd;
    font-size: 0.85rem;
}
.image-preview {
    margin-top: 10px;
    max-height: 150px;
    overflow: hidden;
    border-radius: 8px;
    display: none;
}
.image-preview.active {
    display: block;
}
.image-preview img {
    max-width: 100%;
    max-height: 150px;
    border-radius: 8px;
}
.image-preview .remove-btn {
    display: inline-block;
    margin-top: 5px;
    padding: 5px 10px;
    background: rgba(255, 107, 107, 0.2);
    color: #ff6b6b;
    border: none;
    border-radius: 5px;
    font-size: 0.8rem;
    cursor: pointer;
}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <a href="/stats" class="stats-link">Stats</a>
        <h1>Open Sesame</h1>
        <span class="time-badge" id="currentTime"></span>
        <p>It's late. Please explain why you need internet access right now.</p>
    </div>
    <div class="rules">
        <h3>Access Guidelines</h3>
        <ul>
            <li><span class="duration">10 min</span> - Quick check that can't wait</li>
            <li><span class="duration">60 min</span> - Work/school tasks due TODAY</li>
            <li><span class="duration">120 min</span> - Video calls, meetings</li>
        </ul>
    </div>
    <div class="chat-container" id="chatContainer">
        <div class="message assistant" id="initialMessage">
            Hey there! It's getting late and I want to make sure you get good rest tonight. What brings you here - is there something that really can't wait until morning?
        </div>
    </div>
    <div class="loading" id="loading">
        <div class="spinner"></div>
        <span>Evaluating your request...</span>
    </div>
    <div class="input-area" id="inputArea">
        <textarea id="userInput" placeholder="Explain why you need internet access..."></textarea>
        <button type="button" id="sendBtn">Send</button>
    </div>
    <div class="image-upload" id="imageUpload">
        <label id="uploadLabel">
            <span class="upload-btn">📷 Attach Proof</span>
            <span>Screenshot, email, document</span>
            <input type="file" id="imageInput" accept="image/*">
        </label>
        <div class="image-preview" id="imagePreview">
            <img id="previewImg" src="" alt="Preview">
            <button type="button" class="remove-btn" id="removeImage">Remove</button>
        </div>
    </div>
</div>
<script>
var sessionId = null;
var pendingImage = null;

function updateTime() {
    var now = new Date();
    var h = now.getHours(), m = now.getMinutes();
    var ampm = h >= 12 ? 'PM' : 'AM';
    var h12 = h % 12 || 12;
    var timeStr = h12 + ':' + (m<10?'0':'') + m + ' ' + ampm;
    document.getElementById('currentTime').textContent = timeStr;

    // Update initial message with actual time
    var initialMsg = document.getElementById('initialMessage');
    if (initialMsg) {
        initialMsg.textContent = "Hey there! It's " + timeStr + " - getting late! I want to make sure you get good rest tonight. What brings you here - is there something that really can't wait until morning?";
    }
}
updateTime();
setInterval(updateTime, 60000);

function addMessage(content, type, isImage) {
    var container = document.getElementById('chatContainer');
    var msg = document.createElement('div');
    msg.className = 'message ' + type;
    if (isImage) {
        var img = document.createElement('img');
        img.src = content;
        img.style.maxWidth = '100%';
        img.style.maxHeight = '150px';
        img.style.borderRadius = '8px';
        msg.appendChild(img);
    } else {
        msg.textContent = content;
    }
    container.appendChild(msg);
    container.scrollTop = container.scrollHeight;
}

function setLoading(active) {
    document.getElementById('loading').className = active ? 'loading active' : 'loading';
    document.getElementById('inputArea').className = active ? 'input-area hidden' : 'input-area';
    document.getElementById('imageUpload').className = active ? 'image-upload hidden' : 'image-upload';
}

function disableInput() {
    document.getElementById('inputArea').className = 'input-area hidden';
    document.getElementById('imageUpload').className = 'image-upload hidden';
}

// Image handling
document.getElementById('imageInput').onchange = function(e) {
    var file = e.target.files[0];
    if (!file) return;

    var reader = new FileReader();
    reader.onload = function(ev) {
        pendingImage = ev.target.result;
        document.getElementById('previewImg').src = pendingImage;
        document.getElementById('imagePreview').className = 'image-preview active';
    };
    reader.readAsDataURL(file);
};

document.getElementById('removeImage').onclick = function() {
    pendingImage = null;
    document.getElementById('imageInput').value = '';
    document.getElementById('imagePreview').className = 'image-preview';
};

function sendMessage() {
    var input = document.getElementById('userInput');
    var message = input.value.trim();

    // Allow sending just an image without text
    if (!message && !pendingImage) return;

    if (message) {
        addMessage(message, 'user');
    }
    if (pendingImage) {
        addMessage(pendingImage, 'user', true);
    }

    input.value = '';
    setLoading(true);

    var payload = {
        session_id: sessionId,
        message: message || '(Image attached)'
    };

    if (pendingImage) {
        payload.image = pendingImage;
    }

    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/chat', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            setLoading(false);
            // Clear pending image after send
            pendingImage = null;
            document.getElementById('imageInput').value = '';
            document.getElementById('imagePreview').className = 'image-preview';

            try {
                var data = JSON.parse(xhr.responseText);
                if (data.session_id) sessionId = data.session_id;

                if (data.status === 'question') {
                    addMessage(data.message, 'assistant');
                } else if (data.status === 'approved') {
                    var expiry = new Date(Date.now() + data.duration * 60000);
                    var expiryStr = expiry.toLocaleTimeString('en-US', {hour: '2-digit', minute: '2-digit'});
                    addMessage('Access Granted for ' + data.duration + ' minutes!', 'approved');
                    addMessage(data.message, 'assistant');
                    addMessage('Internet access expires at ' + expiryStr, 'system');
                    disableInput();
                    // Redirect to stats page on the WAN side
                    setTimeout(function() {
                        window.location.href = 'http://192.168.0.2:2050/stats';
                    }, 2000);
                } else if (data.status === 'denied') {
                    addMessage('Access Denied', 'denied');
                    addMessage(data.message, 'assistant');
                    addMessage('Try again in the morning, or with a different reason.', 'system');
                } else if (data.status === 'error') {
                    addMessage('Error: ' + data.message, 'system');
                }
            } catch(e) {
                addMessage('Connection error. Please try again.', 'system');
            }
        }
    };
    xhr.onerror = function() {
        setLoading(false);
        addMessage('Network error. Please try again.', 'system');
    };
    xhr.send(JSON.stringify(payload));
}

document.getElementById('sendBtn').onclick = sendMessage;
document.getElementById('userInput').onkeydown = function(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
};
</script>
</body>
</html>"""

STATS_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Open Sesame - Stats</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: {bg_gradient};
    min-height: 100vh;
    padding: 20px;
    color: {text_color};
}}
.container {{
    max-width: 800px;
    margin: 0 auto;
}}
.header {{
    text-align: center;
    margin-bottom: 30px;
}}
.header h1 {{ font-size: 1.8rem; color: {heading_color}; margin-bottom: 10px; }}
.header p {{ color: {muted_color}; }}
.back-link {{
    display: inline-block;
    margin-bottom: 20px;
    color: {accent_color};
    text-decoration: none;
    font-size: 0.9rem;
}}
.back-link:hover {{ text-decoration: underline; }}
.stats-cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 15px;
    margin-bottom: 30px;
}}
.stat-card {{
    background: {card_bg};
    backdrop-filter: blur(10px);
    border-radius: 15px;
    padding: 20px;
    text-align: center;
    border: 1px solid {border_color};
}}
.stat-card .number {{
    font-size: 2rem;
    font-weight: 700;
    color: {accent_color};
    margin-bottom: 5px;
}}
.stat-card .label {{
    font-size: 0.8rem;
    color: {muted_color};
}}
.chart-section {{
    background: {card_bg};
    backdrop-filter: blur(10px);
    border-radius: 15px;
    padding: 25px;
    margin-bottom: 30px;
    border: 1px solid {border_color};
}}
.chart-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}}
.chart-section h2 {{
    font-size: 1.2rem;
    color: {heading_color};
    margin: 0;
}}
.tab-buttons {{
    display: flex;
    gap: 5px;
}}
.tab-btn {{
    padding: 6px 12px;
    border: none;
    border-radius: 8px;
    background: {chart_bg};
    color: {muted_color};
    font-size: 0.8rem;
    cursor: pointer;
    transition: all 0.2s;
}}
.tab-btn:hover {{
    background: {border_color};
}}
.tab-btn.active {{
    background: {accent_color};
    color: #fff;
}}
.chart-container {{
    position: relative;
    width: 100%;
    height: 250px;
    background: {chart_bg};
    border-radius: 10px;
    padding: 40px 50px 40px 60px;
}}
.chart-panel {{
    display: none;
}}
.chart-panel.active {{
    display: block;
}}
.chart-svg {{
    width: 100%;
    height: 100%;
}}
.axis-label {{
    fill: {muted_color};
    font-size: 11px;
}}
.axis-title {{
    fill: {muted_color};
    font-size: 12px;
}}
.grid-line {{
    stroke: {grid_color};
    stroke-width: 1;
}}
.data-point {{
    opacity: 0.7;
}}
.data-point.approved {{
    fill: {accent_color};
}}
.data-point.denied {{
    fill: #ff6b6b;
}}
.data-point.focus {{
    fill: #f39c12;
}}
.data-point.lockdown {{
    fill: #9b59b6;
}}
.data-point:hover {{
    opacity: 1;
    filter: brightness(1.2);
}}
.bar {{
    opacity: 0.8;
}}
.bar.approved {{
    fill: {accent_color};
}}
.bar.denied {{
    fill: #ff6b6b;
}}
.bar.focus {{
    fill: #f39c12;
}}
.bar.lockdown {{
    fill: #9b59b6;
}}
.bar:hover {{
    opacity: 1;
}}
.recent-section {{
    background: {card_bg};
    backdrop-filter: blur(10px);
    border-radius: 15px;
    padding: 25px;
    border: 1px solid {border_color};
}}
.recent-section h2 {{
    font-size: 1.2rem;
    margin-bottom: 20px;
    color: {heading_color};
}}
.history-table {{
    width: 100%;
    border-collapse: collapse;
}}
.history-table th,
.history-table td {{
    padding: 12px 10px;
    text-align: left;
    border-bottom: 1px solid {border_color};
}}
.history-table th {{
    color: {muted_color};
    font-weight: 500;
    font-size: 0.85rem;
}}
.history-table td {{
    font-size: 0.9rem;
}}
.history-table tr:last-child td {{
    border-bottom: none;
}}
.reason-cell {{
    max-width: 300px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}}
.duration-badge {{
    display: inline-block;
    padding: 4px 10px;
    border-radius: 10px;
    font-size: 0.85rem;
}}
.duration-badge.approved {{
    background: rgba(74, 105, 189, 0.2);
    color: #4a69bd;
}}
.duration-badge.denied {{
    background: rgba(255, 107, 107, 0.2);
    color: #ff6b6b;
}}
.duration-badge.focus_mode {{
    background: rgba(243, 156, 18, 0.2);
    color: #f39c12;
}}
.duration-badge.voluntary_lockdown {{
    background: rgba(155, 89, 182, 0.2);
    color: #9b59b6;
}}
.stat-card .number.denied {{
    color: #ff6b6b;
}}
.stat-card .number.focus {{
    color: #f39c12;
}}
.stat-card .number.lockdown {{
    color: #9b59b6;
}}
.empty-state {{
    text-align: center;
    padding: 40px;
    color: {muted_color};
}}
@media (max-width: 600px) {{
    .history-table th:nth-child(2),
    .history-table td:nth-child(2) {{
        display: none;
    }}
    .reason-cell {{
        max-width: 150px;
    }}
    .chart-container {{
        padding: 30px 40px 30px 50px;
    }}
    .chart-header {{
        flex-direction: column;
        gap: 10px;
        align-items: flex-start;
    }}
    .stats-cards {{
        grid-template-columns: repeat(3, 1fr);
    }}
}}
</style>
</head>
<body>
<div class="container">
    <a href="/" class="back-link">&larr; Back to Portal</a>
    <div class="header">
        <h1>Open Sesame Stats</h1>
        <p>Activity history across all sessions</p>
    </div>
    <div class="stats-cards">
        <div class="stat-card">
            <div class="number">{total_approved}</div>
            <div class="label">Approved</div>
        </div>
        <div class="stat-card">
            <div class="number denied">{total_denied}</div>
            <div class="label">Denied</div>
        </div>
        <div class="stat-card">
            <div class="number">{total_hours}</div>
            <div class="label">Night Hours</div>
        </div>
        <div class="stat-card">
            <div class="number focus">{total_focus}</div>
            <div class="label">Focus Sessions</div>
        </div>
        <div class="stat-card">
            <div class="number lockdown">{total_lockdown}</div>
            <div class="label">Lockdowns</div>
        </div>
        <div class="stat-card">
            <div class="number">{total_daytime_hours}</div>
            <div class="label">Day Hours</div>
        </div>
    </div>
    <div class="chart-section">
        <div class="chart-header">
            <h2>Time Distribution</h2>
            <div class="tab-buttons">
                <button class="tab-btn active" onclick="showTimeTab('night')">Night</button>
                <button class="tab-btn" onclick="showTimeTab('day')">Day</button>
            </div>
        </div>
        <div id="time-night" class="chart-panel active">
            <div class="chart-container">
                {time_chart_night}
            </div>
        </div>
        <div id="time-day" class="chart-panel">
            <div class="chart-container">
                {time_chart_day}
            </div>
        </div>
    </div>
    <div class="chart-section">
        <div class="chart-header">
            <h2>Requests by Weekday</h2>
            <div class="tab-buttons">
                <button class="tab-btn active" onclick="showWeekdayTab('night')">Night</button>
                <button class="tab-btn" onclick="showWeekdayTab('day')">Day</button>
            </div>
        </div>
        <div id="weekday-night" class="chart-panel active">
            <div class="chart-container" style="height: 200px;">
                {weekday_chart_night}
            </div>
        </div>
        <div id="weekday-day" class="chart-panel">
            <div class="chart-container" style="height: 200px;">
                {weekday_chart_day}
            </div>
        </div>
    </div>
    <div class="recent-section">
        <h2>Recent Activity</h2>
        {history_table}
    </div>
</div>
<script>
function showTimeTab(tab) {{
    document.querySelectorAll('#time-night, #time-day').forEach(function(el) {{
        el.classList.remove('active');
    }});
    document.getElementById('time-' + tab).classList.add('active');
    var btns = document.querySelectorAll('.chart-section:nth-of-type(1) .tab-btn');
    btns.forEach(function(btn) {{ btn.classList.remove('active'); }});
    event.target.classList.add('active');
}}
function showWeekdayTab(tab) {{
    document.querySelectorAll('#weekday-night, #weekday-day').forEach(function(el) {{
        el.classList.remove('active');
    }});
    document.getElementById('weekday-' + tab).classList.add('active');
    var btns = document.querySelectorAll('.chart-section:nth-of-type(2) .tab-btn');
    btns.forEach(function(btn) {{ btn.classList.remove('active'); }});
    event.target.classList.add('active');
}}
</script>
</body>
</html>"""

DAYTIME_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Open Sesame - Daytime</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: linear-gradient(135deg, #fef9e7 0%, #fdeaa8 50%, #f6d365 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    color: #2d3436;
}
.container {
    background: rgba(255, 255, 255, 0.85);
    backdrop-filter: blur(10px);
    border-radius: 20px;
    padding: 30px;
    max-width: 500px;
    width: 100%;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.5);
}
.header { text-align: center; margin-bottom: 25px; position: relative; }
.header h1 { font-size: 1.5rem; margin-bottom: 8px; color: #d35400; }
.nav-links {
    position: absolute;
    top: 0;
    right: 0;
    display: flex;
    gap: 8px;
}
.nav-link {
    font-size: 0.8rem;
    color: #7f8c8d;
    text-decoration: none;
    padding: 5px 10px;
    border-radius: 8px;
    background: rgba(0, 0, 0, 0.05);
    transition: background 0.2s;
}
.nav-link:hover { background: rgba(0, 0, 0, 0.1); color: #2d3436; }
.time-badge {
    display: inline-block;
    background: rgba(243, 156, 18, 0.2);
    color: #d35400;
    padding: 5px 15px;
    border-radius: 20px;
    font-size: 0.85rem;
}
.header p { margin-top: 15px; font-size: 0.95rem; color: #7f8c8d; line-height: 1.5; }
.mode-buttons {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 15px;
    margin-bottom: 20px;
}
.mode-btn {
    padding: 20px 15px;
    border: none;
    border-radius: 12px;
    background: rgba(0, 0, 0, 0.03);
    color: #2d3436;
    font-size: 0.9rem;
    cursor: pointer;
    border: 1px solid rgba(0, 0, 0, 0.1);
    transition: all 0.2s;
    text-align: center;
}
.mode-btn:hover { background: rgba(0, 0, 0, 0.06); }
.mode-btn.active { border-color: #d35400; background: rgba(211, 84, 0, 0.1); }
.mode-btn .icon { font-size: 1.5rem; display: block; margin-bottom: 8px; }
.mode-btn .label { font-weight: 500; }
.mode-btn.lockdown { border-color: rgba(192, 57, 43, 0.3); }
.mode-btn.lockdown:hover { background: rgba(192, 57, 43, 0.1); }
.mode-btn.focus { border-color: rgba(243, 156, 18, 0.5); }
.mode-btn.focus:hover { background: rgba(243, 156, 18, 0.15); }
.chat-container {
    background: rgba(0, 0, 0, 0.03);
    border-radius: 15px;
    padding: 15px;
    margin-bottom: 20px;
    max-height: 250px;
    overflow-y: auto;
}
.message {
    margin-bottom: 12px;
    padding: 12px 15px;
    border-radius: 12px;
    max-width: 85%;
    line-height: 1.4;
}
.message.user { background: #d35400; color: #fff; margin-left: auto; border-bottom-right-radius: 4px; }
.message.assistant { background: rgba(0, 0, 0, 0.05); color: #2d3436; margin-right: auto; border-bottom-left-radius: 4px; }
.message.system { background: rgba(243, 156, 18, 0.2); color: #b7791f; text-align: center; max-width: 100%; font-size: 0.9rem; }
.message.success { background: rgba(39, 174, 96, 0.2); color: #1e8449; text-align: center; max-width: 100%; }
.input-area { display: flex; gap: 10px; }
textarea {
    flex: 1;
    padding: 15px;
    border: none;
    border-radius: 12px;
    background: rgba(0, 0, 0, 0.05);
    color: #2d3436;
    font-size: 1rem;
    resize: none;
    height: 60px;
    font-family: inherit;
}
textarea:focus { outline: 2px solid #d35400; }
textarea::placeholder { color: #95a5a6; }
button {
    padding: 15px 25px;
    border: none;
    border-radius: 12px;
    background: #d35400;
    color: #fff;
    font-size: 1rem;
    cursor: pointer;
    font-weight: 500;
}
button:hover:not(:disabled) { background: #e67e22; }
button:disabled { opacity: 0.5; cursor: not-allowed; }
.loading { display: none; text-align: center; padding: 15px; color: #7f8c8d; }
.loading.active { display: block; }
.spinner {
    width: 30px; height: 30px;
    border: 3px solid rgba(0, 0, 0, 0.1);
    border-top-color: #d35400;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin: 0 auto 10px;
}
@keyframes spin { to { transform: rotate(360deg); } }
.hidden { display: none; }
.form-group { margin-bottom: 15px; }
.form-group label { display: block; margin-bottom: 8px; color: #7f8c8d; font-size: 0.9rem; }
.form-group input, .form-group select {
    width: 100%;
    padding: 12px;
    border: none;
    border-radius: 8px;
    background: rgba(0, 0, 0, 0.05);
    color: #2d3436;
    font-size: 1rem;
}
.form-group input:focus, .form-group select:focus { outline: 2px solid #d35400; }
.modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); align-items: center; justify-content: center; z-index: 100; }
.modal.active { display: flex; }
.modal-content {
    background: linear-gradient(135deg, #fff 0%, #fef9e7 100%);
    border-radius: 20px;
    padding: 30px;
    max-width: 450px;
    width: 90%;
    border: 1px solid rgba(0, 0, 0, 0.1);
    color: #2d3436;
}
.modal-header { margin-bottom: 20px; }
.modal-header h2 { font-size: 1.3rem; color: #2d3436; }
.btn-row { display: flex; gap: 10px; margin-top: 20px; }
.btn-row button { flex: 1; }
.btn-cancel { background: rgba(0, 0, 0, 0.08); color: #2d3436; }
.btn-cancel:hover { background: rgba(0, 0, 0, 0.12); }
.status-banner {
    background: rgba(243, 156, 18, 0.15);
    border: 1px solid rgba(243, 156, 18, 0.4);
    border-radius: 10px;
    padding: 15px;
    margin-bottom: 20px;
    text-align: center;
}
.status-banner.focus { background: rgba(243, 156, 18, 0.15); border-color: rgba(243, 156, 18, 0.4); }
.status-banner.lockdown { background: rgba(192, 57, 43, 0.1); border-color: rgba(192, 57, 43, 0.3); }
.status-banner .title { font-weight: 600; margin-bottom: 5px; color: #2d3436; }
.status-banner .time { font-size: 0.9rem; color: #7f8c8d; }
.status-banner button { margin-top: 10px; padding: 8px 20px; font-size: 0.85rem; }
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="nav-links">
            <a href="/stats" class="nav-link">Stats</a>
            <a href="/settings" class="nav-link">Settings</a>
        </div>
        <h1>Open Sesame</h1>
        <span class="time-badge" id="currentTime"></span>
        <p>Daytime mode - internet is open</p>
    </div>

    <div id="statusBanner" class="status-banner hidden"></div>

    <div class="mode-buttons" id="modeButtons">
        <button class="mode-btn focus" onclick="showFocusModal()">
            <span class="icon">🎯</span>
            <span class="label">Focus Mode</span>
        </button>
        <button class="mode-btn lockdown" onclick="showLockdownModal()">
            <span class="icon">🔒</span>
            <span class="label">Lock Internet</span>
        </button>
    </div>

    <div class="chat-container" id="chatContainer">
        <div class="message assistant" id="initialMessage">
            Hi! Internet is open right now. Need to focus? Use Focus Mode to block distracting sites, or Lock Internet to block everything until you provide a good reason.
        </div>
    </div>
    <div class="loading" id="loading">
        <div class="spinner"></div>
        <span>Thinking...</span>
    </div>
    <div class="input-area" id="inputArea">
        <textarea id="userInput" placeholder="Chat with me..."></textarea>
        <button type="button" id="sendBtn">Send</button>
    </div>
</div>

<!-- Focus Mode Modal -->
<div class="modal" id="focusModal">
    <div class="modal-content">
        <div class="modal-header">
            <h2>🎯 Focus Mode</h2>
            <p style="color: #a0a0a0; margin-top: 10px; font-size: 0.9rem;">Block distracting sites (YouTube, Instagram, Twitter, etc.)</p>
        </div>
        <div class="form-group">
            <label>Duration</label>
            <select id="focusDuration">
                <option value="15">15 minutes</option>
                <option value="30">30 minutes</option>
                <option value="60" selected>1 hour</option>
                <option value="120">2 hours</option>
                <option value="180">3 hours</option>
                <option value="until_night">Until 9pm</option>
            </select>
        </div>
        <div class="btn-row">
            <button class="btn-cancel" onclick="closeModal('focusModal')">Cancel</button>
            <button onclick="startFocusMode()">Start Focus</button>
        </div>
    </div>
</div>

<!-- Lockdown Modal -->
<div class="modal" id="lockdownModal">
    <div class="modal-content">
        <div class="modal-header">
            <h2>🔒 Lock Internet</h2>
            <p style="color: #a0a0a0; margin-top: 10px; font-size: 0.9rem;">Block all internet. You'll need to explain why to get it back.</p>
        </div>
        <div class="form-group">
            <label>Duration</label>
            <select id="lockdownDuration">
                <option value="15">15 minutes</option>
                <option value="30">30 minutes</option>
                <option value="60" selected>1 hour</option>
                <option value="120">2 hours</option>
                <option value="until_night">Until 9pm</option>
            </select>
        </div>
        <div class="form-group">
            <label>Why are you locking? (helps the AI understand)</label>
            <input type="text" id="lockdownReason" placeholder="e.g., Need to study for exam">
        </div>
        <div class="form-group">
            <label>Exceptions (what would be a valid reason to unlock?)</label>
            <input type="text" id="lockdownExceptions" placeholder="e.g., Work emergency, family call">
        </div>
        <div class="btn-row">
            <button class="btn-cancel" onclick="closeModal('lockdownModal')">Cancel</button>
            <button onclick="startLockdown()" style="background: #ff6b6b;">Lock Internet</button>
        </div>
    </div>
</div>

<script>
var sessionId = null;

function updateTime() {
    var now = new Date();
    var h = now.getHours(), m = now.getMinutes();
    var ampm = h >= 12 ? 'PM' : 'AM';
    var h12 = h % 12 || 12;
    document.getElementById('currentTime').textContent = h12 + ':' + (m<10?'0':'') + m + ' ' + ampm;
}
updateTime();
setInterval(updateTime, 60000);

function showFocusModal() { document.getElementById('focusModal').className = 'modal active'; }
function showLockdownModal() { document.getElementById('lockdownModal').className = 'modal active'; }
function closeModal(id) { document.getElementById(id).className = 'modal'; }

function startFocusMode() {
    var duration = document.getElementById('focusDuration').value;
    closeModal('focusModal');
    addMessage('Starting focus mode...', 'system');

    fetch('/api/focus', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'start', duration: duration})
    }).then(r => r.json()).then(data => {
        if (data.success) {
            addMessage('Focus mode activated! Distracting sites are now blocked.', 'success');
            updateStatus();
        } else {
            addMessage('Error: ' + data.message, 'system');
        }
    });
}

function startLockdown() {
    var duration = document.getElementById('lockdownDuration').value;
    var reason = document.getElementById('lockdownReason').value;
    var exceptions = document.getElementById('lockdownExceptions').value;
    closeModal('lockdownModal');
    addMessage('Locking internet...', 'system');

    fetch('/api/lockdown', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'start', duration: duration, reason: reason, exceptions: exceptions})
    }).then(r => r.json()).then(data => {
        if (data.success) {
            addMessage('Internet locked! You will need to provide a good reason to unlock.', 'success');
            setTimeout(function() { window.location.reload(); }, 1500);
        } else {
            addMessage('Error: ' + data.message, 'system');
        }
    });
}

function stopMode(mode) {
    fetch('/api/' + mode, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'stop'})
    }).then(r => r.json()).then(data => {
        if (data.success) {
            addMessage(mode.charAt(0).toUpperCase() + mode.slice(1) + ' mode disabled.', 'success');
            updateStatus();
        }
    });
}

function updateStatus() {
    fetch('/api/status').then(r => r.json()).then(data => {
        var banner = document.getElementById('statusBanner');
        var buttons = document.getElementById('modeButtons');

        if (data.focus_mode_active) {
            var expiry = new Date(data.focus_mode_expiry * 1000);
            banner.className = 'status-banner focus';
            banner.innerHTML = '<div class="title">🎯 Focus Mode Active</div>' +
                '<div class="time">Until ' + expiry.toLocaleTimeString('en-US', {hour: '2-digit', minute: '2-digit'}) + '</div>' +
                '<button onclick="stopMode(\\'focus\\')">Stop Focus Mode</button>';
            buttons.style.display = 'none';
        } else if (data.voluntary_lockdown_active) {
            buttons.style.display = 'none';
            banner.className = 'status-banner hidden';
        } else {
            banner.className = 'status-banner hidden';
            buttons.style.display = 'grid';
        }
    });
}
updateStatus();
setInterval(updateStatus, 30000);

function addMessage(content, type) {
    var container = document.getElementById('chatContainer');
    var msg = document.createElement('div');
    msg.className = 'message ' + type;
    msg.textContent = content;
    container.appendChild(msg);
    container.scrollTop = container.scrollHeight;
}

function setLoading(active) {
    document.getElementById('loading').className = active ? 'loading active' : 'loading';
    document.getElementById('inputArea').className = active ? 'input-area hidden' : 'input-area';
}

function sendMessage() {
    var input = document.getElementById('userInput');
    var message = input.value.trim();
    if (!message) return;

    addMessage(message, 'user');
    input.value = '';
    setLoading(true);

    fetch('/daychat', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({session_id: sessionId, message: message})
    }).then(r => r.json()).then(data => {
        setLoading(false);
        if (data.session_id) sessionId = data.session_id;
        if (data.message) addMessage(data.message, 'assistant');
        if (data.status === 'error') addMessage('Error: ' + data.message, 'system');
    }).catch(e => {
        setLoading(false);
        addMessage('Connection error.', 'system');
    });
}

document.getElementById('sendBtn').onclick = sendMessage;
document.getElementById('userInput').onkeydown = function(e) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
};
</script>
</body>
</html>"""

SETTINGS_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Open Sesame - Settings</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: {bg_gradient};
    min-height: 100vh;
    padding: 20px;
    color: {text_color};
}}
.container {{ max-width: 600px; margin: 0 auto; }}
.header {{ text-align: center; margin-bottom: 30px; }}
.header h1 {{ font-size: 1.8rem; color: {heading_color}; margin-bottom: 10px; }}
.back-link {{
    display: inline-block;
    margin-bottom: 20px;
    color: {accent_color};
    text-decoration: none;
    font-size: 0.9rem;
}}
.back-link:hover {{ text-decoration: underline; }}
.section {{
    background: {card_bg};
    backdrop-filter: blur(10px);
    border-radius: 15px;
    padding: 25px;
    margin-bottom: 20px;
    border: 1px solid {border_color};
}}
.section h2 {{ font-size: 1.2rem; margin-bottom: 15px; color: {heading_color}; }}
.section p {{ color: {muted_color}; font-size: 0.9rem; margin-bottom: 15px; }}
.domain-list {{
    background: {chart_bg};
    border-radius: 10px;
    padding: 15px;
    margin-bottom: 15px;
    max-height: 200px;
    overflow-y: auto;
}}
.domain-item {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 0;
    border-bottom: 1px solid {border_color};
}}
.domain-item:last-child {{ border-bottom: none; }}
.domain-item button {{
    padding: 5px 10px;
    font-size: 0.8rem;
    background: rgba(255, 107, 107, 0.2);
    color: #ff6b6b;
    border: none;
    border-radius: 5px;
    cursor: pointer;
}}
.domain-item button:hover {{ background: rgba(255, 107, 107, 0.3); }}
.add-domain {{
    display: flex;
    gap: 10px;
}}
.add-domain input {{
    flex: 1;
    padding: 12px;
    border: none;
    border-radius: 8px;
    background: {input_bg};
    color: {input_color};
    font-size: 1rem;
}}
.add-domain input:focus {{ outline: 2px solid {accent_color}; }}
.add-domain button {{
    padding: 12px 20px;
    border: none;
    border-radius: 8px;
    background: {accent_color};
    color: #fff;
    cursor: pointer;
}}
.add-domain button:hover {{ opacity: 0.9; }}
.message {{
    padding: 15px;
    border-radius: 10px;
    margin-bottom: 15px;
    text-align: center;
}}
.message.success {{ background: rgba(46, 213, 115, 0.15); color: #2ed573; }}
.message.error {{ background: rgba(255, 107, 107, 0.15); color: #ff6b6b; }}
.hidden {{ display: none; }}
</style>
</head>
<body>
<div class="container">
    <a href="/" class="back-link">&larr; Back</a>
    <div class="header">
        <h1>Settings</h1>
    </div>

    <div id="message" class="message hidden"></div>

    <div class="section">
        <h2>Focus Mode Domains</h2>
        <p>These sites will be blocked when Focus Mode is active.</p>
        <div class="domain-list" id="domainList">
            {domain_list}
        </div>
        <div class="add-domain">
            <input type="text" id="newDomain" placeholder="example.com">
            <button onclick="addDomain()">Add</button>
        </div>
    </div>
</div>
<script>
function showMessage(text, type) {{
    var msg = document.getElementById('message');
    msg.textContent = text;
    msg.className = 'message ' + type;
    setTimeout(function() {{ msg.className = 'message hidden'; }}, 3000);
}}

function removeDomain(domain) {{
    fetch('/api/settings', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{action: 'remove_domain', domain: domain}})
    }}).then(r => r.json()).then(data => {{
        if (data.success) {{
            location.reload();
        }} else {{
            showMessage('Error: ' + data.message, 'error');
        }}
    }});
}}

function addDomain() {{
    var input = document.getElementById('newDomain');
    var domain = input.value.trim().toLowerCase();
    if (!domain) return;

    fetch('/api/settings', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{action: 'add_domain', domain: domain}})
    }}).then(r => r.json()).then(data => {{
        if (data.success) {{
            location.reload();
        }} else {{
            showMessage('Error: ' + data.message, 'error');
        }}
    }});
}}
</script>
</body>
</html>"""

DAYTIME_SYSTEM_PROMPT = """You are a friendly AI assistant on a home router. It's daytime, so the internet is open - you're NOT evaluating access requests.

You're just here to chat! Be helpful, friendly, and conversational. You can:
- Answer questions about anything
- Have casual conversations
- Help with general queries
- Be a friendly companion

Keep responses concise (1-3 sentences usually). Be warm and personable.

IMPORTANT: You cannot grant or deny internet access during daytime - the gatekeeper is off. If someone asks for internet access, just let them know it's already open during daytime hours (5am-9pm).

Respond with plain text only - no JSON formatting needed."""


def is_nighttime():
    """Check if current time is nighttime (9pm-5am)."""
    hour = datetime.now().hour
    return hour >= 21 or hour < 5


def get_theme_vars():
    """Get theme variables based on time of day (night=dark, day=golden)."""
    if is_nighttime():
        return {
            'bg_gradient': 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
            'text_color': '#e4e4e4',
            'heading_color': '#fff',
            'accent_color': '#4a69bd',
            'muted_color': '#a0a0a0',
            'card_bg': 'rgba(255, 255, 255, 0.05)',
            'border_color': 'rgba(255, 255, 255, 0.1)',
            'chart_bg': 'rgba(0, 0, 0, 0.3)',
            'grid_color': 'rgba(255, 255, 255, 0.1)',
            'input_bg': 'rgba(255, 255, 255, 0.1)',
            'input_color': '#fff',
        }
    else:
        return {
            'bg_gradient': 'linear-gradient(135deg, #fef9e7 0%, #fdeaa8 50%, #f6d365 100%)',
            'text_color': '#2d3436',
            'heading_color': '#d35400',
            'accent_color': '#e67e22',
            'muted_color': '#7f8c8d',
            'card_bg': 'rgba(255, 255, 255, 0.85)',
            'border_color': 'rgba(255, 255, 255, 0.5)',
            'chart_bg': 'rgba(0, 0, 0, 0.05)',
            'grid_color': 'rgba(0, 0, 0, 0.1)',
            'input_bg': 'rgba(0, 0, 0, 0.05)',
            'input_color': '#2d3436',
        }


def log(message):
    """Log to syslog and stdout."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")
    try:
        subprocess.run(["logger", "-t", "gatekeeper", message], check=False)
    except Exception:
        pass


def generate_session_id(mac, ip):
    """Generate a unique session ID."""
    data = f"{mac}:{ip}:{time.time()}:{os.urandom(8).hex()}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]


def check_rate_limit(ip):
    """Check if IP is rate limited. Returns True if allowed."""
    now = time.time()
    if ip not in rate_limit:
        rate_limit[ip] = {"count": 1, "window_start": now}
        return True

    entry = rate_limit[ip]
    if now - entry["window_start"] > RATE_LIMIT_WINDOW:
        rate_limit[ip] = {"count": 1, "window_start": now}
        return True

    if entry["count"] >= RATE_LIMIT_MAX:
        return False

    entry["count"] += 1
    return True


def resolve_host_external(hostname, dns_server=EXTERNAL_DNS):
    """Resolve hostname using external DNS to bypass local DNS hijacking."""
    try:
        # Use dig/nslookup via subprocess to query external DNS
        result = subprocess.run(
            ["nslookup", hostname, dns_server],
            capture_output=True, text=True, timeout=5
        )
        # Parse nslookup output for IP address
        for line in result.stdout.split("\n"):
            if "Address" in line and dns_server not in line and "#" not in line:
                parts = line.split()
                for part in parts:
                    # Check if it looks like an IPv4 address
                    if part.count(".") == 3 and all(p.isdigit() for p in part.split(".")):
                        return part
    except Exception as e:
        log(f"External DNS resolution failed: {e}")
    return None


# Cache for resolved Gemini IP (avoid repeated DNS lookups)
_gemini_ip_cache = {"ip": None, "expires": 0}


def get_gemini_ip():
    """Get Gemini API IP address, using cache or external DNS resolution."""
    global _gemini_ip_cache
    now = time.time()

    # Return cached IP if still valid (cache for 5 minutes)
    if _gemini_ip_cache["ip"] and now < _gemini_ip_cache["expires"]:
        return _gemini_ip_cache["ip"]

    # Resolve using external DNS
    ip = resolve_host_external(GEMINI_HOST)
    if ip:
        _gemini_ip_cache = {"ip": ip, "expires": now + 300}
        log(f"Resolved {GEMINI_HOST} -> {ip} via external DNS")
        return ip

    # Fallback: try system resolver (might work if DNS hijacking not active)
    try:
        ip = socket.gethostbyname(GEMINI_HOST)
        if ip != GATEWAY_IP:  # Make sure it's not the hijacked response
            _gemini_ip_cache = {"ip": ip, "expires": now + 300}
            return ip
    except Exception:
        pass

    return None


def call_gemini(conversation_history):
    """Call Gemini API with conversation history (supports multimodal with images)."""
    # Resolve Gemini IP to bypass DNS hijacking
    gemini_ip = get_gemini_ip()
    if not gemini_ip:
        log("Failed to resolve Gemini API hostname")
        return {"status": "error", "message": "Failed to resolve API server. Please try again."}

    # Temporarily patch DNS resolution to return our resolved IP
    original_getaddrinfo = socket.getaddrinfo

    def patched_getaddrinfo(host, port, *args, **kwargs):
        if host == GEMINI_HOST:
            # Return our externally-resolved IP
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (gemini_ip, port))]
        return original_getaddrinfo(host, port, *args, **kwargs)

    socket.getaddrinfo = patched_getaddrinfo
    try:
        return _call_gemini_internal(conversation_history)
    finally:
        socket.getaddrinfo = original_getaddrinfo


def _call_gemini_internal(conversation_history):
    """Internal Gemini API call (DNS already patched)."""
    url = f"{GEMINI_ENDPOINT}?key={GEMINI_API_KEY}"

    # Get current date/time context
    now = datetime.now()
    weekday = now.strftime("%A")  # e.g., "Monday"
    date_str = now.strftime("%Y-%m-%d")  # e.g., "2026-02-19"
    time_str = now.strftime("%I:%M %p")  # e.g., "10:30 PM"

    context_info = f"\n\n## Current Context:\n- Date: {date_str} ({weekday})\n- Time: {time_str}"

    # Add request history from tonight
    request_history = get_request_history_for_context()

    system_with_context = SYSTEM_PROMPT + context_info + request_history

    contents = [{"role": "user", "parts": [{"text": system_with_context}]}]
    contents.append({"role": "model", "parts": [{"text": "I understand. I will evaluate internet access requests, require proof for >10 minutes, and respond in JSON format only."}]})

    # Only include actual image data for the most recent message that has an image
    # For older messages, just reference that an image was shown
    last_image_idx = -1
    for i, msg in enumerate(conversation_history):
        if msg.get("image"):
            last_image_idx = i

    for idx, msg in enumerate(conversation_history):
        role = "user" if msg["role"] == "user" else "model"
        parts = []

        # Handle text content
        if msg.get("content"):
            parts.append({"text": msg["content"]})

        # Handle image content - only send actual image data for the most recent image
        if msg.get("image"):
            if idx == last_image_idx:
                # This is the most recent image - send actual data
                image_data = msg["image"]
                # Parse data URL: data:image/jpeg;base64,/9j/4AAQ...
                if image_data.startswith("data:"):
                    try:
                        header, base64_data = image_data.split(",", 1)
                        # Extract mime type from header like "data:image/jpeg;base64"
                        mime_type = header.split(":")[1].split(";")[0]
                        parts.append({
                            "inline_data": {
                                "mime_type": mime_type,
                                "data": base64_data
                            }
                        })
                    except (ValueError, IndexError) as e:
                        log(f"Failed to parse image data URL: {e}")
            else:
                # Older image - just add a text reference
                parts.append({"text": "(Previously uploaded image - already reviewed)"})

        if parts:
            contents.append({"role": role, "parts": parts})

    payload = {
        "contents": contents,
        "generationConfig": {
            "temperature": 0.7,
            "maxOutputTokens": 500
        }
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
            text = result["candidates"][0]["content"]["parts"][0]["text"]
            text = text.strip()

            # Remove markdown code blocks if present
            if text.startswith("```"):
                # Handle ```json or just ```
                lines = text.split("\n")
                start = 1
                end = len(lines)
                for i, line in enumerate(lines):
                    if i > 0 and line.strip().startswith("```"):
                        end = i
                        break
                text = "\n".join(lines[start:end]).strip()

            # Try to extract JSON from the text if it contains other content
            if not text.startswith("{"):
                # Look for JSON object in the text
                start_idx = text.find("{")
                end_idx = text.rfind("}") + 1
                if start_idx != -1 and end_idx > start_idx:
                    text = text[start_idx:end_idx]

            try:
                return json.loads(text)
            except json.JSONDecodeError:
                # If JSON parsing fails, try to construct a response from the text
                log(f"Raw AI response: {text[:200]}")
                # Check if it looks like a question
                if "?" in text:
                    return {"status": "question", "message": text}
                # Check for approval keywords
                elif any(word in text.lower() for word in ["approved", "granted", "allow", "yes"]):
                    return {"status": "approved", "duration": 10, "message": text}
                elif any(word in text.lower() for word in ["denied", "reject", "no", "wait"]):
                    return {"status": "denied", "message": text}
                else:
                    return {"status": "question", "message": text}

    except urllib.error.URLError as e:
        log(f"Gemini API error: {e}")
        return {"status": "error", "message": "Failed to reach AI service. Please try again."}
    except json.JSONDecodeError as e:
        log(f"JSON parse error: {e}")
        return {"status": "error", "message": "AI response was invalid. Please try again."}
    except Exception as e:
        log(f"Unexpected error: {e}")
        return {"status": "error", "message": "An error occurred. Please try again."}


def get_client_mac(ip):
    """Get MAC address for an IP from the ARP table."""
    try:
        result = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, check=False)
        parts = result.stdout.strip().split()
        if len(parts) >= 5:
            return parts[4].upper()
    except Exception:
        pass
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f:
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        return parts[3].upper()
    except Exception:
        pass
    return None


def enable_dns_hijacking():
    """Enable DNS hijacking - all domains resolve to router IP for captive portal detection."""
    log("Enabling DNS hijacking (all domains -> router IP)...")
    try:
        # Add wildcard DNS entry - all domains resolve to router IP
        subprocess.run(["uci", "add_list", f"dhcp.@dnsmasq[0].address=/#/{GATEWAY_IP}"], check=False)
        # Disable rebind protection (needed for wildcard DNS)
        subprocess.run(["uci", "set", "dhcp.@dnsmasq[0].rebind_protection=0"], check=False)
        subprocess.run(["uci", "commit", "dhcp"], check=False)
        subprocess.run(["/etc/init.d/dnsmasq", "restart"], check=False)
        log("DNS hijacking enabled")
    except Exception as e:
        log(f"Error enabling DNS hijacking: {e}")


def disable_dns_hijacking():
    """Disable DNS hijacking - restore normal DNS resolution."""
    log("Disabling DNS hijacking (restoring normal DNS)...")
    try:
        # Remove wildcard DNS entry
        subprocess.run(["uci", "del_list", f"dhcp.@dnsmasq[0].address=/#/{GATEWAY_IP}"], check=False)
        # Re-enable rebind protection
        subprocess.run(["uci", "set", "dhcp.@dnsmasq[0].rebind_protection=1"], check=False)
        subprocess.run(["uci", "commit", "dhcp"], check=False)
        subprocess.run(["/etc/init.d/dnsmasq", "restart"], check=False)
        log("DNS hijacking disabled")
    except Exception as e:
        log(f"Error disabling DNS hijacking: {e}")


def grant_network_access(duration_minutes, requesting_mac):
    """Grant internet access to the ENTIRE network using iptables."""
    global network_access_expiry, network_access_granted_by
    network_access_expiry = time.time() + (duration_minutes * 60)
    network_access_granted_by = requesting_mac

    try:
        # Remove the REJECT rule to allow all LAN traffic
        subprocess.run(["iptables", "-t", "filter", "-D", "FORWARD", "-i", LAN_INTERFACE,
                       "-o", "eth0", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"],
                      capture_output=True, check=False)

        # Remove the HTTP redirect rule (ALL port 80 traffic, including to gateway)
        subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-i", LAN_INTERFACE,
                       "-p", "tcp", "--dport", "80",
                       "-j", "REDIRECT", "--to-port", str(SERVER_PORT)],
                      capture_output=True, check=False)

        # Restore normal DNS so authenticated users can browse properly
        disable_dns_hijacking()

        log(f"Granted {duration_minutes}min NETWORK-WIDE access (requested by {requesting_mac})")
        return True
    except Exception as e:
        log(f"Failed to grant network access: {e}")
        return False


def revoke_network_access():
    """Revoke internet access for the entire network and kick all WiFi clients."""
    global network_access_expiry, network_access_granted_by

    if network_access_expiry is None:
        return  # Already revoked

    log(f"Revoking network-wide access (was granted to {network_access_granted_by})")
    network_access_expiry = None
    network_access_granted_by = None

    try:
        # Re-add the REJECT rule to block all LAN traffic
        subprocess.run(["iptables", "-t", "filter", "-I", "FORWARD", "1", "-i", LAN_INTERFACE,
                       "-o", "eth0", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"],
                      check=False)

        # Re-add the HTTP redirect rule (ALL port 80 traffic, including to gateway)
        subprocess.run(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-i", LAN_INTERFACE,
                       "-p", "tcp", "--dport", "80",
                       "-j", "REDIRECT", "--to-port", str(SERVER_PORT)],
                      check=False)

        # Re-enable DNS hijacking for captive portal detection
        enable_dns_hijacking()

        # Flush connection tracking to kill existing connections
        subprocess.run(["conntrack", "-F"], capture_output=True, check=False)

        # Kick all WiFi clients to force reconnect and see captive portal
        log("Kicking all WiFi clients...")
        kick_wifi_clients()

    except Exception as e:
        log(f"Error revoking network access: {e}")


def check_expired_sessions():
    """Check and revoke expired network access."""
    global network_access_expiry
    if network_access_expiry is not None and time.time() > network_access_expiry:
        log("Network access has expired!")
        revoke_network_access()


def is_network_authenticated():
    """Check if the network currently has access."""
    check_expired_sessions()
    return network_access_expiry is not None


def render_time_chart(approved_data, denied_data):
    """Render SVG scatter plot of time vs duration with approved (blue) and denied (red)."""
    if not approved_data and not denied_data:
        return '<div class="empty-state">No data yet</div>'

    # Chart dimensions (viewBox coordinates)
    width = 500
    height = 200
    padding_left = 45
    padding_bottom = 45
    padding_top = 10
    padding_right = 10

    chart_width = width - padding_left - padding_right
    chart_height = height - padding_top - padding_bottom

    # Time axis: 21:00 (9pm) to 05:00 (5am) - nighttime hours
    # Map 21-24 to 0-3, and 0-5 to 3-8 (total 8 hours span)
    def hour_to_x(hour):
        if hour >= 21:
            normalized = hour - 21  # 21->0, 22->1, 23->2, 24->3
        else:
            normalized = hour + 3   # 0->3, 1->4, 2->5, 3->6, 4->7, 5->8
        return padding_left + (normalized / 8) * chart_width

    # Duration axis: 0-120 minutes
    max_duration = 120
    def duration_to_y(duration):
        return height - padding_bottom - (min(duration, max_duration) / max_duration) * chart_height

    # Build SVG
    svg_parts = [f'<svg class="chart-svg" viewBox="0 0 {width} {height}" preserveAspectRatio="xMidYMid meet">']

    # Grid lines (horizontal for duration)
    for dur in [30, 60, 90, 120]:
        y = duration_to_y(dur)
        svg_parts.append(f'<line class="grid-line" x1="{padding_left}" y1="{y}" x2="{width - padding_right}" y2="{y}"/>')
        svg_parts.append(f'<text class="axis-label" x="{padding_left - 5}" y="{y + 4}" text-anchor="end">{dur}</text>')

    # X-axis labels (time)
    time_labels = [(21, "9pm"), (23, "11pm"), (1, "1am"), (3, "3am"), (5, "5am")]
    for hour, label in time_labels:
        x = hour_to_x(hour)
        svg_parts.append(f'<text class="axis-label" x="{x}" y="{height - padding_bottom + 18}" text-anchor="middle">{label}</text>')

    # Axis titles
    svg_parts.append(f'<text class="axis-title" x="{width / 2}" y="{height - 5}" text-anchor="middle">Time of Night</text>')
    svg_parts.append(f'<text class="axis-title" x="12" y="{(height - padding_bottom) / 2 + padding_top}" text-anchor="middle" transform="rotate(-90, 12, {(height - padding_bottom) / 2 + padding_top})">Duration (min)</text>')

    # Approved data points (blue)
    for point in approved_data:
        hour = point['hour']
        duration = point['duration']
        # Only show points in nighttime range (9pm-5am)
        if hour >= 21 or hour < 5:
            x = hour_to_x(hour)
            y = duration_to_y(duration)
            # Size based on duration (min 4, max 12)
            r = 4 + (duration / 120) * 8
            svg_parts.append(f'<circle class="data-point approved" cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}"><title>Approved {int(hour)}:{int((hour % 1) * 60):02d} - {duration} min</title></circle>')

    # Denied data points (red) - fixed size since no duration
    for point in denied_data:
        hour = point['hour']
        # Only show points in nighttime range (9pm-5am)
        if hour >= 21 or hour < 5:
            x = hour_to_x(hour)
            y = duration_to_y(0)  # Denied requests at bottom (0 duration granted)
            svg_parts.append(f'<circle class="data-point denied" cx="{x:.1f}" cy="{y:.1f}" r="5"><title>Denied {int(hour)}:{int((hour % 1) * 60):02d}</title></circle>')

    # Legend
    svg_parts.append(f'<circle class="data-point approved" cx="{width - 80}" cy="15" r="5"/>')
    svg_parts.append(f'<text class="axis-label" x="{width - 70}" y="19">Approved</text>')
    svg_parts.append(f'<circle class="data-point denied" cx="{width - 80}" cy="30" r="5"/>')
    svg_parts.append(f'<text class="axis-label" x="{width - 70}" y="34">Denied</text>')

    svg_parts.append('</svg>')
    return '\n'.join(svg_parts)


def render_weekday_chart(weekday_approved, weekday_denied, weekday_names):
    """Render SVG bar chart of exceptions per weekday."""
    max_count = max(max(weekday_approved), max(weekday_denied), 1)

    # Chart dimensions
    width = 500
    height = 150
    padding_left = 35
    padding_bottom = 25
    padding_top = 10
    padding_right = 10

    chart_width = width - padding_left - padding_right
    chart_height = height - padding_top - padding_bottom
    bar_width = chart_width / 7 * 0.35  # Each day gets space, bars are 35% of that
    gap = chart_width / 7

    svg_parts = [f'<svg class="chart-svg" viewBox="0 0 {width} {height}" preserveAspectRatio="xMidYMid meet">']

    # Grid lines
    for i in range(1, 5):
        y_val = max_count * i / 4
        y = height - padding_bottom - (i / 4) * chart_height
        svg_parts.append(f'<line class="grid-line" x1="{padding_left}" y1="{y}" x2="{width - padding_right}" y2="{y}"/>')
        svg_parts.append(f'<text class="axis-label" x="{padding_left - 5}" y="{y + 4}" text-anchor="end">{int(y_val)}</text>')

    # Bars for each day
    for i, day in enumerate(weekday_names):
        x_center = padding_left + gap * i + gap / 2

        # Approved bar (blue)
        approved_height = (weekday_approved[i] / max_count) * chart_height if max_count > 0 else 0
        if approved_height > 0:
            svg_parts.append(f'<rect class="bar approved" x="{x_center - bar_width - 1}" y="{height - padding_bottom - approved_height}" width="{bar_width}" height="{approved_height}"><title>{day}: {weekday_approved[i]} approved</title></rect>')

        # Denied bar (red)
        denied_height = (weekday_denied[i] / max_count) * chart_height if max_count > 0 else 0
        if denied_height > 0:
            svg_parts.append(f'<rect class="bar denied" x="{x_center + 1}" y="{height - padding_bottom - denied_height}" width="{bar_width}" height="{denied_height}"><title>{day}: {weekday_denied[i]} denied</title></rect>')

        # Day label
        svg_parts.append(f'<text class="axis-label" x="{x_center}" y="{height - 5}" text-anchor="middle">{day}</text>')

    # Legend
    svg_parts.append(f'<rect class="bar approved" x="{width - 100}" y="8" width="12" height="12"/>')
    svg_parts.append(f'<text class="axis-label" x="{width - 85}" y="18">Approved</text>')
    svg_parts.append(f'<rect class="bar denied" x="{width - 100}" y="24" width="12" height="12"/>')
    svg_parts.append(f'<text class="axis-label" x="{width - 85}" y="34">Denied</text>')

    svg_parts.append('</svg>')
    return '\n'.join(svg_parts)


def render_daytime_chart(focus_data, lockdown_data):
    """Render SVG scatter plot for daytime modes (5am-9pm)."""
    if not focus_data and not lockdown_data:
        return '<div class="empty-state">No daytime mode data yet</div>'

    # Chart dimensions (viewBox coordinates)
    width = 500
    height = 200
    padding_left = 45
    padding_bottom = 45
    padding_top = 10
    padding_right = 10

    chart_width = width - padding_left - padding_right
    chart_height = height - padding_top - padding_bottom

    # Time axis: 5:00 to 21:00 (5am to 9pm) - 16 hour span
    def hour_to_x(hour):
        normalized = hour - 5  # 5->0, 21->16
        return padding_left + (normalized / 16) * chart_width

    # Duration axis: 0-480 minutes (8 hours max)
    max_duration = 480
    def duration_to_y(duration):
        return height - padding_bottom - (min(duration, max_duration) / max_duration) * chart_height

    # Build SVG
    svg_parts = [f'<svg class="chart-svg" viewBox="0 0 {width} {height}" preserveAspectRatio="xMidYMid meet">']

    # Grid lines (horizontal for duration)
    for dur in [60, 120, 240, 480]:
        y = duration_to_y(dur)
        label = f"{dur // 60}h" if dur >= 60 else f"{dur}m"
        svg_parts.append(f'<line class="grid-line" x1="{padding_left}" y1="{y}" x2="{width - padding_right}" y2="{y}"/>')
        svg_parts.append(f'<text class="axis-label" x="{padding_left - 5}" y="{y + 4}" text-anchor="end">{label}</text>')

    # X-axis labels (time)
    time_labels = [(5, "5am"), (9, "9am"), (13, "1pm"), (17, "5pm"), (21, "9pm")]
    for hour, label in time_labels:
        x = hour_to_x(hour)
        svg_parts.append(f'<text class="axis-label" x="{x}" y="{height - padding_bottom + 18}" text-anchor="middle">{label}</text>')

    # Axis titles
    svg_parts.append(f'<text class="axis-title" x="{width / 2}" y="{height - 5}" text-anchor="middle">Time of Day</text>')
    svg_parts.append(f'<text class="axis-title" x="12" y="{(height - padding_bottom) / 2 + padding_top}" text-anchor="middle" transform="rotate(-90, 12, {(height - padding_bottom) / 2 + padding_top})">Duration</text>')

    # Focus mode data points (orange)
    for point in focus_data:
        hour = point['hour']
        duration = point['duration']
        if 5 <= hour < 21:
            x = hour_to_x(hour)
            y = duration_to_y(duration)
            r = 4 + (duration / 480) * 8
            svg_parts.append(f'<circle class="data-point focus" cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}"><title>Focus {int(hour)}:{int((hour % 1) * 60):02d} - {duration} min</title></circle>')

    # Lockdown data points (purple)
    for point in lockdown_data:
        hour = point['hour']
        duration = point['duration']
        if 5 <= hour < 21:
            x = hour_to_x(hour)
            y = duration_to_y(duration)
            r = 4 + (duration / 480) * 8
            svg_parts.append(f'<circle class="data-point lockdown" cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}"><title>Lockdown {int(hour)}:{int((hour % 1) * 60):02d} - {duration} min</title></circle>')

    # Legend
    svg_parts.append(f'<circle class="data-point focus" cx="{width - 80}" cy="15" r="5"/>')
    svg_parts.append(f'<text class="axis-label" x="{width - 70}" y="19">Focus</text>')
    svg_parts.append(f'<circle class="data-point lockdown" cx="{width - 80}" cy="30" r="5"/>')
    svg_parts.append(f'<text class="axis-label" x="{width - 70}" y="34">Lockdown</text>')

    svg_parts.append('</svg>')
    return '\n'.join(svg_parts)


def render_daytime_weekday_chart(weekday_focus, weekday_lockdown, weekday_names):
    """Render SVG bar chart for daytime modes per weekday."""
    max_count = max(max(weekday_focus), max(weekday_lockdown), 1)

    # Chart dimensions
    width = 500
    height = 150
    padding_left = 35
    padding_bottom = 25
    padding_top = 10
    padding_right = 10

    chart_width = width - padding_left - padding_right
    chart_height = height - padding_top - padding_bottom
    bar_width = chart_width / 7 * 0.35
    gap = chart_width / 7

    svg_parts = [f'<svg class="chart-svg" viewBox="0 0 {width} {height}" preserveAspectRatio="xMidYMid meet">']

    # Grid lines
    for i in range(1, 5):
        y_val = max_count * i / 4
        y = height - padding_bottom - (i / 4) * chart_height
        svg_parts.append(f'<line class="grid-line" x1="{padding_left}" y1="{y}" x2="{width - padding_right}" y2="{y}"/>')
        svg_parts.append(f'<text class="axis-label" x="{padding_left - 5}" y="{y + 4}" text-anchor="end">{int(y_val)}</text>')

    # Bars for each day
    for i, day in enumerate(weekday_names):
        x_center = padding_left + gap * i + gap / 2

        # Focus bar (orange)
        focus_height = (weekday_focus[i] / max_count) * chart_height if max_count > 0 else 0
        if focus_height > 0:
            svg_parts.append(f'<rect class="bar focus" x="{x_center - bar_width - 1}" y="{height - padding_bottom - focus_height}" width="{bar_width}" height="{focus_height}"><title>{day}: {weekday_focus[i]} focus</title></rect>')

        # Lockdown bar (purple)
        lockdown_height = (weekday_lockdown[i] / max_count) * chart_height if max_count > 0 else 0
        if lockdown_height > 0:
            svg_parts.append(f'<rect class="bar lockdown" x="{x_center + 1}" y="{height - padding_bottom - lockdown_height}" width="{bar_width}" height="{lockdown_height}"><title>{day}: {weekday_lockdown[i]} lockdown</title></rect>')

        # Day label
        svg_parts.append(f'<text class="axis-label" x="{x_center}" y="{height - 5}" text-anchor="middle">{day}</text>')

    # Legend
    svg_parts.append(f'<rect class="bar focus" x="{width - 100}" y="8" width="12" height="12"/>')
    svg_parts.append(f'<text class="axis-label" x="{width - 85}" y="18">Focus</text>')
    svg_parts.append(f'<rect class="bar lockdown" x="{width - 100}" y="24" width="12" height="12"/>')
    svg_parts.append(f'<text class="axis-label" x="{width - 85}" y="34">Lockdown</text>')

    svg_parts.append('</svg>')
    return '\n'.join(svg_parts)


def render_stats_page():
    """Render the stats HTML page with current data."""
    stats = get_stats()

    # Format hours
    total_hours = f"{stats['total_minutes'] / 60:.1f}"
    total_daytime_hours = f"{(stats['total_focus_minutes'] + stats['total_lockdown_minutes']) / 60:.1f}"

    # Build nighttime charts
    time_chart_night = render_time_chart(
        stats.get('time_distribution_approved', []),
        stats.get('time_distribution_denied', [])
    )
    weekday_chart_night = render_weekday_chart(
        stats.get('weekday_approved', [0]*7),
        stats.get('weekday_denied', [0]*7),
        stats.get('weekday_names', ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])
    )

    # Build daytime charts
    time_chart_day = render_daytime_chart(
        stats.get('time_distribution_focus', []),
        stats.get('time_distribution_lockdown', [])
    )
    weekday_chart_day = render_daytime_weekday_chart(
        stats.get('weekday_focus', [0]*7),
        stats.get('weekday_lockdown', [0]*7),
        stats.get('weekday_names', ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])
    )

    # Build history table
    if stats['recent']:
        rows = []
        for entry in stats['recent']:
            timestamp = entry.get('timestamp', 'Unknown')
            entry_type = entry.get('type', '')
            status = entry.get('status', '')
            duration = entry.get('duration', 0)

            # Determine display based on entry type
            if entry_type == 'focus_mode':
                reason = 'Focus Mode'
                badge_class = 'focus_mode'
                duration_text = f'{duration} min'
            elif entry_type == 'voluntary_lockdown':
                reason = entry.get('reason', 'Lockdown')[:80]
                badge_class = 'voluntary_lockdown'
                duration_text = f'{duration} min'
            else:
                reason = entry.get('reason', 'Unknown')[:80]
                badge_class = 'approved' if status == 'approved' else 'denied'
                duration_text = f'{duration} min' if status == 'approved' else 'Denied'

            rows.append(f"""<tr>
                <td>{timestamp}</td>
                <td class="reason-cell" title="{entry.get('reason', reason)}">{reason}</td>
                <td><span class="duration-badge {badge_class}">{duration_text}</span></td>
            </tr>""")
        history_table = f"""<table class="history-table">
            <thead>
                <tr><th>Time</th><th>Reason</th><th>Result</th></tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>"""
    else:
        history_table = '<div class="empty-state">No activity recorded yet</div>'

    theme = get_theme_vars()
    return STATS_HTML.format(
        total_approved=stats['total_approved'],
        total_denied=stats['total_denied'],
        total_hours=total_hours,
        total_focus=stats['total_focus'],
        total_lockdown=stats['total_lockdown'],
        total_daytime_hours=total_daytime_hours,
        time_chart_night=time_chart_night,
        time_chart_day=time_chart_day,
        weekday_chart_night=weekday_chart_night,
        weekday_chart_day=weekday_chart_day,
        history_table=history_table,
        **theme
    )


def render_settings_page():
    """Render the settings HTML page."""
    domains = get_focus_domains()

    # Build domain list HTML
    domain_items = []
    for domain in sorted(set(domains)):
        domain_items.append(
            f'<div class="domain-item"><span>{domain}</span>'
            f'<button onclick="removeDomain(\'{domain}\')">Remove</button></div>'
        )

    domain_list = '\n'.join(domain_items) if domain_items else '<p style="color: #666;">No domains configured</p>'

    theme = get_theme_vars()
    return SETTINGS_HTML.format(domain_list=domain_list, **theme)


class GatekeeperHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the captive portal."""
    timeout = 30  # Socket timeout in seconds

    def log_message(self, format, *args):
        log(f"HTTP: {args[0]}")

    def send_html(self, html, status=200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """Handle GET requests - serve splash page, stats page, or success page."""
        parsed = urllib.parse.urlparse(self.path)

        # Success endpoint - returns Apple's exact success HTML to dismiss CNA
        if parsed.path == "/success":
            # Apple's CNA looks for exactly this content to show "Done" button
            success_html = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2//EN">
<HTML>
<HEAD>
<TITLE>Success</TITLE>
</HEAD>
<BODY>
Success
</BODY>
</HTML>"""
            self.send_html(success_html)
            return

        # Stats page
        if parsed.path == "/stats":
            self.send_html(render_stats_page())
            return

        # Settings page
        if parsed.path == "/settings":
            self.send_html(render_settings_page())
            return

        # API status endpoint
        if parsed.path == "/api/status":
            self.send_json(get_status())
            return

        # Main page: serve nighttime splash or daytime chat based on time
        # During voluntary lockdown, show the nighttime splash instead
        if is_nighttime() or voluntary_lockdown_active:
            self.send_html(SPLASH_HTML)
        else:
            self.send_html(DAYTIME_HTML)

    def send_success_page(self):
        """Send a success page that closes the captive portal on macOS/iOS."""
        # This page should cause the captive portal assistant to close
        success_html = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Success</title>
<style>
body {
    font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #fff;
    text-align: center;
}
.container { padding: 40px; }
h1 { color: #2ed573; margin-bottom: 20px; }
p { color: #a0a0a0; }
</style>
</head>
<body>
<div class="container">
<h1>Connected!</h1>
<p>You now have internet access.</p>
<p>You can close this window.</p>
</div>
</body>
</html>"""
        self.send_html(success_html)

    def do_POST(self):
        """Handle POST requests - chat API and control endpoints."""
        client_ip = self.client_address[0]
        parsed = urllib.parse.urlparse(self.path)

        valid_paths = ["/chat", "/daychat", "/api/focus", "/api/lockdown", "/api/settings"]
        if parsed.path not in valid_paths:
            self.send_json({"status": "error", "message": "Not found"}, 404)
            return

        # Rate limiting
        if not check_rate_limit(client_ip):
            self.send_json({"status": "error", "message": "Too many requests. Please wait."}, 429)
            return

        # Read POST body
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            log(f"Receiving POST with {content_length} bytes")

            # Read in chunks for large payloads (images)
            body = b""
            remaining = content_length
            while remaining > 0:
                chunk_size = min(remaining, 65536)  # 64KB chunks
                chunk = self.rfile.read(chunk_size)
                if not chunk:
                    break
                body += chunk
                remaining -= len(chunk)

            body = body.decode("utf-8")
            log(f"Received {len(body)} bytes")
        except Exception as e:
            log(f"Error reading POST body: {e}")
            self.send_json({"status": "error", "message": "Failed to read request"}, 400)
            return

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError as e:
            log(f"JSON decode error: {e}")
            self.send_json({"status": "error", "message": "Invalid request"}, 400)
            return

        if parsed.path == "/daychat":
            self.handle_daychat(data, client_ip)
        elif parsed.path == "/api/focus":
            self.handle_focus_api(data)
        elif parsed.path == "/api/lockdown":
            self.handle_lockdown_api(data)
        elif parsed.path == "/api/settings":
            self.handle_settings_api(data)
        else:
            self.handle_chat(data, client_ip)

    def handle_focus_api(self, data):
        """Handle focus mode API requests."""
        action = data.get("action")

        if action == "start":
            duration = data.get("duration", "60")
            if duration == "until_night":
                minutes = get_minutes_until_daytime_end()
            else:
                minutes = int(duration)

            if minutes <= 0:
                self.send_json({"success": False, "message": "Invalid duration"})
                return

            enable_focus_mode(minutes)
            self.send_json({"success": True})

        elif action == "stop":
            disable_focus_mode()
            self.send_json({"success": True})

        else:
            self.send_json({"success": False, "message": "Invalid action"})

    def handle_lockdown_api(self, data):
        """Handle voluntary lockdown API requests."""
        action = data.get("action")

        if action == "start":
            duration = data.get("duration", "60")
            reason = data.get("reason", "")
            exceptions = data.get("exceptions", "")

            if duration == "until_night":
                minutes = get_minutes_until_daytime_end()
            else:
                minutes = int(duration)

            if minutes <= 0:
                self.send_json({"success": False, "message": "Invalid duration"})
                return

            enable_voluntary_lockdown(minutes, reason, exceptions)
            self.send_json({"success": True})

        elif action == "stop":
            disable_voluntary_lockdown()
            self.send_json({"success": True})

        else:
            self.send_json({"success": False, "message": "Invalid action"})

    def handle_settings_api(self, data):
        """Handle settings API requests."""
        action = data.get("action")

        if action == "add_domain":
            domain = data.get("domain", "").strip().lower()
            if not domain:
                self.send_json({"success": False, "message": "Domain required"})
                return

            domains = get_focus_domains()
            if domain not in domains:
                domains.append(domain)
                # Also add www variant if not present
                if not domain.startswith("www."):
                    www_domain = "www." + domain
                    if www_domain not in domains:
                        domains.append(www_domain)
                set_focus_domains(domains)

            self.send_json({"success": True})

        elif action == "remove_domain":
            domain = data.get("domain", "").strip().lower()
            domains = get_focus_domains()
            # Remove domain and its www variant
            domains = [d for d in domains if d != domain and d != "www." + domain and d != domain.replace("www.", "")]
            set_focus_domains(domains)
            self.send_json({"success": True})

        else:
            self.send_json({"success": False, "message": "Invalid action"})

    def handle_chat(self, data, client_ip):
        """Handle chat message and LLM interaction."""
        session_id = data.get("session_id")
        message = data.get("message", "").strip()
        image = data.get("image")  # Base64 data URL
        mac = get_client_mac(client_ip)

        # Find or create session
        session = None
        if session_id and session_id in sessions:
            session = sessions[session_id]
        else:
            for sid, sess in sessions.items():
                if sess["ip"] == client_ip:
                    session_id = sid
                    session = sess
                    break

        if not session:
            session_id = generate_session_id(mac or "unknown", client_ip)
            session = {
                "mac": mac,
                "ip": client_ip,
                "history": [],
                "questions_asked": 0
            }
            sessions[session_id] = session
            log(f"New session: {session_id[:8]}... for MAC={mac}, IP={client_ip}")

        if not message and not image:
            self.send_json({"status": "error", "message": "Please provide a reason.", "session_id": session_id}, 400)
            return

        # Add user message to history (with optional image)
        history_entry = {"role": "user", "content": message or "(Image attached)"}
        if image:
            history_entry["image"] = image
            log(f"Received image proof from {client_ip}")
        session["history"].append(history_entry)

        # Call Gemini
        response = call_gemini(session["history"])

        if response.get("status") == "question":
            session["questions_asked"] += 1
            session["history"].append({"role": "assistant", "content": json.dumps(response)})

            if session["questions_asked"] >= 3:
                session["history"].append({"role": "user", "content": "(Maximum clarifications reached. Please make a final decision.)"})
                response = call_gemini(session["history"])

        if response.get("status") == "approved":
            mac_addr = session["mac"]
            duration = min(response.get("duration", 10), 120)

            if grant_network_access(duration, mac_addr):
                response["granted"] = True
                log(f"Network access approved (requested by {mac_addr}): {duration} minutes")
                # Log to persistent request log (short summary)
                first_message = session["history"][0]["content"] if session["history"] else "Unknown"
                add_request_to_log(mac_addr, first_message, "approved", duration)
                # Log full conversation to nightly log
                conversation_texts = [h.get("content", "") for h in session["history"] if "content" in h]
                add_conversation_to_log(mac_addr, conversation_texts, "approved", duration)
            else:
                log(f"Failed to grant network access")
                response = {"status": "error", "message": "Failed to grant access. Please try again."}

        elif response.get("status") == "denied":
            log(f"Access denied for {session['mac']}: {response.get('message', 'No reason')}")
            # Log to persistent request log (short summary)
            first_message = session["history"][0]["content"] if session["history"] else "Unknown"
            add_request_to_log(session["mac"], first_message, "denied")
            # Log full conversation to nightly log
            conversation_texts = [h.get("content", "") for h in session["history"] if "content" in h]
            add_conversation_to_log(session["mac"], conversation_texts, "denied")

        response["session_id"] = session_id
        self.send_json(response)

    def handle_daychat(self, data, client_ip):
        """Handle daytime chat - just conversation, no access control."""
        session_id = data.get("session_id")
        message = data.get("message", "").strip()
        mac = get_client_mac(client_ip)

        # Find or create session
        session = None
        if session_id and session_id in sessions:
            session = sessions[session_id]
        else:
            for sid, sess in sessions.items():
                if sess["ip"] == client_ip:
                    session_id = sid
                    session = sess
                    break

        if not session:
            session_id = generate_session_id(mac or "unknown", client_ip)
            session = {
                "mac": mac,
                "ip": client_ip,
                "history": [],
                "questions_asked": 0,
                "daytime": True
            }
            sessions[session_id] = session
            log(f"New daytime session: {session_id[:8]}... for MAC={mac}, IP={client_ip}")

        if not message:
            self.send_json({"status": "error", "message": "Please enter a message.", "session_id": session_id}, 400)
            return

        # Add user message to history
        session["history"].append({"role": "user", "content": message})

        # Call Gemini with daytime system prompt
        response = self.call_daychat_gemini(session["history"])

        session["history"].append({"role": "assistant", "content": response})

        self.send_json({"status": "ok", "message": response, "session_id": session_id})

    def call_daychat_gemini(self, conversation_history):
        """Call Gemini for daytime chat (no JSON, just plain text response)."""
        gemini_ip = get_gemini_ip()
        if not gemini_ip:
            return "Sorry, I'm having trouble connecting right now. Try again in a moment!"

        original_getaddrinfo = socket.getaddrinfo

        def patched_getaddrinfo(host, port, *args, **kwargs):
            if host == GEMINI_HOST:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (gemini_ip, port))]
            return original_getaddrinfo(host, port, *args, **kwargs)

        socket.getaddrinfo = patched_getaddrinfo
        try:
            return self._call_daychat_internal(conversation_history)
        finally:
            socket.getaddrinfo = original_getaddrinfo

    def _call_daychat_internal(self, conversation_history):
        """Internal daytime chat API call."""
        url = f"{GEMINI_ENDPOINT}?key={GEMINI_API_KEY}"

        contents = [{"role": "user", "parts": [{"text": DAYTIME_SYSTEM_PROMPT}]}]
        contents.append({"role": "model", "parts": [{"text": "Got it! I'm here for friendly daytime chat. The internet is open, so I'm just a helpful companion. What would you like to talk about?"}]})

        for msg in conversation_history:
            role = "user" if msg["role"] == "user" else "model"
            contents.append({"role": role, "parts": [{"text": msg["content"]}]})

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": 0.8,
                "maxOutputTokens": 300
            }
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.loads(response.read().decode("utf-8"))
                text = result["candidates"][0]["content"]["parts"][0]["text"]
                return text.strip()
        except Exception as e:
            log(f"Daytime chat error: {e}")
            return "Oops, something went wrong! Let me try that again - what were you saying?"


def kick_wifi_clients():
    """Disconnect all WiFi clients to force them to reconnect and see captive portal."""
    log("Disconnecting all WiFi clients...")
    # Brief WiFi restart to kick all clients
    subprocess.run(["wifi", "down"], capture_output=True, check=False)
    time.sleep(2)
    subprocess.run(["wifi", "up"], capture_output=True, check=False)
    time.sleep(3)
    log("WiFi clients disconnected")


def setup_firewall():
    """Set up iptables rules for captive portal."""
    log("Setting up firewall rules...")

    # Clean up any old rules first
    teardown_firewall()

    # Redirect ALL HTTP from LAN to our portal (including to gateway IP for DNS hijacking)
    subprocess.run(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-i", LAN_INTERFACE,
                   "-p", "tcp", "--dport", "80",
                   "-j", "REDIRECT", "--to-port", str(SERVER_PORT)], check=False)

    # Block all forwarding from LAN to WAN (internet) - MUST be at position 1 to be before ESTABLISHED rule
    subprocess.run(["iptables", "-t", "filter", "-I", "FORWARD", "1", "-i", LAN_INTERFACE,
                   "-o", "eth0", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"], check=False)

    # Allow WAN access to stats page on port 2050
    subprocess.run(["iptables", "-A", "INPUT", "-i", "eth0", "-p", "tcp", "--dport", str(SERVER_PORT),
                   "-j", "ACCEPT"], check=False)

    # Enable DNS hijacking for iOS/Android captive portal detection
    enable_dns_hijacking()

    # Flush connection tracking to kill existing connections
    subprocess.run(["conntrack", "-F"], capture_output=True, check=False)

    log("Firewall rules configured")


def teardown_firewall():
    """Remove iptables rules."""
    global network_access_expiry, network_access_granted_by
    log("Removing firewall rules...")

    # Reset network access state
    network_access_expiry = None
    network_access_granted_by = None

    # Remove HTTP redirect (ALL port 80 traffic, including to gateway)
    subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-i", LAN_INTERFACE,
                   "-p", "tcp", "--dport", "80",
                   "-j", "REDIRECT", "--to-port", str(SERVER_PORT)],
                  capture_output=True, check=False)
    # Remove forward block
    subprocess.run(["iptables", "-t", "filter", "-D", "FORWARD", "-i", LAN_INTERFACE,
                   "-o", "eth0", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"],
                  capture_output=True, check=False)

    # Remove WAN access rule for stats page
    subprocess.run(["iptables", "-D", "INPUT", "-i", "eth0", "-p", "tcp", "--dport", str(SERVER_PORT),
                   "-j", "ACCEPT"], capture_output=True, check=False)

    # Disable DNS hijacking
    disable_dns_hijacking()

    log("Firewall rules removed")


def enable_gatekeeper():
    """Enable captive portal."""
    log("Enabling gatekeeper mode...")
    subprocess.run(["/etc/init.d/nodogsplash", "stop"], capture_output=True, check=False)
    setup_firewall()
    kick_wifi_clients()
    log("Gatekeeper mode enabled")


def disable_gatekeeper():
    """Disable captive portal - open access."""
    log("Disabling gatekeeper mode (open access)...")
    teardown_firewall()
    # Clear the nightly logs for the new day
    clear_request_log()
    clear_conversation_log()
    log("Gatekeeper mode disabled - internet access is open")


def expiry_checker_thread():
    """Background thread that checks for expired sessions every 30 seconds."""
    log("Starting expiry checker thread")
    while True:
        time.sleep(30)
        try:
            check_expired_sessions()
            check_focus_mode_expiry()
            check_voluntary_lockdown_expiry()
        except Exception as e:
            log(f"Error in expiry checker: {e}")


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTP server that handles each request in a separate thread."""
    daemon_threads = True  # Don't wait for threads on shutdown


def run_server():
    """Run the HTTP server."""
    # Start background thread for expiry checking
    expiry_thread = threading.Thread(target=expiry_checker_thread, daemon=True)
    expiry_thread.start()

    server = ThreadedHTTPServer(("0.0.0.0", SERVER_PORT), GatekeeperHandler)
    log(f"Gatekeeper server running on port {SERVER_PORT} (threaded)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def test_gemini():
    """Test the Gemini API connection."""
    log("Testing Gemini API connection...")
    response = call_gemini([{"role": "user", "content": "I need to check my work email for an urgent deadline."}])
    print(f"Response: {json.dumps(response, indent=2)}")
    return response.get("status") != "error"


def main():
    parser = argparse.ArgumentParser(description="LLM Gatekeeper for GL-MT3000")
    parser.add_argument("--mode", choices=["gatekeeper", "open"], help="Set access mode")
    parser.add_argument("--test", action="store_true", help="Test Gemini API connection")
    parser.add_argument("--server", action="store_true", help="Run HTTP server only (no firewall changes)")
    args = parser.parse_args()

    if args.test:
        success = test_gemini()
        sys.exit(0 if success else 1)

    if args.mode == "gatekeeper":
        enable_gatekeeper()
        run_server()
    elif args.mode == "open":
        disable_gatekeeper()
        sys.exit(0)
    elif args.server:
        run_server()
    else:
        # Default: run in gatekeeper mode
        enable_gatekeeper()
        run_server()


if __name__ == "__main__":
    main()
