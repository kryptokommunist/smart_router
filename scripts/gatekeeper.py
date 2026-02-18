#!/usr/bin/env python3
"""
LLM Gatekeeper for GL-MT3000 Router
Captive portal with Gemini AI justification for nighttime internet access.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import hashlib
import threading

# Configuration
GEMINI_API_KEY = "AIzaSyDw2hF98LRpKTs64VoO6HrKXVzeSHDSJk4"
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
SERVER_PORT = 2050
NDS_INTERFACE = "br-lan"

# Session storage (in-memory, cleared on restart)
sessions = {}  # {session_id: {"mac": str, "ip": str, "history": [], "questions_asked": int}}

# Rate limiting
rate_limit = {}  # {ip: {"count": int, "window_start": timestamp}}
RATE_LIMIT_WINDOW = 300  # 5 minutes
RATE_LIMIT_MAX = 10  # max requests per window

SYSTEM_PROMPT = """You are a gatekeeper AI controlling internet access during nighttime hours (9pm-5am).

Your role is to evaluate whether someone has a legitimate reason to access the internet right now, or if they should wait until morning.

## Access Rules:
- 10 minutes: Quick check that can't wait, would cause stress if delayed
- Up to 60 minutes: Work tasks, school assignments that must be done TODAY
- Up to 120 minutes: Video calls, Zoom meetings, voice calls

## Your behavior:
1. You may ask up to 3 clarifying questions if the reason is unclear
2. Be understanding but firm - most things CAN wait until morning
3. Mindless browsing, social media, entertainment = DENY
4. Legitimate work/emergency = APPROVE with appropriate duration

## Response format:
If you need clarification, respond with:
{"status": "question", "message": "Your clarifying question here"}

If you're ready to decide, respond with:
{"status": "approved", "duration": <minutes>, "message": "Brief explanation"}
or
{"status": "denied", "message": "Brief explanation of why they should wait"}

IMPORTANT: Always respond with valid JSON only. No markdown, no extra text."""


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


def call_gemini(conversation_history):
    """Call Gemini API with conversation history."""
    url = f"{GEMINI_ENDPOINT}?key={GEMINI_API_KEY}"

    contents = [{"role": "user", "parts": [{"text": SYSTEM_PROMPT}]}]
    contents.append({"role": "model", "parts": [{"text": "I understand. I will evaluate internet access requests and respond in JSON format only."}]})

    for msg in conversation_history:
        role = "user" if msg["role"] == "user" else "model"
        contents.append({"role": role, "parts": [{"text": msg["content"]}]})

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
            # Try to parse as JSON
            text = text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            return json.loads(text)
    except urllib.error.URLError as e:
        log(f"Gemini API error: {e}")
        return {"status": "error", "message": "Failed to reach AI service. Please try again."}
    except json.JSONDecodeError as e:
        log(f"JSON parse error: {e}")
        return {"status": "error", "message": "AI response was invalid. Please try again."}
    except Exception as e:
        log(f"Unexpected error: {e}")
        return {"status": "error", "message": "An error occurred. Please try again."}


def grant_access(mac, duration_minutes):
    """Grant internet access to a MAC address using ndsctl."""
    try:
        cmd = ["ndsctl", "auth", mac, str(duration_minutes * 60)]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            log(f"Granted {duration_minutes}min access to {mac}")
            return True
        else:
            log(f"ndsctl auth failed: {result.stderr}")
            return False
    except Exception as e:
        log(f"Failed to grant access: {e}")
        return False


def get_client_mac(ip):
    """Get MAC address for an IP from the ARP table."""
    try:
        result = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, check=False)
        parts = result.stdout.strip().split()
        if len(parts) >= 5:
            return parts[4].upper()
    except Exception:
        pass

    # Fallback: read /proc/net/arp
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


class GatekeeperHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the captive portal."""

    def log_message(self, format, *args):
        log(f"HTTP: {args[0]}")

    def send_html(self, html, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(html.encode("utf-8")))
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        client_ip = self.client_address[0]

        # Parse query parameters from NDS redirect
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # Get or create session
        mac = params.get("clientmac", [get_client_mac(client_ip)])[0]
        if mac:
            mac = mac.upper().replace("-", ":")

        session_id = None
        for sid, sess in sessions.items():
            if sess["ip"] == client_ip:
                session_id = sid
                break

        if not session_id and mac:
            session_id = generate_session_id(mac or "unknown", client_ip)
            sessions[session_id] = {
                "mac": mac,
                "ip": client_ip,
                "history": [],
                "questions_asked": 0
            }

        # Serve splash page
        self.serve_splash_page(session_id)

    def do_POST(self):
        client_ip = self.client_address[0]

        # Rate limiting
        if not check_rate_limit(client_ip):
            self.send_json({"status": "error", "message": "Too many requests. Please wait a few minutes."}, 429)
            return

        # Read POST body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self.send_json({"status": "error", "message": "Invalid request"}, 400)
            return

        session_id = data.get("session_id")
        message = data.get("message", "").strip()

        if not session_id or session_id not in sessions:
            self.send_json({"status": "error", "message": "Invalid session. Please refresh the page."}, 400)
            return

        if not message:
            self.send_json({"status": "error", "message": "Please provide a reason."}, 400)
            return

        session = sessions[session_id]

        # Add user message to history
        session["history"].append({"role": "user", "content": message})

        # Call Gemini
        response = call_gemini(session["history"])

        if response.get("status") == "question":
            session["questions_asked"] += 1
            session["history"].append({"role": "assistant", "content": json.dumps(response)})

            if session["questions_asked"] >= 3:
                # Force a decision after 3 questions
                session["history"].append({"role": "user", "content": "(Maximum clarifications reached. Please make a final decision.)"})
                response = call_gemini(session["history"])

        if response.get("status") == "approved":
            mac = session["mac"]
            duration = min(response.get("duration", 10), 120)  # Cap at 120 minutes

            if mac and grant_access(mac, duration):
                response["granted"] = True
            else:
                response = {"status": "error", "message": "Failed to grant access. Please contact admin."}

        self.send_json(response)

    def serve_splash_page(self, session_id):
        """Serve the captive portal splash page."""
        try:
            with open("/etc/nodogsplash/htdocs/splash.html", "r") as f:
                html = f.read()
                html = html.replace("{{SESSION_ID}}", session_id or "")
                html = html.replace("{{SERVER_PORT}}", str(SERVER_PORT))
        except FileNotFoundError:
            html = f"""<!DOCTYPE html>
<html>
<head><title>Internet Access</title></head>
<body>
<h1>Gatekeeper Active</h1>
<p>Session: {session_id}</p>
<p>Splash page not found. Please contact administrator.</p>
</body>
</html>"""

        self.send_html(html)


def enable_gatekeeper():
    """Enable nodogsplash captive portal."""
    log("Enabling gatekeeper mode...")
    subprocess.run(["/etc/init.d/nodogsplash", "start"], check=False)
    time.sleep(2)
    result = subprocess.run(["ndsctl", "status"], capture_output=True, text=True, check=False)
    if result.returncode == 0:
        log("Nodogsplash started successfully")
        return True
    else:
        log(f"Failed to start nodogsplash: {result.stderr}")
        return False


def disable_gatekeeper():
    """Disable nodogsplash captive portal - open access."""
    log("Disabling gatekeeper mode (open access)...")
    subprocess.run(["/etc/init.d/nodogsplash", "stop"], check=False)
    log("Nodogsplash stopped - internet access is open")
    return True


def run_server():
    """Run the HTTP server."""
    server = HTTPServer(("0.0.0.0", SERVER_PORT), GatekeeperHandler)
    log(f"Gatekeeper server running on port {SERVER_PORT}")
    server.serve_forever()


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
    parser.add_argument("--server", action="store_true", help="Run HTTP server only")
    args = parser.parse_args()

    if args.test:
        success = test_gemini()
        sys.exit(0 if success else 1)

    if args.mode == "gatekeeper":
        enable_gatekeeper()
        sys.exit(0)
    elif args.mode == "open":
        disable_gatekeeper()
        sys.exit(0)

    if args.server:
        run_server()
    else:
        # Default: start server
        run_server()


if __name__ == "__main__":
    main()
