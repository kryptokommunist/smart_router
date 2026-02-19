#!/usr/bin/env python3
"""
LLM Gatekeeper for GL-MT3000 Router
Standalone captive portal with Gemini AI justification for nighttime internet access.
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

# Configuration
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemma-3-27b-it:generateContent"
SERVER_PORT = 2050  # Use port 2050 for captive portal
API_PORT = 2051   # API port for chat
GATEWAY_IP = "192.168.8.1"
LAN_INTERFACE = "br-lan"
REQUEST_LOG_FILE = "/tmp/gatekeeper_requests.json"  # Persistent log for the night

# Authenticated MACs with expiry times
authenticated_macs = {}  # {mac: expiry_timestamp}

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


def clear_request_log():
    """Clear the request log (called when switching to open mode in the morning)."""
    try:
        if os.path.exists(REQUEST_LOG_FILE):
            os.remove(REQUEST_LOG_FILE)
            log("Request log cleared for new day")
    except Exception as e:
        log(f"Error clearing request log: {e}")


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

SYSTEM_PROMPT = """You are a gatekeeper AI controlling internet access during nighttime hours (9pm-5am).

Your role is to evaluate whether someone has a legitimate reason to access the internet right now, or if they should wait until morning.

## Access Rules:
- 10 minutes: Quick check that can't wait, would cause stress if delayed
- Up to 60 minutes: Work tasks, school assignments that must be done TODAY
- Up to 120 minutes: Video calls, Zoom meetings, voice calls

## Your behavior:
1. ALWAYS ask the user how much time they need (in minutes)
2. If they request MORE than 10 minutes:
   a. Ask them to justify why they need that specific amount of time
   b. REQUIRE them to upload proof (screenshot, email, document, calendar invite, etc.)
   c. When they upload an image, carefully examine it to verify their claim
3. You may ask up to 3 clarifying questions total
4. Be understanding but firm - most things CAN wait until morning
5. Mindless browsing, social media, entertainment = DENY
6. Legitimate work/emergency = APPROVE with appropriate duration

## Proof verification (for requests >10 minutes):
- When the user uploads an image, analyze it carefully
- Check if the image actually supports their stated reason
- Look for: email subject/content, due dates, calendar invites, assignment details
- Be suspicious of generic or irrelevant images
- If the image doesn't match their claim, DENY access
- If no proof is provided for >10 minutes, ask: "Please upload a screenshot as proof (email, calendar, assignment, etc.)"

## Conversation flow:
1. First, understand what they need to do
2. Ask: "How many minutes do you need?"
3. If >10 minutes:
   - Ask: "Why do you need [X] minutes specifically?"
   - Then say: "Please upload a screenshot as proof (email showing deadline, calendar invite, etc.)"
4. Verify the proof image matches their claim
5. Then make your decision

## Response format:
If you need clarification or proof, respond with:
{"status": "question", "message": "Your clarifying question or request for proof"}

If you're ready to decide, respond with:
{"status": "approved", "duration": <minutes>, "message": "Brief explanation"}
or
{"status": "denied", "message": "Brief explanation of why they should wait"}

IMPORTANT: Always respond with valid JSON only. No markdown, no extra text."""

SPLASH_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Internet Access Request</title>
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
.header { text-align: center; margin-bottom: 25px; }
.header h1 { font-size: 1.5rem; margin-bottom: 8px; color: #fff; }
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
        <h1>Nighttime Access Request</h1>
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
            Hi! Why do you need internet access right now? I'll evaluate if it's urgent enough.
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
        <label>
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
        initialMsg.textContent = "Hi! It's " + timeStr + ". Why do you need internet access right now? I'll evaluate if it's urgent enough.";
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
                    addMessage('Your internet access expires at ' + expiryStr + '. Tap Done when finished.', 'system');
                    disableInput();
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
    """Call Gemini API with conversation history (supports multimodal with images)."""
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

    for msg in conversation_history:
        role = "user" if msg["role"] == "user" else "model"
        parts = []

        # Handle text content
        if msg.get("content"):
            parts.append({"text": msg["content"]})

        # Handle image content (base64 data URL)
        if msg.get("image"):
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


def grant_access(mac, duration_minutes):
    """Grant internet access to a MAC address using iptables."""
    global authenticated_macs
    expiry = time.time() + (duration_minutes * 60)
    authenticated_macs[mac] = expiry

    try:
        # 1. Remove any existing rules for this MAC first
        subprocess.run(["iptables", "-t", "filter", "-D", "FORWARD", "-i", LAN_INTERFACE,
                       "-o", "eth0", "-m", "mac", "--mac-source", mac, "-j", "ACCEPT"],
                      capture_output=True, check=False)
        subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-i", LAN_INTERFACE,
                       "-m", "mac", "--mac-source", mac, "-j", "RETURN"],
                      capture_output=True, check=False)

        # 2. Add NAT rule to skip HTTP redirect for this MAC (must be BEFORE the redirect rule)
        subprocess.run(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-i", LAN_INTERFACE,
                       "-m", "mac", "--mac-source", mac, "-j", "RETURN"],
                      check=True)

        # 3. Add FORWARD rule to allow internet access for this MAC
        subprocess.run(["iptables", "-t", "filter", "-I", "FORWARD", "1", "-i", LAN_INTERFACE,
                       "-o", "eth0", "-m", "mac", "--mac-source", mac, "-j", "ACCEPT"],
                      check=True)

        log(f"Granted {duration_minutes}min access to {mac}")
        return True
    except Exception as e:
        log(f"Failed to grant access: {e}")
        return False


def revoke_access(mac):
    """Revoke internet access for a MAC address and kick from WiFi."""
    global authenticated_macs
    if mac in authenticated_macs:
        del authenticated_macs[mac]
    try:
        # Remove NAT bypass rule
        subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-i", LAN_INTERFACE,
                       "-m", "mac", "--mac-source", mac, "-j", "RETURN"],
                      capture_output=True, check=False)
        # Remove FORWARD allow rule
        subprocess.run(["iptables", "-t", "filter", "-D", "FORWARD", "-i", LAN_INTERFACE,
                       "-o", "eth0", "-m", "mac", "--mac-source", mac, "-j", "ACCEPT"],
                      capture_output=True, check=False)
        log(f"Revoked access for {mac}")

        # Kick client from WiFi to force reconnect and captive portal
        log(f"Kicking {mac} from WiFi...")
        kick_wifi_clients()
    except Exception:
        pass


def check_expired_sessions():
    """Check and revoke expired sessions."""
    global authenticated_macs
    now = time.time()
    expired = [mac for mac, expiry in authenticated_macs.items() if expiry < now]
    for mac in expired:
        revoke_access(mac)


def is_mac_authenticated(mac):
    """Check if a MAC is currently authenticated."""
    check_expired_sessions()
    return mac in authenticated_macs


class GatekeeperHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the captive portal."""

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
        """Handle GET requests - serve splash page."""
        client_ip = self.client_address[0]
        mac = get_client_mac(client_ip)

        # If already authenticated, redirect to success
        if mac and is_mac_authenticated(mac):
            self.send_response(302)
            self.send_header("Location", "http://connectivitycheck.gstatic.com/generate_204")
            self.end_headers()
            return

        # Serve splash page
        self.send_html(SPLASH_HTML)

    def do_POST(self):
        """Handle POST requests - chat API."""
        client_ip = self.client_address[0]
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path != "/chat":
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

        self.handle_chat(data, client_ip)

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

            if mac_addr and grant_access(mac_addr, duration):
                response["granted"] = True
                log(f"Access approved for {mac_addr}: {duration} minutes")
                # Log to persistent request log
                first_message = session["history"][0]["content"] if session["history"] else "Unknown"
                add_request_to_log(mac_addr, first_message, "approved", duration)
            else:
                log(f"Failed to grant access for MAC={mac_addr}")
                response = {"status": "error", "message": "Failed to grant access. Please try again."}

        elif response.get("status") == "denied":
            log(f"Access denied for {session['mac']}: {response.get('message', 'No reason')}")
            # Log to persistent request log
            first_message = session["history"][0]["content"] if session["history"] else "Unknown"
            add_request_to_log(session["mac"], first_message, "denied")

        response["session_id"] = session_id
        self.send_json(response)


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

    # Simple approach: redirect ALL HTTP from LAN to our portal (except to gateway itself)
    subprocess.run(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-i", LAN_INTERFACE,
                   "-p", "tcp", "--dport", "80", "!", "-d", GATEWAY_IP,
                   "-j", "REDIRECT", "--to-port", str(SERVER_PORT)], check=False)

    # Block all forwarding from LAN to WAN (internet) - MUST be at position 1 to be before ESTABLISHED rule
    subprocess.run(["iptables", "-t", "filter", "-I", "FORWARD", "1", "-i", LAN_INTERFACE,
                   "-o", "eth0", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"], check=False)

    # Flush connection tracking to kill existing connections
    subprocess.run(["conntrack", "-F"], capture_output=True, check=False)

    log("Firewall rules configured")


def teardown_firewall():
    """Remove iptables rules."""
    log("Removing firewall rules...")
    # Remove HTTP redirect
    subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-i", LAN_INTERFACE,
                   "-p", "tcp", "--dport", "80", "!", "-d", GATEWAY_IP,
                   "-j", "REDIRECT", "--to-port", str(SERVER_PORT)],
                  capture_output=True, check=False)
    # Remove forward block
    subprocess.run(["iptables", "-t", "filter", "-D", "FORWARD", "-i", LAN_INTERFACE,
                   "-o", "eth0", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"],
                  capture_output=True, check=False)
    # Remove any per-MAC allow rules
    for mac in list(authenticated_macs.keys()):
        subprocess.run(["iptables", "-t", "filter", "-D", "FORWARD", "-i", LAN_INTERFACE,
                       "-o", "eth0", "-m", "mac", "--mac-source", mac, "-j", "ACCEPT"],
                      capture_output=True, check=False)
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
    # Clear the request log for the new day
    clear_request_log()
    log("Gatekeeper mode disabled - internet access is open")


def run_server():
    """Run the HTTP server."""
    server = HTTPServer(("0.0.0.0", SERVER_PORT), GatekeeperHandler)
    log(f"Gatekeeper server running on port {SERVER_PORT}")
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
