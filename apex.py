#!/usr/bin/env python3
"""Apex - passive link/phishing/vulnerability analyzer. Run: python3 apex.py  (or install as `apex`).
Only scan targets you own or have written permission to test. Passive: GET requests, headers, TLS, RDAP."""
import json, re, socket, ssl, ipaddress, shutil, subprocess, threading, webbrowser, difflib, datetime, sys, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, urljoin
from html.parser import HTMLParser
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    sys.exit("Missing dependency. Run: sudo apt install python3-requests")

UA = {"User-Agent": "Mozilla/5.0 (Apex passive scanner)"}
BAD_TLD = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "zip", "work", "support", "live", "icu"}
KW = ["login", "signin", "verify", "secure", "update", "account", "bank", "wallet", "confirm", "password", "billing"]
BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram", "netflix", "whatsapp",
          "paytm", "hdfc", "icici", "binance", "cloudflare", "github"]
TUNNELS = {"trycloudflare.com", "ngrok-free.app", "ngrok.io", "loca.lt", "serveo.net"}
OWN = {"trycloudflare.com", "cloudflare.com"}
ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
PORT = 0


class Page(HTMLParser):
    def __init__(s):
        super().__init__(); s.forms = []; s.pw = 0; s.frames = 0
    def handle_starttag(s, t, a):
        a = dict(a)
        if t == "form": s.forms.append(a.get("action") or "")
        elif t == "input" and (a.get("type") or "").lower() == "password": s.pw += 1
        elif t == "iframe": s.frames += 1


def regdom(h):
    l = h.split(".")
    if len(l) > 2 and len(l[-1]) == 2 and l[-2] in ("co", "com", "org", "net", "gov", "ac"): return ".".join(l[-3:])
    return ".".join(l[-2:])


def blocked(h):
    try:
        for i in socket.getaddrinfo(h, None):
            a = ipaddress.ip_address(i[4][0])
            if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast: return True
    except Exception:
        pass
    return False


def scan(raw):
    F, log, sc = [], [], [0]
    def add(sev, t, conf, ev, why, fix, pts=0):
        F.append([sev, t, conf, str(ev), why, fix]); sc[0] += pts
    url = raw.strip()
    if not url: return {"error": "Paste a link first."}
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url): url = "https://" + url
    try:
        p = urlparse(url); host = (p.hostname or "").lower(); port = p.port
    except ValueError:
        return {"error": "The link has an invalid port number."}
    if p.scheme not in ("http", "https") or not host: return {"error": "Not a valid http(s) link."}
    isip = False
    try: ipaddress.ip_address(host); isip = True
    except ValueError: pass
    reg = host if isip else regdom(host)
    sub = "" if isip or host == reg else host[:-len(reg) - 1]
    tld = host.split(".")[-1]
    tunnel = reg in TUNNELS
    log.append("Target: " + url)

    # --- URL pattern checks (always run, no network) ---
    if p.scheme == "http": add("High", "Link uses HTTP, not HTTPS", "Confirmed", "scheme: http", "Anything typed on this page travels unencrypted.", "Serve the site over HTTPS and redirect HTTP to it.", 15)
    if isip: add("High", "IP address used instead of a domain", "Confirmed", "host: " + host, "Legitimate services rarely ask users to visit a raw IP.", "Use a proper domain name.", 25)
    if p.username is not None: add("High", "Username or '@' inside the link", "Confirmed", p.netloc, "Text before '@' is ignored by the browser and can disguise the real destination.", "Do not open the link.", 20)
    if "xn--" in host: add("High", "Punycode domain (possible lookalike characters)", "Likely", host, "Punycode lets attackers mimic a real domain with similar-looking characters.", "Check the decoded domain carefully.", 20)
    if sub and sub.count(".") >= 2: add("Medium", "Many subdomain levels", "Confirmed", host, "Long subdomain chains are used to hide the real registered domain.", "Look at the registered domain: " + reg, 10)
    if not isip and tld in BAD_TLD: add("Medium", "Domain ends in a high-abuse TLD", "Likely", "." + tld, "These TLDs are cheap and often used for throwaway phishing domains.", "Treat with extra suspicion.", 10)
    hits = [k for k in KW if k in host or k in p.path.lower()]
    if hits: add("Medium", "Phishing-style words in the link", "Possible", ", ".join(hits), "Words like login or verify are common in credential-theft links.", "Confirm the domain belongs to the real company.", 10)
    if tunnel: add("Medium", "Temporary tunnel domain", "Likely", reg, "Anyone can publish any page on a tunnel domain within seconds, and phishing kits use them. The domain says nothing about who owns the page.", "Judge the page content, not the domain.", 10)
    if host.count("-") >= 3 and not tunnel: add("Low", "Many hyphens in the domain", "Possible", host, "Hyphen-stuffed names are a common phishing pattern.", "Check the registered domain.", 5)
    if len(url) > 100: add("Low", "Very long link", "Possible", str(len(url)) + " characters", "Long links can hide the real destination.", "Inspect the domain part only.", 5)
    if port not in (None, 80, 443): add("Low", "Non-standard port", "Confirmed", "port " + str(port), "Unusual ports are uncommon for public websites.", "Check why this port is used.", 5)
    label = reg.split(".")[0]
    for b in BRANDS:
        if isip or label == b or reg in OWN: continue
        if b in host: add("High", "Brand name '%s' used on an unrelated domain" % b, "Likely", host, "Attackers put a trusted brand in the link to look genuine.", "The real owner is the registered domain, here: " + reg, 20); break
        if any(difflib.SequenceMatcher(None, w, b).ratio() >= 0.8 and w != b for w in label.split('-')): add("High", "Domain looks like a misspelling of '%s'" % b, "Likely", label + " vs " + b, "Typosquatting imitates a known brand with small changes.", "Check the spelling carefully.", 20); break

    # --- DNS ---
    ips = []
    try:
        ips = sorted({i[4][0] for i in socket.getaddrinfo(host, port or (443 if p.scheme == "https" else 80))})
        log.append("DNS: " + ", ".join(ips))
    except Exception as e:
        add("Medium", "Domain does not resolve", "Confirmed", str(e), "The name has no DNS record, so the link cannot be reached (invalid, expired or taken down).", "Check the spelling of the link.", 5)
        log.append("DNS failed: " + str(e))
    if ips and blocked(host):
        return {"error": "Blocked: this host resolves to a private or local address. Apex only scans public targets."}

    # --- Redirect chain + page fetch ---
    hops, resp, body, cur = [], None, "", url
    if ips:
        for _ in range(8):
            h = urlparse(cur).hostname or ""
            if blocked(h):
                add("High", "Redirect points to a private address", "Confirmed", cur, "A redirect to an internal address is a server-side request trick.", "Do not follow it.", 20); break
            try:
                resp = requests.get(cur, headers=UA, timeout=7, allow_redirects=False, verify=False, stream=True)
            except Exception as e:
                add("Medium", "Could not connect", "Confirmed", str(e)[:200], "The server did not answer a normal request.", "It may be offline or blocking scanners.")
                log.append("GET failed: " + str(e)[:200]); resp = None; break
            hops.append([resp.status_code, cur]); log.append("GET %s -> %s" % (cur, resp.status_code))
            loc = resp.headers.get("location")
            if resp.is_redirect and loc: cur = urljoin(cur, loc); resp.close(); continue
            break
    fin = urlparse(cur)
    hdr, tlsrows, forms_bad, pw = [], [], 0, 0
    if resp is not None:
        try: body = resp.raw.read(300000, decode_content=True).decode("utf-8", "ignore")
        except Exception: body = ""
        H = resp.headers; lower = {k.lower() for k in H}
        if len(hops) > 3: add("Medium", "Long redirect chain (%d hops)" % len(hops), "Confirmed", " > ".join(str(x[0]) for x in hops), "Many hops are used to hide the final page.", "Inspect the Redirects tab.", 10)
        if fin.hostname and regdom(fin.hostname) != reg and not isip: add("Medium", "Redirects to a different domain", "Confirmed", reg + " -> " + regdom(fin.hostname), "The page you land on is not on the domain in the link.", "Judge the final domain, not the first link.", 15)
        cf = "cf-ray" in lower or "cloudflare" in H.get("server", "").lower()
        if cf: add("Info", "Site is behind Cloudflare", "Confirmed", "server: %s, cf-ray present" % H.get("server", ""), "Cloudflare hides the real server, so server-level checks reflect Cloudflare, not the origin.", "Scan the origin only if you own it.")
        if resp.status_code in (403, 503) and (cf and "just a moment" in body.lower()):
            add("Info", "Cloudflare challenge page returned", "Confirmed", "HTTP %d, 'Just a moment'" % resp.status_code, "Cloudflare blocked the scanner, so page content could not be checked.", "Open the link in a browser to view the real page.")
        checks = [("strict-transport-security", "HSTS", "Medium", fin.scheme == "https"), ("content-security-policy", "CSP", "Medium", True),
                  ("x-frame-options", "X-Frame-Options", "Medium", "frame-ancestors" not in H.get("content-security-policy", "")),
                  ("x-content-type-options", "X-Content-Type-Options", "Low", True), ("referrer-policy", "Referrer-Policy", "Low", True)]
        for k, n, sev, applies in checks:
            ok = k in lower
            hdr.append([k, ok, H.get(k, "")[:120]])
            if not ok and applies: add(sev, "Missing " + n + " header", "Confirmed", "header absent", "The browser has no instruction for this protection.", "Add the " + n + " response header.")
        sv = H.get("server", "")
        if re.search(r"\d", sv): add("Low", "Server version disclosed", "Likely", "Server: " + sv, "Version strings help attackers match known CVEs. Verify the real patch level.", "Hide the version and keep software updated.")
        for c in resp.raw.headers.getlist("Set-Cookie"):
            lc = c.lower(); miss = [n for n, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in lc]
            if miss: add("Low", "Cookie '%s' missing %s" % (c.split("=")[0][:40], "/".join(miss)), "Confirmed", "Set-Cookie flags", "Missing flags make session cookies easier to steal.", "Set Secure, HttpOnly and SameSite.")
        if "html" in H.get("content-type", "").lower() and body:
            pg = Page()
            try: pg.feed(body)
            except Exception: pass
            pw = pg.pw
            for a in pg.forms:
                fh = urlparse(urljoin(cur, a)).hostname
                if fh and fin.hostname and regdom(fh) != regdom(fin.hostname): forms_bad += 1; add("Critical", "Form submits to another domain", "Confirmed", "action -> " + fh, "Data typed into this form is sent to a different site than the one you see.", "Do not enter anything.", 30)
            if pw: add("Medium", "Page asks for a password", "Confirmed", "%d password field(s)" % pw, "Combined with other signals, this suggests credential harvesting.", "Only enter passwords on domains you trust.", 10 if (sc[0] > 0) else 0)
            if pg.frames: add("Low", "Page embeds iframes", "Possible", "%d iframe(s)" % pg.frames, "Hidden frames can load content from other sites.", "Review what is embedded.")

    # --- TLS certificate ---
    if ips and fin.scheme == "https" and resp is not None:
        th = fin.hostname; tp = fin.port or 443
        try:
            with socket.create_connection((th, tp), timeout=6) as s:
                with ssl.create_default_context().wrap_socket(s, server_hostname=th) as t:
                    c = t.getpeercert(); ver = t.version()
            iss = dict(x[0] for x in c["issuer"]).get("organizationName", "unknown")
            left = int((ssl.cert_time_to_seconds(c["notAfter"]) - datetime.datetime.now().timestamp()) // 86400)
            tlsrows = [["Verification", "passed", 0], ["Protocol", ver, None], ["Issuer", iss, None], ["Valid until", c["notAfter"], None], ["Days left", str(left), 1 if left < 14 else 0]]
            if left < 14: add("Medium", "Certificate expires soon", "Confirmed", "%d days left" % left, "An expiring certificate causes browser warnings.", "Renew the certificate.")
        except ssl.SSLCertVerificationError as e:
            tlsrows = [["Verification", "FAILED: " + e.verify_message, 1]]
            add("High", "TLS certificate failed verification", "Confirmed", e.verify_message, "Browsers will warn: the certificate is expired, self-signed or for another name.", "Install a valid certificate.", 15)
        except Exception as e:
            tlsrows = [["TLS", "could not check: " + str(e)[:100], 1]]
    elif fin.scheme == "http" and resp is not None: tlsrows = [["Certificate", "none (site served over HTTP)", 1]]

    # --- Domain age via RDAP ---
    age = None
    if tunnel:
        log.append("RDAP skipped: tunnel domain age says nothing about the page")
    elif not isip and ips:
        try:
            r = requests.get("https://rdap.org/domain/" + reg, headers=UA, timeout=7)
            ev = {e["eventAction"]: e["eventDate"] for e in r.json().get("events", [])}
            d = datetime.datetime.fromisoformat(ev["registration"].replace("Z", "+00:00"))
            age = (datetime.datetime.now(datetime.timezone.utc) - d).days
            log.append("RDAP: %s registered %d days ago" % (reg, age))
            if age < 30: add("High", "Domain registered %d days ago" % age, "Confirmed", "RDAP registration date", "Phishing domains are usually days old.", "Treat as untrusted.", 25)
            elif age < 180: add("Medium", "Domain is under 6 months old", "Confirmed", "%d days" % age, "New domains have no reputation yet.", "Check who owns it.", 10)
        except Exception:
            log.append("RDAP: age unavailable")
            add("Info", "Domain age unavailable", "Possible", "RDAP lookup failed or TLD unsupported", "Age could not be verified.", "Check WHOIS manually.")

    F.sort(key=lambda f: ORDER[f[0]]); s = min(sc[0], 100)
    verdict = "Likely phishing" if s >= 50 else "Suspicious" if s >= 25 else "No strong phishing signals"
    ph = [["Registered domain", reg, None], ["Subdomains", sub or "none", 1 if sub.count(".") >= 2 else 0],
          ["Domain age", ("%d days" % age) if age is not None else ("n/a (tunnel domain)" if tunnel else "unavailable"), 1 if (age is not None and age < 30) else None],
          ["Final URL", cur, None], ["Resolved IPs", ", ".join(ips) or "none", None],
          ["Password fields", str(pw), 1 if pw else 0], ["Forms to other domains", str(forms_bad), 1 if forms_bad else 0]]
    return {"target": url, "verdict": verdict, "score": s, "findings": F, "phish": ph, "tls": tlsrows, "headers": hdr,
            "hops": hops, "raw": "\n".join(log), "note": "Passive scan results are evidence-based, not a guarantee. Verify 'Likely' and 'Possible' items manually."}


HTML = r'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Apex</title>
<style>
:root{--bg:#0a0517;--panel:#120a26;--p2:#1c1140;--line:#33206b;--tx:#f1eaff;--mut:#a08fd0;--acc:#a66bff;--ok:#56d3a3;--bad:#ff5d73}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1200px 600px at 20% -10%,#1d0f45 0%,var(--bg) 60%);color:var(--tx);font:14px/1.45 system-ui,"Segoe UI",sans-serif;height:100vh;display:flex;flex-direction:column}
.mono,pre,.ev{font-family:ui-monospace,Menlo,Consolas,monospace}
.body{display:grid;grid-template-columns:180px 1fr;flex:1;min-height:0}
.side{background:var(--panel);border-right:1px solid var(--line);padding:10px 0;overflow:auto}
.brand{padding:6px 16px 14px;font-size:20px;font-weight:800;letter-spacing:.5px;color:var(--acc)}
.side button{display:block;width:100%;text-align:left;background:none;border:0;border-left:3px solid transparent;color:var(--mut);padding:9px 16px;font:inherit;cursor:pointer}
.side button:hover{color:var(--tx);background:var(--p2)}.side button.on{color:var(--tx);border-left-color:var(--acc);background:var(--p2)}
.main{display:flex;flex-direction:column;min-width:0}
.bar{display:flex;gap:8px;padding:10px;border-bottom:1px solid var(--line);flex-wrap:wrap;align-items:center;background:var(--panel)}
.bar input[type=text]{flex:1 1 280px;background:var(--bg);border:1px solid var(--line);border-radius:6px;color:var(--tx);padding:9px 10px;font:13px ui-monospace,Menlo,monospace}
.bar label{color:var(--mut);font-size:12.5px;display:flex;gap:6px;align-items:center}
.btn{background:var(--acc);border:0;color:#10052a;font-weight:700;border-radius:6px;padding:9px 18px;cursor:pointer;font:inherit;font-weight:700}.btn:disabled{opacity:.5}
:focus-visible{outline:2px solid var(--acc);outline-offset:1px}
.pane{flex:1;overflow:auto;padding:12px}
.sum{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}.chip{padding:5px 11px;border-radius:5px;background:var(--p2);border-left:4px solid var(--c)}.chip b{margin-right:5px;font-size:15px}
table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;color:var(--mut);font-weight:500;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:7px 8px;border-bottom:1px solid #24174f;vertical-align:top}tr.r{cursor:pointer}tr.r:hover,tr.r.on{background:var(--p2)}
.sev{display:inline-block;min-width:62px;text-align:center;padding:1px 7px;border-radius:4px;font-size:12px;font-weight:700;color:#150a28;background:var(--c)}
.Confirmed{color:var(--ok)}.Likely{color:#f2cf55}.Possible{color:var(--mut)}.ev{color:var(--mut);font-size:12px;word-break:break-all}
.det{margin-top:12px;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px}.det h3{margin:0 0 6px}.det p{margin:4px 0;color:var(--mut)}.det b{color:var(--tx)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px;margin:0;overflow:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-all}
.verdict{display:flex;gap:18px;align-items:center;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:14px;margin-bottom:12px;flex-wrap:wrap}.score{font-size:34px;font-weight:800}
.meter{flex:1 1 200px;height:10px;background:var(--p2);border-radius:5px;overflow:hidden}.meter i{display:block;height:100%}
.kv{display:grid;grid-template-columns:190px 1fr;gap:1px;background:var(--line);border:1px solid var(--line);border-radius:8px;overflow:hidden}.kv div{background:var(--bg);padding:8px 10px;word-break:break-all}.kv .k{color:var(--mut)}
.ok{color:var(--ok)}.bad{color:var(--bad)}.empty{color:var(--mut);text-align:center;padding:60px 10px}.status{border-top:1px solid var(--line);background:var(--panel);padding:6px 12px;color:var(--mut);font-size:12.5px}
#sp{position:fixed;inset:0;z-index:99;background:radial-gradient(900px 520px at 50% 38%,#2a1366 0%,#0a0517 68%);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;transition:opacity .6s}
#sp.out{opacity:0;pointer-events:none}
#sp svg{width:92px;height:92px;filter:drop-shadow(0 0 20px #7c3aed99);animation:pl 2.4s ease-in-out infinite}
#sp h1{margin:6px 0 0;font-size:46px;letter-spacing:12px;font-weight:800;padding-left:12px;color:#f1eaff}
#sp .tag{color:var(--mut);letter-spacing:1.5px;font-size:13px;margin-bottom:14px}
#sp .pb{width:300px;height:3px;background:#1c1140;border-radius:2px;overflow:hidden}
#sp .pb i{display:block;height:100%;width:0;background:linear-gradient(90deg,#6d28d9,#c4a1ff);}
#sp .msg{height:18px;color:var(--mut);font-size:12.5px}
#sp .ver{position:absolute;bottom:18px;color:#6f5fa3;font-size:12px}
@keyframes pl{50%{transform:scale(1.05)}}
@media(prefers-reduced-motion:reduce){#sp svg{animation:none}}
</style></head><body><div id="sp"><svg viewBox="0 0 64 64" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M32 4 56 14v18c0 14-10 24-24 28C18 56 8 46 8 32V14z" stroke="#a66bff" stroke-width="3"/><path d="M22 42 32 20l10 22M26 36h12" stroke="#f1eaff" stroke-width="3.5"/></svg><h1>APEX</h1><div class="tag">Link and web security analyzer</div><div class="pb"><i id="spb"></i></div><div class="msg" id="spm">Starting...</div><div class="ver">Apex 1.0 - passive scanning only</div></div>
<div class="body"><nav class="side" id="side"></nav><section class="main">
<div class="bar"><input type="text" id="t" placeholder="Paste a link (valid or invalid) and press Scan" autofocus aria-label="Target link">
<label><input type="checkbox" id="auth">I own this target or have permission</label><button class="btn" id="go">Scan</button></div>
<div class="pane" id="pane"><div class="empty">Paste a link, tick the authorization box and press Scan.</div></div>
<div class="status" id="st">Ready</div></section></div>
<script>
const SEV={Critical:'#ff5d73',High:'#ff9152',Medium:'#f2cf55',Low:'#6db6ff',Info:'#a597c9'};
const NAV=['Findings','Phishing','SSL/TLS','Headers','Redirects','Raw Output','History'];
const $=i=>document.getElementById(i),esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let hist=[],cur=null,tab='Findings',sel=0;
const kv=r=>'<div class="kv">'+r.map(x=>`<div class="k">${esc(x[0])}</div><div class="${x[2]===1?'bad':x[2]===0?'ok':''}">${esc(x[1])}</div>`).join('')+'</div>';
function view(){const r=cur;if(tab==='History')return hist.length?'<table><tr><th>Target</th><th>Verdict</th><th>Score</th></tr>'+hist.map((h,i)=>`<tr class="r" data-h="${i}"><td class="ev">${esc(h.target)}</td><td>${esc(h.verdict)}</td><td>${h.score}</td></tr>`).join('')+'</table>':'<div class="empty">No scans yet this session.</div>';
 if(!r)return '<div class="empty">Paste a link, tick the authorization box and press Scan.</div>';
 if(tab==='Findings'){const c={};r.findings.forEach(f=>c[f[0]]=(c[f[0]]||0)+1);let h='<div class="sum">'+Object.keys(SEV).map(s=>`<span class="chip" style="--c:${SEV[s]}"><b>${c[s]||0}</b>${s}</span>`).join('')+'</div>';
  h+='<table><tr><th>Severity</th><th>Issue</th><th>Confidence</th><th>Evidence</th></tr>'+r.findings.map((f,i)=>`<tr class="r ${i===sel?'on':''}" data-i="${i}"><td><span class="sev" style="--c:${SEV[f[0]]}">${f[0]}</span></td><td>${esc(f[1])}</td><td class="${f[2]}">${f[2]}</td><td class="ev">${esc(f[3])}</td></tr>`).join('')+'</table>';
  const f=r.findings[sel];if(f)h+=`<div class="det"><h3>${esc(f[1])}</h3><p><b>What it means:</b> ${esc(f[4])}</p><p><b>How to fix:</b> ${esc(f[5])}</p><p><b>Evidence:</b> <span class="ev">${esc(f[3])}</span></p></div>`;
  return h+`<p class="ev">${esc(r.note)}</p>`}
 if(tab==='Phishing'){const col=r.score>=50?'#ff5d73':r.score>=25?'#f2cf55':'#56d3a3';return `<div class="verdict"><div><div style="color:var(--mut)">Verdict</div><div style="font-size:20px;font-weight:700;color:${col}">${esc(r.verdict)}</div></div><div class="score" style="color:${col}">${r.score}<span style="font-size:15px;color:var(--mut)">/100</span></div><div class="meter"><i style="width:${r.score}%;background:${col}"></i></div></div>`+kv(r.phish)}
 if(tab==='SSL/TLS')return r.tls.length?kv(r.tls):'<div class="empty">No TLS data (host unreachable).</div>';
 if(tab==='Headers')return r.headers.length?'<table><tr><th>Header</th><th>Status</th><th>Value</th></tr>'+r.headers.map(h=>`<tr><td class="ev">${esc(h[0])}</td><td class="${h[1]?'ok':'bad'}">${h[1]?'present':'missing'}</td><td class="ev">${esc(h[2])}</td></tr>`).join('')+'</table>':'<div class="empty">No response headers (host unreachable).</div>';
 if(tab==='Redirects')return r.hops.length?kv(r.hops.map((h,i)=>['Hop '+(i+1),h[0]+'  '+h[1]])):'<div class="empty">No HTTP response.</div>';
 return '<pre>'+esc(r.raw)+'</pre>'}
function draw(){$('side').innerHTML='<div class="brand">APEX</div>'+NAV.map(n=>`<button class="${n===tab?'on':''}">${n}</button>`).join('');
 $('side').querySelectorAll('button').forEach((b,i)=>b.onclick=()=>{tab=NAV[i];draw()});$('pane').innerHTML=view();
 $('pane').querySelectorAll('tr[data-i]').forEach(r=>r.onclick=()=>{sel=+r.dataset.i;draw()});
 $('pane').querySelectorAll('tr[data-h]').forEach(r=>r.onclick=()=>{cur=hist[+r.dataset.h];sel=0;tab='Findings';draw()})}
async function scan(){const u=$('t').value;if(!u.trim())return;$('go').disabled=true;$('st').textContent='Scanning '+u+' ...';
 try{const r=await (await fetch('/scan',{method:'POST',body:JSON.stringify({url:u,auth:$('auth').checked})})).json();
  if(r.error){$('st').textContent=r.error;$('pane').innerHTML='<div class="empty">'+esc(r.error)+'</div>'}
  else{cur=r;hist.unshift(r);sel=0;tab='Findings';draw();$('st').textContent='Done: '+r.findings.length+' findings, score '+r.score+'/100'}}
 catch(e){$('st').textContent='Scan failed: '+e}$('go').disabled=false}
$('go').onclick=scan;$('t').onkeydown=e=>{if(e.key==='Enter')scan()};draw();
</script><script>(()=>{const sp=document.getElementById('sp'),pb=document.getElementById('spb'),m=document.getElementById('spm');
const M=[[0,'Starting Apex engine'],[22,'Loading analysis modules'],[48,'Checking installed security tools'],[76,'Preparing secure workspace'],[97,'Ready']],T=3600;let tools=null;
fetch('/status').then(r=>r.json()).then(j=>tools=j.tools).catch(()=>{});
const t0=performance.now();
(function f(now){const p=Math.min(1,(now-t0)/T),e=p*p*(3-2*p),pc=e*100;pb.style.width=pc+'%';
 let i=0;M.forEach((x,k)=>{if(pc>=x[0])i=k});let txt=M[i][1]+'...';
 if(i===2&&tools){const g=Object.keys(tools).filter(k=>tools[k]);txt='Extra tools found: '+(g.join(', ')||'none (built-in checks only)')}
 if(m.textContent!==txt)m.textContent=txt;
 if(p<1)requestAnimationFrame(f);else setTimeout(()=>{sp.classList.add('out');setTimeout(()=>sp.remove(),700)},350)})(t0);
})();</script></body></html>'''


class H(BaseHTTPRequestHandler):
    def log_message(s, *a): pass
    def _ok(s):
        return s.headers.get("Host") == "127.0.0.1:%d" % PORT
    def _send(s, code, data, ctype):
        s.send_response(code); s.send_header("Content-Type", ctype); s.send_header("Content-Length", str(len(data))); s.end_headers(); s.wfile.write(data)
    def do_GET(s):
        if not s._ok(): return s._send(403, b"forbidden", "text/plain")
        if s.path == "/status":
            tools = {t: bool(shutil.which(t)) for t in ("nmap", "nuclei", "sslscan", "nikto", "whatweb")}
            return s._send(200, json.dumps({"version": "1.0", "tools": tools}).encode(), "application/json")
        s._send(200, HTML.encode(), "text/html; charset=utf-8")
    def do_POST(s):
        if not s._ok() or s.headers.get("Origin") not in (None, "http://127.0.0.1:%d" % PORT): return s._send(403, b"forbidden", "text/plain")
        try:
            d = json.loads(s.rfile.read(int(s.headers.get("Content-Length", 0))) or b"{}")
            out = scan(d.get("url", "")) if d.get("auth") else {"error": "Tick the authorization box first."}
        except Exception as e:
            out = {"error": "Scan error: " + str(e)}
        s._send(200, json.dumps(out).encode(), "application/json")


def main():
    global PORT
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H); PORT = srv.server_address[1]
    url = "http://127.0.0.1:%d/" % PORT
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    for b in ("chromium", "chromium-browser", "google-chrome", "brave-browser"):
        if shutil.which(b):
            cmd = [b, "--app=" + url, "--window-size=1200,780", "--user-data-dir=/tmp/apex-profile"]
            if hasattr(os, "geteuid") and os.geteuid() == 0: cmd.append("--no-sandbox")
            try: subprocess.Popen(cmd, stderr=subprocess.DEVNULL).wait(); return
            except Exception: pass
    webbrowser.open(url); print("Apex running at " + url + "  (Ctrl+C to quit)")
    try: threading.Event().wait()
    except KeyboardInterrupt: pass


if __name__ == "__main__":
    main()
