#!/usr/bin/env python
# vlessbank webui: panel stdlib-only, gaya UI seragam dengan Paypan.
# login: username+password (file webui.login, auto-generate admin/admin pertama kali)
# jalan: python webui.py [--port 9000] [--listen 127.0.0.1] [--xray xray]
import base64
import hashlib
import html
import json
import os
import secrets
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from gen import build_outbound

ACC = os.path.join(HERE, "accounts.txt")
CFG = os.path.join(HERE, "config.json")
LOGF = os.path.join(HERE, "xray.log")
SETF = os.path.join(HERE, "webui.settings.json")
LOGINF = os.path.join(HERE, "webui.login")

def arg(name, default):
    a = sys.argv
    return a[a.index(name) + 1] if name in a else default

PORT_WEB = int(arg("--port", "9000"))
LISTEN = arg("--listen", "127.0.0.1")
XRAY = arg("--xray", "xray")

# ---------- settings ----------

DEFAULTS = {"xray": "", "base": 1081, "base_http": 0, "listen": "127.0.0.1",
            "auth": "", "tunnel": "", "tunnel_id": "", "xray_path": XRAY,
            "insecure": False}

def load_set():
    s = dict(DEFAULTS)
    if os.path.exists(SETF):
        try:
            s.update(json.load(open(SETF, encoding="utf-8")))
        except Exception:
            pass
    return s

SET = load_set()
BASE = int(SET["base"])
AUTH = SET["auth"]
TUNNEL = SET["tunnel"]
TUNNELID = SET["tunnel_id"]
XRAYBIN = SET["xray_path"] or XRAY

def save_set(d):
    global SET, BASE, AUTH, TUNNEL, TUNNELID, XRAYBIN
    SET = d
    json.dump(d, open(SETF, "w", encoding="utf-8"), indent=2)
    BASE = int(d["base"])
    AUTH = d["auth"]
    TUNNEL = d["tunnel"]
    TUNNELID = d["tunnel_id"]
    XRAYBIN = d["xray_path"] or XRAY
# ---------- login ----------

def load_login():
    if not os.path.exists(LOGINF):
        d = {"user": "admin", "salt": secrets.token_hex(8)}
        d["hash"] = hashlib.sha256(("admin" + d["salt"]).encode()).hexdigest()
        json.dump(d, open(LOGINF, "w"), indent=2)
    return json.load(open(LOGINF, encoding="utf-8"))

def check_login(user, pw):
    d = load_login()
    h = hashlib.sha256((pw + d["salt"]).encode()).hexdigest()
    return secrets.compare_digest(user, d["user"]) and secrets.compare_digest(h, d["hash"])

def save_login(user, pw):
    salt = secrets.token_hex(8)
    d = {"user": user, "salt": salt, "hash": hashlib.sha256((pw + salt).encode()).hexdigest()}
    json.dump(d, open(LOGINF, "w"), indent=2)

# ---------- xray ----------

proc = None

def xray_running():
    return proc is not None and proc.poll() is None

def xray_start():
    global proc
    if xray_running():
        return "xray sudah jalan"
    if not os.path.exists(CFG):
        return "config.json belum ada - klik Regenerate dulu"
    log = open(LOGF, "ab")
    try:
        proc = subprocess.Popen([XRAYBIN, "run", "-c", CFG], stdout=log, stderr=log)
        return f"xray start (pid {proc.pid})"
    except FileNotFoundError:
        proc = None
        return f"xray binary tidak ketemu: {XRAYBIN} (atur di Pengaturan)"

def xray_stop():
    global proc
    if not xray_running():
        return "xray memang mati"
    proc.terminate()
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        proc.kill()
    proc = None
    return "xray stop"

def xray_restart():
    if xray_running():
        xray_stop()
    return xray_start()

def gen():
    if not os.path.exists(ACC):
        return "accounts.txt tidak ada"
    base_http = int(SET.get("base_http") or 0) or BASE + 1000
    cmd = [sys.executable, os.path.join(HERE, "gen.py"), ACC, "-o", CFG,
           "--base", str(BASE), "--base-http", str(base_http),
           "--listen", SET["listen"]]
    if AUTH:
        cmd += ["--auth", AUTH]
    if TUNNEL:
        cmd += ["--tunnel", TUNNEL]
    if TUNNELID:
        cmd += ["--tunnel-id", TUNNELID]
    if SET.get("insecure"):
        cmd += ["--insecure"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip() or "ok"

def dedup_accounts():
    """buang baris duplikat dari accounts.txt (kunci: uuid+host+port+path).
    return jumlah yang dibuang."""
    if not os.path.exists(ACC):
        return 0
    lines = open(ACC, encoding="utf-8").readlines()
    seen, out, dup = set(), [], 0
    for l in lines:
        s = l.strip()
        if not s or s.startswith("#"):
            out.append(l)
            continue
        u = urlparse(s)
        q = parse_qs(u.query)
        key = (u.username, u.hostname, u.port or 443,
               unquote(q.get("path", [""])[0]))
        if key in seen:
            dup += 1
            continue
        seen.add(key)
        out.append(l)
    if dup:
        open(ACC, "w", encoding="utf-8").writelines(out)
    return dup

def rows():
    out = []
    if not os.path.exists(ACC):
        return out
    n = 0
    for ln, line in enumerate(open(ACC, encoding="utf-8")):
        ob, name = build_outbound(n, line)
        if ob is None:
            continue
        v = ob["settings"]["vnext"][0]
        s = ob["streamSettings"]
        out.append({"line": ln, "idx": n,
                    "port_socks": BASE + n,
                    "port_http": (int(SET.get("base_http") or 0) or BASE + 1000) + n,
                    "name": name,
                    "server": f'{v["address"]}:{v["port"]}',
                    "tipe": f'{s.get("network", "tcp")}/{s.get("security", "none")}'})
        n += 1
    return out

def ip_test(port):
    if not xray_running():
        return "xray mati"
    if not str(port).isdigit():
        return "?"
    try:
        r = subprocess.run(["curl", "-s", "--socks5-hostname", f"127.0.0.1:{port}",
                            "--max-time", "12",
                            "http://ip-api.com/json/?fields=query,countryCode,country"],
                           capture_output=True, text=True, timeout=20)
        try:
            j = json.loads(r.stdout)
            q, cc = j.get("query", "?"), j.get("countryCode", "??")
            return f'{q} · {cc} ({j.get("country", "")})'
        except Exception:
            return "gagal (dial upstream gagal)"
    except subprocess.TimeoutExpired:
        return "timeout"

def ip_all():
    if not xray_running():
        return {}
    from concurrent.futures import ThreadPoolExecutor
    # test semua port SOCKS (bisa juga HTTP, tapi SOCKS lebih reliable untuk ip-api)
    ports = [str(x["port_socks"]) for x in rows()]
    with ThreadPoolExecutor(max_workers=8) as ex:
        res = list(ex.map(lambda p: ip_test(p), ports))
    return dict(zip(ports, res))

def tail_log(n=80):
    if not os.path.exists(LOGF):
        return "log kosong"
    return "".join(open(LOGF, encoding="utf-8", errors="replace").readlines()[-n:])

CSS = """*{box-sizing:border-box}
body{font-family:system-ui;background:#f2f4f8;margin:0}
.layout{display:flex;min-height:100vh}
.sidebar{width:230px;background:#101828;color:#cbd5e1;padding:18px 14px;display:flex;flex-direction:column;position:fixed;top:0;bottom:0;left:0}
.brand{display:flex;align-items:center;gap:10px;padding:6px 8px 20px;border-bottom:1px solid #1e293b;margin-bottom:14px}
.brand .dot{width:36px;height:36px;border-radius:10px;background:#1a7f37;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:17px;flex-shrink:0}
.brand b{color:#fff;font-size:16px;display:block;line-height:1.1}
.brand small{color:#64748b;font-size:11px}
.menu a{display:flex;align-items:center;gap:10px;padding:11px 12px;border-radius:10px;color:#cbd5e1;text-decoration:none;font-size:14px;font-weight:500;margin-bottom:4px}
.menu a:hover{background:#1e293b;color:#fff}
.menu a.on{background:#1a7f37;color:#fff;font-weight:600}
.menu .ico{width:20px;text-align:center;flex-shrink:0}
.sidebar .foot{margin-top:auto;padding:12px 8px 0;border-top:1px solid #1e293b;font-size:12px;color:#64748b}
.main{margin-left:230px;flex:1;min-width:0}
header{background:#fff;border-bottom:1px solid #e4e7ec;padding:14px 28px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:5}
header h1{font-size:18px;margin:0;color:#101828}
header .right{display:flex;align-items:center;gap:14px}
header .who{font-size:13px;color:#667085}
header a.out{color:#b42318;text-decoration:none;font-size:13px;font-weight:600;padding:7px 14px;border:1px solid #fda29b;border-radius:8px}
header a.out:hover{background:#fee4e2}
.content{max-width:980px;margin:24px auto;padding:0 24px}
.card{background:#fff;border-radius:12px;padding:20px;margin-bottom:20px;box-shadow:0 1px 6px rgba(0,0,0,.06)}
h2{margin:0 0 12px;font-size:16px;color:#101828}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:8px 10px;border-bottom:1px solid #eee;text-align:left}
th{color:#667085;font-weight:600;background:#f9fafb}
code{background:#f2f4f8;padding:2px 6px;border-radius:6px;font-size:13px}
input,select,textarea{padding:8px;border:1px solid #d0d5dd;border-radius:8px;margin:4px 0;font-size:14px}
input:focus,textarea:focus,select:focus{outline:2px solid #1a7f37;border-color:#1a7f37}
textarea{width:100%;height:90px}
label{display:block;font-size:13px;color:#344054;font-weight:600;margin:10px 0 4px}
button{padding:8px 14px;background:#1a7f37;color:#fff;border:0;border-radius:8px;cursor:pointer;font-weight:600;font-size:13px}
button:hover{background:#166f30}
button.del{background:#b42318}button.del:hover{background:#912018}
button.sec{background:#fff;color:#344054;border:1px solid #d0d5dd}button.sec:hover{background:#f9fafb}
.btnrow{display:flex;gap:10px;flex-wrap:wrap}
.badge{padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600}
.paid{background:#d4edda;color:#186a3b}.pending{background:#fff3cd;color:#8a6d00}
.expired{background:#f8d7da;color:#8a1c1c}
td small{color:#98a2b3;font-size:12px}
td.empty{text-align:center;color:#98a2b3;padding:18px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}
.stat{background:#fff;border-radius:12px;padding:16px;box-shadow:0 1px 6px rgba(0,0,0,.06);text-align:center}
.stat .n{font-size:26px;font-weight:800;color:#101828;font-variant-numeric:tabular-nums}
.stat .l{font-size:12px;color:#667085;margin-top:2px}
.flash{background:#d4edda;color:#186a3b;padding:10px 14px;border-radius:8px;margin-bottom:14px}
small{color:#667085}
pre{background:#f8fafc;border:1px solid #e4e7ec;border-radius:8px;padding:12px;font-size:12px;overflow-x:auto;max-height:420px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}
.ip{font-variant-numeric:tabular-nums}
.ip.run{color:#175cd3;font-weight:600}
.hint{color:#667085;font-size:12px;margin-top:8px}
form.inline{display:inline}
@media(max-width:800px){.sidebar{display:none}.main{margin-left:0}}"""

def login_page(msg=""):
    m = f'<p class="e">{html.escape(msg)}</p>' if msg else ""
    return f"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Login — Vlessbank</title>
<style>body{{font-family:system-ui;background:#f2f4f8;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}}
.c{{background:#fff;padding:36px;border-radius:16px;box-shadow:0 2px 16px rgba(0,0,0,.09);width:340px}}
.logo{{display:flex;align-items:center;gap:10px;margin-bottom:20px}}
.logo .dot{{width:38px;height:38px;border-radius:10px;background:#101828;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:18px}}
.logo b{{font-size:19px}} .logo small{{display:block;color:#667085;font-size:12px}}
label{{font-size:13px;color:#344054;font-weight:600;display:block;margin:10px 0 4px}}
input{{width:100%;box-sizing:border-box;padding:10px;margin:0 0 4px;border:1px solid #d0d5dd;border-radius:8px;font-size:14px}}
input:focus{{outline:2px solid #1a7f37;border-color:#1a7f37}}
button{{width:100%;padding:11px;background:#1a7f37;color:#fff;border:0;border-radius:8px;font-weight:600;cursor:pointer;margin-top:14px;font-size:15px}}
button:hover{{background:#166f30}}
.e{{color:#b42318;font-size:14px;background:#fee4e2;padding:8px 12px;border-radius:8px;margin-bottom:10px}}
.hint{{color:#667085;font-size:12px;margin-top:14px;text-align:center}}</style></head>
<body><div class="c">
<div class="logo"><div class="dot">V</div><div><b>Vlessbank</b><small>by JhopanStore</small></div></div>
{m}
<label>Username</label><input type="text" id="u" placeholder="username" autofocus autocomplete="username">
<label>Password</label><input type="password" id="p" placeholder="password" autocomplete="current-password">
<button onclick="doLogin()">Masuk</button>
<div class="hint">default: admin / admin — ganti di Pengaturan</div></div>
<script>
function doLogin(){{
  var u = document.getElementById('u').value, p = document.getElementById('p').value;
  var h = 'Basic ' + btoa(u + ':' + p);
  fetch('/api/login', {{method:'POST', headers:{{'Authorization': h}}}}).then(function(r){{
    if(r.ok) {{
      sessionStorage.setItem('vbauth', h);   // kredensial di browser saja, server stateless
      renderApp();
    }} else {{
      var m = document.querySelector('.e') || document.createElement('p');
      m.className = 'e'; m.textContent = 'Username atau password salah';
      document.querySelector('.c').prepend(m);
    }}
  }}).catch(function(){{
    var m = document.querySelector('.e') || document.createElement('p');
    m.className = 'e'; m.textContent = 'Koneksi gagal';
    document.querySelector('.c').prepend(m);
  }});
}}
document.getElementById('p').addEventListener('keydown', function(e){{ if(e.key==='Enter') doLogin(); }});
// dashboard dirender via fetch (semua request bawa Basic header) - bukan navigasi
function renderApp(){{
  fetch('/admin', {{headers: {{'Authorization': sessionStorage.getItem('vbauth')}}}})
    .then(function(r){{ return r.text(); }})
    .then(function(html){{
      document.open(); document.write(html); document.close();
    }});
}}
</script></body></html>"""

# auth: halaman login cantik + Basic header dari sessionStorage (browser-side).
# server stateless: tiap request diverifikasi check_login(user, pass). tanpa cookie, tanpa token.
def status_page():
    run = xray_running()
    dot = "#1a7f37" if run else "#b42318"
    teks = "VLESS BANK BERJALAN" if run else "VLESS BANK MATI"
    n = len(rows())
    return f"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Vlessbank</title>
<style>body{{font-family:system-ui;background:#f2f4f8;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}}
.c{{background:#fff;padding:40px 48px;border-radius:16px;box-shadow:0 2px 16px rgba(0,0,0,.09);text-align:center}}
.dot{{width:16px;height:16px;border-radius:50%;background:{dot};display:inline-block;margin-right:10px;vertical-align:middle}}
h1{{font-size:20px;color:#101828;margin:0;display:inline-block;vertical-align:middle}}
p{{color:#667085;font-size:13px;margin:14px 0 0}}
a{{color:#1a7f37;font-weight:600;text-decoration:none}}</style></head>
<body><div class="c">
<h1><span class="dot"></span>{teks}</h1>
<p>{n} akun aktif · <a href="/admin">Kelola →</a></p>
</div></body></html>"""

MENUS = [("dash", "/admin", "▤", "Dashboard"), ("log", "/admin/log", "☰", "Log"),
         ("set", "/admin/settings", "⚙", "Pengaturan")]

def page(tab, msg="", body=None):
    run = xray_running()
    stat = '<span class="badge paid">RUNNING</span>' if run else '<span class="badge expired">MATI</span>'
    m = f'<div class="flash">{html.escape(msg)}</div>' if msg else ""
    if body is None:
        body = body_dash()
    menu = "".join(f'<a href="{u}" onclick="nav(event,\'{u}\')" class="{"on" if tab == t else ""}"><span class="ico">{i}</span> {l}</a>'
                   for t, u, i, l in MENUS)
    return f"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Vlessbank</title><style>{CSS}</style></head>
<body><div class="layout">
<div class="sidebar">
<div class="brand"><div class="dot">V</div><div><b>Vlessbank</b><small>by JhopanStore</small></div></div>
<div class="menu">{menu}</div>
<div class="foot">v0.2 · JhopanStore</div>
</div>
<div class="main">
<header><h1>{dict((t, l) for t, u, i, l in MENUS)[tab]}</h1>
<div class="right"><span class="who">{stat}</span><a class="out" href="/logout" onclick="logout(event)">Logout</a></div></header>
<div class="content">{m}{body}</div>
</div></div>
<script>
function logout(e){{
  e.preventDefault();
  sessionStorage.removeItem('vbauth');
  location.href = '/login';
}}
function nav(e, u){{
  // navigasi menu via fetch: header Basic ikut, gak kena 401 loop
  e.preventDefault();
  fetch(u, {{headers: authH()}}).then(function(r){{
    if(r.status === 401) {{ sessionStorage.removeItem('vbauth'); location.href = '/login'; return; }}
    return r.text();
  }}).then(function(html){{
    if(!html) return;
    document.open(); document.write(html); document.close();
  }});
}}
function authH(){{
  return {{'Authorization': sessionStorage.getItem('vbauth') || '',
    'Content-Type':'application/x-www-form-urlencoded'}};
}}
function api(p, d){{
  var o = {{method:'POST', headers: authH()}};
  if(d) o.body = d;
  return fetch(p, o).then(function(r){{
    if(r.status === 401) {{ sessionStorage.removeItem('vbauth'); location.href = '/login'; throw 'unauth'; }}
    return r.json();
  }});
}}
function badge(){{
  api('/api/status').then(function(j) {{
    var el = document.getElementById('xstat');
    if(el) el.outerHTML = j.xray
      ? '<span class="badge paid" id="xstat">RUNNING</span>'
      : '<span class="badge expired" id="xstat">MATI</span>';
  }}).catch(function(){{}});
}}
function xray(act){{
  api('/api/xray', 'act=' + act).then(function(j) {{
    api('/api/status').then(function(s) {{
      var el = document.getElementById('xstat');
      if(el) el.outerHTML = s.xray
        ? '<span class="badge paid" id="xstat">RUNNING</span>'
        : '<span class="badge expired" id="xstat">MATI</span>';
    }});
    flash(j.result || j.error || 'ok');
  }}).catch(function(){{}});
}}
function regen(){{
  api('/api/regen', '').then(function(j) {{ flash(j.result || 'config digenerate'); }}).catch(function(){{}});
}}
function flash(s){{
  var m = document.getElementById('msg');
  if(m){{ m.textContent = s; m.style.display = 'block'; }}
}}
function t(p){{
  var c = document.getElementById('ip' + p);
  c.textContent = 'mengambil...'; c.className = 'ip run';
  fetch('/api/ip?port=' + p, {{headers: authH()}}).then(function(r){{ return r.json(); }}).then(function(j) {{
    c.textContent = j.result; c.className = 'ip';
  }}).catch(function(){{ c.textContent = 'err'; c.className = 'ip'; }});
}}
function tall(){{
  var btn = event.target; btn.disabled = true;
  document.getElementById('tallstat').textContent = 'mengetes semua port...';
  fetch('/api/ipall', {{headers: authH()}}).then(function(r){{ return r.json(); }}).then(function(j) {{
    for(var p in j) {{
      var c = document.getElementById('ip' + p);
      if(c) {{ c.textContent = j[p]; c.className = 'ip'; }}
    }}
    document.getElementById('tallstat').textContent = 'selesai';
    btn.disabled = false;
  }}).catch(function() {{
    document.getElementById('tallstat').textContent = 'gagal';
    btn.disabled = false;
  }});
}}
function del(line, nm){{
  if(!confirm('hapus ' + nm + '?')) return;
  api('/api/delete', 'line=' + line).then(function(j) {{
    if(j.error) return flash(j.error);
    fetch('/admin', {{headers: authH()}}).then(function(r){{ return r.text(); }}).then(function(h){{
      document.open(); document.write(h); document.close();
    }});
  }}).catch(function(){{}});
}}
function add(){{
  var ta = document.getElementById('newlinks');
  if(!ta.value.trim()) return;
  var fd = new URLSearchParams(); fd.set('links', ta.value);
  fetch('/api/add', {{method:'POST', headers: authH(), body: fd.toString()}})
    .then(function(r){{ return r.json(); }}).then(function(j) {{
    flash(j.added + ' akun ditambah' + (j.skipped ? ', ' + j.skipped + ' dilewati' : ''));
    ta.value = '';
    if(j.added) location.reload();
  }}).catch(function(){{}});
}}
</script>
</body></html>"""

def body_dash():
    run = xray_running()
    stat = ('<span class="badge paid" id="xstat">RUNNING</span>' if run
            else '<span class="badge expired" id="xstat">MATI</span>')
    rs = rows()
    trs = ""
    for x in rs:
        nm = html.escape(x["name"], quote=True)
        ps, ph = x["port_socks"], x["port_http"]
        client = (f'<tr><td colspan="7" style="background:#f9fafb"><code>cloudflared access tcp '
                  f'--hostname socks{x["idx"] + 1}.{html.escape(TUNNEL)} --url 127.0.0.1:{ps}</code>'
                  f' &nbsp;|&nbsp; <code>cloudflared access tcp '
                  f'--hostname http{x["idx"] + 1}.{html.escape(TUNNEL)} --url 127.0.0.1:{ph}</code></td></tr>'
                  if TUNNEL else "")
        trs += f"""<tr><td><b>{ps}</b><br><small style="color:#667085">HTTP:{ph}</small></td><td>{nm}</td><td>{html.escape(x["server"])}</td>
<td>{x["tipe"]}</td><td class="ip" id="ip{ps}"><small>belum dites</small></td>
<td style="white-space:nowrap">
<button class="sec" onclick="t({ps})">Test IP</button>
<button class="del" onclick="del({x['line']},'{nm}')">Hapus</button></td></tr>{client}"""
    empty = '<tr><td colspan="7" class="empty">Belum ada akun - tempel link vless:// di bawah</td></tr>' if not rs else ""
    tun = f' | tunnel <code>{html.escape(TUNNEL)}</code>' if TUNNEL else ""
    auth = f' | socks auth <code>{html.escape(AUTH)}</code>' if AUTH else ""
    cfgstat = '<code>sudah ada</code>' if os.path.exists(CFG) else '<b style="color:#b42318">belum ada - klik Regenerate</b>'
    return f"""<div class="stats">
<div class="stat"><div class="n">{len(rs)}</div><div class="l">Akun</div></div>
<div class="stat"><div class="n">{stat}</div><div class="l">Xray</div></div>
<div class="stat"><div class="n">{BASE}-{BASE + len(rs) - 1 if rs else BASE}</div><div class="l">Port SOCKS</div></div>
</div>
<div id="msg" class="flash" style="display:none"></div>
<div class="card"><h2>Kontrol</h2><div class="btnrow">
<button onclick="xray('start')">Start</button>
<button class="sec" onclick="xray('restart')">Restart</button>
<button class="del" onclick="xray('stop')">Stop</button>
<button class="sec" onclick="regen()">Regenerate config</button>
</div><div class="hint">config.json {cfgstat}</div></div>
<div class="card"><h2>Daftar Akun</h2>
<table><tr><th>Port SOCKS/HTTP</th><th>Nama</th><th>Server</th><th>Tipe</th><th>IP keluar</th><th></th></tr>{empty}{trs}</table>
<div class="btnrow" style="margin-top:10px">
<button class="sec" onclick="tall()">Test Semua IP</button>
<span id="tallstat" class="hint"></span>
</div>
<div class="hint">Browser/ekstensi arahkan ke <code>socks5://127.0.0.1:PORT_SOCKS</code> atau <code>http://127.0.0.1:PORT_HTTP</code>. 1 baris = 1 akun = 1 IP keluar.</div></div>
<div class="card"><h2>Tambah Akun</h2>
<textarea id="newlinks" placeholder="tempel link vless:// di sini, satu baris satu akun"></textarea>
<button style="margin-top:8px" onclick="add()">Tambah</button></div>
<div class="card"><h2>Mode</h2><small>listen <code>{html.escape(SET["listen"])}</code>{auth}{tun}</small> -
<a href="/settings">ubah di Pengaturan</a></div>"""

def body_settings():
    s = SET
    bh = int(s.get("base_http") or 0) or BASE + 1000
    return f"""
<div class="card"><h2>Xray</h2>
<form method="post" action="/settings">
<label>Lokasi binary xray</label>
<input name="xray_path" value="{html.escape(s["xray_path"])}" style="width:100%" placeholder="C:/.../xray.exe atau xray">
<label>Port SOCKS awal (base)</label>
<input name="base" type="number" value="{BASE}" style="width:140px">
<label>Port HTTP proxy awal (base_http, 0 = SOCKS+1000)</label>
<input name="base_http" type="number" value="{bh}" style="width:140px">
<label>SOCKS+HTTP listen</label>
<select name="listen">
<option value="127.0.0.1" {'selected' if s['listen'] == '127.0.0.1' else ''}>127.0.0.1 (lokal saja)</option>
<option value="0.0.0.0" {'selected' if s['listen'] == '0.0.0.0' else ''}>0.0.0.0 (LAN+publik - wajib auth)</option>
</select>
<label>Auth user:pass untuk SOCKS+HTTP (kosong = tanpa auth)</label>
<input name="auth" value="{html.escape(s["auth"])}" style="width:280px" placeholder="user:pass">
<label style="margin-top:12px"><input type="checkbox" name="insecure" value="1" {'checked' if s.get('insecure') else ''} style="width:auto;margin-right:6px">allowInsecure (abaikan sertifikat TLS tidak valid)</label>
<label>Domain tunnel Cloudflare (kosong = mode tunnel mati)</label>
<input name="tunnel" value="{html.escape(s["tunnel"])}" style="width:100%" placeholder="socks.example.com">
<label>UUID tunnel Cloudflare</label>
<input name="tunnel_id" value="{html.escape(s["tunnel_id"])}" style="width:100%" placeholder="opsional">
<button style="margin-top:12px">Simpan Semua</button>
</form>
<div class="hint">Perubahan baru efektif setelah klik Regenerate config (+ Restart xray).</div></div>
<div class="card"><h2>Login WebUI</h2>
<form method="post" action="/pass">
<label>Username</label>
<input name="user" value="{html.escape(load_login()["user"])}" style="width:280px">
<label>Password baru (kosong = tetap)</label>
<input name="pass" type="password" style="width:280px">
<button style="margin-top:12px">Simpan Login</button>
</form></div>"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _auth_ok(self):
        # stateless murni: Basic auth user:pass tiap request. tanpa cookie, tanpa sesi.
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                u, p = base64.b64decode(h[6:]).decode().split(":", 1)
                return check_login(u, p)
            except Exception:
                return False
        return False

    def _send(self, body, code=200):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _redir(self, msg=""):
        self.send_response(303)
        self.send_header("Location", "/" + (f"?msg={quote(msg)}" if msg else ""))
        self.end_headers()

    def _form(self):
        ln = int(self.headers.get("Content-Length", 0))
        return parse_qs(self.rfile.read(ln).decode())

    def _challenge(self):
        # 401 + WWW-Authenticate: kotak login bawaan browser yang muncul.
        # browser nyimpen kredensialnya sendiri & kirim otomatis di tiap request
        # (termasuk navigasi). stateless, tanpa cookie, tanpa token.
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="vlessbank", charset="UTF-8"')
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        # halaman status publik: / menunjukkan kondisi saja
        if u.path == "/" and not self._auth_ok():
            return self._send(status_page())
        if u.path in ("/login",) or not self._auth_ok():
            # halaman login selalu tampil; dashboard dirender JS via API
            if u.path.startswith("/api/"):
                return self._json({"error": "unauthorized"}, 401)
            return self._send(login_page())
        if u.path == "/logout":
            self.send_response(303)
            self.send_header("Location", "/login")
            self.end_headers()
            return
        if u.path == "/api/status":
            return self._json({"xray": xray_running(), "accounts": len(rows()),
                               "base": BASE, "listen": SET["listen"],
                               "auth": bool(AUTH), "tunnel": TUNNEL,
                               "config": os.path.exists(CFG)})
        if u.path == "/api/accounts":
            return self._json({"accounts": rows()})
        if u.path == "/api/ip":
            return self._json({"port": parse_qs(u.query).get("port", [""])[0],
                               "result": ip_test(parse_qs(u.query).get("port", [""])[0])})
        if u.path == "/api/ipall":
            return self._json(ip_all())
        if u.path == "/ip":
            return self._send(ip_test(parse_qs(u.query).get("port", [""])[0]))
        if u.path == "/ipall":
            return self._send(json.dumps(ip_all()))
        # halaman admin: /admin, /admin/log, /admin/settings
        tab = u.path[len("/admin"):].strip("/") or "dash"
        if u.path.startswith("/admin"):
            if tab == "log":
                b = f'<div class="card"><h2>Log Xray</h2><pre>{html.escape(tail_log())}</pre></div>'
                return self._send(page("log", parse_qs(u.query).get("msg", [""])[0], b))
            if tab == "settings":
                return self._send(page("set", parse_qs(u.query).get("msg", [""])[0], body_settings()))
            return self._send(page("dash", parse_qs(u.query).get("msg", [""])[0]))
        # path lama tetap dialihkan biar bookmark lama gak mati
        if u.path in ("/log", "/settings"):
            dst = "/admin/log" if u.path == "/log" else "/admin/settings"
            self.send_response(303)
            self.send_header("Location", dst)
            self.end_headers()
            return
        self._send(status_page())

    def do_POST(self):
        if self.path == "/api/login":
            # validasi Basic header dari halaman login JS
            h = self.headers.get("Authorization", "")
            if h.startswith("Basic "):
                try:
                    u, p = base64.b64decode(h[6:]).decode().split(":", 1)
                    if check_login(u, p):
                        return self._json({"ok": True})
                except Exception:
                    pass
            return self._json({"error": "salah"}, 401)
        if not self._auth_ok():
            if self.path.startswith("/api/"):
                return self._json({"error": "unauthorized"}, 401)
            return self._json({"error": "unauthorized"}, 401)
        f = self._form()
        # API JSON (buat bot/script client)
        if self.path == "/api/add":
            links = [l.strip() for l in f.get("links", [""])[0].splitlines()
                     if l.strip() and not l.startswith("#")]
            ok = [l for l in links if urlparse(l).scheme == "vless"]
            if ok:
                with open(ACC, "a", encoding="utf-8") as fh:
                    fh.write("\n".join(ok) + "\n")
                dup = dedup_accounts()
                gen()
                if xray_running():
                    xray_restart()
            else:
                dup = 0
            return self._json({"added": len(ok) - dup, "skipped": len(links) - len(ok) + dup,
                               "duplicates": dup})
        if self.path == "/api/delete":
            try:
                line = int(f.get("line", ["-1"])[0])
            except ValueError:
                line = -1
            ls = open(ACC, encoding="utf-8").readlines() if os.path.exists(ACC) else []
            if 0 <= line < len(ls):
                del ls[line]
                open(ACC, "w", encoding="utf-8").writelines(ls)
                gen()
                if xray_running():
                    xray_restart()
                return self._json({"deleted": line})
            return self._json({"error": "line tidak valid"}, 400)
        if self.path == "/api/xray":
            act = f.get("act", [""])[0]
            if act == "start":
                return self._json({"action": "start", "result": xray_start()})
            if act == "stop":
                return self._json({"action": "stop", "result": xray_stop()})
            if act == "restart":
                return self._json({"action": "restart", "result": xray_restart()})
            return self._json({"error": "act harus start/stop/restart"}, 400)
        if self.path == "/api/regen":
            return self._json({"result": gen()})
        # form HTML lama (dari dashboard)
        if self.path == "/add":
            links = [l.strip() for l in f.get("links", [""])[0].splitlines()
                     if l.strip() and not l.startswith("#")]
            ok = [l for l in links if urlparse(l).scheme == "vless"]
            bad = len(links) - len(ok)
            if ok:
                with open(ACC, "a", encoding="utf-8") as fh:
                    fh.write("\n".join(ok) + "\n")
                gen()
                if xray_running():
                    xray_restart()
            self._redir(f"{len(ok)} akun ditambah" +
                        (f", {bad} dilewati (bukan vless)" if bad else ""))
        elif self.path == "/del":
            try:
                line = int(f.get("line", ["-1"])[0])
            except ValueError:
                line = -1
            ls = open(ACC, encoding="utf-8").readlines()
            if 0 <= line < len(ls):
                del ls[line]
                open(ACC, "w", encoding="utf-8").writelines(ls)
                gen()
                if xray_running():
                    xray_restart()
                self._redir("akun dihapus")
            else:
                self._redir("line tidak valid")
        elif self.path == "/regen":
            self._redir(gen())
        elif self.path == "/start":
            self._redir(xray_start())
        elif self.path == "/stop":
            self._redir(xray_stop())
        elif self.path == "/restart":
            self._redir(xray_restart())
        elif self.path == "/settings":
            d = dict(SET)
            d["xray_path"] = f.get("xray_path", [""])[0].strip()
            try:
                d["base"] = max(1024, min(65000, int(f.get("base", ["1081"])[0])))
            except ValueError:
                pass
            try:
                bh = int(f.get("base_http", ["0"])[0])
                d["base_http"] = max(1024, min(65000, bh)) if bh else 0
            except ValueError:
                pass
            d["listen"] = f.get("listen", ["127.0.0.1"])[0]
            d["auth"] = f.get("auth", [""])[0].strip()
            d["insecure"] = f.get("insecure", [""])[0] == "1"
            d["tunnel"] = f.get("tunnel", [""])[0].strip()
            d["tunnel_id"] = f.get("tunnel_id", [""])[0].strip()
            if d["listen"] == "0.0.0.0" and not d["auth"]:
                return self._redir("ditolak: listen publik wajib auth")
            save_set(d)
            self._redir("pengaturan disimpan - Regenerate config untuk efektif")
        elif self.path == "/settings-tunnel":
            d = dict(SET)
            d["tunnel"] = f.get("tunnel", [""])[0].strip()
            d["tunnel_id"] = f.get("tunnel_id", [""])[0].strip()
            save_set(d)
            self._redir("tunnel disimpan - Regenerate config untuk efektif")
        elif self.path == "/pass":
            u = f.get("user", [""])[0].strip()
            p = f.get("pass", [""])[0]
            if not u:
                return self._redir("username tidak boleh kosong")
            if p:
                if len(p) < 4:
                    return self._redir("password minimal 4 karakter")
                save_login(u, p)
            else:
                d = load_login()
                d["user"] = u
                json.dump(d, open(LOGINF, "w"), indent=2)
            self._redir("login disimpan")
        else:
            self._send("?", 404)

if __name__ == "__main__":
    srv = ThreadingHTTPServer((LISTEN, PORT_WEB), H)
    print(f"vlessbank webui : http://{LISTEN}:{PORT_WEB}/")
    d = load_login()
    if d["hash"] == hashlib.sha256(("admin" + d["salt"]).encode()).hexdigest():
        print("login default   : admin / admin  (SAGERA GANTI di Pengaturan)")
    if LISTEN == "0.0.0.0":
        print("PERINGATAN: listen publik - taruh di belakang CF Access / firewall")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        xray_stop()
