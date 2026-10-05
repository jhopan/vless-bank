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
import cf as CF

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
         ("cf", "/admin/cf", "☁", "Cloudflare"), ("set", "/admin/settings", "⚙", "Pengaturan")]

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

def body_cf():
    st  = CF.tunnel_status()
    dl  = CF.dl_status()
    pi  = CF.platform_info()
    try:
        dl_fname = CF._cf_fname()
        dl_url   = CF._CF_CDN + dl_fname
    except Exception:
        dl_fname = dl_url = ""

    tunnels = st["tunnels"]
    cur_tid = SET.get("tunnel_id", "")

    # rows tunnel — highlight yang aktif dipakai
    def _trow(t):
        tid  = t["id"]
        nm   = html.escape(t["name"])
        aktif = " ✓" if tid == cur_tid else ""
        style = ' style="background:#f0fdf4"' if tid == cur_tid else ""
        return (f'<tr{style}><td><code style="font-size:11px">{tid}</code></td>'
                f'<td><b>{nm}</b>{aktif}</td>'
                f'<td style="white-space:nowrap">'
                f'<button class="sec" onclick="cfUseTunnel(\'{tid}\',\'{nm}\')">Pakai</button> '
                f'<button class="del" onclick="cfDelTunnel(\'{tid}\',\'{nm}\')">Hapus</button>'
                f'</td></tr>')
    tun_rows = "".join(_trow(t) for t in tunnels) or \
               '<tr><td colspan="3" class="empty">Belum ada tunnel</td></tr>'

    # badges
    if dl["state"] == "done":
        bin_badge = f'<span class="badge paid">ADA · {html.escape(dl["version"])}</span>'
    elif dl["state"] == "downloading":
        bin_badge = f'<span class="badge pending">Mengunduh {dl["progress"]}%...</span>'
    elif dl["state"] == "error":
        bin_badge = f'<span class="badge expired">Error download</span>'
    else:
        bin_badge = '<span class="badge expired">BELUM ADA</span>'

    login_st    = CF.login_status()
    login_badge = ('<span class="badge paid">Proses login aktif</span>' if login_st["running"]
                   else '<span class="badge pending">Belum login / siap login baru</span>')
    tun_badge   = ('<span class="badge paid">RUNNING</span>' if st["running"]
                   else '<span class="badge expired">MATI</span>')
    yml_ok      = st["yml_ok"]

    # preview yml jika ada
    yml_preview_html = ""
    if yml_ok:
        pv = CF.yml_preview()
        if pv["ok"]:
            yml_preview_html = f'<pre style="margin-top:10px;max-height:180px">{html.escape(pv["content"])}</pre>'

    log_html = html.escape(CF._tail_log(30)) or "(kosong)"

    return f"""
<div class="stats">
<div class="stat"><div class="n" style="font-size:13px">{bin_badge}</div><div class="l">Binary</div></div>
<div class="stat"><div class="n" style="font-size:13px">{login_badge}</div><div class="l">Login CF</div></div>
<div class="stat"><div class="n" style="font-size:13px">{tun_badge}</div><div class="l">Tunnel</div></div>
</div>
<div id="cfmsg" class="flash" style="display:none"></div>

<div class="card"><h2>1 · Binary cloudflared</h2>
<div class="hint">Platform: <code>{html.escape(pi["os"])}</code> / <code>{html.escape(pi["arch"])}</code> &nbsp;·&nbsp; Lokasi: <code>{html.escape(pi["bin"])}</code></div>
{'<div class="hint" style="color:#186a3b;margin-top:6px">cloudflared sudah ada · ' + html.escape(dl["version"]) + '</div>' if dl["state"]=="done" else '<p style="font-size:13px;margin-top:8px">cloudflared belum ada. Download otomatis atau manual.</p>'}
<div class="btnrow" style="margin-top:8px">
{'<button class="sec" onclick="cfDownload()">Download Otomatis</button>' if dl["state"] not in ("done","downloading") else ""}
{'<div class="hint">Sedang mengunduh... <span id="dlpct">' + str(dl["progress"]) + '</span>%</div>' if dl["state"]=="downloading" else ""}
{('<a href="' + html.escape(dl_url) + '" target="_blank"><button class="sec">Download Manual (' + html.escape(dl_fname) + ') ↗</button></a>') if dl_url and dl["state"] not in ("done","downloading") else ""}
</div>
{('<div class="hint" style="color:#b42318">Error: ' + html.escape(dl.get("error","")) + '<br>Download manual lalu taruh di: <code>' + html.escape(pi["bundle"]) + '</code></div>') if dl["state"]=="error" else ""}
</div>

<div class="card"><h2>2 · Login Cloudflare</h2>
<p style="font-size:13px;color:#344054">Login ke akun Cloudflare kamu. Link login akan muncul di sini — klik, authorize di browser, lanjut ke step 3.</p>
<div class="btnrow">
<button onclick="cfLogin()" {'disabled' if not CF.bin_ok() else ''}>Login ke Cloudflare</button>
{'<button class="sec" onclick="cfCancelLogin()">Batal</button>' if login_st["running"] else ""}
</div>
<div id="cfloginbox" style="margin-top:14px;display:{'block' if login_st['running'] else 'none'}">
  <div style="background:#fffbeb;border:1px solid #f59e0b;border-radius:8px;padding:14px">
    <div style="font-size:13px;color:#344054;margin-bottom:8px"><b>Klik link berikut untuk login:</b></div>
    <div id="cfloginurl" style="word-break:break-all;font-size:13px">
      {'<a href="' + login_st["url"] + '" target="_blank" style="color:#1a7f37;font-weight:600">' + login_st["url"] + '</a>' if login_st["url"] else 'Menunggu URL...'}
    </div>
    <div style="font-size:12px;color:#667085;margin-top:8px">Setelah authorize di browser, status di sini akan update otomatis.</div>
  </div>
</div>
{'<div class="hint" style="color:#186a3b;margin-top:8px">✓ Login berhasil — lanjut ke step 3</div>' if login_st["done"] else ""}
</div>

<div class="card"><h2>3 · Buat atau Pilih Tunnel</h2>
<label>Nama tunnel baru</label>
<div class="btnrow">
<input id="tname" placeholder="vlessbank" style="width:220px">
<button onclick="cfCreate()">Buat Tunnel</button>
</div>
<div style="margin-top:14px">
<table><tr><th>Tunnel ID</th><th>Nama</th><th></th></tr>{tun_rows}</table>
<button class="sec" style="margin-top:8px" onclick="cfRefreshTunnels()">↻ Refresh</button>
</div></div>

<div class="card"><h2>4 · Setup Domain & Generate Config</h2>
<p style="font-size:13px;color:#344054">Masukkan CF API Token untuk load daftar domain, lalu pilih domain dan generate config tunnel.</p>
<div class="hint" style="margin-bottom:10px">Buat token di <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" style="color:#1a7f37">CF dashboard → API Tokens</a> dengan permission <b>Zone:DNS:Edit</b>.</div>
<div class="btnrow">
<input id="cftoken" type="password" placeholder="CF API Token" style="width:320px">
<button class="sec" onclick="cfLoadZones()">Load Domain</button>
</div>
<div id="zonebox" style="margin-top:12px;display:none">
  <label>Pilih domain</label>
  <select id="zoneSel" style="width:300px"><option value="">-- pilih --</option></select>
  <label style="margin-top:10px">Subdomain prefix (default: socks)</label>
  <input id="subdom" value="socks" style="width:140px">
  <div class="hint">Wildcard CNAME yang akan dibuat: <code>*.socks.domain.com</code></div>
  <div class="btnrow" style="margin-top:12px">
    <button onclick="cfGenYml()">Generate config.tunnel.yml</button>
    <button class="sec" onclick="cfCreateDNS()">Buat DNS Wildcard via API</button>
  </div>
</div>
<div style="margin-top:10px">
  <label>Atau isi manual:</label>
  <div class="btnrow">
    <input id="manDomain" placeholder="domain.com" style="width:220px" value="{html.escape(SET.get('tunnel',''))}">
    <button class="sec" onclick="cfGenYmlManual()">Generate (manual)</button>
  </div>
</div>
{yml_preview_html}
</div>

<div class="card"><h2>5 · DNS Wildcard</h2>
<p style="font-size:13px;color:#344054">Satu CNAME wildcard cover semua akun sekarang dan nanti. Buat via tombol di step 4, atau manual:</p>
{'<table><tr><th>Type</th><th>Name</th><th>Target</th><th>Proxy</th></tr><tr><td>CNAME</td><td><code>*.' + html.escape(SET.get("tunnel_id","?")) + '.cfargotunnel.com</code>... (isi setelah pilih domain)</td><td></td><td><b style="color:#b42318">OFF</b></td></tr></table>' if not SET.get("tunnel") else
f'<table><tr><th>Type</th><th>Name</th><th>Target</th><th>Proxy</th></tr><tr><td>CNAME</td><td><code>*.socks.{html.escape(SET.get("tunnel",""))}</code></td><td><code>{html.escape(SET.get("tunnel_id","?"))}.cfargotunnel.com</code></td><td><b style="color:#b42318">OFF</b></td></tr></table>'}
<div class="hint">Proxy <b>harus OFF</b> — raw TCP tidak bisa lewat CF HTTP proxy.</div>
</div>

<div class="card"><h2>6 · Jalankan Tunnel</h2>
<p style="font-size:13px;color:#344054">
config.tunnel.yml: {'<span style="color:#186a3b">✓ ada</span>' if yml_ok else '<b style="color:#b42318">belum ada — selesaikan step 4 dulu</b>'}
</p>
<div class="btnrow">
<button onclick="cfTunnel('start')" {'disabled' if not yml_ok else ''}>▶ Start Tunnel</button>
<button class="del" onclick="cfTunnel('stop')">■ Stop Tunnel</button>
</div>
<div style="margin-top:14px"><b style="font-size:13px">Log cloudflared:</b><pre id="cflog">{log_html}</pre></div>
</div>

<script>
function cfMsg(s,ok){{
  var m=document.getElementById('cfmsg');
  m.textContent=s; m.style.display='block';
  m.style.background=ok===false?'#fee4e2':ok===true?'#d4edda':'#fffbeb';
  m.style.color=ok===false?'#b42318':ok===true?'#186a3b':'#8a6d00';
}}
function cfApi(path,data){{
  return fetch(path,{{method:'POST',headers:authH(),body:data?new URLSearchParams(data).toString():''}})
    .then(function(r){{if(r.status===401){{sessionStorage.removeItem('vbauth');location.href='/login';throw 'unauth';}}return r.json();}});
}}
function cfGet(path){{
  return fetch(path,{{headers:{{'Authorization':sessionStorage.getItem('vbauth')||''}}}}).then(function(r){{return r.json();}});
}}

function cfDownload(){{
  cfApi('/api/cf/download').then(function(){{
    cfMsg('Mengunduh cloudflared...',null);
    var iv=setInterval(function(){{
      cfGet('/api/cf/dlstatus').then(function(s){{
        if(s.state==='done'){{clearInterval(iv);cfMsg('Download selesai: '+s.version,true);location.reload();}}
        else if(s.state==='error'){{clearInterval(iv);cfMsg('Error: '+s.error,false);}}
        else{{var el=document.getElementById('dlpct');if(el)el.textContent=s.progress;}}
      }});
    }},1500);
  }});
}}

var _loginIv=null;
function cfLogin(){{
  cfMsg('Memulai proses login...',null);
  cfApi('/api/cf/login').then(function(j){{
    if(!j.ok){{cfMsg('Error: '+j.error,false);return;}}
    document.getElementById('cfloginbox').style.display='block';
    if(j.url) _setLoginUrl(j.url);
    if(j.done){{cfMsg('Login berhasil!',true);return;}}
    if(_loginIv) clearInterval(_loginIv);
    _loginIv=setInterval(function(){{
      cfGet('/api/cf/loginstatus').then(function(s){{
        if(s.url) _setLoginUrl(s.url);
        if(s.done){{clearInterval(_loginIv);cfMsg('✓ Login berhasil! Lanjut ke step 3.',true);
          setTimeout(function(){{location.reload();}},2000);}}
        else if(!s.running){{clearInterval(_loginIv);}}
      }});
    }},2000);
  }});
}}
function _setLoginUrl(url){{
  var el=document.getElementById('cfloginurl');
  if(el) el.innerHTML='<a href="'+url+'" target="_blank" style="color:#1a7f37;font-weight:600">'+url+'</a>';
}}
function cfCancelLogin(){{
  if(_loginIv) clearInterval(_loginIv);
  cfApi('/api/cf/cancelLogin').then(function(){{
    cfMsg('Login dibatalkan',null); location.reload();
  }});
}}

function cfCreate(){{
  var nm=document.getElementById('tname').value.trim();
  if(!nm){{cfMsg('Isi nama tunnel dulu',false);return;}}
  cfMsg('Membuat tunnel "'+nm+'"...',null);
  cfApi('/api/cf/create',{{name:nm}}).then(function(j){{
    if(j.ok){{cfMsg('✓ Tunnel dibuat! ID: '+j.id,true);setTimeout(function(){{location.reload();}},1500);}}
    else cfMsg('Error: '+j.error,false);
  }});
}}
function cfRefreshTunnels(){{
  cfApi('/api/cf/refreshtunnels').then(function(j){{
    cfMsg('List direfresh ('+j.count+' tunnel)',true);setTimeout(function(){{location.reload();}},800);
  }});
}}
function cfUseTunnel(id,name){{
  cfApi('/api/cf/usetunnel',{{id:id,name:name}}).then(function(j){{
    if(j.ok){{cfMsg('✓ Tunnel "'+name+'" dipilih. Lanjut ke step 4.',true);setTimeout(function(){{location.reload();}},1000);}}
    else cfMsg('Error: '+(j.error||'?'),false);
  }});
}}
function cfDelTunnel(id,name){{
  if(!confirm('Hapus tunnel '+name+'?'))return;
  cfApi('/api/cf/deltunnel',{{id:id}}).then(function(j){{
    if(j.ok){{cfMsg('Tunnel dihapus',true);setTimeout(function(){{location.reload();}},800);}}
    else cfMsg('Error: '+j.error,false);
  }});
}}

var _zones=[];
function cfLoadZones(){{
  var tok=document.getElementById('cftoken').value.trim();
  if(!tok){{cfMsg('Isi API token dulu',false);return;}}
  cfMsg('Mengambil daftar domain...',null);
  cfApi('/api/cf/zones',{{token:tok}}).then(function(j){{
    if(!j.ok){{cfMsg('Error: '+j.error,false);return;}}
    _zones=j.zones;
    var sel=document.getElementById('zoneSel');
    sel.innerHTML='<option value="">-- pilih domain --</option>';
    j.zones.forEach(function(z){{
      var o=document.createElement('option');
      o.value=z.id; o.textContent=z.name+' ('+z.status+')'; o.dataset.name=z.name;
      sel.appendChild(o);
    }});
    document.getElementById('zonebox').style.display='block';
    cfMsg('✓ '+j.zones.length+' domain ditemukan',true);
    // simpan token ke session (tidak ke server)
    sessionStorage.setItem('cftoken',tok);
  }});
}}
function _selectedZone(){{
  var sel=document.getElementById('zoneSel');
  var opt=sel.options[sel.selectedIndex];
  return {{id:sel.value, name:opt?opt.dataset.name:''}};
}}
function cfGenYml(){{
  var z=_selectedZone();
  if(!z.id){{cfMsg('Pilih domain dulu',false);return;}}
  var sub=document.getElementById('subdom').value.trim()||'socks';
  var tok=document.getElementById('cftoken').value.trim();
  cfMsg('Generate config.tunnel.yml...',null);
  cfApi('/api/cf/genYml',{{zone_name:z.name,subdomain:sub,token:tok}}).then(function(j){{
    if(j.ok){{cfMsg('✓ config.tunnel.yml dibuat ('+j.accounts+' akun)',true);setTimeout(function(){{location.reload();}},1000);}}
    else cfMsg('Error: '+j.error,false);
  }});
}}
function cfGenYmlManual(){{
  var dom=document.getElementById('manDomain').value.trim();
  if(!dom){{cfMsg('Isi domain dulu',false);return;}}
  cfMsg('Generate config.tunnel.yml...',null);
  cfApi('/api/cf/genYml',{{zone_name:dom,subdomain:'socks'}}).then(function(j){{
    if(j.ok){{cfMsg('✓ config.tunnel.yml dibuat ('+j.accounts+' akun)',true);setTimeout(function(){{location.reload();}},1000);}}
    else cfMsg('Error: '+j.error,false);
  }});
}}
function cfCreateDNS(){{
  var z=_selectedZone();
  if(!z.id){{cfMsg('Pilih domain dulu',false);return;}}
  var sub=document.getElementById('subdom').value.trim()||'socks';
  var tok=document.getElementById('cftoken').value.trim();
  if(!tok){{cfMsg('Isi API token dulu',false);return;}}
  cfMsg('Membuat DNS wildcard...',null);
  cfApi('/api/cf/createDNS',{{token:tok,zone_id:z.id,zone_name:z.name,subdomain:sub}}).then(function(j){{
    if(j.ok){{cfMsg('✓ CNAME *.'+sub+'.'+z.name+' -> '+j.target+(j.note?' ('+j.note+')':''),true);}}
    else cfMsg('Error DNS: '+j.error,false);
  }});
}}
function cfTunnel(act){{
  cfApi('/api/cf/tunnel',{{act:act}}).then(function(j){{
    cfMsg(j.result||j.error||'ok', act==='stop'?null:true);
    setTimeout(function(){{
      cfGet('/api/cf/logstatus').then(function(s){{
        var el=document.getElementById('cflog');if(el)el.textContent=s.log||'(kosong)';
      }});
    }},2000);
  }});
}}
// restore token dari session
(function(){{var t=sessionStorage.getItem('cftoken');if(t)document.getElementById('cftoken').value=t;}})();
// poll log + badge tiap 5 detik
setInterval(function(){{
  cfGet('/api/cf/logstatus').then(function(s){{
    var el=document.getElementById('cflog');if(el)el.textContent=s.log||'(kosong)';
    var tb=document.querySelector('.stat:nth-child(3) .n');
    if(tb)tb.innerHTML=s.running?'<span class="badge paid">RUNNING</span>':'<span class="badge expired">MATI</span>';
  }}).catch(function(){{}});
}},5000);
</script>"""
    tun_rows = "".join(
        f'<tr><td><code>{t["id"]}</code></td><td>{html.escape(t["name"])}</td>'
        f'<td><button class="sec" onclick="cfUseTunnel(\'{t["id"]}\',\'{html.escape(t["name"])}\')">Pakai</button> '
        f'<button class="del" onclick="cfDelTunnel(\'{t["id"]}\',\'{html.escape(t["name"])}\')">Hapus</button></td></tr>'
        for t in tunnels
    ) or '<tr><td colspan="3" class="empty">Belum ada tunnel</td></tr>'

    # status badge cloudflared binary
    if dl["state"] == "done":
        bin_badge = f'<span class="badge paid">ADA · {html.escape(dl["version"])}</span>'
    elif dl["state"] == "downloading":
        bin_badge = f'<span class="badge pending">Mengunduh {dl["progress"]}%...</span>'
    elif dl["state"] == "error":
        bin_badge = f'<span class="badge expired">Error: {html.escape(dl["error"])}</span>'
    else:
        bin_badge = '<span class="badge expired">BELUM ADA</span>'

    login_st  = CF.login_status()
    login_badge = '<span class="badge paid">Sudah login</span>' if login_st["done"] \
                  else '<span class="badge expired">Belum login</span>'
    tun_badge = ('<span class="badge paid">RUNNING</span>' if st["running"]
                 else '<span class="badge expired">MATI</span>')
    tun_yml   = os.path.join(CF.HERE, "config.tunnel.yml")
    yml_ok    = os.path.exists(tun_yml)

    dns_hint = ""
    if SET.get("tunnel") and SET.get("tunnel_id"):
        dom   = html.escape(SET["tunnel"])
        tid   = html.escape(SET["tunnel_id"])
        cname = f"{tid}.cfargotunnel.com"
        dns_hint = f"""<div class="card"><h2>☁ DNS Wildcard</h2>
<p style="font-size:13px;color:#344054">Buat CNAME berikut di Cloudflare DNS <b>sekali saja</b> — cover semua akun sekarang dan nanti:</p>
<table><tr><th>Type</th><th>Name</th><th>Target</th><th>Proxy</th></tr>
<tr><td>CNAME</td><td><code>*.socks.{dom}</code></td><td><code>{cname}</code></td><td><b style="color:#b42318">OFF (DNS only)</b></td></tr></table>
<div class="btnrow" style="margin-top:10px">
<a href="https://dash.cloudflare.com/?to=/:account/:zone/dns" target="_blank"><button class="sec">Buka CF DNS Dashboard ↗</button></a>
</div>
<div class="hint">Proxy harus OFF — raw TCP tunnel tidak bisa lewat CF HTTP proxy.</div></div>"""

    log_html = html.escape(CF._tail_log(30)) or "(kosong)"

    return f"""
<div class="stats">
<div class="stat"><div class="n" style="font-size:14px">{bin_badge}</div><div class="l">Binary cloudflared</div></div>
<div class="stat"><div class="n" style="font-size:14px">{login_badge}</div><div class="l">Login CF</div></div>
<div class="stat"><div class="n" style="font-size:14px">{tun_badge}</div><div class="l">Tunnel</div></div>
</div>
<div id="cfmsg" class="flash" style="display:none"></div>

<div class="card"><h2>1 · Binary cloudflared</h2>
<div class="hint">Platform: <code>{html.escape(pi["os"])}</code> / <code>{html.escape(pi["arch"])}</code> &nbsp;·&nbsp; Lokasi: <code>{html.escape(pi["bin"])}</code></div>
{'<div class="hint" style="color:#186a3b;margin-top:6px">cloudflared sudah ada · versi: ' + html.escape(dl["version"]) + '</div>' if dl["state"]=="done" else
 '<p style="font-size:13px;margin-top:8px">cloudflared belum ada. Download otomatis atau manual.</p>'}
<div class="btnrow" style="margin-top:8px">
{'<button class="sec" onclick="cfDownload()">Download Otomatis</button>' if dl["state"] not in ("done","downloading") else ""}
{'<div class="hint">Sedang mengunduh... <span id="dlpct">' + str(dl["progress"]) + '</span>%</div>' if dl["state"]=="downloading" else ""}
{('<a href="' + html.escape(dl_url) + '" target="_blank"><button class="sec">Download Manual (' + html.escape(dl_fname) + ') ↗</button></a>') if dl_url and dl["state"] not in ("done","downloading") else ""}
</div>
{('<div class="hint" style="color:#b42318">Error download: ' + html.escape(dl.get("error","")) + '<br>Coba download manual lalu letakkan file di: <code>' + html.escape(pi["bin"]) + '</code></div>') if dl["state"]=="error" else ""}
{'<div class="hint">Setelah download manual, letakkan file di: <code>' + html.escape(pi["bin"]) + '</code> lalu refresh halaman ini.</div>' if dl["state"] not in ("done","downloading") and dl_fname else ""}
</div>

<div class="card"><h2>2 · Login Cloudflare</h2>
<p style="font-size:13px;color:#344054">Login sekali — CF simpan sertifikat di <code>~/.cloudflared/cert.pem</code>.</p>
<div class="btnrow">
<button onclick="cfLogin()" {'disabled' if not CF.bin_ok() else ''}>Login ke Cloudflare</button>
</div>
<div id="cfloginurl" style="margin-top:12px;font-size:13px"></div>
</div>

<div class="card"><h2>3 · Buat atau Pilih Tunnel</h2>
<label>Nama tunnel baru</label>
<div class="btnrow">
<input id="tname" placeholder="vlessbank" style="width:220px">
<button onclick="cfCreate()" {'disabled' if not login_st["done"] else ''}>Buat Tunnel</button>
</div>
<div style="margin-top:14px">
<table><tr><th>Tunnel ID</th><th>Nama</th><th></th></tr>{tun_rows}</table>
<button class="sec" style="margin-top:8px" onclick="cfListTunnels()">Refresh List</button>
</div></div>

{dns_hint}

<div class="card"><h2>5 · Jalankan Tunnel</h2>
<p style="font-size:13px;color:#344054">
config.tunnel.yml: {'<code>ada</code>' if yml_ok else '<b style="color:#b42318">belum ada — isi Pengaturan lalu klik Regenerate config di Dashboard</b>'}
</p>
<div class="btnrow">
<button onclick="cfTunnel('start')" {'disabled' if not yml_ok else ''}>Start Tunnel</button>
<button class="del" onclick="cfTunnel('stop')">Stop Tunnel</button>
</div>
<div style="margin-top:14px"><h2>Log cloudflared</h2><pre id="cflog">{log_html}</pre></div>
</div>

<script>
function cfMsg(s,ok){{var m=document.getElementById('cfmsg');m.textContent=s;m.style.display='block';m.style.background=ok===false?'#fee4e2':ok===true?'#d4edda':'#fff3cd';m.style.color=ok===false?'#b42318':ok===true?'#186a3b':'#8a6d00';}}
function cfApi(path,data){{return fetch(path,{{method:'POST',headers:authH(),body:data?new URLSearchParams(data).toString():''}}).then(function(r){{if(r.status===401){{sessionStorage.removeItem('vbauth');location.href='/login';throw 'unauth';}}return r.json();}});}}
function cfGet(path){{return fetch(path,{{headers:{{'Authorization':sessionStorage.getItem('vbauth')||''}}}}).then(function(r){{return r.json();}});}}

function cfDownload(){{
  cfApi('/api/cf/download').then(function(j){{
    cfMsg('Mengunduh...',null);
    var iv=setInterval(function(){{
      cfGet('/api/cf/dlstatus').then(function(s){{
        if(s.state==='done'){{clearInterval(iv);cfMsg('Download selesai: '+s.version,true);location.reload();}}
        else if(s.state==='error'){{clearInterval(iv);cfMsg('Error: '+s.error,false);}}
        else{{var el=document.getElementById('dlpct');if(el)el.textContent=s.progress;cfMsg('Mengunduh '+s.progress+'%',null);}}
      }});
    }},1500);
  }});
}}

function cfLogin(){{
  cfMsg('Memulai login...',null);
  cfApi('/api/cf/login').then(function(j){{
    if(j.url){{
      document.getElementById('cfloginurl').innerHTML='Klik link berikut untuk login di browser:<br><a href="'+j.url+'" target="_blank" style="color:#1a7f37;font-weight:600;word-break:break-all">'+j.url+'</a><br><small>Setelah authorize, halaman ini akan otomatis update.</small>';
      cfMsg('Menunggu authorize di browser...',null);
    }}
    var iv=setInterval(function(){{
      cfGet('/api/cf/loginstatus').then(function(s){{
        if(s.done){{clearInterval(iv);cfMsg('Login berhasil!',true);setTimeout(function(){{location.reload();}},1500);}}
        else if(s.url&&!document.getElementById('cfloginurl').innerHTML){{
          document.getElementById('cfloginurl').innerHTML='<a href="'+s.url+'" target="_blank">'+s.url+'</a>';
        }}
      }});
    }},2000);
  }});
}}

function cfCreate(){{
  var nm=document.getElementById('tname').value.trim();
  if(!nm){{cfMsg('Isi nama tunnel dulu',false);return;}}
  cfMsg('Membuat tunnel...',null);
  cfApi('/api/cf/create',{{name:nm}}).then(function(j){{
    if(j.ok){{cfMsg('Tunnel dibuat! ID: '+j.id,true);setTimeout(function(){{location.reload();}},1500);}}
    else cfMsg('Error: '+j.error,false);
  }});
}}

function cfUseTunnel(id,name){{
  cfApi('/api/cf/usetunnel',{{id:id,name:name}}).then(function(j){{
    if(j.ok)cfMsg('Tunnel dipilih: '+name+' ('+id+'). Regenerate config di Dashboard.',true);
    else cfMsg('Error: '+(j.error||'?'),false);
  }});
}}

function cfDelTunnel(id,name){{
  if(!confirm('Hapus tunnel '+name+'?'))return;
  cfApi('/api/cf/deltunnel',{{id:id}}).then(function(j){{
    if(j.ok){{cfMsg('Tunnel dihapus',true);setTimeout(function(){{location.reload();}},1000);}}
    else cfMsg('Error: '+j.error,false);
  }});
}}

function cfTunnel(act){{
  cfApi('/api/cf/tunnel',{{act:act}}).then(function(j){{
    cfMsg(j.result||j.error||'ok', act==='stop'?null:true);
    setTimeout(function(){{cfGet('/api/cf/logstatus').then(function(s){{
      var el=document.getElementById('cflog');if(el)el.textContent=s.log;
    }});}},2000);
  }});
}}

// poll log setiap 5 detik kalau di halaman cf
setInterval(function(){{
  cfGet('/api/cf/logstatus').then(function(s){{
    var el=document.getElementById('cflog');if(el)el.textContent=s.log||'(kosong)';
    var tb=document.querySelector('.stat:nth-child(3) .n');
    if(tb)tb.innerHTML=s.running?'<span class="badge paid">RUNNING</span>':'<span class="badge expired">MATI</span>';
  }}).catch(function(){{}});
}},5000);
</script>"""

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
        # CF API endpoints (GET)
        if u.path == "/api/cf/dlstatus":
            return self._json(CF.dl_status())
        if u.path == "/api/cf/loginstatus":
            return self._json(CF.login_status())
        if u.path == "/api/cf/logstatus":
            return self._json({"log": CF._tail_log(40), "running": CF.tunnel_running()})
        if u.path == "/api/cf/status":
            return self._json(CF.tunnel_status())
        # halaman admin: /admin, /admin/log, /admin/settings, /admin/cf
        tab = u.path[len("/admin"):].strip("/") or "dash"
        if u.path.startswith("/admin"):
            if tab == "log":
                b = f'<div class="card"><h2>Log Xray</h2><pre>{html.escape(tail_log())}</pre></div>'
                return self._send(page("log", parse_qs(u.query).get("msg", [""])[0], b))
            if tab == "settings":
                return self._send(page("set", parse_qs(u.query).get("msg", [""])[0], body_settings()))
            if tab == "cf":
                return self._send(page("cf", parse_qs(u.query).get("msg", [""])[0], body_cf()))
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
        # CF API endpoints (POST)
        if self.path == "/api/cf/download":
            CF.download_binary()
            return self._json({"ok": True})
        if self.path == "/api/cf/login":
            return self._json(CF.start_login())
        if self.path == "/api/cf/create":
            name = f.get("name", [""])[0].strip()
            res = CF.create_tunnel(name)
            if res.get("ok"):
                # otomatis simpan ke settings
                d = dict(SET)
                d["tunnel_id"] = res["id"]
                if not d.get("tunnel"):
                    d["tunnel"] = ""  # user masih perlu isi domain
                save_set(d)
            return self._json(res)
        if self.path == "/api/cf/usetunnel":
            tid  = f.get("id",   [""])[0].strip()
            name = f.get("name", [""])[0].strip()
            if not tid:
                return self._json({"ok": False, "error": "id kosong"}, 400)
            d = dict(SET)
            d["tunnel_id"] = tid
            save_set(d)
            return self._json({"ok": True, "id": tid, "name": name})
        if self.path == "/api/cf/deltunnel":
            tid = f.get("id", [""])[0].strip()
            return self._json(CF.delete_tunnel(tid))
        if self.path == "/api/cf/cancelLogin":
            return self._json(CF.cancel_login())
        if self.path == "/api/cf/refreshtunnels":
            t = CF.list_tunnels()
            return self._json({"ok": True, "count": len(t), "tunnels": t})
        if self.path == "/api/cf/zones":
            tok = f.get("token", [""])[0].strip()
            if not tok:
                return self._json({"ok": False, "error": "token kosong"}, 400)
            return self._json(CF.cf_api_zones(tok))
        if self.path == "/api/cf/genYml":
            tid = SET.get("tunnel_id", "")
            if not tid:
                return self._json({"ok": False, "error": "Pilih tunnel dulu (step 3)"})
            zone_name = f.get("zone_name", [""])[0].strip()
            subdomain = f.get("subdomain", ["socks"])[0].strip() or "socks"
            if not zone_name:
                return self._json({"ok": False, "error": "domain kosong"})
            # simpan domain ke settings juga
            d = dict(SET); d["tunnel"] = zone_name; save_set(d)
            return self._json(CF.generate_tunnel_yml(tid, zone_name, subdomain))
        if self.path == "/api/cf/createDNS":
            tok       = f.get("token",     [""])[0].strip()
            zone_id   = f.get("zone_id",   [""])[0].strip()
            zone_name = f.get("zone_name", [""])[0].strip()
            subdomain = f.get("subdomain", ["socks"])[0].strip() or "socks"
            tid = SET.get("tunnel_id", "")
            if not all([tok, zone_id, zone_name, tid]):
                return self._json({"ok": False, "error": "token/zone/tunnel_id tidak lengkap"})
            return self._json(CF.cf_api_create_dns(tok, zone_id, zone_name, tid, subdomain))
        if self.path == "/api/cf/tunnel":
            act     = f.get("act", [""])[0]
            tun_yml = os.path.join(CF.HERE, "config.tunnel.yml")
            if act == "start":
                return self._json({"result": CF.tunnel_start(tun_yml)})
            if act == "stop":
                return self._json({"result": CF.tunnel_stop()})
            return self._json({"error": "act harus start/stop"}, 400)
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
