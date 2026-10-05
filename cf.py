#!/usr/bin/env python
# cf.py - cloudflared manager untuk vlessbank webui
import json, os, platform, re, shutil, subprocess, threading, time, urllib.request

HERE    = os.path.dirname(os.path.abspath(__file__))
_IS_WIN = platform.system() == "Windows"
CF_DIR  = os.path.join(os.path.expanduser("~"), ".cloudflared")
CF_LOG  = os.path.join(HERE, "cloudflared.log")

def _bundle_path():
    return os.path.join(HERE, "cloudflared.exe" if _IS_WIN else "cloudflared")

def find_bin():
    b = _bundle_path()
    if os.path.isfile(b):
        return b
    return shutil.which("cloudflared") or ""

CF_BIN = find_bin()

def _resolved_bin():
    global CF_BIN
    CF_BIN = find_bin()
    return CF_BIN

def bin_ok():
    return bool(_resolved_bin())

def cf_version():
    b = _resolved_bin()
    if not b:
        return ""
    try:
        r = subprocess.run([b, "--version"], capture_output=True, text=True, timeout=5)
        return (r.stdout + r.stderr).strip().split("\n")[0]
    except Exception:
        return "?"

def platform_info():
    b = _resolved_bin()
    return {
        "os":        platform.system(),
        "arch":      platform.machine(),
        "bin":       b or "(belum ditemukan)",
        "bin_found": bool(b),
        "bundle":    _bundle_path(),
    }

def _cf_fname():
    sys_map = {
        ("Windows", "AMD64"):  "cloudflared-windows-amd64.exe",
        ("Windows", "x86_64"): "cloudflared-windows-amd64.exe",
        ("Windows", "x86"):    "cloudflared-windows-386.exe",
        ("Linux",   "x86_64"): "cloudflared-linux-amd64",
        ("Linux",   "aarch64"):"cloudflared-linux-arm64",
        ("Linux",   "armv7l"): "cloudflared-linux-arm",
        ("Darwin",  "x86_64"): "cloudflared-darwin-amd64.tgz",
        ("Darwin",  "arm64"):  "cloudflared-darwin-arm64.tgz",
    }
    key = (platform.system(), platform.machine())
    fname = sys_map.get(key)
    if not fname:
        raise RuntimeError(f"Platform tidak didukung: {key}")
    return fname

_CF_CDN      = "https://github.com/cloudflare/cloudflared/releases/latest/download/"
_lock        = threading.Lock()
_dl_progress = -1
_dl_error    = ""

def download_binary():
    global _dl_progress, _dl_error
    with _lock:
        if 0 <= _dl_progress <= 100:
            return
        _dl_progress = 0
        _dl_error    = ""

    def _do():
        global _dl_progress, _dl_error
        try:
            fname = _cf_fname()
            url   = _CF_CDN + fname
            dest  = _bundle_path()
            tmp   = dest + ".tmp"
            def _hook(count, block, total):
                global _dl_progress
                if total > 0:
                    _dl_progress = min(99, int(count * block * 100 / total))
            urllib.request.urlretrieve(url, tmp, reporthook=_hook)
            os.replace(tmp, dest)
            if not _IS_WIN:
                os.chmod(dest, 0o755)
            _resolved_bin()
            with _lock:
                _dl_progress = 101
        except Exception as e:
            with _lock:
                _dl_progress = -2
                _dl_error    = str(e)

    threading.Thread(target=_do, daemon=True).start()

def dl_status():
    with _lock:
        p, e = _dl_progress, _dl_error
    if p == 101 or (p == -1 and bin_ok()):
        return {"state": "done",        "progress": 100, "error": "",  "version": cf_version()}
    if p == -2:
        return {"state": "error",       "progress": 0,   "error": e,   "version": ""}
    if p >= 0:
        return {"state": "downloading", "progress": p,   "error": "",  "version": ""}
    return     {"state": "missing",     "progress": 0,   "error": "",  "version": ""}

# login - SELALU fresh, tidak auto-detect cert lama
_proc_login = None
_login_url  = ""
_login_done = False

def start_login():
    # Jalankan cloudflared tunnel login baru.
    # Tidak auto-detect cert lama. User klik URL sendiri di browser.
    global _proc_login, _login_url, _login_done
    b = _resolved_bin()
    if not b:
        return {"ok": False, "error": "cloudflared belum ada"}
    with _lock:
        if _proc_login and _proc_login.poll() is None:
            return {"ok": True, "url": _login_url, "done": _login_done}
        _login_url  = ""
        _login_done = False

    def _read(proc):
        global _login_url, _login_done
        try:
            for line in proc.stdout:
                line = line.strip()
                if not _login_url:
                    m = re.search(r"(https://\S+)", line)
                    if m:
                        with _lock:
                            _login_url = m.group(1)
                if any(kw in line for kw in ("cert.pem", "You have successfully", "logged in")):
                    with _lock:
                        _login_done = True
        except Exception:
            pass

    p = subprocess.Popen([b, "tunnel", "login"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, bufsize=1)
    with _lock:
        _proc_login = p
    threading.Thread(target=_read, args=(p,), daemon=True).start()
    for _ in range(16):
        time.sleep(0.5)
        with _lock:
            url = _login_url
        if url:
            break
    with _lock:
        return {"ok": True, "url": _login_url, "done": _login_done}

def login_status():
    with _lock:
        p    = _proc_login
        url  = _login_url
        done = _login_done
    running = p is not None and p.poll() is None
    return {"running": running, "url": url, "done": done}

def cancel_login():
    global _proc_login, _login_url, _login_done
    with _lock:
        p = _proc_login
    if p and p.poll() is None:
        p.terminate()
        try:    p.wait(3)
        except Exception: p.kill()
    with _lock:
        _proc_login = None
        _login_url  = ""
        _login_done = False
    return {"ok": True}

def list_tunnels():
    b = _resolved_bin()
    if not b:
        return []
    try:
        r = subprocess.run([b, "tunnel", "list", "--output", "json"],
                           capture_output=True, text=True, timeout=15)
        data = json.loads(r.stdout or "[]")
        return [{"id": t.get("id",""), "name": t.get("name",""),
                 "created": t.get("created_at","")} for t in (data or [])]
    except Exception:
        return []

def create_tunnel(name):
    b = _resolved_bin()
    if not b:
        return {"ok": False, "error": "cloudflared belum ada"}
    if not name.strip():
        return {"ok": False, "error": "nama tunnel kosong"}
    try:
        r = subprocess.run([b, "tunnel", "create", name.strip()],
                           capture_output=True, text=True, timeout=30)
        out = r.stdout + r.stderr
        m = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", out)
        if m:
            return {"ok": True, "id": m.group(1), "name": name.strip()}
        return {"ok": False, "error": out.strip() or "UUID tidak ditemukan"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def delete_tunnel(tid):
    b = _resolved_bin()
    if not b:
        return {"ok": False, "error": "cloudflared belum ada"}
    try:
        r = subprocess.run([b, "tunnel", "delete", "-f", tid],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return {"ok": True}
        return {"ok": False, "error": (r.stdout + r.stderr).strip()}
    except Exception as e:
        return {"ok": False, "error": str(e)}

_proc_tunnel = None

def tunnel_running():
    with _lock:
        return _proc_tunnel is not None and _proc_tunnel.poll() is None

def tunnel_start(config_yml):
    global _proc_tunnel
    b = _resolved_bin()
    if not b:
        return "cloudflared belum ada"
    if not os.path.exists(config_yml):
        return "config.tunnel.yml tidak ada"
    if tunnel_running():
        return "tunnel sudah jalan"
    log = open(CF_LOG, "ab")
    try:
        p = subprocess.Popen([b, "tunnel", "--config", config_yml, "run"],
                             stdout=log, stderr=log)
        with _lock:
            _proc_tunnel = p
        return f"tunnel start (pid {p.pid})"
    except Exception as e:
        return f"error: {e}"

def tunnel_stop():
    global _proc_tunnel
    with _lock:
        p = _proc_tunnel
    if p is None or p.poll() is not None:
        return "tunnel memang mati"
    p.terminate()
    try:    p.wait(5)
    except subprocess.TimeoutExpired: p.kill()
    with _lock:
        _proc_tunnel = None
    return "tunnel stop"

def tunnel_status():
    b = _resolved_bin()
    yml = os.path.join(HERE, "config.tunnel.yml")
    return {
        "running":  tunnel_running(),
        "bin_ok":   bool(b),
        "version":  cf_version(),
        "tunnels":  list_tunnels(),
        "log_tail": _tail_log(40),
        "yml_ok":   os.path.exists(yml),
        "yml_path": yml,
    }

# ── CF API (via token) ───────────────────────────────────────────────────────

def _cf_api(token, path, method="GET", body=None):
    url = "https://api.cloudflare.com/client/v4" + path
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())
    except Exception as e:
        return {"success": False, "errors": [{"message": str(e)}]}

def cf_api_zones(token):
    """Ambil daftar zone (domain) dari akun CF."""
    r = _cf_api(token, "/zones?per_page=50")
    if not r.get("success"):
        errs = r.get("errors", [])
        return {"ok": False, "error": errs[0].get("message","?") if errs else "API error"}
    zones = [{"id": z["id"], "name": z["name"], "status": z["status"]}
             for z in r.get("result", [])]
    return {"ok": True, "zones": zones}

def cf_api_create_dns(token, zone_id, zone_name, tunnel_id, subdomain="socks"):
    """
    Buat CNAME wildcard *.{subdomain}.{zone_name} -> {tunnel_id}.cfargotunnel.com
    Proxy OFF (DNS only) — raw TCP tunnel tidak bisa lewat CF HTTP proxy.
    """
    name   = f"*.{subdomain}.{zone_name}"
    target = f"{tunnel_id}.cfargotunnel.com"
    body   = {"type": "CNAME", "name": name, "content": target,
              "ttl": 1, "proxied": False}
    r = _cf_api(token, f"/zones/{zone_id}/dns_records", method="POST", body=body)
    if r.get("success"):
        rec = r.get("result", {})
        return {"ok": True, "id": rec.get("id",""), "name": name, "target": target}
    errs = r.get("errors", [])
    msg  = errs[0].get("message","?") if errs else "API error"
    # 81057 = record already exists — anggap ok
    if errs and errs[0].get("code") == 81057:
        return {"ok": True, "id": "", "name": name, "target": target, "note": "sudah ada"}
    return {"ok": False, "error": msg}

def generate_tunnel_yml(tunnel_id, domain, subdomain="socks"):
    """
    Generate config.tunnel.yml dari tunnel_id + domain.
    Credentials path otomatis dari ~/.cloudflared/<tunnel_id>.json.
    Return {ok, path, error}
    """
    cred = os.path.join(CF_DIR, f"{tunnel_id}.json")
    if not os.path.exists(cred):
        return {"ok": False, "error": f"credentials tidak ada: {cred}"}

    # baca akun dari accounts.txt untuk generate ingress
    acc_path = os.path.join(HERE, "accounts.txt")
    n_acc = 0
    if os.path.exists(acc_path):
        for l in open(acc_path, encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#"):
                n_acc += 1

    # baca settings untuk base port
    setf = os.path.join(HERE, "webui.settings.json")
    base      = 1081
    base_http = 2081
    try:
        s = json.load(open(setf, encoding="utf-8"))
        base      = int(s.get("base", 1081))
        bh        = int(s.get("base_http") or 0)
        base_http = bh if bh else base + 1000
    except Exception:
        pass

    yml  = os.path.join(HERE, "config.tunnel.yml")
    lines = [
        f"tunnel: {tunnel_id}",
        f"credentials-file: {cred}",
        "ingress:",
    ]
    for i in range(n_acc):
        n = i + 1
        lines.append(f"  - hostname: socks{n}.{subdomain}.{domain}")
        lines.append(f"    service: tcp://localhost:{base + i}")
        lines.append(f"  - hostname: http{n}.{subdomain}.{domain}")
        lines.append(f"    service: tcp://localhost:{base_http + i}")
    lines.append("  - service: http_status:404")

    try:
        with open(yml, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return {"ok": True, "path": yml, "accounts": n_acc,
                "cred": cred, "domain": domain, "subdomain": subdomain}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def yml_preview():
    """Baca config.tunnel.yml yang ada, return isinya."""
    yml = os.path.join(HERE, "config.tunnel.yml")
    if not os.path.exists(yml):
        return {"ok": False, "error": "config.tunnel.yml belum ada"}
    try:
        return {"ok": True, "content": open(yml, encoding="utf-8").read()}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _tail_log(n=40):
    if not os.path.exists(CF_LOG):
        return ""
    try:
        return "".join(open(CF_LOG, encoding="utf-8", errors="replace").readlines()[-n:])
    except Exception:
        return ""
