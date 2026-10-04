#!/usr/bin/env python
# vlessbank: daftar link vless:// -> config xray, 1 akun = 2 inbound (SOCKS5 + HTTP proxy).
# Port SOCKS  = base      + i  (default 1081, 1082, ...)
# Port HTTP   = base+1000 + i  (default 2081, 2082, ...)
# mode: lokal (default) | direct (0.0.0.0 + auth) | tunnel (cloudflared yml ikut digenerate)
import argparse, json, sys
from urllib.parse import urlparse, parse_qs, unquote

def build_outbound(i, link):
    u = urlparse(link.strip())
    if u.scheme != "vless":
        return None, f"SKIP (bukan vless): {link[:40]}..."
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    uuid, addr = u.username, u.hostname
    port = u.port or 443
    name = unquote(u.fragment or f"acc{i+1}")
    net, sec = q.get("type", "tcp"), q.get("security", "none")
    stream = {"network": net, "security": sec}
    if sec == "tls":
        tls = {"serverName": q.get("sni", addr)}
        if "alpn" in q:
            tls["alpn"] = q["alpn"].split(",")
        if "fp" in q:
            tls["fingerprint"] = q["fp"]
        stream["tlsSettings"] = tls
    elif sec == "reality":
        stream["realitySettings"] = {"serverName": q.get("sni", addr),
            "publicKey": q.get("pbk", ""), "shortId": q.get("sid", ""),
            "fingerprint": q.get("fp", "chrome")}
    if net == "ws":
        ws = {"path": unquote(q.get("path", "/"))}
        if "host" in q:
            ws["headers"] = {"Host": q["host"]}
        stream["wsSettings"] = ws
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
    ob = {"tag": f"acc{i+1}", "protocol": "vless",
        "settings": {"vnext": [{"address": addr, "port": port,
            "users": [{"id": uuid, "encryption": "none", "flow": q.get("flow", "")}]}]},
        "streamSettings": stream}
    return ob, name

def socks_inbound(tag, listen, port, auth):
    s = {"auth": "noauth", "udp": True}
    if auth:
        user, pw = auth.split(":", 1)
        s = {"auth": "password", "accounts": [{"user": user, "pass": pw}], "udp": True}
    return {"tag": tag, "listen": listen, "port": port, "protocol": "socks",
            "settings": s,
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}}

def http_inbound(tag, listen, port, auth):
    s = {}
    if auth:
        user, pw = auth.split(":", 1)
        s = {"accounts": [{"user": user, "pass": pw}]}
    return {"tag": tag, "listen": listen, "port": port, "protocol": "http",
            "settings": s,
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}}

def main():
    ap = argparse.ArgumentParser(description="vlessbank generator")
    ap.add_argument("accounts", nargs="?", default="accounts.txt")
    ap.add_argument("-o", "--out", default="config.json")
    ap.add_argument("--base", type=int, default=1081,
                    help="port SOCKS awal (default 1081)")
    ap.add_argument("--base-http", type=int, default=0,
                    help="port HTTP proxy awal (default base+1000, jadi 2081)")
    ap.add_argument("--listen", default="127.0.0.1",
                    help="127.0.0.1 = lokal saja (default), 0.0.0.0 = expose publik")
    ap.add_argument("--auth", metavar="USER:PASS",
                    help="SOCKS user:pass, wajib jika --listen 0.0.0.0")
    ap.add_argument("--tunnel", metavar="DOMAIN",
                    help="generate juga cloudflared config.yml: socksN.DOMAIN -> port")
    ap.add_argument("--tunnel-id", help="UUID tunnel cloudflare (untuk config.yml)")
    ap.add_argument("--insecure", action="store_true",
                    help="set allowInsecure=true di semua outbound TLS")
    args = ap.parse_args()

    if args.listen == "0.0.0.0" and not args.auth:
        sys.exit("ERROR: --listen 0.0.0.0 wajib pakai --auth (open proxy = IP cepat ke-flag)")
    if args.auth and ":" not in args.auth:
        sys.exit("ERROR: format --auth USER:PASS")

    base_http = args.base_http if args.base_http else args.base + 1000

    try:
        links = [l.strip() for l in open(args.accounts, encoding="utf-8")
                 if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        sys.exit(f"ERROR: {args.accounts} tidak ada")

    # dedup: kunci = uuid+host+port+path. duplikat belakangan dibuang.
    seen, uniq, dup = set(), [], 0
    for link in links:
        u = urlparse(link)
        q = parse_qs(u.query)
        key = (u.username, u.hostname, u.port or 443,
               unquote(q.get("path", [""])[0]))
        if key in seen:
            dup += 1
            continue
        seen.add(key)
        uniq.append(link)

    inbounds, outbounds, rules, names = [], [], [], []
    i = 0
    for link in uniq:
        ob, name = build_outbound(i, link)
        if ob is None:
            print(name)
            continue
        if args.insecure and ob["streamSettings"].get("security") == "tls":
            # Xray 26.x: allowInsecure masih didukung di tlsSettings
            tls = ob["streamSettings"].setdefault("tlsSettings", {})
            tls["allowInsecure"] = True
        tag = ob["tag"]
        port_s = args.base + i
        port_h = base_http + i

        inbounds.append(socks_inbound(f"in_s{i+1}", args.listen, port_s, args.auth))
        inbounds.append(http_inbound(f"in_h{i+1}", args.listen, port_h, args.auth))
        outbounds.append(ob)
        # kedua inbound (SOCKS + HTTP) routing ke outbound yang sama -> IP keluar sama
        rules.append({"type": "field",
                       "inboundTag": [f"in_s{i+1}", f"in_h{i+1}"],
                       "outboundTag": tag})
        names.append((port_s, port_h, name))
        i += 1
    if not names:
        sys.exit("ERROR: tidak ada akun valid")

    cfg = {"log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"], "queryStrategy": "UseIPv4",
            "disableCache": False, "disableFallback": False},
        "inbounds": inbounds, "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules}}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    if args.tunnel:
        yml = args.out[:-5] + ".tunnel.yml" if args.out.endswith(".json") else "config.tunnel.yml"
        with open(yml, "w", encoding="utf-8") as f:
            f.write(f"tunnel: {args.tunnel_id or '<TUNNEL-UUID>'}\n")
            f.write("credentials-file: <PATH>/<TUNNEL-UUID>.json\n")
            f.write("ingress:\n")
            for port_s, port_h, _ in names:
                n = port_s - args.base + 1
                f.write(f"  - hostname: socks{n}.{args.tunnel}\n    service: tcp://localhost:{port_s}\n")
                f.write(f"  - hostname: http{n}.{args.tunnel}\n    service: tcp://localhost:{port_h}\n")
            f.write("  - service: http_status:404\n")
        print(f"tunnel yml -> {yml}")

    print(f"{len(names)} akun -> {args.out} (listen {args.listen}, SOCKS {args.base}+, HTTP {base_http}+)"
          + (f", {dup} duplikat dibuang" if dup else "")
          + (", allowInsecure ON" if args.insecure else ""))
    for port_s, port_h, name in names:
        n = port_s - args.base + 1
        if args.tunnel:
            print(f"  SOCKS socks{n}.{args.tunnel} | HTTP http{n}.{args.tunnel}  <-  {name}")
        else:
            print(f"  SOCKS :{port_s} | HTTP :{port_h}  <-  {name}")

if __name__ == "__main__":
    main()
