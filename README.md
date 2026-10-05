# vless-bank

Banyak akun `vless://` -> satu proses Xray -> 1 akun = 2 port: **SOCKS5 + HTTP proxy**.

```
accounts.txt (link vless, 1 baris 1 akun)
     |
     v
gen.py  ->  config.json (+ config.tunnel.yml jika mode tunnel)
     |
     v
xray run -c config.json
     |
     +--> 127.0.0.1:1081 (SOCKS5)  -> akun 1
     +--> 127.0.0.1:2081 (HTTP)    -> akun 1
     +--> 127.0.0.1:1082 (SOCKS5)  -> akun 2
     +--> 127.0.0.1:2082 (HTTP)    -> akun 2
     ...
```

Port SOCKS = `base  + i` (default 1081). Port HTTP = `base+1000 + i` (default 2081).
Dua inbound route ke SAMA outbound -> IP keluar identik per akun. IP stabil per port -- cocok untuk sesi login/banking.

## Pakai (CLI)

```bash
# mode lokal (default): hanya 127.0.0.1
python gen.py accounts.txt

# mode direct: VPS / mesin dengan IP publik (wajib auth!)
python gen.py accounts.txt --listen 0.0.0.0 --auth user:pass

# port HTTP manual
python gen.py accounts.txt --base-http 2081

# mode tunnel: mesin tanpa IP publik, lewat Cloudflare Tunnel
python gen.py accounts.txt --tunnel socks.example.com --tunnel-id <UUID>
cloudflared tunnel run
```

## Pakai (WebUI, recommended)

```bash
python webui.py --port 9000
# binary xray + cloudflared auto-scan di folder project, atau via Pengaturan
```

Buka `http://127.0.0.1:9000/` -> login `admin/admin` (ganti di Pengaturan).

Dashboard: start/stop/restart xray, regenerate config, tambah/hapus akun (paste `vless://`), test IP per port.

### Cloudflare menu (via web, no terminal)

Menu **Cloudflare** alur completo:

1. Binary cloudflared — auto-scan / download otomatis
2. Login CF — klik tombol, link muncul, authorize di browser (fresh setiap kali)
3. Buat / Pilih tunnel — tunnel ID tersimpan otomatis
4. Setup Domain — paste CF API token -> Load Domain (list zone) -> pilih domain -> **Generate config.tunnel.yml** (credentials path auto) -> **Buat DNS Wildcard via API** (CNAME `*.socks.domain.com`)
5. DNS wildcard summary
6. Start/Stop tunnel + live log

### Client

| Mode | URI |
|---|---|
| Laptop sendiri | `socks5://127.0.0.1:1081` atau `http://127.0.0.1:2081` |
| LAN device | `socks5://IP_LAPTOP:1081` atau `http://IP_LAPTOP:2081` |
| Remote (tunnel) | `cloudflared access tcp --hostname socks1.socks.domain.com --url 127.0.0.1:1081` then `socks5://user:pass@127.0.0.1:1081` |

DNS wildcard: satu CNAME `*.socks.domain.com` -> `<tunnel-id>.cfargotunnel.com`, Proxy **OFF** (raw TCP).

## Catatan

- `accounts.txt` berisi UUID = kredensial. Gitignored — jangan pernah push.
- Mode direct (0.0.0.0) WAJIB `--auth`. Proxy terbuka tanpa auth = open proxy, IP cepat ke-flag.
- HTTPS client traffic pakai CONNECT — HTTP inbound xray juga tunneling TLS-nya, sama bagus SOCKS.
- Xray: binary ~35MB, RAM ~30-60MB stabil walau banyak akun (18 akun da ketahua).
- cloudflared: 1 proses, RAM ~40-80MB, unmetered bandwidth, 1000 tunnel/akun limit free plan.
- Dua binary bisa download via webui — xray di Pengaturan, cloudflared di menu Cloudflare.

## Struktur

```
gen.py                  generator config (stdlib only) — dual inbound per akun
webui.py                panel web kendali + CF manager (stdlib only)
cf.py                   cloudflared manager (stdlib only)
accounts.txt            akun asli (gitignored)
accounts.example.txt    contoh format
config.json             output xray (gitignored)
config.tunnel.yml       output cloudflared (gitignored)
webui.login             login hash panel (gitignored)
webui.settings.json     settings panel (gitignored)
xray.exe / cloudflared.exe  binary lokal (gitignored)
```
