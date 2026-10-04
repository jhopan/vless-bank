# vlessbank

Banyak akun `vless://` -> satu proses Xray -> 1 akun = 1 port SOCKS.

```
accounts.txt (link vless, 1 baris 1 akun)
     |
     v
gen.py  ->  config.json (+ config.tunnel.yml jika mode tunnel)
     |
     v
xray run -c config.json
     |
     v
127.0.0.1:1081 -> akun 1    (IP keluar selalu IP akun 1)
127.0.0.1:1082 -> akun 2    (IP keluar selalu IP akun 2)
127.0.0.1:10NN -> akun N
```

IP keluar stabil per port -- cocok untuk sesi login/banking. IP gak tukar-tukar antar koneksi.

## Pakai

```bash
# mode lokal (default): hanya 127.0.0.1
python gen.py accounts.txt

# mode direct: VPS / mesin dengan IP publik
python gen.py accounts.txt --listen 0.0.0.0 --auth user:pass

# mode tunnel: mesin tanpa IP publik (laptop rumah), lewat Cloudflare Tunnel
python gen.py accounts.txt --tunnel socks.example.com --tunnel-id <UUID>
cloudflared tunnel run
```

Client jauh (HP / PC lain), mode tunnel:

```bash
cloudflared access tcp --hostname socks1.socks.example.com --url 127.0.0.1:1081
```

lalu browser/ekstensi proxy pakai `socks5://127.0.0.1:1081`.

DNS route per subdomain (sekali saja):

```bash
cloudflared tunnel route dns <tunnel> socks1.socks.example.com
```

## Catatan

- `accounts.txt` berisi UUID = kredensial. Sudah di-gitignore. Jangan pernah push.
- Mode direct (0.0.0.0) WAJIB `--auth`. SOCKS terbuka = open proxy, IP cepat ke-flag.
- Mode tunnel auth-nya ditangani Cloudflare Access (service token di sisi client).
- Xray: satu binary ~35MB, RAM ~30-40MB stabil walau banyak akun.
- Download xray: https://github.com/XTLS/Xray-core/releases

## WebUI

```bash
python webui.py --port 9000 --xray /path/ke/xray
#                [--base 1081] [--auth user:pass] [--tunnel domain --tunnel-id UUID]
```

Buka `http://127.0.0.1:9000/`, login pakai token di file `webui.token` (auto-dibuat saat pertama jalan).

Fitur: Start/Stop/Restart xray, Regenerate config, tambah/hapus akun (paste link `vless://` langsung dari browser), Test IP keluar per port (curl ipify via SOCKS).

Semua aksi tambah/hapus otomatis regenerate config + restart xray kalau sedang jalan.

## Struktur

```
gen.py                  generator config (stdlib only)
webui.py                panel web kendali (stdlib only, 1 file)
accounts.txt            akun asli (gitignored)
accounts.example.txt    contoh format
config.json             output (gitignored)
config.tunnel.yml       output cloudflared (gitignored)
webui.token             token login WebUI (gitignored)
```
