#!/usr/bin/env bash
# ============================================================================
#  vless-bank — one-shot installer
#  Buka: clone repo, download xray + cloudflared, setup config, tampil URL webui.
#
#  Pakai:
#    curl -fsSL https://raw.githubusercontent.com/jhopan/vless-bank/master/install.sh | bash
#
#  Atur via env (semua opsional):
#    VLESSBANK_DIR          lokasi app          (default: ~/vless-bank)
#    VLESSBANK_WEBUI_PORT   port webui          (default: 9000)
#    VLESSBANK_BASE_PORT    port SOCKS awal     (default: 1081)
#    VLESSBANK_BASE_HTTP    port HTTP awal      (default: 0 = base+1000)
#    VLESSBANK_LISTEN       listen address      (default: 127.0.0.1)
#    VLESSBANK_AUTH         user:pass proxy     (wajib kalau listen=0.0.0.0)
#    VLESSBANK_FORCE        overwrite settings  (default: 0)
#    VLESSBANK_SKIP_BINS    skip download bin   (default: 0)
# ============================================================================
set -euo pipefail

RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; BLD=$'\e[1m'; NC=$'\e[0m'

# ---------- env / default ----------
REPO_URL="${VLESSBANK_REPO:-https://github.com/jhopan/vless-bank}"
APP_DIR="${VLESSBANK_DIR:-$HOME/vless-bank}"
WEBUI_PORT="${VLESSBANK_WEBUI_PORT:-9000}"
BASE_PORT="${VLESSBANK_BASE_PORT:-1081}"
BASE_HTTP="${VLESSBANK_BASE_HTTP:-0}"
LISTEN="${VLESSBANK_LISTEN:-127.0.0.1}"
AUTH="${VLESSBANK_AUTH:-}"
FORCE="${VLESSBANK_FORCE:-0}"
SKIP_BINS="${VLESSBANK_SKIP_BINS:-0}"

# charge .env kalau ada (override default di atas)
if [ -f "$APP_DIR/.env" ]; then
  # shellcheck disable=source
  . "$APP_DIR/.env"
fi

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s  %s\n' "${GRN}✓${NC}" "$*"; }
warn() { printf '%s  %s\n' "${YLW}!${NC}" "$*"; }
die()  { printf '%s  %s\n' "${RED}✗${NC}" "$*" >&2; exit 1; }

# ---------- platform ----------
OS=$(uname -s); ARCH=$(uname -m)
case "$OS" in
  Linux)            EXT="";  CF_ASSET="cloudflared-linux-amd64";                                   ;;
  MINGW*|MSYS*|CYGWIN*) EXT=".exe"; CF_ASSET="cloudflared-windows-amd64.exe";                       ;;
  *) die "OS '$OS' belum didukung. Linux / Windows (git-bash) saja." ;;
esac
case "$ARCH" in
  x86_64|amd64) CF_ASSET=$( [ "$OS" = Linux ] && echo cloudflared-linux-amd64 || echo "$CF_ASSET"); XRAY_ZIP=$( [ "$OS" = Linux ] && echo Xray-linux-64.zip || echo Xray-windows-64.zip) ;;
  aarch64|arm64) CF_ASSET=$( [ "$OS" = Linux ] && echo cloudflared-linux-arm64 || echo "$CF_ASSET"); XRAY_ZIP=$( [ "$OS" = Linux ] && echo Xray-linux-arm64-v8.zip || echo "$XRAY_ZIP") ;;
  *) die "Arch '$ARCH' belum didukung." ;;
esac

XRAY_BIN="xray$EXT"
CF_BIN="cloudflared$EXT"

# ---------- prereq ----------
command -v curl  >/dev/null || die "curl belum install"
command -v python3 >/dev/null || die "python3 belum install"
command -v unzip >/dev/null || warn "unzip belum ada — pakai python fallback"
! command -v pip3 >/dev/null && warn "pip3 belum ada (stdlib-only, jadi gak blokir)"

# ---------- 1. clone ----------
if [ ! -d "$APP_DIR" ]; then
  say "  clone -> $APP_DIR"
  git clone --depth 1 "$REPO_URL" "$APP_DIR" || die "git clone gagal"
elif [ -f "$APP_DIR/gen.py" ]; then
  say "  sudah ada -> pull"
  git -C "$APP_DIR" pull --ff-only 2>/dev/null || warn "pull gagal, jalan dengan file yang ada"
else
  die "$APP_DIR ada tapi bukan vless-bank. Ganti VLESSBANK_DIR atau hapus folder."
fi
cd "$APP_DIR"

# ---------- 2. binaries ----------
if [ "$SKIP_BINS" = "0" ]; then
  # xray
  if [ ! -x "$XRAY_BIN" ]; then
    say "  download xray ($XRAY_ZIP) ..."
    URL="https://github.com/XTLS/Xray-core/releases/latest/download/$XRAY_ZIP"
    rm -rf .xray_tmp && mkdir -p .xray_tmp
    curl -fsSL --retry 3 -o .xray_tmp/x.zip "$URL" || die "download xray gagal: $URL"
    if command -v unzip >/dev/null; then unzip -oq .xray_tmp/x.zip -d .xray_tmp
    else python3 -c "import zipfile;zipfile.ZipFile('.xray_tmp/x.zip').extractall('.xray_tmp')"; fi
    mv -f .xray_tmp/xray* "$XRAY_BIN" 2>/dev/null
    rm -rf .xray_tmp
    [ -x "$XRAY_BIN" ] || die "xray binary gak ketemu setelah unzip"
  fi
  # cloudflared
  if [ ! -x "$CF_BIN" ]; then
    say "  download cloudflared ($CF_ASSET) ..."
    URL="https://github.com/cloudflare/cloudflared/releases/latest/download/$CF_ASSET"
    curl -fsSL --retry 3 -o "$CF_BIN" "$URL" || die "download cloudflared gagal: $URL"
  fi
  chmod +x "$XRAY_BIN" "$CF_BIN" 2>/dev/null || true
fi

# ---------- 3. verify ----------
./"$XRAY_BIN" version 2>/dev/null | head -1 || die "xray gak jalan"
./"$CF_BIN" --version 2>/dev/null | head -1 || die "cloudflared gak jalan"
ok "xray: $("$PWD/$XRAY_BIN" version 2>/dev/null | head -1)"
ok "cloudflared: $("$PWD/$CF_BIN" --version 2>/dev/null | head -1)"

# ---------- 4. settings ----------
SETF="$APP_DIR/webui.settings.json"
if [ ! -f "$SETF" ] || [ "$FORCE" = "1" ]; then
  cat > "$SETF" <<EOF
{
  "xray": "",
  "base": $BASE_PORT,
  "base_http": $BASE_HTTP,
  "listen": "$LISTEN",
  "auth": "$AUTH",
  "tunnel": "",
  "tunnel_id": "",
  "xray_path": "$APP_DIR/$XRAY_BIN",
  "insecure": true
}
EOF
  ok "settings -> $SETF"
else
  warn "settings sudah ada — retained (VLESSBANK_FORCE=1 untuk overwrite)"
fi

# ---------- 5. generate config ----------
if [ -s "$APP_DIR/accounts.txt" ]; then
  ARGS=(accounts.txt --base "$BASE_PORT" --listen "$LISTEN")
  [ "$BASE_HTTP" != "0" ] && ARGS+=(--base-http "$BASE_HTTP")
  [ -n "$AUTH" ] && ARGS+=(--auth "$AUTH")
  python3 gen.py "${ARGS[@]}"
else
  warn "accounts.txt kosong — tempel link vless:// di file lalu:"
  warn "  cd $APP_DIR && python3 gen.py accounts.txt && python3 webui.py --port $WEBUI_PORT"
fi

# ---------- 6. summary ----------
URL="http://$LISTEN:$WEBUI_PORT/"
say
say "${BLD}========== VLESS-BANK SIAP ==========${NC}"
say "  App      : $APP_DIR"
say "  WebUI    : $URL"
say "  Login    : admin / admin   (ganti di Pengaturan)"
say "  Run      : cd $APP_DIR && python3 webui.py --port $WEBUI_PORT"
say "  Binaries : $XRAY_BIN + $CF_BIN (auto-detect, no PATH setup)"
say "${BLD}===================================${NC}"