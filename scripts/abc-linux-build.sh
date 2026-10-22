#!/usr/bin/env bash
# A/B/C Linux server build: pinned sources, isolated stock/candidate worktrees.
# --plan is read-only and usable on macOS; --build is Linux-only and is NOT a benchmark.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../integration/versions/versions.env
source "$ROOT/integration/versions/versions.env"
MODE="${1:---plan}"
case "$MODE" in --plan|--build) ;; *) echo "Usage: $0 [--plan|--build]" >&2; exit 2;; esac
BASE="$ROOT/work/abc-linux"
DEST="$ROOT/build/abc-linux"
NGI541_PREFIX="${NGI541_PREFIX:-}"
PCRE2_PREFIX="${PCRE2_PREFIX:-/usr}"
JOBS="${ABC_BUILD_JOBS:-4}"
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo 'ERROR: ABC_BUILD_JOBS must be positive integer' >&2; exit 2; }
cat <<EOF
ABC Linux build plan ($MODE)
  NGINX $NGINX_VERSION SHA256 $NGINX_SHA256
  OpenSSL $OPENSSL_VERSION SHA256 $OPENSSL_SHA256
  NGI541 $NGI541_VERSION commit $NGI541_COMMIT
  A/B: stock NGINX (--with-http_v2_module --with-http_v3_module)
  C:   separate patched NGINX with -DNGX_QUIC_NGI541=1
  output: $DEST/{stock,ngi541-direct}
  isolated source/build: $BASE
  job limit: $JOBS
  client: NOT BUILT HERE; pinned loadgen separately qualified
EOF
[[ "$MODE" == '--plan' ]] && exit 0
[[ "$(uname -s)" == Linux ]] || { echo 'ERROR: --build requires Linux' >&2; exit 2; }
for tool in curl sha256sum tar patch make cc perl python3; do
  command -v "$tool" >/dev/null || { echo "ERROR: missing $tool" >&2; exit 2; }
done
[[ -d "$PCRE2_PREFIX/include" && -d "$PCRE2_PREFIX/lib" ]] || {
  echo "ERROR: PCRE2_PREFIX invalid: $PCRE2_PREFIX" >&2; exit 2;
}
[[ -n "$NGI541_PREFIX" && "$NGI541_PREFIX" == /* ]] || {
  echo 'ERROR: NGI541_PREFIX must be absolute path to installed NGI541 0.1.1' >&2; exit 2;
}
[[ -f "$NGI541_PREFIX/include/ngi541/engine.h" ]] || {
  echo 'ERROR: missing NGI541 public header' >&2; exit 2;
}
[[ -d "$NGI541_PREFIX/lib" ]] || { echo 'ERROR: missing NGI541 lib' >&2; exit 2; }
NGI541_LIB="$NGI541_PREFIX/lib/libngi541_engine.so"
[[ -f "$NGI541_LIB" ]] || { echo "ERROR: missing $NGI541_LIB" >&2; exit 2; }
# Refuse to reuse a previous partial build, thereby preventing sample contamination.
[[ ! -e "$BASE" && ! -e "$DEST" ]] || {
  echo "ERROR: pre-existing ABC work/build directory: inspect $BASE and $DEST first" >&2; exit 3;
}
mkdir -p "$BASE/downloads" "$DEST"
fetch_checked() {
  local name="$1" url="$2" sha="$3" out="$BASE/downloads/$1"
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2 -o "$out.part" "$url"
  mv "$out.part" "$out"
  echo "$sha  $out" | sha256sum -c -
}
fetch_checked "nginx-${NGINX_VERSION}.tar.gz" "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" "$NGINX_SHA256"
fetch_checked "openssl-${OPENSSL_VERSION}.tar.gz" "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" "$OPENSSL_SHA256"
PATCH="$ROOT/integration/patches/nginx-${NGINX_VERSION}/0001-ngi541-quic-crypto.patch"
[[ -f "$PATCH" ]] || { echo "ERROR: integration patch missing" >&2; exit 2; }
for VARIANT in stock ngi541-direct; do
  STAGE="$BASE/$VARIANT"
  mkdir -p "$STAGE" "$DEST/$VARIANT"
  tar -xzf "$BASE/downloads/nginx-${NGINX_VERSION}.tar.gz" -C "$STAGE"
  tar -xzf "$BASE/downloads/openssl-${OPENSSL_VERSION}.tar.gz" -C "$STAGE"
  NGINX_SRC="$STAGE/nginx-${NGINX_VERSION}"
  OPENSSL_SRC="$STAGE/openssl-${OPENSSL_VERSION}"
  CC_OPT="-O2 -g -I$PCRE2_PREFIX/include"
  LD_OPT="-L$PCRE2_PREFIX/lib"
  if [[ "$VARIANT" == ngi541-direct ]]; then
    patch --batch --forward -p1 -d "$NGINX_SRC" < "$PATCH"
    CC_OPT+=" -DNGX_QUIC_NGI541=1 -I$NGI541_PREFIX/include"
    LD_OPT+=" -L$NGI541_PREFIX/lib -Wl,-rpath,$NGI541_PREFIX/lib -lngi541_engine"
  fi
  (
    cd "$NGINX_SRC"
    ./configure \
       --prefix="$DEST/$VARIANT" \
       --with-openssl="$OPENSSL_SRC" \
       --with-http_ssl_module \
       --with-http_v2_module \
       --with-http_v3_module \
       --with-cc-opt="$CC_OPT" \
       --with-ld-opt="$LD_OPT"
    make -j"$JOBS"
    make install
  ) 2>&1 | tee "$STAGE/build.log"
  BIN="$DEST/$VARIANT/sbin/nginx"
  [[ -x "$BIN" ]] || { echo "ERROR: nginx missing for $VARIANT" >&2; exit 3; }
  "$BIN" -V 2>"$STAGE/nginx-version.txt"
  grep -q -- '--with-http_v2_module' "$STAGE/nginx-version.txt"
  grep -q -- '--with-http_v3_module' "$STAGE/nginx-version.txt"
  if [[ "$VARIANT" == ngi541-direct ]]; then
    grep -q -- '-DNGX_QUIC_NGI541=1' "$STAGE/nginx-version.txt"
    ldd "$BIN" > "$STAGE/ldd.txt"
    grep -q 'libngi541_engine.so' "$STAGE/ldd.txt" || {
      echo 'ERROR: NGI541 dynamic library not linked' >&2; exit 3;
    }
    grep -q 'not found' "$STAGE/ldd.txt" && { echo 'ERROR: unresolved dependency' >&2; exit 3; }
  else
    if grep -q -- '-DNGX_QUIC_NGI541=1' "$STAGE/nginx-version.txt"; then
      echo 'ERROR: stock accidentally has NGI541 enabled' >&2; exit 3
    fi
  fi
  # Receipt records hashes/provenance; it does NOT prove HTTP/2/3 handshake yet.
  ABC_VARIANT="$VARIANT" ABC_NGINX_BIN="$BIN" ABC_NGINX_VTXT="$STAGE/nginx-version.txt" \
  ABC_LIB="$NGI541_LIB" ABC_NGINX_VERSION="$NGINX_VERSION" ABC_OPENSSL_VERSION="$OPENSSL_VERSION" \
  ABC_OUTPUT="$STAGE/build-receipt.json" python3 - <<'PY'
import hashlib, json, os, platform, pathlib
file_hash=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
v=os.environ['ABC_VARIANT']; txt=pathlib.Path(os.environ['ABC_NGINX_VTXT']).read_text()
receipt={
  'schema_version':1,'os':'linux','arch':platform.machine(),
  'variant':v, 'nginx_version':os.environ['ABC_NGINX_VERSION'],
  'openssl_version':os.environ['ABC_OPENSSL_VERSION'],
  'binary_sha256':file_hash(os.environ['ABC_NGINX_BIN']),
  'configure_arguments':txt,'ngi541_enabled':v=='ngi541-direct',
  'ngi541_library_sha256':file_hash(os.environ['ABC_LIB']) if v=='ngi541-direct' else None,
}
pathlib.Path(os.environ['ABC_OUTPUT']).write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
PY
  echo "PASS: Linux build $VARIANT binary=$(sha256sum "$BIN" | cut -d' ' -f1)"
done
printf 'PASS: stock and NGI541 Linux binaries built; ALPN/cipher/payload smoke qualification still required\n'
