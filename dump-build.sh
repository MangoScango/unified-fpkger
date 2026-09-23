#!/usr/bin/env bash
# ----------------------------------------------------------------------------
# dump-build.sh
# Dump a running game off a console with ftpdump, then build a fake-pkg from it.
#
# USAGE
#   dump-build.sh [options] IP[:PORT] [build-fpkg options ...]
#     -o, --output-dir DIR  where ftpdump writes the dump (default: cwd)
#     -j, --jobs N          ftpdump parallel downloads (default: 8)
#         --dump-only       stop after dumping
#         --delete-dumps    remove the dumped <TITLEID>-{app,patch,dlc,keystone}
#                           dirs once build-fpkg.sh has succeeded. Irreversible,
#                           and the console is the only other copy.
#     -h, --help            this text
#
#   Anything after IP[:PORT] is forwarded to build-fpkg.sh, e.g.
#     dump-build.sh 192.168.1.50:1337 --out /mnt/pkgs --keystone kscreate
#
#   ftpdump is run as: <host> -a -d -k -p -r -j N -o DIR
#   so app, patch, DLC and the original keystone are all dumped. Only the -app
#   dir is handed to build-fpkg.sh; it finds the sibling -patch and -dlc itself.
# ----------------------------------------------------------------------------
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_FPKG="${BUILD_FPKG:-$SELF_DIR/build-fpkg.sh}"
JOBS=8
OUT_DIR="$PWD"
DUMP_ONLY=0
DELETE_DUMPS=0
HOST=""
declare -a BUILD_ARGS=()

die() { echo "error: $*" >&2; exit 1; }
log() { echo ">> $*" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output-dir) OUT_DIR="${2:?}"; shift 2 ;;
    -j|--jobs)       JOBS="${2:?}"; shift 2 ;;
    --dump-only)     DUMP_ONLY=1; shift ;;
    --delete-dumps)  DELETE_DUMPS=1; shift ;;
    -h|--help)       awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"
                     exit 0 ;;
    *)               HOST="$1"; shift; BUILD_ARGS=("$@"); break ;;
  esac
done

[ -n "$HOST" ] || die "console address required (IP[:PORT])"
case "$JOBS" in ''|*[!0-9]*) die "--jobs must be a positive integer" ;; esac
[ "$JOBS" -ge 1 ] || die "--jobs must be at least 1"
[ -x "$BUILD_FPKG" ] || die "build-fpkg.sh not found or not executable: $BUILD_FPKG"

FTPDUMP="${FTPDUMP:-}"
if [ -z "$FTPDUMP" ]; then
  for c in "$SELF_DIR/ftpdump.sh" "$SELF_DIR/ftpdump"; do
    [ -x "$c" ] && { FTPDUMP="$c"; break; }
  done
fi
[ -n "$FTPDUMP" ] || FTPDUMP="$(command -v ftpdump || true)"
[ -n "$FTPDUMP" ] && [ -x "$FTPDUMP" ] || die "ftpdump not found (set FTPDUMP=/path/to/ftpdump.sh)"

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

DUMP_LOG="$(mktemp)"
STARTED="$(date +%s)"
keep_log=0
cleanup() { [ "$keep_log" -eq 1 ] || rm -f "$DUMP_LOG"; }
trap cleanup EXIT

log "dumping $HOST -> $OUT_DIR (jobs=$JOBS)"
rc=0
if command -v script >/dev/null 2>&1; then
  # A pty keeps ftpdump's progress display working while still capturing output.
  SHELL=/bin/sh script -qefc \
    "$(printf '%q' "$FTPDUMP") $(printf '%q' "$HOST") -a -d -k -p -r -j $JOBS -o $(printf '%q' "$OUT_DIR")" \
    "$DUMP_LOG" || rc=$?
else
  "$FTPDUMP" "$HOST" -a -d -k -p -r -j "$JOBS" -o "$OUT_DIR" 2>&1 | tee "$DUMP_LOG" || true
  rc="${PIPESTATUS[0]}"
fi

if [ "$rc" -ne 0 ]; then
  keep_log=1
  die "ftpdump failed (exit $rc); output kept at $DUMP_LOG"
fi

# ftpdump reports warnings/criticals without failing.
if grep -qaE '[0-9]+ (warning|critical) message' "$DUMP_LOG"; then
  grep -aoE '[0-9]+ (warning|critical) message\(s\)' "$DUMP_LOG" | sort -u \
    | while read -r m; do log "ftpdump reported $m"; done
fi

# "Dumping CUSA12345 app data (123 MB):" names the title that was dumped.
TITLE_ID="$(tr -d '\r' < "$DUMP_LOG" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
  | grep -oE 'Dumping [A-Z]{4}[0-9]{5} app data' | grep -oE '[A-Z]{4}[0-9]{5}' | head -1 || true)"

APP_DIR=""
if [ -n "$TITLE_ID" ] && [ -d "$OUT_DIR/$TITLE_ID-app" ]; then
  APP_DIR="$OUT_DIR/$TITLE_ID-app"
else
  while IFS= read -r d; do
    [ -n "$(find "$d" -newermt "@$STARTED" -print -quit 2>/dev/null)" ] || continue
    [ -z "$APP_DIR" ] || die "cannot tell which dump to build: $(basename "$APP_DIR") and $(basename "$d")"
    APP_DIR="$d"
  done < <(find "$OUT_DIR" -mindepth 1 -maxdepth 1 -type d -name '*-app' | sort)
fi

[ -n "$APP_DIR" ] || { keep_log=1; die "no dumped *-app dir found under $OUT_DIR (log: $DUMP_LOG)"; }
log "dumped: $APP_DIR"

if [ "$DUMP_ONLY" -eq 1 ]; then
  echo "$APP_DIR"
  exit 0
fi

log "building pkg from $(basename "$APP_DIR")"
if [ "$DELETE_DUMPS" -eq 0 ]; then
  exec "$BUILD_FPKG" ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"} "$APP_DIR"
fi

"$BUILD_FPKG" ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"} "$APP_DIR" \
  || die "build failed; dumps kept under $OUT_DIR"

# build-fpkg.sh aborts unless it produced a pkg.
TITLE="$(basename "$APP_DIR")"; TITLE="${TITLE%-app}"

PKG_OUT="$PWD"
for ((i = 0; i < ${#BUILD_ARGS[@]}; i++)); do
  if [ "${BUILD_ARGS[i]}" = "--out" ] && [ $((i + 1)) -lt "${#BUILD_ARGS[@]}" ]; then
    PKG_OUT="${BUILD_ARGS[i + 1]}"
  fi
done
PKG_OUT="$(cd "$PKG_OUT" 2>/dev/null && pwd || printf '%s' "$PKG_OUT")"

for suffix in app patch dlc keystone; do
  d="$OUT_DIR/$TITLE-$suffix"
  [ -d "$d" ] || continue
  case "$PKG_OUT/" in
    "$d"/*) die "refusing to delete $d: the pkg output dir is inside it" ;;
  esac
  log "deleting dump: $d"
  rm -rf "$d"
done
