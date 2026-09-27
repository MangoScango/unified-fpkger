#!/usr/bin/env bash
# ----------------------------------------------------------------------------
# dump-build.sh
# Dump a running game off a console, then build a fake-pkg from it.
#
# USAGE
#   dump-build.sh [options] IP[:PORT] [build-fpkg options ...]
#     -d, --dump-dir DIR    where the raw dump is written (default: cwd)
#     -o, --out DIR         where build-fpkg writes the pkg (default: cwd)
#     -j, --jobs N          ftpdump parallel downloads (default: 8); the pfs
#                           method is a single sequential stream and ignores it
#         --method M        pfs (default) or ftp; see DUMP METHODS below
#         --dump-only       stop after dumping
#         --delete-dumps    remove the dumped <TITLEID>-{app,patch,dlc,keystone}
#                           dirs once build-fpkg.sh has succeeded. Irreversible,
#                           and the console is the only other copy.
#     -h, --help            this text
#
#   Anything after IP[:PORT] is forwarded to build-fpkg.sh, e.g.
#     dump-build.sh 192.168.1.50:1337 --out /mnt/pkgs --keystone kscreate
#
# DUMP METHODS
#   pfs  pfsdump.py streams each layer's PFS image straight off the console and
#        demultiplexes it, merging the patch into the app tree as it writes. One
#        sequential transfer per layer instead of a request per file. It only
#        produces merged trees, so a build that needs the layers apart
#        (--remaster, --separate, --no-update) falls back to ftp.
#   ftp  ftpdump.sh mirrors the loose files, run as:
#          <host> -a -d -k -p -r -j N [--union] -o DIR
#
#   Either way only the -app dir is handed to build-fpkg.sh; it finds the
#   sibling -patch and -dlc itself.
# ----------------------------------------------------------------------------
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for _f in "$PWD/.env" "$SELF_DIR/.env"; do
  [ -f "$_f" ] || continue
  while IFS= read -r _line || [ -n "$_line" ]; do
    case "$_line" in ''|'#'*) continue ;; esac
    _key="${_line%%=*}"
    case "$_key" in ''|*[!A-Za-z0-9_]*) continue ;; esac
    [ -n "${!_key:-}" ] || eval "export $_line"
  done < "$_f"
done
unset _f _line _key

BUILD_FPKG="${BUILD_FPKG:-$SELF_DIR/build-fpkg.sh}"
JOBS="${JOBS:-8}"
DUMP_DIR="${DUMP_DIR:-$PWD}"
# build-fpkg.sh calls this OUT_DIR and inherits it from the environment. The
# --delete-dumps check near the end compares paths against it.
PKG_DIR="${PKG_DIR:-${OUT_DIR:-}}"
DUMP_ONLY="${DUMP_ONLY:-0}"
DELETE_DUMPS="${DELETE_DUMPS:-0}"
DUMP_METHOD="${DUMP_METHOD:-pfs}"
HOST="${HOST:-}"
declare -a BUILD_ARGS=()

die() { echo "error: $*" >&2; exit 1; }
log() { echo ">> $*" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    -d|--dump-dir)   DUMP_DIR="${2:?}"; shift 2 ;;
    -o|--out)        PKG_DIR="${2:?}"; shift 2 ;;
    -j|--jobs)       JOBS="${2:?}"; shift 2 ;;
    --method)        DUMP_METHOD="${2:?}"; shift 2 ;;
    --dump-only)     DUMP_ONLY=1; shift ;;
    --delete-dumps)  DELETE_DUMPS=1; shift ;;
    -h|--help)       awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"
                     exit 0 ;;
    # Options for build-fpkg.sh go after the address, so a flag here is a typo.
    -*)              die "unknown option: $1" ;;
    *)               HOST="$1"; shift; BUILD_ARGS=("$@"); break ;;
  esac
done

[ -n "$HOST" ] || die "console address required (IP[:PORT])"

# Our own options have to precede the address; past it everything belongs to
# build-fpkg.sh, which would reject them with a far less obvious message.
for a in ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"}; do
  case "$a" in
    -d|--dump-dir|-j|--jobs|--method|--dump-only|--delete-dumps)
      die "$a must come before the console address" ;;
  esac
done

[ -z "$PKG_DIR" ] || BUILD_ARGS=(--out "$PKG_DIR" ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"})
case "$JOBS" in ''|*[!0-9]*) die "--jobs must be a positive integer" ;; esac
[ "$JOBS" -ge 1 ] || die "--jobs must be at least 1"
[ -x "$BUILD_FPKG" ] || die "build-fpkg.sh not found or not executable: $BUILD_FPKG"

case "$DUMP_METHOD" in
  pfs|ftp) ;;
  *) die "--method must be pfs or ftp" ;;
esac

FTPDUMP="${FTPDUMP:-}"
if [ -z "$FTPDUMP" ]; then
  for c in "$SELF_DIR/ftpdump.sh" "$SELF_DIR/ftpdump"; do
    [ -x "$c" ] && { FTPDUMP="$c"; break; }
  done
fi
[ -n "$FTPDUMP" ] || FTPDUMP="$(command -v ftpdump || true)"

# An explicit PFSDUMP that is not there is a typo worth reporting, where merely
# not finding one is a reason to use the other method.
if [ -n "${PFSDUMP:-}" ]; then
  [ -f "$PFSDUMP" ] || die "PFSDUMP is set but not a file: $PFSDUMP"
else
  PFSDUMP=""
  for c in "$SELF_DIR/pfsdump.py" "$(command -v pfsdump.py || true)"; do
    [ -n "$c" ] && [ -f "$c" ] && { PFSDUMP="$c"; break; }
  done
fi

mkdir -p "$DUMP_DIR"
DUMP_DIR="$(cd "$DUMP_DIR" && pwd)"

# A partial dump left by a different user fails deep inside wget, so check up front.
whoami_now="$(id -un):$(id -gn)"
[ -w "$DUMP_DIR" ] || die "$DUMP_DIR is not writable: owned by $(stat -c %U:%G "$DUMP_DIR"), running as $whoami_now"
while IFS= read -r d; do
  [ -w "$d" ] && continue
  die "$d is not writable: owned by $(stat -c %U:%G "$d"), running as $whoami_now"
done < <(find "$DUMP_DIR" -mindepth 1 -maxdepth 1 -type d \
           \( -name '*-app' -o -name '*-patch' -o -name '*-dlc' -o -name '*-keystone' \))

STARTED="$(date +%s)"
RUN_LOG="${RUN_LOG:-$DUMP_DIR/dump-build-$(date +%Y%m%d-%H%M%S).log}"
DUMP_LOG="$RUN_LOG"
log "logging this run to $RUN_LOG"

# A union dump folds the patch into the app tree, which only a merged build can
# use: --remaster needs a base-only tree for its --app_path reference, --separate
# builds a distinct patch, and --no-update wants the base alone.
declare -a UNION=(--union)
for a in ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"}; do
  case "$a" in
    --remaster|--separate|--no-update) UNION=() ;;
  esac
done

# pfsdump only ever writes a merged tree, so a build that needs the layers apart
# has to go the mirroring route.
if [ "$DUMP_METHOD" = pfs ] && [ "${#UNION[@]}" -eq 0 ]; then
  log "build needs the layers apart: falling back to the ftp method"
  DUMP_METHOD=ftp
fi
if [ "$DUMP_METHOD" = pfs ] && [ -z "$PFSDUMP" ]; then
  log "pfsdump.py not found: falling back to the ftp method (set PFSDUMP=/path/to/pfsdump.py)"
  DUMP_METHOD=ftp
fi

declare -a DUMP_CMD=()
if [ "$DUMP_METHOD" = pfs ]; then
  command -v python3 >/dev/null 2>&1 || die "python3 not found, needed by pfsdump.py"
  DUMP_CMD=(python3 "$PFSDUMP" "$HOST" -o "$DUMP_DIR")
  log "dumping $HOST -> $DUMP_DIR (pfs stream)"
else
  [ -n "$FTPDUMP" ] && [ -x "$FTPDUMP" ] \
    || die "ftpdump not found (set FTPDUMP=/path/to/ftpdump.sh)"
  DUMP_CMD=("$FTPDUMP" "$HOST" -a -d -k -p -r -j "$JOBS"
            ${UNION[@]+"${UNION[@]}"} -o "$DUMP_DIR")
  [ "${#UNION[@]}" -gt 0 ] && log "merge build: dumping the app0-patch0 union"
  log "dumping $HOST -> $DUMP_DIR (ftp mirror, jobs=$JOBS)"
fi

rc=0
if command -v script >/dev/null 2>&1; then
  # A pty keeps the dumper's progress display working while still capturing it.
  _quoted=""
  for _a in "${DUMP_CMD[@]}"; do _quoted+="$(printf '%q' "$_a") "; done
  SHELL=/bin/sh script -qefc "$_quoted" "$DUMP_LOG" || rc=$?
  unset _quoted _a
else
  "${DUMP_CMD[@]}" 2>&1 | tee "$DUMP_LOG" || true
  rc="${PIPESTATUS[0]}"
fi

if [ "$rc" -ne 0 ]; then
  die "$DUMP_METHOD dump failed (exit $rc); output kept at $DUMP_LOG"
fi

# ftpdump tallies warnings/criticals without failing. pfsdump has no equivalent:
# anything it could not resolve is listed and exits non-zero, caught above.
if grep -qaE '[0-9]+ (warning|critical) message' "$DUMP_LOG"; then
  grep -aoE '[0-9]+ (warning|critical) message\(s\)' "$DUMP_LOG" | sort -u \
    | while read -r m; do log "the dump reported $m"; done
fi

# "Dumping CUSA12345 app data (123 MB):" names the title that was dumped.
TITLE_ID="$(tr -d '\r' < "$DUMP_LOG" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
  | grep -oE 'Dumping [A-Z]{4}[0-9]{5} app data' | grep -oE '[A-Z]{4}[0-9]{5}' | head -1 || true)"

APP_DIR=""
if [ -n "$TITLE_ID" ] && [ -d "$DUMP_DIR/$TITLE_ID-app" ]; then
  APP_DIR="$DUMP_DIR/$TITLE_ID-app"
else
  while IFS= read -r d; do
    [ -n "$(find "$d" -newermt "@$STARTED" -print -quit 2>/dev/null)" ] || continue
    [ -z "$APP_DIR" ] || die "cannot tell which dump to build: $(basename "$APP_DIR") and $(basename "$d")"
    APP_DIR="$d"
  done < <(find "$DUMP_DIR" -mindepth 1 -maxdepth 1 -type d -name '*-app' | sort)
fi

[ -n "$APP_DIR" ] || { die "no dumped *-app dir found under $DUMP_DIR (log: $DUMP_LOG)"; }
log "dumped: $APP_DIR"

if [ "$DUMP_ONLY" -eq 1 ]; then
  echo "$APP_DIR"
  exit 0
fi

log "building pkg from $(basename "$APP_DIR")"
"$BUILD_FPKG" ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"} "$APP_DIR" 2>&1 | tee -a "$RUN_LOG"
brc="${PIPESTATUS[0]}"
[ "$brc" -eq 0 ] \
  || die "build failed; dumps kept under $DUMP_DIR (log: $RUN_LOG)"

if [ "$DELETE_DUMPS" -eq 0 ]; then
  log "log: $RUN_LOG"
  exit 0
fi

# build-fpkg.sh aborts unless it produced a pkg.
TITLE="$(basename "$APP_DIR")"; TITLE="${TITLE%-app}"
PKG_OUT="${PKG_DIR:-$PWD}"
for ((i = 0; i < ${#BUILD_ARGS[@]}; i++)); do
  if [ "${BUILD_ARGS[i]}" = "--out" ] && [ $((i + 1)) -lt "${#BUILD_ARGS[@]}" ]; then
    PKG_OUT="${BUILD_ARGS[i + 1]}"
  fi
done
PKG_OUT="$(cd "$PKG_OUT" 2>/dev/null && pwd || printf '%s' "$PKG_OUT")"
PKG_OUT="$(cd "$PKG_OUT" 2>/dev/null && pwd || printf '%s' "$PKG_OUT")"

for suffix in app patch dlc keystone; do
  d="$DUMP_DIR/$TITLE-$suffix"
  [ -d "$d" ] || continue
  case "$PKG_OUT/" in
    "$d"/*) die "refusing to delete $d: the pkg output dir is inside it" ;;
  esac
  log "deleting dump: $d"
  rm -rf "$d"
done
