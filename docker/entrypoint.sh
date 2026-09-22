#!/usr/bin/env bash
set -euo pipefail

USER_HOME=/home/fpkg

# Drop to PUID:PGID only on a rootful host (e.g. Unraid) where they're set
DO_DROP=0
if [ "$(id -u)" = "0" ] && [ -n "${PUID:-}" ] && [ -n "${PGID:-}" ]; then
  DO_DROP=1
fi

if [ "$DO_DROP" = "1" ]; then
  getent group "$PGID"  >/dev/null || groupadd -g "$PGID" fpkg
  getent passwd "$PUID" >/dev/null || useradd -u "$PUID" -g "$PGID" -d "$USER_HOME" -s /bin/bash -M fpkg
  mkdir -p "$USER_HOME"
  chown "$PUID:$PGID" "$USER_HOME"
  chown -R "$PUID:$PGID" /opt/fpkger 2>/dev/null || true
else
  USER_HOME="${HOME:-/tmp}"
  [ -w "$USER_HOME" ] || USER_HOME=/tmp
fi

export HOME="$USER_HOME"
export WINEPREFIX="$USER_HOME/.wine"
export WINEARCH=win64
export WINEDEBUG="${WINEDEBUG:--all}"
export WINEDLLOVERRIDES="${WINEDLLOVERRIDES:-wineps.drv,localspl.dll,spoolss.dll=d}"

# gengp4_app is a GUI-subsystem binary and aborts without an X display
DISP=99
rm -f "/tmp/.X${DISP}-lock" 2>/dev/null || true
Xvfb ":${DISP}" -screen 0 1280x1024x24 -nolisten tcp >/dev/null 2>&1 &
XVFB_PID=$!
export DISPLAY=":${DISP}"
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -e "/tmp/.X11-unix/X${DISP}" ] && break; sleep 0.3; done
trap 'kill "$XVFB_PID" 2>/dev/null || true' EXIT

init_prefix() {
  [ -f "$WINEPREFIX/system.reg" ] && return
  echo ">> initializing wine prefix (first run) ..." >&2
  WINEDLLOVERRIDES="mscoree,mshtml=" wineboot --init >/dev/null 2>&1 || true
  wineserver -w >/dev/null 2>&1 || true
}

COMMON_ENV=(HOME="$HOME" WINEPREFIX="$WINEPREFIX" WINEARCH="$WINEARCH"
            WINEDEBUG="$WINEDEBUG" WINEDLLOVERRIDES="$WINEDLLOVERRIDES"
            DISPLAY="$DISPLAY")

if [ "$DO_DROP" = "1" ]; then
  gosu "$PUID:$PGID" env "${COMMON_ENV[@]}" WINEDLLOVERRIDES="mscoree,mshtml=" \
    bash -c '[ -f "$WINEPREFIX/system.reg" ] || { wineboot --init >/dev/null 2>&1 || true; wineserver -w >/dev/null 2>&1 || true; }'
  exec gosu "$PUID:$PGID" env "${COMMON_ENV[@]}" build-fpkg.sh "$@"
else
  init_prefix
  exec env "${COMMON_ENV[@]}" build-fpkg.sh "$@"
fi
