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

# gengp4_app is a GUI-subsystem binary and aborts (wine 0x0eedfade) without an X
# display, so run a headless Xvfb. The X socket dir may not exist yet in a fresh
# container; create it world-writable (sticky) like a normal /tmp/.X11-unix.
DISP=99
mkdir -p /tmp/.X11-unix && chmod 1777 /tmp/.X11-unix
rm -f "/tmp/.X${DISP}-lock" 2>/dev/null || true
Xvfb ":${DISP}" -screen 0 1280x1024x24 -nolisten tcp >/dev/null 2>&1 &
XVFB_PID=$!
export DISPLAY=":${DISP}"
trap 'kill "$XVFB_PID" 2>/dev/null || true' EXIT

# Wait until Xvfb is actually accepting connections
for _ in $(seq 1 100); do
  [ -S "/tmp/.X11-unix/X${DISP}" ] && break
  kill -0 "$XVFB_PID" 2>/dev/null || { echo "error: Xvfb (:$DISP) failed to start" >&2; exit 1; }
  sleep 0.1
done
[ -S "/tmp/.X11-unix/X${DISP}" ] || { echo "error: Xvfb (:$DISP) not ready after 10s" >&2; exit 1; }

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
else
  init_prefix
fi

# docker exec starts from the image ENV only; /etc/bash.bashrc sources this.
{
  for v in HOME WINEPREFIX WINEARCH WINEDEBUG WINEDLLOVERRIDES DISPLAY; do
    printf 'export %s=%q\n' "$v" "${!v}"
  done
} > /tmp/fpkger-env.sh 2>/dev/null || true
chmod 0644 /tmp/fpkger-env.sh 2>/dev/null || true

case "${1:-idle}" in
  idle)
    echo ">> environment ready (DISPLAY=$DISPLAY, WINEPREFIX=$WINEPREFIX)" >&2
    echo ">> idling; shell in with: docker exec -it <container> bash" >&2
    trap 'exit 0' TERM INT
    sleep infinity & wait $! || true
    exit 0 ;;
  web)           shift; set -- python3 /opt/fpkger/web/server.py ${@+"$@"} ;;
  bash|sh|shell) shift; set -- bash ${@+"$@"} ;;
  *)             set -- build-fpkg.sh ${@+"$@"} ;;
esac

if [ "$DO_DROP" = "1" ]; then
  exec gosu "$PUID:$PGID" env "${COMMON_ENV[@]}" "$@"
else
  exec env "${COMMON_ENV[@]}" "$@"
fi
