#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
VENV="$ROOT/.venv"
VENV_PYTHON="$VENV/bin/python"

if [ ! -x "$VENV_PYTHON" ]; then
    PYTHON=${PYTHON:-python3}
    if ! command -v "$PYTHON" >/dev/null 2>&1; then
        echo "Python 3.9 or newer is required. Set PYTHON to its executable path." >&2
        exit 1
    fi
    if ! "$PYTHON" -c 'import sys; raise SystemExit(sys.version_info < (3, 9))'; then
        echo "Python 3.9 or newer is required." >&2
        exit 1
    fi
    echo "Creating Python environment in $VENV ..." >&2
    if ! "$PYTHON" -m venv "$VENV"; then
        echo "Could not create $VENV. Ensure venv is available and the directory is writable." >&2
        exit 1
    fi
fi

if ! "$VENV_PYTHON" -c 'import PIL' >/dev/null 2>&1; then
    echo "Installing Python dependencies ..." >&2
    if ! "$VENV_PYTHON" -m pip install --disable-pip-version-check -r "$ROOT/requirements.txt"; then
        echo "Could not install Python dependencies. Check your network connection, or run:" >&2
        echo "  $VENV_PYTHON -m pip install -r $ROOT/requirements.txt" >&2
        exit 1
    fi
fi

exec "$VENV_PYTHON" web/server.py "$@"
