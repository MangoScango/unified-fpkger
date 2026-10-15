#!/usr/bin/env python3
"""Web front end for dumping titles off a console and building fake packages.

Serves one page with Dump, Build and Dump+Build tabs. Each submission becomes a
job that drives the same tools the terminal workflow uses: pfsdump.py (or
ftpdump.sh when a PS4 build needs the base and patch apart), then build-fpkg.sh
for PS4 or build-ps5.sh for PS5. Jobs run one at a time, since they compete for
the console's FTP server and for the disk.

Configuration comes from the environment, or a .env beside the tools:
  WEB_BIND      address to listen on (default 0.0.0.0)
  WEB_PORT      port (default 8080)
  WEB_ROOTS     colon-separated directories the UI may read and write
                (default: the working directory)
  WEB_PASSWORD  when set, every request needs HTTP basic auth with it
  WEB_LOG_DIR   where job logs go (default <first root>/fpkger-logs)
  SCAN_DIR      folder the Build tab scans for dumps (default: DUMP_DIR)
  SCAN_DEPTH    how many folders down that scan looks (default 3)
"""

import base64
import codecs
import collections
import fcntl
import hmac
import itertools
import json
import os
import pty
import queue
import re
import select
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import termios
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.environ.get("FPKGER_DIR") or os.path.dirname(HERE)
sys.path.insert(0, TOOLS)
import pfsdump  # noqa: E402
import pkg as pkgmod  # noqa: E402

sys.path.insert(0, HERE)
import dumpscan  # noqa: E402
import dlc_emu  # noqa: E402

PFSDUMP = os.path.join(TOOLS, "pfsdump.py")
FTPDUMP = os.environ.get("FTPDUMP") or os.path.join(TOOLS, "ftpdump.sh")
BUILD_FPKG = os.environ.get("BUILD_FPKG") or os.path.join(TOOLS, "build-fpkg.sh")
BUILD_PS5 = os.environ.get("BUILD_PS5") or os.path.join(TOOLS, "build-ps5.sh")
BACKPORT_PS5 = (os.environ.get("BACKPORT_PS5")
                or os.path.join(TOOLS, "another-backporter", "backport-ps5.py"))
MAKE_FSELF = os.path.join(TOOLS, "make_fself.py")
SC_OVERLAY = os.environ.get("SC_OVERLAY") or os.path.join(TOOLS, "sc-overlay.py")
PROSPERO_PUB_CMD = os.path.join(TOOLS, "drakmor", "toolchain", "prospero-pub-cmd.exe")
# another-backporter's SOURCE_FW: the firmware whose modules the fakelibs are
# built from, so the libraries folder must hold its dump.
BACKPORT_SOURCE_FW = "13.60"
BACKPORT_TIERS = ("7xx", "4xx")
DEFAULT_FTP_PORT = 2121
# orbis-pub-cmd wraps its output to the terminal width, truncating paths.
PTY_COLUMNS, PTY_ROWS = 400, 50

HOST_RE = re.compile(r"^[A-Za-z0-9.\-]+$")
TITLE_RE = re.compile(r"^[A-Z]{4}[0-9]{5}$")
CONTENT_ID_RE = re.compile(r"^[A-Z0-9]{2}[0-9]{4}-[A-Z]{4}[0-9]{5}_[0-9]{2}-[A-Z0-9]{16}$")
SDK_RE = re.compile(r"^(auto|0x[0-9A-Fa-f]{8})$")
PASSCODE_RE = re.compile(r"^[0-9A-Fa-f]{32}$")
FILENAME_RE = re.compile(r"^[A-Za-z0-9._\-]+$")
ANSI_RE = re.compile(r"\x1b(\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(\x07|\x1b\\)|[@-Z\\-_])")
NEWLINE_RE = re.compile(r"\r+\n")
# create-gp5-from-folder.py's PLAYGO_LANGUAGES, compared case-insensitively.
PLAYGO_LANGUAGES = {code.casefold() for code in (
    "ja-JP", "en-US", "fr-FR", "es-ES", "de-DE", "it-IT", "nl-NL", "pt-PT",
    "ru-RU", "ko-KR", "zh-Hant", "zh-Hans", "fi-FI", "sv-SE", "da-DK", "no-NO",
    "pl-PL", "pt-BR", "en-GB", "tr-TR", "es-419", "ar-AE", "fr-CA", "cs-CZ",
    "hu-HU", "el-GR", "ro-RO", "th-TH", "vi-VN", "id-ID", "uk-UA")}


def read_env_files():
    """KEY=VALUE pairs from ./.env, then the one beside the tools; first wins.

    The shell scripts read the same files, so prefilling the form from them
    keeps the UI and a terminal run in agreement.
    """
    values = {}
    for path in (os.path.join(os.getcwd(), ".env"), os.path.join(TOOLS, ".env")):
        try:
            with open(path, encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except OSError:
            continue
        for line in lines:
            key, sep, raw = line.strip().partition("=")
            if not sep or not re.fullmatch(r"[A-Za-z0-9_]+", key) or key in values:
                continue
            try:
                words = shlex.split(raw, comments=True)
            except ValueError:
                words = [raw]
            values[key] = " ".join(words)
    return values


ENV_FILE = read_env_files()


def setting(key, default=""):
    return os.environ.get(key) or ENV_FILE.get(key) or default


def default_roots():
    return [os.path.realpath(p)
            for p in setting("WEB_ROOTS", os.getcwd()).split(":") if p]


ROOTS = default_roots()


def pick_log_dir():
    """WEB_LOG_DIR, else fpkger-logs in the first root this user can write.

    Returns (directory, warning or None).
    """
    explicit = setting("WEB_LOG_DIR")
    candidates = [explicit] if explicit else []
    candidates += [os.path.join(root, "fpkger-logs") for root in ROOTS]
    candidates.append(os.path.join(os.path.expanduser("~"), "fpkger-logs"))
    for path in candidates:
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            continue
        if os.access(path, os.W_OK):
            if path == candidates[0]:
                return path, None
            first = explicit or ROOTS[0]
            return path, f"{first} is not writable as uid {os.getuid()}; logging to {path}"
    raise SystemExit(f"no writable place for job logs; tried {', '.join(candidates)}")


LOG_DIR, LOG_DIR_WARNING = pick_log_dir()
PASSWORD = setting("WEB_PASSWORD")


class BadRequest(Exception):
    """A submission the server refuses; the message goes back to the page."""


class JobError(Exception):
    """A job step failed in a way worth reporting as the job's outcome."""


class Cancelled(Exception):
    pass


def inside_roots(real):
    return any(real == root or real.startswith(root.rstrip(os.sep) + os.sep)
               for root in ROOTS)


def resolve_path(value, label, kind="dir", must_exist=True, create=False):
    """An absolute, symlink-free path under one of ROOTS, or BadRequest.

    Relative paths are taken from the first root.
    """
    value = (value or "").strip()
    if not value:
        raise BadRequest(f"{label} is required")
    if not os.path.isabs(value):
        value = os.path.join(ROOTS[0], value)
    real = os.path.realpath(value)
    if not inside_roots(real):
        raise BadRequest(f"{label} must be under {', '.join(ROOTS)}")
    if create:
        os.makedirs(real, exist_ok=True)
    if must_exist or create:
        if kind == "dir" and not os.path.isdir(real):
            raise BadRequest(f"{label} is not a directory: {real}")
        if kind == "file" and not os.path.isfile(real):
            raise BadRequest(f"{label} is not a file: {real}")
    return real


def optional_path(params, key, label, kind="dir"):
    return resolve_path(params[key], label, kind) if params.get(key) else None


def parse_host(value):
    """(host, port) from HOST or HOST:PORT."""
    value = (value or "").strip()
    host, _, port = value.partition(":")
    if not host or not HOST_RE.match(host):
        raise BadRequest("console address must be an IP or hostname, optionally :PORT")
    if port:
        if not port.isdigit() or not 0 < int(port) < 65536:
            raise BadRequest(f"bad port: {port}")
        return host, int(port)
    return host, DEFAULT_FTP_PORT


def checked(params, key, pattern, label):
    value = (params.get(key) or "").strip()
    if value and not pattern.match(value):
        raise BadRequest(f"{label} is not valid: {value}")
    return value


def int_in(params, key, low, high, default, label):
    raw = str(params.get(key, "")).strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise BadRequest(f"{label} must be a number") from None
    if not low <= value <= high:
        raise BadRequest(f"{label} must be between {low} and {high}")
    return value


class Job:
    """One queued unit of work, its output, and its outcome."""

    MAX_LINES = 20000
    _ids = itertools.count(1)

    def __init__(self, kind, plan, summary):
        self.id = next(Job._ids)
        self.kind, self.plan, self.summary = kind, plan, summary
        self.status = "queued"
        self.step = ""
        self.error = ""
        self.outputs = []
        self.created = time.time()
        self.started = self.finished = None
        self.lines = collections.deque(maxlen=self.MAX_LINES)
        self.line_count = 0
        self.partial = ""
        self.proc = None
        self.cancelled = False
        self.lock = threading.Lock()
        os.makedirs(LOG_DIR, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(self.created))
        self.log_path = os.path.join(LOG_DIR, f"{stamp}-{kind}-{self.id}.log")
        self._log = open(self.log_path, "a", encoding="utf-8")

    def _commit(self, line):
        with self.lock:
            self.lines.append(line)
            self.line_count += 1
        self._log.write(line + "\n")
        self._log.flush()

    def say(self, text):
        self.flush()
        for line in text.splitlines() or [""]:
            self._commit(f">> {line}")

    def feed(self, text):
        """Takes raw terminal output, keeping only what a terminal would show.

        Progress displays redraw one line with carriage returns; only the last
        redraw of each line is kept.
        """
        # wine's console ends its lines with \r\r\n.
        text = NEWLINE_RE.sub("\n", ANSI_RE.sub("", self.partial + text))
        parts = text.split("\n")
        for part in parts[:-1]:
            self._commit(part.rsplit("\r", 1)[-1])
        tail = parts[-1]
        # A trailing \r may be the first half of a \r\n split across reads.
        if not tail.endswith("\r") and "\r" in tail:
            tail = tail.rsplit("\r", 1)[-1]
        with self.lock:
            self.partial = tail[-4096:]

    def flush(self):
        if self.partial.strip("\r"):
            self._commit(self.partial.rstrip("\r").rsplit("\r", 1)[-1])
        self.partial = ""

    def tail(self, since, count=6):
        """The last non-blank output lines committed after line number since."""
        with self.lock:
            first = self.line_count - len(self.lines)
            recent = list(itertools.islice(self.lines, max(since - first, 0), None))
        # >> lines are the server's own narration; progress bars say nothing.
        useful = [line.strip() for line in recent
                  if line.strip() and not line.startswith(">> ")
                  and line.strip("=|_.0123456789 ")]
        return useful[-count:]

    def close_log(self):
        self._log.close()

    def summary_dict(self):
        return {
            "id": self.id, "kind": self.kind, "summary": self.summary,
            "status": self.status, "step": self.step, "error": self.error,
            "outputs": self.outputs, "created": self.created,
            "started": self.started, "finished": self.finished,
            "log_path": self.log_path,
        }

    def detail(self, since):
        with self.lock:
            first = self.line_count - len(self.lines)
            start = max(since, first)
            lines = list(itertools.islice(self.lines, start - first, None))
            partial = self.partial.rstrip("\r").rsplit("\r", 1)[-1]
            total = self.line_count
        info = self.summary_dict()
        info.update(lines=lines, next=total, skipped=start - since,
                    partial=partial)
        return info


def run(job, argv, cwd, env_extra=None):
    """Runs argv on a pty, streaming its output into the job. Returns the rc.

    A pty keeps the tools' progress displays on, since they only draw them for
    a terminal.
    """
    if job.cancelled:
        raise Cancelled()
    job.say("$ " + shlex.join(argv))
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ,
                struct.pack("HHHH", PTY_ROWS, PTY_COLUMNS, 0, 0))
    env = dict(os.environ, COLUMNS=str(PTY_COLUMNS), PYTHONUNBUFFERED="1")
    if env_extra:
        env.update(env_extra)
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=slave, stderr=slave, start_new_session=True)
    except OSError as err:
        os.close(master)
        os.close(slave)
        raise JobError(f"could not start {argv[0]}: {err}") from None
    os.close(slave)
    job.proc = proc
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    exited_at = None
    try:
        while True:
            ready, _, _ = select.select([master], [], [], 0.5)
            if ready:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break
                if not data:
                    break
                job.feed(decoder.decode(data))
            if proc.poll() is not None:
                # wineserver outlives the tool that started it and holds the
                # pty open, so stop reading shortly after the tool itself exits.
                exited_at = exited_at or time.monotonic()
                if not ready or time.monotonic() - exited_at > 2:
                    break
    finally:
        os.close(master)
    rc = proc.wait()
    job.proc = None
    job.feed(decoder.decode(b"", final=True))
    job.flush()
    if job.cancelled:
        raise Cancelled()
    return rc


def cancel(job):
    job.cancelled = True
    proc = job.proc
    if proc is None:
        return

    def terminate():
        for sig, wait in ((signal.SIGTERM, 10), (signal.SIGKILL, 0)):
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                return
            try:
                proc.wait(timeout=wait or None)
                return
            except subprocess.TimeoutExpired:
                continue

    threading.Thread(target=terminate, daemon=True).start()


# --- console probing ---------------------------------------------------------

def image_platform(host, port, title):
    """'ps4' or 'ps5', read from the start of the title's nest image.

    A PS4 image opens with its superblock; a PS5 one opens with file data.
    """
    remote = pfsdump.FtpFile(host, port, pfsdump.nest_path(title, "app0"), timeout=15)
    try:
        head = remote.read(0, 16)
    finally:
        remote.close()
    version, magic = struct.unpack("<qq", head)
    return "ps4" if version == 1 and magic == pfsdump.PFS_MAGIC else "ps5"


def mounted_titles(host, port):
    mount = pfsdump.FtpMount(host, port, timeout=15)
    try:
        _first, titles = pfsdump.discover_title(mount)
    finally:
        mount.close()
    return titles


def probe(job, host, port, title):
    """Settles which title is being dumped and what console it is on."""
    job.step = "probing the console"
    try:
        if not title:
            titles = mounted_titles(host, port)
            if not titles:
                raise JobError("no mounted app0 on the console; is the game running?")
            title = titles[0]
            if len(titles) > 1:
                job.say(f"several titles are mounted ({', '.join(titles)}); using {title}")
        platform = image_platform(host, port, title)
    except (OSError, EOFError, pfsdump.ftplib.Error) as err:
        raise JobError(f"could not reach {host}:{port}: {err}") from None
    job.say(f"{title} on a {platform.upper()}")
    return title, platform


# --- steps ---------------------------------------------------------------------

def dump_step(job, spec, title, method):
    host, port = spec["host"], spec["port"]
    dump_dir = spec["dump_dir"]
    os.makedirs(dump_dir, exist_ok=True)
    job.step = f"dumping {title}"
    if method == "pfs":
        argv = [sys.executable, PFSDUMP, f"{host}:{port}", title, "-o", dump_dir]
        for flag in ("no_patch", "no_decrypt", "no_dlc", "no_entitlements"):
            if spec.get(flag):
                argv.append("--" + flag.replace("_", "-"))
        if spec.get("verbose"):
            argv.append("-v")
    else:
        # dump-build.sh's mirror invocation, minus --union: this path is only
        # taken when the build needs the layers apart.
        argv = [FTPDUMP, f"{host}:{port}", "-a", "-d", "-k", "-p", "-r",
                "-j", str(spec["jobs"]), "-o", dump_dir]
    start = job.line_count
    rc = run(job, argv, cwd=dump_dir)
    if rc != 0:
        detail = job.tail(start)
        raise JobError(f"{method} dump failed (exit {rc})"
                       + "".join(f"\n  {line}" for line in detail))
    app_dir = os.path.join(dump_dir, f"{title}-app")
    if not os.path.isdir(app_dir):
        raise JobError(f"the dump finished but {app_dir} is missing")
    job.outputs.append(app_dir)
    return app_dir


def source_platform(src):
    """'ps5' when the tree carries PS5 metadata, else 'ps4'.

    build-fpkg.sh does its own identification of PS4 trees, including add-on
    containers with no param.sfo at all, so anything not PS5 goes to it.
    """
    platform = dumpscan.platform_of(src)
    if platform is None and ps5_addons(src):
        return "ps5"
    return "ps5" if platform == "ps5" else "ps4"


def is_ps5_addon(path):
    """A PS5 tree with metadata but no eboot.bin, which only an add-on lacks."""
    return (dumpscan.platform_of(path) == "ps5"
            and not os.path.isfile(os.path.join(path, "eboot.bin")))


def ps5_addons(directory):
    """The PS5 add-on trees directly inside directory, such as a -dlc dump."""
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return []
    return [os.path.join(directory, name) for name in names
            if is_ps5_addon(os.path.join(directory, name))]


def ps5_package_name(src, requested):
    if requested:
        return requested
    try:
        with open(os.path.join(src, "sce_sys", "param.json"), encoding="utf-8-sig") as handle:
            content_id = json.load(handle).get("contentId", "")
        if FILENAME_RE.match(content_id or ""):
            return content_id
    except (OSError, ValueError):
        pass
    return os.path.basename(src.rstrip(os.sep))


def package_mtimes(directory):
    return {entry.name: entry.stat().st_mtime_ns for entry in os.scandir(directory)
            if entry.is_file() and entry.name.lower().endswith(".pkg")}


def extract_step(job, spec, pkg_path):
    """Extract a PS5 pkg into a tree build-ps5.sh can take, and return the tree.

    prospero-pub-cmd's img_extract writes the whole image (sce_sys included) to
    <stem>-extract next to the pkg, or under the extraction folder when one is
    set. An earlier extraction is reused when its param.json declares the same
    title.
    """
    if not os.path.isfile(PROSPERO_PUB_CMD):
        raise JobError(f"rebuilding a pkg needs prospero-pub-cmd.exe, which is missing: "
                       f"{PROSPERO_PUB_CMD}")
    stem = os.path.splitext(os.path.basename(pkg_path))[0]
    root = spec["ps5"].get("extract_dir") or os.path.dirname(pkg_path)
    dest = os.path.join(root, f"{stem}-extract")
    param_json = os.path.join(dest, "sce_sys", "param.json")
    if os.path.isfile(param_json):
        try:
            with open(param_json, encoding="utf-8-sig") as handle:
                content_id = json.load(handle).get("contentId", "")
        except (OSError, ValueError):
            content_id = ""
        try:
            with pkgmod.Pkg.open(pkg_path) as pkg:
                title_id = pkg.title_id
        except (pkgmod.PkgError, OSError):
            title_id = None
        extracted = dumpscan.title_id_from_content_id(content_id)
        if not title_id or extracted != title_id:
            raise JobError(f"{dest} already exists but is not {title_id or 'this package'}"
                           f"'s extraction; move it away or pick another extraction folder")
        job.say(f"reusing existing extraction: {dest}")
    else:
        os.makedirs(dest, exist_ok=True)
        job.step = f"extracting {os.path.basename(pkg_path)}"
        argv = ["wine", PROSPERO_PUB_CMD, "img_extract", "--passcode",
                spec["ps5"]["passcode"], pkg_path, dest]
        start = job.line_count
        rc = run(job, argv, cwd=dest, env_extra={"WINEDEBUG": "-all"})
        if rc != 0:
            detail = job.tail(start)
            raise JobError(f"pkg extraction failed (exit {rc})"
                           + "".join(f"\n  {line}" for line in detail))
        if not os.path.isfile(param_json):
            raise JobError(f"the extraction finished but {param_json} is missing")
    job.outputs.append(dest)
    return dest


def build_step(job, spec, src, platform):
    out_dir = spec["out_dir"]
    os.makedirs(out_dir, exist_ok=True)
    if platform != "ps4" and spec.get("layers") and spec["layers"].get("rebuild"):
        src = extract_step(job, spec, src)
    if platform == "ps4":
        before = package_mtimes(out_dir)
        job.step = f"building {os.path.basename(src)} (PS4)"
        opts = spec["ps4"]
        argv = [BUILD_FPKG, "--" + opts["mode"]]
        if not opts["backport"]:
            argv.append("--no-backport")
        for key, flag in (("sdk", "--sdk"), ("keystone", "--keystone"),
                          ("content_id", "--content-id"), ("ps2_tid", "--ps2-tid"),
                          ("base_pkg", "--base-pkg"), ("tmp_dir", "--tmp-dir"),
                          ("update_dir", "--update"), ("dlc_dir", "--dlc")):
            if opts.get(key):
                argv += [flag, opts[key]]
        layers = spec.get("layers")
        if layers is not None:
            # From a scan: every layer is named, so build-fpkg's sibling
            # lookup is turned off. Named add-ons still build under --no-dlc,
            # which only stops it looking for a -dlc folder.
            if not layers["update"]:
                argv.append("--no-update")
            argv += ["--no-dlc", "--out", out_dir]
            argv += [p for p in (layers["base"], layers["update"], *layers["addons"]) if p]
        else:
            if opts["no_update"]:
                argv.append("--no-update")
            if opts["no_dlc"]:
                argv.append("--no-dlc")
            argv += ["--out", out_dir, src]
        run_build(job, argv, out_dir, before, platform)
        return
    # A folder of add-ons, as pfsdump writes into <title>-dlc, builds each one.
    if os.path.isfile(os.path.join(src, "sce_sys", "param.json")):
        targets = [src]
    else:
        targets = ps5_addons(src)
        if not targets:
            raise JobError(f"{src} is neither a PS5 tree nor a folder of add-ons")
        job.say(f"{len(targets)} add-on(s) in {os.path.basename(src)}")
    if spec["ps5"]["entitlement_key"] and len(targets) > 1:
        raise JobError("one entitlement key cannot cover several add-ons; clear it "
                       "so each uses its own entitlement_key.dat")
    for target in targets:
        build_ps5(job, spec, target, out_dir)


def build_ps5(job, spec, src, out_dir):
    opts = spec["ps5"]
    addon = is_ps5_addon(src)
    # One name override cannot cover several packages, so add-ons keep theirs.
    requested = None if addon else opts["name"]
    package = os.path.join(out_dir, ps5_package_name(src, requested) + ".pkg")
    job.step = f"building {os.path.basename(src)} (PS5 {'add-on' if addon else 'app'})"
    argv = [BUILD_PS5, "--source-folder", src, "--output-package", package,
            "--volume", "ac" if addon else "app",
            "--passcode", opts["passcode"],
            "--compression-level", str(opts["compression_level"])]
    # An SC package restores sce_sys for apps and add-ons alike.
    if opts.get("sc_pkg"):
        argv += ["--sc-pkg", opts["sc_pkg"]]
    if not addon:
        if opts["chunk_count"] is not None:
            argv += ["--chunk-count", str(opts["chunk_count"])]
        if opts["playgo_languages"]:
            argv += ["--playgo-languages", opts["playgo_languages"]]
        if opts["drop_unused_chunks"]:
            argv.append("--drop-unused-chunks")
        if opts.get("reference_pkg"):
            argv += ["--reference-package", opts["reference_pkg"]]
    elif opts["entitlement_key"]:
        argv += ["--entitlement-key", opts["entitlement_key"]]
    else:
        key = dumpscan.read_entitlement_key(src)
        job.say(f"entitlement key for {os.path.basename(src)}: "
                + (f"{key} from {dumpscan.ENTITLEMENT_KEY_FILE}" if key
                   else f"none recorded ({dumpscan.ENTITLEMENT_KEY_FILE} missing), "
                        "building with zeroes"))
    if opts.get("temp_dir"):
        argv += ["--temp-dir", opts["temp_dir"]]
    if opts["keep_intermediate"]:
        argv.append("--keep-intermediate")
    if opts["force"]:
        argv.append("--force")
    run_build(job, argv, out_dir, package_mtimes(out_dir), "PS5")


def run_build(job, argv, out_dir, before, label):
    start = job.line_count
    rc = run(job, argv, cwd=out_dir)
    if rc != 0:
        detail = job.tail(start)
        raise JobError(f"{label.upper()} build failed (exit {rc})"
                       + ("".join(f"\n  {line}" for line in detail) if detail
                          else ": the build printed nothing after its last step"))
    built = sorted(os.path.join(out_dir, name)
                   for name, mtime in package_mtimes(out_dir).items()
                   if before.get(name) != mtime)
    job.outputs += built
    if not built:
        job.say(f"warning: the build succeeded but no new .pkg is in {out_dir}")


def dlc_split_step(job, spec):
    """Splits a dlc_emu dump: mounted folders become add-on trees, see dlc_emu.py."""
    src = spec["source"]
    job.step = f"splitting DLC out of {os.path.basename(src.rstrip(os.sep))}"

    def overlay(sc_pkg, ac_dir):
        start = job.line_count
        rc = run(job, [sys.executable, SC_OVERLAY, sc_pkg, ac_dir], cwd=ac_dir)
        if rc != 0:
            detail = job.tail(start)
            raise dlc_emu.SplitError(
                f"SC overlay failed for {sc_pkg} (exit {rc})"
                + "".join(f"\n  {line}" for line in detail))

    try:
        built = dlc_emu.split(src, spec["title_id"], spec["entries"],
                              overlay=overlay, log=job.say)
    except dlc_emu.SplitError as err:
        raise JobError(str(err)) from None
    job.outputs += built
    job.say("rescan the folder to build the base and its new add-ons")


def backport_step(job, spec):
    """another-backporter's end-to-end run: acquire, unwrap, plan, build.

    Writes loose files (the fakelib set plus patched game executables) into
    spec["out"]; nothing here packages them.
    """
    src, out = spec["source"], spec["out"]
    job.step = f"backporting {os.path.basename(src.rstrip(os.sep))} to {spec['tier']}"
    argv = [sys.executable, BACKPORT_PS5, "run", src, out, "--tier", spec["tier"]]
    if spec["title"]:
        argv += ["--title", spec["title"]]
    for key, flag in (("allow_unreviewed", "--allow-unreviewed"),
                      ("unpeg_shim", "--unpeg-shim")):
        if spec[key]:
            argv.append(flag)
    # The acquired and unwrapped binaries are worth keeping between runs.
    data = setting("BACKPORT_DATA_DIR") or os.path.join(ROOTS[0], "ps5backport-data")
    env = {"PS5BACKPORT_LIBS": spec["libs_dir"],
           "PS5BACKPORT_CACHE": os.path.join(data, "binaries"),
           "PS5BACKPORT_ELF_CACHE": os.path.join(data, "binaries-elf")}
    os.makedirs(env["PS5BACKPORT_CACHE"], exist_ok=True)
    os.makedirs(env["PS5BACKPORT_ELF_CACHE"], exist_ok=True)
    for key, path in (("PS5BACKPORT_MAKE_FSELF", MAKE_FSELF),
                      ("PS5BACKPORT_PUB_CMD", PROSPERO_PUB_CMD)):
        if not os.environ.get(key) and os.path.exists(path):
            env[key] = path
    start = job.line_count
    rc = run(job, argv, cwd=spec["out_dir"], env_extra=env)
    if rc != 0:
        detail = job.tail(start)
        raise JobError(f"backport failed (exit {rc})"
                       + "".join(f"\n  {line}" for line in detail))
    job.outputs.append(out)
    report = os.path.join(spec["out_dir"], os.path.basename(out) + "-report.json")
    if os.path.isfile(report):
        job.outputs.append(report)


def delete_dumps(job, dump_dir, title, out_dir):
    """Removes this title's dump directories after a successful build."""
    for suffix in ("app", "patch", "dlc", "keystone"):
        path = os.path.join(dump_dir, f"{title}-{suffix}")
        if not os.path.isdir(path):
            continue
        if out_dir == path or out_dir.startswith(path + os.sep):
            raise JobError(f"refusing to delete {path}: the output directory is inside it")
        job.say(f"deleting dump: {path}")
        shutil.rmtree(path)
        job.outputs = [o for o in job.outputs if o != path]


def execute(job):
    spec = job.plan
    if job.kind == "dump":
        title, _platform = probe(job, spec["host"], spec["port"], spec["title"])
        dump_step(job, spec, title, "pfs")
    elif job.kind == "build":
        build_step(job, spec, spec["source_dir"], spec["platform"])
    elif job.kind == "dlc-split":
        dlc_split_step(job, spec)
    elif job.kind == "backport":
        backport_step(job, spec)
    else:
        title, platform = probe(job, spec["host"], spec["port"], spec["title"])
        if platform in spec["option_problems"]:
            raise JobError(f"{platform.upper()} build options: "
                           f"{spec['option_problems'][platform]}")
        method = "pfs"
        if platform == "ps4":
            ps4 = spec["ps4"]
            if ps4["mode"] in ("remaster", "separate"):
                job.say(f"--{ps4['mode']} needs the base and patch apart: "
                        "mirroring with ftpdump.sh instead of streaming")
                method = "ftp"
            elif ps4["no_update"]:
                spec["no_patch"] = True
        app_dir = dump_step(job, spec, title, method)
        build_step(job, spec, app_dir, platform)
        # build-fpkg.sh finds a PS4 title's sibling -dlc itself; build-ps5.sh
        # takes one tree at a time.
        dlc_dir = os.path.join(spec["dump_dir"], f"{title}-dlc")
        if platform == "ps5" and not spec["no_dlc"] and ps5_addons(dlc_dir):
            build_step(job, spec, dlc_dir, platform)
        if spec["delete_dumps"]:
            delete_dumps(job, spec["dump_dir"], title, spec["out_dir"])


# --- validation ----------------------------------------------------------------

def console_spec(params, spec):
    spec["host"], spec["port"] = parse_host(params.get("host"))
    spec["title"] = checked(params, "title", TITLE_RE, "title ID")


def dump_spec(params, spec):
    spec["dump_dir"] = resolve_path(params.get("dump_dir"), "dump directory", create=True)
    for flag in ("no_patch", "no_decrypt", "no_dlc", "no_entitlements", "verbose"):
        spec[flag] = bool(params.get(flag))


def ps4_spec(params, with_sources):
    mode = params.get("mode") or "app-merge"
    if mode not in ("app-merge", "remaster", "separate"):
        raise BadRequest(f"unknown build mode: {mode}")
    keystone = params.get("keystone") or "retail"
    if keystone not in ("retail", "kscreate"):
        raise BadRequest(f"unknown keystone mode: {keystone}")
    ps2_tid = (params.get("ps2_tid") or "").strip()
    if ps2_tid and not re.fullmatch(r"[0-9]{5}", ps2_tid):
        raise BadRequest("PS2 serial must be 5 digits")
    opts = {
        "mode": mode, "keystone": keystone, "ps2_tid": ps2_tid,
        "backport": bool(params.get("backport", True)),
        "sdk": checked(params, "sdk", SDK_RE, "backport SDK"),
        "content_id": checked(params, "content_id", CONTENT_ID_RE, "content ID"),
        "no_update": bool(params.get("no_update")),
        "no_dlc": bool(params.get("build_no_dlc")),
        "base_pkg": optional_path(params, "base_pkg", "base package", "file"),
        "tmp_dir": (resolve_path(params["tmp_dir"], "scratch directory", create=True)
                    if params.get("tmp_dir") else None),
    }
    if with_sources:
        opts["update_dir"] = optional_path(params, "update_dir", "update directory")
        opts["dlc_dir"] = optional_path(params, "dlc_dir", "DLC directory")
        if opts["update_dir"] and opts["no_update"]:
            raise BadRequest("choose either an update directory or no update")
        if opts["dlc_dir"] and opts["no_dlc"]:
            raise BadRequest("choose either a DLC directory or no DLC")
    return opts


def sc_pkg_checked(value, label="SC package"):
    """A SC package as an http(s) URL or a local .pkg under ROOTS; "" for none."""
    value = (value or "").strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        if not urlparse(value).netloc:
            raise BadRequest(f"bad {label} URL: {value}")
        return value
    if "://" in value:
        raise BadRequest(f"the {label} URL must be http or https")
    path = resolve_path(value, label, "file")
    if not path.lower().endswith(".pkg"):
        raise BadRequest(f"the {label} must be a .pkg or an http(s) URL")
    return path


def ps5_spec(params):
    passcode = (params.get("passcode") or "0" * 32).strip()
    if not PASSCODE_RE.match(passcode):
        raise BadRequest("passcode must be 32 hex digits")
    name = checked(params, "ps5_name", FILENAME_RE, "package name")
    if name.lower().endswith(".pkg"):
        name = name[:-4]
    reference = optional_path(params, "reference_pkg", "reference package", "file")
    if reference and not reference.lower().endswith(".pkg"):
        raise BadRequest("the reference package must be a .pkg")
    sc_pkg = sc_pkg_checked(params.get("sc_pkg"))
    playgo_languages = ",".join(code.strip() for code in
                                str(params.get("playgo_languages") or "").split(",")
                                if code.strip())
    unknown = [code for code in playgo_languages.split(",")
               if code and code.casefold() not in PLAYGO_LANGUAGES]
    if unknown:
        raise BadRequest(f"unknown PlayGo language(s): {', '.join(unknown)}")
    entitlement_key = (params.get("entitlement_key") or "").strip()
    if entitlement_key and not PASSCODE_RE.match(entitlement_key):
        raise BadRequest("the entitlement key must be 32 hex digits")
    return {
        "name": name, "passcode": passcode, "reference_pkg": reference,
        "sc_pkg": sc_pkg,
        "compression_level": int_in(params, "compression_level", -4, 9, 7,
                                    "compression level"),
        "chunk_count": int_in(params, "chunk_count", 1, 255, None, "chunk count"),
        "playgo_languages": playgo_languages,
        "drop_unused_chunks": bool(params.get("drop_unused_chunks")),
        "temp_dir": (resolve_path(params["ps5_temp_dir"], "PS5 temp directory",
                                  create=True) if params.get("ps5_temp_dir") else None),
        "extract_dir": (resolve_path(params["extract_dir"], "pkg extraction folder",
                                     create=True) if params.get("extract_dir") else None),
        "entitlement_key": entitlement_key.upper(),
        "keep_intermediate": bool(params.get("keep_intermediate")),
        "force": bool(params.get("force")),
    }


def dlc_split_spec(params):
    """A dlc_emu dump plus, per PSAC entry, the SC package and key to split it with.

    The ini is re-read here and the page's entries are matched against it by
    content ID: only the SC package and entitlement key are taken from the
    submission.
    """
    src = resolve_path(params.get("source"), "dlc_emu dump")
    meta = dumpscan.read_meta(src)
    if not meta or meta["platform"] != "ps5" or meta["kind"] == "Add-on":
        raise BadRequest(f"not a PS5 app dump: {src}")
    if not meta["title_id"]:
        raise BadRequest(f"the dump's title ID is unknown: {src}")
    entries = dlc_emu.read_entries(src)
    if not entries:
        raise BadRequest(f"{src} has no dlc_emu.ini with PSAC entries")
    choices = params.get("dlc")
    if not isinstance(choices, dict):
        raise BadRequest("dlc must be an object keyed by content ID")
    known = {entry["content_id"] for entry in entries}
    unknown = [cid for cid in choices if cid not in known]
    if unknown:
        raise BadRequest(f"unknown DLC content ID(s): {', '.join(map(str, unknown))}")
    selected = []
    for entry in entries:
        choice = choices.get(entry["content_id"])
        if choice is None:
            continue
        if not isinstance(choice, dict):
            raise BadRequest("each DLC entry must be an object")
        name = entry["label"] or entry["content_id"]
        if entry["problems"]:
            raise BadRequest(f"{name}: " + "; ".join(entry["problems"]))
        sc_pkg = sc_pkg_checked(choice.get("sc_pkg"), f"SC package for {name}")
        if not sc_pkg:
            raise BadRequest(f"{name}: the SC package is required "
                             "(prosperopatches has them; match the DLC's version)")
        key = (choice.get("entitlement_key") or "").strip()
        if key and not PASSCODE_RE.match(key):
            raise BadRequest(f"{name}: the entitlement key must be 32 hex digits")
        entry = dict(entry, sc_pkg=sc_pkg)
        if key:
            entry["entitlement_key"] = key.upper()
        selected.append(entry)
    if not selected:
        raise BadRequest("no DLC selected to split")
    return {"source": src, "title_id": meta["title_id"], "entries": selected}


def backport_spec(params):
    """Options for another-backporter's `run`: a dump or pkg, a target tier."""
    value = (params.get("source") or "").strip()
    if not value:
        raise BadRequest("source is required")
    if not os.path.isabs(value):
        value = os.path.join(ROOTS[0], value)
    src = os.path.realpath(value)
    if not inside_roots(src):
        raise BadRequest(f"source must be under {', '.join(ROOTS)}")
    if not os.path.isdir(src):
        if not (os.path.isfile(src) and src.lower().endswith(".pkg")):
            raise BadRequest(f"source is neither a dump folder nor a .pkg: {src}")
        if not (os.environ.get("PS5BACKPORT_PUB_CMD")
                or os.path.exists(PROSPERO_PUB_CMD)):
            raise BadRequest("pkg input needs prospero-pub-cmd.exe, which is missing")
    tier = params.get("tier") or "7xx"
    if tier not in BACKPORT_TIERS:
        raise BadRequest(f"unknown tier: {tier}")
    libs = resolve_path(params.get("libs_dir"), "firmware libraries")
    if not os.path.isdir(os.path.join(libs, BACKPORT_SOURCE_FW)):
        raise BadRequest(f"firmware libraries: no {BACKPORT_SOURCE_FW} dump in {libs}")
    title = checked(params, "title", TITLE_RE, "title ID")
    out_dir = resolve_path(params.get("out_dir"), "output directory", create=True)
    # build_title() deletes the output folder outright before writing, so the
    # server names it and refuses to reuse one that already exists.
    m = re.search(r"[A-Z]{4}[0-9]{5}", os.path.basename(src.rstrip(os.sep)))
    name = title or (m.group(0) if m else "backport")
    out = os.path.join(out_dir, f"{name}-backport")
    if os.path.exists(out):
        raise BadRequest(f"output folder already exists: {out}")
    return {"source": src, "title": title, "tier": tier, "libs_dir": libs,
            "out_dir": out_dir, "out": out,
            "allow_unreviewed": bool(params.get("allow_unreviewed")),
            "unpeg_shim": bool(params.get("unpeg_shim"))}


def build_job(kind, params):
    """Validates a submission into a Job, raising BadRequest on anything off."""
    if not isinstance(params, dict):
        raise BadRequest("params must be an object")
    spec = {}
    if kind == "dump":
        console_spec(params, spec)
        dump_spec(params, spec)
        summary = f"Dump {spec['title'] or 'running game'} from {spec['host']}"
    elif kind == "build":
        spec["source_dir"] = resolve_path(params.get("source_dir"), "source directory")
        spec["platform"] = params.get("platform") or "auto"
        if spec["platform"] not in ("auto", "ps4", "ps5"):
            raise BadRequest(f"unknown platform: {spec['platform']}")
        if spec["platform"] == "auto":
            spec["platform"] = source_platform(spec["source_dir"])
        spec["out_dir"] = resolve_path(params.get("out_dir"), "output directory", create=True)
        # The form carries both platforms' options; only the one that will
        # build is checked, so a stale field for the other cannot block it.
        if spec["platform"] == "ps4":
            spec["ps4"] = ps4_spec(params, with_sources=True)
        else:
            spec["ps5"] = ps5_spec(params)
        summary = (f"Build {os.path.basename(spec['source_dir'])} "
                   f"({spec['platform'].upper()})")
    elif kind == "dump-build":
        console_spec(params, spec)
        dump_spec(params, spec)
        spec["out_dir"] = resolve_path(params.get("out_dir"), "output directory", create=True)
        spec["jobs"] = int_in(params, "jobs", 1, 64, 8, "ftp jobs")
        spec["delete_dumps"] = bool(params.get("delete_dumps"))
        # The platform is only known once the console is asked, so a problem
        # with one platform's options is held until then rather than refused.
        problems = {}
        for platform, parse in (("ps4", lambda: ps4_spec(params, with_sources=False)),
                                ("ps5", lambda: ps5_spec(params))):
            try:
                spec[platform] = parse()
            except BadRequest as err:
                problems[platform] = str(err)
        if len(problems) == 2:
            raise BadRequest("; ".join(f"{p.upper()}: {e}" for p, e in problems.items()))
        spec["option_problems"] = problems
        summary = f"Dump+Build {spec['title'] or 'running game'} from {spec['host']}"
    elif kind == "backport":
        if not os.path.isfile(BACKPORT_PS5):
            raise BadRequest(f"another-backporter is not installed: {BACKPORT_PS5}")
        spec.update(backport_spec(params))
        summary = f"Backport {os.path.basename(spec['source'].rstrip(os.sep))} ({spec['tier']})"
    elif kind == "dlc-split":
        spec.update(dlc_split_spec(params))
        base = os.path.basename(spec["source"].rstrip(os.sep))
        summary = f"Split {len(spec['entries'])} DLC out of {base}"
    else:
        raise BadRequest(f"unknown job kind: {kind}")
    return Job(kind, spec, summary)


# Options that name one title's files or identity, so cannot be shared.
PER_TITLE_OPTIONS = {
    "content_id": "content ID override", "ps2_tid": "PS2 serial override",
    "base_pkg": "existing base package", "ps5_name": "package name",
    "reference_pkg": "reference package", "entitlement_key": "entitlement key",
    "sc_pkg": "SC package",
}
MAX_BATCH = 200
SCAN_DEPTH = int(setting("SCAN_DEPTH", "4"))
SCAN_LIMIT = 2000
ICON_MAX_BYTES = 8 << 20


def scanned_tree(path, label, platform, role, title_id=None):
    """A folder the scan offered, re-read here: the page's word is not trusted."""
    real = resolve_path(path, label)
    meta = dumpscan.read_meta(real)
    if meta is None:
        raise BadRequest(f"{label} has no sce_sys/param.sfo or param.json: {real}")
    if meta["platform"] != platform or meta["role"] != role:
        raise BadRequest(f"{label} is a {meta['platform'].upper()} {meta['kind']}, "
                         f"not a {platform.upper()} {role}: {real}")
    if title_id and meta["title_id"] and meta["title_id"] != title_id:
        raise BadRequest(f"{label} is for {meta['title_id']}, not {title_id}: {real}")
    return meta


def scanned_pkg(path):
    """A package the scan offered, re-read here: the page's word is not trusted."""
    real = resolve_path(path, "package", "file")
    if not real.lower().endswith(".pkg"):
        raise BadRequest(f"not a .pkg: {real}")
    try:
        pkg = pkgmod.Pkg.open(real)
    except (pkgmod.PkgError, OSError) as err:
        raise BadRequest(f"could not parse {real}: {err}") from None
    with pkg:
        if pkg.platform != "PS5":
            raise BadRequest(f"only PS5 packages can be rebuilt for now: {real}")
        if pkg.is_metadata_fragment(os.path.getsize(real)):
            raise BadRequest(f"{real} is a metadata fragment, not a full package")
        if pkg.kind == "Update":
            raise BadRequest(f"{real} is a patch image; it cannot be rebuilt on its own")
        title = pkg.title or pkg.title_id
    return real, title or os.path.splitext(os.path.basename(real))[0]


def unit_layers(source, params):
    """(platform, layers, title) for one selected scan unit.

    layers is {"base", "update", "addons"}: folders handed to build-fpkg by
    name, so it builds what the param files say rather than guessing siblings.
    A pkg source instead gives {"base": pkg_path, "rebuild": True}: build-ps5
    runs against the extracted image.
    """
    if not isinstance(source, dict):
        raise BadRequest("each source must be an object")
    if source.get("pkg"):
        if source.get("base") or source.get("update") or source.get("addons"):
            raise BadRequest("a package rebuild takes no dump folders")
        real, title = scanned_pkg(source["pkg"])
        return "ps5", {"base": real, "update": None, "addons": [],
                       "rebuild": True}, title
    base, update = source.get("base") or None, source.get("update") or None
    addons = source.get("addons") or []
    if not isinstance(addons, list) or not all(isinstance(a, str) for a in addons):
        raise BadRequest("addons must be a list of folders")
    if not all(isinstance(p, (str, type(None))) for p in (base, update)):
        raise BadRequest("base and update must be folders")
    if base and dumpscan.platform_of(resolve_path(base, "base dump")) == "ps5":
        meta = scanned_tree(base, "dump", "ps5", "base")
        if update or addons:
            raise BadRequest("PS5 dumps are built on their own")
        return "ps5", {"base": meta["path"]}, meta["title"] or meta["title_id"]
    meta = scanned_tree(base, "base dump", "ps4", "base") if base else None
    title_id = meta["title_id"] if meta else None
    if params.get("no_update"):
        update = None
    if params.get("build_no_dlc"):
        addons = []
    update_meta = scanned_tree(update, "update", "ps4", "update", title_id) if update else None
    addon_metas = [scanned_tree(a, "add-on", "ps4", "addon", title_id) for a in addons]
    if not meta and not addon_metas:
        raise BadRequest("nothing to build: an update needs its base dump")
    if not meta and update_meta:
        raise BadRequest("an update cannot be built without its base dump")
    if len({a["path"] for a in addon_metas}) != len(addon_metas):
        raise BadRequest("the same add-on is selected twice")
    lead = meta or addon_metas[0]
    title = lead["title"] or lead["title_id"] or os.path.basename(lead["path"])
    return "ps4", {"base": meta["path"] if meta else None,
                   "update": update_meta["path"] if update_meta else None,
                   "addons": [a["path"] for a in addon_metas]}, title


def build_jobs(params, sources):
    """One build Job per selected scan unit, all sharing params.

    Every unit is validated before any job exists, so a bad one queues none.
    """
    if not isinstance(params, dict):
        raise BadRequest("params must be an object")
    if not isinstance(sources, list) or not sources:
        raise BadRequest("choose at least one dump to build")
    if len(sources) > MAX_BATCH:
        raise BadRequest(f"at most {MAX_BATCH} dumps per submission")
    if len(sources) > 1:
        shared = [label for key, label in PER_TITLE_OPTIONS.items()
                  if str(params.get(key) or "").strip()]
        if shared:
            raise BadRequest(f"these options are for a single dump: {', '.join(shared)}; "
                             "clear them or select one dump")
    units = [unit_layers(s, params) for s in sources]
    used = [p for _pl, layers, _t in units for p in
            [layers.get("base"), layers.get("update"), *layers.get("addons", [])] if p]
    if len(set(used)) != len(used):
        raise BadRequest("the same folder is part of more than one selected build")
    out_dir = resolve_path(params.get("out_dir"), "output directory", create=True)
    options = {p: (ps4_spec(params, with_sources=False) if p == "ps4" else ps5_spec(params))
               for p in {pl for pl, _l, _t in units}}
    jobs = []
    for platform, layers, title in units:
        spec = {"source_dir": layers["base"] or layers["addons"][0],
                "platform": platform, "out_dir": out_dir, "layers": layers,
                platform: options[platform]}
        verb = "Rebuild" if layers.get("rebuild") else "Build"
        jobs.append(Job("build", spec, f"{verb} {title} ({platform.upper()})"))
    return jobs


# --- queue -----------------------------------------------------------------------

JOBS = {}
PENDING = queue.Queue()
JOBS_LOCK = threading.Lock()
KEEP_FINISHED = 50


def submit(job):
    with JOBS_LOCK:
        JOBS[job.id] = job
        finished = sorted((j for j in JOBS.values() if j.finished), key=lambda j: j.id)
        for old in finished[:-KEEP_FINISHED]:
            del JOBS[old.id]
    job.say(f"queued: {job.summary}")
    PENDING.put(job)


def worker():
    while True:
        job = PENDING.get()
        if job.cancelled:
            job.status = "cancelled"
            job.finished = time.time()
            job.close_log()
            continue
        job.status, job.started = "running", time.time()
        try:
            execute(job)
            job.status = "done"
            job.say("finished")
        except Cancelled:
            job.status = "cancelled"
            job.say("cancelled")
        except (JobError, BadRequest) as err:
            job.status, job.error = "failed", str(err)
            job.say(f"error: {err}")
        except Exception as err:  # a bug here must not kill the worker thread
            job.status, job.error = "failed", f"internal error: {err!r}"
            job.say(job.error)
        finally:
            job.step = ""
            job.finished = time.time()
            job.close_log()


# --- HTTP --------------------------------------------------------------------------

def list_dir(path, want_files):
    # "@roots" is the level above every allowed folder, where they are listed.
    if path == "@roots":
        return {"path": "", "parent": None, "dirs": ROOTS, "files": [],
                "roots": ROOTS, "absolute": True}
    real = resolve_path(path or ROOTS[0], "folder")
    dirs, files = [], []
    try:
        names = sorted(os.listdir(real), key=str.lower)
    except OSError as err:
        raise BadRequest(f"cannot list {real}: {err.strerror}") from None
    for name in names:
        if name.startswith("."):
            continue
        full = os.path.join(real, name)
        if os.path.isdir(full):
            dirs.append(name)
        elif want_files and name.lower().endswith(want_files):
            files.append(name)
    parent = os.path.dirname(real)
    if not inside_roots(parent) or parent == real:
        parent = "@roots"
    return {"path": real, "parent": parent, "dirs": dirs, "files": files,
            "roots": ROOTS, "absolute": False}


def usable_path(value, fallback=""):
    """value if the UI could accept it, else fallback.

    A .env written for terminal use can name host paths this container or
    WEB_ROOTS cannot reach, which would only turn into a refused submission.
    """
    if value and os.path.isabs(value) and inside_roots(os.path.realpath(value)):
        return value
    return fallback


def config():
    defaults = {
        "host": setting("HOST"),
        "dump_dir": usable_path(setting("DUMP_DIR"), ROOTS[0]),
        "scan_dir": usable_path(setting("SCAN_DIR") or setting("DUMP_DIR"), ROOTS[0]),
        "out_dir": usable_path(setting("PKG_DIR") or setting("OUT_DIR"),
                               os.path.join(ROOTS[0], "out")),
        "mode": setting("MODE", "app-merge"),
        "backport": setting("BACKPORT", "1") != "0",
        "sdk": setting("BACKPORT_TARGET_SDK", "auto"),
        "keystone": setting("KEYSTONE_MODE", "retail"),
        "no_update": setting("UPDATE") == "none",
        "build_no_dlc": setting("DLC_MODE") == "none",
        "content_id": setting("CONTENT_ID"),
        "ps2_tid": setting("PS2_TID"),
        "tmp_dir": usable_path(setting("IMG_TMP_DIR")),
        "jobs": setting("JOBS", "8"),
        "ps5_temp_dir": usable_path(setting("LIBPROSPERO_TEMP_DIR")),
        "passcode": "0" * 32,
        "compression_level": "7",
        "chunk_count": "",
        "libs_dir": usable_path(setting("PS5BACKPORT_LIBS")),
        "tier": "7xx",
    }
    tools = {name: os.path.exists(path) for name, path in
             (("pfsdump", PFSDUMP), ("ftpdump", FTPDUMP),
              ("build-fpkg", BUILD_FPKG), ("build-ps5", BUILD_PS5),
              ("backport-ps5", BACKPORT_PS5),
              ("prospero-pub-cmd", PROSPERO_PUB_CMD))}
    tools["wine"] = shutil.which("wine") is not None
    return {"defaults": defaults, "roots": ROOTS, "tools": tools,
            "log_dir": LOG_DIR}


class Handler(BaseHTTPRequestHandler):
    server_version = "fpkger-web"

    def log_message(self, fmt, *args):
        if os.environ.get("WEB_ACCESS_LOG"):
            super().log_message(fmt, *args)

    def _send(self, status, body, content_type="application/json", cache="no-store"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(data)

    def _error(self, status, message):
        self._send(status, {"error": message})

    def _authorised(self):
        if not PASSWORD:
            return True
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                _user, _, given = base64.b64decode(header[6:]).decode().partition(":")
            except (ValueError, UnicodeDecodeError):
                given = ""
            if hmac.compare_digest(given.encode(), PASSWORD.encode()):
                return True
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="fpkger"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def do_GET(self):
        if not self._authorised():
            return
        url = urlparse(self.path)
        query = parse_qs(url.query)
        arg = lambda key: (query.get(key) or [""])[0]  # noqa: E731
        try:
            if url.path in ("/", "/index.html"):
                with open(os.path.join(HERE, "index.html"), "rb") as handle:
                    self._send(HTTPStatus.OK, handle.read(), "text/html; charset=utf-8")
            elif url.path == "/api/config":
                self._send(HTTPStatus.OK, config())
            elif url.path == "/api/browse":
                files = arg("files")
                self._send(HTTPStatus.OK, list_dir(arg("path"), f".{files}" if files else ""))
            elif url.path == "/api/platform":
                src = resolve_path(arg("path"), "dump folder")
                self._send(HTTPStatus.OK, {"platform": source_platform(src)})
            elif url.path == "/api/scan":
                root = resolve_path(arg("path"), "scan folder")
                depth = int_in({"d": arg("depth")}, "d", 0, 8, SCAN_DEPTH, "scan depth")
                units, found, truncated = dumpscan.scan(root, depth, SCAN_LIMIT)
                if not os.path.isfile(PROSPERO_PUB_CMD):
                    for u in units:
                        if u.get("rebuild"):
                            u["buildable"] = False
                            u["notes"].append("rebuilding needs prospero-pub-cmd.exe, "
                                              f"which is missing: {PROSPERO_PUB_CMD}")
                self._send(HTTPStatus.OK, {"path": root, "depth": depth, "units": units,
                                           "found": found, "truncated": truncated,
                                           "limit": SCAN_LIMIT})
            elif url.path == "/api/icon":
                if arg("path").lower().endswith(".pkg"):
                    src = resolve_path(arg("path"), "package", "file")
                    try:
                        with pkgmod.Pkg.open(src) as pkg:
                            data = pkg.read_icon0()
                    except (pkgmod.PkgError, OSError):
                        data = None
                    if not data or len(data) > ICON_MAX_BYTES:
                        return self._error(HTTPStatus.NOT_FOUND, "no icon")
                else:
                    src = resolve_path(arg("path"), "dump folder")
                    icon = os.path.join(src, "sce_sys", "icon0.png")
                    if not inside_roots(os.path.realpath(icon)) or not os.path.isfile(icon):
                        return self._error(HTTPStatus.NOT_FOUND, "no icon")
                    if os.path.getsize(icon) > ICON_MAX_BYTES:
                        return self._error(HTTPStatus.NOT_FOUND, "icon too large")
                    with open(icon, "rb") as handle:
                        data = handle.read()
                if not data.startswith(b"\x89PNG\r\n\x1a\n"):
                    return self._error(HTTPStatus.NOT_FOUND, "icon is not a PNG")
                self._send(HTTPStatus.OK, data, "image/png", "private, max-age=300")
            elif url.path == "/api/titles":
                host, port = parse_host(arg("host"))
                try:
                    titles = mounted_titles(host, port)
                    found = [{"title": t, "platform": image_platform(host, port, t)}
                             for t in titles]
                except (OSError, EOFError, pfsdump.ftplib.Error) as err:
                    raise BadRequest(f"could not reach {host}:{port}: {err}") from None
                self._send(HTTPStatus.OK, {"titles": found})
            elif url.path == "/api/jobs":
                with JOBS_LOCK:
                    jobs = sorted(JOBS.values(), key=lambda j: -j.id)
                self._send(HTTPStatus.OK, {"jobs": [j.summary_dict() for j in jobs]})
            elif m := re.fullmatch(r"/api/jobs/(\d+)", url.path):
                job = JOBS.get(int(m.group(1)))
                if job is None:
                    return self._error(HTTPStatus.NOT_FOUND, "no such job")
                since = int(arg("since") or 0)
                self._send(HTTPStatus.OK, job.detail(since))
            else:
                self._error(HTTPStatus.NOT_FOUND, "not found")
        except BadRequest as err:
            self._error(HTTPStatus.BAD_REQUEST, str(err))
        except ValueError as err:
            self._error(HTTPStatus.BAD_REQUEST, str(err))

    def do_POST(self):
        if not self._authorised():
            return
        # A cross-site form cannot send JSON without a preflight this server
        # never answers, and a stated Origin must be this host.
        if self.headers.get_content_type() != "application/json":
            return self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "expected JSON")
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).netloc != self.headers.get("Host"):
            return self._error(HTTPStatus.FORBIDDEN, "cross-origin request refused")
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 1 << 20:
                return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too large")
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._error(HTTPStatus.BAD_REQUEST, "invalid JSON")
        url = urlparse(self.path)
        try:
            if url.path == "/api/jobs":
                job = build_job(body.get("kind"), body.get("params"))
                submit(job)
                self._send(HTTPStatus.CREATED, job.summary_dict())
            elif url.path == "/api/jobs/batch":
                jobs = build_jobs(body.get("params"), body.get("sources"))
                for job in jobs:
                    submit(job)
                self._send(HTTPStatus.CREATED, {"jobs": [j.summary_dict() for j in jobs]})
            elif m := re.fullmatch(r"/api/jobs/(\d+)/cancel", url.path):
                job = JOBS.get(int(m.group(1)))
                if job is None:
                    return self._error(HTTPStatus.NOT_FOUND, "no such job")
                if job.finished is None:
                    cancel(job)
                    job.say("cancel requested")
                self._send(HTTPStatus.OK, job.summary_dict())
            else:
                self._error(HTTPStatus.NOT_FOUND, "not found")
        except BadRequest as err:
            self._error(HTTPStatus.BAD_REQUEST, str(err))
        except OSError as err:
            self._error(HTTPStatus.BAD_REQUEST, f"{err.strerror}: {err.filename}")


def main():
    bind = setting("WEB_BIND", "0.0.0.0")
    port = int(setting("WEB_PORT", "8080"))
    threading.Thread(target=worker, daemon=True).start()
    server = ThreadingHTTPServer((bind, port), Handler)
    server.daemon_threads = True
    print(f">> fpkger web UI on http://{bind}:{port}/", file=sys.stderr)
    print(f">> folders: {', '.join(ROOTS)}; logs: {LOG_DIR}", file=sys.stderr)
    if not PASSWORD:
        print(">> warning: WEB_PASSWORD is unset, so anyone who can reach this "
              "port can run dumps and builds", file=sys.stderr)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        for job in list(JOBS.values()):
            if job.finished is None:
                cancel(job)
        server.server_close()


if __name__ == "__main__":
    main()
