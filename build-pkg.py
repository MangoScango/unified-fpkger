#!/usr/bin/env python3
"""build-pkg.py — repackage a raw PS4 or PS5 dump into a fake PKG on Linux.

One module replacing build-fpkg.sh (PS4) and build-ps5.sh (PS5); the pipelines
are verbatim ports, with the external tools (wine exes, sfo, the python
helpers) still subprocesses on the same argv shapes.

----------------------------------------------------------------------------
PS4: build-pkg.py ps4 [options] <dir> [dir ...]

Repackage a raw PS4 dump into a booting, COMPRESSED fake-PKG. Works for
normal PS4 games AND PS2-Classics; the PS2 handling is applied automatically
when a PS2-emulator title is detected. Optionally merges an update/patch dump
onto the base first.

Directories are identified by their own param.sfo, so they can be given in
any order and no flag is needed to say what each one is:
  CATEGORY=gd   -> base app dump
  CATEGORY=gp*  -> update/patch dump (merged onto the base as a remaster)
  CATEGORY=ac   -> add-on ("-ac" = with content, "-al" = entitlement only)
  no param.sfo but add-on subdirs -> a container of add-ons
Pass only add-on/DLC dirs to build just those pkgs; no base dump is needed
for them. --update/--dlc still work and are equivalent to naming the dir.

  --content-id CID   pkg content id (default: read from base param.sfo)
  --update DIR       explicit update/patch dump to merge onto the base
  --no-update        base-only; do not auto-merge a sibling patch
  --app-merge        merged app pkg + backport patch (default)
  --remaster         merged remaster pkg with the backport baked in
  --separate         app pkg + update pkg + backport patch
  --no-backport      do not run the SDK backport pass
  --base-pkg PKG     build only the backport patch, for a base package that
                     already exists. The dumps still supply the executables;
                     CONTENT_ID and APP_VER come from the pkg, and a mismatch
                     against the dumps is refused since a patch only marries
                     the base it was built against.
  --sdk VER          backport target SDK, or "auto" (default). "auto" picks
                     the oldest firmware exporting everything the title
                     imports; pass an explicit stamp to override.
  --dlc DIR          DLC dump dir (holds one or more "*-ac"/"*-al" content
                     dirs) to build add-on pkgs from; repeatable. Default:
                     auto-detect a sibling "<foo>-dlc" dir.
  --no-dlc           do not build any DLC pkgs
  --keystone MODE    retail (default) | kscreate
  --ps2-tid NNNNN    force the 5-digit PS2 serial for emu auth
                     (default: auto-derived from CONTENT_ID for PS2 titles)
  -o, --out DIR      output directory (default: cwd)
  --tmp-dir DIR      scratch for img_create's internal image, which needs
                     room for another copy of the title (default: <cwd>/fpkgtmp)

Every option above has an environment variable behind it (MODE, BACKPORT,
BACKPORT_TARGET_SDK, KEYSTONE_MODE, CONTENT_ID, UPDATE, DLC_MODE, DLC,
BASE_PKG_IN, IMG_TMP_DIR, PATCH_SCE_SYS, PS2_TID, KEEP_STAGE,
KEEP_VERSION_RECORDS), and a .env file of KEY=VALUE lines sets those.
./.env is read first, then the one beside the script; the environment wins
over both.

How signing works (PS4): orbis-pub-cmd's img_create fake-signs plain-ELF
executables itself during the build, so a normal game is signed by no one.
The only pre-signing is the PS2-emulator auth block on a PS2 classic:
eboot.bin, ps2-emu-compiler.self, sce_module/libc.prx and libSceFios2.prx.
Everything else is left for img_create.

----------------------------------------------------------------------------
PS5: build-pkg.py ps5 --source-folder <dir> --output-package <file.pkg> [opts]

  --reference-package <file.pkg>   build a plaintext/no-auth patch against it
  --sc-pkg <file.pkg|url>          restore sce_sys metadata from a retail SC pkg
  --passcode <hex>                 (default: 00000000000000000000000000000000)
  --python <path>                  (default: python3)
  --temp-dir <dir>                 (default: $LIBPROSPERO_TEMP_DIR)
  --compression-level <-4..9>      (default: 7)
  --chunk-count <1..800>           apps only; used when the source has no
                                   sce_sys/playgo-chunk.dat (default: 100)
  --playgo-languages <list>        apps only; e.g. en-US,ru-RU
  --volume <auto|app|ac>           (default: auto; ac when there is no eboot.bin)
  --entitlement-key <hex>          add-ons only (default: the source's
                                   entitlement_key.dat, else 32 zeroes)
  --keep-intermediate
  --force

----------------------------------------------------------------------------
With no subcommand the source is sniffed: a tree holding sce_sys/param.json
builds as ps5, anything else as ps4.

stdout carries only the result .pkg paths, one per line; all narration goes
to stderr with a ">> " prefix. Exit 0 on success, 1 on failure.
"""

import argparse
import datetime
import glob
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

SELF_DIR = os.path.dirname(os.path.realpath(__file__))


# Defaults for every tool path and option below, as KEY=VALUE lines. Only
# unset variables are filled, so the environment wins over ./.env, which wins
# over the one beside the script.
def load_env():
    values = {}
    for path in (os.path.join(os.getcwd(), ".env"), os.path.join(SELF_DIR, ".env")):
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
    for key, value in values.items():
        os.environ.setdefault(key, value)


load_env()


def env(key, default=""):
    return os.environ.get(key) or default


# --- tools (override via env) ----------------------------------------------
SDK_DIR = env("SDK_DIR", os.path.join(SELF_DIR, "PS4_Fake_PKG_Tools_3"))
GENGP4_APP = env("GENGP4_APP", os.path.join(SDK_DIR, "gengp4_app.exe"))
GENGP4_PATCH = env("GENGP4_PATCH", os.path.join(SDK_DIR, "gengp4_patch.exe"))
# Patched to accept APP_VER != 01.00 on an app volume.
ORBIS_PUB_CMD = env("ORBIS_PUB_CMD", os.path.join(SDK_DIR, "orbis-pub-cmd.exe"))
MAKE_FSELF = env("MAKE_FSELF", os.path.join(SELF_DIR, "make_fself.py"))
BACKPORT_SDK = env("BACKPORT_SDK", os.path.join(SELF_DIR, "backport-sdk.py"))
PKG_SET_APPVER = env("PKG_SET_APPVER", os.path.join(SELF_DIR, "pkg-set-appver.py"))
SHRINK_PNG = env("SHRINK_PNG", os.path.join(SELF_DIR, "shrink-png.py"))
SFO_TOOL = env("SFO_TOOL", os.path.join(SELF_DIR, "sfo"))
SC_OVERLAY = env("SC_OVERLAY", os.path.join(SELF_DIR, "sc-overlay.py"))
FAKE_PASSCODE = "00000000000000000000000000000000"
DLC_ENT_KEY = "00000000000000000000000000000000"   # zero entitlement key (kstuff fakes the check)
WINE_OVERRIDES = "wineps.drv,localspl.dll,spoolss.dll=d"

# PS2-emu auth-info templates (authinfo_emu.txt, FW=501). The first 2 bytes
# (4 hex chars) are replaced with the PS2 title-id decimal bytes.
EBOOT_AUTH_TMPL = "0000C2AC03000034000000008003002000FF00000000002000000000000000000000000000000000000080C000400040000000000000004002000000000080000040FFFF000000F000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
COMPILER_AUTH_TMPL = "0000C2AC03000034000000008003002000FF00000000004000000000000000000000000000000000000080C000400040000000000000004008000000000080000040FFFF000000F000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
PRX_AUTH_TMPL = "0000C2AC03000035000000000000000000FF000000000000000000000000000000000000000000000000004000300030000000000000004000000000000080000040FFFF000000F000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def log(*msg):
    print(">>", *msg, file=sys.stderr, flush=True)


def strip_one_slash(path):
    # the shell scripts' ${var%/}
    return path[:-1] if path.endswith("/") else path


def sanitize(text):
    # tr -c 'A-Za-z0-9_-' '_' — byte-wise, like tr
    return re.sub(rb"[^A-Za-z0-9_-]", b"_", os.fsencode(text)).decode(
        "utf-8", errors="replace")


def iec(n):
    # numfmt --to=iec
    units = ("", "K", "M", "G", "T", "P")
    if n < 1024:
        return str(int(n))
    value = float(n)
    unit = 0
    while value >= 1024 and unit < len(units) - 1:
        value /= 1024
        unit += 1
    return f"{value:.1f}{units[unit]}"


def newest_pkg(directory, pattern="*.pkg"):
    # ls -t <dir>/<pattern> | head -1
    paths = glob.glob(os.path.join(glob.escape(directory), pattern))
    if not paths:
        return ""
    return max(paths, key=lambda p: (os.path.getmtime(p), p))


def show_files(*paths):
    # the ls -la ... >&2 result listings
    for path in paths:
        if not path:
            continue
        try:
            log(f"{os.path.getsize(path):>14}  {path}")
        except OSError:
            log(path)


# ---------------------------------------------------------------------------
# wine / sfo / helpers
# ---------------------------------------------------------------------------
def wine_env():
    return dict(os.environ,
                WINEDEBUG=env("WINEDEBUG", "-all"),
                WINEDLLOVERRIDES=WINE_OVERRIDES)


# The CyB1K tools write to a Windows console, which wine only bridges onto
# unix fds when fd 0/1/2 is a tty, so run them under a pty. /dev/null as the
# typescript makes script(1) stream to our stdout instead of buffering to a
# file.
def wine_argv(argv):
    if shutil.which("script"):
        cmd = ("WINEDEBUG=%s WINEDLLOVERRIDES=%s wine %s"
               % (env("WINEDEBUG", "-all"), WINE_OVERRIDES, shlex.join(argv)))
        # script -c runs through $SHELL, not sh, and script itself consumes stdin.
        return ["script", "-qefc", cmd, "/dev/null"], dict(os.environ, SHELL="/bin/sh")
    return ["wine", *argv], wine_env()


def wine_run(argv, cwd=None, stdout=None, stderr=None):
    # stdout defaults to our stderr: the tool chatter is narration, and our own
    # stdout carries only the result pkg paths
    if stdout is None:
        stdout = sys.stderr
    cmd, environ = wine_argv(argv)
    return subprocess.run(cmd, cwd=cwd, env=environ,
                          stdin=subprocess.DEVNULL, stdout=stdout,
                          stderr=stderr).returncode


def wine_popen(argv):
    cmd, environ = wine_argv(argv)
    return subprocess.Popen(cmd, env=environ, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def winpath(path):
    out = subprocess.run(["winepath", "-w", path], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL)
    return out.stdout.decode(errors="replace").strip()


def sfo_get(path, key):
    out = subprocess.run([SFO_TOOL, path, "-q", key], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL)
    return out.stdout.decode(errors="replace").replace("\r", "").replace("\n", "")


def sfo_pkg(pkg, key):
    # the sfo tool also takes the key first, which is how it reads inside a pkg
    out = subprocess.run([SFO_TOOL, "-q", key, pkg], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL)
    return out.stdout.decode(errors="replace").replace("\r", "").replace("\n", "")


def sfo_edit(*args):
    subprocess.run([SFO_TOOL, *args], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


# Publishing Tools rejects icon0*.png over 1 MiB; some dumps pad them with metadata.
def fix_icons(sce_sys):
    if subprocess.run([sys.executable, SHRINK_PNG, sce_sys]).returncode:
        die(f"icon0 in {sce_sys} is too large for Publishing Tools")


# ent_key_of <dir>: the add-on dump's entitlement_key.dat as 32 hex digits
# (16 raw bytes from pfsdump, or hand-written hex), else the zero key.
def ent_key_of(directory):
    path = os.path.join(directory, "entitlement_key.dat")
    key = ""
    if os.path.isfile(path):
        with open(path, "rb") as handle:
            data = handle.read()
        if len(data) == 16:
            key = data.hex()
        else:
            key = re.sub(r"\s+", "", data.decode(errors="replace"))
    return key.upper() if re.fullmatch(r"[0-9A-Fa-f]{32}", key) else DLC_ENT_KEY


# ---------------------------------------------------------------------------
# staging: hardlinked copies, with sce_sys always real files (gengp4 and
# img_create rewrite files where they lie, and a hardlink would write
# straight through to the dump)
# ---------------------------------------------------------------------------
def copy_tree(src, dst, link=False):
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        target = dst if rel == "." else os.path.join(dst, rel)
        os.makedirs(target, exist_ok=True)
        for name in list(dirs):
            src_dir = os.path.join(root, name)
            if os.path.islink(src_dir):
                os.symlink(os.readlink(src_dir), os.path.join(target, name))
                dirs.remove(name)
        for name in files:
            src_file = os.path.join(root, name)
            dst_file = os.path.join(target, name)
            if os.path.islink(src_file):
                os.symlink(os.readlink(src_file), dst_file)
            elif link:
                try:
                    os.link(src_file, dst_file)
                except OSError:
                    shutil.copy2(src_file, dst_file)
            else:
                shutil.copy2(src_file, dst_file)


def overlay_tree(src, dst, link=False):
    # cp -a(l)f <src>/., merging over an existing tree; the destination file is
    # replaced rather than rewritten, so a hardlink is never written through
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        target = dst if rel == "." else os.path.join(dst, rel)
        os.makedirs(target, exist_ok=True)
        for name in list(dirs):
            src_dir = os.path.join(root, name)
            if os.path.islink(src_dir):
                dst_dir = os.path.join(target, name)
                if os.path.lexists(dst_dir):
                    os.remove(dst_dir)
                os.symlink(os.readlink(src_dir), dst_dir)
                dirs.remove(name)
        for name in files:
            src_file = os.path.join(root, name)
            dst_file = os.path.join(target, name)
            if os.path.lexists(dst_file):
                os.remove(dst_file)
            if os.path.islink(src_file):
                os.symlink(os.readlink(src_file), dst_file)
            elif link:
                try:
                    os.link(src_file, dst_file)
                except OSError:
                    shutil.copy2(src_file, dst_file)
            else:
                shutil.copy2(src_file, dst_file)


EXECUTABLE_NAME = re.compile(r"(eboot\.bin|.*\.(elf|self|prx|sprx))$")


# img_create fake-signs executables by rewriting them where they lie, so a
# hardlink from the stage would carry the rewrite back into the dump.
def unlink_executables(stage):
    for root, dirs, files in os.walk(stage):
        for name in files:
            if not EXECUTABLE_NAME.match(name):
                continue
            path = os.path.join(root, name)
            if os.path.islink(path):
                continue
            try:
                if os.stat(path).st_nlink <= 1:
                    continue
            except OSError:
                continue
            shutil.copy2(path, path + ".unlinking")
            os.replace(path + ".unlinking", path)


# ---------------------------------------------------------------------------
# PS4 pipeline state (the shell script's globals)
# ---------------------------------------------------------------------------
WORK_DIR = ""
OUT_DIR = ""
DUMP = ""
UPDATE = ""                    # "" = auto-discover, "none" = base-only, else a dir
CONTENT_ID = ""
TITLE_ID = ""
BASE_APPVER = ""
OBSERVED_SDK = ""
IS_PS2 = False
PS2_TID = ""
KEYSTONE_MODE = "retail"
MODE = "app-merge"
BACKPORT = 1
BACKPORT_TARGET_SDK = "auto"
RESOLVED_SDK = ""
BASE_PKG_IN = ""
DLC_MODE = ""                  # "" = auto-discover, "none" = no DLC, "explicit"
DLC_DIRS = []
DLC_ITEMS = []
# sce_sys a backport patch carries; a directory here is taken whole. Anything
# not listed falls through to the app volume underneath.
#
# playgo-chunk.dat carries the chunk count, and img_create rejects a patch that
# changes it. npbind.dat holds the NP Communication ID the trophy system resolves
# at startup. Trimming this list needs hardware to check.
PATCH_SCE_SYS = env("PATCH_SCE_SYS", "param.sfo icon0.png playgo-chunk.dat npbind.dat")

# PS2 auth blobs, derived from the PS2 title id once per run
EBOOT_AUTH = EBOOT_PAID = COMPILER_AUTH = COMPILER_PAID = PRX_AUTH = PRX_PAID = ""


# ---------------------------------------------------------------------------
# img_create progress: report the package as it grows, since orbis-pub-cmd
# prints nothing while img_create runs. NO_PROGRESS silences it,
# PROGRESS_EVERY sets the interval.
# ---------------------------------------------------------------------------
IMG_TMP_DIR = env("IMG_TMP_DIR")
IMG_TMP_WIN = ""
IMG_PS4PUB = ""


# orbis-pub-cmd stages the internal image as numbered .tpfs files under
# <tmp_path>\ps4pub\build<id>\, needing room for another copy of the title.
# IMG_TMP_DIR overrides the location.
def img_tmp_init():
    global IMG_TMP_DIR, IMG_TMP_WIN
    if IMG_TMP_WIN:
        return
    if not IMG_TMP_DIR:
        IMG_TMP_DIR = os.path.join(WORK_DIR, "fpkgtmp")
    os.makedirs(IMG_TMP_DIR, exist_ok=True)
    IMG_TMP_WIN = winpath(IMG_TMP_DIR)


def ps4pub_dir():
    global IMG_PS4PUB
    if not IMG_PS4PUB:
        base = os.path.join(env("WINEPREFIX", os.path.expanduser("~/.wine")),
                            "drive_c")
        for root, dirs, _files in os.walk(base):
            depth = 0 if root == base else os.path.relpath(root, base).count(os.sep) + 1
            if "ps4pub" in dirs:
                IMG_PS4PUB = os.path.join(root, "ps4pub")
                break
            if depth >= 3:
                dirs[:] = []
    return IMG_PS4PUB


# Bytes in the build dirs this run created. A failed run leaves its dir
# behind, so the marker is what separates ours from the debris.
def img_staged_bytes(marker):
    root = os.path.join(IMG_TMP_DIR, "ps4pub") if IMG_TMP_DIR else ""
    if not root or not os.path.isdir(root):
        root = ps4pub_dir()
    if not root or not os.path.isdir(root):
        return 0
    try:
        marker_mtime = os.path.getmtime(marker)
    except OSError:
        return 0
    total = 0
    for build in glob.glob(os.path.join(glob.escape(root), "build*")):
        try:
            if not os.path.isdir(build) or os.path.getmtime(build) <= marker_mtime:
                continue
        except OSError:
            continue
        for root2, dirs, files in os.walk(build):
            for name in dirs + files:
                try:
                    total += os.path.getsize(os.path.join(root2, name))
                except OSError:
                    pass
    return total


class ImgProgress(threading.Thread):
    def __init__(self, out_dir):
        super().__init__(daemon=True)
        self.out_dir = out_dir
        self.marker = None
        self.stop_event = threading.Event()
        try:
            self.every = int(env("PROGRESS_EVERY", "15"))
        except ValueError:
            self.every = 0

    def start(self):
        if env("NO_PROGRESS") or self.every <= 0:
            return
        fd, self.marker = tempfile.mkstemp()
        os.close(fd)
        super().start()

    def run(self):
        prev = iprev = 0
        while not self.stop_event.wait(self.every):
            # img_create creates the package up front and leaves it at zero
            # bytes until staging finishes.
            current = 0
            pkg = newest_pkg(self.out_dir)
            if pkg:
                try:
                    current = os.path.getsize(pkg)
                except OSError:
                    pass
            if current > prev:
                log(f"image: {iec(current)} written "
                    f"({iec((current - prev) // self.every)}/s)")
                prev = current
                continue
            staged = img_staged_bytes(self.marker)
            if staged > iprev:
                log(f"internal image: {iec(staged)} staged "
                    f"({iec((staged - iprev) // self.every)}/s)")
                iprev = staged

    def stop(self):
        self.stop_event.set()
        if self.marker:
            try:
                os.remove(self.marker)
            except OSError:
                pass
            self.marker = None
        if self.is_alive():
            self.join()


# img_create with progress around it. orbis-pub-cmd returns non-zero on
# warnings alone, so the status is dropped and callers check for the package.
def img_create(out_dir, args):
    # The watcher reads IMG_TMP_DIR, so resolve it before forking.
    img_tmp_init()
    watcher = ImgProgress(out_dir)
    watcher.start()
    fd, log_file = tempfile.mkstemp()
    proc = wine_popen([ORBIS_PUB_CMD, "img_create", "--tmp_path", IMG_TMP_WIN, *args])
    with os.fdopen(fd, "wb") as log_handle:
        for chunk in iter(proc.stdout.readline, b""):
            sys.stderr.buffer.write(chunk)
            sys.stderr.buffer.flush()
            log_handle.write(chunk)
    proc.wait()
    watcher.stop()
    # The exit status is useless here - orbis-pub-cmd returns non-zero for
    # warnings alone - but it prefixes real failures with [Error]. The pty
    # leaves CSI escapes and CRs around those lines.
    with open(log_file, "rb") as handle:
        text = handle.read().replace(b"\0", b"").replace(b"\r", b"")
    text = re.sub(rb"\x1b\[[0-9;?]*[a-zA-Z]", b"", text).decode(errors="replace")
    os.remove(log_file)
    errors = [line for line in text.split("\n") if line.startswith("[Error]")]
    if errors:
        die("img_create failed:\n" + "\n".join(errors))


# ---------------------------------------------------------------------------
# gen_gp4 <stage_dir> -> produces <stage_dir>.gp4
# ---------------------------------------------------------------------------
# An update can respell a file it replaces (il2CppUserAssemblies.prx ->
# Il2CppUserAssemblies.prx), and img_create rejects a project holding two
# targ_paths that differ only in case. The update's spelling wins.
def dedupe_case(stage, update):
    if not os.path.isdir(update):
        return
    files = []
    for root, dirs, names in os.walk(stage):
        for name in names:
            if os.path.islink(os.path.join(root, name)):
                continue
            files.append(os.path.relpath(os.path.join(root, name), stage))
    files.sort(key=lambda p: (p.lower(), p))
    prev_lower = prev_rel = None
    dropped = 0
    for rel in files:
        lower = rel.lower()
        if prev_lower is not None and lower == prev_lower:
            in_update = os.path.lexists(os.path.join(update, rel))
            prev_in_update = os.path.lexists(os.path.join(update, prev_rel))
            if in_update and not prev_in_update:
                os.remove(os.path.join(stage, prev_rel))
                dropped += 1
                log(f"case-duplicate from the base dropped: {prev_rel}")
            elif prev_in_update and not in_update:
                os.remove(os.path.join(stage, rel))
                dropped += 1
                log(f"case-duplicate from the base dropped: {rel}")
                continue
            else:
                die("case-duplicate the update does not disambiguate: "
                    f"{prev_rel}, {rel}")
        prev_lower, prev_rel = lower, rel
    if dropped:
        log(f"dropped {dropped} case-duplicate file(s) the update respelled")


# Win32 strips trailing spaces and dots from path components, so gengp4_app
# cannot open such a file and dies with an unhandled exception. Retail titles
# do ship them: Dark Souls Remastered has "playgo-chunks.xml ". Stage them
# under a name it can open and record the mapping.
def stage_fix_names(stage):
    map_path = stage + ".namefix"
    if os.path.lexists(map_path):
        os.remove(map_path)
    for root, dirs, _files in os.walk(stage):
        for name in dirs:
            if name.endswith(" ") or name.endswith("."):
                die("directory name ends in a space or dot, which these tools "
                    "cannot address: "
                    + os.path.relpath(os.path.join(root, name), stage))
    mapping = []
    for root, _dirs, files in os.walk(stage):
        for name in files:
            if not (name.endswith(" ") or name.endswith(".")):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, stage)
            reldir = rel[:len(rel) - len(name)]
            safe = name.rstrip(" .")
            # same length, so no sibling collision
            safe += "_" * (len(name) - len(safe))
            try:
                os.rename(path, os.path.join(stage, reldir + safe))
            except OSError:
                die(f"could not rename {rel} in the stage")
            mapping.append((reldir + safe, rel))
            log(f"staged '{rel}' as '{safe}' (name ends in space/dot)")
    if mapping:
        with open(map_path, "w", encoding="utf-8") as handle:
            for safe, real in mapping:
                handle.write(f"{safe}\t{real}\n")


# targ_path is stored verbatim in the pkg and never opened as a Win32 path, so
# the real name goes back here.
def gp4_restore_names(stage):
    gp4 = stage + ".gp4"
    map_path = stage + ".namefix"
    if not os.path.isfile(map_path) or os.path.getsize(map_path) == 0:
        if os.path.lexists(map_path):
            os.remove(map_path)
        return
    with open(map_path, encoding="utf-8", errors="replace") as handle:
        mapping = [line.rstrip("\n").split("\t", 1)
                   for line in handle if "\t" in line]
    for safe, real in mapping:
        with open(gp4, "rb") as handle:
            data = handle.read()
        new = b'targ_path="' + real.encode() + b'"'
        data = data.replace(b'targ_path="' + safe.encode() + b'"', new)
        with open(gp4, "wb") as handle:
            handle.write(data)
        if new not in data:
            die(f"could not restore '{real}' in {gp4}")
        log(f"restored '{real}' in the gp4")
    os.remove(map_path)


# A stage name may not start with a dot: these tools treat everything after
# one as an extension and would write the project to ".gp4".
def gen_gp4(stage, gen=None):
    gen = gen or GENGP4_APP
    gp4 = stage + ".gp4"
    if os.path.basename(stage).startswith("."):
        die(f"stage name may not start with a dot: {stage}")
    if os.path.lexists(gp4):
        os.remove(gp4)
    stage_fix_names(stage)
    wine_run([gen, winpath(stage)], cwd=os.path.dirname(stage))
    if not os.path.isfile(gp4):
        die(f"gengp4 did not produce {gp4}")
    gp4_restore_names(stage)

    # gengp4 can point default_id at a scenario that isn't there, which both
    # img_create and gp4_proj_update reject.
    with open(gp4, "rb") as handle:
        data = handle.read()
    first = re.search(rb'<scenario id="([0-9]+)"', data)
    if first:
        data = re.sub(rb'<scenarios default_id="[0-9]*">',
                      b'<scenarios default_id="' + first.group(1) + b'">', data)
        with open(gp4, "wb") as handle:
            handle.write(data)


# ---------------------------------------------------------------------------
# stage_tree <stage_dir> [overlay_update]
#   Populate a staging dir from the base dump (hardlinked), optionally overlay
#   the update, pre-sign PS2 emu modules, and place the keystone.
# ---------------------------------------------------------------------------
def stage_tree(stage, overlay):
    shutil.rmtree(stage, ignore_errors=True)
    # Bulk content is hardlinked but sce_sys is copied to prevent modifying dump
    copy_tree(DUMP, stage, link=True)
    shutil.rmtree(os.path.join(stage, "sce_sys"), ignore_errors=True)
    copy_tree(os.path.join(DUMP, "sce_sys"), os.path.join(stage, "sce_sys"))
    entitlements = os.path.join(stage, "entitlements.txt")
    if os.path.lexists(entitlements):
        os.remove(entitlements)     # pfsdump's record, not game content
    if overlay and UPDATE:
        log("overlaying update (update wins)")
        overlay_tree(UPDATE, stage)
        dedupe_case(stage, UPDATE)
    fix_icons(os.path.join(stage, "sce_sys"))

    if IS_PS2:
        for paid, auth, name in (
                (EBOOT_PAID, EBOOT_AUTH, "eboot.bin"),
                (COMPILER_PAID, COMPILER_AUTH, "ps2-emu-compiler.self"),
                (PRX_PAID, PRX_AUTH, "sce_module/libc.prx"),
                (PRX_PAID, PRX_AUTH, "sce_module/libSceFios2.prx")):
            path = os.path.join(stage, name)
            if not os.path.isfile(path):
                continue
            log(f"pre-signing PS2-emu module: {name}")
            rc = subprocess.run([sys.executable, MAKE_FSELF,
                                 "--paid", paid, "--auth-info", auth,
                                 path, path + ".fself"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL).returncode
            if rc:
                die(f"sign failed: {name}")
            os.replace(path + ".fself", path)

    keystone = os.path.join(stage, "sce_sys", "keystone")
    if KEYSTONE_MODE == "kscreate":
        log("generating keystone from passcode (ks_create)")
        rc = wine_run([ORBIS_PUB_CMD, "ks_create", "--passcode", FAKE_PASSCODE,
                       winpath(keystone)],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if rc:
            die("ks_create failed")
    else:
        log("using retail keystone from base dump")
        source = os.path.join(DUMP, "sce_sys", "keystone")
        if not os.path.isfile(source):
            die(f"no keystone in base dump: {source}")
        if os.path.lexists(keystone):
            os.remove(keystone)
        shutil.copyfile(source, keystone)

    unlink_executables(stage)


# ---------------------------------------------------------------------------
# stage_from <src_dir> <stage_dir> [overlay_dir]
#   Hardlinked copy of any tree, with sce_sys as real files (gengp4_app rewrites
#   param.sfo in place, and a hardlink would write through to the dump).
#   Unlike stage_tree this touches neither the keystone nor the PS2 modules: it
#   is for update trees, which carry their own sce_sys and no keystone.
# ---------------------------------------------------------------------------
def stage_from(src, stage, overlay=""):
    shutil.rmtree(stage, ignore_errors=True)
    copy_tree(src, stage, link=True)
    shutil.rmtree(os.path.join(stage, "sce_sys"), ignore_errors=True)
    copy_tree(os.path.join(src, "sce_sys"), os.path.join(stage, "sce_sys"))
    if overlay:
        log(f"overlaying {os.path.basename(overlay)} onto the update tree")
        overlay_tree(overlay, stage)
        # the overlay carries whichever param.sfo the backport last collected
        shutil.copy2(os.path.join(src, "sce_sys", "param.sfo"),
                     os.path.join(stage, "sce_sys", "param.sfo"))
    fix_icons(os.path.join(stage, "sce_sys"))
    unlink_executables(stage)


# ---------------------------------------------------------------------------
# build_patch_pkg <update_dir> <app_pkg> <suffix> [overlay_dir]
#   Returns the built pkg path. Scanned with gengp4_patch.exe, which is the
#   generator meant for update trees (it keeps a keystone out of the project),
#   then pointed at the app pkg it patches -- the headless equivalent of the
#   GUI's Project Settings > Patch > "Application Package" field. The update's
#   own sce_sys already holds CATEGORY=gp / APP_VER / TARGET_APP_VER, so no
#   SFO surgery is needed. <suffix> distinguishes the output file, since two
#   patches for one title otherwise land on the same name.
#
#   The stage has to be named "<TITLEID>-patch": these generators read the
#   directory name to decide what they are looking at, and given anything else
#   gengp4_patch rewrites the staged param.sfo (CATEGORY, APP_VER) and emits an
#   app volume, which img_create then rejects as "unexpected APP_VER". Named
#   correctly it emits pkg_ps4_patch with storage_type=digital25 and leaves the
#   sfo alone, so no volume or SFO surgery is needed here at all.
# ---------------------------------------------------------------------------
def build_patch_pkg(update, app_pkg, suffix, overlay=""):
    tag = sanitize(CONTENT_ID + suffix)
    parent = os.path.join(WORK_DIR, "fpkgwork_patch_" + tag)
    out = os.path.join(WORK_DIR, "patchpkg_" + tag)
    title = sfo_get(os.path.join(update, "sce_sys", "param.sfo"), "TITLE_ID")
    if not title:
        die(f"could not read TITLE_ID from {update}/sce_sys/param.sfo")

    # the generators read the directory name; anything but "<TITLEID>-patch"
    # makes gengp4_patch rewrite the staged sfo and emit an app volume
    shutil.rmtree(parent, ignore_errors=True)
    os.makedirs(parent)
    stage = os.path.join(parent, title + "-patch")
    stage_from(update, stage, overlay)

    if not os.path.isfile(GENGP4_PATCH):
        die(f"gengp4_patch.exe not found at {GENGP4_PATCH}")
    gen_gp4(stage, GENGP4_PATCH)
    gp4 = stage + ".gp4"
    with open(gp4, "rb") as handle:
        if b"<volume_type>pkg_ps4_patch</volume_type>" not in handle.read():
            die(f"gengp4_patch emitted an app volume for {stage}")

    log(f"gp4_proj_update --app_path {os.path.basename(app_pkg)}")
    if wine_run([ORBIS_PUB_CMD, "gp4_proj_update", "--app_path",
                 winpath(app_pkg), winpath(gp4)]):
        die("gp4_proj_update failed for the patch pkg")

    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    log("building patch pkg (orbis-pub-cmd img_create --skip_digest)")
    img_create(out, ["--oformat", "pkg", "--skip_digest", "--no_progress_bar",
                     winpath(gp4), winpath(out)])
    built = newest_pkg(out)
    if not built:
        die("patch pkg build failed")

    stem = os.path.basename(built)[:-len(".pkg")]
    final = os.path.join(OUT_DIR, stem + suffix + ".pkg")
    # an app and its patch can carry the same version in their names
    if final == app_pkg:
        final = os.path.join(OUT_DIR, stem + suffix + "-patch.pkg")
    shutil.move(built, final)
    shutil.rmtree(parent, ignore_errors=True)
    shutil.rmtree(out, ignore_errors=True)
    return final


# appver_bump <XX.YY> -> the next version
def appver_bump(version):
    major, minor = version.split(".")
    major, minor = int(major, 10), int(minor, 10) + 1
    if minor > 99:
        major, minor = major + 1, 0
    return "%02d.%02d" % (major, minor)


# ---------------------------------------------------------------------------
# layered_tree <dir>
#   A hardlinked view of the image the console mounts: the base with the update
#   over it. Hardlinks are safe because the backport only reads, writing its
#   copies elsewhere.
# ---------------------------------------------------------------------------
def layered_tree(out):
    shutil.rmtree(out, ignore_errors=True)
    copy_tree(DUMP, out, link=True)
    if UPDATE:
        overlay_tree(UPDATE, out, link=True)


# ---------------------------------------------------------------------------
# run_backport <dest_parent> <tree>...
#   Collect every executable into <dest_parent>/<TITLEID>-bp, restamping any
#   whose SDK sits above the target. Returns the -bp tree, or "" when nothing
#   needed lowering; sets RESOLVED_SDK.
#
#   Pass the layered image, not the dumps it was built from. A base and its
#   update each carry an eboot and only one is ever loaded, so resolving against
#   both lets the unused one raise the floor.
# ---------------------------------------------------------------------------
def run_backport(dest, trees):
    global RESOLVED_SDK
    RESOLVED_SDK = ""
    if not BACKPORT:
        log("backport: skipped (--no-backport)")
        return ""
    if not os.path.isfile(BACKPORT_SDK):
        log(f"backport: {BACKPORT_SDK} not found, skipping")
        return ""

    title = sfo_get(os.path.join(DUMP, "sce_sys", "param.sfo"), "TITLE_ID")
    if not title:
        die("could not read TITLE_ID for the backport tree")
    os.makedirs(dest, exist_ok=True)
    # Resolve "auto" once across every tree: a title's base and update share one
    # process, so they have to end up carrying the same stamp.
    target = BACKPORT_TARGET_SDK
    if target == "auto":
        proc = subprocess.run([sys.executable, BACKPORT_SDK, "--resolve", *trees],
                              stdout=subprocess.PIPE)
        if proc.returncode:
            die(f"could not resolve an SDK target for {' '.join(trees)}")
        target = proc.stdout.decode(errors="replace").strip()
        log(f"backport: resolved SDK {target}")
    RESOLVED_SDK = target
    log(f"backport: collecting executables at SDK {target}")
    restamped = False
    for tree in trees:
        argv = [sys.executable, BACKPORT_SDK, "--sdk", target]
        if env("KEEP_VERSION_RECORDS"):
            argv.append("--keep-version-records")
        argv += ["--out", dest, tree]
        rc = subprocess.run(argv, stdout=sys.stderr).returncode
        if rc == 0:
            restamped = True
        elif rc != 3:
            die(f"backport-sdk.py failed on {os.path.basename(tree)} (exit {rc})")

    if not restamped:
        log(f"backport: every stamp is already at or below {target}")
        shutil.rmtree(os.path.join(dest, title + "-bp"), ignore_errors=True)
        return ""
    bp_dir = os.path.join(dest, title + "-bp")
    if not os.path.isdir(bp_dir):
        die(f"backport-sdk.py produced no {title}-bp")
    return bp_dir


# ---------------------------------------------------------------------------
# save_stock_binaries <bp_dir> <stage_dir> <dest_dir>
#   Keep the pre-backport copy of everything the backport collected, for builds
#   that overwrite those files inside the package.
# ---------------------------------------------------------------------------
def save_stock_binaries(bp, stage, dest):
    shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest)
    kept = 0
    for root, _dirs, files in os.walk(bp):
        for name in files:
            if os.path.islink(os.path.join(root, name)):
                continue
            rel = os.path.relpath(os.path.join(root, name), bp)
            if rel == os.path.join("sce_sys", "param.sfo"):
                continue
            source = os.path.join(stage, rel)
            if not os.path.isfile(source):
                continue
            os.makedirs(os.path.dirname(os.path.join(dest, rel)), exist_ok=True)
            shutil.copy2(source, os.path.join(dest, rel))
            kept += 1
    log(f"kept {kept} stock binaries in {os.path.basename(dest)}")


# ---------------------------------------------------------------------------
# build_variant_patch <bp_dir> <app_pkg> <app_ver> [sce_sys_source_tree]
#   A patch carrying only the backported executables, declaring the same APP_VER
#   as the package it sits on so installing it does not change the version the
#   console shows. img_create requires a patch to out-rank the package named by
#   app_path, so it is built one version up and the finished pkg restamped back
#   down.
# ---------------------------------------------------------------------------
def build_variant_patch(bp, app_pkg, app_ver, src_tree=None):
    built_ver = appver_bump(app_ver)
    tag = sanitize(CONTENT_ID)
    parent = os.path.join(WORK_DIR, "fpkgwork_bp_" + tag)
    out = os.path.join(WORK_DIR, "bppkg_" + tag)
    title = sfo_get(os.path.join(DUMP, "sce_sys", "param.sfo"), "TITLE_ID")

    shutil.rmtree(parent, ignore_errors=True)
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(parent)
    os.makedirs(out)
    stage = os.path.join(parent, title + "-patch")
    copy_tree(bp, stage, link=True)
    # A patch layer only has to carry what it changes: anything it leaves out
    # falls through to the app volume underneath. The stage gets the collected
    # executables plus PATCH_SCE_SYS, taken from the layered image they came from.
    src_sys = os.path.join(src_tree or UPDATE or DUMP, "sce_sys")
    stage_sys = os.path.join(stage, "sce_sys")
    for keep in PATCH_SCE_SYS.split():
        source = os.path.join(src_sys, keep)
        target = os.path.join(stage_sys, keep)
        if os.path.isdir(source):
            os.makedirs(target, exist_ok=True)
            overlay_tree(source, target)
        elif os.path.isfile(source):
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(source, target)
    # An executable can live under sce_sys too, so the collected copies go last.
    bp_sys = os.path.join(bp, "sce_sys")
    if not os.path.isdir(bp_sys):
        die(f"backport tree has no sce_sys: {bp}")
    os.makedirs(stage_sys, exist_ok=True)
    overlay_tree(bp_sys, stage_sys)
    shutil.copy2(os.path.join(src_sys, "param.sfo"),
                 os.path.join(stage_sys, "param.sfo"))
    fix_icons(stage_sys)
    unlink_executables(stage)

    gen_gp4(stage, GENGP4_PATCH)
    gp4 = stage + ".gp4"
    with open(gp4, "rb") as handle:
        if b"<volume_type>pkg_ps4_patch</volume_type>" not in handle.read():
            die(f"gengp4_patch emitted an app volume for {stage}")

    log(f"gp4_proj_update --app_path {os.path.basename(app_pkg)}")
    if wine_run([ORBIS_PUB_CMD, "gp4_proj_update", "--app_path",
                 winpath(app_pkg), winpath(gp4)]):
        die("gp4_proj_update failed for the backport patch")

    sfo = os.path.join(stage_sys, "param.sfo")
    log(f"SFO: CATEGORY=gp, TARGET_APP_VER={app_ver}, APP_VER={built_ver}")
    sfo_edit("-s", "str", "CATEGORY", "gp", "-s", "str", "TARGET_APP_VER",
             app_ver, "-s", "str", "APP_VER", built_ver, sfo)

    log("building backport patch (img_create --skip_digest)")
    img_create(out, ["--oformat", "pkg", "--skip_digest", "--no_progress_bar",
                     winpath(gp4), winpath(out)])
    built = newest_pkg(out)
    if not built:
        die("backport patch build failed")

    if not os.path.isfile(PKG_SET_APPVER):
        die(f"pkg-set-appver.py not found at {PKG_SET_APPVER}")
    # A patch inherits SYSTEM_VER from the package --app_path names, so unlike
    # an app volume it does not pick up the lowered stamps from its own
    # executables.
    sysver = ""
    if RESOLVED_SDK:
        sysver = "0x%08x" % (int(RESOLVED_SDK, 0) & 0xFFFFF000)
    log(f"restamping the patch to APP_VER {app_ver}"
        + (f", SYSTEM_VER {sysver}" if sysver else ""))
    argv = [sys.executable, PKG_SET_APPVER, built, app_ver]
    if sysver:
        argv.append(sysver)
    if subprocess.run(argv, stdout=sys.stderr).returncode:
        die(f"could not restamp the backport patch to {app_ver}")

    stem = os.path.basename(built)[:-len(".pkg")]
    final = os.path.join(
        OUT_DIR,
        stem.replace("-A" + built_ver.replace(".", "") + "-",
                     "-A" + app_ver.replace(".", "") + "-", 1) + "-bp.pkg")
    shutil.move(built, final)
    if env("KEEP_STAGE"):
        log(f"kept the patch stage at {parent}")
    else:
        shutil.rmtree(parent, ignore_errors=True)
        shutil.rmtree(out, ignore_errors=True)
    return final


# ---------------------------------------------------------------------------
# build_one_dlc <ac_content_dir>
#   Build a single pkg_ps4_ac_data (add-on) pkg from one "*-ac" DLC dump dir
#   (content + a populated sce_sys). Emits the pkg into OUT_DIR.
#
#   gengp4_app can't scan an ac tree (it crashes on CATEGORY=ac and, worse,
#   rewrites the tree's param.sfo in place), so we:
#     1. hardlink the DLC tree into a scratch STAGE (original stays untouched),
#     2. save the real ac param.sfo, drop a throwaway "app" param.sfo in,
#     3. gengp4_app the stage -> gives us the <files>/<rootdir> list,
#     4. restore the real ac param.sfo in the stage,
#     5. gp4_proj_create an ac_data project (real content_id / zero ent. key),
#        splice in the scanned file list, drop any stray backup-file entries,
#     6. img_create from the stage.
# ---------------------------------------------------------------------------
def build_one_dlc(ac):
    ac_sfo = os.path.join(ac, "sce_sys", "param.sfo")
    if not os.path.isfile(ac_sfo):
        die(f"dlc: {ac} has no sce_sys/param.sfo (re-dump with a recent ftpdump)")
    cid = sfo_get(ac_sfo, "CONTENT_ID")
    cat = sfo_get(ac_sfo, "CATEGORY")
    if not cid:
        die(f"dlc: could not read CONTENT_ID from {ac}")
    if cat != "ac":
        log(f"dlc: warning: {ac} CATEGORY is '{cat}' (expected 'ac')")
    log(f"dlc: building add-on pkg for {cid}")

    tag = sanitize(cid)
    stage = os.path.join(WORK_DIR, "fpkgwork_dlc_" + tag)
    gp4 = os.path.join(WORK_DIR, "dlc_" + tag + ".gp4")
    shutil.rmtree(stage, ignore_errors=True)
    if os.path.lexists(gp4):
        os.remove(gp4)

    # 1. hardlinked stage of the DLC tree (never touch the original dump).
    copy_tree(ac, stage, link=True)
    shutil.rmtree(os.path.join(stage, "sce_sys"), ignore_errors=True)
    copy_tree(os.path.join(ac, "sce_sys"), os.path.join(stage, "sce_sys"))
    key_record = os.path.join(stage, "entitlement_key.dat")
    if os.path.lexists(key_record):
        os.remove(key_record)       # pfsdump's record, not add-on content
    fix_icons(os.path.join(stage, "sce_sys"))

    # 2. make the staged sfo look like an app so gengp4_app can scan it.
    #    CATEGORY alone is not enough; it also needs the app keys an ac sfo lacks.
    real_sfo = os.path.join(stage, "sce_sys", "param.sfo")
    shutil.copy2(real_sfo, real_sfo + ".real")
    rc = subprocess.run([SFO_TOOL, "-s", "str", "CATEGORY", "gd",
                         "-s", "int", "APP_TYPE", "1",
                         "-s", "str", "APP_VER", "01.00",
                         "-s", "int", "SYSTEM_VER", "0x03110000", real_sfo],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL).returncode
    if rc:
        die(f"dlc: could not build scan decoy sfo for {cid}")

    # 3. scan -> file list (gengp4_app writes <stage>.gp4 and edits the decoy)
    scan = stage + ".gp4"
    if os.path.lexists(scan):
        os.remove(scan)
    wine_run([GENGP4_APP, winpath(stage)], cwd=os.path.dirname(stage))
    if not os.path.isfile(scan):
        die(f"dlc: gengp4 scan failed for {cid}")

    # 4. restore the real ac param.sfo in the stage; remove the decoy backup
    os.replace(real_sfo + ".real", real_sfo)

    # 5. ac_data project + splice the scanned file list
    ent_key = ent_key_of(ac)
    log(f"dlc: entitlement key {ent_key}")
    rc = wine_run([ORBIS_PUB_CMD, "gp4_proj_create",
                   "--volume_type", "pkg_ps4_ac_data", "--content_id", cid,
                   "--passcode", FAKE_PASSCODE, "--entitlement_key", ent_key,
                   winpath(gp4)],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if rc:
        die(f"dlc: gp4_proj_create failed for {cid}")

    # Splice the scanned file list into the ac project: gp4_proj_create emits
    # an empty '<files img_no="0"/>' + '<rootdir/>' pair; replace them with the
    # scan's populated <files>..</rootdir>. Drop the transient decoy-backup
    # entry (param.sfo.real, which existed in sce_sys during the scan).
    with open(scan, encoding="utf-8", errors="replace") as handle:
        scan_lines = handle.read().splitlines(keepends=True)
    frag = []
    capturing = False
    for line in scan_lines:
        if not capturing:
            if "<files" in line:
                capturing = True
            else:
                continue
        frag.append(line)
        if "</rootdir>" in line:
            capturing = False
    frag = [line for line in frag if "param.sfo.real" not in line]
    if not any("<files" in line for line in frag):
        die(f"dlc: scan produced no file list for {cid}")
    with open(gp4, encoding="utf-8", errors="replace") as handle:
        gp4_lines = handle.read().splitlines(keepends=True)
    spliced = []
    for line in gp4_lines:
        if '<files img_no="0"/>' in line:
            spliced.extend(frag)
            continue
        if "<rootdir/>" in line:
            continue
        spliced.append(line)
    with open(gp4, "w", encoding="utf-8") as handle:
        handle.writelines(spliced)
    os.remove(scan)

    # 6. build
    log(f"dlc: img_create ({cid})")
    img_create(OUT_DIR, ["--oformat", "pkg", "--no_progress_bar",
                         winpath(gp4), winpath(OUT_DIR)])

    pkg = newest_pkg(OUT_DIR, cid + "-*.pkg")
    if not pkg:
        die(f"dlc: no pkg produced for {cid}")
    shutil.rmtree(stage, ignore_errors=True)
    os.remove(gp4)
    log(f"dlc: done: {pkg}")
    print(pkg, flush=True)


# ---------------------------------------------------------------------------
# build_dlc_pkgs
#   Build an add-on pkg for every "*-ac" and "*-al" dir across all DLC_DIRS.
#   No-op if none.
# ---------------------------------------------------------------------------
def build_dlc_pkgs():
    built_any = False
    for item in DLC_ITEMS:
        build_one_dlc(item)
        built_any = True
    for dlc_dir in DLC_DIRS:
        for name in sorted(os.listdir(dlc_dir)):
            sub = os.path.join(dlc_dir, name)
            sub_sfo = os.path.join(sub, "sce_sys", "param.sfo")
            if not os.path.isdir(sub) or not os.path.isfile(sub_sfo):
                continue
            if sfo_get(sub_sfo, "CATEGORY") != "ac":
                continue
            build_one_dlc(sub)
            built_any = True
    if not built_any and DLC_DIRS:
        log("dlc: no add-on (CATEGORY=ac) dirs found under: " + " ".join(DLC_DIRS))


# ---------------------------------------------------------------------------
# PS4 pipeline main flow
# ---------------------------------------------------------------------------
# A dir with no param.sfo of its own but add-on children is a container.
def classify_dir(directory):
    sfo = os.path.join(directory, "sce_sys", "param.sfo")
    if os.path.isfile(sfo):
        category = sfo_get(sfo, "CATEGORY")
        if category == "gd":
            return "app"
        if category.startswith("gp"):
            return "patch"
        if category == "ac":
            return "addon"
        # Only applications carry an eboot.
        return "app" if os.path.isfile(os.path.join(directory, "eboot.bin")) \
            else "unknown"
    for name in sorted(os.listdir(directory)):
        sub = os.path.join(directory, name)
        sub_sfo = os.path.join(sub, "sce_sys", "param.sfo")
        if os.path.isdir(sub) and os.path.isfile(sub_sfo) \
                and sfo_get(sub_sfo, "CATEGORY") == "ac":
            return "container"
    return "unknown"


def cmd_ps4(args):
    global WORK_DIR, OUT_DIR, DUMP, UPDATE, CONTENT_ID, TITLE_ID, BASE_APPVER
    global OBSERVED_SDK, IS_PS2, PS2_TID, KEYSTONE_MODE, MODE, BACKPORT
    global BACKPORT_TARGET_SDK, BASE_PKG_IN, DLC_MODE, DLC_DIRS, DLC_ITEMS
    global IMG_TMP_DIR, EBOOT_AUTH, EBOOT_PAID, COMPILER_AUTH, COMPILER_PAID
    global PRX_AUTH, PRX_PAID

    KEYSTONE_MODE = args.keystone
    if KEYSTONE_MODE not in ("kscreate", "retail"):
        die("--keystone must be kscreate or retail")
    if not shutil.which("wine"):
        die("wine not found")
    OUT_DIR = args.out
    try:
        os.makedirs(OUT_DIR, exist_ok=True)
    except OSError as err:
        die(f"cannot create output directory {OUT_DIR}: {err}")
    OUT_DIR = os.path.realpath(OUT_DIR)
    WORK_DIR = os.getcwd()
    IMG_TMP_DIR = args.tmp_dir
    MODE = args.mode
    BACKPORT = 1 if args.backport else 0
    BACKPORT_TARGET_SDK = args.sdk
    BASE_PKG_IN = args.base_pkg
    CONTENT_ID = args.content_id
    PS2_TID = args.ps2_tid
    UPDATE = strip_one_slash(args.update) if args.update else args.update
    DLC_MODE = args.dlc_mode
    DLC_DIRS = list(args.dlc_dirs)
    DLC_ITEMS = []

    # --- classify the given dirs -------------------------------------------
    for given in args.dirs:
        given = strip_one_slash(given)
        if not os.path.isdir(given):
            die(f"not a directory: {given}")
        given = os.path.realpath(given)
        kind = classify_dir(given)
        if kind == "app":
            if DUMP:
                die(f"more than one base app dir given: {DUMP} and {given}")
            DUMP = given
        elif kind == "patch":
            if UPDATE == "none":
                log(f"ignoring update dir (--no-update): {given}")
            elif UPDATE:
                die(f"more than one update dir given: {UPDATE} and {given}")
            else:
                UPDATE = given
        elif kind == "addon":
            DLC_ITEMS.append(given)
        elif kind == "container":
            DLC_DIRS.append(given)
            DLC_MODE = "explicit"
        else:
            die(f"cannot tell what '{given}' is: no sce_sys/param.sfo with "
                "CATEGORY gd/gp*/ac, and no add-on subdirs")

    # Add-ons carry their own identity, so a dump is only needed for app builds.
    build_app = True
    if not DUMP:
        if DLC_ITEMS or DLC_DIRS:
            build_app = False
        else:
            die("nothing to build: pass a base app dump, and/or an add-on or "
                "DLC dir")
    else:
        if not os.path.isfile(os.path.join(DUMP, "sce_sys", "param.sfo")):
            die("dump missing sce_sys/param.sfo")
        if not os.path.isfile(os.path.join(DUMP, "eboot.bin")):
            die("dump missing eboot.bin")

    # --- resolve the update dir --------------------------------------------
    if UPDATE == "none":
        UPDATE = ""                             # explicitly base-only
    elif UPDATE:
        if not os.path.isdir(UPDATE):
            die(f"update dir not found: {UPDATE}")
        UPDATE = os.path.realpath(UPDATE)
    elif DUMP.endswith("-app"):
        # auto-discover: a sibling dir named like the base but -app -> -patch
        candidate = DUMP[:-len("-app")] + "-patch"
        if os.path.isdir(candidate) \
                and os.path.isfile(os.path.join(candidate, "sce_sys", "param.sfo")):
            UPDATE = candidate
            log(f"auto-detected update: {UPDATE}  (use --no-update to skip)")

    # --- resolve the DLC dir(s) --------------------------------------------
    if DLC_MODE == "none":
        DLC_DIRS = []                           # explicitly no DLC
    elif DLC_MODE == "explicit":
        for directory in DLC_DIRS:
            if not os.path.isdir(directory):
                die(f"dlc dir not found: {directory}")
    elif DUMP.endswith("-app"):
        # auto-discover: a sibling dir named like the base but -app -> -dlc
        candidate = DUMP[:-len("-app")] + "-dlc"
        if os.path.isdir(candidate):
            DLC_DIRS = [candidate]
            log(f"auto-detected dlc: {candidate}  (use --no-dlc to skip)")
    DLC_DIRS = [os.path.realpath(directory) for directory in DLC_DIRS]

    if build_app:
        if not CONTENT_ID:
            CONTENT_ID = sfo_get(os.path.join(DUMP, "sce_sys", "param.sfo"),
                                 "CONTENT_ID")
        if not CONTENT_ID:
            die("could not determine CONTENT_ID")
        TITLE_ID = sfo_get(os.path.join(DUMP, "sce_sys", "param.sfo"), "TITLE_ID")
        BASE_APPVER = sfo_get(os.path.join(DUMP, "sce_sys", "param.sfo"),
                              "APP_VER")
        # What the executables ask for, for SYSTEM_VER on packages we do not
        # restamp.
        observed = [DUMP] + ([UPDATE] if UPDATE else [])
        proc = subprocess.run([sys.executable, BACKPORT_SDK, "--observed",
                               *observed],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        OBSERVED_SDK = proc.stdout.decode(errors="replace").strip()
        if OBSERVED_SDK:
            log(f"executables were built against {OBSERVED_SDK}")

        # --- detect PS2 classic --------------------------------------------
        # Signal: the PS2 emulator compiler self is present (backed by EMU_VER).
        IS_PS2 = os.path.isfile(os.path.join(DUMP, "ps2-emu-compiler.self"))
        if sfo_get(os.path.join(DUMP, "sce_sys", "param.sfo"), "EMU_VER"):
            IS_PS2 = True

        if IS_PS2 and not PS2_TID:
            # CONTENT_ID tail segment holds the disc serial, e.g.
            #   UP9000-CUSA01724_00-SCUS971050000001 -> SCUS 97105 -> 97105
            serial = CONTENT_ID.rsplit("-", 1)[-1]
            match = re.match(r"[A-Z]{4}([0-9]{5})", serial)
            PS2_TID = match.group(1) if match else ""
            if len(PS2_TID) != 5:
                die("could not derive PS2 title id from CONTENT_ID "
                    f"({CONTENT_ID}); pass --ps2-tid")

        log(f"content id : {CONTENT_ID}")
        log("type       : " + (f"PS2 classic (ps2-tid={PS2_TID})" if IS_PS2
                               else "normal PS4"))
        log(f"update     : {UPDATE or '<none>'}")
        log(f"mode       : {MODE}" + ("" if BACKPORT else " (no backport)"))
        log(f"keystone   : {KEYSTONE_MODE}")
    else:
        log("add-ons only (no base app dump given)")
    dlc_all = DLC_DIRS + DLC_ITEMS
    log("dlc        : " + (" ".join(dlc_all) if dlc_all else "<none>"))

    # --- PS2 auth (used to pre-sign the emu modules) ------------------------
    # The auth-info blob and its paid are derived from the PS2 title id:
    #   deci = low 2 bytes of the (5-digit) title id, little-endian, as hex
    #          (e.g. 97105 = 0x17B51 -> "517B"). This mirrors free-ps2-pub-gen's
    #          GetDecimalBytes; for a value that fits in 32 bits the .NET decimal
    #          layout is just the integer little-endian, so this is exact.
    #   auth = deci + template[4:]           (patch title bytes into the front)
    #   paid = endian-swap of auth's first 8 bytes (16 hex chars)
    if IS_PS2:
        try:
            tid = int(PS2_TID)
        except ValueError:
            die(f"--ps2-tid must be the 5-digit PS2 serial, got: {PS2_TID}")
        deci = "%02X%02X" % (tid & 0xFF, (tid >> 8) & 0xFF)

        def mk_auth(template):
            return deci + template[4:]

        def mk_paid(auth):
            head = auth[:16]
            return "0x" + "".join(head[i:i + 2] for i in range(14, -1, -2))

        EBOOT_AUTH = mk_auth(EBOOT_AUTH_TMPL)
        EBOOT_PAID = mk_paid(EBOOT_AUTH)
        COMPILER_AUTH = mk_auth(COMPILER_AUTH_TMPL)
        COMPILER_PAID = mk_paid(COMPILER_AUTH)
        PRX_AUTH = mk_auth(PRX_AUTH_TMPL)
        PRX_PAID = mk_paid(PRX_AUTH)

    # =======================================================================
    # ADD-ONS ONLY (no base app dump given)
    # =======================================================================
    if not build_app:
        build_dlc_pkgs()
        return

    # =======================================================================
    # BACKPORT ONLY (--base-pkg): a patch for a base package that already
    # exists. The dumps supply the executables; the pkg supplies the identity
    # the patch has to marry, so its CONTENT_ID and APP_VER are read from it
    # rather than guessed.
    # =======================================================================
    if BASE_PKG_IN:
        if not os.path.isfile(BASE_PKG_IN):
            die(f"--base-pkg: no such file: {BASE_PKG_IN}")
        BASE_PKG_IN = os.path.realpath(BASE_PKG_IN)
        pkg_cid = sfo_pkg(BASE_PKG_IN, "CONTENT_ID")
        pkg_appver = sfo_pkg(BASE_PKG_IN, "APP_VER")
        if not pkg_cid:
            die("--base-pkg: could not read CONTENT_ID from "
                + os.path.basename(BASE_PKG_IN))
        if not pkg_appver:
            die("--base-pkg: could not read APP_VER from "
                + os.path.basename(BASE_PKG_IN))
        if pkg_cid != CONTENT_ID:
            die(f"--base-pkg is {pkg_cid} but the dumps are {CONTENT_ID}; "
                "a patch only marries its own base")
        log(f"base pkg   : {os.path.basename(BASE_PKG_IN)}  "
            f"({pkg_cid}, APP_VER={pkg_appver})")
        if not BACKPORT:
            die("--base-pkg with --no-backport would build nothing")

        layered = os.path.join(WORK_DIR, "fpkglayer_" + sanitize(CONTENT_ID))
        layered_tree(layered)
        bp_dir = run_backport(WORK_DIR, [layered])
        if not bp_dir:
            die(f"no executable needed restamping for {BACKPORT_TARGET_SDK}")
        bp_patch = build_variant_patch(bp_dir, BASE_PKG_IN, pkg_appver, layered)
        shutil.rmtree(layered, ignore_errors=True)
        shutil.rmtree(bp_dir, ignore_errors=True)
        log(f"backport patch: {bp_patch}")
        show_files(bp_patch)
        print(bp_patch, flush=True)
        return

    # =======================================================================
    # BASE-ONLY build: one app pkg, with a backport either as its own patch
    # or, under --remaster, baked in.
    # =======================================================================
    if not UPDATE:
        tag = sanitize(CONTENT_ID)
        stage = os.path.join(WORK_DIR, "fpkgwork_" + tag)
        stage_tree(stage, False)

        bp_dir = run_backport(WORK_DIR, [stage])
        if bp_dir and MODE == "remaster":
            save_stock_binaries(bp_dir, stage,
                                os.path.join(OUT_DIR, TITLE_ID + "-stock"))
            log("baking the backported executables into the app pkg")
            overlay_tree(bp_dir, stage)
            shutil.rmtree(bp_dir, ignore_errors=True)
            bp_dir = ""

        gen_gp4(stage)
        gp4 = stage + ".gp4"
        # gengp4_app normalises an app volume to APP_VER 01.00 and moves the
        # version it found into VERSION, which loses the patch level of an
        # already-merged dump. BASE_APPVER predates gengp4, so it still holds
        # what the dump claimed.
        sfo = os.path.join(stage, "sce_sys", "param.sfo")
        if BASE_APPVER and BASE_APPVER != "01.00":
            log(f"SFO: dump already merged, restoring APP_VER={BASE_APPVER}, "
                "VERSION=01.00")
            sfo_edit("-e", "APP_VER", BASE_APPVER, sfo)
            sfo_edit("-e", "VERSION", "01.00", sfo)
        log("building pkg (orbis-pub-cmd img_create)")
        app_out = os.path.join(WORK_DIR, "apppkg_" + tag)
        shutil.rmtree(app_out, ignore_errors=True)
        os.makedirs(app_out)
        img_create(app_out, ["--oformat", "pkg", "--no_progress_bar",
                             winpath(gp4), winpath(app_out)])
        pkg = newest_pkg(app_out)
        if not pkg:
            die("no pkg produced")
        try:
            shutil.move(pkg, os.path.join(OUT_DIR, os.path.basename(pkg)))
        except OSError:
            die(f"could not move {pkg} to {OUT_DIR}")
        pkg = os.path.join(OUT_DIR, os.path.basename(pkg))
        try:
            os.rmdir(app_out)
        except OSError:
            pass
        if os.path.lexists(gp4):
            os.remove(gp4)
        log(f"app pkg: {pkg}")

        bp_patch = ""
        if bp_dir:
            bp_patch = build_variant_patch(bp_dir, pkg, BASE_APPVER, stage)
            shutil.rmtree(bp_dir, ignore_errors=True)
            log(f"backport patch: {bp_patch}")
        shutil.rmtree(stage, ignore_errors=True)

        show_files(pkg, bp_patch)
        print(pkg, flush=True)
        if bp_patch:
            print(bp_patch, flush=True)
        build_dlc_pkgs()                # separate add-on pkg(s), if any DLC
        return

    # =======================================================================
    # SEPARATE (--separate): app pkg and update pkg as their own packages, the
    # way retail ships them, then a backported patch if the dumps ask for a
    # newer SDK than the target firmware provides.
    #
    # That backport patch is the whole update tree with the restamped
    # executables overlaid: the console replaces the entire patch layer, so a
    # handful of files on their own would drop the rest of the update.
    # =======================================================================
    if MODE == "separate":
        log("separate build: app + update as individual pkgs")

        tag = sanitize(CONTENT_ID)
        stage = os.path.join(WORK_DIR, "fpkgwork_" + tag)
        stage_tree(stage, False)
        gen_gp4(stage)
        gp4 = stage + ".gp4"
        log("building app pkg (orbis-pub-cmd img_create)")
        img_create(OUT_DIR, ["--oformat", "pkg", "--no_progress_bar",
                             winpath(gp4), winpath(OUT_DIR)])
        app_pkg = newest_pkg(OUT_DIR)
        if not app_pkg:
            die("app pkg build failed")
        shutil.rmtree(stage, ignore_errors=True)
        if os.path.lexists(gp4):
            os.remove(gp4)
        log(f"app pkg  : {app_pkg}")

        patch_pkg = build_patch_pkg(UPDATE, app_pkg, "")
        log(f"patch pkg: {patch_pkg}")

        # 3. backport pass over the layered image, the way the console mounts it
        layered = os.path.join(WORK_DIR, "fpkglayer_" + tag)
        layered_tree(layered)
        bp_dir = run_backport(WORK_DIR, [layered])
        shutil.rmtree(layered, ignore_errors=True)

        # 4. second patch built from the restamped binaries
        bp_patch = ""
        if bp_dir:
            log(f"backport: building a second patch from {os.path.basename(bp_dir)}")
            bp_patch = build_patch_pkg(UPDATE, app_pkg, "-bp", bp_dir)
            shutil.rmtree(bp_dir, ignore_errors=True)
            log(f"backported patch: {bp_patch}")

        show_files(app_pkg, patch_pkg, bp_patch)
        print(app_pkg, patch_pkg, sep="\n", flush=True)
        if bp_patch:
            print(bp_patch, flush=True)

        build_dlc_pkgs()
        return

    update_appver = sfo_get(os.path.join(UPDATE, "sce_sys", "param.sfo"),
                            "APP_VER")
    base_cat = sfo_get(os.path.join(DUMP, "sce_sys", "param.sfo"), "CATEGORY")
    if not update_appver:
        die("could not read update APP_VER")
    tag = sanitize(CONTENT_ID)
    stage = os.path.join(WORK_DIR, "fpkgwork_" + tag)

    # =======================================================================
    # REMASTER (--remaster): base + update merged into one pkg_ps4_remaster. A
    # remaster supersedes the whole application and cannot be patched
    # afterwards, so a backport has to be baked in.
    #
    # The throwaway base pkg exists only to be named by --app_path, which is
    # what lets the tool accept an elevated APP_VER on a remaster volume.
    # =======================================================================
    if MODE == "remaster":
        log(f"merge (remaster): base_cat={base_cat}  app_ver={update_appver}")

        base_out = os.path.join(WORK_DIR, ".basepkg_" + tag)
        shutil.rmtree(base_out, ignore_errors=True)
        os.makedirs(base_out)
        base_stage = os.path.join(WORK_DIR, "fpkgwork_base_" + tag)
        log("building base pkg (for --app_path reference)")
        stage_tree(base_stage, False)           # base only, no overlay
        gen_gp4(base_stage)
        base_gp4 = base_stage + ".gp4"
        img_create(base_out, ["--oformat", "pkg", "--no_progress_bar",
                              winpath(base_gp4), winpath(base_out)])
        base_pkg = newest_pkg(base_out)
        if not base_pkg:
            die("base pkg build failed")
        shutil.rmtree(base_stage, ignore_errors=True)
        if os.path.lexists(base_gp4):
            os.remove(base_gp4)

        stage_tree(stage, True)

        bp_dir = run_backport(WORK_DIR, [stage])
        if bp_dir:
            save_stock_binaries(bp_dir, stage,
                                os.path.join(OUT_DIR, TITLE_ID + "-stock"))
            log("baking the backported executables into the remaster")
            overlay_tree(bp_dir, stage)
            shutil.rmtree(bp_dir, ignore_errors=True)

        gen_gp4(stage)
        gp4 = stage + ".gp4"
        with open(gp4, "rb") as handle:
            data = handle.read()
        data = data.replace(b"<volume_type>pkg_ps4_app</volume_type>",
                            b"<volume_type>pkg_ps4_remaster</volume_type>")
        with open(gp4, "wb") as handle:
            handle.write(data)

        log("gp4_proj_update --app_path <base pkg>")
        if wine_run([ORBIS_PUB_CMD, "gp4_proj_update", "--app_path",
                     winpath(base_pkg), winpath(gp4)]):
            die("gp4_proj_update failed")

        # gengp4 and gp4_proj_update both rewrite param.sfo, so identity is
        # set after.
        sfo = os.path.join(stage, "sce_sys", "param.sfo")
        log(f"SFO: CATEGORY={base_cat}, REMASTER_TYPE=1, "
            f"APP_VER={update_appver}, VERSION=01.00")
        sfo_edit("-e", "CATEGORY", base_cat, sfo)
        sfo_edit("-d", "TARGET_APP_VER", sfo)   # patch-only key
        sfo_edit("-a", "int", "REMASTER_TYPE", "0x00000001", sfo)
        sfo_edit("-e", "APP_VER", update_appver, sfo)
        sfo_edit("-e", "VERSION", "01.00", sfo)

        log("building remaster pkg (orbis-pub-cmd img_create --skip_digest)")
        img_create(OUT_DIR, ["--oformat", "pkg", "--skip_digest",
                             "--no_progress_bar", winpath(gp4), winpath(OUT_DIR)])

        pkg = newest_pkg(OUT_DIR)
        if not pkg:
            die("no pkg produced")

        shutil.rmtree(stage, ignore_errors=True)
        if os.path.lexists(gp4):
            os.remove(gp4)
        shutil.rmtree(base_out, ignore_errors=True)
        log(f"done: {pkg}")
        show_files(pkg)
        print(pkg, flush=True)

        build_dlc_pkgs()                # separate add-on pkg(s), if any DLC
        return

    # =======================================================================
    # APP-MERGE (default): base + update merged into a single pkg_ps4_app
    # carrying the update's APP_VER. The patch layer stays free, so a backport
    # ships as its own patch declaring that same APP_VER.
    # =======================================================================
    log(f"merge (app): base_cat={base_cat}  app_ver={update_appver}")

    stage_tree(stage, True)

    # Before gen_gp4 and img_create: gengp4 rewrites param.sfo and img_create
    # fake-signs the executables where they lie, and the backport wants the
    # plain ELFs the console would load.
    bp_dir = run_backport(WORK_DIR, [stage])

    gen_gp4(stage)
    gp4 = stage + ".gp4"

    sfo = os.path.join(stage, "sce_sys", "param.sfo")
    log(f"SFO: CATEGORY={base_cat}, APP_VER={update_appver}, VERSION=01.00")
    sfo_edit("-e", "CATEGORY", base_cat, sfo)
    sfo_edit("-d", "TARGET_APP_VER", sfo)       # patch-only key
    sfo_edit("-e", "APP_VER", update_appver, sfo)
    sfo_edit("-e", "VERSION", "01.00", sfo)

    log("building merged app pkg (img_create --skip_digest)")
    # Its own empty directory, so the result is unambiguous when OUT_DIR
    # already holds packages from earlier runs.
    app_out = os.path.join(WORK_DIR, "apppkg_" + tag)
    shutil.rmtree(app_out, ignore_errors=True)
    os.makedirs(app_out)
    img_create(app_out, ["--oformat", "pkg", "--skip_digest",
                         "--no_progress_bar", winpath(gp4), winpath(app_out)])
    pkg = newest_pkg(app_out)
    if not pkg:
        die("no pkg produced")
    try:
        shutil.move(pkg, os.path.join(OUT_DIR, os.path.basename(pkg)))
    except OSError:
        die(f"could not move {pkg} to {OUT_DIR}")
    pkg = os.path.join(OUT_DIR, os.path.basename(pkg))
    try:
        os.rmdir(app_out)
    except OSError:
        pass
    if os.path.lexists(gp4):
        os.remove(gp4)
    log(f"merged app pkg: {pkg}")

    bp_patch = ""
    if bp_dir:
        bp_patch = build_variant_patch(bp_dir, pkg, update_appver, stage)
        shutil.rmtree(bp_dir, ignore_errors=True)
        log(f"backport patch: {bp_patch}")
    shutil.rmtree(stage, ignore_errors=True)

    show_files(pkg, bp_patch)
    print(pkg, flush=True)
    if bp_patch:
        print(bp_patch, flush=True)

    build_dlc_pkgs()                    # separate add-on pkg(s), if any DLC


# ---------------------------------------------------------------------------
# PS5 pipeline
# ---------------------------------------------------------------------------
TOOLKIT = os.path.join(SELF_DIR, "drakmor")
AUTO_SIZE_PROFILE = "sdk279"
# Games read it back through sceNpEntitlementAccessGetEntitlementKey, and some
# (FF7R) decide which add-on to mount from it. pfsdump saves the real one as
# entitlement_key.dat in the add-on dump; zeroes are the last resort.
ENTITLEMENT_KEY_FILE = "entitlement_key.dat"


def free_space_line(directory):
    try:
        out = subprocess.run(["df", "-h", "--output=avail,target", directory],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL).stdout
        fields = out.decode(errors="replace").splitlines()[-1].split()
        return f"  free space: {fields[0]} on {fields[1]} ({directory})"
    except (OSError, IndexError):
        usage = shutil.disk_usage(directory)
        return f"  free space: {iec(usage.free)} on {directory} ({directory})"


def cmd_ps5(args):
    if not re.fullmatch(r"[0-9A-Fa-f]{32}", args.passcode):
        die("The passcode must be 32 hex digits")

    source = args.source_folder
    if not os.path.isdir(source):
        die(f"SourceFolder does not exist or is not a directory: {source}")
    source = os.path.realpath(source)

    volume = args.volume
    if volume == "auto":
        volume = "app" if os.path.isfile(os.path.join(source, "eboot.bin")) \
            else "ac"
    elif volume not in ("app", "ac"):
        die("--volume must be auto, app or ac")
    log(f"Volume: {volume}")

    if not os.path.isfile(os.path.join(source, "sce_sys", "param.json")):
        die(f"Not a PS5 tree, no sce_sys/param.json: {source}")

    if args.sc_pkg:
        log(f"Restoring sce_sys metadata from SC package: {args.sc_pkg}")
        rc = subprocess.run([args.python, SC_OVERLAY, args.sc_pkg,
                             source], stdout=sys.stderr).returncode
        if rc:
            die(f"sc-overlay.py failed (exit {rc})")

    # Add-ons carry no keystone; the custom-keystone requirement is the app's.
    entitlement_key = ""
    if volume == "app":
        keystone = os.path.join(source, "sce_sys", "keystone")
        if not os.path.isfile(keystone):
            die(f"This custom-keystone toolchain requires: {keystone}")
        if os.path.getsize(keystone) != 96:
            die(f"The source keystone must be exactly 96 bytes: {keystone}")
        if args.entitlement_key:
            die("--entitlement-key applies to add-on builds only")
        if args.chunk_count and not (re.fullmatch(r"[0-9]+", args.chunk_count)
                                     and 1 <= int(args.chunk_count) <= 800):
            die("--chunk-count must be 1 through 800")
    elif args.reference_package:
        die("--reference-package applies to application builds only")
    elif args.chunk_count or args.playgo_languages:
        die("--chunk-count and --playgo-languages apply to application "
            "builds only")
    else:
        key_file = os.path.join(source, ENTITLEMENT_KEY_FILE)
        if args.entitlement_key:
            entitlement_key = args.entitlement_key
            key_source = "--entitlement-key"
        elif os.path.isfile(key_file):
            # 16 raw bytes from pfsdump, or 32 hex digits written by hand.
            with open(key_file, "rb") as handle:
                data = handle.read()
            if len(data) == 16:
                entitlement_key = data.hex()
            else:
                entitlement_key = re.sub(r"\s+", "", data.decode(errors="replace"))
            key_source = key_file
        else:
            entitlement_key = DLC_ENT_KEY
            key_source = f"default; no {ENTITLEMENT_KEY_FILE} in the source"
        if not re.fullmatch(r"[0-9A-Fa-f]{32}", entitlement_key):
            die(f"The entitlement key must be 32 hex digits ({key_source})")
        entitlement_key = entitlement_key.upper()
        log(f"Entitlement key: {entitlement_key} ({key_source})")

    if not args.output_package.lower().endswith(".pkg"):
        die("OutputPackage must be a .pkg path.")

    final = os.path.realpath(args.output_package)

    reference = ""
    if args.reference_package:
        if not os.path.isfile(args.reference_package):
            die("ReferencePackage does not exist or is not a file: "
                + args.reference_package)
        if not args.reference_package.lower().endswith(".pkg"):
            die("ReferencePackage must be a .pkg path.")
        reference = os.path.realpath(args.reference_package)
        if reference == final:
            die("ReferencePackage and OutputPackage must be different files.")

    toolkit_prefix = os.path.realpath(TOOLKIT) + os.sep
    if (final + os.sep).startswith(toolkit_prefix):
        die("Build output must be outside the tools-only directory.")

    output_directory = os.path.dirname(final)
    os.makedirs(output_directory, exist_ok=True)

    temporary_root = ""
    temporary_root_created = False
    temporary_build_directory = ""

    if args.temp_dir:
        expanded = os.path.expandvars(os.path.expanduser(args.temp_dir))
        temporary_root = os.path.realpath(expanded)
        if os.path.exists(temporary_root):
            if not os.path.isdir(temporary_root):
                die(f"TemporaryDirectory is not a directory: {temporary_root}")
        else:
            os.makedirs(temporary_root)
            temporary_root_created = True
        temporary_build_directory = os.path.join(
            temporary_root, "libprospero-pkg-" + uuid.uuid4().hex)

    stem = os.path.basename(final)[:-len(".pkg")]
    gp5 = os.path.join(output_directory, stem + ".gp5")
    scenario = os.path.join(output_directory, stem + ".playgo-scenario.json")
    assets = os.path.join(output_directory, "gp5-assets", stem)
    partial = os.path.join(output_directory, stem + ".partial.pkg")
    partial_remastered = partial + ".remastered.pkg"
    final_remastered = final + ".remastered.pkg"
    metric = partial + ".naps_metric.json"
    final_metric = final + ".naps_metric.json"
    log_directory = os.path.join(output_directory, stem + "-build-logs")

    if final == partial:
        die("OutputPackage name conflicts with the temporary package name.")

    if reference:
        for generated in (gp5, scenario, partial, partial_remastered, metric,
                          final, final_remastered, final_metric):
            if reference == os.path.realpath(generated):
                die(f"ReferencePackage conflicts with a generated output: "
                    f"{generated}")

        assets_path = os.path.realpath(assets)
        if reference == assets_path \
                or (reference + os.sep).startswith(assets_path + os.sep):
            die("ReferencePackage must be outside the generated GP5 assets "
                "directory.")

    outputs = [gp5, scenario, partial, metric, final, final_metric]
    if reference:
        outputs += [partial_remastered, final_remastered]

    for path in outputs:
        if os.path.lexists(path):
            if not args.force:
                die(f"Output already exists: {path} (use --force to replace it)")
            os.remove(path)

    if os.path.isdir(assets):
        if not args.force:
            die(f"Generated GP5 assets already exist: {assets} "
                "(use --force to replace them)")
        shutil.rmtree(assets)

    os.makedirs(log_directory, exist_ok=True)

    if temporary_build_directory:
        os.makedirs(temporary_build_directory, exist_ok=True)
        os.environ["TEMP"] = temporary_build_directory
        os.environ["TMP"] = temporary_build_directory
        log(f"Temporary build directory: {temporary_build_directory}")

    log(f"[1/2] Creating GP5: {gp5}")
    gp5_args = [
        os.path.join(TOOLKIT, "scripts", "create-gp5-from-folder.py"),
        source,
        gp5,
        "--passcode", args.passcode,
        "--absolute-paths",
        "--volume", volume,
    ]

    # Keystone, chunk layout and size profile are application-only.
    if volume == "ac":
        gp5_args += ["--entitlement-key", entitlement_key]
    else:
        gp5_args += ["--keep-keystone", "--chunk-count",
                     args.chunk_count or "100"]
        if args.playgo_languages:
            gp5_args += ["--playgo-languages", args.playgo_languages]
        if not reference:
            gp5_args += ["--auto-size-profile", AUTO_SIZE_PROFILE]
        else:
            log("Reference build: preserving source attributePub; unpacked "
                "patch size cannot determine remastered size.")

    with open(os.path.join(log_directory, "01-create-gp5.log"), "wb") as tee:
        proc = subprocess.Popen([args.python, *gp5_args],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        for chunk in iter(proc.stdout.readline, b""):
            sys.stderr.buffer.write(chunk)
            sys.stderr.buffer.flush()
            tee.write(chunk)
        py_exit = proc.wait()
    if py_exit:
        die(f"GP5 creation failed with exit code {py_exit}")

    with open(gp5, "rb") as handle:
        data = handle.read()
    with open(gp5, "wb") as handle:
        handle.write(data.replace(b'src_path="', b'src_path="Z:'))

    if reference:
        log(f"[2/2] Building plaintext/no-auth patch against: {reference}")
    else:
        log("[2/2] Building final plaintext/no-auth PKG "
            f"(compression level: {args.compression_level})")

    publisher = os.path.join(TOOLKIT, "toolchain", "prospero-pub-cmd.exe")
    wineprefix_dir = env("WINEPREFIX", os.path.expanduser("~/.wine"))
    sdk_started = datetime.datetime.now(datetime.timezone.utc)
    sdk_started_epoch = int(time.time())

    publisher_args = ["img_create", "--oformat", "nwonly",
                      "--compression_level", str(args.compression_level)]
    if reference:
        publisher_args += ["--ref_pkg_path", reference]
    publisher_args += [gp5, partial]

    sdk_exit = subprocess.run(["wine", publisher, *publisher_args],
                              stdout=sys.stderr).returncode

    sdk_finished = datetime.datetime.now(datetime.timezone.utc)
    elapsed = int(time.time()) - sdk_started_epoch

    logged_command = " ".join(
        '"%s"' % arg.replace('"', '\\"') if re.search(r'[\s"]', arg) else arg
        for arg in publisher_args)

    with open(os.path.join(log_directory, "02-img-create.log"), "w",
              encoding="utf-8") as handle:
        handle.write(f"command={logged_command}\n")
        handle.write('started_utc='
                     + sdk_started.strftime("%Y-%m-%dT%H:%M:%SZ") + "\n")
        handle.write('finished_utc='
                     + sdk_finished.strftime("%Y-%m-%dT%H:%M:%SZ") + "\n")
        handle.write(f"elapsed={elapsed}s\n")
        handle.write(f"exit_code={sdk_exit}\n")

    if sdk_exit:
        print(f"PKG creation failed: img_create exited with {sdk_exit} "
              f"after {elapsed}s", file=sys.stderr)
        # Without --temp-dir, img_create stages in wine's %TEMP%, which lives
        # in the prefix and is easy to fill with a large title.
        for directory in (output_directory,
                          env("TEMP", os.path.join(wineprefix_dir, "drive_c"))):
            if os.path.isdir(directory):
                print(free_space_line(directory), file=sys.stderr)
        print(f"  details: {log_directory}/02-img-create.log", file=sys.stderr)
        sys.exit(1)

    if reference and not os.path.isfile(partial_remastered):
        die("Publisher did not create the expected remastered package: "
            + partial_remastered)

    os.replace(partial, final)
    if reference:
        os.replace(partial_remastered, final_remastered)
    if args.keep_intermediate and os.path.isfile(metric):
        os.replace(metric, final_metric)

    if not args.keep_intermediate:
        if temporary_build_directory:
            resolved_temp_build = os.path.realpath(temporary_build_directory)
            temp_prefix = os.path.realpath(temporary_root) + os.sep
            if not (resolved_temp_build + os.sep).startswith(temp_prefix):
                die("Refusing to clean a temporary directory outside "
                    "TemporaryDirectory.")
            shutil.rmtree(resolved_temp_build)
            if temporary_root_created and os.path.isdir(temporary_root) \
                    and not os.listdir(temporary_root):
                os.rmdir(temporary_root)

        for path in (metric, gp5, scenario):
            try:
                os.remove(path)
            except OSError:
                pass

        if os.path.isdir(assets):
            generated_assets_root = os.path.realpath(
                os.path.join(output_directory, "gp5-assets"))
            resolved_assets = os.path.realpath(assets)
            if not (resolved_assets + os.sep).startswith(
                    generated_assets_root + os.sep):
                die("Refusing to clean generated assets outside gp5-assets.")
            shutil.rmtree(resolved_assets)
            if os.path.isdir(generated_assets_root) \
                    and not os.listdir(generated_assets_root):
                os.rmdir(generated_assets_root)
        log("Temporary GP5 inputs removed.")
    elif temporary_build_directory:
        log(f"Temporary workspace retained in: {temporary_build_directory}")

    if args.keep_intermediate:
        log(f"Created GP5: {gp5}")
    log(f"Created PKG: {final}")
    print(final, flush=True)
    if reference:
        log(f"Created remastered PKG: {final_remastered}")
        print(final_remastered, flush=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class Parser(argparse.ArgumentParser):
    # the shell scripts exit 1 on a usage error
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


class DlcAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        dirs = list(getattr(namespace, self.dest, None) or [])
        dirs.append(strip_one_slash(values))
        setattr(namespace, self.dest, dirs)
        namespace.dlc_mode = "explicit"


def build_parser():
    parser = Parser(
        prog="build-pkg.py",
        description="Repackage a raw PS4 or PS5 dump into a fake PKG. "
                    "With no subcommand the source is sniffed: "
                    "sce_sys/param.json means ps5, anything else ps4.")
    sub = parser.add_subparsers(dest="platform", parser_class=Parser)

    # DLC="dir dir" is the environment's form of repeating --dlc.
    dlc_env = [strip_one_slash(d) for d in env("DLC").split()]
    backport_env = env("BACKPORT", "1")

    ps4 = sub.add_parser(
        "ps4",
        help="repackage a PS4 dump (port of build-fpkg.sh)",
        description="Repackage a raw PS4 dump into a booting, compressed "
                    "fake-PKG. Directories are identified by their own "
                    "param.sfo and can be given in any order.")
    ps4.add_argument("--content-id", default=env("CONTENT_ID"),
                     help="pkg content id (default: read from base param.sfo)")
    ps4.add_argument("--update", default=env("UPDATE"), metavar="DIR",
                     help="explicit update/patch dump to merge onto the base")
    ps4.add_argument("--no-update", dest="update", action="store_const",
                     const="none",
                     help="base-only; do not auto-merge a sibling patch")
    ps4.add_argument("--app-merge", dest="mode", action="store_const",
                     const="app-merge",
                     help="merged app pkg + backport patch (default)")
    ps4.add_argument("--remaster", dest="mode", action="store_const",
                     const="remaster",
                     help="merged remaster pkg with the backport baked in")
    ps4.add_argument("--separate", dest="mode", action="store_const",
                     const="separate",
                     help="app pkg + update pkg + backport patch")
    ps4.set_defaults(mode=env("MODE", "app-merge"))
    ps4.add_argument("--no-backport", dest="backport", action="store_false",
                     help="do not run the SDK backport pass")
    ps4.set_defaults(backport=backport_env == "1")
    ps4.add_argument("--base-pkg", default=env("BASE_PKG_IN"), metavar="PKG",
                     help="build only the backport patch, for a base package "
                          "that already exists")
    ps4.add_argument("--sdk", default=env("BACKPORT_TARGET_SDK", "auto"),
                     metavar="VER",
                     help="backport target SDK, or \"auto\" (default)")
    ps4.add_argument("--tmp-dir", default=strip_one_slash(env("IMG_TMP_DIR")),
                     metavar="DIR",
                     help="scratch for img_create's internal image "
                          "(default: <cwd>/fpkgtmp)")
    ps4.add_argument("--dlc", action=DlcAction, dest="dlc_dirs",
                     default=list(dlc_env), metavar="DIR",
                     help="DLC dump dir holding \"*-ac\"/\"*-al\" content "
                          "dirs; repeatable")
    ps4.add_argument("--no-dlc", dest="dlc_mode", action="store_const",
                     const="none", help="do not build any DLC pkgs")
    ps4.set_defaults(dlc_mode="explicit" if dlc_env else env("DLC_MODE"))
    ps4.add_argument("--keystone", default=env("KEYSTONE_MODE", "retail"),
                     metavar="MODE", help="retail (default) | kscreate")
    ps4.add_argument("--ps2-tid", default=env("PS2_TID"), metavar="NNNNN",
                     help="force the 5-digit PS2 serial for emu auth")
    ps4.add_argument("-o", "--out", default=env("OUT_DIR", os.getcwd()),
                     metavar="DIR", help="output directory (default: cwd)")
    ps4.add_argument("dirs", nargs="*", metavar="dir",
                     help="base/update/add-on dump dirs, in any order")

    ps5 = sub.add_parser(
        "ps5",
        help="repackage a PS5 dump (port of build-ps5.sh)",
        description="Repackage a raw PS5 dump into a fake PKG.")
    ps5.add_argument("--source-folder", "-s", required=True, metavar="DIR")
    ps5.add_argument("--output-package", "-o", required=True, metavar="PKG")
    ps5.add_argument("--reference-package", "-r", default="", metavar="PKG",
                     help="build a plaintext/no-auth patch against it")
    ps5.add_argument("--sc-pkg", default="", metavar="PKG_OR_URL",
                     help="restore sce_sys metadata from a retail SC package")
    ps5.add_argument("--passcode", default=FAKE_PASSCODE, metavar="HEX")
    ps5.add_argument("--python", default="python3", metavar="PATH")
    ps5.add_argument("--temp-dir", default=env("LIBPROSPERO_TEMP_DIR"),
                     metavar="DIR")
    ps5.add_argument("--compression-level", type=int, default=7, metavar="N",
                     help="-4..9 (default: 7)")
    ps5.add_argument("--chunk-count", default="", metavar="N",
                     help="1..800, apps only (default: 100)")
    ps5.add_argument("--playgo-languages", default="", metavar="LIST",
                     help="apps only; e.g. en-US,ru-RU")
    ps5.add_argument("--volume", default="auto", metavar="VOL",
                     help="auto|app|ac (default: auto; ac when there is no "
                          "eboot.bin)")
    ps5.add_argument("--entitlement-key", default="", metavar="HEX",
                     help="add-ons only (default: the source's "
                          "entitlement_key.dat, else 32 zeroes)")
    ps5.add_argument("--keep-intermediate", action="store_true")
    ps5.add_argument("--force", "-f", action="store_true")
    return parser


def detect_platform(argv):
    # No subcommand: sniff the source tree the args point at.
    for token in argv:
        if os.path.isdir(token):
            if os.path.isfile(os.path.join(token, "sce_sys", "param.json")):
                return "ps5"
            return "ps4"
    return "ps4"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in ("ps4", "ps5", "-h", "--help"):
        argv.insert(0, detect_platform(argv))
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.platform == "ps5":
        cmd_ps5(args)
    else:
        cmd_ps4(args)


if __name__ == "__main__":
    main()
