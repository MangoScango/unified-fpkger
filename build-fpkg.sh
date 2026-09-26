#!/usr/bin/env bash
#
# build-fpkg.sh
# ============================================================================
# Repackage a raw PS4 dump into a booting, COMPRESSED fake-PKG on Linux.
# Works for normal PS4 games AND PS2-Classics; the PS2 handling is applied
# automatically when a PS2-emulator title is detected. Optionally merges an
# update/patch dump onto the base first.
#
# ----------------------------------------------------------------------------
# HOW SIGNING WORKS (important)
#   orbis-pub-cmd's img_create fake-signs plain-ELF executables ITSELF during
#   the build. So for a normal PS4 game we sign NOTHING by hand - we just hand
#   the dump to gengp4 + img_create.
#
#   The ONLY reason we ever pre-sign is to inject a special "PS2 emulator" auth
#   block that img_create's default signing does not produce. Without it a PS2
#   classic loads its eboot but the console never grants PS2-emulation rights
#   (hang on splash), and the prx modules fail to load (PRX_SCE_MODULE_LOAD_
#   ERROR). So on a PS2 classic we pre-sign exactly these four:
#       eboot.bin, ps2-emu-compiler.self      (PS2-emu exec auth)
#       sce_module/libc.prx, libSceFios2.prx  (PS2-emu dynlib auth)
#   Everything else is left for img_create.
#
# ----------------------------------------------------------------------------
# OTHER RULES (apply to both game types)
#   * KEYSTONE must exist in the tree/gp4. orbis-pub-cmd does not generate one;
#     a missing keystone => "save data corrupted / cannot create save".
#       --keystone retail   (default): use the dump's original keystone
#                                      (allows retail-save interop).
#       --keystone kscreate          : generate a fresh keystone from the
#                                      (all-zero) passcode.
#   * gengp4 sometimes emits <scenarios default_id="1"> pointing at a missing
#     scenario => img_create rejects it. We rewrite it to "0".
#   * sce_discmap.plt is NOT carried (img_create regenerates it; the dump's is a
#     stale finalized-BD map). Confirmed builds boot without carrying it.
#   * We build with orbis-pub-cmd.exe (standard CyB1K 3.87): it compresses the
#     image (~1.5GB vs LibOrbis's uncompressed ~2.0GB), regenerates the discmap,
#     and preserves any executables we pre-signed. (The PS2-patched pkg.exe
#     re-enables checks that reject a merged APP_VER / mangle the SFO; LibOrbis
#     is native but its PFSC writer does not actually compress.)
#
# ----------------------------------------------------------------------------
# BUILD MODES
#
#   A base on its own builds one app pkg, with the backport handled the same way
#   each mode handles it below: as its own patch, or baked in under --remaster.
#
#   default        one pkg_ps4_app holding base+update at the update's APP_VER,
#                  plus a small patch for the backport. This needs the patched
#                  orbis-pub-cmd; stock rejects APP_VER != 01.00 on an app volume.
#   --remaster     one pkg_ps4_remaster. A remaster cannot be patched
#                  afterwards, so a backport is baked in and the executables it
#                  displaces are written to <TITLEID>-stock beside the output.
#   --separate     app pkg and update pkg as retail ships them, plus a second
#                  full update carrying the backport.
#
# --no-backport skips the SDK pass in any mode.
#
# The update's param.sfo is carried; TARGET_APP_VER is patch-only and dropped
# from an app or remaster volume. APP_VER is what the console displays.
#
# SYSTEM_VER is rewritten to match the executables rather than carried. Sony sets
# it from release policy, so a patch built long after the code can demand a much
# newer firmware than anything in it needs. A package holding backported
# executables asks for the backport target; one holding the originals asks for
# whatever they were built against.
#
# A backport patch declares the same APP_VER as the base it sits on, so the
# displayed version does not move. img_create requires a patch to out-rank the
# package its app_path names, so it is built one version up and restamped.
#
# ----------------------------------------------------------------------------
# DLC: builds a SEPARATE add-on (ac) pkg for each DLC found, alongside the
# app/remaster pkg. This is the kstuff-native approach: the DLC installs as its
# own pkg and is unlocked by a DLC-capable kstuff on the console (no eboot patch,
# no merging). Two dir kinds are handled, both produced by a recent ftpdump:
#   *-ac  installed DLC (content + a populated sce_sys) -> pkg_ps4_ac_data
#   *-al  entitlement-only license, no content          -> pkg_ps4_ac_nodata
# An "-al" unlocker just grants the license for content already present in the
# game or its update; it carries no files beyond sce_sys.
#
# Building an ac pkg needs a file list, but gengp4_app (the only gp4 generator
# we have) CRASHES when it parses an ac-category param.sfo, and it also rewrites
# the scanned tree's param.sfo in place. So we scan a hardlinked STAGE of the
# DLC tree with a throwaway "app" param.sfo swapped in, capture the file list,
# restore the real ac param.sfo in the stage, splice the list into an
# ac_data project (gp4_proj_create), and img_create from the stage. The
# original dump is never modified.
#
# ----------------------------------------------------------------------------
# USAGE
#   build-fpkg.sh [options] <dir> [dir ...]
#
#   Directories are identified by their own param.sfo, so they can be given in
#   any order and no flag is needed to say what each one is:
#     CATEGORY=gd   -> base app dump
#     CATEGORY=gp*  -> update/patch dump (merged onto the base as a remaster)
#     CATEGORY=ac   -> add-on ("-ac" = with content, "-al" = entitlement only)
#     no param.sfo but add-on subdirs -> a container of add-ons
#   Pass only add-on/DLC dirs to build just those pkgs; no base dump is needed
#   for them. --update/--dlc still work and are equivalent to naming the dir.
#     --content-id CID   pkg content id (default: read from base param.sfo)
#     --update DIR       explicit update/patch dump to merge onto the base
#     --no-update        base-only; do not auto-merge a sibling patch
#     --app-merge        merged app pkg + backport patch (default)
#     --remaster         merged remaster pkg with the backport baked in
#     --separate         app pkg + update pkg + backport patch
#     --no-backport      do not run the SDK backport pass
#     --base-pkg PKG     build only the backport patch, for a base package that
#                        already exists. The dumps still supply the executables;
#                        CONTENT_ID and APP_VER come from the pkg, and a mismatch
#                        against the dumps is refused since a patch only marries
#                        the base it was built against.
#     --sdk VER          backport target SDK, or "auto" (default). "auto" picks
#                        the oldest firmware exporting everything the title
#                        imports, which is the most portable target it can take;
#                        pass an explicit stamp to override.
#     --dlc DIR          DLC dump dir (holds one or more "*-ac"/"*-al" content
#                        dirs) to build add-on pkgs from; repeatable. Default:
#                        auto-detect a sibling "<foo>-dlc" dir.
#     --no-dlc           do not build any DLC pkgs
#     --keystone MODE    retail (default) | kscreate
#     --ps2-tid NNNNN    force the 5-digit PS2 serial for emu auth
#                        (default: auto-derived from CONTENT_ID for PS2 titles)
#     -o, --out DIR      output directory (default: cwd)
#
#   By default, if the base dump dir is named "<foo>-app", the script looks for
#   a sibling "<foo>-patch" and merges it automatically, and a sibling
#   "<foo>-dlc" whose "*-ac"/"*-al" dirs each become a separate add-on pkg. Pass
#   --no-update / --no-dlc to skip, or --update DIR / --dlc DIR to point
#   elsewhere.
# ============================================================================
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- tools (override via env) ----------------------------------------------
SDK_DIR="${SDK_DIR:-$SELF_DIR/PS4_Fake_PKG_Tools_3}"
GENGP4_APP="${GENGP4_APP:-$SDK_DIR/gengp4_app.exe}"
GENGP4_PATCH="${GENGP4_PATCH:-$SDK_DIR/gengp4_patch.exe}"
# Patched to accept APP_VER != 01.00 on an app volume.
ORBIS_PUB_CMD="${ORBIS_PUB_CMD:-$SDK_DIR/orbis-pub-cmd.exe}"
MAKE_FSELF="${MAKE_FSELF:-$SELF_DIR/make_fself.py}"
BACKPORT_SDK="${BACKPORT_SDK:-$SELF_DIR/backport-sdk.py}"
PKG_SET_APPVER="${PKG_SET_APPVER:-$SELF_DIR/pkg-set-appver.py}"
SFO_TOOL="${SFO_TOOL:-$SELF_DIR/sfo}"
FAKE_PASSCODE="00000000000000000000000000000000"
DLC_ENT_KEY="00000000000000000000000000000000"   # zero entitlement key (kstuff fakes the check)
WINE_OVERRIDES="wineps.drv,localspl.dll,spoolss.dll=d"

# PS2-emu auth-info templates (authinfo_emu.txt, FW=501). The first 2 bytes
# (4 hex chars) are replaced with the PS2 title-id decimal bytes.
EBOOT_AUTH_TMPL="0000C2AC03000034000000008003002000FF00000000002000000000000000000000000000000000000080C000400040000000000000004002000000000080000040FFFF000000F000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
COMPILER_AUTH_TMPL="0000C2AC03000034000000008003002000FF00000000004000000000000000000000000000000000000080C000400040000000000000004008000000000080000040FFFF000000F000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
PRX_AUTH_TMPL="0000C2AC03000035000000000000000000FF000000000000000000000000000000000000000000000000004000300030000000000000004000000000000080000040FFFF000000F000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

die() { echo "error: $*" >&2; exit 1; }
log() { echo ">> $*" >&2; }
# ---------------------------------------------------------------------------
# img_progress_start <out_dir> / img_progress_stop
#   Report the package as it grows, since orbis-pub-cmd prints nothing while
#   img_create runs. NO_PROGRESS silences it, PROGRESS_EVERY sets the interval.
# ---------------------------------------------------------------------------
IMG_PROGRESS_PID="" IMG_PROGRESS_MARKER="" IMG_PS4PUB="" IMG_TMP_WIN=""
# orbis-pub-cmd stages the internal image as numbered .tpfs files under
# <tmp_path>\ps4pub\build<id>\, needing room for another copy of the title.
# IMG_TMP_DIR overrides the location.
img_tmp_init() {
  [ -n "$IMG_TMP_WIN" ] && return
  IMG_TMP_DIR="${IMG_TMP_DIR:-$WORK_DIR/fpkgtmp}"
  mkdir -p "$IMG_TMP_DIR"
  IMG_TMP_WIN="$(winpath "$IMG_TMP_DIR")"
}
ps4pub_dir() {
  [ -n "$IMG_PS4PUB" ] || IMG_PS4PUB="$(find "${WINEPREFIX:-$HOME/.wine}/drive_c" \
    -maxdepth 3 -type d -name ps4pub -print -quit 2>/dev/null)"
  printf '%s' "$IMG_PS4PUB"
}
# Bytes in the build dirs this run created. A failed run leaves its dir behind, so
# the marker is what separates ours from the debris.
img_staged_bytes() {
  local root d n total=0
  root="${IMG_TMP_DIR:-}/ps4pub"
  [ -d "$root" ] || root="$(ps4pub_dir)"
  [ -n "$root" ] && [ -d "$root" ] || { printf 0; return; }
  for d in "$root"/build*; do
    [ -d "$d" ] && [ "$d" -nt "$IMG_PROGRESS_MARKER" ] || continue
    n="$(du -sb "$d" 2>/dev/null | cut -f1)"
    [ -n "$n" ] && total=$(( total + n ))
  done
  printf '%s' "$total"
}
img_progress_start() {
  local dir="$1" every="${PROGRESS_EVERY:-15}"
  IMG_PROGRESS_PID=""
  [ -z "${NO_PROGRESS:-}" ] || return 0
  [ "$every" -gt 0 ] || return 0
  IMG_PROGRESS_MARKER="$(mktemp)"
  (
    # The package does not exist for the first few seconds; errexit would take
    # the watcher down with the failing listing.
    set +e
    prev=0 iprev=0
    while sleep "$every"; do
      # img_create creates the package up front and leaves it at zero bytes until
      # staging finishes.
      f="$(ls -t "$dir"/*.pkg 2>/dev/null | head -1)"
      cur=0
      [ -n "$f" ] && cur="$(stat -c %s "$f" 2>/dev/null || echo 0)"
      if [ "$cur" -gt "$prev" ]; then
        log "image: $(numfmt --to=iec "$cur") written" \
          "($(numfmt --to=iec $(( (cur - prev) / every )))/s)"
        prev="$cur"
        continue
      fi
      staged="$(img_staged_bytes)"
      [ "$staged" -gt "$iprev" ] || continue
      log "internal image: $(numfmt --to=iec "$staged") staged" \
        "($(numfmt --to=iec $(( (staged - iprev) / every )))/s)"
      iprev="$staged"
    done
  ) &
  IMG_PROGRESS_PID=$!
}
img_progress_stop() {
  [ -n "$IMG_PROGRESS_MARKER" ] && rm -f "$IMG_PROGRESS_MARKER"
  IMG_PROGRESS_MARKER=""
  [ -n "$IMG_PROGRESS_PID" ] || return 0
  kill "$IMG_PROGRESS_PID" 2>/dev/null || true
  wait "$IMG_PROGRESS_PID" 2>/dev/null || true
  IMG_PROGRESS_PID=""
}
# ---------------------------------------------------------------------------
# img_create <out_dir> <pub-cmd args ...>
#   img_create with progress around it. orbis-pub-cmd returns non-zero on
#   warnings alone, so the status is dropped and callers check for the package.
# ---------------------------------------------------------------------------
img_create() {
  local out="$1"; shift
  # The watcher reads IMG_TMP_DIR, so resolve it before forking.
  img_tmp_init
  img_progress_start "$out"
  local log_file; log_file="$(mktemp)"
  wine_run "$ORBIS_PUB_CMD" img_create --tmp_path "$IMG_TMP_WIN" "$@" \
    2> >(tee -a "$log_file" >&2) | tee -a "$log_file" || true
  img_progress_stop
  # The exit status is useless here - orbis-pub-cmd returns non-zero for warnings
  # alone - but it prefixes real failures with [Error].
  local errors; errors="$(tr -d '\000' < "$log_file" | grep '^\[Error\]' || true)"
  rm -f "$log_file"
  [ -z "$errors" ] || die "img_create failed:
$errors"
}
# The CyB1K tools write to a Windows console, which wine only bridges onto unix
# fds when fd 0/1/2 is a tty, so run them under a pty. /dev/null as the typescript
# makes script(1) stream to our stdout instead of buffering to a file.
wine_run() {
  local cmd="WINEDEBUG=${WINEDEBUG:--all} WINEDLLOVERRIDES=$WINE_OVERRIDES wine"
  local a; for a in "$@"; do cmd+=" $(printf '%q' "$a")"; done
  if command -v script >/dev/null 2>&1; then
    # script -c runs through $SHELL, not sh, and script itself consumes stdin.
    SHELL=/bin/sh script -qefc "$cmd" /dev/null </dev/null
    return $?
  fi
  WINEDEBUG="${WINEDEBUG:--all}" WINEDLLOVERRIDES="$WINE_OVERRIDES" wine "$@" </dev/null
}
winpath() { winepath -w "$1"; }
sfo_get() { "$SFO_TOOL" "$1" -q "$2" 2>/dev/null | tr -d '\r\n'; }
sfo_edit() { "$SFO_TOOL" "$@" >/dev/null 2>&1 || true; }

# --- args ------------------------------------------------------------------
# UPDATE: "" = auto-discover sibling "-patch" dir; "none" = base-only;
#         a path = explicit update dir.
# DLC_DIRS: explicit --dlc dirs (repeatable). DLC_MODE: "" = auto-discover a
# sibling "-dlc" dir; "none" = do not build DLC; "explicit" = use DLC_DIRS.
CONTENT_ID="" UPDATE="" DUMP="" OUT_DIR="$PWD" KEYSTONE_MODE="retail" PS2_TID=""
# sce_sys a backport patch carries; a directory here is taken whole. Anything not
# listed falls through to the app volume underneath.
#
# playgo-chunk.dat carries the chunk count, and img_create rejects a patch that
# changes it. npbind.dat holds the NP Communication ID the trophy system resolves
# at startup. Trimming this list needs hardware to check.
PATCH_SCE_SYS="${PATCH_SCE_SYS:-param.sfo icon0.png playgo-chunk.dat npbind.dat}"
MODE="app-merge" BACKPORT=1 BACKPORT_TARGET_SDK="auto" BASE_PKG_IN=""
RESOLVED_SDK="" OBSERVED_SDK=""
DLC_MODE="" ; declare -a DLC_DIRS=() DLC_ITEMS=() ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --content-id) CONTENT_ID="${2:?}"; shift 2 ;;
    --update)     UPDATE="${2%/}"; shift 2 ;;
    --no-update)  UPDATE="none"; shift ;;
    --app-merge)  MODE="app-merge"; shift ;;
    --remaster)   MODE="remaster"; shift ;;
    --separate)   MODE="separate"; shift ;;
    --no-backport) BACKPORT=0; shift ;;
    --base-pkg)   BASE_PKG_IN="${2:?}"; shift 2 ;;
    --sdk)        BACKPORT_TARGET_SDK="${2:?}"; shift 2 ;;
    --dlc)        DLC_DIRS+=("${2%/}"); DLC_MODE="explicit"; shift 2 ;;
    --no-dlc)     DLC_MODE="none"; shift ;;
    --keystone)   KEYSTONE_MODE="${2:?}"; shift 2 ;;
    --ps2-tid)    PS2_TID="${2:?}"; shift 2 ;;
    -o|--out)     OUT_DIR="${2:?}"; shift 2 ;;
    -h|--help)    grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)           die "unknown option: $1" ;;
    *)            ARGS+=("${1%/}"); shift ;;
  esac
done

case "$KEYSTONE_MODE" in kscreate|retail) ;; *) die "--keystone must be kscreate or retail" ;; esac
command -v wine >/dev/null || die "wine not found"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
WORK_DIR="$PWD"

# --- classify the given dirs -----------------------------------------------
# A dir with no param.sfo of its own but add-on children is a container.
classify_dir() {
  local d="$1" sub
  if [ -f "$d/sce_sys/param.sfo" ]; then
    case "$(sfo_get "$d/sce_sys/param.sfo" CATEGORY)" in
      gd)  echo app ;;
      gp*) echo patch ;;
      ac)  echo addon ;;
      # Only applications carry an eboot.
      *)   if [ -f "$d/eboot.bin" ]; then echo app; else echo unknown; fi ;;
    esac
    return
  fi
  while IFS= read -r sub; do
    [ -f "$sub/sce_sys/param.sfo" ] || continue
    if [ "$(sfo_get "$sub/sce_sys/param.sfo" CATEGORY)" = "ac" ]; then echo container; return; fi
  done < <(find "$d" -mindepth 1 -maxdepth 1 -type d | sort)
  echo unknown
}

if [ "${#ARGS[@]}" -gt 0 ]; then
  for a in "${ARGS[@]}"; do
    [ -d "$a" ] || die "not a directory: $a"
    a="$(cd "$a" && pwd)"
    case "$(classify_dir "$a")" in
      app)   [ -z "$DUMP" ] || die "more than one base app dir given: $DUMP and $a"
             DUMP="$a" ;;
      patch) if [ "$UPDATE" = "none" ]; then log "ignoring update dir (--no-update): $a"
             else [ -z "$UPDATE" ] || die "more than one update dir given: $UPDATE and $a"
                  UPDATE="$a"; fi ;;
      addon)     DLC_ITEMS+=("$a") ;;
      container) DLC_DIRS+=("$a"); DLC_MODE="explicit" ;;
      *) die "cannot tell what '$a' is: no sce_sys/param.sfo with CATEGORY gd/gp*/ac, and no add-on subdirs" ;;
    esac
  done
fi

# Add-ons carry their own identity, so a dump is only needed for app builds.
BUILD_APP=1
if [ -z "$DUMP" ]; then
  if [ "${#DLC_ITEMS[@]}" -gt 0 ] || [ "${#DLC_DIRS[@]}" -gt 0 ]; then
    BUILD_APP=0
  else
    die "nothing to build: pass a base app dump, and/or an add-on or DLC dir"
  fi
else
  [ -f "$DUMP/sce_sys/param.sfo" ] || die "dump missing sce_sys/param.sfo"
  [ -f "$DUMP/eboot.bin" ] || die "dump missing eboot.bin"
fi

# --- resolve the update dir ------------------------------------------------
if [ "$UPDATE" = "none" ]; then
  UPDATE=""                                   # explicitly base-only
elif [ -n "$UPDATE" ]; then
  [ -d "$UPDATE" ] || die "update dir not found: $UPDATE"
  UPDATE="$(cd "$UPDATE" && pwd)"
else
  # auto-discover: a sibling dir named like the base but with -app -> -patch.
  case "$DUMP" in
    *-app)
      cand="${DUMP%-app}-patch"
      if [ -d "$cand" ] && [ -f "$cand/sce_sys/param.sfo" ]; then
        UPDATE="$cand"
        log "auto-detected update: $UPDATE  (use --no-update to skip)"
      fi
      ;;
  esac
fi

# --- resolve the DLC dir(s) ------------------------------------------------
if [ "$DLC_MODE" = "none" ]; then
  DLC_DIRS=()                                 # explicitly no DLC
elif [ "$DLC_MODE" = "explicit" ]; then
  for d in "${DLC_DIRS[@]}"; do
    [ -d "$d" ] || die "dlc dir not found: $d"
  done
else
  # auto-discover: a sibling dir named like the base but with -app -> -dlc.
  case "$DUMP" in
    *-app)
      cand="${DUMP%-app}-dlc"
      if [ -d "$cand" ]; then
        DLC_DIRS=("$cand")
        log "auto-detected dlc: $cand  (use --no-dlc to skip)"
      fi
      ;;
  esac
fi
if [ "${#DLC_DIRS[@]}" -gt 0 ]; then
  _tmp=(); for d in "${DLC_DIRS[@]}"; do _tmp+=("$(cd "$d" && pwd)"); done
  DLC_DIRS=("${_tmp[@]}"); unset _tmp
fi

IS_PS2=0
if [ "$BUILD_APP" -eq 1 ]; then
  [ -n "$CONTENT_ID" ] || CONTENT_ID="$(sfo_get "$DUMP/sce_sys/param.sfo" CONTENT_ID)"
  [ -n "$CONTENT_ID" ] || die "could not determine CONTENT_ID"
  TITLE_ID="$(sfo_get "$DUMP/sce_sys/param.sfo" TITLE_ID)"
  BASE_APPVER="$(sfo_get "$DUMP/sce_sys/param.sfo" APP_VER)"
  # What the executables ask for, for SYSTEM_VER on packages we do not restamp.
  declare -a _obs=("$DUMP")
  if [ -n "$UPDATE" ] && [ "$UPDATE" != none ]; then _obs+=("$UPDATE"); fi
  OBSERVED_SDK="$(python3 "$BACKPORT_SDK" --observed "${_obs[@]}" 2>/dev/null || true)"
  unset _obs
  [ -n "$OBSERVED_SDK" ] && log "executables were built against $OBSERVED_SDK" || true

  # --- detect PS2 classic --------------------------------------------------
  # Signal: the PS2 emulator compiler self is present (backed by EMU_VER).
  if [ -f "$DUMP/ps2-emu-compiler.self" ]; then IS_PS2=1; fi
  [ -n "$(sfo_get "$DUMP/sce_sys/param.sfo" EMU_VER)" ] && IS_PS2=1

  if [ "$IS_PS2" -eq 1 ] && [ -z "$PS2_TID" ]; then
    # CONTENT_ID tail segment holds the disc serial, e.g.
    #   UP9000-CUSA01724_00-SCUS971050000001  ->  SCUS 97105  ->  ps2-tid 97105
    serial="${CONTENT_ID##*-}"               # SCUS971050000001
    PS2_TID="$(printf '%s' "$serial" | sed -E 's/^[A-Z]{4}([0-9]{5}).*/\1/')"
    [ "${#PS2_TID}" -eq 5 ] || die "could not derive PS2 title id from CONTENT_ID ($CONTENT_ID); pass --ps2-tid"
  fi

  log "content id : $CONTENT_ID"
  log "type       : $([ "$IS_PS2" -eq 1 ] && echo "PS2 classic (ps2-tid=$PS2_TID)" || echo "normal PS4")"
  log "update     : ${UPDATE:-<none>}"
  log "mode       : $MODE$([ "$BACKPORT" -eq 1 ] || echo " (no backport)")"
  log "keystone   : $KEYSTONE_MODE"
else
  log "add-ons only (no base app dump given)"
fi
log "dlc        : $( { [ "${#DLC_DIRS[@]}" -gt 0 ] && printf '%s ' "${DLC_DIRS[@]}"; [ "${#DLC_ITEMS[@]}" -gt 0 ] && printf '%s ' "${DLC_ITEMS[@]}"; } || echo "<none>")"

# --- PS2 auth (computed once; used to pre-sign the emu modules) ------------
# The auth-info blob and its paid are derived from the PS2 title id:
#   deci = low 2 bytes of the (5-digit) title id, little-endian, as hex
#          (e.g. 97105 = 0x17B51 -> "517B"). This mirrors free-ps2-pub-gen's
#          GetDecimalBytes; for a value that fits in 32 bits the .NET decimal
#          layout is just the integer little-endian, so this is exact.
#   auth = deci + template[4:]           (patch title bytes into the front)
#   paid = endian-swap of auth's first 8 bytes (16 hex chars)
if [ "$IS_PS2" -eq 1 ]; then
  DECI="$(printf '%02X%02X' $(( PS2_TID & 0xFF )) $(( (PS2_TID >> 8) & 0xFF )))"
  _mk_auth() { printf '%s%s' "$DECI" "${1:4}"; }
  _mk_paid() { local h="${1:0:16}" out="" i; for ((i=14;i>=0;i-=2)); do out+="${h:i:2}"; done; printf '0x%s' "$out"; }
  EBOOT_AUTH="$(_mk_auth "$EBOOT_AUTH_TMPL")";       EBOOT_PAID="$(_mk_paid "$EBOOT_AUTH")"
  COMPILER_AUTH="$(_mk_auth "$COMPILER_AUTH_TMPL")"; COMPILER_PAID="$(_mk_paid "$COMPILER_AUTH")"
  PRX_AUTH="$(_mk_auth "$PRX_AUTH_TMPL")";           PRX_PAID="$(_mk_paid "$PRX_AUTH")"
fi

# ---------------------------------------------------------------------------
# stage_tree <stage_dir> [overlay_update]
#   Populate a staging dir from the base dump (hardlinked), optionally overlay
#   the update, pre-sign PS2 emu modules, and place the keystone.
# ---------------------------------------------------------------------------
stage_tree() {
  local stage="$1" overlay="$2"
  rm -rf "$stage"
  # Bulk content is hardlinked but sce_sys is copied to prevent modifying dump
  cp -al "$DUMP" "$stage" 2>/dev/null || cp -a "$DUMP" "$stage"
  rm -rf "$stage/sce_sys"; cp -a "$DUMP/sce_sys" "$stage/sce_sys"
  if [ -n "$overlay" ] && [ -n "$UPDATE" ]; then
    log "overlaying update (update wins)"
    cp -a "$UPDATE/." "$stage/"
    dedupe_case "$stage" "$UPDATE"
  fi

  if [ "$IS_PS2" -eq 1 ]; then
    local paid auth file
    for spec in \
      "$EBOOT_PAID|$EBOOT_AUTH|eboot.bin" \
      "$COMPILER_PAID|$COMPILER_AUTH|ps2-emu-compiler.self" \
      "$PRX_PAID|$PRX_AUTH|sce_module/libc.prx" \
      "$PRX_PAID|$PRX_AUTH|sce_module/libSceFios2.prx"; do
      paid="${spec%%|*}"; auth="${spec#*|}"; file="${auth#*|}"; auth="${auth%%|*}"
      [ -f "$stage/$file" ] || continue
      log "pre-signing PS2-emu module: $file"
      python3 "$MAKE_FSELF" --paid "$paid" --auth-info "$auth" \
        "$stage/$file" "$stage/$file.fself" >/dev/null 2>&1 || die "sign failed: $file"
      mv "$stage/$file.fself" "$stage/$file"
    done
  fi

  if [ "$KEYSTONE_MODE" = "kscreate" ]; then
    log "generating keystone from passcode (ks_create)"
    wine_run "$ORBIS_PUB_CMD" ks_create --passcode "$FAKE_PASSCODE" \
      "$(winpath "$stage/sce_sys/keystone")" >/dev/null 2>&1 || die "ks_create failed"
  else
    log "using retail keystone from base dump"
    cp --remove-destination "$DUMP/sce_sys/keystone" "$stage/sce_sys/keystone"
  fi

  unlink_executables "$stage"
}

# ---------------------------------------------------------------------------
# dedupe_case <stage_dir> <update_dir>
#   An update can respell a file it replaces (il2CppUserAssemblies.prx ->
#   Il2CppUserAssemblies.prx). Both survive the overlay on a case-sensitive host,
#   and img_create rejects a project holding two targ_paths that differ only in
#   case. The update's spelling wins, matching what the console resolves to.
# ---------------------------------------------------------------------------
dedupe_case() {
  local stage="$1" update="$2" lower rel prev_lower="" prev_rel="" n=0
  [ -d "$update" ] || return 0
  while IFS=$'\t' read -r lower rel; do
    if [ "$lower" = "$prev_lower" ]; then
      if [ -e "$update/$rel" ] && [ ! -e "$update/$prev_rel" ]; then
        rm -f "$stage/$prev_rel" && n=$((n + 1))
        log "case-duplicate from the base dropped: $prev_rel"
      elif [ -e "$update/$prev_rel" ] && [ ! -e "$update/$rel" ]; then
        rm -f "$stage/$rel" && n=$((n + 1))
        log "case-duplicate from the base dropped: $rel"
        continue
      else
        die "two files differ only in case and the update claims neither or both, so there is no way to tell which img_create should carry: $prev_rel, $rel"
      fi
    fi
    prev_lower="$lower" prev_rel="$rel"
  done < <(cd "$stage" && find . -type f -printf '%P\n' \
    | awk '{ print tolower($0) "\t" $0 }' | LC_ALL=C sort)
  [ "$n" -eq 0 ] || log "dropped $n case-duplicate file(s) the update respelled"
}

# ---------------------------------------------------------------------------
# unlink_executables <stage_dir>
#   img_create fake-signs executables by rewriting them where they lie, so a
#   hardlink from the stage would carry the rewrite back into the dump.
# ---------------------------------------------------------------------------
unlink_executables() {
  local stage="$1" f
  while IFS= read -r f; do
    [ "$(stat -c %h "$f")" -gt 1 ] || continue
    cp -a "$f" "$f.unlinking" && mv -f "$f.unlinking" "$f"
  done < <(find "$stage" -type f \( -name eboot.bin -o -name '*.elf' \
             -o -name '*.self' -o -name '*.prx' -o -name '*.sprx' \))
}

# ---------------------------------------------------------------------------
# gen_gp4 <stage_dir> -> produces <stage_dir>.gp4
# ---------------------------------------------------------------------------
# Win32 strips trailing spaces and dots from path components, so gengp4_app
# cannot open such a file and dies with an unhandled exception. Retail titles do
# ship them: Dark Souls Remastered has "playgo-chunks.xml ". Stage them under a
# name it can open and record the mapping.
stage_fix_names() {
  local stage="$1" map="$1.namefix" d p rel base reldir safe pad
  rm -f "$map"

  while IFS= read -r d; do
    die "directory name ends in a space or dot, which these tools cannot address: ${d#"$stage"/}"
  done < <(find "$stage" -mindepth 1 -type d \( -name '* ' -o -name '*.' \))

  while IFS= read -r p; do
    rel="${p#"$stage"/}"; base="${rel##*/}"; reldir="${rel%"$base"}"
    safe="${base%"${base##*[! .]}"}"
    pad=""; while [ "${#pad}" -lt $(( ${#base} - ${#safe} )) ]; do pad+="_"; done
    safe="$safe$pad"                        # same length, so no sibling collision
    mv -- "$p" "$stage/$reldir$safe" || die "could not rename $rel in the stage"
    printf '%s\t%s\n' "$reldir$safe" "$rel" >> "$map"
    log "staged '$rel' as '$safe' (name ends in space/dot)"
  done < <(find "$stage" -type f \( -name '* ' -o -name '*.' \))
}

# targ_path is stored verbatim in the pkg and never opened as a Win32 path, so the
# real name goes back here.
gp4_restore_names() {
  local stage="$1" gp4="$1.gp4" map="$1.namefix" safe real
  [ -s "$map" ] || { rm -f "$map"; return 0; }
  while IFS=$'\t' read -r safe real; do
    awk -v s="targ_path=\"$safe\"" -v r="targ_path=\"$real\"" \
      '{ i = index($0, s); if (i) $0 = substr($0, 1, i-1) r substr($0, i+length(s)) } 1' \
      "$gp4" > "$gp4.tmp" && mv "$gp4.tmp" "$gp4"
    grep -qF "targ_path=\"$real\"" "$gp4" || die "could not restore '$real' in $gp4"
    log "restored '$real' in the gp4"
  done < "$map"
  rm -f "$map"
}

# gen_gp4 <stage_dir> [generator]   (default: gengp4_app.exe)
# A stage name may not start with a dot: these tools treat everything after one
# as an extension and would write the project to ".gp4".
gen_gp4() {
  local stage="$1" gp4="$1.gp4" gen="${2:-$GENGP4_APP}"
  case "$(basename "$stage")" in .*) die "stage name may not start with a dot: $stage" ;; esac
  rm -f "$gp4"
  stage_fix_names "$stage"
  ( cd "$(dirname "$stage")" && wine_run "$gen" "$(winpath "$stage")" ) || true
  [ -f "$gp4" ] || die "gengp4 did not produce $gp4"
  gp4_restore_names "$stage"

  # gengp4 can point default_id at a scenario that isn't there, which both
  # img_create and gp4_proj_update reject.
  local first
  first="$(grep -oE '<scenario id="[0-9]+"' "$gp4" | head -1 | grep -oE '[0-9]+')"
  [ -z "$first" ] || sed -i "s|<scenarios default_id=\"[0-9]*\">|<scenarios default_id=\"$first\">|" "$gp4"
}

# ---------------------------------------------------------------------------
# stage_from <src_dir> <stage_dir> [overlay_dir]
#   Hardlinked copy of any tree, with sce_sys as real files (gengp4_app rewrites
#   param.sfo in place, and a hardlink would write through to the dump).
#   Unlike stage_tree this touches neither the keystone nor the PS2 modules: it
#   is for update trees, which carry their own sce_sys and no keystone.
# ---------------------------------------------------------------------------
stage_from() {
  local src="$1" stage="$2" overlay="${3:-}"
  rm -rf "$stage"
  cp -al "$src" "$stage" 2>/dev/null || cp -a "$src" "$stage"
  rm -rf "$stage/sce_sys"; cp -a "$src/sce_sys" "$stage/sce_sys"
  if [ -n "$overlay" ]; then
    log "overlaying $(basename "$overlay") onto the update tree"
    cp -a "$overlay/." "$stage/"
    # the overlay carries whichever param.sfo the backport last collected
    cp -a "$src/sce_sys/param.sfo" "$stage/sce_sys/param.sfo"
  fi
  unlink_executables "$stage"
}

# ---------------------------------------------------------------------------
# build_patch_pkg <update_dir> <app_pkg> <suffix> [overlay_dir]
#   Result lands in PATCH_PKG_RESULT, not on stdout: the tools write their own
#   output there, so a command substitution would capture their chatter too.
#   Scanned with gengp4_patch.exe, which is the generator meant for update trees
#   (it keeps a keystone out of the project), then pointed at the app pkg it
#   patches -- the headless equivalent of the GUI's Project Settings > Patch >
#   "Application Package" field. The update's own sce_sys already holds
#   CATEGORY=gp / APP_VER / TARGET_APP_VER, so no SFO surgery is needed.
#   <suffix> distinguishes the output file, since two patches for one title
#   otherwise land on the same name.
#
#   The stage has to be named "<TITLEID>-patch": these generators read the
#   directory name to decide what they are looking at, and given anything else
#   gengp4_patch rewrites the staged param.sfo (CATEGORY, APP_VER) and emits an
#   app volume, which img_create then rejects as "unexpected APP_VER". Named
#   correctly it emits pkg_ps4_patch with storage_type=digital25 and leaves the
#   sfo alone, so no volume or SFO surgery is needed here at all.
# ---------------------------------------------------------------------------
build_patch_pkg() {
  local update="$1" app_pkg="$2" suffix="$3" overlay="${4:-}"
  local tag; tag="$(printf '%s' "$CONTENT_ID$suffix" | tr -c 'A-Za-z0-9_-' '_')"
  local parent="$WORK_DIR/fpkgwork_patch_$tag" out="$WORK_DIR/patchpkg_$tag" gp4
  local title; title="$(sfo_get "$update/sce_sys/param.sfo" TITLE_ID)"
  [ -n "$title" ] || die "could not read TITLE_ID from $update/sce_sys/param.sfo"

  # the generators read the directory name; anything but "<TITLEID>-patch" makes
  # gengp4_patch rewrite the staged sfo and emit an app volume
  rm -rf "$parent"; mkdir -p "$parent"
  local stage="$parent/$title-patch"
  stage_from "$update" "$stage" "$overlay"

  [ -f "$GENGP4_PATCH" ] || die "gengp4_patch.exe not found at $GENGP4_PATCH"
  gen_gp4 "$stage" "$GENGP4_PATCH"; gp4="$stage.gp4"
  grep -q '<volume_type>pkg_ps4_patch</volume_type>' "$gp4" \
    || die "gengp4_patch emitted an app volume for $stage"

  log "gp4_proj_update --app_path $(basename "$app_pkg")"
  wine_run "$ORBIS_PUB_CMD" gp4_proj_update --app_path "$(winpath "$app_pkg")" \
    "$(winpath "$gp4")" || die "gp4_proj_update failed for the patch pkg"

  rm -rf "$out"; mkdir -p "$out"
  log "building patch pkg (orbis-pub-cmd img_create --skip_digest)"
  img_create "$out" --oformat pkg --skip_digest --no_progress_bar \
    "$(winpath "$gp4")" "$(winpath "$out")"
  local built; built="$(ls -t "$out"/*.pkg 2>/dev/null | head -1)"
  [ -n "$built" ] || die "patch pkg build failed"

  local final="$OUT_DIR/$(basename "${built%.pkg}")$suffix.pkg"
  # an app and its patch can carry the same version in their names
  [ "$final" != "$app_pkg" ] || final="$OUT_DIR/$(basename "${built%.pkg}")$suffix-patch.pkg"
  mv -f "$built" "$final"
  rm -rf "$parent" "$out"
  PATCH_PKG_RESULT="$final"
}

# ---------------------------------------------------------------------------
# appver_bump <XX.YY> -> the next version
# ---------------------------------------------------------------------------
appver_bump() {
  local maj min
  maj=$(( 10#${1%%.*} )); min=$(( 10#${1##*.} + 1 ))
  [ "$min" -le 99 ] || { maj=$(( maj + 1 )); min=0; }
  printf '%02d.%02d' "$maj" "$min"
}

# ---------------------------------------------------------------------------
# layered_tree <dir>
#   A hardlinked view of the image the console mounts: the base with the update
#   over it. Hardlinks are safe because the backport only reads, writing its
#   copies elsewhere.
# ---------------------------------------------------------------------------
layered_tree() {
  local out="$1"
  rm -rf "$out"
  cp -al "$DUMP" "$out" 2>/dev/null || cp -a "$DUMP" "$out"
  if [ -n "$UPDATE" ] && [ "$UPDATE" != none ]; then
    cp -alf "$UPDATE/." "$out/" 2>/dev/null || cp -af "$UPDATE/." "$out/"
  fi
}
# ---------------------------------------------------------------------------
# run_backport <dest_parent> <tree>...
#   Collect every executable into <dest_parent>/<TITLEID>-bp, restamping any
#   whose SDK sits above the target. Sets BP_DIR to the tree, or "" when nothing
#   needed lowering.
#
#   Pass the layered image, not the dumps it was built from. A base and its
#   update each carry an eboot and only one is ever loaded, so resolving against
#   both lets the unused one raise the floor.
# ---------------------------------------------------------------------------
run_backport() {
  local dest="$1"; shift
  local d rc restamped=0 title
  BP_DIR="" RESOLVED_SDK=""
  if [ "$BACKPORT" -eq 0 ]; then log "backport: skipped (--no-backport)"; return 0; fi
  [ -f "$BACKPORT_SDK" ] || { log "backport: $BACKPORT_SDK not found, skipping"; return 0; }

  title="$(sfo_get "$DUMP/sce_sys/param.sfo" TITLE_ID)"
  [ -n "$title" ] || die "could not read TITLE_ID for the backport tree"
  mkdir -p "$dest"
  # Resolve "auto" once across every tree: a title's base and update share one
  # process, so they have to end up carrying the same stamp.
  local target="$BACKPORT_TARGET_SDK"
  if [ "$target" = auto ]; then
    target="$(python3 "$BACKPORT_SDK" --resolve "$@")" \
      || die "could not resolve an SDK target for $*"
    log "backport: resolved SDK $target"
  fi
  RESOLVED_SDK="$target"
  log "backport: collecting executables at SDK $target"
  for d in "$@"; do
    rc=0
    python3 "$BACKPORT_SDK" --sdk "$target" ${KEEP_VERSION_RECORDS:+--keep-version-records} \
      --out "$dest" "$d" >&2 || rc=$?
    case "$rc" in
      0) restamped=1 ;;
      3) ;;
      *) die "backport-sdk.py failed on $(basename "$d") (exit $rc)" ;;
    esac
  done

  if [ "$restamped" -eq 0 ]; then
    log "backport: every stamp is already at or below $target"
    rm -rf "$dest/$title-bp"
    return 0
  fi
  BP_DIR="$dest/$title-bp"
  [ -d "$BP_DIR" ] || die "backport-sdk.py produced no $title-bp"
}

# ---------------------------------------------------------------------------
# save_stock_binaries <bp_dir> <stage_dir> <dest_dir>
#   Keep the pre-backport copy of everything the backport collected, for builds
#   that overwrite those files inside the package.
# ---------------------------------------------------------------------------
save_stock_binaries() {
  local bp="$1" stage="$2" dest="$3" rel n=0
  rm -rf "$dest"; mkdir -p "$dest"
  while IFS= read -r rel; do
    [ -f "$stage/$rel" ] || continue
    mkdir -p "$dest/$(dirname "$rel")"
    cp -a "$stage/$rel" "$dest/$rel"
    n=$(( n + 1 ))
  done < <(cd "$bp" && find . -type f ! -path './sce_sys/param.sfo' -printf '%P\n')
  log "kept $n stock binaries in $(basename "$dest")"
}

# ---------------------------------------------------------------------------
# build_variant_patch <bp_dir> <app_pkg> <app_ver> [sce_sys_source_tree]
#   A patch carrying only the backported executables, declaring the same APP_VER
#   as the package it sits on so installing it does not change the version the
#   console shows. img_create requires a patch to out-rank the package named by
#   app_path, so it is built one version up and the finished pkg restamped back
#   down. Result in PATCH_PKG_RESULT.
# ---------------------------------------------------------------------------
build_variant_patch() {
  local bp="$1" app_pkg="$2" app_ver="$3"
  local built_ver; built_ver="$(appver_bump "$app_ver")"
  local tag; tag="$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
  local parent="$WORK_DIR/fpkgwork_bp_$tag" out="$WORK_DIR/bppkg_$tag" gp4 p
  local title; title="$(sfo_get "$DUMP/sce_sys/param.sfo" TITLE_ID)"

  rm -rf "$parent" "$out"; mkdir -p "$parent" "$out"
  local stage="$parent/$title-patch"
  cp -al "$bp" "$stage" 2>/dev/null || cp -a "$bp" "$stage"
  # A patch layer only has to carry what it changes: anything it leaves out falls
  # through to the app volume underneath. The stage gets the collected
  # executables plus PATCH_SCE_SYS, taken from the layered image they came from.
  local src_sys="${4:-${UPDATE:-$DUMP}}/sce_sys" keep
  for keep in $PATCH_SCE_SYS; do
    if [ -d "$src_sys/$keep" ]; then
      mkdir -p "$stage/sce_sys/$keep"
      cp -a "$src_sys/$keep/." "$stage/sce_sys/$keep/"
    elif [ -f "$src_sys/$keep" ]; then
      mkdir -p "$stage/sce_sys/$(dirname "$keep")"
      cp -a "$src_sys/$keep" "$stage/sce_sys/$keep"
    fi
  done
  # An executable can live under sce_sys too, so the collected copies go last.
  cp -a "$bp/sce_sys/." "$stage/sce_sys/"
  cp -a "$src_sys/param.sfo" "$stage/sce_sys/param.sfo"
  unlink_executables "$stage"

  gen_gp4 "$stage" "$GENGP4_PATCH"; gp4="$stage.gp4"
  grep -q '<volume_type>pkg_ps4_patch</volume_type>' "$gp4" \
    || die "gengp4_patch emitted an app volume for $stage"

  log "gp4_proj_update --app_path $(basename "$app_pkg")"
  wine_run "$ORBIS_PUB_CMD" gp4_proj_update --app_path "$(winpath "$app_pkg")" \
    "$(winpath "$gp4")" || die "gp4_proj_update failed for the backport patch"

  p="$stage/sce_sys/param.sfo"
  log "SFO: CATEGORY=gp, TARGET_APP_VER=$app_ver, APP_VER=$built_ver"
  sfo_edit -s str CATEGORY gp -s str TARGET_APP_VER "$app_ver" \
    -s str APP_VER "$built_ver" "$p"

  log "building backport patch (img_create --skip_digest)"
  img_create "$out" --oformat pkg --skip_digest --no_progress_bar \
    "$(winpath "$gp4")" "$(winpath "$out")"
  local built; built="$(ls -t "$out"/*.pkg 2>/dev/null | head -1)"
  [ -n "$built" ] || die "backport patch build failed"

  [ -f "$PKG_SET_APPVER" ] || die "pkg-set-appver.py not found at $PKG_SET_APPVER"
  # A patch inherits SYSTEM_VER from the package --app_path names, so unlike an
  # app volume it does not pick up the lowered stamps from its own executables.
  local sysver=""
  [ -z "$RESOLVED_SDK" ] || sysver="$(printf '0x%08x' \
    $(( RESOLVED_SDK & 0xFFFFF000 )))"
  log "restamping the patch to APP_VER $app_ver${sysver:+, SYSTEM_VER $sysver}"
  python3 "$PKG_SET_APPVER" "$built" "$app_ver" ${sysver:+"$sysver"} >&2 \
    || die "could not restamp the backport patch to $app_ver"

  local stem; stem="$(basename "${built%.pkg}")"
  local final="$OUT_DIR/${stem/-A${built_ver//./}-/-A${app_ver//./}-}-bp.pkg"
  mv -f "$built" "$final"
  if [ -n "${KEEP_STAGE:-}" ]; then
    log "kept the patch stage at $parent"
  else
    rm -rf "$parent" "$out"
  fi
  PATCH_PKG_RESULT="$final"
}

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
build_one_dlc() {
  local ac="$1"
  [ -f "$ac/sce_sys/param.sfo" ] || die "dlc: $ac has no sce_sys/param.sfo (re-dump with a recent ftpdump)"
  local cid cat
  cid="$(sfo_get "$ac/sce_sys/param.sfo" CONTENT_ID)"
  cat="$(sfo_get "$ac/sce_sys/param.sfo" CATEGORY)"
  [ -n "$cid" ] || die "dlc: could not read CONTENT_ID from $ac"
  [ "$cat" = "ac" ] || log "dlc: warning: $ac CATEGORY is '$cat' (expected 'ac')"
  log "dlc: building add-on pkg for $cid"

  local tag; tag="$(printf '%s' "$cid" | tr -c 'A-Za-z0-9_-' '_')"
  local stage="$WORK_DIR/fpkgwork_dlc_$tag"
  local gp4="$WORK_DIR/dlc_$tag.gp4"
  rm -rf "$stage"; rm -f "$gp4"

  # 1. hardlinked stage of the DLC tree (never touch the original dump).
  #    Bulk content is hardlinked (fast, no extra space), but sce_sys is
  #    re-copied as REAL files: gengp4_app rewrites param.sfo in place, and a
  #    hardlink would write straight through to the original dump.
  cp -al "$ac" "$stage" 2>/dev/null || cp -a "$ac" "$stage"
  rm -rf "$stage/sce_sys"; cp -a "$ac/sce_sys" "$stage/sce_sys"

  # 2. make the staged sfo look like an app so gengp4_app can scan it. CATEGORY
  #    alone is not enough; it also needs the app keys an ac sfo lacks.
  local real_sfo="$stage/sce_sys/param.sfo"
  cp "$real_sfo" "$real_sfo.real"
  "$SFO_TOOL" -s str CATEGORY gd -s int APP_TYPE 1 -s str APP_VER 01.00 \
    -s int SYSTEM_VER 0x03110000 "$real_sfo" >/dev/null 2>&1 \
    || die "dlc: could not build scan decoy sfo for $cid"

  # 3. scan -> file list (gengp4_app writes <stage>.gp4 and edits the decoy)
  local scan="$stage.gp4"; rm -f "$scan"
  ( cd "$(dirname "$stage")" && wine_run "$GENGP4_APP" "$(winpath "$stage")" ) || true
  [ -f "$scan" ] || die "dlc: gengp4 scan failed for $cid"

  # 4. restore the real ac param.sfo in the stage; remove the decoy backup
  mv -f "$real_sfo.real" "$real_sfo"

  # 5. ac_data project + splice the scanned file list
  wine_run "$ORBIS_PUB_CMD" gp4_proj_create \
    --volume_type pkg_ps4_ac_data --content_id "$cid" \
    --passcode "$FAKE_PASSCODE" --entitlement_key "$DLC_ENT_KEY" \
    "$(winpath "$gp4")" >/dev/null 2>&1 || die "dlc: gp4_proj_create failed for $cid"

  # Splice the scanned file list into the ac project: gp4_proj_create emits an
  # empty '<files img_no="0"/>' + '<rootdir/>' pair; replace them with the scan's
  # populated <files>..</rootdir>. Drop the transient decoy-backup entry
  # (param.sfo.real, which existed in sce_sys during the scan).
  local frag; frag="$(mktemp)"
  sed -n '/<files/,/<\/rootdir>/p' "$scan" | grep -v 'param\.sfo\.real' > "$frag"
  grep -q '<files' "$frag" || die "dlc: scan produced no file list for $cid"
  # read $frag in after the <files.../> placeholder, then delete both placeholders
  sed -e "/<files img_no=\"0\"\/>/{r $frag" -e "d}" -e "/<rootdir\/>/d" \
    "$gp4" > "$gp4.tmp" && mv "$gp4.tmp" "$gp4"
  rm -f "$frag" "$scan"

  # 6. build
  log "dlc: img_create ($cid)"
  img_create "$OUT_DIR" --oformat pkg --no_progress_bar \
    "$(winpath "$gp4")" "$(winpath "$OUT_DIR")"

  local pkg; pkg="$(ls -t "$OUT_DIR"/"$cid"-*.pkg 2>/dev/null | head -1)"
  [ -n "$pkg" ] || die "dlc: no pkg produced for $cid"
  rm -rf "$stage" "$gp4"
  log "dlc: done: $pkg"
  echo "$pkg"
}

# ---------------------------------------------------------------------------
# build_one_al <al_content_dir>
#   Build a pkg_ps4_ac_nodata (unlocker) pkg from one "*-al" dir. These come
#   from the entitlement database and carry no content, just sce_sys/param.sfo
#   plus an optional icon0.png, so there is no tree to scan: the file list is
#   written directly and gengp4_app is not involved.
# ---------------------------------------------------------------------------
build_one_al() {
  local al="$1"
  [ -f "$al/sce_sys/param.sfo" ] || die "dlc: $al has no sce_sys/param.sfo"
  local cid cat
  cid="$(sfo_get "$al/sce_sys/param.sfo" CONTENT_ID)"
  cat="$(sfo_get "$al/sce_sys/param.sfo" CATEGORY)"
  [ -n "$cid" ] || die "dlc: could not read CONTENT_ID from $al"
  [ "$cat" = "ac" ] || log "dlc: warning: $al CATEGORY is '$cat' (expected 'ac')"
  log "dlc: building unlocker pkg for $cid"

  local tag; tag="$(printf '%s' "$cid" | tr -c 'A-Za-z0-9_-' '_')"
  local stage="$WORK_DIR/fpkgwork_al_$tag"
  rm -rf "$stage"
  mkdir -p "$stage/sce_sys" || die "dlc: could not stage $cid"
  cp "$al/sce_sys/param.sfo" "$stage/sce_sys/param.sfo"
  local have_icon=0
  if [ -f "$al/sce_sys/icon0.png" ]; then
    cp "$al/sce_sys/icon0.png" "$stage/sce_sys/icon0.png"
    have_icon=1
  fi

  # The project sits beside sce_sys and img_create runs from there, so the
  # file entries need no orig_path.
  local gp4="$stage/unlocker.gp4"
  wine_run "$ORBIS_PUB_CMD" gp4_proj_create \
    --volume_type pkg_ps4_ac_nodata --content_id "$cid" \
    --passcode "$FAKE_PASSCODE" --entitlement_key "$DLC_ENT_KEY" \
    "$(winpath "$gp4")" >/dev/null 2>&1 || die "dlc: gp4_proj_create failed for $cid"

  local frag; frag="$(mktemp)"
  {
    echo '  <files img_no="0">'
    echo '    <file targ_path="sce_sys/param.sfo"/>'
    [ "$have_icon" -eq 1 ] && echo '    <file targ_path="sce_sys/icon0.png"/>'
    echo '  </files>'
    echo '  <rootdir>'
    echo '    <dir targ_name="sce_sys"/>'
    echo '  </rootdir>'
  } > "$frag"
  sed -e "/<files img_no=\"0\"\/>/{r $frag" -e "d}" -e "/<rootdir\/>/d" \
    "$gp4" > "$gp4.tmp" && mv "$gp4.tmp" "$gp4"
  rm -f "$frag"

  log "dlc: img_create ($cid)"
  ( cd "$stage" && img_create "$OUT_DIR" --oformat pkg \
    --no_progress_bar "$(winpath "$gp4")" "$(winpath "$OUT_DIR")" ) || true

  local pkg; pkg="$(ls -t "$OUT_DIR"/"$cid"-*.pkg 2>/dev/null | head -1)"
  [ -n "$pkg" ] || die "dlc: no pkg produced for $cid"
  rm -rf "$stage"
  log "dlc: done: $pkg"
  echo "$pkg"
}

# ---------------------------------------------------------------------------
# build_dlc_pkgs
#   Build a pkg for every "*-ac" (data) and "*-al" (unlocker) dir across all
#   DLC_DIRS. No-op if none.
# ---------------------------------------------------------------------------
# ac_data vs ac_nodata is a declaration, not a property of the files: the -ac/-al
# suffix is what the console reported. Sniffing is a fallback for other names;
# param.sfx and *.gp4 are dump byproducts, not content.
build_one_addon() {
  case "$1" in
    *-ac) build_one_dlc "$1"; return ;;
    *-al) build_one_al  "$1"; return ;;
  esac
  if [ -n "$(find "$1" -mindepth 1 -maxdepth 1 \
               ! -name sce_sys ! -name param.sfx ! -name '*.gp4' -print -quit)" ]; then
    log "dlc: $(basename "$1"): no -ac/-al suffix, treating as ac_data (has content)"
    build_one_dlc "$1"
  else
    log "dlc: $(basename "$1"): no -ac/-al suffix, treating as ac_nodata (no content)"
    build_one_al "$1"
  fi
}

build_dlc_pkgs() {
  local dd sub any=0
  for sub in ${DLC_ITEMS[@]+"${DLC_ITEMS[@]}"}; do
    build_one_addon "$sub"; any=1
  done
  for dd in ${DLC_DIRS[@]+"${DLC_DIRS[@]}"}; do
    while IFS= read -r sub; do
      [ -f "$sub/sce_sys/param.sfo" ] || continue
      [ "$(sfo_get "$sub/sce_sys/param.sfo" CATEGORY)" = "ac" ] || continue
      build_one_addon "$sub"; any=1
    done < <(find "$dd" -mindepth 1 -maxdepth 1 -type d | sort)
  done
  [ "$any" -eq 1 ] || [ "${#DLC_DIRS[@]}" -eq 0 ] || \
    log "dlc: no add-on (CATEGORY=ac) dirs found under: ${DLC_DIRS[*]}"
}

# ===========================================================================
# ADD-ONS ONLY (no base app dump given)
# ===========================================================================
if [ "$BUILD_APP" -eq 0 ]; then
  build_dlc_pkgs
  exit 0
fi

# ===========================================================================
# BACKPORT ONLY (--base-pkg): a patch for a base package that already exists.
# The dumps supply the executables; the pkg supplies the identity the patch has
# to marry, so its CONTENT_ID and APP_VER are read from it rather than guessed.
# ===========================================================================
if [ -n "$BASE_PKG_IN" ]; then
  [ -f "$BASE_PKG_IN" ] || die "--base-pkg: no such file: $BASE_PKG_IN"
  BASE_PKG_IN="$(cd "$(dirname "$BASE_PKG_IN")" && pwd)/$(basename "$BASE_PKG_IN")"
  PKG_CID="$("$SFO_TOOL" -q CONTENT_ID "$BASE_PKG_IN" 2>/dev/null || true)"
  PKG_APPVER="$("$SFO_TOOL" -q APP_VER "$BASE_PKG_IN" 2>/dev/null || true)"
  [ -n "$PKG_CID" ] || die "--base-pkg: could not read CONTENT_ID from $(basename "$BASE_PKG_IN")"
  [ -n "$PKG_APPVER" ] || die "--base-pkg: could not read APP_VER from $(basename "$BASE_PKG_IN")"
  [ "$PKG_CID" = "$CONTENT_ID" ] \
    || die "--base-pkg is $PKG_CID but the dumps are $CONTENT_ID; a patch only marries its own base"
  log "base pkg   : $(basename "$BASE_PKG_IN")  ($PKG_CID, APP_VER=$PKG_APPVER)"
  [ "$BACKPORT" -eq 1 ] || die "--base-pkg with --no-backport would build nothing"

  LAYERED="$WORK_DIR/fpkglayer_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
  layered_tree "$LAYERED"
  run_backport "$WORK_DIR" "$LAYERED"
  [ -n "$BP_DIR" ] || die "no executable needed restamping for $BACKPORT_TARGET_SDK"
  build_variant_patch "$BP_DIR" "$BASE_PKG_IN" "$PKG_APPVER" "$LAYERED"
  rm -rf "$LAYERED"
  BP_PATCH_PKG="$PATCH_PKG_RESULT"
  rm -rf "$BP_DIR"
  log "backport patch: $BP_PATCH_PKG"
  ls -la "$BP_PATCH_PKG" >&2
  echo "$BP_PATCH_PKG"
  exit 0
fi

# ===========================================================================
# BASE-ONLY build: one app pkg, with a backport either as its own patch or, under
# --remaster, baked in.
# ===========================================================================
if [ -z "$UPDATE" ]; then
  STAGE="$WORK_DIR/fpkgwork_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
  stage_tree "$STAGE" ""

  run_backport "$WORK_DIR" "$STAGE"
  if [ -n "$BP_DIR" ] && [ "$MODE" = "remaster" ]; then
    save_stock_binaries "$BP_DIR" "$STAGE" "$OUT_DIR/$TITLE_ID-stock"
    log "baking the backported executables into the app pkg"
    cp -a "$BP_DIR/." "$STAGE/"
    rm -rf "$BP_DIR"; BP_DIR=""
  fi

  gen_gp4 "$STAGE"; GP4="$STAGE.gp4"
  log "building pkg (orbis-pub-cmd img_create)"
  img_create "$OUT_DIR" --oformat pkg --no_progress_bar \
    "$(winpath "$GP4")" "$(winpath "$OUT_DIR")"
  PKG="$(ls -t "$OUT_DIR"/*.pkg 2>/dev/null | head -1)"
  [ -n "$PKG" ] || die "no pkg produced"
  rm -f "$GP4"
  log "app pkg: $PKG"

  if [ -n "$BP_DIR" ]; then
    build_variant_patch "$BP_DIR" "$PKG" "$BASE_APPVER" "$STAGE"
    BP_PATCH_PKG="$PATCH_PKG_RESULT"
    rm -rf "$BP_DIR"
    log "backport patch: $BP_PATCH_PKG"
  fi
  rm -rf "$STAGE"

  ls -la "$PKG" ${BP_PATCH_PKG:+"$BP_PATCH_PKG"} >&2
  echo "$PKG"
  [ -z "${BP_PATCH_PKG:-}" ] || printf '%s\n' "$BP_PATCH_PKG"
  build_dlc_pkgs                     # separate add-on pkg(s), if any DLC
  exit 0
fi

# ===========================================================================
# SEPARATE (--separate): app pkg and update pkg as their own packages, the way
# retail ships them, then a backported patch if the dumps ask for a newer SDK
# than the target firmware provides.
#
# That backport patch is the whole update tree with the restamped executables
# overlaid: the console replaces the entire patch layer, so a handful of files on
# their own would drop the rest of the update.
# ===========================================================================
if [ "$MODE" = "separate" ]; then
  log "separate build: app + update as individual pkgs"

  STAGE="$WORK_DIR/fpkgwork_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
  stage_tree "$STAGE" ""
  gen_gp4 "$STAGE"; GP4="$STAGE.gp4"
  log "building app pkg (orbis-pub-cmd img_create)"
  img_create "$OUT_DIR" --oformat pkg --no_progress_bar \
    "$(winpath "$GP4")" "$(winpath "$OUT_DIR")"
  APP_PKG="$(ls -t "$OUT_DIR"/*.pkg 2>/dev/null | head -1)"
  [ -n "$APP_PKG" ] || die "app pkg build failed"
  rm -rf "$STAGE" "$GP4"
  log "app pkg  : $APP_PKG"

  build_patch_pkg "$UPDATE" "$APP_PKG" ""
  PATCH_PKG="$PATCH_PKG_RESULT"
  log "patch pkg: $PATCH_PKG"

  # 3. backport pass over the layered image, the way the console mounts it
  LAYERED="$WORK_DIR/fpkglayer_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
  layered_tree "$LAYERED"
  run_backport "$WORK_DIR" "$LAYERED"
  rm -rf "$LAYERED"

  # 4. second patch built from the restamped binaries
  if [ -n "$BP_DIR" ]; then
    log "backport: building a second patch from $(basename "$BP_DIR")"
    build_patch_pkg "$UPDATE" "$APP_PKG" "-bp" "$BP_DIR"
    BP_PATCH_PKG="$PATCH_PKG_RESULT"
    rm -rf "$BP_DIR"
    log "backported patch: $BP_PATCH_PKG"
  fi

  ls -la "$APP_PKG" "$PATCH_PKG" ${BP_PATCH_PKG:+"$BP_PATCH_PKG"} >&2
  printf '%s\n%s\n' "$APP_PKG" "$PATCH_PKG"
  [ -z "${BP_PATCH_PKG:-}" ] || printf '%s\n' "$BP_PATCH_PKG"

  build_dlc_pkgs
  exit 0
fi

UPDATE_APPVER="$(sfo_get "$UPDATE/sce_sys/param.sfo" APP_VER)"
BASE_CAT="$(sfo_get "$DUMP/sce_sys/param.sfo" CATEGORY)"
[ -n "$UPDATE_APPVER" ] || die "could not read update APP_VER"
STAGE="$WORK_DIR/fpkgwork_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"

# ===========================================================================
# REMASTER (--remaster): base + update merged into one pkg_ps4_remaster. A
# remaster supersedes the whole application and cannot be patched afterwards, so
# a backport has to be baked in.
#
# The throwaway base pkg exists only to be named by --app_path, which is what
# lets the tool accept an elevated APP_VER on a remaster volume.
# ===========================================================================
if [ "$MODE" = "remaster" ]; then
  log "merge (remaster): base_cat=$BASE_CAT  app_ver=$UPDATE_APPVER"

  BASE_OUT="$WORK_DIR/.basepkg_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
  rm -rf "$BASE_OUT"; mkdir -p "$BASE_OUT"
  BASE_STAGE="$WORK_DIR/fpkgwork_base_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
  log "building base pkg (for --app_path reference)"
  stage_tree "$BASE_STAGE" ""              # base only, no overlay
  gen_gp4 "$BASE_STAGE"; BASE_GP4="$BASE_STAGE.gp4"
  img_create "$BASE_OUT" --oformat pkg --no_progress_bar \
    "$(winpath "$BASE_GP4")" "$(winpath "$BASE_OUT")"
  BASE_PKG="$(ls -t "$BASE_OUT"/*.pkg 2>/dev/null | head -1)"
  [ -n "$BASE_PKG" ] || die "base pkg build failed"
  rm -rf "$BASE_STAGE" "$BASE_GP4"

  stage_tree "$STAGE" overlay

  run_backport "$WORK_DIR" "$STAGE"
  if [ -n "$BP_DIR" ]; then
    save_stock_binaries "$BP_DIR" "$STAGE" "$OUT_DIR/$TITLE_ID-stock"
    log "baking the backported executables into the remaster"
    cp -a "$BP_DIR/." "$STAGE/"
    rm -rf "$BP_DIR"
  fi

  gen_gp4 "$STAGE"; GP4="$STAGE.gp4"
  sed -i 's|<volume_type>pkg_ps4_app</volume_type>|<volume_type>pkg_ps4_remaster</volume_type>|' "$GP4"

  log "gp4_proj_update --app_path <base pkg>"
  wine_run "$ORBIS_PUB_CMD" gp4_proj_update --app_path "$(winpath "$BASE_PKG")" \
    "$(winpath "$GP4")" || die "gp4_proj_update failed"

  # gengp4 and gp4_proj_update both rewrite param.sfo, so identity is set after.
  P="$STAGE/sce_sys/param.sfo"
  log "SFO: CATEGORY=$BASE_CAT, REMASTER_TYPE=1, APP_VER=$UPDATE_APPVER, VERSION=01.00"
  sfo_edit -e CATEGORY "$BASE_CAT" "$P"
  sfo_edit -d TARGET_APP_VER "$P"                    # patch-only key
  sfo_edit -a int REMASTER_TYPE 0x00000001 "$P"
  sfo_edit -e APP_VER "$UPDATE_APPVER" "$P"
  sfo_edit -e VERSION 01.00 "$P"

  log "building remaster pkg (orbis-pub-cmd img_create --skip_digest)"
  img_create "$OUT_DIR" --oformat pkg --skip_digest --no_progress_bar \
    "$(winpath "$GP4")" "$(winpath "$OUT_DIR")"

  PKG="$(ls -t "$OUT_DIR"/*.pkg 2>/dev/null | head -1)"
  [ -n "$PKG" ] || die "no pkg produced"

  rm -rf "$STAGE" "$GP4" "$BASE_OUT"
  log "done: $PKG"
  ls -la "$PKG" >&2
  echo "$PKG"

  build_dlc_pkgs                     # separate add-on pkg(s), if any DLC
  exit 0
fi

# ===========================================================================
# APP-MERGE (default): base + update merged into a single pkg_ps4_app carrying
# the update's APP_VER. The patch layer stays free, so a backport ships as its
# own patch declaring that same APP_VER.
# ===========================================================================
log "merge (app): base_cat=$BASE_CAT  app_ver=$UPDATE_APPVER"

stage_tree "$STAGE" overlay

# Before gen_gp4 and img_create: gengp4 rewrites param.sfo and img_create
# fake-signs the executables where they lie, and the backport wants the plain
# ELFs the console would load.
run_backport "$WORK_DIR" "$STAGE"

gen_gp4 "$STAGE"; GP4="$STAGE.gp4"

P="$STAGE/sce_sys/param.sfo"
log "SFO: CATEGORY=$BASE_CAT, APP_VER=$UPDATE_APPVER, VERSION=01.00"
sfo_edit -e CATEGORY "$BASE_CAT" "$P"
sfo_edit -d TARGET_APP_VER "$P"                      # patch-only key
sfo_edit -e APP_VER "$UPDATE_APPVER" "$P"
sfo_edit -e VERSION 01.00 "$P"

log "building merged app pkg (img_create --skip_digest)"
# Built into an empty directory of its own: OUT_DIR usually holds packages from
# earlier runs, and picking the newest of those hides a failed build.
APP_OUT="$WORK_DIR/apppkg_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
rm -rf "$APP_OUT"; mkdir -p "$APP_OUT"
img_create "$APP_OUT" --oformat pkg --skip_digest \
  --no_progress_bar "$(winpath "$GP4")" "$(winpath "$APP_OUT")"
PKG="$(ls -t "$APP_OUT"/*.pkg 2>/dev/null | head -1)"
[ -n "$PKG" ] || die "no pkg produced"
mv "$PKG" "$OUT_DIR/" || die "could not move $PKG to $OUT_DIR"
PKG="$OUT_DIR/$(basename "$PKG")"
rmdir "$APP_OUT" 2>/dev/null
rm -f "$GP4"
log "merged app pkg: $PKG"

if [ -n "$BP_DIR" ]; then
  build_variant_patch "$BP_DIR" "$PKG" "$UPDATE_APPVER" "$STAGE"
  BP_PATCH_PKG="$PATCH_PKG_RESULT"
  rm -rf "$BP_DIR"
  log "backport patch: $BP_PATCH_PKG"
fi
rm -rf "$STAGE"

ls -la "$PKG" ${BP_PATCH_PKG:+"$BP_PATCH_PKG"} >&2
echo "$PKG"
[ -z "${BP_PATCH_PKG:-}" ] || printf '%s\n' "$BP_PATCH_PKG"

build_dlc_pkgs                       # separate add-on pkg(s), if any DLC
