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
# MERGE (--update DIR): builds base+update into one standalone pkg, as a
# REMASTER, so the updated version displays in the UI. This mirrors the Windows
# "Merge Game + Update" flow, which is the only way this CyB1K orbis-pub-cmd
# will emit APP_VER != 01.00:
#   1. build the BASE pkg first (used as the --app_path reference)
#   2. overlay the update tree on the base (update wins)
#   3. gengp4, then set volume_type = pkg_ps4_remaster
#   4. gp4_proj_update --app_path <base.pkg>   (lets it accept the elevated ver)
#   5. SFO: CATEGORY <- base value, add REMASTER_TYPE=1, APP_VER <- update's
#           APP_VER, VERSION <- 01.00 (matches how retail remaster pkgs look)
#   6. img_create --skip_digest
# The update's param.sfo (patch notes changeinfo/changeinfo.xml too) is carried;
# TARGET_APP_VER (patch-only) is dropped. APP_VER is what the console displays.
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
#     --dlc DIR          DLC dump dir (holds one or more "*-ac"/"*-al" content
#                        dirs) to build add-on pkgs from; repeatable. Default:
#                        auto-detect a sibling "<foo>-dlc" dir.
#     --no-dlc           do not build any DLC pkgs
#     --keystone MODE    retail (default) | kscreate
#     --ps2-tid NNNNN    force the 5-digit PS2 serial for emu auth
#                        (default: auto-derived from CONTENT_ID for PS2 titles)
#     --out DIR          output directory (default: cwd)
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
ORBIS_PUB_CMD="${ORBIS_PUB_CMD:-$SDK_DIR/orbis-pub-cmd.exe}"
MAKE_FSELF="${MAKE_FSELF:-$SELF_DIR/make_fself.py}"
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
DLC_MODE="" ; declare -a DLC_DIRS=() DLC_ITEMS=() ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --content-id) CONTENT_ID="${2:?}"; shift 2 ;;
    --update)     UPDATE="${2%/}"; shift 2 ;;
    --no-update)  UPDATE="none"; shift ;;
    --dlc)        DLC_DIRS+=("${2%/}"); DLC_MODE="explicit"; shift 2 ;;
    --no-dlc)     DLC_MODE="none"; shift ;;
    --keystone)   KEYSTONE_MODE="${2:?}"; shift 2 ;;
    --ps2-tid)    PS2_TID="${2:?}"; shift 2 ;;
    --out)        OUT_DIR="${2:?}"; shift 2 ;;
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
}

# ---------------------------------------------------------------------------
# gen_gp4 <stage_dir> -> produces <stage_dir>.gp4
# ---------------------------------------------------------------------------
gen_gp4() {
  local stage="$1" gp4="$1.gp4"
  rm -f "$gp4"
  ( cd "$(dirname "$stage")" && wine_run "$GENGP4_APP" "$(winpath "$stage")" ) || true
  [ -f "$gp4" ] || die "gengp4 did not produce $gp4"
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
  wine_run "$ORBIS_PUB_CMD" img_create --oformat pkg --no_progress_bar \
    "$(winpath "$gp4")" "$(winpath "$OUT_DIR")" || true

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
  ( cd "$stage" && wine_run "$ORBIS_PUB_CMD" img_create --oformat pkg \
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
# BASE-ONLY build
# ===========================================================================
if [ -z "$UPDATE" ]; then
  STAGE="$WORK_DIR/fpkgwork_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
  stage_tree "$STAGE" ""
  gen_gp4 "$STAGE"; GP4="$STAGE.gp4"
  log "building pkg (orbis-pub-cmd img_create)"
  wine_run "$ORBIS_PUB_CMD" img_create --oformat pkg --no_progress_bar \
    "$(winpath "$GP4")" "$(winpath "$OUT_DIR")" || true
  PKG="$(ls -t "$OUT_DIR"/*.pkg 2>/dev/null | head -1)"
  [ -n "$PKG" ] || die "no pkg produced"
  rm -rf "$STAGE" "$GP4"
  log "done: $PKG"
  ls -la "$PKG" >&2
  echo "$PKG"
  build_dlc_pkgs                     # separate add-on pkg(s), if any DLC
  exit 0
fi

# ===========================================================================
# MERGE (base + update) as a REMASTER, so the updated APP_VER displays.
#
# Mirrors the Windows "Merge Game + Update" flow (which we verified is the only
# way this CyB1K orbis-pub-cmd will emit APP_VER != 01.00):
#   1. build the BASE pkg (needed as --app_path reference)
#   2. stage the merged tree
#   3. gengp4, flip volume_type -> pkg_ps4_remaster
#   4. gp4_proj_update --app_path <base.pkg>   (lets the tool accept the version)
#   5. SFO: CATEGORY=base, REMASTER_TYPE=1, APP_VER=<update's>, VERSION=01.00
#   6. img_create --skip_digest
# ===========================================================================
UPDATE_APPVER="$(sfo_get "$UPDATE/sce_sys/param.sfo" APP_VER)"
BASE_CAT="$(sfo_get "$DUMP/sce_sys/param.sfo" CATEGORY)"
[ -n "$UPDATE_APPVER" ] || die "could not read update APP_VER"
log "merge (remaster): base_cat=$BASE_CAT  app_ver=$UPDATE_APPVER"

# 1. base pkg (temp, into a subdir so it isn't confused with the final output)
BASE_OUT="$WORK_DIR/.basepkg_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
rm -rf "$BASE_OUT"; mkdir -p "$BASE_OUT"
BASE_STAGE="$WORK_DIR/fpkgwork_base_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
log "building base pkg (for --app_path reference)"
stage_tree "$BASE_STAGE" ""              # base only, no overlay
gen_gp4 "$BASE_STAGE"; BASE_GP4="$BASE_STAGE.gp4"
wine_run "$ORBIS_PUB_CMD" img_create --oformat pkg --no_progress_bar \
  "$(winpath "$BASE_GP4")" "$(winpath "$BASE_OUT")" || true
BASE_PKG="$(ls -t "$BASE_OUT"/*.pkg 2>/dev/null | head -1)"
[ -n "$BASE_PKG" ] || die "base pkg build failed"
rm -rf "$BASE_STAGE" "$BASE_GP4"

# 2. staged merged tree
STAGE="$WORK_DIR/fpkgwork_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
stage_tree "$STAGE" overlay

# 3. gengp4 + remaster volume
gen_gp4 "$STAGE"; GP4="$STAGE.gp4"
sed -i 's|<volume_type>pkg_ps4_app</volume_type>|<volume_type>pkg_ps4_remaster</volume_type>|' "$GP4"

# 4. point the remaster at the base pkg
log "gp4_proj_update --app_path <base pkg>"
wine_run "$ORBIS_PUB_CMD" gp4_proj_update --app_path "$(winpath "$BASE_PKG")" \
  "$(winpath "$GP4")" || die "gp4_proj_update failed"

# 5. SFO edits LAST (after gengp4/gp4_proj_update, matching the verified order):
#    take update's values (already staged from overlay), fix identity.
P="$STAGE/sce_sys/param.sfo"
log "SFO: CATEGORY=$BASE_CAT, REMASTER_TYPE=1, APP_VER=$UPDATE_APPVER, VERSION=01.00"
sfo_edit -e CATEGORY "$BASE_CAT" "$P"
sfo_edit -d TARGET_APP_VER "$P"                    # patch-only key
sfo_edit -a int REMASTER_TYPE 0x00000001 "$P"
sfo_edit -e APP_VER "$UPDATE_APPVER" "$P"
sfo_edit -e VERSION 01.00 "$P"

# 6. build (skip_digest, as the Windows flow does for merges)
log "building remaster pkg (orbis-pub-cmd img_create --skip_digest)"
wine_run "$ORBIS_PUB_CMD" img_create --oformat pkg --skip_digest --no_progress_bar \
  "$(winpath "$GP4")" "$(winpath "$OUT_DIR")" || true

PKG="$(ls -t "$OUT_DIR"/*.pkg 2>/dev/null | head -1)"
[ -n "$PKG" ] || die "no pkg produced"

rm -rf "$STAGE" "$GP4" "$BASE_OUT"
log "done: $PKG"
ls -la "$PKG" >&2
echo "$PKG"

build_dlc_pkgs                       # separate add-on pkg(s), if any DLC
