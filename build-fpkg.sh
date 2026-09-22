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
# USAGE
#   build-fpkg.sh [options] <base_dump_dir>
#     --content-id CID   pkg content id (default: read from base param.sfo)
#     --update DIR       explicit update/patch dump to merge onto the base
#     --no-update        base-only; do not auto-merge a sibling patch
#     --keystone MODE    retail (default) | kscreate
#     --ps2-tid NNNNN    force the 5-digit PS2 serial for emu auth
#                        (default: auto-derived from CONTENT_ID for PS2 titles)
#     --out DIR          output directory (default: cwd)
#
#   By default, if the base dump dir is named "<foo>-app", the script looks for
#   a sibling "<foo>-patch" and merges it automatically. Pass --no-update to
#   build the base alone, or --update DIR to point at a patch elsewhere.
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
WINE_OVERRIDES="wineps.drv,localspl.dll,spoolss.dll=d"

# PS2-emu auth-info templates (authinfo_emu.txt, FW=501). The first 2 bytes
# (4 hex chars) are replaced with the PS2 title-id decimal bytes.
EBOOT_AUTH_TMPL="0000C2AC03000034000000008003002000FF00000000002000000000000000000000000000000000000080C000400040000000000000004002000000000080000040FFFF000000F000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
COMPILER_AUTH_TMPL="0000C2AC03000034000000008003002000FF00000000004000000000000000000000000000000000000080C000400040000000000000004008000000000080000040FFFF000000F000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
PRX_AUTH_TMPL="0000C2AC03000035000000000000000000FF000000000000000000000000000000000000000000000000004000300030000000000000004000000000000080000040FFFF000000F000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

die() { echo "error: $*" >&2; exit 1; }
log() { echo ">> $*" >&2; }
wine_run() { WINEDEBUG=-all WINEDLLOVERRIDES="$WINE_OVERRIDES" wine "$@"; }
winpath() { winepath -w "$1"; }
sfo_get() { "$SFO_TOOL" "$1" -q "$2" 2>/dev/null | tr -d '\r\n'; }
sfo_edit() { "$SFO_TOOL" "$@" >/dev/null 2>&1 || true; }

# --- args ------------------------------------------------------------------
# UPDATE: "" = auto-discover sibling "-patch" dir; "none" = base-only;
#         a path = explicit update dir.
CONTENT_ID="" UPDATE="" DUMP="" OUT_DIR="$PWD" KEYSTONE_MODE="retail" PS2_TID=""
while [ $# -gt 0 ]; do
  case "$1" in
    --content-id) CONTENT_ID="${2:?}"; shift 2 ;;
    --update)     UPDATE="${2%/}"; shift 2 ;;
    --no-update)  UPDATE="none"; shift ;;
    --keystone)   KEYSTONE_MODE="${2:?}"; shift 2 ;;
    --ps2-tid)    PS2_TID="${2:?}"; shift 2 ;;
    --out)        OUT_DIR="${2:?}"; shift 2 ;;
    -h|--help)    grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)           die "unknown option: $1" ;;
    *)            DUMP="${1%/}"; shift ;;
  esac
done

[ -n "$DUMP" ] && [ -d "$DUMP" ] || die "base dump dir required"
[ -f "$DUMP/sce_sys/param.sfo" ] || die "dump missing sce_sys/param.sfo"
[ -f "$DUMP/eboot.bin" ] || die "dump missing eboot.bin"
case "$KEYSTONE_MODE" in kscreate|retail) ;; *) die "--keystone must be kscreate or retail" ;; esac
command -v wine >/dev/null || die "wine not found"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
DUMP="$(cd "$DUMP" && pwd)"

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

[ -n "$CONTENT_ID" ] || CONTENT_ID="$(sfo_get "$DUMP/sce_sys/param.sfo" CONTENT_ID)"
[ -n "$CONTENT_ID" ] || die "could not determine CONTENT_ID"

# --- detect PS2 classic ----------------------------------------------------
# Signal: the PS2 emulator compiler self is present (backed by EMU_VER).
IS_PS2=0
if [ -f "$DUMP/ps2-emu-compiler.self" ]; then IS_PS2=1; fi
[ -n "$(sfo_get "$DUMP/sce_sys/param.sfo" EMU_VER)" ] && IS_PS2=1

if [ "$IS_PS2" -eq 1 ] && [ -z "$PS2_TID" ]; then
  # CONTENT_ID tail segment holds the disc serial, e.g.
  #   UP9000-CUSA01724_00-SCUS971050000001  ->  SCUS 97105  ->  ps2-tid 97105
  serial="${CONTENT_ID##*-}"                 # SCUS971050000001
  PS2_TID="$(printf '%s' "$serial" | sed -E 's/^[A-Z]{4}([0-9]{5}).*/\1/')"
  [ "${#PS2_TID}" -eq 5 ] || die "could not derive PS2 title id from CONTENT_ID ($CONTENT_ID); pass --ps2-tid"
fi

log "content id : $CONTENT_ID"
log "type       : $([ "$IS_PS2" -eq 1 ] && echo "PS2 classic (ps2-tid=$PS2_TID)" || echo "normal PS4")"
log "update     : ${UPDATE:-<none>}"
log "keystone   : $KEYSTONE_MODE"

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
  cp -al "$DUMP" "$stage" 2>/dev/null || cp -a "$DUMP" "$stage"
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
# gen_gp4 <stage_dir> -> echoes gp4 path
# ---------------------------------------------------------------------------
gen_gp4() {
  local stage="$1" gp4="$1.gp4"
  rm -f "$gp4"
  ( cd "$(dirname "$stage")" && wine_run "$GENGP4_APP" "$(winpath "$stage")" ) || true
  [ -f "$gp4" ] || die "gengp4 did not produce $gp4"
  echo "$gp4"
}

# ===========================================================================
# BASE-ONLY build
# ===========================================================================
if [ -z "$UPDATE" ]; then
  STAGE="$OUT_DIR/fpkgwork_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
  stage_tree "$STAGE" ""
  GP4="$(gen_gp4 "$STAGE")"
  log "building pkg (orbis-pub-cmd img_create)"
  wine_run "$ORBIS_PUB_CMD" img_create --oformat pkg --no_progress_bar \
    "$(winpath "$GP4")" "$(winpath "$OUT_DIR")" || true
  PKG="$(ls -t "$OUT_DIR"/*.pkg 2>/dev/null | head -1)"
  [ -n "$PKG" ] || die "no pkg produced"
  rm -rf "$STAGE" "$GP4"
  log "done: $PKG"
  ls -la "$PKG" >&2
  echo "$PKG"
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
BASE_OUT="$OUT_DIR/.basepkg_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
rm -rf "$BASE_OUT"; mkdir -p "$BASE_OUT"
BASE_STAGE="$OUT_DIR/fpkgwork_base_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
log "building base pkg (for --app_path reference)"
stage_tree "$BASE_STAGE" ""              # base only, no overlay
BASE_GP4="$(gen_gp4 "$BASE_STAGE")"
wine_run "$ORBIS_PUB_CMD" img_create --oformat pkg --no_progress_bar \
  "$(winpath "$BASE_GP4")" "$(winpath "$BASE_OUT")" || true
BASE_PKG="$(ls -t "$BASE_OUT"/*.pkg 2>/dev/null | head -1)"
[ -n "$BASE_PKG" ] || die "base pkg build failed"
rm -rf "$BASE_STAGE" "$BASE_GP4"

# 2. staged merged tree
STAGE="$OUT_DIR/fpkgwork_$(printf '%s' "$CONTENT_ID" | tr -c 'A-Za-z0-9_-' '_')"
stage_tree "$STAGE" overlay

# 3. gengp4 + remaster volume
GP4="$(gen_gp4 "$STAGE")"
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
