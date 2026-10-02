#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLKIT="$SCRIPT_DIR"/drakmor
AUTO_SIZE_PROFILE="sdk279"

SOURCE_FOLDER=""
OUTPUT_PACKAGE=""
REFERENCE_PACKAGE=""
PASSCODE="00000000000000000000000000000000"
PYTHON="python3"
TEMPORARY_DIRECTORY="${LIBPROSPERO_TEMP_DIR:-}"
COMPRESSION_LEVEL=7
CHUNK_COUNT=100
KEEP_INTERMEDIATE=0
FORCE=0
VOLUME=auto
# Games read it back through sceNpEntitlementAccessGetEntitlementKey, and some
# (FF7R) decide which add-on to mount from it. pfsdump saves the real one as
# entitlement_key.dat in the add-on dump; zeroes are the last resort.
ENTITLEMENT_KEY=""
ENTITLEMENT_KEY_FILE="entitlement_key.dat"

usage() {
    echo "Usage: $0 --source-folder <dir> --output-package <file.pkg> [options]"
    echo "Options:"
    echo "  --reference-package <file.pkg>"
    echo "  --passcode <hex>             (default: 00000000000000000000000000000000)"
    echo "  --python <path>             (default: python3)"
    echo "  --temp-dir <dir>            (default: \$LIBPROSPERO_TEMP_DIR)"
    echo "  --compression-level <-4..9> (default: 7)"
    echo "  --chunk-count <1..255>      (default: 100)"
    echo "  --volume <auto|app|ac>      (default: auto; ac when there is no eboot.bin)"
    echo "  --entitlement-key <hex>     add-ons only (default: the source's $ENTITLEMENT_KEY_FILE, else 32 zeroes)"
    echo "  --keep-intermediate"
    echo "  --force"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source-folder|-s) SOURCE_FOLDER="$2"; shift 2 ;;
        --output-package|-o) OUTPUT_PACKAGE="$2"; shift 2 ;;
        --reference-package|-r) REFERENCE_PACKAGE="$2"; shift 2 ;;
        --passcode) PASSCODE="$2"; shift 2 ;;
        --python) PYTHON="$2"; shift 2 ;;
        --temp-dir) TEMPORARY_DIRECTORY="$2"; shift 2 ;;
        --compression-level) COMPRESSION_LEVEL="$2"; shift 2 ;;
        --chunk-count) CHUNK_COUNT="$2"; shift 2 ;;
        --volume) VOLUME="$2"; shift 2 ;;
        --entitlement-key) ENTITLEMENT_KEY="$2"; shift 2 ;;
        --keep-intermediate) KEEP_INTERMEDIATE=1; shift ;;
        --force|-f) FORCE=1; shift ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

if [[ -z "$SOURCE_FOLDER" || -z "$OUTPUT_PACKAGE" ]]; then
    echo "Error: --source-folder and --output-package are required." >&2
    usage
fi

if [[ ! -d "$SOURCE_FOLDER" ]]; then
    echo "SourceFolder does not exist or is not a directory: $SOURCE_FOLDER" >&2
    exit 1
fi
SOURCE_FOLDER="$(realpath "$SOURCE_FOLDER")"

case "$VOLUME" in
    auto) if [[ -f "$SOURCE_FOLDER/eboot.bin" ]]; then VOLUME=app; else VOLUME=ac; fi ;;
    app|ac) ;;
    *) echo "--volume must be auto, app or ac" >&2; exit 1 ;;
esac
echo "Volume: $VOLUME"

if [[ ! -f "$SOURCE_FOLDER/sce_sys/param.json" ]]; then
    echo "Not a PS5 tree, no sce_sys/param.json: $SOURCE_FOLDER" >&2
    exit 1
fi

# Add-ons carry no keystone; the custom-keystone requirement is the app's.
if [[ "$VOLUME" == app ]]; then
    SOURCE_KEYSTONE="$SOURCE_FOLDER/sce_sys/keystone"
    if [[ ! -f "$SOURCE_KEYSTONE" ]]; then
        echo "This custom-keystone toolchain requires: $SOURCE_KEYSTONE" >&2
        exit 1
    fi

    KEYSTONE_SIZE=$(stat -c%s "$SOURCE_KEYSTONE")
    if [[ "$KEYSTONE_SIZE" -ne 96 ]]; then
        echo "The source keystone must be exactly 96 bytes: $SOURCE_KEYSTONE" >&2
        exit 1
    fi
elif [[ -n "$REFERENCE_PACKAGE" ]]; then
    echo "--reference-package applies to application builds only" >&2
    exit 1
else
    KEY_FILE="$SOURCE_FOLDER/$ENTITLEMENT_KEY_FILE"
    if [[ -n "$ENTITLEMENT_KEY" ]]; then
        KEY_SOURCE="--entitlement-key"
    elif [[ -f "$KEY_FILE" ]]; then
        # 16 raw bytes from pfsdump, or 32 hex digits written by hand.
        if [[ "$(stat -c%s "$KEY_FILE")" -eq 16 ]]; then
            ENTITLEMENT_KEY="$(od -An -tx1 -v "$KEY_FILE" | tr -d ' \n')"
        else
            ENTITLEMENT_KEY="$(tr -d '[:space:]' < "$KEY_FILE")"
        fi
        KEY_SOURCE="$KEY_FILE"
    else
        ENTITLEMENT_KEY="00000000000000000000000000000000"
        KEY_SOURCE="default; no $ENTITLEMENT_KEY_FILE in the source"
    fi
    if [[ ! "$ENTITLEMENT_KEY" =~ ^[0-9A-Fa-f]{32}$ ]]; then
        echo "The entitlement key must be 32 hex digits ($KEY_SOURCE)" >&2
        exit 1
    fi
    ENTITLEMENT_KEY="${ENTITLEMENT_KEY^^}"
    echo "Entitlement key: $ENTITLEMENT_KEY ($KEY_SOURCE)"
fi

if [[ "${OUTPUT_PACKAGE,,}" != *.pkg ]]; then
    echo "OutputPackage must be a .pkg path." >&2
    exit 1
fi

FINAL="$(realpath -m "$OUTPUT_PACKAGE")"

REFERENCE=""
if [[ -n "$REFERENCE_PACKAGE" ]]; then
    if [[ ! -f "$REFERENCE_PACKAGE" ]]; then
        echo "ReferencePackage does not exist or is not a file: $REFERENCE_PACKAGE" >&2
        exit 1
    fi
    if [[ "${REFERENCE_PACKAGE,,}" != *.pkg ]]; then
        echo "ReferencePackage must be a .pkg path." >&2
        exit 1
    fi
    REFERENCE="$(realpath "$REFERENCE_PACKAGE")"
    if [[ "$REFERENCE" == "$FINAL" ]]; then
        echo "ReferencePackage and OutputPackage must be different files." >&2
        exit 1
    fi
fi

TOOLKIT_PREFIX="$(realpath "$TOOLKIT")/"
if [[ "$FINAL/" == "$TOOLKIT_PREFIX"* ]]; then
    echo "Build output must be outside the tools-only directory." >&2
    exit 1
fi

OUTPUT_DIRECTORY="$(dirname "$FINAL")"
mkdir -p "$OUTPUT_DIRECTORY"

TEMPORARY_ROOT=""
TEMPORARY_ROOT_CREATED=0
TEMPORARY_BUILD_DIRECTORY=""

if [[ -n "$TEMPORARY_DIRECTORY" ]]; then
    TEMPORARY_DIRECTORY_EXPANDED="$(eval echo "$TEMPORARY_DIRECTORY")"
    TEMPORARY_ROOT="$(realpath -m "$TEMPORARY_DIRECTORY_EXPANDED")"
    if [[ -e "$TEMPORARY_ROOT" ]]; then
        if [[ ! -d "$TEMPORARY_ROOT" ]]; then
            echo "TemporaryDirectory is not a directory: $TEMPORARY_ROOT" >&2
            exit 1
        fi
    else
        mkdir -p "$TEMPORARY_ROOT"
        TEMPORARY_ROOT_CREATED=1
    fi
    RANDOM_UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4().hex)')
    RANDOM_UUID="${RANDOM_UUID//-/}"
    TEMPORARY_BUILD_DIRECTORY="$TEMPORARY_ROOT/libprospero-pkg-$RANDOM_UUID"
fi

STEM="$(basename "$FINAL" .pkg)"
GP5="$OUTPUT_DIRECTORY/$STEM.gp5"
SCENARIO="$OUTPUT_DIRECTORY/$STEM.playgo-scenario.json"
ASSETS="$OUTPUT_DIRECTORY/gp5-assets/$STEM"
PARTIAL="$OUTPUT_DIRECTORY/$STEM.partial.pkg"
PARTIAL_REMASTERED="${PARTIAL}.remastered.pkg"
FINAL_REMASTERED="${FINAL}.remastered.pkg"
METRIC="${PARTIAL}.naps_metric.json"
FINAL_METRIC="${FINAL}.naps_metric.json"
LOG_DIRECTORY="$OUTPUT_DIRECTORY/${STEM}-build-logs"

if [[ "$FINAL" == "$PARTIAL" ]]; then
    echo "OutputPackage name conflicts with the temporary package name." >&2
    exit 1
fi

if [[ -n "$REFERENCE" ]]; then
    GEN_PATHS=("$GP5" "$SCENARIO" "$PARTIAL" "$PARTIAL_REMASTERED" "$METRIC" "$FINAL" "$FINAL_REMASTERED" "$FINAL_METRIC")
    for gen_path in "${GEN_PATHS[@]}"; do
        if [[ "$REFERENCE" == "$(realpath -m "$gen_path")" ]]; then
            echo "ReferencePackage conflicts with a generated output: $gen_path" >&2
            exit 1
        fi
    done

    ASSETS_PATH="$(realpath -m "$ASSETS")"
    ASSETS_PREFIX="${ASSETS_PATH}/"
    if [[ "$REFERENCE" == "$ASSETS_PATH" || "$REFERENCE/" == "$ASSETS_PREFIX"* ]]; then
        echo "ReferencePackage must be outside the generated GP5 assets directory." >&2
        exit 1
    fi
fi

OUTPUTS=("$GP5" "$SCENARIO" "$PARTIAL" "$METRIC" "$FINAL" "$FINAL_METRIC")
if [[ -n "$REFERENCE" ]]; then
    OUTPUTS+=("$PARTIAL_REMASTERED" "$FINAL_REMASTERED")
fi

for path in "${OUTPUTS[@]}"; do
    if [[ -e "$path" ]]; then
        if [[ "$FORCE" -ne 1 ]]; then
            echo "Output already exists: $path (use --force to replace it)" >&2
            exit 1
        fi
        rm -f "$path"
    fi
done

if [[ -d "$ASSETS" ]]; then
    if [[ "$FORCE" -ne 1 ]]; then
        echo "Generated GP5 assets already exist: $ASSETS (use --force to replace them)" >&2
        exit 1
    fi
    rm -rf "$ASSETS"
fi

mkdir -p "$LOG_DIRECTORY"

if [[ -n "$TEMPORARY_BUILD_DIRECTORY" ]]; then
    mkdir -p "$TEMPORARY_BUILD_DIRECTORY"
    export TEMP="$TEMPORARY_BUILD_DIRECTORY"
    export TMP="$TEMPORARY_BUILD_DIRECTORY"
    echo "Temporary build directory: $TEMPORARY_BUILD_DIRECTORY"
fi

echo "[1/2] Creating GP5: $GP5"
GP5_ARGS=(
    "$TOOLKIT/scripts/create-gp5-from-folder.py"
    "$SOURCE_FOLDER"
    "$GP5"
    "--passcode" "$PASSCODE"
    "--absolute-paths"
    "--volume" "$VOLUME"
)

# Keystone, chunk layout and size profile are application-only.
if [[ "$VOLUME" == ac ]]; then
    GP5_ARGS+=("--entitlement-key" "$ENTITLEMENT_KEY")
else
    GP5_ARGS+=("--keep-keystone" "--chunk-count" "$CHUNK_COUNT")
    if [[ -z "$REFERENCE" ]]; then
        GP5_ARGS+=("--auto-size-profile" "$AUTO_SIZE_PROFILE")
    else
        echo "Reference build: preserving source attributePub; unpacked patch size cannot determine remastered size."
    fi
fi

set +e
"$PYTHON" "${GP5_ARGS[@]}" 2>&1 | tee "$LOG_DIRECTORY/01-create-gp5.log"
PY_EXIT="${PIPESTATUS[0]}"
set -e
if [[ "$PY_EXIT" -ne 0 ]]; then
    echo "GP5 creation failed with exit code $PY_EXIT" >&2
    exit 1
fi

sed -i 's/src_path="/src_path="Z:/g' "$GP5"

if [[ -n "$REFERENCE" ]]; then
    echo "[2/2] Building plaintext/no-auth patch against: $REFERENCE"
else
    echo "[2/2] Building final plaintext/no-auth PKG (compression level: $COMPRESSION_LEVEL)"
fi

PUBLISHER="$TOOLKIT/toolchain/prospero-pub-cmd.exe"
SDK_STARTED="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
SDK_STARTED_EPOCH="$(date +%s)"

PUBLISHER_ARGS=("img_create" "--oformat" "nwonly" "--compression_level" "$COMPRESSION_LEVEL")
if [[ -n "$REFERENCE" ]]; then
    PUBLISHER_ARGS+=("--ref_pkg_path" "$REFERENCE")
fi
PUBLISHER_ARGS+=("$GP5" "$PARTIAL")

wine "$PUBLISHER" "${PUBLISHER_ARGS[@]}"
SDK_EXIT_CODE=$?

SDK_FINISHED="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
SDK_FINISHED_EPOCH="$(date +%s)"
ELAPSED=$(( SDK_FINISHED_EPOCH - SDK_STARTED_EPOCH ))

LOGGED_COMMAND=""
for arg in "${PUBLISHER_ARGS[@]}"; do
    if [[ "$arg" =~ [[:space:]\"] ]]; then
        LOGGED_COMMAND+="\"${arg//\"/\\\"}\" "
    else
        LOGGED_COMMAND+="$arg "
    fi
done

cat <<EOF > "$LOG_DIRECTORY/02-img-create.log"
command=${LOGGED_COMMAND% }
started_utc=$SDK_STARTED
finished_utc=$SDK_FINISHED
elapsed=${ELAPSED}s
exit_code=$SDK_EXIT_CODE
EOF

if [[ "$SDK_EXIT_CODE" -ne 0 ]]; then
    echo "PKG creation failed with exit code $SDK_EXIT_CODE" >&2
    exit 1
fi

if [[ -n "$REFERENCE" && ! -f "$PARTIAL_REMASTERED" ]]; then
    echo "Publisher did not create the expected remastered package: $PARTIAL_REMASTERED" >&2
    exit 1
fi

mv "$PARTIAL" "$FINAL"
if [[ -n "$REFERENCE" ]]; then
    mv "$PARTIAL_REMASTERED" "$FINAL_REMASTERED"
fi
if [[ "$KEEP_INTERMEDIATE" -eq 1 && -f "$METRIC" ]]; then
    mv "$METRIC" "$FINAL_METRIC"
fi

if [[ "$KEEP_INTERMEDIATE" -ne 1 ]]; then
    if [[ -n "$TEMPORARY_BUILD_DIRECTORY" ]]; then
        RESOLVED_TEMP_BUILD="$(realpath "$TEMPORARY_BUILD_DIRECTORY")"
        TEMP_PREFIX="$(realpath "$TEMPORARY_ROOT")/"
        if [[ "$RESOLVED_TEMP_BUILD/" != "$TEMP_PREFIX"* ]]; then
            echo "Refusing to clean a temporary directory outside TemporaryDirectory." >&2
            exit 1
        fi
        rm -rf "$RESOLVED_TEMP_BUILD"
        if [[ "$TEMPORARY_ROOT_CREATED" -eq 1 && -d "$TEMPORARY_ROOT" && -z "$(ls -A "$TEMPORARY_ROOT")" ]]; then
            rmdir "$TEMPORARY_ROOT"
        fi
    fi

    rm -f "$METRIC" "$GP5" "$SCENARIO"

    if [[ -d "$ASSETS" ]]; then
        GENERATED_ASSETS_ROOT="$(realpath -m "$OUTPUT_DIRECTORY/gp5-assets")"
        RESOLVED_ASSETS="$(realpath -m "$ASSETS")"
        ASSETS_PREFIX="${GENERATED_ASSETS_ROOT}/"
        if [[ "$RESOLVED_ASSETS/" != "$ASSETS_PREFIX"* ]]; then
            echo "Refusing to clean generated assets outside gp5-assets." >&2
            exit 1
        fi
        rm -rf "$RESOLVED_ASSETS"
        if [[ -d "$GENERATED_ASSETS_ROOT" && -z "$(ls -A "$GENERATED_ASSETS_ROOT")" ]]; then
            rmdir "$GENERATED_ASSETS_ROOT"
        fi
    fi
    echo "Temporary GP5 inputs removed."
elif [[ -n "$TEMPORARY_BUILD_DIRECTORY" ]]; then
    echo "Temporary workspace retained in: $TEMPORARY_BUILD_DIRECTORY"
fi

if [[ "$KEEP_INTERMEDIATE" -eq 1 ]]; then
    echo "Created GP5: $GP5"
fi
echo "Created PKG: $FINAL"
if [[ -n "$REFERENCE" ]]; then
    echo "Created remastered PKG: $FINAL_REMASTERED"
fi