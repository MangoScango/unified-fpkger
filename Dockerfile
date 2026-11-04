# syntax=docker/dockerfile:1
#
#   Web UI (the default):
#     docker run -d -p 8080:8080 -e WEB_PASSWORD=... -v /mnt/user/ps4dumps:/work unified-fpkger
#   One-off build from the terminal:
#     docker run --rm -e PUID=99 -e PGID=100 -v /mnt/user/ps4dumps:/work \
#         unified-fpkger --out /work/out /work/CUSA28863-app

FROM debian:trixie-slim AS deps

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG PKGTOOLS_REPO=https://github.com/CyB1K/PS4-Fake-PKG-Tools-3.87
ARG PKGTOOLS_REF=main
RUN git clone --depth 1 --branch "$PKGTOOLS_REF" "$PKGTOOLS_REPO" /out-pkgtools \
    && rm -rf /out-pkgtools/.git

ARG PS_PKG_INFO_REPO=https://github.com/MangoScango/ps-pkg-info
ARG PS_PKG_INFO_REF=main
RUN git init -q /src/ps-pkg-info \
    && git -C /src/ps-pkg-info fetch -q --depth 1 "$PS_PKG_INFO_REPO" "$PS_PKG_INFO_REF" \
    && git -C /src/ps-pkg-info checkout -q FETCH_HEAD

FROM debian:trixie-slim

ARG WINE_BRANCH=stable

# i386 multiarch is required: the CyB1K tools are 32-bit PE binaries. Deleting
# i386-unix below keeps only the 32-bit PE builtins, which leaves wine in new
# WoW64 mode: a 64-bit CUI loader parents the 32-bit PEs, and GUI-subsystem
# gengp4_app.exe only gets console output by inheriting that parent's console.
RUN dpkg --add-architecture i386 \
    && apt-get update && apt-get install -y --no-install-recommends \
        wget gnupg ca-certificates \
    && mkdir -p /etc/apt/keyrings \
    && wget -qO /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key \
    && wget -qO /etc/apt/sources.list.d/winehq-trixie.sources \
        https://dl.winehq.org/wine-builds/debian/dists/trixie/winehq-trixie.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
        "winehq-${WINE_BRANCH}" \
        python3 python3-pil \
        bash coreutils sed grep findutils \
        xvfb gosu \
        curl sqlite3 lftp binutils \
    && rm -rf "/opt/wine-${WINE_BRANCH}/lib/wine/i386-unix" \
    # WineHQ's PE builtins carry full DWARF debug info. Strip them in this
    # layer, otherwise the ~1.1 GB stays in the image even if a later layer
    # removes it.
    && find "/opt/wine-${WINE_BRANCH}" -type f \( \
            -name '*.dll' -o -name '*.exe' -o -name '*.so' -o -name '*.so.*' \
            -o -name '*.drv' -o -name '*.sys' -o -name '*.ocx' \
            -o -name '*.cpl' -o -name '*.acm' -o -name '*.ax' \) -print0 \
       | xargs -0 -r -P"$(nproc)" strip --strip-unneeded \
    # Import libraries are only used by winegcc/winebuild; this image just
    # runs PE binaries.
    && find "/opt/wine-${WINE_BRANCH}" -type f -name '*.a' -delete \
    # New WoW64 runs the 32-bit PEs inside the 64-bit loader, so the i386
    # Unix libraries pulled in by multiarch are dead weight.
    && rm -rf /usr/lib/i386-linux-gnu /lib/i386-linux-gnu \
    # Xvfb pulls Mesa/LLVM in through libgl1, but the tools only need a plain
    # X server. Drop the DRI/LLVM stack (~190 MB) and keep libgl1/libglx.
    && rm -rf /usr/lib/x86_64-linux-gnu/libLLVM.so.19.1 \
              /usr/lib/x86_64-linux-gnu/libgallium-*.so \
              /usr/lib/x86_64-linux-gnu/libz3.so.4* \
              /usr/lib/x86_64-linux-gnu/dri \
    && apt-get purge -y --auto-remove wget gnupg \
    && rm -rf /var/lib/apt/lists/*
# binutils provides as/ld for another-backporter's --unpeg-shim, which
# assembles ps5backport/vrr_shim.s at runtime; patch.py uses clang/lld when
# they exist and falls back to as/ld otherwise.

# Consumed by build-pkg.py's tool-path env hooks.
ENV SDK_DIR=/opt/fpkger/PS4_Fake_PKG_Tools_3 \
    MAKE_FSELF=/opt/fpkger/make_fself.py \
    GENGP4_APP=/opt/fpkger/PS4_Fake_PKG_Tools_3/gengp4_app.exe \
    ORBIS_PUB_CMD=/opt/fpkger/PS4_Fake_PKG_Tools_3/orbis-pub-cmd.exe \
    PKG_SET_APPVER=/opt/fpkger/pkg-set-appver.py \
    BACKPORT_SDK=/opt/fpkger/backport-sdk.py \
    FW_EXPORT_DB=/opt/fpkger/another-backporter/fwdb \
    BACKPORT_PS5=/opt/fpkger/another-backporter/backport-ps5.py \
    PS5BACKPORT_MAKE_FSELF=/opt/fpkger/make_fself.py \
    PS5BACKPORT_PUB_CMD=/opt/fpkger/drakmor/toolchain/prospero-pub-cmd.exe \
    WINEDEBUG=-all \
    WINEDLLOVERRIDES="wineps.drv,localspl.dll,spoolss.dll=d"

COPY --from=deps /out-pkgtools   /opt/fpkger/PS4_Fake_PKG_Tools_3
COPY --from=deps /src/ps-pkg-info/ps_pkg_info /opt/fpkger/ps_pkg_info
# another-backporter is a git submodule: backport-ps5.py drives the web UI's
# Backport tab, and its fwdb/ CSVs are backport-sdk.py's export tables. The
# PS5 firmware dumps fakelibs are built from are not shipped; the Backport
# tab takes them at runtime (PS5BACKPORT_LIBS).
COPY another-backporter /opt/fpkger/another-backporter
COPY *.py \
     /opt/fpkger/
# pfsdump sends this to the console's payload loader to read PS5 add-on
# entitlement keys from the running game.
ARG ENTITLEMENT_INJECTOR_URL=https://github.com/MangoScango/ps5-entitlement-dumper/releases/latest/download/entitlements.elf
ADD --chmod=644 "$ENTITLEMENT_INJECTOR_URL" /opt/fpkger/entitlements.elf
ENV ENTITLEMENT_INJECTOR=/opt/fpkger/entitlements.elf
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY drakmor /opt/fpkger/drakmor
COPY web /opt/fpkger/web

# 0x3681B is the JZ guarding orbis-pub-cmd's "app volume must carry
# APP_VER == 01.00" test (VA 0x43741B). EB makes it unconditional, letting a
# merged app+update package advertise the game's real version.
RUN off=$((0x3681B)) \
    && [ "$(dd if="$ORBIS_PUB_CMD" bs=1 skip=$off count=2 status=none \
            | od -An -tx1 | tr -d ' \n')" = 7407 ] \
    && printf '\353' \
       | dd of="$ORBIS_PUB_CMD" bs=1 seek=$off conv=notrunc status=none

RUN chmod +x /opt/fpkger/build-pkg.py \
        /opt/fpkger/pkg-set-appver.py \
        /opt/fpkger/pfsdump.py /opt/fpkger/sfo.py \
        /usr/local/bin/entrypoint.sh \
    && ln -s /opt/fpkger/build-pkg.py /usr/local/bin/build-pkg.py \
    && ln -s /opt/fpkger/pkg-set-appver.py /usr/local/bin/pkg-set-appver.py \
    && ln -s /opt/fpkger/pfsdump.py /usr/local/bin/pfsdump.py

# No PUID/PGID default: unset means "run in place" (see entrypoint), which is
# what a rootless `docker run` needs.
# Interactive docker exec shells need the runtime wine env (prefix, DISPLAY).
RUN printf '%s\n' '[ -f /tmp/fpkger-env.sh ] && . /tmp/fpkger-env.sh' >> /etc/bash.bashrc

WORKDIR /work
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["web"]
