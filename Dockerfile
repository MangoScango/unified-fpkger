# syntax=docker/dockerfile:1
#
#   Web UI (the default):
#     docker run -d -p 8080:8080 -e WEB_PASSWORD=... -v /mnt/user/ps4dumps:/work unified-fpkger
#   One-off build from the terminal:
#     docker run --rm -e PUID=99 -e PGID=100 -v /mnt/user/ps4dumps:/work \
#         unified-fpkger --out /work/out /work/CUSA28863-app

FROM debian:trixie-slim AS deps

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG SFO_REPO=https://github.com/hippie68/sfo
ARG SFO_REF=main
RUN git clone --depth 1 --branch "$SFO_REF" "$SFO_REPO" /src/sfo \
    && gcc /src/sfo/sfo.c -O3 -s -o /out-sfo

ARG PKGTOOLS_REPO=https://github.com/CyB1K/PS4-Fake-PKG-Tools-3.87
ARG PKGTOOLS_REF=main
RUN git clone --depth 1 --branch "$PKGTOOLS_REF" "$PKGTOOLS_REPO" /out-pkgtools \
    && rm -rf /out-pkgtools/.git

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
        python3 \
        bash coreutils sed grep findutils \
        xvfb gosu \
        curl sqlite3 lftp binutils \
        clang lld \
    && rm -rf "/opt/wine-${WINE_BRANCH}/lib/wine/i386-unix" \
    && rm -rf /var/lib/apt/lists/*
# clang + lld are only for another-backporter's --unpeg-shim, which assembles
# ps5backport/vrr_shim.s at build time.

# Consumed by build-fpkg.sh's ${VAR:-default} tool-path hooks.
ENV SDK_DIR=/opt/fpkger/PS4_Fake_PKG_Tools_3 \
    SFO_TOOL=/opt/fpkger/sfo \
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

COPY --from=deps /out-sfo        /opt/fpkger/sfo
COPY --from=deps /out-pkgtools   /opt/fpkger/PS4_Fake_PKG_Tools_3
# another-backporter is a git submodule: backport-ps5.py drives the web UI's
# Backport tab, and its fwdb/ CSVs are backport-sdk.py's export tables. The
# PS5 firmware dumps fakelibs are built from are not shipped; the Backport
# tab takes them at runtime (PS5BACKPORT_LIBS).
COPY another-backporter /opt/fpkger/another-backporter
# ftpdump takes sfo from its own directory when sfo_path is unset, so they ship
# side by side.
COPY *.sh *.py \
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

RUN chmod +x /opt/fpkger/build-fpkg.sh /opt/fpkger/dump-build.sh \
        /opt/fpkger/build-ps5.sh \
        /opt/fpkger/ftpdump.sh /opt/fpkger/pkg-set-appver.py \
        /opt/fpkger/pfsdump.py /opt/fpkger/sfo \
        /usr/local/bin/entrypoint.sh \
    && for t in build-fpkg dump-build ftpdump; do \
         ln -s "/opt/fpkger/$t.sh" "/usr/local/bin/$t.sh"; \
       done \
    && ln -s /opt/fpkger/sfo /usr/local/bin/sfo \
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
