# syntax=docker/dockerfile:1
#
#   docker run --rm -e PUID=99 -e PGID=100 -v /mnt/user/ps4dumps:/work \
#       unified-fpkger --out /work/out /work/CUSA28863-app

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
    && rm -rf "/opt/wine-${WINE_BRANCH}/lib/wine/i386-unix" \
    && rm -rf /var/lib/apt/lists/*

# Consumed by build-fpkg.sh's ${VAR:-default} tool-path hooks.
ENV SDK_DIR=/opt/fpkger/PS4_Fake_PKG_Tools_3 \
    SFO_TOOL=/opt/fpkger/sfo \
    MAKE_FSELF=/opt/fpkger/make_fself.py \
    GENGP4_APP=/opt/fpkger/PS4_Fake_PKG_Tools_3/gengp4_app.exe \
    ORBIS_PUB_CMD=/opt/fpkger/PS4_Fake_PKG_Tools_3/orbis-pub-cmd.exe \
    WINEDEBUG=-all \
    WINEDLLOVERRIDES="wineps.drv,localspl.dll,spoolss.dll=d"

COPY --from=deps /out-sfo      /opt/fpkger/sfo
COPY --from=deps /out-pkgtools /opt/fpkger/PS4_Fake_PKG_Tools_3
COPY build-fpkg.sh make_fself.py /opt/fpkger/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /opt/fpkger/build-fpkg.sh /opt/fpkger/sfo /usr/local/bin/entrypoint.sh \
    && ln -s /opt/fpkger/build-fpkg.sh /usr/local/bin/build-fpkg.sh

# No PUID/PGID default: unset means "run in place" (see entrypoint), which is
# what a rootless `docker run` needs.
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--help"]
