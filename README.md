### unified-fpkger

Dockerized ftp dumper, fpkg builder, and backport creator for PS4 & PS5 games. Serves a simple web interface designed to handle every part of the backup & repacking process for seamless backups. It is powered by several individual python scripts working in tandem.

## pfsdump.py
- Dumps games by streaming from the pfs image directly over any standard ftp server (with SELF decryption support), rather than walking the folder mount. This make dumping games with thousands of files much faster.
- Reads playgo installation status to identify and warn about missing chunks, and identifies which content is missing. Missing chunks are automatically skipped without error if chosen to continue dumping.
- Dump PS4 games as a unified app+patch without having to download duplicate files.
- Automatically injects [ps5-entitlement-dumper](https://github.com/MangoScango/ps5-entitlement-dumper) to force all DLC to mount for dumping, and saves DLC entitlement keys.
- Parses the entitlements database to generate stub dumps for AL type DLC, with correct entitlement keys.

## build-pkg.py
- Supports building PS4 "remaster" style pkgs that can still accept patches for backports/mods, while displaying the correct version number.
- Builds basic PS4 backports by identifying the lowest viable SDK target for a given game and lowers the SDK without stubbing any functionality. (Note: this is built primarily to run on PS5, so the lowest backport target is PS5 1.0 / PS4 7.50).
- Supports overlaying retail PS5 SC pkgs to repair dumps with missing metadata.
- Build fpkg for AC DLC, as wells as AL (via stubbed AC fpkg) on both PS4 and PS5.
- Supports unrolling combined PS5 dlc_emu dumps into individual fpkgs.
- Rebuild existing PS5 fpkgs.

## psn_entitlements.py
- Searches the PSN API for all available AL DLC of a given title and automatically generates stub dumps for fpkg generation.

## another-backporter
- Experimental automatic backport creator. See [another-backporter](https://github.com/MangoScango/another-backporter) for more information.

## Requirements

See [docker/docker-compose.yml](docker/docker-compose.yml) for Docker deployment. This is the intended deployment method, but the project can run on bare metal in Windows, or any other environment where Wine is available.

## Special Thanks

This project was built piecemeal as I learned the existing best practices and new techniques for dealing with PS4 & PS5 backups. As such, it would not exist if it were not for those in the community who did most of the hard work before me. As such, thanks to:

- [Drakmor](https://github.com/drakmor/) for the PS5 fpkg builder and the numerous other tools he's created for the community
- [SvenGDK](https://github.com/SvenGDK) for libProsperoPkg
- [CyB1K](https://github.com/CyB1K) for the PS4 fpkg builder
- [hippie68](https://github.com/hippie68) for ftpdump & sfo tools
- [EchoStrech](https://github.com/echostretch) for PS5-app-dumper and kstuff
- [BestPig](https://github.com/BestPig) for their work on backports
- [Deckerr97](https://github.com/kerrdec97) for their work on backports
- [flatz](https://github.com/flatz) for more than I can even articulate

and everyone else in the community whose research has contributed.