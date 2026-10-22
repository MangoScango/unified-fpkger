Here's a test plan, ordered roughly by risk. PS4 build paths are the least verified, so they're weighted first.

## PS4 builds (highest priority — only synthetic-tree tested)

1. **Plain app-merge from a real dump** — `CUSAxxxxx-app` with a `-patch` sibling, no flags. Expect: merged pkg in out dir, backport patch `-bp.pkg` beside it if a restamp happened, DLC pkgs if a `-dlc` sibling exists.
2. **Same again via the web UI Build tab** (scan → select → build). Confirms the layers-by-name path (`--no-update --no-dlc` + positional dirs).
3. **Base-only** — `--no-update --no-dlc` (or Build tab with update picker set to "No update").
4. **Remaster mode** — watch the log for the throwaway base pkg + `gp4_proj_update --app_path`; verify the pkg installs and shows the update's version.
5. **Separate mode** — expect three pkgs: app, update patch, `-bp` patch (if backported).
6. **`--base-pkg` mode** — point at an existing base pkg; expect only a backport patch. Also try `--base-pkg` + `--no-backport`: must die with "would build nothing".
7. **DLC handling** — a dump with several `*-ac` dirs in `-dlc`; check each gets a pkg and the right entitlement key (log line says where the key came from). Also an `-al` (license-only) one.
8. **`--dlc DIR` from the command line** (or the DLC dir field in the UI) — this is the bug I fixed in review; confirm the named DLC actually builds.
9. **Ke** vs retail — one build each.
10. **Explicit `--sdk 0x........`** and `--no-backport` — check the log's SDK lines.
11. **A game with trailing-space/dot filenames** if you have one (Dark Souls Remastered was the known case) — exercises the namefix mapping.
12. **PS2 classic** dump if available — exercises make_fself pre-signing/auth derivation.
13. **Overwrite behavior** — build the same title twice into the same out dir; second run should replace/merge sensibly, not corrupt.

## PS5 builds (worked end-to-end, but only on a synthetic tree)

14. **Real PS5 app dump** → pkg; install/check it runs.
15. **PS5 add-on** (ac) — once with its `entitlement_key.dat` present, once with `--entitlement-key` override.
16. **`--sc-pkg`** — once with a local SC pkg, once with a prosperopatches URL.
17. **`--reference-package`** patch build — verify **both** outputs appear (patch + `.remastered.pkg`).
18. **Chunk count / PlayGo languages** on a dump lacking `playgo-chunk.dat`. Note the 255-vs-800 validation mismatch I if you intend 800, tell me and I'll align server/UI/module.
19. **Existing output without `--force`** → must refuse; with `--force`** → rebuilds.

## Dump tab with "Build fpkgs" toggle (the earlier rework)

20. Toggle on **before** Detect: build options hidden, hint shown; after Detect, correct platform's panel appears.
21. Toggle off → submits a plain `dump` job (check job summary says "Dump", not "Dump+Build").
22. Toggle on with PS4 remaster mode → log should say "dumping the patch as a separate layer" (pfsdump, no ftpdump).
23. `no_decrypt` is hidden/forced off while toggled on.
24. **Delete dumps after build** — confirm the confirm-dialog appears and the `-app/-patch/-dlc/-keystone` dirs are removed only on success.

## Regression checks

25. **Terminal/docker one-off**: `build-pkg.py <dump-dir>` (no subcommand — auto-detect both platforms); `docker compose run --rm fpkger --out /work/out /work/CUSAx-xxxx-app`.
26. **Full docker image build** — the `COPY *.py` change and entrypoint default only prove out there.
27. **dlc-split and Backport tabs** — untouched, but a quick run confirms no collateral damage.
28. **Cancel a job mid-build** from the UI — wine process group should die cleanly.

Anything that misbehaves, paste the job log (or `fpkger-logs/*.log` path) and I'll dig in.