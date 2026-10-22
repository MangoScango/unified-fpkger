#!/usr/bin/env python3
"""Builds DLC unlocker trees from the PSN store's chihiro API.

Each license becomes <out_dir>/<title>-dlc/<content-id>-al with a
sce_sys/param.sfo (PS4) or param.json (PS5), ready for build-pkg.py. The API
provides no entitlement keys or concept IDs, so no entitlement_key.dat is
written and param.json carries an empty conceptId.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

import pfsdump

CHIHIRO_CONTAINER = ("https://store.playstation.com/store/api/chihiro/"
                     "00_09_000/container/{region}/{language}/67/{title}")
PAGE_SIZE = 255

TITLE_ID = re.compile(r"^[A-Z]{4}[0-9]{5}$")


def normalize_title(value):
    """A bare title ID (PPSA01289), accepting a _00 suffix."""
    title = value.strip().upper()
    if title.endswith("_00"):
        title = title[:-3]
    if not TITLE_ID.match(title):
        raise ValueError(f"not a title ID: {value}")
    return title


def _container_page(title, region, language, start):
    url = CHIHIRO_CONTAINER.format(region=region, language=language,
                                   title=title + "_00")
    url += f"?size={PAGE_SIZE}&start={start}"
    request = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            # The store answers 204 when a title has no add-ons at all.
            if response.status == 204:
                return None
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        raise RuntimeError(f"PSN store request failed for {title}: "
                           f"http {err.code}") from err
    except (OSError, ValueError) as err:
        raise RuntimeError(f"PSN store request failed for {title}: {err}") from err


def fetch_addons(title, region="us", language="en", include_siblings=False):
    """The title's AL licenses as [(content_id, title, icon_url, title_id)].

    A store page also lists the other platform's sibling title (a PS5 page
    includes the PS4 title's PS4AL entitlements); those come along only with
    include_siblings.
    """
    found = {}
    start = 0
    while True:
        page = _container_page(title, region, language, start)
        if page is None:
            break
        links = page.get("links") or []
        for link in links:
            if link.get("game_contentType") == "Bundle":
                continue
            icon_url = ""
            images = link.get("images") or []
            if images and images[0].get("url"):
                icon_url = images[0]["url"]
            for entitlement in (link.get("default_sku") or {}).get("entitlements") or []:
                if entitlement.get("packageType") not in ("PSAL", "PS4AL"):
                    continue
                content_id = entitlement.get("id") or ""
                match = pfsdump.AL_CONTENT_ID.fullmatch(content_id)
                if match is None or content_id in found:
                    continue
                if not include_siblings and match.group(1) != title:
                    continue
                name = link.get("name") or entitlement.get("name") or content_id
                found[content_id] = (content_id, name, icon_url, match.group(1))
        start += len(links)
        if not links or start >= page.get("total_results", start):
            break
    return list(found.values())


def build_unlockers(titles, out_dir, region="us", language="en",
                    skip_existing=False, include_siblings=False, log=print):
    """Writes a <title>-dlc/<content-id>-al tree per license. Returns them.

    skip_existing keeps unlocker trees already on disk; include_siblings also
    builds the other platform's entitlements the store page carries.
    """
    licenses = []
    for title in titles:
        log(f"Fetching add-ons for {title} from the PSN store ...")
        found = fetch_addons(title, region, language, include_siblings)
        log(f"  {len(found)} entitlement(s)")
        licenses += found

    tool = pfsdump.sfo_tool()
    if tool is None and any(not title_id.startswith("PPSA")
                            for _c, _t, _i, title_id in licenses):
        raise RuntimeError(
            "PS4 DLC entitlement unlockers require program \"sfo\" "
            "(https://github.com/hippie68/sfo) to build param.sfo files. "
            "Place it next to pfsdump.py or set SFO_PATH.")

    created = []
    skipped = 0
    for content_id, title, icon_url, title_id in licenses:
        dlc_dir = os.path.join(out_dir, f"{title_id}-dlc", f"{content_id}-al")
        if skip_existing and os.path.isdir(dlc_dir):
            skipped += 1
            continue
        sce_sys = os.path.join(dlc_dir, "sce_sys")
        try:
            os.makedirs(sce_sys, exist_ok=True)
        except OSError as err:
            raise RuntimeError(
                f"could not create unlocker directory for {content_id}: {err}"
            ) from err
        created.append(dlc_dir)

        if title_id.startswith("PPSA"):
            try:
                pfsdump.write_ps5_al_param(
                    os.path.join(sce_sys, "param.json"),
                    content_id, title_id, title, "")
            except OSError as err:
                raise RuntimeError(
                    f"could not build param.json for {content_id}: {err}") from err
            try:
                os.unlink(os.path.join(sce_sys, "param.sfo"))
            except FileNotFoundError:
                pass
            except OSError as err:
                raise RuntimeError(
                    f"could not remove stale param.sfo for {content_id}: {err}"
                ) from err
        else:
            command = [
                tool, os.path.join(sce_sys, "param.sfo"),
                "--new-file", "--force",
                "--set", "int", "ATTRIBUTE", "0",
                "--set", "str", "CATEGORY", "ac",
                "--set", "str", "CONTENT_ID", content_id,
                "--set", "str", "FORMAT", "obs",
                "--set", "str", "TITLE", title,
                "--set", "str", "TITLE_ID", title_id,
                "--set", "str", "VERSION", "01.00",
            ]
            try:
                done = subprocess.run(command, check=False)
            except OSError as err:
                raise RuntimeError(
                    f"could not run sfo for {content_id}: {err}") from err
            if done.returncode != 0:
                raise RuntimeError(f"could not build param.sfo for {content_id}")

        if icon_url:
            icon_path = os.path.join(sce_sys, "icon0.png")
            try:
                with urllib.request.urlopen(icon_url, timeout=30) as response:
                    icon = pfsdump.to_png(response.read())
                with open(icon_path, "wb") as out:
                    out.write(icon)
            except Exception as err:
                try:
                    os.unlink(icon_path)
                except FileNotFoundError:
                    pass
                log(f"  warning: could not download icon0.png for "
                    f"{content_id}: {err}")

        log(f"{content_id}  ({title_id})  {title}")

    if not licenses:
        log("No DLC entitlements found on the store for "
            + ", ".join(titles) + ".")
    else:
        note = f", {skipped} kept from an earlier pass" if skipped else ""
        log(f"Created {len(created)} DLC unlocker template(s){note} under "
            f"\"{out_dir}/<title_id>-dlc/\".")
        if created:
            log("note: PSN has no entitlement keys, so none were written; "
                "packages build with zeroed keys.")
    return created


def main():
    parser = argparse.ArgumentParser(
        description="Build DLC unlocker trees from the PSN store API.")
    parser.add_argument("titles", nargs="+",
                        help="title IDs, e.g. PPSA01289 CUSA07211")
    parser.add_argument("-o", "--out-dir", required=True,
                        help="directory the <title>-dlc folders are written into")
    parser.add_argument("--region", default="us", help="store region (default: us)")
    parser.add_argument("--language", default="en",
                        help="store language (default: en)")
    parser.add_argument("--skip-existing", action="store_true",
                        help="keep unlocker trees that already exist, e.g. ones "
                             "built from a console's entitlement database")
    parser.add_argument("--include-siblings", action="store_true",
                        help="also build the entitlements of the other platform's "
                             "sibling title the store page carries")
    args = parser.parse_args()
    try:
        titles = [normalize_title(value) for value in args.titles]
        os.makedirs(args.out_dir, exist_ok=True)
        build_unlockers(titles, args.out_dir, args.region, args.language,
                        skip_existing=args.skip_existing,
                        include_siblings=args.include_siblings)
    except (ValueError, RuntimeError, OSError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
