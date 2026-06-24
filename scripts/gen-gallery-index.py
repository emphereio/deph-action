#!/usr/bin/env python3
"""Generate examples/gallery/index.html from each example's verdict.json.

Reads the curated list in images.yaml (order + display metadata) and each
example's verdict.json (counts + the resolved image digest), then writes a
stamped index.html. Every card is stamped with the scan date, platform, deph
version, and the resolved digest so the gallery can never be mistaken for live:
:latest moves and CVE data drifts, so these are explicitly point-in-time.

Usage:
  gen-gallery-index.py --gallery-dir examples/gallery \
      --date 2026-06-24 --platform linux/amd64 --deph-version v0.1.2
"""
import argparse
import html
import json
import os
import sys


def short_digest(d):
    if not d:
        return ""
    algo, _, hexd = d.partition(":")
    if not hexd:
        algo, hexd = "sha256", d
    if len(hexd) <= 16:
        return f"{algo}:{hexd}"
    return f"{algo}:{hexd[:12]}…{hexd[-4:]}"


def load_manifest(path):
    import yaml
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("scan", []) or [], data.get("static", []) or []


def read_verdict(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def stat_line(summary):
    total = summary.get("total", 0)
    in_path = summary.get("in_path", 0)
    linked = summary.get("linked", 0)
    not_found = summary.get("not_found_in_path", 0)
    parts = [
        f"{total:,} known CVEs",
        f'<span class="reach">{in_path:,} in the execution path</span>',
    ]
    if linked:
        parts.append(f"{linked:,} linked")
    parts.append(f"{not_found:,} no path found")
    return " &middot; ".join(parts)


def card(entry, gallery_dir, date, platform, deph_version):
    href = entry.get("href")
    verdict_path = entry.get("verdict")
    name = entry.get("name")
    if name and not href:
        href = f"{name}/report.html"
    if name and not verdict_path:
        verdict_path = os.path.join(gallery_dir, name, "verdict.json")
    elif verdict_path and not os.path.isabs(verdict_path):
        verdict_path = os.path.join(gallery_dir, verdict_path)

    verdict = read_verdict(verdict_path) if verdict_path else None
    if not verdict:
        sys.stderr.write(f"skip (no verdict): {entry}\n")
        return None

    summary = verdict.get("summary", {}) or {}
    image = verdict.get("image", {}) or {}
    title = entry.get("title") or image.get("ref") or name or "example"
    digest = image.get("digest", "")
    digest_kind = image.get("digest_kind", "")

    if digest_kind == "tar-sha256":
        stamp = f"scanned {date} &middot; local build &middot; tar {short_digest(digest)}"
    elif digest:
        stamp = f"scanned {date} &middot; {platform} &middot; deph {deph_version} &middot; @{short_digest(digest)}"
    else:
        stamp = f"scanned {date} &middot; {platform} &middot; deph {deph_version}"

    li = [f'    <li>']
    li.append(f'      <a class="title" href="{html.escape(href)}">{html.escape(title)} &rarr;</a>')
    li.append(f'      <div class="stat">{stat_line(summary)}</div>')
    note = entry.get("note")
    if note:
        li.append(f'      <div class="note">{html.escape(note)}</div>')
    li.append(f'      <div class="stamp">{stamp}</div>')
    li.append('    </li>')
    return "\n".join(li)


PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>deph — example reports</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{ font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
           max-width: 46rem; margin: 3rem auto; padding: 0 1.25rem; }}
    h1 {{ font-size: 1.5rem; margin-bottom: .25rem; }}
    .sub {{ color: #6a737d; margin-top: 0; }}
    ul {{ list-style: none; padding: 0; }}
    li {{ margin: .9rem 0; padding-bottom: .9rem; border-bottom: 1px solid rgba(127,127,127,.2); }}
    a.title {{ font-size: 1.1rem; font-weight: 600; color: #2d6090; text-decoration: none; }}
    .stat {{ color: #6a737d; }}
    .reach {{ color: #c9512b; font-weight: 600; }}
    .note {{ color: #6a737d; font-size: .85rem; }}
    .stamp {{ color: #8a929b; font-size: .78rem; margin-top: .25rem;
             font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
  </style>
</head>
<body>
  <h1>deph — example reports</h1>
  <p class="sub">Real deph scans you can click through. For each, deph maps every CVE-affected
  component to whether the application actually reaches it. Each card is stamped with its scan
  date and the exact image digest it was run against, because <code>:latest</code> moves and
  CVE data drifts. These are point-in-time, not live; the registry examples are re-scanned on a
  schedule.</p>

  <ul>
{cards}
  </ul>

  <p class="note">Full image digests are recorded in each example's <code>verdict.json</code>.
  Reachability is shown for the ecosystems deph has measured (Go especially); "no path found"
  means no execution path was traced, not a proof of safety.
  <a href="https://github.com/emphereio/deph-action">deph-action</a></p>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gallery-dir", default="examples/gallery")
    ap.add_argument("--manifest", default=None, help="defaults to <gallery-dir>/images.yaml")
    ap.add_argument("--out", default=None, help="defaults to <gallery-dir>/index.html")
    ap.add_argument("--date", required=True)
    ap.add_argument("--platform", default="linux/amd64")
    ap.add_argument("--deph-version", default="")
    args = ap.parse_args()

    manifest = args.manifest or os.path.join(args.gallery_dir, "images.yaml")
    out = args.out or os.path.join(args.gallery_dir, "index.html")
    scan_entries, static_entries = load_manifest(manifest)

    cards = []
    for entry in list(scan_entries) + list(static_entries):
        c = card(entry, args.gallery_dir, args.date, args.platform, args.deph_version)
        if c:
            cards.append(c)
    if not cards:
        sys.exit("no cards generated (no verdicts found)")

    with open(out, "w", encoding="utf-8") as fh:
        fh.write(PAGE.format(cards="\n".join(cards)))
    sys.stderr.write(f"wrote {out} ({len(cards)} cards)\n")


if __name__ == "__main__":
    main()
