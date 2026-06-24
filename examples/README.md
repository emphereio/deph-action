# Example output

Real output from `deph-action`, produced by scanning a small Flask service
([`src/`](src)) that imports and **calls** several pinned-vulnerable dependencies
(`flask`, `jinja2`, `requests`, `pyyaml`), so deph traces multiple CVEs as reachable
across a realistic dependency + native-library graph.

> Scanned **2026-06-24** against a local build (`tar sha256:6e639dc4cd78…5905`).
> Point-in-time: CVE data drifts, so re-run to refresh. Full digest in [`verdict.json`](verdict.json).

[![open the live report](https://img.shields.io/badge/▶-open%20the%20live%20interactive%20report-2d6090)](https://emphereio.github.io/deph-action/report.html)

[![report preview](report-preview.png)](https://emphereio.github.io/deph-action/report.html)

| file | what it is |
| --- | --- |
| [`verdict.json`](verdict.json) | the canonical digest-bound verdict (the action's source of truth) |
| [`summary.md`](summary.md) | the Markdown job summary / sticky PR comment |
| [`report.html`](report.html) | the self-contained interactive dependency graph (open in a browser) |
| [`deph-report.json`](deph-report.json) | the full deph JSON report the verdict is derived from |

## What it shows

```
132 known CVEs · 42 in your execution path · 58 linked/present · 32 no path found
```

42 reachable: **2 critical · 14 high · 17 medium · 2 low**. A sample of the in-path findings:

| in-path CVE | severity | reached via |
|---|---|---|
| CVE-2020-14343 | CRITICAL | pyyaml (`yaml.load`) |
| CVE-2023-30861 | HIGH | flask |
| CVE-2023-32681 | MEDIUM | requests |
| CVE-2024-22195 | MEDIUM | jinja2 |

deph separates the **42 it found reachable** from your code from the 58 linked/present and
32 installed-but-no-path-found — real signal vs. noise, with the call chain for each.

## View the graph in your browser

Rendered live via GitHub Pages (GitHub does not render raw `.html` from the file view):

**<https://emphereio.github.io/deph-action/report.html>**

More real-image reports: [grafana](https://emphereio.github.io/deph-action/gallery/grafana/report.html) · [prometheus](https://emphereio.github.io/deph-action/gallery/prometheus/report.html).
(`report.html` is also self-contained — download it and open it locally.)

## Regenerate

```bash
docker build -t deph-showcase examples/src
docker save deph-showcase -o image.tar
deph scan image.tar --format json -o examples/deph-report.json --ui-out examples/report.html
```
