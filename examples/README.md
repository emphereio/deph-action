# Example output

Real output from `deph-action`, produced by scanning [`testdata/e2e`](../testdata/e2e)
(a minimal Python image that deliberately makes a vulnerable dependency reachable:
`pyyaml==5.3.1`, CVE-2020-14343, called via `yaml.load`).

| file | what it is |
| --- | --- |
| [`verdict.json`](verdict.json) | the canonical digest-bound verdict (the action's source of truth) |
| [`summary.md`](summary.md) | the Markdown job summary / sticky PR comment |
| [`report.html`](report.html) | the self-contained interactive dependency graph (open in a browser) |
| [`deph-report.json`](deph-report.json) | the full deph JSON report the verdict is derived from |

## What it shows

```
59 known CVEs · 1 in your execution path · 33 linked/present · 25 no path found
```

| in-path CVE | severity | fix | evidence |
|---|---|---|---|
| CVE-2020-14343 | CRITICAL | 5.4 | traced: pyyaml |

deph found **one** CVE actually reachable from application code (the `yaml.load` call),
distinguished from 33 that are linked/present and 25 that are installed-but-no-path-found.
That separation — real vs. noise — is the point.

## View the graph in your browser

`report.html` is self-contained: download it and open it, or — once this repo is public —
view it rendered via:

<https://htmlpreview.github.io/?https://raw.githubusercontent.com/emphereio/deph-action/main/examples/report.html>

## Regenerate

```bash
docker build -t deph-e2e-app testdata/e2e
docker save deph-e2e-app -o image.tar
deph scan image.tar --format json -o examples/deph-report.json --ui-out examples/report.html
```
