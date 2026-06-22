# Changelog

All notable changes to deph-action are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Consumers pin to the moving
major tag (`emphereio/deph-action@v0`).

## [Unreleased]

### Added

- Initial public release of deph-action — a composite GitHub Action that runs the
  [deph](https://github.com/emphereio/deph) container CVE-reachability scanner and
  produces a **digest-bound verdict** splitting known CVEs into *in the execution path*,
  *linked/present*, and *no path found*.
- Downloads a **checksum-verified** deph release binary (`deph-version` input); never
  builds from source.
- Image sources: a local image built on the runner (`docker save` → tarball) or a
  registry reference deph pulls directly.
- Honest digest binding with a recorded strength (`digest_kind`): `provided` >
  `repo-digest` > `tar-sha256` > `config-id`.
- Outputs: `verdict.json` (canonical), the deph JSON report, a self-contained HTML
  report, a Markdown job summary, and step outputs for chaining.
- Opt-in: reachable-only SARIF to the code-scanning tab (`upload-sarif`), a CycloneDX
  SBOM (`upload-sbom`), and a sticky PR comment (`comment-on-pr`).
- `fail-on` release gate (`none` / `any-reachable` / `reachable-high` /
  `reachable-critical`), evaluated **after** artifacts are uploaded.
- Offline self-test (`scripts/validate.sh`) and a JSON Schema for the verdict.

[Unreleased]: https://github.com/emphereio/deph-action/commits/main
