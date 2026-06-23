# Contributing to deph-action

Thanks for your interest in improving deph-action. This repo is the public GitHub
Action that wraps deph, which unpacks a built container image into a dependency graph and maps CVEs to the components your application actually reaches. It is intentionally small: a composite action plus a few
shell/Python scripts that download a released deph binary, run one scan, and turn the
result into a digest-bound verdict.

**No engine source lives here.** deph-action never builds deph from source — it
downloads a checksum- and provenance-verified release binary at runtime. Changes to
scanning, ecosystems, or reachability analysis live in the closed-source deph engine,
maintained by Emphere — file engine feedback as an issue here and we'll route it.

## Repository layout

| path | purpose |
| --- | --- |
| `action.yml` | Composite action definition: inputs, outputs, and step wiring. |
| `scripts/install-deph.sh` | Downloads and **sha256-verifies** the deph release binary. |
| `scripts/run.sh` | Orchestrator: resolve image + digest, run the scan, compose the verdict. |
| `scripts/verdict.py` | Transforms the deph JSON report into `verdict.json` + a Markdown summary. |
| `scripts/comment.sh` | Upserts the sticky PR comment (idempotent, never fails the job). |
| `scripts/validate.sh` | Offline self-test (no download, no scan). |
| `schema/deph-verdict.schema.json` | JSON Schema for the emitted `verdict.json`. |
| `testdata/` | A checked-in deph report fixture and a fake-deph stub for offline tests. |

## Development setup

You need `bash`, `python3`, and (for the optional shellcheck step) Docker or a local
`shellcheck`. No Go toolchain is required.

```bash
# Offline self-test: shell syntax, the verdict transform against the fixture,
# the schema, and an end-to-end run.sh on both gate directions — no deph download.
./scripts/validate.sh

# Lint shell (matches CI). Locally without shellcheck installed, use Docker:
docker run --rm -v "$PWD:/mnt" -w /mnt koalaman/shellcheck:stable \
  scripts/*.sh testdata/*.sh
```

If your change affects the verdict shape, update the fixture
(`testdata/sample-deph-report.json`) and/or `schema/deph-verdict.schema.json` so the
self-test continues to assert the right thing.

### Testing against a real scan

`scripts/validate.sh` is fully offline using a fake deph. To exercise the real binary,
run the action against a public image once an `emphereio/deph-dist` release exists; CI's
`integration` job does this automatically when the repo variable `DEPH_RELEASE_READY`
is `true` (see below).

## Pull requests

- Keep PRs focused on a single change; fill in the PR template checklist.
- `./scripts/validate.sh` and `shellcheck` must pass.
- Keep public-facing language **honest**: deph reports what it found *in the execution
  path*, what is *linked/present*, and what it found *no path to* — never "safe" or
  "unreachable".
- Update the README inputs/outputs tables when you change `action.yml`.

## Versioning & releases (maintainers)

deph-action follows [semantic versioning](https://semver.org/). Consumers pin to the
moving major tag, e.g. `uses: emphereio/deph-action@v0`.

1. Update `CHANGELOG.md`.
2. Tag the release: `git tag v0.1.0 && git push origin v0.1.0`.
3. Move the major tag: `git tag -f v0 v0.1.0 && git push -f origin v0`.

Third-party actions are **pinned to commit SHAs** (with a version comment) in
`action.yml` and the workflows; Dependabot proposes updates for review. The deph binary
is pinned by the `deph-version` input (default points at the current `emphereio/deph-dist`
release) and verified against its published `checksums.txt` and Sigstore build provenance.

## Reporting security issues

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
