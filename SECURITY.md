# Security Policy

## Reporting a vulnerability

Please report security issues **privately**:

- Preferred: open a [private security advisory](https://github.com/emphereio/deph-action/security/advisories/new) on this repository, or
- Email **security@emphere.com**.

Do **not** open public issues for vulnerabilities or for sensitive report data.
Include the affected version, reproduction steps, and whether generated artifacts
(the verdict, JSON report, SBOM, SARIF, or HTML report) contain private repository or
image data.

We aim to acknowledge reports within 3 business days and to keep you updated as we
investigate and prepare a fix.

## Supported versions

Security fixes are released against the latest `v0.x` and published under the moving
major tag `emphereio/deph-action@v0`. Pin `deph-version` (and, if you prefer, the action
itself) to a specific tag or commit SHA for reproducible runs.

## Supply-chain posture

- **The deph binary is verified.** The action downloads deph from
  [`emphereio/deph`](https://github.com/emphereio/deph) releases and checks it against
  the published `checksums.txt` before running. A cached binary is re-verified before
  reuse. The action never builds deph from source and vendors no engine code.
- **Third-party actions are pinned to commit SHAs** (with a version comment) in
  `action.yml` and the workflows. Dependabot proposes updates for review.
- **Least privilege.** The base scan needs only `contents: read`. `pull-requests: write`
  is required only for the sticky PR comment, and `security-events: write` only for
  `upload-sarif`. The action requests no other scopes.

## Handling of generated artifacts

Generated artifacts (`verdict.json`, the JSON/HTML reports, SBOM, SARIF) describe your
image and may contain private repository or image data. Treat uploaded workflow
artifacts and the code-scanning tab according to your own data-handling policy. The
action writes only to the configured `output-directory` and does not transmit reports
anywhere.
