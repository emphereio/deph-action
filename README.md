# deph-action

GitHub Action scaffolding for deph evidence reports.

`deph-action` is the public workflow surface for Emphere's vulnerability triage work. It is designed to collect a bounded evidence packet for a container image: the image under review, the commit that produced it, the optional test window the customer chose to run, and the report files that downstream reachability and AI triage layers can consume.

The first public contract is deliberately narrow. It does not claim exhaustive reachability and it does not infer production behavior from a test run. It records what was analyzed, what was exercised, and where the evidence came from.

## Usage

```yaml
name: deph

on:
  pull_request:
  workflow_dispatch:

jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read

    steps:
      - uses: actions/checkout@v4

      - uses: emphereio/deph-action@v0
        with:
          image: ghcr.io/acme/app:${{ github.sha }}
          test-command: npm test
```

The Action writes:

- `deph-evidence/deph-evidence.json`
- `deph-evidence/summary.md`
- `deph-evidence/test.log` when `test-command` is provided

It also appends the Markdown summary to the GitHub Actions job summary.

## Inputs

| input | required | default | description |
| --- | --- | --- | --- |
| `image` | yes | | Container image reference to analyze. |
| `test-command` | no | | Command to run during the evidence window. |
| `working-directory` | no | `.` | Directory where `test-command` should run. |
| `output-directory` | no | `deph-evidence` | Directory for generated report files. |
| `fail-on-test-failure` | no | `true` | Fail the Action if `test-command` fails. |
| `upload-artifact` | no | `true` | Upload the evidence directory as a workflow artifact. |
| `artifact-name` | no | `deph-evidence` | Name of the uploaded artifact. |

## Outputs

| output | description |
| --- | --- |
| `report-json` | Path to the JSON evidence report. |
| `summary-markdown` | Path to the Markdown summary. |
| `test-exit-code` | Exit code from `test-command`, or empty when no command was provided. |

## Evidence Model

The report separates facts from interpretation:

- **image**: the container image the workflow asked deph to analyze.
- **source**: repository, ref, commit SHA, run id, and run attempt.
- **test_window**: the optional command executed by the caller, its exit code, and duration.
- **artifacts**: local paths to generated evidence files.

Future reachability, runtime observation, coverage, and AI triage layers should extend this schema without changing the basic Action interface.

## Development

Run the shell checks:

```bash
bash -n scripts/*.sh
./scripts/run.sh --self-test
```

Run the Action locally by invoking `scripts/run.sh` with the same environment variables GitHub provides:

```bash
DEPH_IMAGE=example/app:latest \
DEPH_TEST_COMMAND='echo ok' \
DEPH_OUTPUT_DIRECTORY=/tmp/deph-evidence \
DEPH_FAIL_ON_TEST_FAILURE=true \
GITHUB_REPOSITORY=emphereio/example \
GITHUB_REF=refs/heads/main \
GITHUB_SHA=0000000000000000000000000000000000000000 \
GITHUB_RUN_ID=1 \
GITHUB_RUN_ATTEMPT=1 \
./scripts/run.sh
```

## Security

Do not put secrets in `test-command`. The command and its exit status are recorded in the evidence report. Test output is written to `test.log` and uploaded when artifact upload is enabled.
