<!-- Thanks for contributing to deph-action! Keep this PR focused on one change. -->

## What & why

<!-- What does this change do, and why? Link any related issue (e.g. "Closes #123"). -->

## Type of change

- [ ] Bug fix
- [ ] New capability / input / output
- [ ] Docs only
- [ ] CI / tooling

## Checklist

- [ ] `./scripts/validate.sh` passes locally (offline self-test).
- [ ] `shellcheck scripts/*.sh testdata/*.sh` is clean (any new/changed shell).
- [ ] Inputs/outputs changed in `action.yml` are reflected in the README table.
- [ ] The verdict schema (`schema/deph-verdict.schema.json`) is updated if `verdict.json` shape changed.
- [ ] Public-facing language stays honest: deph reports what it found *in the execution path* — never a claim that something is "safe" or "unreachable".
- [ ] No deph engine source is vendored here — this repo only downloads a checksum-verified released binary.

## Notes for reviewers

<!-- Anything that needs special attention, follow-ups, or known limitations. -->
