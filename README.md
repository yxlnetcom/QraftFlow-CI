# QraftFlow-CI

Public CI orchestration for QraftFlow Creator OS.

## Architecture

- Private source of truth: `yxlnetcom/QraftFlow-Creator-OS`
- Public CI orchestration: `yxlnetcom/QraftFlow-CI`
- CI provider: GitHub Actions
- Source checkout: exact private-repository SHA, read-only
- Product source code is not stored in this repository.

## Current baseline validation

Validated source SHA:

`2641793f63dbb44635ecbda7b0956d17be5a620b`

GitHub Actions run:

`#2 / 36004199167`

Jobs:

- repository-checks: success
- swift-linux: success
- swift-macos: success
- macos-app-package: success

CircleCI is retained as a standby provider with new work blocked.

## Security

- Private source access is read-only through the repository secret `QRAFTFLOW_SOURCE_TOKEN`.
- No source artifacts or full build trees are published from this repository.
- CI requests identify an exact 40-character source SHA.
