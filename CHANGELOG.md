# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **`scripts/scan-gitlab.sh` passes the image to scan by name (`-e CS_IMAGE`).** Not a secret, but fleet conformance now flags any value expanded into `-e NAME=`, and the scan's other values already went this way. Nothing the scan does changes.

## [1.0.0] - 2026-10-28

### Added

- **Both tools on one sample.** A Flask application with planted flaws (SQL injection, command injection, unsafe YAML, a hardcoded key) on an end-of-life Debian base, scanned in every CI run by Snyk Code and Snyk Container and by GitLab's SAST, Secret Detection and Container Scanning, on the same commit and the same image. Every scanner is pinned.
- **`migration/migrate.py`.** Maps each Snyk finding to the GitLab findings it became (code on file, line and CWE; secrets on file and line; packages on CVE and installed package), carries Snyk's ignores to a GitLab vulnerability allowlist and a dismissal list with their reasons and expiries, and writes a validation report.
- **The migration gate.** Fails on a critical or high Snyk finding with no GitLab counterpart and no recorded decision, on an expired ignore or one without a reason, and on a decision without a reason or one left behind. It runs on each CI run's live reports.
- **Tests on real reports.** `tests/` runs `migrate.py` against the reports of one CI run and against each way the move can go wrong; each gate rule is shown the report that breaks it.

[Unreleased]: https://github.com/heyvaldemar/snyk-to-gitlab-security-migration/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/heyvaldemar/snyk-to-gitlab-security-migration/releases/tag/v1.0.0
