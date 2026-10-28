# snyk-to-gitlab-security-migration

[![Scan](https://github.com/heyvaldemar/snyk-to-gitlab-security-migration/actions/workflows/scan.yml/badge.svg?branch=main)](https://github.com/heyvaldemar/snyk-to-gitlab-security-migration/actions/workflows/scan.yml)

Moving an application security programme from Snyk to GitLab's security scanners, with every Snyk finding mapped to what GitLab reports for it, Snyk's ignores carried across with their reasons, and a gate that fails when the move would lose something.

Both tools scan the same sample application and the same container image in every CI run, and `migration/migrate.py` judges that run's reports, not stored ones.

## What one run shows

From the reports of [run 40723821452](https://github.com/heyvaldemar/snyk-to-gitlab-security-migration/actions/runs/40723821452), counted once per Snyk issue and installed package:

| Snyk findings | matched in GitLab | ignore carried | gap, decided | gap, below the gate |
|---|---:|---:|---:|---:|
| SAST (4) | 3 | 0 | 1 | 0 |
| Secrets (1) | 1 | 0 | 0 | 0 |
| OS packages (197) | 120 | 1 | 0 | 76 |
| Application packages (37) | 35 | 0 | 0 | 2 |

Every critical and high Snyk finding has a GitLab counterpart, except one, which has a recorded decision. GitLab reports 17 findings Snyk does not: 1 critical, 4 high, 7 medium, 2 low, 3 unknown. The gate passes.

## What the move turned up

These came out of the run, not out of documentation:

- **A weakness only one tool names.** Snyk Code reports the `/ping` handler as reflected XSS (CWE-79): it returns command output to the browser. GitLab's default Python rules do not. The same line is a GitLab finding for command injection (CWE-78, `bandit.B602`), so the line is not invisible after the move, but its XSS facet is. Reporting that facet needs a custom SAST ruleset, a GitLab Ultimate feature. The decision is in [`migration/decisions.json`](migration/decisions.json).
- **Ignores lose their expiry.** A Snyk ignore carries a reason and an expiry date. GitLab's [vulnerability allowlist](https://docs.gitlab.com/user/application_security/container_scanning/) carries a CVE and a comment. Carried as they are, temporary acceptances become permanent ones. `migrate.py` writes each expiry into the allowlist comment and fails the gate once it passes, so the risk is decided again rather than kept by accident.
- **The tools read different parts of the image.** Snyk Container with `--app-vulns` read the application's `requirements.txt`. GitLab's Container Scanning, with language packages turned on, also read the packages the Python base image installs itself: three high findings in `setuptools` and one in `wheel` are GitLab-only for that reason.
- **The advisory databases disagree at the edges.** `CVE-2011-3374` in `apt` is in Snyk's report and not in GitLab's; `CVE-2023-45853` in `zlib1g`, critical, is in GitLab's and not in Snyk's. Neither is a matching error: neither CVE appears anywhere in the other tool's report.
- **One finding can become two.** GitLab reports the SQL injection twice, from two rule sets (`bandit.B608` and a Flask taint rule). Both map to Snyk's one finding, so neither is counted as new.
- **Snyk counts paths, not issues.** Its container report lists 414 entries: one per dependency path. Counted once per issue and installed package, they are 197.

## How findings are matched

| Kind | Snyk | GitLab | They match on |
|---|---|---|---|
| Code | `snyk code test` (SARIF) | SAST | file, line and CWE |
| Secrets | Snyk Code's hardcoded-secret rules | Secret Detection | file and line |
| Packages | `snyk container test --app-vulns` | Container Scanning, language packages on | CVE and the installed package's name |

Snyk names an OS finding by its source package (`systemd`) and lists the binary one in the path (`systemd/libudev1`); GitLab names the binary. The binary is what both tools saw installed, so that is the key.

## The gate

`migrate.py` exits 1, and CI fails, when:

1. A critical or high Snyk finding has no GitLab counterpart and no decision in `migration/decisions.json`.
2. A Snyk ignore has expired, or has no reason. It is not carried, and has to be decided again.
3. A recorded decision has no reason, or matches no finding any more. A decision for a gap that is gone is reported, so the file cannot rot.

It exits 2 when a report cannot be read. A missing report is an error, never a pass.

Findings GitLab reports and Snyk does not are listed for triage and not gated: a new scanner is expected to find new things.

## Using it on your own project

1. **Inventory.** Export the reports Snyk produces for the project today (`snyk code test --sarif-file-output`, `snyk container test --app-vulns --json-file-output`), with your `.snyk` policy in place, so the ignores come out with their reasons and expiries.
2. **Run GitLab's scanners side by side** on the same commit and the same image. In GitLab CI that is the SAST, Secret Detection and Container Scanning templates, with `CS_DISABLE_LANGUAGE_VULNERABILITY_SCAN: "false"`; `scripts/scan-gitlab.sh` shows the same three analyzers run by hand.
3. **Map and judge.** `python3 migration/migrate.py --snyk <dir> --gitlab <dir> --decisions decisions.json --out <dir>`. Read `report.md`.
4. **Decide every gap.** For each critical or high gap: fix the coverage (a custom rule, a different scanner setting) or record why it is acceptable, with a reason a reviewer can check. Run again until the gate passes.
5. **Carry the ignores.** `vulnerability-allowlist.yml` goes in the root of the repository for Container Scanning (Ultimate); `dismissals.json` lists the findings to dismiss through GitLab's API, with the reason as the comment.
6. **Cut over without a gap.** Make GitLab's scanners the pipeline gate while Snyk keeps reporting, and keep the migration gate in CI. Turn Snyk off once the gate has passed on enough consecutive runs to cover your release cycle. Until then, rolling back is turning one setting off.

## What it does not do

- **GitLab Ultimate features are not exercised.** Enforcement of the allowlist, custom SAST rulesets and the vulnerability dismissal API are Ultimate. Here the allowlist and the dismissals are generated and checked for what they contain, not applied.
- **Dependency Scanning is not run.** Its analyzers are under the GitLab Enterprise Edition licence; SAST, Secret Detection and Container Scanning are MIT-licensed and run outside GitLab, which is what CI does here. Container Scanning with language packages turned on covers the dependencies. DAST is out of scope: the sample is scanned at rest, not running.
- **Snyk Code's ignores are not carried.** `.snyk` does not hold them: Snyk keeps them as [Consistent Ignores](https://docs.snyk.io/scan-fix-and-prevent/fix/prioritize-issues-for-fixing/ignore-issues/consistent-ignores-for-snyk-code), set in the web app or with `snyk ignore create`. This sample carries a container ignore; `dismissals.json` is the shape a code ignore would take.
- **One sample, in Python.** The mapping keys are not Python-specific, but only Python, Debian packages and these four kinds of finding have been run.

## Repository

| Path | What it is |
|---|---|
| `sample-app/` | The application both tools scan, with planted flaws marked `PLANT`, and its `.snyk` policy |
| `plants/settings.py.b64` | The planted key, stored encoded so that neither git history nor push protection ever holds it in clear; decoded only for a scan, and redacted from every report |
| `ci-images.pins` | Every scanner image by digest and the Snyk CLI by version and checksum |
| `scripts/scan-gitlab.sh`, `scripts/scan-snyk.sh` | Each tool run by hand, the same way CI runs it |
| `migration/migrate.py` | The mapping, the carried ignores and the gate; Python 3.9+, standard library only |
| `migration/decisions.json` | The recorded decisions on gaps |
| `tests/` | `migrate.py` against the real reports of one run, and against each way the move can go wrong |

The tests are the gate's own proof: each rule is shown a report that breaks it, and must fail. They were also run against a `migrate.py` with a rule switched off, and caught it.

## Questions, bugs and changes

Open an [issue](https://github.com/heyvaldemar/snyk-to-gitlab-security-migration/issues) for a bug, a question or an idea. Security reports go privately, as [SECURITY.md](SECURITY.md) describes.

## How this is built

One maintainer and an AI agent. The agent writes most of the code; the decisions are mine, and so is the verification. Nothing merges on the agent's report that it works: it merges on the checks above, and each of them has been shown the failure it exists to catch.

## License

[MIT](LICENSE).
