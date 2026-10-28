# Security policy

## Supported versions

| Version | Supported |
|---|---|
| The latest release | yes |
| `main` | yes |
| Older releases | no |

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository. Email to v@valdemar.ai also works. The process is described at [heyvaldemar.com/security](https://heyvaldemar.com/security/).

You can expect an acknowledgment within 7 days. There is no bounty program; valid, responsibly disclosed reports are credited in the changelog. Please do not open public issues for security reports.

## What this repository is

A reference, not a hosted service. `sample-app/` is vulnerable on purpose: every flaw in it is planted and marked `PLANT`, so that both scanners have something to find. It is never deployed. GitHub's Dependabot alerts on `sample-app/requirements.txt` are these plants; Dependabot security updates are turned off for this repository so that no automated pull request fixes them, and the auto-merge merges nothing for them. A vulnerability report about this repository is most likely about `migration/migrate.py` or the CI: a finding the gate lets through, or a report it misreads.

## The planted key

The key in `plants/settings.py.b64` is not a credential for any account. It is stored encoded so that it never appears in git history in clear, decoded only for a scan, and redacted from every report the scripts keep.

## Supply chain

- Scanner images are pinned by digest and the Snyk CLI by version and checksum, in `ci-images.pins`.
- Actions are pinned by commit SHA and moved by Dependabot, merged only after the Scan workflow passes.
- Releases carry a signed source archive with build provenance.

## Credentials

One: `SNYK_TOKEN`, an Actions secret the Snyk step reads from the environment. It is never printed, and pull requests from forks do not receive it.
