# Working on this repository as an agent

Most of the code here is written by an AI agent, and the decisions and the verification are the maintainer's. This file is what the agent is held to. A reviewer can hold it to the same rules.

## What this repository claims

Every number in the README comes from a named CI run's reports, and every finding it describes ("What the move turned up") was read out of those reports, not out of documentation. A claim with no run behind it is not written. When the README's numbers are refreshed, they come from one run, and the run is linked.

## A check is trusted only after it has failed

A new or changed gate rule ships with a test in `tests/test_migrate.py` that feeds it the report that breaks it and expects the gate to fail. Before a change to `migration/migrate.py` merges, switch the rule it touches off and see the tests catch it.

## The planted key

Never write it in clear: not in a file, a commit message, a test, a log or a report. It lives in `plants/settings.py.b64`, and both scan scripts redact it from what they keep. Fixtures in `tests/fixtures/` are real reports with the key redacted; check for it before adding one.

## Pins

Scanner images by digest and the Snyk CLI by version and sha256, in `ci-images.pins`, moved by hand with the new hash checked against the publisher's. Actions by commit SHA, moved by Dependabot and merged only after Scan passes. The sample's base image is pinned by digest and is old on purpose.

## Licences

Only the MIT-licensed GitLab analyzers run here (SAST, Secret Detection, Container Scanning). Analyzers under the GitLab Enterprise Edition licence are not run outside GitLab, and Ultimate features are never switched on by setting variables a GitLab instance would set.
