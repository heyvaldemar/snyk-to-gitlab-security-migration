#!/usr/bin/env bash
# Runs Snyk on the same sample and the same image the GitLab analyzers see,
# and keeps its native reports in reports/snyk/:
#   snyk code test       -> snyk-code.sarif       (SAST, hardcoded secrets)
#   snyk container test  -> snyk-container.json   (OS packages, and the Python
#                           packages in the image with --app-vulns)
#
#   SNYK_TOKEN=… ./scripts/scan-snyk.sh <image>
#
# The token is read from the environment by the CLI and never printed here.
# Snyk exits 1 when it finds issues, which is the point of the sample, and 2
# or 3 when the scan itself failed; only the second is an error.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
image="${1:?usage: scan-snyk.sh <registry/image:tag>}"
[ -n "${SNYK_TOKEN:-}" ] || { echo "SNYK_TOKEN is not set" >&2; exit 2; }
out="$ROOT/reports/snyk"; mkdir -p "$out"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
cp -R sample-app/. "$work/"
base64 -d < plants/settings.py.b64 > "$work/settings.py"

snyk_ok() { local rc=0; "$@" || rc=$?; [ "$rc" -le 1 ] || { echo "snyk failed (exit $rc): $*" >&2; exit "$rc"; }; }
( cd "$work" && snyk_ok snyk code test . --sarif-file-output="$out/snyk-code.sarif" >/dev/null )
snyk_ok snyk container test "$image" --app-vulns --file="$work/Dockerfile" \
  --policy-path="$work" --json-file-output="$out/snyk-container.json" >/dev/null

# The planted key must not travel with the reports: GitLab's secret report
# quotes the line it found the key on, and the reports are kept as artifacts.
python3 - "$out" "$work/settings.py" <<'SCRUB'
import os, re, sys
key = re.search(r'"([^"]+)"', open(sys.argv[2]).read()).group(1)
for name in os.listdir(sys.argv[1]):
    path = os.path.join(sys.argv[1], name)
    text = open(path).read()
    if key in text:
        open(path, "w").write(text.replace(key, "<planted key, redacted>"))
SCRUB
python3 - "$out" <<'PY'
import json, os, sys
d = sys.argv[1]
code = json.load(open(os.path.join(d, "snyk-code.sarif")))
print("%-36s %4d findings" % ("snyk-code.sarif", sum(len(r.get("results", [])) for r in code["runs"])))
cont = json.load(open(os.path.join(d, "snyk-container.json")))
parts = cont if isinstance(cont, list) else [cont]
print("%-36s %4d findings in %d parts" % ("snyk-container.json", sum(len(p.get("vulnerabilities", [])) for p in parts), len(parts)))
PY
