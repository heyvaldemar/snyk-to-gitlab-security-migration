#!/usr/bin/env bash
# Runs GitLab's three MIT-licensed analyzers on sample-app and keeps their
# native reports in reports/gitlab/. The same command runs on a laptop and in CI.
#
#   ./scripts/scan-gitlab.sh <image the container scanner can pull>
#
# The analyzers write into the directory they scan, so they get a copy of
# sample-app, with the planted key decoded into it: the key lives in plants/
# as base64 so that no scanner, and no push protection, ever sees it in git.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# The pins are KEY=value lines, read as data.
set -a
# shellcheck disable=SC1091
. ./ci-images.pins
set +a
image="${1:?usage: scan-gitlab.sh <registry/image:tag>}"
out="reports/gitlab"; mkdir -p "$out"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
# The container scanner runs as an unprivileged user and writes its report
# here; a 0700 temp directory owned by the runner would refuse it.
chmod 0777 "$work"
cp -R sample-app/. "$work/"
base64 -d < plants/settings.py.b64 > "$work/settings.py"

docker run --rm -e CI_PROJECT_DIR=/src -v "$work:/src" -w /src "$SEMGREP_IMAGE" /analyzer run
docker run --rm -e CI_PROJECT_DIR=/src -v "$work:/src" -w /src "$SECRETS_IMAGE" /analyzer run
docker run --rm --network host -e CI_PROJECT_DIR=/src \
  -e CS_IMAGE="$image" -e CS_REGISTRY_INSECURE=true \
  -e CS_DISABLE_LANGUAGE_VULNERABILITY_SCAN=false \
  -v "$work:/src" -w /src "$CONTAINER_SCANNING_IMAGE" gtcs scan

for r in sast secret-detection container-scanning; do
  cp "$work/gl-$r-report.json" "$out/" || { echo "no gl-$r-report.json was written" >&2; exit 1; }
done
python3 - "$out" <<'PY'
import json, os, sys
for name in sorted(os.listdir(sys.argv[1])):
    d = json.load(open(os.path.join(sys.argv[1], name)))
    print("%-36s %4d findings  (%s %s)" % (name, len(d["vulnerabilities"]), d["scan"]["scanner"]["id"], d["scan"]["scanner"]["version"]))
PY
