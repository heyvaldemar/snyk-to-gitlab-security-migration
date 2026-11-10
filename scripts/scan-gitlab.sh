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

# The analyzers are named by tag (ci-images.pins says why). Each is pulled
# once here and run by the digest that pull returned, not by the tag, so the
# digest written down at the end is the build that ran. A pull that fails
# stops the scan: an older build left on this machine is not the one to run.
pulled() {
  docker pull -q "$1" >/dev/null || return 1
  docker image inspect --format '{{index .RepoDigests 0}}' "$1"
}
semgrep="$(pulled "$SEMGREP_IMAGE")"
secrets="$(pulled "$SECRETS_IMAGE")"
scanning="$(pulled "$CONTAINER_SCANNING_IMAGE")"

docker run --rm -e CI_PROJECT_DIR=/src -v "$work:/src" -w /src "$semgrep" /analyzer run
docker run --rm -e CI_PROJECT_DIR=/src -v "$work:/src" -w /src "$secrets" /analyzer run
CS_IMAGE="$image" docker run --rm --network host -e CI_PROJECT_DIR=/src \
  -e CS_IMAGE -e CS_REGISTRY_INSECURE=true \
  -e CS_DISABLE_LANGUAGE_VULNERABILITY_SCAN=false \
  -v "$work:/src" -w /src "$scanning" gtcs scan

for r in sast secret-detection container-scanning; do
  cp "$work/gl-$r-report.json" "$out/" || { echo "no gl-$r-report.json was written" >&2; exit 1; }
done
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
# What ran, next to the reports: the tag each analyzer was named by, the
# digest that tag gave this run, and the versions the report itself states.
python3 - "$out" \
  "$SEMGREP_IMAGE" "$semgrep" "$SECRETS_IMAGE" "$secrets" "$CONTAINER_SCANNING_IMAGE" "$scanning" <<'PY'
import json, os, sys
out = sys.argv[1]
ran = dict(zip(("gl-sast-report.json", "gl-secret-detection-report.json", "gl-container-scanning-report.json"),
               zip(sys.argv[2::2], sys.argv[3::2])))
analyzers = []
for name in sorted(ran):
    d = json.load(open(os.path.join(out, name)))
    scan, (named, digest) = d["scan"], ran[name]
    analyzer = scan.get("analyzer") or {}
    print("%-36s %4d findings  (%s %s)" % (name, len(d["vulnerabilities"]), scan["scanner"]["id"], scan["scanner"]["version"]))
    print("%-36s ran %s" % ("", digest))
    analyzers.append({"report": name, "named": named, "ran": digest,
                      "analyzer": analyzer.get("id"), "analyzer_version": analyzer.get("version"),
                      "scanner": scan["scanner"]["id"], "scanner_version": scan["scanner"]["version"]})
with open(os.path.join(os.path.dirname(out), "analyzers.json"), "w") as f:
    json.dump(analyzers, f, indent=2)
    f.write("\n")
PY
