#!/usr/bin/env python3
"""Map Snyk findings onto GitLab's, carry Snyk's ignores across, and judge
whether the move from one tool to the other lost anything.

    python3 migration/migrate.py --snyk reports/snyk --gitlab reports/gitlab \
        --decisions migration/decisions.json --out reports/migration

Reads the tools' native reports, unchanged:
  reports/snyk/snyk-code.sarif                    snyk code test --sarif-file-output
  reports/snyk/snyk-container.json                snyk container test --app-vulns --json
  reports/gitlab/gl-sast-report.json              GitLab SAST
  reports/gitlab/gl-secret-detection-report.json  GitLab Secret Detection
  reports/gitlab/gl-container-scanning-report.json
                                                  GitLab Container Scanning, with
                                                  language packages turned on

Writes to --out:
  report.md                      the validation report, for people
  mapping.json                   every Snyk finding, what it became, and why
  vulnerability-allowlist.yml    Snyk's container ignores, for GitLab
  dismissals.json                Snyk's code ignores, for GitLab's API

Exits 1 when the gate fails, 2 when an input cannot be read. The gate:
  1. Every critical or high Snyk finding has a GitLab counterpart, or a
     recorded decision in --decisions saying why it does not need one.
  2. Every Snyk ignore is carried across with its reason, and none has
     expired: GitLab's allowlist has no expiry, so a temporary acceptance
     carried as it is would become a permanent one.
  3. Every recorded decision still matches a finding. A decision for a
     finding that no longer exists is reported, so the file cannot rot.

Standard library only: this runs wherever Python 3.9+ does.
"""
import argparse
import datetime as dt
import json
import os
import sys

SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"]
GATED = {"critical", "high"}
# SARIF has levels, not severities. Snyk Code writes error for its high
# findings, warning for medium and note for low.
SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low"}
# Snyk Code's hardcoded-secret rules carry these CWEs. A GitLab secret is
# found by Secret Detection, not by SAST, so the two meet by file and line.
SECRET_CWES = {"CWE-547", "CWE-798", "CWE-259", "CWE-321"}


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        print("cannot read %s: %s" % (path, e), file=sys.stderr)
        sys.exit(2)


def norm_sev(s):
    s = (s or "unknown").lower()
    return s if s in SEVERITIES else "unknown"


def cwe_id(value):
    """'89', 'CWE-89' and 'cwe-89' are one weakness."""
    v = str(value).upper()
    return v if v.startswith("CWE-") else "CWE-" + v


def os_package(vuln):
    """Snyk names an OS finding by its source package (systemd) and the path
    by the binary one (systemd/libudev1@241-7); GitLab names the binary. The
    binary is what both tools actually saw installed."""
    last = vuln["from"][-1].split("@")[0]
    return last.split("/")[-1].lower()


# ---- Snyk -----------------------------------------------------------------

def snyk_findings(snyk_dir):
    out = []
    sarif = load(os.path.join(snyk_dir, "snyk-code.sarif"))
    for run in sarif.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for r in run.get("results", []):
            loc = r["locations"][0]["physicalLocation"]
            cwes = [cwe_id(c) for c in rules.get(r["ruleId"], {}).get("properties", {}).get("cwe", [])]
            kind = "secret" if SECRET_CWES & set(cwes) else "code"
            out.append({
                "id": r["ruleId"], "kind": kind, "severity": SARIF_LEVEL.get(r.get("level"), "unknown"),
                "file": loc["artifactLocation"]["uri"], "line": loc.get("region", {}).get("startLine"),
                "cwes": cwes, "ignore": None,
            })
    cont = load(os.path.join(snyk_dir, "snyk-container.json"))
    parts = cont if isinstance(cont, list) else [cont]
    seen = set()

    def add(vuln, kind, package, ignored):
        key = (vuln["id"], package)
        if key in seen:                 # one finding per package, however many paths reach it
            return
        seen.add(key)
        reason = None
        if ignored:
            ig = (vuln.get("filtered") or {}).get("ignored") or [{}]
            reason = {"reason": ig[0].get("reason", ""), "expires": ig[0].get("expires")}
        out.append({
            "id": vuln["id"], "kind": kind, "severity": norm_sev(vuln.get("severity")),
            "package": package, "version": vuln.get("version"),
            "cves": vuln.get("identifiers", {}).get("CVE", []), "ignore": reason,
        })

    for p in parts:
        for v in p.get("vulnerabilities", []):
            add(v, "os", os_package(v), False)
        for v in (p.get("filtered") or {}).get("ignore", []):
            add(v, "os", os_package(v), True)
        for a in p.get("applications", []):
            for v in a.get("vulnerabilities", []):
                add(v, "app", v["packageName"].lower(), False)
            for v in (a.get("filtered") or {}).get("ignore", []):
                add(v, "app", v["packageName"].lower(), True)
    return out


# ---- GitLab ---------------------------------------------------------------

def gitlab_findings(gitlab_dir):
    out = []
    for name, kind in (("gl-sast-report.json", "code"),
                       ("gl-secret-detection-report.json", "secret"),
                       ("gl-container-scanning-report.json", "dependency")):
        report = load(os.path.join(gitlab_dir, name))
        for v in report.get("vulnerabilities", []):
            ids = v.get("identifiers", [])
            loc = v.get("location", {})
            dep = loc.get("dependency", {})
            out.append({
                "id": v["id"], "kind": kind, "severity": norm_sev(v.get("severity")),
                "name": v.get("name") or ids[0]["value"],
                "file": loc.get("file"), "line": loc.get("start_line"),
                "cwes": [cwe_id(i["value"]) for i in ids if i.get("type") == "cwe"],
                "cves": [i["value"] for i in ids if i.get("type") == "cve"],
                "package": (dep.get("package") or {}).get("name", "").lower() or None,
            })
    return out


# ---- matching ---------------------------------------------------------------

def match(s, gitlab):
    """The GitLab findings a Snyk finding became. Code meets code on file,
    line and weakness; a secret meets a secret on file and line; a package
    meets a package on CVE and the installed package's name."""
    if s["kind"] == "code":
        return [g for g in gitlab if g["kind"] == "code" and g["file"] == s["file"]
                and g["line"] == s["line"] and set(g["cwes"]) & set(s["cwes"])]
    if s["kind"] == "secret":
        return [g for g in gitlab if g["kind"] == "secret" and g["file"] == s["file"] and g["line"] == s["line"]]
    return [g for g in gitlab if g["kind"] == "dependency" and g["package"] == s["package"]
            and set(g["cves"]) & set(s["cves"])]


def decided(s, decisions):
    """The recorded decision for this gap, if any. A Snyk Code rule fires on
    many lines, so a decision names the file and line; a package decision
    names the package. A field a decision leaves out matches anything."""
    for d in decisions:
        if d["snyk_id"] == s["id"] and all(d.get(k) in (None, s.get(k)) for k in ("file", "line", "package")):
            return d
    return None


def run(args):
    snyk = snyk_findings(args.snyk)
    gitlab = gitlab_findings(args.gitlab)
    decisions = load(args.decisions) if args.decisions else {"accepted_gaps": []}
    gaps_ok = decisions.get("accepted_gaps", [])
    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()

    rows, failures, used_decisions = [], [], set()
    allow, dismiss = [], []
    matched_gitlab = set()
    for s in snyk:
        hits = match(s, gitlab)
        matched_gitlab.update(g["id"] for g in hits)
        row = dict(s, gitlab=[g["id"] for g in hits])
        if s["ignore"] is not None:
            exp = s["ignore"].get("expires")
            expired = exp and dt.date.fromisoformat(exp[:10]) < today
            if expired:
                row["outcome"] = "ignore expired"
                failures.append("%s: its Snyk ignore expired on %s; decide again before it is carried" % (s["id"], exp[:10]))
            elif not s["ignore"].get("reason"):
                row["outcome"] = "ignore without a reason"
                failures.append("%s: its Snyk ignore has no reason, and GitLab would keep it with none" % s["id"])
            else:
                row["outcome"] = "ignore carried"
                note = "%s (Snyk %s, expires %s)" % (s["ignore"]["reason"], s["id"], (exp or "never")[:10])
                if s["kind"] in ("os", "app"):
                    for cve in s["cves"]:
                        allow.append((cve, s["package"], note))
                else:
                    dismiss.append({"gitlab_finding_ids": row["gitlab"], "snyk_id": s["id"], "comment": note,
                                    "dismissal_reason": "ACCEPTABLE_RISK"})
        elif hits:
            row["outcome"] = "matched"
        elif decided(s, gaps_ok):
            d = decided(s, gaps_ok)
            used_decisions.add(id(d))
            row["outcome"] = "gap, decided"
            row["decision"] = d["reason"]
        elif s["severity"] in GATED:
            row["outcome"] = "gap, undecided"
            failures.append("%s (%s, %s): no GitLab finding and no recorded decision" % (
                s["id"], s["severity"], s.get("file") or s.get("package")))
        else:
            row["outcome"] = "gap, below the gate"
        rows.append(row)
    for d in gaps_ok:
        if not d.get("reason"):
            failures.append("%s: a recorded decision without a reason is not a decision" % d["snyk_id"])
        if id(d) not in used_decisions:
            failures.append("%s: a decision is recorded for a gap that no longer exists; remove it" % d["snyk_id"])
    new_in_gitlab = [g for g in gitlab if g["id"] not in matched_gitlab]

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "mapping.json"), "w", encoding="utf-8") as f:
        json.dump({"snyk": rows, "new_in_gitlab": new_in_gitlab, "failures": failures}, f, indent=1)
    with open(os.path.join(args.out, "vulnerability-allowlist.yml"), "w", encoding="utf-8") as f:
        f.write("# Generated by migration/migrate.py from Snyk's ignores. GitLab's\n"
                "# allowlist has no expiry field, so each expiry is kept in the comment\n"
                "# and enforced by the migration gate, which fails once it passes.\n")
        f.write("generalallowlist:\n" if allow else "generalallowlist: {}\n")
        for cve, pkg, note in sorted(set(allow)):
            f.write("  %s: %s  # %s\n" % (cve, pkg, note.replace("\n", " ")))
    with open(os.path.join(args.out, "dismissals.json"), "w", encoding="utf-8") as f:
        json.dump(dismiss, f, indent=1)
    write_report(os.path.join(args.out, "report.md"), rows, new_in_gitlab, failures, today)
    print("%d Snyk findings: %s" % (len(rows), ", ".join(
        "%d %s" % (n, o) for o, n in sorted(count(rows, "outcome").items()))))
    print("%d GitLab findings with no Snyk counterpart" % len(new_in_gitlab))
    for line in failures:
        print("GATE: " + line)
    return 1 if failures else 0


def count(rows, key):
    c = {}
    for r in rows:
        c[r[key]] = c.get(r[key], 0) + 1
    return c


def write_report(path, rows, new_in_gitlab, failures, today):
    kinds = [("code", "SAST"), ("secret", "Secrets"), ("os", "OS packages"), ("app", "Application packages")]
    outcomes = ["matched", "ignore carried", "gap, decided", "gap, below the gate", "gap, undecided",
                "ignore expired", "ignore without a reason"]
    lines = ["# Migration validation report", "",
             "Judged on %s. %s." % (today.isoformat(), "The gate passes" if not failures else
                                    "**The gate fails: %d item(s) below**" % len(failures)), "",
             "| Snyk findings | " + " | ".join(outcomes) + " |",
             "|---|" + "---:|" * len(outcomes)]
    for kind, label in kinds:
        sub = [r for r in rows if r["kind"] == kind]
        c = count(sub, "outcome")
        lines.append("| %s (%d) | " % (label, len(sub)) + " | ".join(str(c.get(o, 0)) for o in outcomes) + " |")
    lines += ["", "Counted once per Snyk issue and installed package, however many dependency paths reach it.", ""]
    if failures:
        lines += ["## What fails the gate", ""] + ["- " + f for f in failures] + [""]
    decided = [r for r in rows if r["outcome"] == "gap, decided"]
    if decided:
        lines += ["## Gaps with a recorded decision", ""]
        lines += ["- `%s` (%s, %s): %s" % (r["id"], r["severity"], r.get("file") or r.get("package"), r["decision"]) for r in decided]
        lines.append("")
    carried = [r for r in rows if r["outcome"] == "ignore carried"]
    if carried:
        lines += ["## Ignores carried to GitLab", ""]
        lines += ["- `%s` (%s): %s Expires %s." % (r["id"], ", ".join(r.get("cves") or []) or r.get("file"),
                                                 r["ignore"]["reason"].rstrip(), (r["ignore"]["expires"] or "never")[:10]) for r in carried]
        lines.append("")
    sev = count(new_in_gitlab, "severity")
    lines += ["## Found by GitLab only", "",
              "%d finding(s): %s. A new scanner finds new things; these are reported for triage, not gated." % (
                  len(new_in_gitlab), ", ".join("%d %s" % (sev[s], s) for s in SEVERITIES if s in sev) or "none"), ""]
    top = sorted((g for g in new_in_gitlab if g["severity"] in GATED), key=lambda g: (SEVERITIES.index(g["severity"]), g["name"]))
    lines += ["- %s: %s (%s)" % (g["severity"], g["name"], g.get("package") or "%s:%s" % (g["file"], g["line"])) for g in top]
    lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--snyk", required=True)
    ap.add_argument("--gitlab", required=True)
    ap.add_argument("--decisions")
    ap.add_argument("--out", required=True)
    ap.add_argument("--today", help="judge expiries as of this date (YYYY-MM-DD); default today")
    sys.exit(run(ap.parse_args()))


if __name__ == "__main__":
    main()
