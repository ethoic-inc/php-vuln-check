#!/usr/bin/env python3
"""Smoke test that CI runs inside a real distro container (see .github/workflows/distros.yml).

Not collected by `unittest discover` (the name does not start with test_). It runs the
real tool against the PHP packages installed in this container, checks that exec mode and
--no-exec mode agree, and then runs the unit tests on this container's Python.

Environment:
  EXPECT_PKG=1      at least one finding must be owned by a dpkg/rpm package
  EXPECT_MODPHP=1   an Apache libphp module must be found with a version
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "php_vuln_check.py")
STATUSES = {"PATCHED", "VULNERABLE", "REVIEW"}
failures = []


def fail(message):
    failures.append(message)
    print("FAIL: " + message)


def run(args):
    return subprocess.run([sys.executable] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, cwd=ROOT)


def scan(*extra):
    p = run([TOOL, "scan", "--format", "json", "--fail-on", "never"] + list(extra))
    if p.returncode != 0:
        fail("scan %s exited %s: %s" % (" ".join(extra), p.returncode, p.stderr.strip()[:300]))
        return []
    return json.loads(p.stdout)["findings"]


def numeric(version):
    return tuple(version.split(".")[:3]) if version else None


def show(title, findings):
    print("== " + title)
    for f in findings:
        print("  %-8s %-10s %-34s v=%-8s sapi=%-14s pkg=%s" % (
            f["kind"], f["status"], f["target"], f["version"], f["sapi"], f["package"]))
        print("           %s" % f["reason"])
        if f["config"]:
            print("           config: %s" % f["config"])


print("python %s on %s" % (sys.version.split()[0], os.uname().sysname))
executed = scan()
static = scan("--no-exec")
show("exec mode", executed)
show("--no-exec mode", static)

if not any(f["kind"] == "binary" for f in executed):
    fail("no PHP binary was found in exec mode")
for f in executed + static:
    if f["status"] not in STATUSES:
        fail("unexpected status %r for %s" % (f["status"], f["target"]))
    if f["status"] == "PATCHED" and not f["version"]:
        fail("PATCHED without a version for %s" % f["target"])
for f in executed:
    if f["kind"] == "binary" and not f["version"]:
        fail("exec mode could not read the version of %s" % f["target"])

by_target = dict((f["target"], f) for f in static)
for f in executed:
    other = by_target.get(f["target"])
    if other is None:
        fail("--no-exec mode missed %s" % f["target"])
    elif f["version"] and numeric(other["version"]) != numeric(f["version"]):
        fail("version mismatch for %s: exec=%s no-exec=%s" % (f["target"], f["version"], other["version"]))

if os.environ.get("EXPECT_PKG") == "1" and not any(f["package"] for f in executed):
    fail("expected at least one package-owned PHP install")
if os.environ.get("EXPECT_MODPHP") == "1" and not any(f["kind"] == "mod_php" and f["version"] for f in executed):
    fail("expected an Apache libphp module with a readable version")

p = run([TOOL, "images", "examples/demo", "--format", "sarif", "--fail-on", "never"])
if p.returncode != 0 or not json.loads(p.stdout)["runs"][0]["results"]:
    fail("images demo did not produce SARIF results: %s" % p.stderr.strip()[:300])

print("== unit tests on this Python")
tests = run(["-m", "unittest", "discover", "-s", "tests"])
print(tests.stderr.strip().splitlines()[-1] if tests.stderr.strip() else tests.stdout.strip())
if tests.returncode != 0:
    fail("unit tests failed on Python %s:\n%s" % (sys.version.split()[0], tests.stderr[-1500:]))

print("RESULT: " + ("FAILED (%d)" % len(failures) if failures else "ok"))
sys.exit(1 if failures else 0)
