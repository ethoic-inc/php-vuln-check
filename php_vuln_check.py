#!/usr/bin/env python3
"""php-vuln-check: find PHP installs exposed to known PHP vulnerabilities.

Starts with PHP2Shell (CVE-2026-109618 / CVE-2026-109619). Checks servers,
Docker images, Kubernetes and CI pipelines without sending exploit traffic: it
reads versions, vendor changelogs and config, and never probes a target into
failing.

Single file, standard library only, Python 3.6+.
https://github.com/ethoic-inc/php-vuln-check  (MIT License)
"""
import argparse
import csv
import datetime
import glob
import gzip
import io
import json
import os
import re
import shlex
import signal
import socket
import stat
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

__version__ = "0.1.4"
REPO_URL = "https://github.com/ethoic-inc/php-vuln-check"

VULNERABLE, REVIEW, PATCHED, ERROR, NONE = "VULNERABLE", "REVIEW", "PATCHED", "ERROR", "NONE"
STATUS_ORDER = {VULNERABLE: 0, ERROR: 1, REVIEW: 2, PATCHED: 3, NONE: 4}

# One entry per advisory. Adding the next PHP CVE means adding one dict here.
ADVISORIES = [
    {
        "id": "PHP2SHELL",
        "name": "PHP2Shell",
        "cves": ["CVE-2026-109618", "CVE-2026-109619"],
        "severity": "critical",
        "cvss": "9.2 (CVSS v4.0)",
        "published": "2026-10-21",
        # PHP's own advisories list only 8.2 to 8.5; Sansec reports exposure back to 5.4 (older branches get no release).
        "min_affected": "5.4.0",
        "fixed": {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"},
        "summary": (
            "Unauthenticated remote code execution in the PHP engine (Apache mod_php "
            "and PHP-FPM), triggered by a fatal error such as running out of memory "
            "while PHP parses a request, for example a multipart/form-data upload."
        ),
        # Ordered as PHP's advisory ranks them: memory_limit=-1 is its primary config mitigation.
        "mitigations": [
            "Update PHP to a fixed release, or to a vendor build whose changelog lists both CVEs, then restart PHP-FPM / Apache.",
            "PHP 7.4, 8.0 and 8.1 are end of life with no release, but PHP published source backports on php-src branches (PHP-7.4-CVE-2026-109618-109619, PHP-8.0-CVE-2026-109618-109619 and PHP-8.1-CVE-2026-109618-109619). Build from them or use a vendor backport; older branches get nothing, so upgrade.",
            "Temporary and partial: enforce memory_limit=-1 in admin config (php.ini or php_admin_value, not .user.ini) and cap request body size at the web server; watch memory use.",
            "Temporary and partial: set session.upload_progress.enabled=0, and on PHP 8.5 also fatal_error_backtraces=0, then restart every worker.",
            "Temporary and partial: if the application takes no uploads, block multipart/form-data requests at the web server.",
        ],
        # Distro builds that fix both CVEs without a new upstream version, from each vendor notice.
        # Used when the package changelog is not installed: Docker's ubuntu and debian images strip /usr/share/doc.
        # Debian's fixes (DSA-6574-1 and the bookworm update) are upstream releases, so the version check covers them.
        "vendor_fixed": {
            "USN-8948-1": {
                "php8.5": ["8.5.9-0ubuntu2.1", "8.5.4-0ubuntu1.5"],
                "php8.3": ["8.3.6-0ubuntu0.24.04.13"],
                "php8.1": ["8.1.2-1ubuntu2.28"],
            },
        },
        "references": [
            {"title": "PHP advisory for CVE-2026-109618", "url": "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"},
            {"title": "PHP advisory for CVE-2026-109619", "url": "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"},
            {"title": "PHP source backports for 7.4, 8.0 and 8.1", "url": "https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619"},
            {"title": "Ubuntu USN-8948-1", "url": "https://ubuntu.com/security/notices/USN-8948-1"},
            {"title": "Sansec research", "url": "https://sansec.io/research/php2shell"},
            {"title": "Help Net Security", "url": "https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/"},
            {"title": "watchTowr FAQ", "url": "https://watchtowr.com/intelligence/php-cve-2026-109618-faq/"},
        ],
    }
]
ADVISORIES_BY_ID = {a["id"]: a for a in ADVISORIES}
# The day ADVISORIES (fixed versions and vendor builds) was last checked against the vendors.
# Bump it with every data update; reports warn once it is older than STALE_AFTER_DAYS.
DATA_CHECKED = "2026-10-23"
STALE_AFTER_DAYS = 30

CONFIG_KEYS = ("session.upload_progress.enabled", "memory_limit", "fatal_error_backtraces")

# Digit runs are capped at 6 and must end there, so an absurdly long number is rejected rather than truncated.
VERSION_RE = re.compile(r"^(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?!\d)(.*)$", re.S)
PRERELEASE_RE = re.compile(r"(?<![A-Za-z])(alpha|beta|rc|dev)(?![A-Za-z])", re.I)
DASH_V_RE = re.compile(r"^PHP (\d{1,6}\.\d{1,6}\.\d{1,6}(?!\d))(\S*)\s+\(([^)]+)\)")
STATIC_RE = re.compile(rb"X-Powered-By: PHP/(\d{1,6}\.\d{1,6}\.\d{1,6}(?!\d)[0-9A-Za-z.+~_-]*)")
HEADER_RE = re.compile(r"PHP/(\d{1,6}\.\d{1,6}\.\d{1,6}(?!\d)[0-9A-Za-z.+~_-]*)")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

MAX_TEXT_FILE = 2 * 1024 * 1024
BIN = {"dpkg": "/usr/bin/dpkg", "dpkg-query": "/usr/bin/dpkg-query", "rpm": "/usr/bin/rpm"}


class UsageError(Exception):
    """A problem with how the tool was invoked; reported with exit code 3."""


def clean(value, limit=500):
    """Make a value safe to print: no control characters, bounded length."""
    return CONTROL_RE.sub("?", "" if value is None else str(value))[:limit]


# --------------------------------------------------------------------------
# Version logic
# --------------------------------------------------------------------------

def parse_version(text):
    """'8.2.30-1ubuntu1' -> (8, 2, 30, '-1ubuntu1'); None when unparsable."""
    m = VERSION_RE.match((text or "").strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4))


def _tuple(text):
    return tuple(int(p) for p in text.split(".")[:3])


def _branch_data(adv):
    fixed = adv["fixed"]
    newest = max(_tuple(b) for b in fixed)
    floor = _tuple(adv["min_affected"])[:2]
    return fixed, newest, floor


def evaluate(adv, version, backports=None, packaged=False, tail=True):
    """Judge one PHP version against one advisory.

    backports: the advisory's CVE ids found in the vendor changelog (a set, empty
    when a changelog was read and named none), or None when no changelog was read.
    packaged: the install belongs to a distro package. tail: add a note about
    vendor backports when the version is below the fix.
    Returns (status, reason).
    """
    major, minor, patch, extra = version
    shown = "%d.%d.%d" % (major, minor, patch)
    branch = "%d.%d" % (major, minor)
    if PRERELEASE_RE.search(extra):
        return REVIEW, "%s looks like a pre-release build; compare it with the PHP release notes" % shown
    fixed_map, newest, floor = _branch_data(adv)
    cves = adv["cves"]
    found = [c for c in cves if backports and c in backports]

    fixed = fixed_map.get(branch)
    if fixed:
        if (major, minor, patch) >= _tuple(fixed):
            if shown == fixed:
                return PATCHED, "%s is the fixed release" % shown
            return PATCHED, "%s is newer than the fixed release %s" % (shown, fixed)
        why = "%s is below the fixed release %s" % (shown, fixed)
    else:
        if (major, minor) > newest:
            return REVIEW, "branch %s is newer than this tool's advisory data; check the PHP release notes" % branch
        if (major, minor) < floor:
            return REVIEW, "%s is older than the documented affected range (PHP %s+) but long end-of-life; upgrade" % (shown, adv["min_affected"].rsplit(".", 1)[0])
        why = "branch %s is end-of-life and has no upstream release" % branch

    if len(found) == len(cves):
        return PATCHED, "%s, but the vendor changelog lists fixes for %s" % (why, " and ".join(cves))
    if found:
        return VULNERABLE, "%s; the vendor changelog only mentions %s" % (why, ", ".join(found))
    if backports is not None:
        return VULNERABLE, "%s; no vendor backport found in the changelog" % why
    if packaged:
        return REVIEW, ("%s; the vendor changelog could not be read here, so a backport cannot be "
                        "ruled out (check the vendor's security advisory)" % why)
    if not tail:
        return VULNERABLE, why
    return VULNERABLE, "%s; not installed from a distro package, so no vendor backport applies" % why


def evaluate_branch_only(adv, major, minor):
    """Judge a floating tag such as php:8.3-apache where the patch level is unknown."""
    fixed_map, newest, floor = _branch_data(adv)
    branch = "%d.%d" % (major, minor)
    if branch in fixed_map:
        return REVIEW, (
            "floating tag: resolves to the newest %s.x at pull time. Pin it to %s or later "
            "and rebuild with --pull" % (branch, fixed_map[branch])
        )
    if (major, minor) > newest:
        return REVIEW, "branch %s is newer than this tool's advisory data" % branch
    if (major, minor) < floor:
        return REVIEW, "branch %s is older than the documented affected range but long end-of-life; upgrade" % branch
    return VULNERABLE, "branch %s is end-of-life with no upstream release; pulling a newer image on this branch cannot fix it" % branch


def package_upstream_version(pkg_version):
    """'1:8.2.30+dfsg-1~deb12u1' -> '8.2.30+dfsg-1~deb12u1' (epoch dropped)."""
    return re.sub(r"^\d+:", "", pkg_version or "")


# --------------------------------------------------------------------------
# Running commands and reading the host
# --------------------------------------------------------------------------

def _drain(pipe, sink, cap):
    kept = 0
    try:
        while True:
            chunk = pipe.read(65536)
            if not chunk:
                break
            if kept < cap:
                sink.append(chunk[:cap - kept])
                kept += len(chunk)
    except (OSError, ValueError):
        pass


def _feed(pipe, data):
    try:
        pipe.write(data)
    except (OSError, ValueError):
        pass
    finally:
        try:
            pipe.close()
        except (OSError, ValueError):
            pass


def run(cmd, timeout=20, stdin=None, cap=8 * 1024 * 1024):
    """Run a command with no terminal input, a capped output and a hard timeout.

    The child gets its own session so a timeout kills grandchildren too.
    Returns (exit_code, stdout, stderr); exit_code is None on failure or timeout.
    """
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except (OSError, ValueError) as exc:
        return None, "", str(exc)
    out, err = [], []
    threads = [threading.Thread(target=_drain, args=(proc.stdout, out, cap), daemon=True),
               threading.Thread(target=_drain, args=(proc.stderr, err, 65536), daemon=True)]
    if stdin is not None:
        threads.append(threading.Thread(target=_feed, args=(proc.stdin, stdin.encode("utf-8")), daemon=True))
    for t in threads:
        t.start()
    code = None
    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()
        proc.wait()
        err.append(b"timed out")
    for t in threads:
        t.join(timeout=2)
    for pipe in (proc.stdout, proc.stderr):
        try:
            pipe.close()
        except (OSError, ValueError):
            pass
    return (code, b"".join(out).decode("utf-8", "replace"), b"".join(err).decode("utf-8", "replace"))


def exec_allowed(path):
    """May we run this binary? Only if it and every parent directory belong to root
    (or to us) and are not writable by group or others."""
    try:
        me = os.geteuid()
        current = os.path.realpath(path)
        while True:
            st = os.stat(current)
            if st.st_uid not in (0, me) or st.st_mode & 0o022:
                return False
            parent = os.path.dirname(current)
            if parent == current:
                return True
            current = parent
    except OSError:
        return False


def static_version(path, limit=512 * 1024 * 1024):
    """Read the version PHP embeds in its own binary, without running it."""
    read, tail = 0, b""
    try:
        with open(path, "rb") as fh:
            while read < limit:
                chunk = fh.read(8 * 1024 * 1024)
                if not chunk:
                    break
                read += len(chunk)
                window = tail + chunk
                m = STATIC_RE.search(window)
                if m and m.end() < len(window):
                    return m.group(1).decode("ascii", "replace")
                # A match touching the end of the window may be cut short: keep it for the next read.
                tail = window[m.start():] if m else window[-256:]
        if tail:
            m = STATIC_RE.search(tail)
            if m:
                return m.group(1).decode("ascii", "replace")
    except OSError:
        return None
    return None


def php_dash_v(path):
    """Run `php -n -v`; return (version_text, sapi) or (None, None)."""
    code, out, _ = run([path, "-n", "-v"], timeout=15, cap=65536)
    if code != 0 or not out:
        return None, None
    m = DASH_V_RE.match(out.splitlines()[0])
    if not m:
        return None, None
    return m.group(1) + m.group(2), m.group(3)


def parse_ini_dump(text):
    values = {}
    for key in CONFIG_KEYS:
        m = re.search(r"^%s\s*=>\s*([0-9A-Za-z_.-]{1,32})" % re.escape(key), text, re.M)
        if m:
            values[key] = m.group(1)
    return values


def php_config(path):
    code, out, _ = run([path, "-i"], timeout=30, cap=8 * 1024 * 1024)
    return parse_ini_dump(out) if code == 0 else {}


POOL_SECTION_RE = re.compile(r"^\s*\[([^\]]{1,64})\]\s*$")
POOL_VALUE_RE = re.compile(r"^\s*php(?:_admin)?_(?:value|flag)\[([\w.]{1,64})\]\s*=\s*['\"]?([0-9A-Za-z_.-]{1,32})['\"]?\s*$")
FPM_INCLUDE_RE = re.compile(r"^\s*include\s*=\s*(\S+)\s*$")


def fpm_main_config(path):
    """The php-fpm.conf this binary reads by packaging convention.

    shortcut: follows the packaging layout only, not a custom -y/--fpm-config; add a --fpm-config
    option if users report pools it misses.
    """
    m = re.match(r"^php-fpm(\d+\.\d+)$", os.path.basename(path))
    if m:  # Debian, Ubuntu and Sury: /usr/sbin/php-fpm8.3
        return "/etc/php/%s/fpm/php-fpm.conf" % m.group(1)
    prefix = os.path.dirname(os.path.dirname(path))  # <root>/usr/sbin/php-fpm -> <root>/usr
    if prefix.endswith("/usr"):
        prefix = prefix[:-len("/usr")]  # RHEL, Remi and cPanel keep etc/ beside usr/
    return os.path.join(prefix or "/", "etc", "php-fpm.conf")


def fpm_pool_overrides(path, max_files=200):
    """Pool-level php_value / php_admin_value settings for CONFIG_KEYS, which `php -i` cannot see.

    Returns {"pool www: memory_limit": "-1"}. Includes are resolved relative to the FPM prefix
    (the folder above etc/), as php-fpm does.
    """
    main = fpm_main_config(path)
    prefix = os.path.dirname(os.path.dirname(main))
    files, values, pending = [], {}, [main]
    while pending and len(files) < max_files:
        conf = pending.pop(0)
        if conf in files:
            continue
        text, _ = read_text_file(conf, limit=1024 * 1024)
        if text is None:
            continue
        files.append(conf)
        pool = None
        for line in text.splitlines():
            m = POOL_SECTION_RE.match(line)
            if m:
                pool = m.group(1)
                continue
            m = FPM_INCLUDE_RE.match(line)
            if m:
                pattern = m.group(1).replace("${prefix}", prefix).replace("$prefix", prefix)
                pending.extend(sorted(glob.glob(os.path.join(prefix, pattern)))[:max_files])
                continue
            m = POOL_VALUE_RE.match(line)
            if m and pool and pool != "global" and m.group(1) in CONFIG_KEYS:
                values["pool %s: %s" % (pool, m.group(1))] = m.group(2)
    return values


def guess_sapi(path):
    name = os.path.basename(path).lower()
    if "fpm" in name:
        return "fpm-fcgi"
    if "cgi" in name:
        return "cgi-fcgi"
    if name.startswith("lsphp"):
        return "litespeed"
    return None


def _dpkg_owner(path):
    if not os.path.exists(BIN["dpkg"]):
        return None
    code, out, _ = run([BIN["dpkg"], "-S", path])
    if code != 0:
        return None
    line = next((l for l in out.splitlines() if l.strip() and not l.startswith("diversion by")), "")
    if ": " not in line:
        return None
    pkg = line.rsplit(": ", 1)[0].split(",")[0].strip().split(":")[0]
    if not pkg:
        return None
    lines = []
    if os.path.exists(BIN["dpkg-query"]):
        code, info, _ = run([BIN["dpkg-query"], "-W", "-f", "${Version}\n${source:Package}\n", pkg])
        lines = info.splitlines() if code == 0 else []
    return {
        "manager": "dpkg", "name": pkg,
        "version": lines[0] if lines else "",
        "source": lines[1] if len(lines) > 1 else "",
    }


def _rpm_owner(path):
    if not os.path.exists(BIN["rpm"]):
        return None
    code, out, _ = run([BIN["rpm"], "-qf", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n", path])
    if code != 0 or "\t" not in out:
        return None
    name, version = out.splitlines()[0].split("\t", 1)
    return {"manager": "rpm", "name": name, "version": version, "source": ""}


def package_owner(path):
    """Which distro package owns this file? Tries dpkg, then rpm."""
    for probe in (_dpkg_owner, _rpm_owner):
        for candidate in dict.fromkeys([path, os.path.realpath(path)]):
            info = probe(candidate)
            if info:
                return info
    return None


def read_text_file(path, limit=MAX_TEXT_FILE):
    """Read a regular text file of at most `limit` bytes. Returns (text, problem)."""
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            return None, "not a regular file"
        with io.open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError as exc:
        return None, "cannot read it (%s)" % (exc.strerror or exc)
    if len(data) > limit:
        return None, "larger than %d MiB" % (limit // (1024 * 1024))
    return data.decode("utf-8-sig", "replace"), None


def _read_gz_or_text(path, limit=20 * 1024 * 1024):
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rb") as fh:
                data = fh.read(limit)
        else:
            with io.open(path, "rb") as fh:
                data = fh.read(limit)
    except (OSError, EOFError):
        return None
    return data.decode("utf-8", "replace")


# A changelog line that names a CVE only counts as a fix when it is not saying the opposite.
NEGATIVE_RE = re.compile(
    r"revert|not affected|unaffected|not vulnerable|pending|todo|not yet|postpone|"
    r"wont ?fix|won't fix|ignore|\bdrop|\bskip", re.I)


def cves_named_in(text, cves):
    """The subset of `cves` that a changelog names on a line that reads like a fix."""
    found = set()
    lines = text.splitlines()
    for cve in cves:
        pattern = re.compile(r"(?<![\w-])%s(?!\d)" % re.escape(cve))
        for line in lines:
            if len(line) < 2000 and pattern.search(line) and not NEGATIVE_RE.search(line):
                found.add(cve)
                break
    return found


def dpkg_changelog(owner, doc_root="/usr/share/doc"):
    names = [owner["name"], owner.get("source") or "",
             re.sub(r"-[a-z0-9]+$", "-common", owner["name"])]
    for name in dict.fromkeys(n for n in names if n):
        for fname in ("changelog.Debian.gz", "changelog.gz", "changelog"):
            text = _read_gz_or_text(os.path.join(doc_root, name, fname))
            if text:
                return text
    return None


def vendor_changelog(owner, path, cves):
    """Return the set of `cves` the owning package's changelog names as fixed, or None."""
    if owner["manager"] == "dpkg":
        text = dpkg_changelog(owner)
    else:
        code, out, _ = run([BIN["rpm"], "-qf", path, "--changelog"], timeout=90)
        text = out if code == 0 else None
    if not text:
        return None
    return cves_named_in(text, cves)


def vendor_fixed_build(adv, owner):
    """(status, reason) from the advisory's list of fixed distro builds, or None without evidence.

    A fixed build only speaks for installs of the same build line: 8.3.6-0ubuntu0.24.04.13 says
    nothing about a Sury 8.3.6-1+ubuntu24.04.1 or about 8.5.9-0ubuntu2 versus 8.5.4-0ubuntu1.5.
    """
    if owner["manager"] != "dpkg" or not owner.get("version"):
        return None
    m = re.search(r"php\d+\.\d+", owner.get("source") or owner["name"])
    installed = package_upstream_version(owner["version"])
    for notice, builds in sorted(adv.get("vendor_fixed", {}).items()):
        for build in builds.get(m.group(0) if m else "", []):
            if not installed.startswith(build.rstrip("0123456789")):
                continue
            code, _, _ = run([BIN["dpkg"], "--compare-versions", installed, "ge", build])
            shown = "package %s %s" % (owner["name"], installed)
            if code == 0:
                return PATCHED, "%s is at or above %s, the fixed build in %s" % (shown, build, notice)
            if code == 1:
                return VULNERABLE, "%s is below %s, the fixed build in %s" % (shown, build, notice)
    return None


def stale_processes(proc_root="/proc"):
    """Running processes that still use a replaced PHP file: {realpath: [pids]}.

    A package update fixes the files on disk, but PHP-FPM and Apache keep running
    the old code until restarted. Linux only; needs root to see other users' processes.
    """
    stale = {}
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return stale
    for name in entries:
        if not name.isdigit():
            continue
        base = os.path.join(proc_root, name)
        try:
            exe = os.readlink(os.path.join(base, "exe"))
        except OSError:
            continue
        if exe.endswith(" (deleted)"):
            old = exe[:-len(" (deleted)")]
            if BIN_NAME_RE.match(os.path.basename(old)):
                stale.setdefault(os.path.realpath(old), []).append(int(name))
        if os.path.basename(exe).lower().startswith(("apache2", "httpd")):
            try:
                with io.open(os.path.join(base, "maps"), "r", errors="replace") as fh:
                    for line in fh:
                        parts = line.rstrip("\n").split(None, 5)
                        if len(parts) == 6 and parts[5].endswith(" (deleted)"):
                            old = parts[5][:-len(" (deleted)")]
                            if LIBPHP_RE.match(os.path.basename(old)):
                                pids = stale.setdefault(os.path.realpath(old), [])
                                if int(name) not in pids:
                                    pids.append(int(name))
            except OSError:
                continue
    return stale


# --------------------------------------------------------------------------
# Finding model
# --------------------------------------------------------------------------

def fixed_in(adv, version):
    """The release that fixes this branch, or the list of fixed releases when it is unknown."""
    fixed = adv["fixed"]
    parts = (version or "").split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        branch = ".".join(parts[:2])
        if branch in fixed:
            return fixed[branch]
        oldest = min(fixed, key=_tuple)
        if (int(parts[0]), int(parts[1])) < _tuple(oldest)[:2]:
            return "no upstream release; move to %s or later, or use a vendor backport" % fixed[oldest]
    return ", ".join(fixed[b] for b in sorted(fixed, key=_tuple))


def make_finding(adv, kind, target, status, reason, **extra):
    finding = {
        "advisory": adv["id"], "host": None, "kind": kind, "target": target,
        "status": status, "reason": reason, "sapi": None, "version": None,
        "package": None, "confidence": None, "config": {}, "location": None,
    }
    finding.update(extra)
    finding["fixed_in"] = fixed_in(adv, finding["version"])
    return finding


def error_finding(adv, kind, target, reason, **extra):
    return make_finding(adv, kind, target, ERROR, reason, **extra)


# --------------------------------------------------------------------------
# scan: a server's own PHP installs
# --------------------------------------------------------------------------

# php, php8.2, php5-fpm, php-fpm8.2, php-cgi, lsphp83 ... but not php-config or phpize
BIN_NAME_RE = re.compile(r"^(?:lsphp[0-9.]*|php[0-9.]*(?:-(?:fpm|cgi)[0-9.]*)?)$")
LIBPHP_RE = re.compile(r"^libphp[0-9.\-]*\.so$")
REAL_NAME_RE = re.compile(r"^(?:lsphp|php|libphp)")
SKIP_DIRS = {".git", "node_modules", ".venv"}
PSEUDO_FS = ("proc", "sys", "dev", "run")

STD_BIN_DIRS = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin",
                "/opt/homebrew/bin"]
GLOB_BIN_DIRS = [
    "/opt/remi/php*/root/usr/bin", "/opt/remi/php*/root/usr/sbin",
    "/opt/plesk/php/*/bin", "/opt/plesk/php/*/sbin",
    "/opt/cpanel/ea-php*/root/usr/bin", "/opt/cpanel/ea-php*/root/usr/sbin",
    "/opt/alt/php*/usr/bin", "/opt/alt/php*/usr/sbin",
    "/usr/local/php*/bin", "/usr/local/php*/sbin", "/opt/php*/bin", "/opt/php*/sbin",
    "/usr/local/lsws/lsphp*/bin", "/opt/homebrew/opt/php*/bin", "/opt/homebrew/opt/php*/sbin",
]
GLOB_MODULE_DIRS = [
    "/usr/lib/apache2/modules", "/usr/lib64/httpd/modules", "/usr/lib/httpd/modules",
    "/usr/libexec/apache2", "/usr/local/apache2/modules",
    "/opt/homebrew/opt/php*/lib/httpd/modules", "/usr/local/opt/php*/lib/httpd/modules",
]


def _consider(path, seen, found):
    name = os.path.basename(path)
    kind = "mod_php" if LIBPHP_RE.match(name) else "binary" if BIN_NAME_RE.match(name) else None
    if not kind:
        return
    real = os.path.realpath(path)
    if real in seen or not os.path.isfile(real):
        return
    # The link's name matched, but what it points at must still look like PHP: a file called
    # "php" that is really a symlink to /bin/sh must not be treated as (or run as) PHP.
    if not REAL_NAME_RE.match(os.path.basename(real)):
        return
    seen.add(real)
    found.append((real, kind))


def _scan_dir(directory, seen, found):
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return
    for name in names:
        _consider(os.path.join(directory, name), seen, found)


def discover(extra_paths=(), defaults=True):
    seen, found = set(), []
    if defaults:
        dirs = list(STD_BIN_DIRS)
        for pattern in GLOB_BIN_DIRS + GLOB_MODULE_DIRS:
            dirs.extend(sorted(glob.glob(pattern)))
        dirs.extend(p for p in os.environ.get("PATH", "").split(os.pathsep) if p and os.path.isabs(p))
        for directory in dict.fromkeys(dirs):
            _scan_dir(directory, seen, found)
    for root in extra_paths:
        if os.path.isfile(root):
            real = os.path.realpath(root)
            if real not in seen:
                seen.add(real)
                found.append((real, "mod_php" if LIBPHP_RE.match(os.path.basename(real)) else "binary"))
            continue
        base_depth = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS
                           and not (dirpath == os.sep and d in PSEUDO_FS)]
            if dirpath.count(os.sep) - base_depth >= 6:
                dirnames[:] = []
            for fname in sorted(filenames):
                _consider(os.path.join(dirpath, fname), seen, found)
    return found


def inspect_target(path, kind, exec_mode, advisories, stale=None):
    """exec_mode: 'auto' runs only trusted binaries, 'always' runs any, 'never' runs none."""
    stale = stale or {}
    owner = package_owner(path)
    sapi = "apache2handler" if kind == "mod_php" else None
    version_text, method, config = None, None, {}

    run_it = kind == "binary" and (exec_mode == "always" or (exec_mode == "auto" and exec_allowed(path)))
    refused = kind == "binary" and exec_mode == "auto" and not run_it
    if run_it:
        version_text, sapi_out = php_dash_v(path)
        if version_text:
            method, sapi = "exec", sapi_out
            config = php_config(path)
    if not version_text:
        version_text = static_version(path)
        method = "static" if version_text else None
    if not version_text and owner and owner["version"]:
        version_text = package_upstream_version(owner["version"])
        method = "package"
    if not sapi and kind == "binary":
        sapi = guess_sapi(path)
    if kind == "binary" and "fpm" in os.path.basename(path).lower():
        config.update(fpm_pool_overrides(path))

    version = parse_version(version_text) if version_text else None
    package = "%s %s" % (owner["name"], owner["version"]) if owner else None
    confidence = {"exec": "high", "static": "high", "package": "medium"}.get(method)

    findings = []
    for adv in advisories:
        if version is None:
            status = REVIEW
            reason = "could not determine the PHP version"
            if refused:
                reason += " (the binary was not run because it or a parent folder is not root-owned or is writable by others; use --exec to allow it)"
            elif exec_mode == "never":
                reason += " (try again without --no-exec)"
        else:
            status, reason = evaluate(adv, version, None, packaged=bool(owner))
            if owner and evaluate(adv, version, set(), packaged=True)[0] == VULNERABLE:
                status, reason = evaluate(adv, version, vendor_changelog(owner, path, adv["cves"]), packaged=True)
                if status != PATCHED:
                    status, reason = vendor_fixed_build(adv, owner) or (status, reason)
            if status == PATCHED and stale.get(path):
                pids = ", ".join(str(p) for p in sorted(stale[path])[:5])
                status = REVIEW
                reason += ("; but running processes (pid %s) still use the old file, so restart "
                           "PHP-FPM / Apache to load the fix" % pids)
        findings.append(make_finding(
            adv, kind, path, status, reason, sapi=sapi, package=package, config=config,
            version="%d.%d.%d" % version[:3] if version else None, confidence=confidence,
            host=socket.gethostname(),
        ))
    return findings


def _require_paths(paths):
    for p in paths or []:
        if not os.path.exists(p):
            raise UsageError("path does not exist: %s" % p)


def cmd_scan(args, advisories):
    _require_paths(args.path)
    exec_mode = "never" if args.no_exec else "always" if args.exec else "auto"
    targets = discover(args.path or [], defaults=not args.no_defaults)
    stale = stale_processes()
    findings = []
    for path, kind in targets:
        findings.extend(inspect_target(path, kind, exec_mode, advisories, stale))
    notes = []
    if not targets:
        notes.append("No PHP binaries or Apache mod_php modules were found in the searched locations. "
                     "PHP in a custom prefix, a container or a vhost folder will not appear: use --path DIR.")
    return findings, notes


# --------------------------------------------------------------------------
# images: Dockerfiles, compose files, Kubernetes manifests, running containers
# --------------------------------------------------------------------------

FROM_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.I)
COPY_FROM_RE = re.compile(r"^\s*COPY\s+(?:--\S+\s+)*?--from=(\S+)", re.I)
ARG_RE = re.compile(r"^\s*ARG\s+([A-Za-z_]\w*)(?:=(.*))?\s*$")
YAML_IMAGE_RE = re.compile(r"^[ \t]*(?:-[ \t]+)?image:[ \t]*['\"]?([^\s'\"#]+)")
JSON_IMAGE_RE = re.compile(r'"image"\s*:\s*"([^"\s]+)"')
VAR_RE = re.compile(r"\$\{(\w+)(?::?-([^}]*))?\}|\$(\w+)")
TAG_VERSION_RE = re.compile(r"^(\d{1,6})(?!\d)(?:\.(\d{1,6})(?!\d))?(?:\.(\d{1,6})(?!\d))?(.*)$", re.S)
BUNDLED_RE = re.compile(r"php(\d{1,6})\.(\d{1,6})(?!\d)(?:\.(\d{1,6})(?!\d))?")
OFFICIAL_PHP = {"php", "library/php", "docker.io/library/php", "index.docker.io/library/php",
                "registry.hub.docker.com/library/php"}
PHP_IMAGE_NAMES = {"php", "php-fpm", "php-cli", "php-apache", "php-nginx", "php-fpm-nginx"}
IMAGE_SKIP_DIRS = {".git", "node_modules", ".venv", "vendor", "__pycache__"}
MAX_LINE = 20000


def substitute(text, variables):
    """Expand $VAR and ${VAR:-default}. Returns (text, used) where `used` says a
    variable or a default decided part of the result."""
    used = []

    def repl(m):
        name = m.group(1) or m.group(3)
        if name in variables:
            used.append(name)
            return variables[name]
        if m.group(2) is not None:
            used.append(name)
            return m.group(2)
        return m.group(0)
    return VAR_RE.sub(repl, text), bool(used)


def parse_image(ref):
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        cut = ref.rfind(":")
        ref, tag = ref[:cut], ref[cut + 1:]
    return ref, tag, digest


def _is_dockerfile(fname):
    low = fname.lower()
    return (low.startswith(("dockerfile", "containerfile"))
            or low.endswith((".dockerfile", ".containerfile")))


def _logical_lines(text):
    """Dockerfile lines with backslash continuations joined; yields (first_line_number, text)."""
    pending, start = "", 0
    for number, line in enumerate(text.splitlines(), 1):
        if len(line) > MAX_LINE:
            line = line[:MAX_LINE]
        if not pending:
            start = number
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        yield start, pending + line
        pending = ""
    if pending:
        yield start, pending


def _dockerfile_refs(text):
    global_args, stages, seen_from = {}, set(), False
    for number, line in _logical_lines(text):
        if line.lstrip().startswith("#"):
            continue
        arg = ARG_RE.match(line)
        if arg:
            if not seen_from and arg.group(2) is not None:
                global_args[arg.group(1)] = arg.group(2).strip().strip("'\"")
            continue
        m = FROM_RE.match(line)
        if m:
            seen_from = True
            ref, derived = substitute(m.group(1), global_args)
            if m.group(2):
                stages.add(m.group(2).lower())
            if ref.lower() != "scratch" and ref.lower() not in stages:
                yield number, ref, derived
            continue
        m = COPY_FROM_RE.match(line)
        if m and not m.group(1).isdigit() and m.group(1).lower() not in stages:
            ref, derived = substitute(m.group(1), global_args)
            yield number, ref, derived


def _file_image_refs(path, text, as_yaml=None):
    """Yield (line_number, ref, derived) for each image reference in one file's text."""
    low = path.lower()
    if as_yaml is None:
        as_yaml = low.endswith((".yml", ".yaml"))
    if low.endswith(".json"):
        for number, line in enumerate(text.splitlines(), 1):
            for m in JSON_IMAGE_RE.finditer(line[:MAX_LINE]):
                ref, derived = substitute(m.group(1), {})
                yield number, ref, derived
    elif as_yaml:
        for number, line in enumerate(text.splitlines(), 1):
            m = YAML_IMAGE_RE.match(line[:MAX_LINE])
            if m:
                ref, derived = substitute(m.group(1), {})
                yield number, ref, derived
    else:
        for item in _dockerfile_refs(text):
            yield item


def collect_image_refs(roots, problems):
    """Yield (path, line, ref, derived). Files that could not be read are appended to
    `problems` as (path, message, important)."""
    for root in roots:
        if not os.path.isdir(root):
            text, problem = read_text_file(root)
            if problem:
                problems.append((root, problem, True))
                continue
            for number, ref, derived in _file_image_refs(root, text):
                yield root, number, ref, derived
            continue
        onerror = lambda exc: problems.append((exc.filename, "cannot read it (%s)" % (exc.strerror or exc), True))
        for dirpath, dirnames, filenames in os.walk(root, onerror=onerror):
            dirnames[:] = sorted(d for d in dirnames if d not in IMAGE_SKIP_DIRS)
            for fname in sorted(filenames):
                path = os.path.join(dirpath, fname)
                is_docker = _is_dockerfile(fname)
                if not (is_docker or fname.lower().endswith((".yml", ".yaml"))):
                    continue
                text, problem = read_text_file(path)
                if problem:
                    problems.append((path, problem, is_docker))
                    continue
                for number, ref, derived in _file_image_refs(path, text):
                    yield path, number, ref, derived


def _opt_int(text):
    return int(text) if text else None


def evaluate_image(adv, ref, derived=False):
    """Return (status, reason, version) for an image reference, or None if it is not PHP.

    `derived` says the reference came from a default value or variable that a build
    argument or .env file could override."""
    if "$" in ref:
        if "php" not in ref.lower():
            return None
        return REVIEW, "the image reference uses a build variable this tool cannot resolve", None
    name, tag, digest = parse_image(ref)
    low = name.lower()
    official = low in OFFICIAL_PHP
    named_php = official or low.rsplit("/", 1)[-1] in PHP_IMAGE_NAMES
    match = None
    if named_php:
        m = TAG_VERSION_RE.match(tag or "")
        if m:
            match = (int(m.group(1)), _opt_int(m.group(2)), _opt_int(m.group(3)), m.group(4))
    else:
        # Images that bundle PHP and say so in the tag, e.g. wordpress:6.8-php8.3-apache.
        m = BUNDLED_RE.search(tag or "")
        if not m:
            return None
        match = (int(m.group(1)), int(m.group(2)), _opt_int(m.group(3)), tag[m.end():])
    if match is None:
        what = "pinned only by digest" if digest and not tag else "using an unpinned tag"
        return REVIEW, "PHP image %s; the PHP version cannot be read from the reference" % what, None

    major, minor, patch, rest = match
    if PRERELEASE_RE.search(rest):
        return REVIEW, "pre-release PHP image tag; compare it with the release notes", None
    if minor is not None and patch is not None:
        status, reason = evaluate(adv, (major, minor, patch, ""), None, tail=False)
        version = "%d.%d.%d" % (major, minor, patch)
    elif minor is not None:
        status, reason = evaluate_branch_only(adv, major, minor)
        version = "%d.%d" % (major, minor)
    else:
        return REVIEW, "tag pins only the major version (PHP %d); pin a full version such as 8.3.36 or later" % major, str(major)

    if digest:
        return REVIEW, ("pinned by digest, which Docker uses instead of the tag; the tag says %s (%s) but the "
                        "digest decides what runs. Check it with `docker run --rm IMAGE php -v`" % (version, status)), version
    if named_php and not official:
        if status == PATCHED:
            return REVIEW, ("third-party image whose tag looks like PHP %s; confirm with "
                            "`docker run --rm %s php -v`" % (version, ref)), version
        reason += " (third-party image: confirm with `docker run --rm IMAGE php -v`)"
    if derived:
        if status == PATCHED:
            return REVIEW, ("%s, but the version comes from a default value that a build argument or .env "
                            "file can override" % reason), version
        if status == VULNERABLE:
            reason += " (taken from a default value; a build argument or .env file could override it)"
    return status, reason, version


def image_findings(advisories, refs, used_by=None):
    findings = []
    cwd = os.getcwd()
    for path, number, ref, derived in refs:
        for adv in advisories:
            verdict = evaluate_image(adv, ref, derived)
            if verdict is None:
                continue
            status, reason, version = verdict
            shown = None
            if path:
                rel = os.path.relpath(path, cwd)
                shown = path if rel.startswith("..") else rel
            if used_by and ref in used_by:
                pods = sorted(used_by[ref])
                reason += "; used by %s%s" % (", ".join(pods[:3]), " and %d more" % (len(pods) - 3) if len(pods) > 3 else "")
            findings.append(make_finding(
                adv, "image", ref, status, reason, version=version,
                confidence="high" if version and version.count(".") == 2 else "medium",
                location={"file": shown, "line": number} if shown else None,
            ))
    return findings


def kubectl_images(text):
    """{image: set of 'namespace/pod'} from `kubectl get pods -o json`, or None."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    used = {}
    items = data.get("items") if isinstance(data, dict) else None
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        meta, spec = item.get("metadata") or {}, item.get("spec") or {}
        pod = "%s/%s" % (clean(meta.get("namespace") or "?", 80), clean(meta.get("name") or "?", 120))
        for key in ("initContainers", "containers", "ephemeralContainers"):
            for container in spec.get(key) or []:
                image = container.get("image") if isinstance(container, dict) else None
                if isinstance(image, str) and image:
                    used.setdefault(image, set()).add(pod)
    return used


def cmd_images(args, advisories):
    paths = args.paths or ([] if args.image or args.docker or args.kubectl else ["."])
    _require_paths(paths)
    problems = []
    refs = list(collect_image_refs(paths, problems))
    notes, used_by = [], {}
    for ref in args.image or []:
        refs.append((None, 0, ref, False))
    if args.docker:
        code, out, err = run(["docker", "ps", "--format", "{{.Image}}"], timeout=30)
        if code != 0:
            raise UsageError("could not list running containers: %s" % (clean(err).strip() or "docker not available"))
        refs.extend((None, 0, ref.strip(), False) for ref in sorted(set(out.splitlines())) if ref.strip())
    if args.kubectl:
        cmd = ["kubectl"] + shlex.split(args.kubectl_args or "") + ["get", "pods", "--all-namespaces", "-o", "json"]
        code, out, err = run(cmd, timeout=120, cap=64 * 1024 * 1024)
        used_by = kubectl_images(out) if code == 0 else None
        if used_by is None:
            raise UsageError("could not read pods from kubectl: %s" % (clean(err).strip() or "unexpected output"))
        refs.extend((None, 0, ref, False) for ref in sorted(used_by))
        notes.append("Checked %d distinct image(s) across the cluster's pods." % len(used_by))
    findings = image_findings(advisories, refs, used_by)

    adv = advisories[0]
    skipped = 0
    for path, message, important in problems:
        if important:
            findings.append(error_finding(adv, "file", clean(path), "skipped: %s" % message))
        else:
            skipped += 1
    if skipped:
        notes.append("Skipped %d YAML file(s) that could not be read or were too large." % skipped)
    if not [f for f in findings if f["kind"] != "file"]:
        notes.append("No PHP image references found.")
    return findings, notes


# --------------------------------------------------------------------------
# url: one ordinary GET, read the advertised version
# --------------------------------------------------------------------------

class _HttpOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not re.match(r"^https?://", newurl, re.I):
            raise urllib.error.URLError("redirect to a non-http URL was refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_url(url, advisories, timeout):
    """A banner can be set by a proxy and one request reaches one backend, so this never says PATCHED."""
    headers = {"User-Agent": "php-vuln-check/%s (+%s)" % (__version__, REPO_URL)}
    opener = urllib.request.build_opener(_HttpOnlyRedirect)
    values = []
    try:
        with opener.open(urllib.request.Request(url, headers=headers), timeout=timeout) as resp:
            values = resp.headers.get_all("X-Powered-By") or []
    except urllib.error.HTTPError as exc:
        values = (exc.headers.get_all("X-Powered-By") if exc.headers else None) or []
    except Exception as exc:  # DNS, TLS, timeout, refused, refused redirect
        return [error_finding(adv, "url", url, "request failed: %s" % clean(exc)) for adv in advisories]

    versions = []
    for value in values:
        versions.extend(parse_version(v) for v in HEADER_RE.findall(value))
    versions = sorted(v for v in versions if v)
    findings = []
    for adv in advisories:
        if not versions:
            findings.append(make_finding(
                adv, "url", url, REVIEW,
                "no PHP version is advertised (expose_php is off, or a proxy strips X-Powered-By); "
                "run `php-vuln-check scan` on the server", confidence="low"))
            continue
        lowest = versions[0]
        status, reason = evaluate(adv, lowest, None, tail=False)
        shown = "%d.%d.%d" % lowest[:3]
        if status == VULNERABLE:
            reason += "; distro backports are invisible from outside, so confirm on the host with `php-vuln-check scan`"
        elif status == PATCHED:
            reason += "; a banner cannot prove the server is patched, so confirm on the host with `php-vuln-check scan`"
        findings.append(make_finding(
            adv, "url", url, REVIEW, "the server advertises PHP/%s: %s" % (shown, reason),
            version=shown, confidence="low"))
    return findings


def cmd_url(args, advisories):
    findings = []
    for url in args.urls:
        if not re.match(r"^https?://", url, re.I):
            raise UsageError("URLs must start with http:// or https:// (got %r)" % clean(url, 80))
        findings.extend(check_url(url, advisories, args.timeout))
    return findings, []


# --------------------------------------------------------------------------
# fleet: run `scan` on many hosts over SSH, nothing installed remotely
# --------------------------------------------------------------------------

HOST_RE = re.compile(r"^[A-Za-z0-9_:][A-Za-z0-9_.@:%-]*$")  # never starts with "-", so it cannot be an ssh option


def read_hosts(path):
    hosts = []
    try:
        fh = io.open(path, "r", errors="replace")
    except OSError as exc:
        raise UsageError("cannot read hosts file %s: %s" % (path, exc.strerror or exc))
    with fh:
        for line in fh:
            host = line.split("#", 1)[0].strip()
            if not host:
                continue
            if not HOST_RE.match(host):
                raise UsageError("refusing suspicious host entry %r in %s" % (clean(host, 80), path))
            hosts.append(host)
    return hosts


def extract_report(text):
    """Find the tool's JSON report in ssh output that may carry a login banner."""
    decoder = json.JSONDecoder()
    for m in re.finditer(r"(?m)^\{", text):
        try:
            obj, _ = decoder.raw_decode(text[m.start():])
        except ValueError:
            continue
        if isinstance(obj, dict) and obj.get("tool") == "php-vuln-check" and isinstance(obj.get("findings"), list):
            return obj
    return None


def validate_finding(raw, host):
    """Rebuild a finding from untrusted remote JSON: known keys, bounded strings, valid status."""
    if not isinstance(raw, dict):
        return None
    status = raw.get("status")
    reason = clean(raw.get("reason"))
    if status not in STATUS_ORDER:
        status, reason = ERROR, "the host returned a malformed result"
    advisory = raw.get("advisory") if raw.get("advisory") in ADVISORIES_BY_ID else ADVISORIES[0]["id"]
    out = {"advisory": advisory, "host": host, "status": status, "reason": reason,
           "kind": clean(raw.get("kind"), 40) or "?", "target": clean(raw.get("target")) or "?"}
    for key in ("sapi", "version", "package", "confidence", "fixed_in"):
        value = raw.get(key)
        out[key] = clean(value) if isinstance(value, str) else None
    config = raw.get("config")
    out["config"] = dict((clean(k, 60), clean(v, 40)) for k, v in list(config.items())[:20]
                         if isinstance(k, str) and isinstance(v, str)) if isinstance(config, dict) else {}
    loc = raw.get("location")
    out["location"] = ({"file": clean(loc.get("file")), "line": loc.get("line") if isinstance(loc.get("line"), int) else 0}
                       if isinstance(loc, dict) and isinstance(loc.get("file"), str) else None)
    return out


def fleet_one(host, script, args, advisory_ids):
    adv = ADVISORIES_BY_ID[advisory_ids[0]]
    remote = ["python3", "-", "scan", "--format", "json", "--quiet"]
    if args.no_exec:
        remote.append("--no-exec")
    if args.exec:
        remote.append("--exec")
    for adv_id in advisory_ids:
        remote.extend(["--advisory", adv_id])
    cmd = (["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=%d" % args.connect_timeout]
           + shlex.split(args.ssh_opts or "") + ["--", host, " ".join(shlex.quote(p) for p in remote)])
    code, out, err = run(cmd, timeout=args.timeout, stdin=script)
    report = extract_report(out)
    if report is None:
        first = (clean(err).strip().splitlines() or ["no output"])[0]
        return [error_finding(adv, "host", host, "ssh or scan failed: %s" % first, host=host)]
    findings = [f for f in (validate_finding(r, host) for r in report["findings"]) if f]
    if not findings:
        # Nothing found is not the same as patched: PHP may live somewhere the scan does not look.
        return [make_finding(adv, "host", host, NONE,
                             "no PHP found in the standard locations; PHP in a custom prefix, container "
                             "or vhost folder would not appear (re-run with --path on that host)", host=host)]
    return findings


def cmd_fleet(args, advisories):
    hosts = read_hosts(args.hosts_file)
    if not hosts:
        raise UsageError("no hosts found in %s" % args.hosts_file)
    with io.open(os.path.abspath(__file__), "r", encoding="utf-8") as fh:
        script = fh.read()
    ids = [a["id"] for a in advisories]
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        results = list(pool.map(lambda h: fleet_one(h, script, args, ids), hosts))
    findings = [f for batch in results for f in batch]
    return findings, ["Checked %d host(s) over SSH." % len(hosts)]


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def summarize(findings):
    counts = dict((s, 0) for s in STATUS_ORDER)
    for f in findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    return counts


def stale_data_note(today=None):
    """A warning when the advisory data is old enough that newer fixes may be missing, else None."""
    checked = datetime.datetime.strptime(DATA_CHECKED, "%Y-%m-%d").date()
    age = ((today or datetime.date.today()) - checked).days
    if age <= STALE_AFTER_DAYS:
        return None
    return ("This tool's advisory data was last checked on %s (%d days ago), so newer PHP fixes or vendor "
            "builds may be missing. Get the latest release: %s/releases/latest" % (DATA_CHECKED, age, REPO_URL))


def build_report(findings, notes, mode):
    counts = summarize(findings)
    stale = stale_data_note()
    notes = notes + [stale] if stale else notes
    return {
        "tool": "php-vuln-check", "version": __version__, "mode": mode,
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": dict((k.lower(), v) for k, v in counts.items()),
        "notes": notes,
        "findings": sorted(findings, key=lambda f: (STATUS_ORDER.get(f["status"], 9), f.get("host") or "", f["target"])),
    }


def exit_code(findings, fail_on):
    counts = summarize(findings)
    if fail_on == "never":
        return 0
    if counts[VULNERABLE]:
        return 1
    if counts[ERROR]:
        return 3
    if counts[REVIEW] and fail_on == "review":
        return 2
    return 0


COLORS = {VULNERABLE: "1;31", ERROR: "1;35", REVIEW: "1;33", PATCHED: "1;32", NONE: "2"}


def render_text(report, advisories, color, quiet):
    def paint(status, text):
        return "\033[%sm%s\033[0m" % (COLORS[status], text) if color else text

    out = []
    if not quiet:
        names = "; ".join("%s (%s)" % (a["name"], ", ".join(a["cves"])) for a in advisories)
        out.append("php-vuln-check %s  |  checking %s" % (__version__, names))
        out.append("")
    for f in report["findings"]:
        head = clean(f["target"])
        if f.get("host") and report["mode"] == "fleet":
            head = "%s  %s" % (clean(f["host"]), head)
        out.append("%s  %s" % (paint(f["status"], "%-10s" % f["status"]), head))
        detail = [clean(d) for d in (
            ("PHP %s" % f["version"]) if f.get("version") else None,
            f.get("sapi"), f.get("package")) if d]
        if detail:
            out.append("            " + " | ".join(detail))
        out.append("            " + clean(f["reason"], 1000))
        if f.get("location"):
            out.append("            at %s:%s" % (clean(f["location"]["file"]), clean(f["location"]["line"], 12)))
        cfg = f.get("config") or {}
        if cfg:
            out.append("            config: " + " ".join("%s=%s" % (clean(k), clean(v)) for k, v in sorted(cfg.items())))
        out.append("")
    for note in report["notes"]:
        out.append(clean(note, 1000))
    s = report["summary"]
    line = "Summary: %d vulnerable | %d need review | %d patched" % (s["vulnerable"], s["review"], s["patched"])
    if s["error"]:
        line += " | %d error" % s["error"]
    if s["none"]:
        line += " | %d with no PHP found" % s["none"]
    out.append(line)
    if not quiet and s["patched"]:
        out.append("PATCHED describes the files on disk. After an update, restart PHP-FPM or Apache so running workers load them.")
    if not quiet and (s["vulnerable"] or s["review"]):
        out.append("")
        out.append("What to do:")
        for adv in advisories:
            for step in adv["mitigations"]:
                out.append("  - " + step)
            out.append("  - Details: " + adv["references"][0]["url"])
        out.append("  - REVIEW means the tool could not prove either way; it is not a clean bill of health.")
    return "\n".join(out) + "\n"


def _csv_cell(value):
    """Neutralise spreadsheet formulas in untrusted text."""
    if value is None:
        return ""
    if isinstance(value, str):
        value = clean(value, 2000)
        if value[:1] in ("=", "+", "-", "@"):
            return "'" + value
    return value


def render_csv(report):
    buf = io.StringIO()
    cols = ["host", "advisory", "status", "kind", "target", "sapi", "version", "package",
            "fixed_in", "confidence", "reason", "file", "line"]
    writer = csv.writer(buf)
    writer.writerow(cols)
    for f in report["findings"]:
        loc = f.get("location") or {}
        row = [f.get(c) for c in cols[:-2]] + [loc.get("file"), loc.get("line")]
        writer.writerow([_csv_cell(v) for v in row])
    return buf.getvalue()


def render_sarif(report, advisories):
    """SARIF for GitHub code scanning. Only findings with a file location are included:
    code scanning needs a location in the repository, and a host or URL has none."""
    severities = {VULNERABLE: "9.0", REVIEW: "5.0"}
    rules = []
    for a in advisories:
        for status in (VULNERABLE, REVIEW):
            rules.append({
                "id": "%s/%s" % (a["id"], status.lower()), "name": "%s%s" % (a["name"], status.title()),
                "shortDescription": {"text": "%s (%s): %s" % (a["name"], ", ".join(a["cves"]), status.lower())},
                "fullDescription": {"text": a["summary"]},
                "helpUri": a["references"][0]["url"],
                "properties": {"tags": ["security"] + a["cves"], "security-severity": severities[status]},
            })
    results = []
    for f in report["findings"]:
        loc = f.get("location")
        if f["status"] not in severities or not loc:
            continue
        results.append({
            "ruleId": "%s/%s" % (f["advisory"], f["status"].lower()),
            "level": "error" if f["status"] == VULNERABLE else "warning",
            "message": {"text": clean("%s: %s" % (f["target"], f["reason"]), 1500)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": urllib.parse.quote(loc["file"])},
                "region": {"startLine": max(1, int(loc.get("line") or 1))},
            }}],
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "php-vuln-check", "version": __version__, "informationUri": REPO_URL, "rules": rules}},
            "results": results}],
    }, indent=2) + "\n"


def emit(text, output):
    if output:
        with io.open(output, "w", encoding="utf-8") as fh:
            fh.write(text)
        return
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:  # an ASCII-only locale
        sys.stdout.write(text.encode("ascii", "replace").decode("ascii"))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

class Parser(argparse.ArgumentParser):
    """Usage errors exit 3 so they cannot be mistaken for 'vulnerable' (1) or 'review' (2)."""

    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("%s: error: %s\n" % (self.prog, message))
        raise SystemExit(3)


def common_options():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--format", choices=["text", "json", "csv", "sarif"], default="text",
                   help="output format (default: text)")
    p.add_argument("--json", dest="format", action="store_const", const="json", help="shortcut for --format json")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    p.add_argument("--advisory", action="append", metavar="ID", choices=sorted(ADVISORIES_BY_ID),
                   help="check only this advisory (default: all). See `php-vuln-check advisories`")
    p.add_argument("--fail-on", choices=["review", "vulnerable", "never"], default="review",
                   help="exit non-zero for REVIEW and VULNERABLE (default), only VULNERABLE, or never")
    p.add_argument("-q", "--quiet", action="store_true", help="omit the banner and the what-to-do block")
    p.add_argument("--no-color", action="store_true", help="never use colors")
    return p


def exec_options(p):
    group = p.add_mutually_exclusive_group()
    group.add_argument("--no-exec", action="store_true",
                       help="never run PHP binaries; read versions from the files and the package manager instead")
    group.add_argument("--exec", action="store_true",
                       help="run every PHP binary found, even ones that are not root-owned or are writable by others")


def build_parser():
    common = common_options()
    parser = Parser(
        prog="php-vuln-check",
        description="Find PHP installs exposed to PHP2Shell (CVE-2026-109618 / CVE-2026-109619) and "
                    "other tracked PHP vulnerabilities. Reads versions, vendor changelogs and config; "
                    "never sends exploit traffic.",
        epilog="Exit codes: 0 clean, 1 vulnerable, 2 needs review, 3 error or bad usage.  Docs: " + REPO_URL)
    parser.add_argument("--version", action="version", version="php-vuln-check " + __version__)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("scan", parents=[common], help="audit PHP installs on this machine (default)")
    p.add_argument("--path", action="append", metavar="DIR", help="also search DIR (or check this file); repeatable")
    p.add_argument("--no-defaults", action="store_true", help="skip the standard install locations")
    exec_options(p)

    p = sub.add_parser("images", parents=[common], help="check Dockerfiles, compose files, k8s manifests, images")
    p.add_argument("paths", nargs="*", metavar="PATH", help="files or folders to scan (default: .)")
    p.add_argument("--image", action="append", metavar="REF", help="check one image reference such as php:8.3-fpm")
    p.add_argument("--docker", action="store_true", help="also check images of running containers")
    p.add_argument("--kubectl", action="store_true", help="also check images of pods in the current cluster")
    p.add_argument("--kubectl-args", default="", metavar="ARGS", help='extra kubectl arguments, e.g. "--context prod"')

    p = sub.add_parser("url", parents=[common], help="read the PHP version a website advertises (one GET each)")
    p.add_argument("urls", nargs="+", metavar="URL")
    p.add_argument("--timeout", type=int, default=15)

    p = sub.add_parser("fleet", parents=[common], help="run `scan` on many hosts over SSH")
    p.add_argument("hosts_file", metavar="HOSTS_FILE", help="one [user@]host per line; # starts a comment")
    p.add_argument("--jobs", type=int, default=8, help="hosts to check in parallel (default: 8)")
    p.add_argument("--ssh-opts", default="", help='extra ssh options, e.g. "-i ~/.ssh/key -p 2222"')
    p.add_argument("--connect-timeout", type=int, default=10)
    p.add_argument("--timeout", type=int, default=300, help="seconds to wait for each host")
    exec_options(p)

    sub.add_parser("advisories", help="list the advisories this version knows about")
    return parser


def cmd_advisories():
    for a in ADVISORIES:
        print("%s  %s  %s  severity %s  published %s" % (a["id"], a["name"], ", ".join(a["cves"]), a["cvss"], a["published"]))
        print("  fixed in: " + ", ".join(a["fixed"][b] for b in sorted(a["fixed"])) + "; older branches need a vendor backport")
        print("  " + a["summary"])
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")
    try:
        args = build_parser().parse_args(argv)
        if args.command == "advisories":
            return cmd_advisories()

        advisories = [ADVISORIES_BY_ID[i] for i in args.advisory] if args.advisory else list(ADVISORIES)
        handlers = {"scan": cmd_scan, "images": cmd_images, "url": cmd_url, "fleet": cmd_fleet}
        findings, notes = handlers[args.command](args, advisories)
        report = build_report(findings, notes, args.command)

        color = (not args.no_color and not args.output and sys.stdout.isatty() and "NO_COLOR" not in os.environ)
        if args.format == "json":
            text = json.dumps(report, indent=2) + "\n"
        elif args.format == "csv":
            text = render_csv(report)
        elif args.format == "sarif":
            text = render_sarif(report, advisories)
        else:
            text = render_text(report, advisories, color, args.quiet)
        emit(text, args.output)
        return exit_code(findings, args.fail_on)
    except UsageError as exc:
        sys.stderr.write("php-vuln-check: %s\n" % exc)
        return 3
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # never let a crash look like 'vulnerable' (1) or 'review' (2)
        sys.stderr.write("php-vuln-check: internal error: %s: %s\nPlease report it at %s/issues\n"
                         % (type(exc).__name__, exc, REPO_URL))
        return 3


if __name__ == "__main__":
    sys.exit(main())
